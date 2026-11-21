//! Routes and DNS for Session Router on Windows.
//!
//! The router's own Windows code shells out to `route.exe` and PowerShell, guesses the
//! default gateway, and leaves routes and DNS behind if it crashes. This crate does the
//! same jobs through the IP Helper API and writes down every change it makes in a small
//! journal file before making it, so whatever is left after a crash can be undone on the
//! next start.
//!
//! Platform calls sit behind the [`RouteTable`] and [`DnsSettings`] traits. The Windows
//! implementations live in [`windows`]; [`mem`] is an in-memory stand-in used by tests.

pub mod ip;
pub mod journal;
pub mod mem;
pub mod vpn;
#[cfg(windows)]
pub mod windows;

pub use ip::Ipv4Net;
pub use journal::Journal;

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// One IPv4 route. `metric` is the route's own metric; Windows adds the interface metric.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Route {
    pub dest: Ipv4Net,
    pub next_hop: Ipv4Addr,
    pub if_index: u32,
    pub metric: u32,
}

/// Where traffic leaves the machine when it isn't going through the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    pub next_hop: Ipv4Addr,
    pub if_index: u32,
}

pub trait RouteTable {
    fn routes(&self) -> io::Result<Vec<Route>>;
    fn add(&mut self, r: &Route) -> io::Result<()>;
    /// Removing a route that is already gone must succeed.
    fn delete(&mut self, r: &Route) -> io::Result<()>;
    /// The interface's own IPv4 metric. Windows ranks routes by route metric plus this.
    fn interface_metric(&self, _if_index: u32) -> io::Result<u32> {
        Ok(0)
    }
    /// True for tunnel and virtual adapters (Wintun and the like), which are never the
    /// physical uplink even when they hold the best default route.
    fn is_tunnel(&self, _if_index: u32) -> bool {
        false
    }
    /// Interface index for an adapter name such as "Ethernet", if it exists.
    fn index_of(&self, _name: &str) -> io::Result<Option<u32>> {
        Ok(None)
    }
    /// The adapter's name ("Wi-Fi", "NordLynx"), if known.
    fn name_of(&self, _if_index: u32) -> Option<String> {
        None
    }
    /// The adapter's description ("TAP-NordVPN Windows Adapter V9"), if known.
    fn description_of(&self, _if_index: u32) -> Option<String> {
        None
    }
}

/// DNS servers per interface. An empty list means "automatic" (DHCP or router advert).
pub trait DnsSettings {
    fn servers(&self, if_index: u32) -> io::Result<Vec<IpAddr>>;
    fn set_servers(&mut self, if_index: u32, servers: &[IpAddr]) -> io::Result<()>;
}

/// IPv6 on/off per network adapter.
///
/// The router turns IPv6 off on adapters when a full-tunnel exit comes up and only turns
/// it back on if it shuts down cleanly. Rusty notes which adapters had it on before the
/// router started and turns it back on for any the router left off.
pub trait Ipv6Bindings {
    /// Names of adapters with IPv6 turned on.
    fn enabled(&self) -> io::Result<Vec<String>>;
    fn enable(&mut self, adapter: &str) -> io::Result<()>;
}

/// For platforms or tests with nothing to track.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoIpv6;

impl Ipv6Bindings for NoIpv6 {
    fn enabled(&self) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn enable(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
}

/// The best default route on an interface `usable` accepts, ranked the way Windows ranks
/// them: route metric plus interface metric. Ties go to the lower interface index so the
/// answer is stable.
pub fn best_gateway(
    routes: &[Route],
    usable: impl Fn(u32) -> bool,
    if_metric: impl Fn(u32) -> u32,
) -> Option<Gateway> {
    routes
        .iter()
        .filter(|r| r.dest.is_default() && !r.next_hop.is_unspecified() && usable(r.if_index))
        .min_by_key(|r| (r.metric.saturating_add(if_metric(r.if_index)), r.if_index))
        .map(|r| Gateway {
            next_hop: r.next_hop,
            if_index: r.if_index,
        })
}

/// The best default route that isn't on one of the `skip` interfaces, by route metric
/// alone. Use [`physical_gateway`] when a live route table is at hand.
pub fn default_gateway(routes: &[Route], skip: &[u32]) -> Option<Gateway> {
    best_gateway(routes, |i| !skip.contains(&i), |_| 0)
}

/// The physical uplink: the best default route by effective metric (route plus
/// interface), never on a tunnel adapter or one of the `skip` interfaces.
pub fn physical_gateway<R: RouteTable + ?Sized>(
    table: &R,
    skip: &[u32],
) -> io::Result<Option<Gateway>> {
    let routes = table.routes()?;
    let mut metrics = std::collections::BTreeMap::new();
    for r in routes.iter().filter(|r| r.dest.is_default()) {
        if let std::collections::btree_map::Entry::Vacant(e) = metrics.entry(r.if_index) {
            // An interface that vanished between the two reads can't be the uplink.
            e.insert(table.interface_metric(r.if_index).ok());
        }
    }
    Ok(best_gateway(
        &routes,
        |i| {
            !skip.contains(&i)
                && metrics.get(&i).is_some_and(|m| m.is_some())
                && !table.is_tunnel(i)
        },
        |i| metrics.get(&i).copied().flatten().unwrap_or(u32::MAX),
    ))
}

/// Other VPN adapters that hold a default route (0.0.0.0/0, or the 0/1 and 128/1 pair)
/// right now, by name. Session Router's own `sr-tun*` adapters don't count. Another VPN's
/// default route fights with the exit's routes and its own filters may block ours.
pub fn other_vpn_defaults<R: RouteTable + ?Sized>(table: &R) -> io::Result<Vec<String>> {
    let half_lo = Ipv4Net {
        addr: Ipv4Addr::UNSPECIFIED,
        prefix: 1,
    };
    let half_hi = Ipv4Net {
        addr: Ipv4Addr::new(128, 0, 0, 0),
        prefix: 1,
    };
    let mut seen = Vec::new();
    let mut names = Vec::new();
    for r in table.routes()? {
        if !(r.dest.is_default() || r.dest == half_lo || r.dest == half_hi) {
            continue;
        }
        if seen.contains(&r.if_index) || !table.is_tunnel(r.if_index) {
            continue;
        }
        seen.push(r.if_index);
        let name = table
            .name_of(r.if_index)
            .unwrap_or_else(|| format!("interface {}", r.if_index));
        if !name.to_ascii_lowercase().starts_with("sr-tun") {
            names.push(name);
        }
    }
    Ok(names)
}

/// What changed about the default gateway since the last look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayEvent {
    Lost(Gateway),
    Found(Gateway),
    Changed { old: Gateway, new: Gateway },
}

/// Notices when the physical default gateway goes away, comes back, or moves (Wi-Fi to
/// Ethernet, a new DHCP lease). Feed it the route table whenever Windows reports a change
/// or on a timer.
#[derive(Debug, Default)]
pub struct GatewayWatcher {
    last: Option<Gateway>,
    skip: Vec<u32>,
}

impl GatewayWatcher {
    pub fn new(skip: Vec<u32>) -> Self {
        GatewayWatcher { last: None, skip }
    }

    pub fn current(&self) -> Option<Gateway> {
        self.last
    }

    /// Looks at a live table: effective metrics, tunnels skipped.
    pub fn observe_table<R: RouteTable + ?Sized>(
        &mut self,
        table: &R,
    ) -> io::Result<Option<GatewayEvent>> {
        let now = physical_gateway(table, &self.skip)?;
        Ok(self.update(now))
    }

    /// Looks at a bare list of routes, by route metric alone.
    pub fn observe(&mut self, routes: &[Route]) -> Option<GatewayEvent> {
        let now = default_gateway(routes, &self.skip);
        self.update(now)
    }

    fn update(&mut self, now: Option<Gateway>) -> Option<GatewayEvent> {
        let ev = match (self.last, now) {
            (None, None) => None,
            (Some(old), None) => Some(GatewayEvent::Lost(old)),
            (None, Some(new)) => Some(GatewayEvent::Found(new)),
            (Some(old), Some(new)) if old != new => Some(GatewayEvent::Changed { old, new }),
            _ => None,
        };
        self.last = now;
        ev
    }
}

/// Metric for pinned host routes: low, so they beat the tunnel's catch-all routes.
pub const PIN_METRIC: u32 = 1;

/// Makes route and DNS changes and remembers them so they can always be undone.
pub struct NetGuard<R: RouteTable, D: DnsSettings> {
    routes: R,
    dns: D,
    ipv6: Box<dyn Ipv6Bindings + Send>,
    journal_path: PathBuf,
    journal: Journal,
}

impl<R: RouteTable, D: DnsSettings> NetGuard<R, D> {
    /// Opens the guard. If the journal shows changes left behind by an earlier run that
    /// didn't shut down cleanly, they are undone first.
    pub fn open(routes: R, dns: D, journal_path: PathBuf) -> io::Result<(Self, RestoreReport)> {
        Self::open_with_ipv6(routes, dns, Box::new(NoIpv6), journal_path)
    }

    /// Same as [`open`](Self::open), also tracking IPv6 adapter bindings.
    pub fn open_with_ipv6(
        routes: R,
        dns: D,
        ipv6: Box<dyn Ipv6Bindings + Send>,
        journal_path: PathBuf,
    ) -> io::Result<(Self, RestoreReport)> {
        let journal = Journal::load(&journal_path)?;
        let mut g = NetGuard {
            routes,
            dns,
            ipv6,
            journal_path,
            journal,
        };
        let report = g.restore()?;
        Ok((g, report))
    }

    /// Notes which adapters have IPv6 on, so [`restore`](Self::restore) can turn back on
    /// any that get turned off. Keeps the first note until it has been restored.
    pub fn note_ipv6(&mut self) -> io::Result<()> {
        if !self.journal.ipv6_enabled.is_empty() {
            return Ok(());
        }
        self.journal.ipv6_enabled = self.ipv6.enabled()?;
        self.save()
    }

    /// Turns IPv6 back on for adapters noted with it on that are off now, and keeps the
    /// note (the router may turn it off again on the next map). Returns the adapters.
    pub fn reenable_ipv6(&mut self) -> io::Result<Vec<String>> {
        if self.journal.ipv6_enabled.is_empty() {
            return Ok(Vec::new());
        }
        let now = self.ipv6.enabled()?;
        let mut done = Vec::new();
        let mut first_err = None;
        for a in self.journal.ipv6_enabled.clone() {
            if now.contains(&a) {
                continue;
            }
            match self.ipv6.enable(&a) {
                Ok(()) => done.push(a),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match first_err {
            Some(e) if done.is_empty() => Err(e),
            _ => Ok(done),
        }
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn route_table(&self) -> &R {
        &self.routes
    }

    /// Direct access, for removing routes this guard didn't add (crash leftovers).
    pub fn route_table_mut(&mut self) -> &mut R {
        &mut self.routes
    }

    pub fn dns(&self) -> &D {
        &self.dns
    }

    fn save(&self) -> io::Result<()> {
        self.journal.save(&self.journal_path)
    }

    /// Sends traffic for each host straight out of the physical gateway instead of the
    /// tunnel. Used for the router's first hops so its own traffic can't loop into itself.
    pub fn pin_hosts(&mut self, hosts: &[Ipv4Addr], gw: Gateway) -> io::Result<()> {
        for &h in hosts {
            let r = Route {
                dest: Ipv4Net::host(h),
                next_hop: gw.next_hop,
                if_index: gw.if_index,
                metric: PIN_METRIC,
            };
            if self.journal.pinned.contains(&r) {
                continue;
            }
            // Write it down first: if we die between these two lines, restore just
            // deletes a route that isn't there, which is fine.
            self.journal.pinned.push(r.clone());
            self.save()?;
            if let Err(e) = self.routes.add(&r) {
                self.journal.pinned.retain(|p| p != &r);
                self.save()?;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Moves every pinned host route onto a new gateway (after a network change).
    pub fn repin(&mut self, gw: Gateway) -> io::Result<()> {
        let hosts: Vec<Ipv4Addr> = self.journal.pinned.iter().map(|r| r.dest.addr).collect();
        self.unpin_all()?;
        self.pin_hosts(&hosts, gw)
    }

    pub fn unpin_all(&mut self) -> io::Result<()> {
        let mut first_err = None;
        for r in std::mem::take(&mut self.journal.pinned) {
            if let Err(e) = self.routes.delete(&r) {
                first_err.get_or_insert(e);
                self.journal.pinned.push(r);
            }
        }
        self.save()?;
        first_err.map_or(Ok(()), Err)
    }

    /// Points an interface's DNS at `servers`, remembering what it had before.
    pub fn set_dns(&mut self, if_index: u32, servers: &[IpAddr]) -> io::Result<()> {
        if !self.journal.dns.iter().any(|d| d.if_index == if_index) {
            let before = self.dns.servers(if_index)?;
            self.journal.dns.push(journal::DnsBefore {
                if_index,
                servers: before,
            });
            self.save()?;
        }
        self.dns.set_servers(if_index, servers)
    }

    /// Gives one interface its DNS servers back (DNS moved to another interface).
    pub fn restore_dns(&mut self, if_index: u32) -> io::Result<()> {
        let Some(pos) = self.journal.dns.iter().position(|d| d.if_index == if_index) else {
            return Ok(());
        };
        let d = self.journal.dns[pos].clone();
        match self.dns.set_servers(d.if_index, &d.servers) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.journal.dns.remove(pos);
        self.save()
    }

    /// Undoes everything in the journal: pinned routes go, DNS goes back to what it was.
    pub fn restore(&mut self) -> io::Result<RestoreReport> {
        let mut report = RestoreReport::default();
        let mut failed = Vec::new();
        for r in std::mem::take(&mut self.journal.pinned) {
            match self.routes.delete(&r) {
                Ok(()) => report.routes_removed += 1,
                Err(e) => {
                    report
                        .errors
                        .push(format!("route {} via {}: {e}", r.dest, r.next_hop));
                    failed.push(r);
                }
            }
        }
        self.journal.pinned = failed;
        let mut dns_failed = Vec::new();
        for d in std::mem::take(&mut self.journal.dns) {
            match self.dns.set_servers(d.if_index, &d.servers) {
                Ok(()) => report.dns_restored += 1,
                // The interface may be gone (a USB adapter unplugged); nothing to restore.
                Err(e) if e.kind() == io::ErrorKind::NotFound => report.dns_restored += 1,
                Err(e) => {
                    report
                        .errors
                        .push(format!("DNS on interface {}: {e}", d.if_index));
                    dns_failed.push(d);
                }
            }
        }
        self.journal.dns = dns_failed;
        if !self.journal.ipv6_enabled.is_empty() {
            match self.ipv6.enabled() {
                Ok(now) => {
                    let mut failed = Vec::new();
                    for a in std::mem::take(&mut self.journal.ipv6_enabled) {
                        if now.contains(&a) {
                            continue;
                        }
                        match self.ipv6.enable(&a) {
                            Ok(()) => report.ipv6_reenabled.push(a),
                            // Removed or renamed: nothing to turn back on, and keeping it
                            // would fail every later start.
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                                report.ipv6_gone.push(a)
                            }
                            Err(e) => {
                                report.errors.push(format!("IPv6 on {a}: {e}"));
                                failed.push(a);
                            }
                        }
                    }
                    // Keep the ones that failed so the next restore tries again.
                    self.journal.ipv6_enabled = failed;
                }
                Err(e) => report.errors.push(format!("reading IPv6 state: {e}")),
            }
        }
        self.save()?;
        Ok(report)
    }
}

/// Parses a DNS server list as Windows writes it: separated by commas or spaces.
pub fn parse_server_list(s: &str) -> Vec<IpAddr> {
    s.split([',', ' ', ';'])
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

/// Error for a failed PowerShell helper. Exit code 3, or a NetAdapter "not found" error,
/// means the adapter is gone.
pub fn ps_error(code: Option<i32>, stderr: &str) -> io::Error {
    let gone = code == Some(3)
        || stderr.contains("ObjectNotFound")
        || stderr.contains("No MSFT_NetAdapter");
    // PowerShell's error text runs to several lines of position markers; the first line
    // says what went wrong.
    let msg = match stderr.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(first) => first.to_string(),
        None => format!("powershell exited with {code:?}"),
    };
    if gone {
        io::Error::new(io::ErrorKind::NotFound, msg)
    } else {
        io::Error::other(msg)
    }
}

pub fn format_server_list(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub routes_removed: usize,
    pub dns_restored: usize,
    /// Adapters whose IPv6 was off and has been turned back on.
    pub ipv6_reenabled: Vec<String>,
    /// Adapters noted with IPv6 on that no longer exist; dropped from the journal.
    pub ipv6_gone: Vec<String>,
    pub errors: Vec<String>,
}

impl RestoreReport {
    pub fn is_empty(&self) -> bool {
        self.routes_removed == 0
            && self.dns_restored == 0
            && self.ipv6_reenabled.is_empty()
            && self.ipv6_gone.is_empty()
            && self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mem::{MemDns, MemRoutes};

    fn r(dest: &str, hop: &str, ifx: u32, metric: u32) -> Route {
        Route {
            dest: dest.parse().unwrap(),
            next_hop: hop.parse().unwrap(),
            if_index: ifx,
            metric,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rusty-net-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    const TUN: u32 = 40;

    fn table() -> MemRoutes {
        MemRoutes::with(vec![
            r("0.0.0.0/0", "192.168.1.1", 7, 25),
            r("0.0.0.0/0", "10.0.0.1", 9, 50),
            r("0.0.0.0/1", "0.0.0.0", TUN, 0),
            r("0.0.0.0/0", "172.16.0.1", TUN, 1),
            r("192.168.1.0/24", "0.0.0.0", 7, 25),
        ])
    }

    #[test]
    fn server_lists() {
        let v = parse_server_list("192.168.1.1, 1.1.1.1 fe80::1;junk");
        assert_eq!(v.len(), 3);
        assert_eq!(format_server_list(&v[..2]), "192.168.1.1,1.1.1.1");
        assert!(parse_server_list("").is_empty());
    }

    #[test]
    fn picks_lowest_metric_gateway_off_the_tunnel() {
        let gw = default_gateway(&table().routes().unwrap(), &[TUN]).unwrap();
        assert_eq!(
            gw,
            Gateway {
                next_hop: "192.168.1.1".parse().unwrap(),
                if_index: 7
            }
        );
        // Without skipping the tunnel its metric-1 default would win.
        assert_eq!(
            default_gateway(&table().routes().unwrap(), &[])
                .unwrap()
                .if_index,
            TUN
        );
        assert_eq!(default_gateway(&[], &[]), None);
    }

    #[test]
    fn watcher_reports_loss_return_and_moves() {
        let mut w = GatewayWatcher::new(vec![TUN]);
        let mut t = table();
        assert!(
            matches!(w.observe(&t.routes().unwrap()), Some(GatewayEvent::Found(g)) if g.if_index == 7)
        );
        assert_eq!(w.observe(&t.routes().unwrap()), None);
        // Wi-Fi drops: its default route goes away, the backup on 9 takes over.
        t.delete(&r("0.0.0.0/0", "192.168.1.1", 7, 25)).unwrap();
        assert!(
            matches!(w.observe(&t.routes().unwrap()), Some(GatewayEvent::Changed { old, new }) if old.if_index == 7 && new.if_index == 9)
        );
        t.delete(&r("0.0.0.0/0", "10.0.0.1", 9, 50)).unwrap();
        assert!(
            matches!(w.observe(&t.routes().unwrap()), Some(GatewayEvent::Lost(g)) if g.if_index == 9)
        );
        assert_eq!(w.current(), None);
        t.add(&r("0.0.0.0/0", "192.168.1.254", 7, 25)).unwrap();
        assert!(
            matches!(w.observe(&t.routes().unwrap()), Some(GatewayEvent::Found(g)) if g.next_hop == Ipv4Addr::new(192, 168, 1, 254))
        );
    }

    #[test]
    fn pins_then_restores_after_a_crash() {
        let path = tmp("crash");
        let gw = Gateway {
            next_hop: "192.168.1.1".parse().unwrap(),
            if_index: 7,
        };
        let hosts = [
            "203.0.113.5".parse().unwrap(),
            "198.51.100.9".parse().unwrap(),
        ];
        let dns_before: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let mut dns = MemDns::default();
        dns.add_interface(7, dns_before.clone());

        let (mut g, rep) = NetGuard::open(table(), dns, path.clone()).unwrap();
        assert!(rep.is_empty());
        g.pin_hosts(&hosts, gw).unwrap();
        g.pin_hosts(&hosts, gw).unwrap(); // second call is a no-op
        g.set_dns(7, &["127.0.0.1".parse().unwrap()]).unwrap();
        g.set_dns(7, &["127.0.0.2".parse().unwrap()]).unwrap(); // keeps the first "before"
        let routes_now = g.route_table().clone();
        let dns_now = g.dns().clone();
        assert_eq!(
            routes_now
                .routes()
                .unwrap()
                .iter()
                .filter(|r| r.dest.prefix == 32)
                .count(),
            2
        );
        assert_eq!(g.journal().dns[0].servers, dns_before);

        // Simulate a crash: drop the guard without restoring, keep the OS state.
        drop(g);
        let (g2, rep) = NetGuard::open(routes_now, dns_now, path.clone()).unwrap();
        assert_eq!(rep.routes_removed, 2);
        assert_eq!(rep.dns_restored, 1);
        assert!(rep.errors.is_empty());
        assert_eq!(
            g2.route_table().routes().unwrap(),
            table().routes().unwrap()
        );
        assert_eq!(g2.dns().servers(7).unwrap(), dns_before);
        assert!(g2.journal().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn repin_moves_routes_to_new_gateway() {
        let path = tmp("repin");
        let (mut g, _) = NetGuard::open(table(), MemDns::default(), path.clone()).unwrap();
        let a = Gateway {
            next_hop: "192.168.1.1".parse().unwrap(),
            if_index: 7,
        };
        let b = Gateway {
            next_hop: "10.0.0.1".parse().unwrap(),
            if_index: 9,
        };
        g.pin_hosts(&["203.0.113.5".parse().unwrap()], a).unwrap();
        g.repin(b).unwrap();
        let pins: Vec<_> = g
            .route_table()
            .routes()
            .unwrap()
            .into_iter()
            .filter(|r| r.dest.prefix == 32)
            .collect();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].if_index, 9);
        assert_eq!(g.journal().pinned, pins);
        g.restore().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_add_is_not_left_in_the_journal() {
        let path = tmp("fail");
        let mut t = table();
        t.refuse_adds = true;
        let (mut g, _) = NetGuard::open(t, MemDns::default(), path.clone()).unwrap();
        let gw = Gateway {
            next_hop: "192.168.1.1".parse().unwrap(),
            if_index: 7,
        };
        assert!(g.pin_hosts(&["203.0.113.5".parse().unwrap()], gw).is_err());
        assert!(g.journal().is_empty());
        assert!(Journal::load(&path).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn turns_ipv6_back_on_after_a_crash() {
        use mem::MemIpv6;
        let path = tmp("ipv6");
        let v6 = MemIpv6::with(&[("Ethernet", true), ("Wi-Fi", true), ("Teredo", false)]);
        let (mut g, _) = NetGuard::open_with_ipv6(
            table(),
            MemDns::default(),
            Box::new(v6.clone()),
            path.clone(),
        )
        .unwrap();
        g.note_ipv6().unwrap();
        // The router turns IPv6 off everywhere for a full tunnel, then crashes.
        v6.set("Ethernet", false);
        v6.set("Wi-Fi", false);
        drop(g);
        let (g2, rep) = NetGuard::open_with_ipv6(
            table(),
            MemDns::default(),
            Box::new(v6.clone()),
            path.clone(),
        )
        .unwrap();
        assert_eq!(
            rep.ipv6_reenabled,
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );
        assert!(v6.is_on("Ethernet") && v6.is_on("Wi-Fi"));
        assert!(!v6.is_on("Teredo"), "an adapter that was off stays off");
        assert!(g2.journal().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn restore_tolerates_vanished_interface() {
        let path = tmp("vanish");
        let mut dns = MemDns::default();
        dns.add_interface(12, vec![]);
        let (mut g, _) = NetGuard::open(table(), dns, path.clone()).unwrap();
        g.set_dns(12, &["127.0.0.1".parse().unwrap()]).unwrap();
        let mut dns_after = g.dns().clone();
        dns_after.remove_interface(12);
        let routes = g.route_table().clone();
        drop(g);
        let (g2, rep) = NetGuard::open(routes, dns_after, path.clone()).unwrap();
        assert_eq!(rep.dns_restored, 1);
        assert!(g2.journal().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn physical_gateway_adds_interface_metric_and_skips_tunnels() {
        let mut t = table();
        // By route metric alone 7 (25) beats 9 (50) and the tunnel (1) beats both.
        t.if_metrics.insert(7, 100);
        t.if_metrics.insert(9, 10);
        t.tunnels.push(TUN);
        let gw = physical_gateway(&t, &[]).unwrap().unwrap();
        assert_eq!(gw.if_index, 9, "25 + 100 loses to 50 + 10");
        t.if_metrics.insert(9, 80);
        assert_eq!(physical_gateway(&t, &[]).unwrap().unwrap().if_index, 7);
        // With nothing but the tunnel left there is no physical gateway.
        t.table.retain(|r| r.if_index == TUN);
        assert_eq!(physical_gateway(&t, &[]).unwrap(), None);
    }

    #[test]
    fn watcher_on_a_live_table_ignores_the_tunnel() {
        let mut t = table();
        t.tunnels.push(TUN);
        let mut w = GatewayWatcher::default();
        assert!(
            matches!(w.observe_table(&t).unwrap(), Some(GatewayEvent::Found(g)) if g.if_index == 7)
        );
    }

    #[test]
    fn ipv6_for_a_removed_adapter_is_dropped_not_retried() {
        use mem::MemIpv6;
        let path = tmp("v6gone");
        let v6 = MemIpv6::with(&[("Ethernet", true), ("USB", true)]);
        let (mut g, _) = NetGuard::open_with_ipv6(
            table(),
            MemDns::default(),
            Box::new(v6.clone()),
            path.clone(),
        )
        .unwrap();
        g.note_ipv6().unwrap();
        v6.set("Ethernet", false);
        // The USB adapter is unplugged (or renamed): enable() says NotFound.
        v6.remove("USB");
        drop(g);
        let open = || {
            NetGuard::open_with_ipv6(
                table(),
                MemDns::default(),
                Box::new(v6.clone()),
                path.clone(),
            )
            .unwrap()
        };
        let (g2, rep) = open();
        assert_eq!(rep.ipv6_reenabled, vec!["Ethernet".to_string()]);
        assert_eq!(rep.ipv6_gone, vec!["USB".to_string()]);
        assert!(rep.errors.is_empty());
        assert!(g2.journal().is_empty());
        drop(g2);
        let (_, rep) = open();
        assert!(
            rep.is_empty(),
            "nothing left to do on the next start: {rep:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn powershell_errors() {
        assert_eq!(ps_error(Some(3), "").kind(), io::ErrorKind::NotFound);
        let e = ps_error(
            Some(1),
            "Enable-NetAdapterBinding : No MSFT_NetAdapterBindingSettingData objects found with property 'Name' equal to 'USB'.\n    + CategoryInfo          : ObjectNotFound: (USB:String)",
        );
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            ps_error(Some(1), "Access is denied.").kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn other_vpn_with_a_default_route_is_named() {
        let mut t = MemRoutes::with(vec![
            r("0.0.0.0/0", "192.168.1.254", 17, 0),
            r("0.0.0.0/0", "10.3.0.1", 12, 1),
            r("0.0.0.0/1", "10.192.0.0", 49, 2),
            r("128.0.0.0/1", "10.192.0.0", 49, 2),
        ]);
        t.tunnels = vec![12, 49];
        t.names.insert("NordWhisper".into(), 12);
        t.names.insert("sr-tun0".into(), 49);
        assert_eq!(
            other_vpn_defaults(&t).unwrap(),
            vec!["NordWhisper".to_string()]
        );
        t.table.retain(|r| r.if_index != 12);
        assert!(other_vpn_defaults(&t).unwrap().is_empty());
    }
}
