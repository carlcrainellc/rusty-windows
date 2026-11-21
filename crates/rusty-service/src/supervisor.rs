//! Starts the router, watches it, restarts it on crash, and puts the network back.

use crate::guard::{ExitView, Guard, GuardTimes, LastRollback};
use crate::policy::{CrashHistory, Decision, RestartPolicy};
use crate::sweep;
use rusty_net::{physical_gateway, DnsSettings, NetGuard, RouteTable};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub trait Child {
    /// `Some(code)` once the process has exited.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    fn kill(&mut self) -> io::Result<()>;
}

pub trait Launcher {
    type C: Child;
    fn spawn(&mut self) -> io::Result<Self::C>;
}

/// The router's control channel, as far as the supervisor needs it.
pub trait Control {
    /// True once the router answers RPC.
    fn ready(&mut self) -> bool;
    /// Asks for a clean shutdown. Errors are fine; we kill it after a timeout anyway.
    fn halt(&mut self);
    /// Mapped exits, or `None` if the router didn't answer.
    fn exits(&mut self) -> Option<Vec<ExitView>> {
        None
    }
    /// Unmaps one exit. The router takes its routes down.
    fn unmap(&mut self, _address: &str) -> Result<(), String> {
        Err("not supported".into())
    }
}

#[derive(Clone, Default)]
pub struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Stopped,
    GaveUp {
        crashes: usize,
        last_code: Option<i32>,
    },
}

pub struct Options {
    pub policy: RestartPolicy,
    pub set_dns: Option<IpAddr>,
    /// Adapter whose DNS to point at the router. When unset, the physical uplink: the
    /// best default route by effective metric that isn't on a tunnel adapter.
    pub dns_interface: Option<String>,
    /// How often to check DNS is still on the right adapter and still ours.
    pub dns_recheck: Duration,
    pub stop_timeout: Duration,
    pub poll: Duration,
    /// Exit guard timings; `None` turns the guard off.
    pub guard: Option<GuardTimes>,
    /// How often the guard looks.
    pub guard_every: Duration,
    /// Where the guard writes what it last did (`exit-guard.json`).
    pub guard_file: Option<PathBuf>,
}

pub type Log<'a> = &'a mut dyn FnMut(&str);

#[derive(Default)]
struct DnsState {
    /// Interface we pointed at the router, if any.
    if_index: Option<u32>,
    /// Already logged that there was nowhere to put DNS.
    said_none: bool,
}

pub struct Supervisor<L: Launcher, K: Control, R: RouteTable, D: DnsSettings> {
    pub launcher: L,
    pub control: K,
    pub net: NetGuard<R, D>,
    pub opts: Options,
}

impl<L: Launcher, K: Control, R: RouteTable, D: DnsSettings> Supervisor<L, K, R, D> {
    /// Sleeps in small steps so a stop request is noticed quickly. Returns false if stopped.
    fn wait(&self, stop: &StopFlag, d: Duration) -> bool {
        let end = Instant::now() + d;
        while Instant::now() < end {
            if stop.is_set() {
                return false;
            }
            std::thread::sleep(
                self.opts
                    .poll
                    .min(end.saturating_duration_since(Instant::now())),
            );
        }
        !stop.is_set()
    }

    fn cleanup(&mut self, before: &[rusty_net::Route], log: Log) {
        match self.net.restore() {
            Ok(rep) if !rep.is_empty() => log(&format!(
                "put back {} route(s) and DNS on {} interface(s){}{}{}",
                rep.routes_removed,
                rep.dns_restored,
                if rep.ipv6_reenabled.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; turned IPv6 back on for {}",
                        rep.ipv6_reenabled.join(", ")
                    )
                },
                if rep.ipv6_gone.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; forgot IPv6 state for adapters that are gone: {}",
                        rep.ipv6_gone.join(", ")
                    )
                },
                if rep.errors.is_empty() {
                    String::new()
                } else {
                    format!("; problems: {}", rep.errors.join("; "))
                }
            )),
            Ok(_) => {}
            Err(e) => log(&format!("couldn't restore network settings: {e}")),
        }
        let after = match self.net.route_table().routes() {
            Ok(a) => a,
            Err(e) => return log(&format!("couldn't read routes: {e}")),
        };
        let gone = sweep::vanished_loopback(before, &after);
        if !gone.is_empty() {
            let mut back = 0;
            for r in &gone {
                if self.net_routes_mut().add(r).is_ok() {
                    back += 1;
                }
            }
            log(&format!(
                "put back {back} loopback route(s) the router removed"
            ));
        }
        let table = self.net.route_table();
        let left = sweep::leftovers_except(before, &after, |i| {
            table.is_tunnel(i)
                && !table
                    .name_of(i)
                    .is_some_and(|n| rusty_net::vpn::is_own_adapter(&n))
        });
        if left.is_empty() {
            return;
        }
        let mut removed = 0;
        for r in &left {
            if self.net_routes_mut().delete(r).is_ok() {
                removed += 1;
            }
        }
        log(&format!(
            "removed {removed} route(s) the router left behind"
        ));
    }

    /// The interface whose DNS should point at the router right now.
    fn dns_target(&self) -> io::Result<Option<u32>> {
        match &self.opts.dns_interface {
            Some(name) => self.net.route_table().index_of(name),
            None => Ok(physical_gateway(self.net.route_table(), &[])?.map(|g| g.if_index)),
        }
    }

    /// Points DNS at the router on the physical adapter, follows the adapter if the
    /// uplink moves, and puts our server back if something else changed it.
    fn check_dns(&mut self, dns: IpAddr, st: &mut DnsState, log: Log) {
        let target = match self.dns_target() {
            Ok(Some(t)) => t,
            Ok(None) => {
                if !st.said_none {
                    st.said_none = true;
                    match &self.opts.dns_interface {
                        Some(n) => log(&format!("no adapter named {n}; leaving DNS alone")),
                        None => log("no physical default gateway; leaving DNS alone"),
                    }
                }
                return;
            }
            Err(e) => return log(&format!("couldn't pick an interface for DNS: {e}")),
        };
        st.said_none = false;
        if st.if_index != Some(target) {
            if let Some(old) = st.if_index {
                match self.net.restore_dns(old) {
                    Ok(()) => log(&format!(
                        "uplink moved to interface {target}; DNS on interface {old} put back"
                    )),
                    Err(e) => log(&format!("couldn't put back DNS on interface {old}: {e}")),
                }
            }
            match self.net.set_dns(target, &[dns]) {
                Ok(()) => {
                    st.if_index = Some(target);
                    log(&format!("DNS on interface {target} now {dns}"));
                }
                Err(e) => log(&format!("couldn't set DNS: {e}")),
            }
            return;
        }
        match self.net.dns().servers(target) {
            Ok(now) if now == [dns] => {}
            Ok(now) => match self.net.set_dns(target, &[dns]) {
                Ok(()) => log(&format!(
                    "DNS on interface {target} had changed to {}; set back to {dns}",
                    rusty_net::format_server_list(&now)
                )),
                Err(e) => log(&format!("couldn't set DNS: {e}")),
            },
            Err(e) => log(&format!("couldn't read DNS on interface {target}: {e}")),
        }
    }

    /// One look by the exit guard. Unmaps what it says to and remembers to check, a few
    /// seconds later, that nothing of ours is left holding the route.
    fn check_exits(&mut self, g: &mut GuardRun, log: Log) {
        let Some(exits) = self.control.exits() else {
            return;
        };
        let now = Instant::now();
        let other = match rusty_net::vpn::other_vpn(self.net.route_table()) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("couldn't read routes for the exit guard: {e}"));
                None
            }
        };
        let first_look = !g.uplink_seen;
        g.uplink_seen = true;
        if let Some(gw) = g
            .uplink
            .observe_table(self.net.route_table())
            .ok()
            .flatten()
        {
            if !exits.is_empty() && !first_look {
                let what = match gw {
                    rusty_net::GatewayEvent::Lost(o) => format!("uplink {} went away", o.next_hop),
                    rusty_net::GatewayEvent::Found(n) => format!("uplink is {}", n.next_hop),
                    rusty_net::GatewayEvent::Changed { old, new } => {
                        format!("uplink moved from {} to {}", old.next_hop, new.next_hop)
                    }
                };
                log(&format!(
                    "{what} while an exit is mapped; the router moves its first hops"
                ));
            }
        }
        if let Some(u) = g.guard.tick(now, &exits, other.as_ref()) {
            log(&format!("exit guard: {}", u.message));
            for a in &u.addresses {
                if let Err(e) = self.control.unmap(a) {
                    log(&format!("exit guard: couldn't unmap {a}: {e}"));
                }
            }
            if let Some(path) = &self.opts.guard_file {
                let rec = LastRollback {
                    time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    addresses: u.addresses.clone(),
                    why: u.why.clone(),
                    message: u.message.clone(),
                };
                if let Ok(b) = serde_json::to_vec_pretty(&rec) {
                    let tmp = path.with_extension("json.tmp");
                    if std::fs::write(&tmp, b)
                        .and_then(|_| std::fs::rename(&tmp, path))
                        .is_err()
                    {
                        log(&format!("couldn't write {}", path.display()));
                    }
                }
            }
            g.settle_at = Some(now + Duration::from_secs(5));
            g.rolled_back = true;
            return;
        }
        // Nothing mapped, but our tunnel still carries the traffic: the router didn't take
        // its routes down (or a rollback just happened). Two looks in a row, then clean up.
        let stale = exits.is_empty()
            && rusty_net::vpn::own_tunnel_holds(self.net.route_table()).unwrap_or(false);
        g.stale_looks = if stale { g.stale_looks + 1 } else { 0 };
        let settle_due = g.settle_at.is_some_and(|t| now >= t) && exits.is_empty();
        if g.stale_looks >= 2 || settle_due {
            g.settle_at = None;
            g.stale_looks = 0;
            self.settle(std::mem::take(&mut g.rolled_back), log);
        }
    }

    /// After a rollback: remove our full-tunnel routes if they're still there and turn IPv6
    /// back on where the router left it off.
    fn settle(&mut self, ipv6_too: bool, log: Log) {
        let routes = match self.net.route_table().routes() {
            Ok(r) => r,
            Err(e) => return log(&format!("couldn't read routes: {e}")),
        };
        let mine: Vec<rusty_net::Route> = routes
            .into_iter()
            .filter(|r| rusty_net::vpn::is_half_default(&r.dest))
            .filter(|r| {
                self.net
                    .route_table()
                    .name_of(r.if_index)
                    .is_some_and(|n| rusty_net::vpn::is_own_adapter(&n))
            })
            .collect();
        let mut removed = 0;
        for r in &mine {
            if self.net_routes_mut().delete(r).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            log(&format!(
                "removed {removed} tunnel route(s) left with no exit mapped"
            ));
        }
        if ipv6_too {
            match self.net.reenable_ipv6() {
                Ok(v) if !v.is_empty() => log(&format!("turned IPv6 back on for {}", v.join(", "))),
                Ok(_) => {}
                Err(e) => log(&format!("couldn't turn IPv6 back on: {e}")),
            }
        }
    }

    fn net_routes_mut(&mut self) -> &mut R {
        self.net.route_table_mut()
    }

    pub fn run(&mut self, stop: &StopFlag, log: Log) -> io::Result<Outcome> {
        let mut history = CrashHistory::default();
        loop {
            if stop.is_set() {
                return Ok(Outcome::Stopped);
            }
            let before = self.net.route_table().routes()?;
            if let Err(e) = self.net.note_ipv6() {
                log(&format!("couldn't read IPv6 state: {e}"));
            }
            let mut child = self.launcher.spawn()?;
            log("router started");
            let mut ready = false;
            let mut next_dns_check = Instant::now();
            let mut dns_state = DnsState::default();
            let mut guard_run = self.opts.guard.map(GuardRun::new);
            let mut next_guard_check = Instant::now();
            let code = loop {
                if stop.is_set() {
                    log("stopping router");
                    self.control.halt();
                    let deadline = Instant::now() + self.opts.stop_timeout;
                    let mut exited = false;
                    while Instant::now() < deadline {
                        if child.try_wait()?.is_some() {
                            exited = true;
                            break;
                        }
                        std::thread::sleep(self.opts.poll);
                    }
                    if !exited {
                        log("router didn't stop in time; ending it");
                        let _ = child.kill();
                        let _ = child.try_wait();
                    }
                    self.cleanup(&before, log);
                    return Ok(Outcome::Stopped);
                }
                if let Some(code) = child.try_wait()? {
                    break code;
                }
                if (self.opts.set_dns.is_some() || guard_run.is_some()) && !ready {
                    ready = self.control.ready();
                }
                if let Some(dns) = self.opts.set_dns {
                    if ready && Instant::now() >= next_dns_check {
                        next_dns_check = Instant::now() + self.opts.dns_recheck;
                        self.check_dns(dns, &mut dns_state, log);
                    }
                }
                if let Some(g) = guard_run.as_mut() {
                    if ready && Instant::now() >= next_guard_check {
                        next_guard_check = Instant::now() + self.opts.guard_every;
                        self.check_exits(g, log);
                    }
                }
                std::thread::sleep(self.opts.poll);
            };
            log(&format!("router exited with code {code}"));
            self.cleanup(&before, log);
            match history.on_exit(&self.opts.policy, Instant::now()) {
                Decision::RestartAfter(d) => {
                    log(&format!("restarting in {}s", d.as_secs_f32()));
                    if !self.wait(stop, d) {
                        return Ok(Outcome::Stopped);
                    }
                }
                Decision::GiveUp { crashes } => {
                    log(&format!(
                        "router exited {crashes} times in a short time; not restarting it"
                    ));
                    return Ok(Outcome::GaveUp {
                        crashes,
                        last_code: Some(code),
                    });
                }
            }
        }
    }
}

/// The guard's state for one router run.
struct GuardRun {
    guard: Guard,
    uplink: rusty_net::GatewayWatcher,
    settle_at: Option<Instant>,
    rolled_back: bool,
    stale_looks: u32,
    uplink_seen: bool,
}

impl GuardRun {
    fn new(times: GuardTimes) -> Self {
        GuardRun {
            guard: Guard::new(times),
            uplink: rusty_net::GatewayWatcher::new(Vec::new()),
            settle_at: None,
            rolled_back: false,
            stale_looks: 0,
            uplink_seen: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_net::mem::{MemDns, MemRoutes};
    use rusty_net::{Ipv4Net, Route};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Shared fake world: the route table the "router" scribbles on.
    type World = Rc<RefCell<MemRoutes>>;

    #[derive(Clone)]
    struct WorldRoutes(World);
    impl RouteTable for WorldRoutes {
        fn routes(&self) -> io::Result<Vec<Route>> {
            self.0.borrow().routes()
        }
        fn add(&mut self, r: &Route) -> io::Result<()> {
            self.0.borrow_mut().add(r)
        }
        fn delete(&mut self, r: &Route) -> io::Result<()> {
            self.0.borrow_mut().delete(r)
        }
        fn interface_metric(&self, i: u32) -> io::Result<u32> {
            self.0.borrow().interface_metric(i)
        }
        fn is_tunnel(&self, i: u32) -> bool {
            self.0.borrow().is_tunnel(i)
        }
        fn index_of(&self, n: &str) -> io::Result<Option<u32>> {
            self.0.borrow().index_of(n)
        }
        fn name_of(&self, i: u32) -> Option<String> {
            self.0.borrow().name_of(i)
        }
        fn description_of(&self, i: u32) -> Option<String> {
            self.0.borrow().description_of(i)
        }
    }

    struct FakeChild {
        polls_left: Option<u32>,
        code: i32,
        killed: Rc<RefCell<u32>>,
        dead: bool,
    }
    impl Child for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            if self.dead {
                return Ok(Some(self.code));
            }
            match &mut self.polls_left {
                Some(0) => {
                    self.dead = true;
                    Ok(Some(self.code))
                }
                Some(n) => {
                    *n -= 1;
                    Ok(None)
                }
                None => Ok(None),
            }
        }
        fn kill(&mut self) -> io::Result<()> {
            *self.killed.borrow_mut() += 1;
            self.dead = true;
            Ok(())
        }
    }

    /// Each spawn adds a first-hop pin like the real router, then dies after a few polls.
    struct CrashyLauncher {
        world: World,
        spawns: u32,
        lifetime: Option<u32>,
        killed: Rc<RefCell<u32>>,
    }
    impl Launcher for CrashyLauncher {
        type C = FakeChild;
        fn spawn(&mut self) -> io::Result<FakeChild> {
            self.spawns += 1;
            let hop = Route {
                dest: Ipv4Net::host(std::net::Ipv4Addr::new(198, 51, 100, self.spawns as u8)),
                next_hop: "192.168.1.1".parse().unwrap(),
                if_index: 7,
                metric: 5,
            };
            self.world.borrow_mut().add(&hop)?;
            Ok(FakeChild {
                polls_left: self.lifetime,
                code: 3,
                killed: self.killed.clone(),
                dead: false,
            })
        }
    }

    struct FakeControl {
        halts: u32,
        stop_on_ready: Option<StopFlag>,
    }
    impl Control for FakeControl {
        fn ready(&mut self) -> bool {
            if let Some(s) = &self.stop_on_ready {
                s.stop();
            }
            true
        }
        fn halt(&mut self) {
            self.halts += 1;
        }
    }

    fn world() -> World {
        Rc::new(RefCell::new(MemRoutes::with(vec![Route {
            dest: Ipv4Net::DEFAULT,
            next_hop: "192.168.1.1".parse().unwrap(),
            if_index: 7,
            metric: 25,
        }])))
    }

    fn opts(set_dns: Option<IpAddr>) -> Options {
        Options {
            policy: RestartPolicy {
                max_crashes: 3,
                first_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                ..Default::default()
            },
            set_dns,
            dns_interface: None,
            dns_recheck: Duration::ZERO,
            stop_timeout: Duration::from_millis(30),
            poll: Duration::from_millis(1),
            guard: None,
            guard_every: Duration::ZERO,
            guard_file: None,
        }
    }

    fn journal(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rusty-sup-{}-{name}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn crash_loop_gives_up_and_leaves_network_clean() {
        let w = world();
        let clean = w.borrow().clone();
        let mut dns = MemDns::default();
        dns.add_interface(7, vec!["192.168.1.1".parse().unwrap()]);
        let (net, _) = NetGuard::open(WorldRoutes(w.clone()), dns, journal("loop")).unwrap();
        let killed = Rc::new(RefCell::new(0));
        let mut s = Supervisor {
            launcher: CrashyLauncher {
                world: w.clone(),
                spawns: 0,
                lifetime: Some(3),
                killed: killed.clone(),
            },
            control: FakeControl {
                halts: 0,
                stop_on_ready: None,
            },
            net,
            opts: opts(Some("127.0.0.1".parse().unwrap())),
        };
        let mut lines = Vec::new();
        let out = s
            .run(&StopFlag::default(), &mut |l| lines.push(l.to_string()))
            .unwrap();
        assert_eq!(
            out,
            Outcome::GaveUp {
                crashes: 3,
                last_code: Some(3)
            }
        );
        assert_eq!(s.launcher.spawns, 3);
        // Every first-hop pin the "router" left is gone, and DNS is back.
        assert_eq!(*w.borrow(), clean);
        assert_eq!(
            s.net.dns().servers(7).unwrap(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert!(s.net.journal().is_empty());
        assert!(lines.iter().any(|l| l.contains("left behind")));
    }

    #[test]
    fn stop_asks_nicely_then_kills_and_cleans_up() {
        let w = world();
        let clean = w.borrow().clone();
        let stop = StopFlag::default();
        let mut dns = MemDns::default();
        dns.add_interface(7, vec![]);
        let (net, _) = NetGuard::open(WorldRoutes(w.clone()), dns, journal("stop")).unwrap();
        let killed = Rc::new(RefCell::new(0));
        let mut s = Supervisor {
            launcher: CrashyLauncher {
                world: w.clone(),
                spawns: 0,
                lifetime: None,
                killed: killed.clone(),
            },
            control: FakeControl {
                halts: 0,
                stop_on_ready: Some(stop.clone()),
            },
            net,
            opts: opts(Some("127.0.0.1".parse().unwrap())),
        };
        let out = s.run(&stop, &mut |_| {}).unwrap();
        assert_eq!(out, Outcome::Stopped);
        assert_eq!(s.control.halts, 1);
        assert_eq!(
            *killed.borrow(),
            1,
            "router ignored halt, so it gets killed"
        );
        assert_eq!(*w.borrow(), clean);
        assert_eq!(s.net.dns().servers(7).unwrap(), Vec::<IpAddr>::new());
    }

    const TUN: u32 = 40;

    fn r(dest: &str, hop: &str, ifx: u32, metric: u32) -> Route {
        Route {
            dest: dest.parse().unwrap(),
            next_hop: hop.parse().unwrap(),
            if_index: ifx,
            metric,
        }
    }

    /// (poll number, change to the world) pairs.
    type Steps = Vec<(u32, fn(&mut MemRoutes))>;

    /// Child that runs a script against the world on given polls, then exits.
    struct ScriptChild {
        world: World,
        polls: u32,
        steps: Steps,
        die_at: u32,
    }
    impl Child for ScriptChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            self.polls += 1;
            for (at, f) in &self.steps {
                if *at == self.polls {
                    f(&mut self.world.borrow_mut());
                }
            }
            Ok((self.polls >= self.die_at).then_some(0))
        }
        fn kill(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A router that brings up its tunnel with the best default route on the machine.
    struct TunnelLauncher {
        world: World,
        steps: Steps,
        die_at: u32,
    }
    impl Launcher for TunnelLauncher {
        type C = ScriptChild;
        fn spawn(&mut self) -> io::Result<ScriptChild> {
            self.world
                .borrow_mut()
                .add(&r("0.0.0.0/0", "10.192.0.2", TUN, 0))?;
            Ok(ScriptChild {
                world: self.world.clone(),
                polls: 0,
                steps: self.steps.clone(),
                die_at: self.die_at,
            })
        }
    }

    fn tunnel_world() -> World {
        let mut m = MemRoutes::with(vec![
            r("0.0.0.0/0", "192.168.1.1", 7, 0),
            r("0.0.0.0/0", "10.0.0.1", 9, 0),
        ]);
        // Ethernet (7) has interface metric 5; the backup (9) has 50; the tunnel 1.
        m.if_metrics.insert(7, 5);
        m.if_metrics.insert(9, 50);
        m.if_metrics.insert(TUN, 1);
        m.tunnels.push(TUN);
        m.names.insert("Backup".into(), 9);
        Rc::new(RefCell::new(m))
    }

    fn tunnel_dns() -> MemDns {
        let mut dns = MemDns::default();
        dns.add_interface(7, vec!["192.168.1.1".parse().unwrap()]);
        dns.add_interface(9, vec![]);
        dns.add_interface(TUN, vec![]);
        dns
    }

    fn run_once(
        w: &World,
        name: &str,
        steps: Steps,
        dns_interface: Option<&str>,
    ) -> (
        Supervisor<TunnelLauncher, FakeControl, WorldRoutes, MemDns>,
        Vec<String>,
    ) {
        let (net, _) = NetGuard::open(WorldRoutes(w.clone()), tunnel_dns(), journal(name)).unwrap();
        let mut o = opts(Some("127.0.0.1".parse().unwrap()));
        o.policy.max_crashes = 1;
        o.dns_interface = dns_interface.map(str::to_string);
        let mut s = Supervisor {
            launcher: TunnelLauncher {
                world: w.clone(),
                steps,
                die_at: 20,
            },
            control: FakeControl {
                halts: 0,
                stop_on_ready: None,
            },
            net,
            opts: o,
        };
        let mut lines = Vec::new();
        let stop = StopFlag::default();
        s.run(&stop, &mut |l| lines.push(l.to_string())).unwrap();
        (s, lines)
    }

    fn set_lines(lines: &[String]) -> Vec<&String> {
        lines
            .iter()
            .filter(|l| l.contains(" now 127.0.0.1"))
            .collect()
    }

    #[test]
    fn dns_goes_on_physical_adapter_not_the_tunnel() {
        let w = tunnel_world();
        // The tunnel's default (0 + 1) beats Ethernet's (0 + 5), so a plain
        // lowest-metric pick would put DNS on the tunnel.
        let (s, lines) = run_once(&w, "dns-tun", vec![], None);
        assert_eq!(set_lines(&lines), vec!["DNS on interface 7 now 127.0.0.1"]);
        // Never touched the tunnel or the backup, and Ethernet is back as it was.
        assert_eq!(s.net.dns().servers(TUN).unwrap(), Vec::<IpAddr>::new());
        assert_eq!(s.net.dns().servers(9).unwrap(), Vec::<IpAddr>::new());
        assert_eq!(
            s.net.dns().servers(7).unwrap(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn interface_metric_decides_the_uplink() {
        let w = tunnel_world();
        {
            // Route metrics now favour 9 (0 vs 10), but 9's interface metric (50) makes
            // its effective metric 50 against Ethernet's 15.
            let mut m = w.borrow_mut();
            m.table[0].metric = 10;
        }
        let (_, lines) = run_once(&w, "dns-ifm", vec![], None);
        assert_eq!(set_lines(&lines), vec!["DNS on interface 7 now 127.0.0.1"]);
    }

    #[test]
    fn dns_follows_the_uplink_and_is_put_back() {
        let w = tunnel_world();
        // Poll 5: Ethernet goes away (adapter disabled). Poll 10: it comes back.
        let steps: Steps = vec![
            (5, |m| {
                m.table.retain(|x| x.if_index != 7);
            }),
            (10, |m| {
                m.table.push(Route {
                    dest: Ipv4Net::DEFAULT,
                    next_hop: "192.168.1.1".parse().unwrap(),
                    if_index: 7,
                    metric: 0,
                });
            }),
        ];
        let (s, lines) = run_once(&w, "dns-move", steps, None);
        assert_eq!(
            set_lines(&lines),
            vec![
                "DNS on interface 7 now 127.0.0.1",
                "DNS on interface 9 now 127.0.0.1",
                "DNS on interface 7 now 127.0.0.1",
            ]
        );
        assert!(lines
            .iter()
            .any(|l| l.contains("DNS on interface 7 put back")));
        assert_eq!(s.net.dns().servers(9).unwrap(), Vec::<IpAddr>::new());
        assert_eq!(
            s.net.dns().servers(7).unwrap(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert!(s.net.journal().is_empty());
    }

    #[test]
    fn configured_adapter_wins() {
        let w = tunnel_world();
        let (_, lines) = run_once(&w, "dns-cfg", vec![], Some("Backup"));
        assert_eq!(set_lines(&lines), vec!["DNS on interface 9 now 127.0.0.1"]);
        let (_, lines) = run_once(&tunnel_world(), "dns-cfg2", vec![], Some("Nope"));
        assert!(set_lines(&lines).is_empty());
        assert!(lines
            .iter()
            .any(|l| l == "no adapter named Nope; leaving DNS alone"));
    }

    /// Router control for guard tests: one exit mapped (never live); unmapping it takes
    /// it off the list but, like a misbehaving router, leaves the tunnel's /1 routes.
    struct GuardControl {
        mapped: Rc<RefCell<Vec<String>>>,
        unmapped: Rc<RefCell<Vec<String>>>,
    }
    impl Control for GuardControl {
        fn ready(&mut self) -> bool {
            true
        }
        fn halt(&mut self) {}
        fn exits(&mut self) -> Option<Vec<ExitView>> {
            Some(
                self.mapped
                    .borrow()
                    .iter()
                    .map(|a| ExitView {
                        address: a.clone(),
                        live: false,
                    })
                    .collect(),
            )
        }
        fn unmap(&mut self, address: &str) -> Result<(), String> {
            self.mapped.borrow_mut().retain(|a| a != address);
            self.unmapped.borrow_mut().push(address.to_string());
            Ok(())
        }
    }

    fn guard_world() -> World {
        let mut m = MemRoutes::with(vec![
            r("0.0.0.0/0", "192.168.1.1", 7, 25),
            r("0.0.0.0/1", "10.192.0.0", TUN, 5),
            r("128.0.0.0/1", "10.192.0.0", TUN, 5),
        ]);
        m.if_metrics.insert(7, 35);
        m.if_metrics.insert(TUN, 5);
        m.tunnels.push(TUN);
        m.names.insert("sr-tun0".into(), TUN);
        Rc::new(RefCell::new(m))
    }

    fn run_guarded(
        w: &World,
        name: &str,
        steps: Steps,
    ) -> (Vec<String>, Vec<String>, std::path::PathBuf) {
        let (net, _) = NetGuard::open(WorldRoutes(w.clone()), tunnel_dns(), journal(name)).unwrap();
        let mut o = opts(None);
        o.policy.max_crashes = 1;
        o.guard = Some(GuardTimes {
            map_timeout: Duration::from_millis(20),
            lost_grace: Duration::from_millis(20),
        });
        let gf = journal(&format!("{name}-guard"));
        o.guard_file = Some(gf.clone());
        let unmapped = Rc::new(RefCell::new(Vec::new()));
        let mut s = Supervisor {
            launcher: TunnelLauncher {
                world: w.clone(),
                steps,
                die_at: 400,
            },
            control: GuardControl {
                mapped: Rc::new(RefCell::new(vec!["x.sesh".into()])),
                unmapped: unmapped.clone(),
            },
            net,
            opts: o,
        };
        let mut lines = Vec::new();
        s.run(&StopFlag::default(), &mut |l| lines.push(l.to_string()))
            .unwrap();
        let u = unmapped.borrow().clone();
        (lines, u, gf)
    }

    #[test]
    fn guard_unmaps_a_dead_exit_and_clears_our_routes() {
        let w = guard_world();
        let (lines, unmapped, gf) = run_guarded(&w, "guard-dead", vec![]);
        assert_eq!(unmapped, vec!["x.sesh".to_string()]);
        assert!(
            lines.iter().any(|l| l.contains("isn't answering")),
            "{lines:#?}"
        );
        let rec: LastRollback = serde_json::from_slice(&std::fs::read(&gf).unwrap()).unwrap();
        assert_eq!(rec.why, crate::guard::Why::ExitNotAnswering);
        // The /1 halves the router left are gone; the uplink's default route stays.
        let left = w.borrow().table.clone();
        assert!(
            !left
                .iter()
                .any(|x| rusty_net::vpn::is_half_default(&x.dest)),
            "{left:?}"
        );
        assert!(left.iter().any(|x| x.dest.is_default() && x.if_index == 7));
        let _ = std::fs::remove_file(gf);
    }

    #[test]
    fn guard_unmaps_when_another_vpn_takes_over() {
        let w = guard_world();
        // Nord comes up on poll 2 with a better /1 pair; the guard sees it before the
        // map timeout matters.
        let steps: Steps = vec![(2, |m| {
            m.table.push(r("0.0.0.0/1", "10.8.1.1", 23, 0));
            m.table.push(r("128.0.0.0/1", "10.8.1.1", 23, 0));
            m.if_metrics.insert(23, 1);
            m.tunnels.push(23);
            m.names.insert("NordLynx".into(), 23);
        })];
        let (lines, unmapped, gf) = run_guarded(&w, "guard-vpn", steps);
        assert_eq!(unmapped, vec!["x.sesh".to_string()]);
        let rec: LastRollback = serde_json::from_slice(&std::fs::read(&gf).unwrap()).unwrap();
        assert!(
            rec.why == crate::guard::Why::OtherVpn
                || rec.why == crate::guard::Why::ExitNotAnswering,
            "{lines:#?}"
        );
        // Nord's own routes are never touched.
        assert_eq!(
            w.borrow().table.iter().filter(|x| x.if_index == 23).count(),
            2
        );
        let _ = std::fs::remove_file(gf);
    }
}
