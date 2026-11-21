//! Is another VPN handling this computer's traffic?
//!
//! Windows sends a packet by the most specific matching route, and among equally specific
//! ones the lowest route metric plus interface metric. Another VPN takes over either with
//! a default route that beats the uplink's, or with the `0.0.0.0/1` + `128.0.0.0/1` pair
//! (OpenVPN, NordVPN and others), which beats any default route. Mapping an exit while
//! that is going on doesn't work: the other VPN's routes win over the exit's, and its own
//! firewall often drops the router's traffic. So we look at who would carry ordinary
//! internet traffic right now and refuse to map if it's someone else's tunnel.

use crate::{Ipv4Net, Route, RouteTable};
use serde::Serialize;
use std::io;
use std::net::Ipv4Addr;

/// Addresses we ask "which route carries this?" for, one in each /1 half.
const PROBES: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(208, 67, 222, 222)];

/// Another VPN that carries ordinary internet traffic right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtherVpn {
    /// What to call it in a message: "NordVPN", or the adapter name.
    pub name: String,
    /// The adapter name Windows shows ("NordLynx").
    pub adapter: String,
    pub if_index: u32,
    /// The route that wins, e.g. "0.0.0.0/1".
    pub route: String,
}

impl OtherVpn {
    /// The line SeshSwap and rusty-ctl show.
    pub fn message(&self) -> String {
        format!(
            "Another VPN is still holding your connection ({}). Disconnect it or turn off its kill switch, then map again.",
            self.name
        )
    }
}

/// The route Windows would use for `dst`: longest prefix, then lowest route + interface
/// metric, then lowest interface index.
pub fn route_for(
    routes: &[Route],
    dst: Ipv4Addr,
    if_metric: impl Fn(u32) -> Option<u32>,
) -> Option<&Route> {
    routes
        .iter()
        .filter(|r| r.dest.contains(dst))
        // An interface with no IPv4 metric is gone or down; Windows won't use it.
        .filter_map(|r| if_metric(r.if_index).map(|m| (r, r.metric.saturating_add(m))))
        .min_by_key(|(r, m)| (std::cmp::Reverse(r.dest.prefix), *m, r.if_index))
        .map(|(r, _)| r)
}

/// Session Router's own adapter. Its routes are ours, not another VPN's.
pub fn is_own_adapter(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("sr-tun") || n.starts_with("session-router") || n.starts_with("sessionrouter")
}

/// A friendlier name for well-known VPNs, from the adapter's name and description.
pub fn vpn_brand(alias: &str, description: &str) -> String {
    let both = format!("{} {}", alias, description).to_ascii_lowercase();
    const BRANDS: [(&str, &str); 12] = [
        ("nord", "NordVPN"),
        ("proton", "Proton VPN"),
        ("mullvad", "Mullvad"),
        ("expressvpn", "ExpressVPN"),
        ("surfshark", "Surfshark"),
        ("windscribe", "Windscribe"),
        ("private internet access", "Private Internet Access"),
        ("pia", "Private Internet Access"),
        ("cyberghost", "CyberGhost"),
        ("tailscale", "Tailscale"),
        ("wireguard", "WireGuard"),
        ("openvpn", "OpenVPN"),
    ];
    for (needle, brand) in BRANDS {
        let hit = if needle == "pia" {
            both.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == "pia")
        } else {
            both.contains(needle)
        };
        if hit {
            return brand.to_string();
        }
    }
    if both.contains("tap-windows") {
        return "OpenVPN".to_string();
    }
    if alias.is_empty() {
        "a VPN".to_string()
    } else {
        alias.to_string()
    }
}

/// Another VPN that holds the route for ordinary internet traffic, if any. Pure: takes the
/// table and lookups, so tests can feed it any shape.
pub fn other_vpn_in(
    routes: &[Route],
    if_metric: impl Fn(u32) -> Option<u32>,
    is_tunnel: impl Fn(u32) -> bool,
    alias: impl Fn(u32) -> Option<String>,
    description: impl Fn(u32) -> Option<String>,
) -> Option<OtherVpn> {
    for dst in PROBES {
        let Some(r) = route_for(routes, dst, &if_metric) else {
            continue;
        };
        let a = alias(r.if_index).unwrap_or_default();
        if is_own_adapter(&a) || !is_tunnel(r.if_index) {
            continue;
        }
        let d = description(r.if_index).unwrap_or_default();
        return Some(OtherVpn {
            name: vpn_brand(&a, &d),
            adapter: if a.is_empty() {
                format!("interface {}", r.if_index)
            } else {
                a
            },
            if_index: r.if_index,
            route: r.dest.to_string(),
        });
    }
    None
}

/// [`other_vpn_in`] on a live route table.
pub fn other_vpn<R: RouteTable + ?Sized>(table: &R) -> io::Result<Option<OtherVpn>> {
    let routes = table.routes()?;
    Ok(other_vpn_in(
        &routes,
        |i| table.interface_metric(i).ok(),
        |i| table.is_tunnel(i),
        |i| table.name_of(i),
        |i| table.description_of(i),
    ))
}

/// What `rusty-ctl preflight` found in the live route table and DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Preflight {
    /// Mapping now would not work.
    pub block: Option<OtherVpn>,
    /// Might get in the way; mapping goes ahead, and the exit guard rolls back if it hangs.
    pub warnings: Vec<String>,
}

fn named<R: RouteTable + ?Sized>(table: &R, r: &Route) -> OtherVpn {
    let a = table.name_of(r.if_index).unwrap_or_default();
    let d = table.description_of(r.if_index).unwrap_or_default();
    OtherVpn {
        name: vpn_brand(&a, &d),
        adapter: if a.is_empty() {
            format!("interface {}", r.if_index)
        } else {
            a
        },
        if_index: r.if_index,
        route: r.dest.to_string(),
    }
}

/// Checks the live route table, adapters and the uplink's DNS servers at map time. This
/// looks at what Windows would actually do, not at whether a VPN app is running or says
/// it's disconnected: some keep their routes after disconnecting.
///
/// Blocks when another adapter carries internet traffic (a better default route, or the
/// 0/1 + 128/1 pair), or when another tunnel adapter still has the /1 pair even if it
/// isn't winning right now. Warns about a VPN adapter that still has a default route, and
/// about DNS servers that are only reachable through another VPN. A kill switch that
/// works through Windows firewall rules can't be seen from here without admin rights; the
/// exit guard and SeshSwap unmap the exit if the path never comes up.
pub fn preflight<R: RouteTable + ?Sized>(
    table: &R,
    uplink_dns: &[std::net::IpAddr],
) -> io::Result<Preflight> {
    let routes = table.routes()?;
    let mut p = Preflight {
        block: other_vpn(table)?,
        ..Default::default()
    };
    let foreign =
        |i: u32| table.is_tunnel(i) && !table.name_of(i).is_some_and(|n| is_own_adapter(&n));
    let mut seen = Vec::new();
    for r in &routes {
        if !foreign(r.if_index) || seen.contains(&r.if_index) {
            continue;
        }
        let halves = routes
            .iter()
            .filter(|x| x.if_index == r.if_index && is_half_default(&x.dest))
            .count();
        if halves >= 2 {
            seen.push(r.if_index);
            if p.block.is_none() {
                let mut v = named(table, r);
                v.route = "0.0.0.0/1 + 128.0.0.0/1".into();
                p.block = Some(v);
            }
        } else if r.dest.is_default() {
            seen.push(r.if_index);
            let v = named(table, r);
            if p.block.as_ref().is_none_or(|b| b.if_index != r.if_index) {
                p.warnings.push(format!(
                    "{} still has a default route ({}). If the map hangs, disconnect it or turn off its kill switch.",
                    v.name, v.adapter
                ));
            }
        }
    }
    for ip in uplink_dns {
        let std::net::IpAddr::V4(v4) = ip else {
            continue;
        };
        if let Some(r) = route_for(&routes, *v4, |i| table.interface_metric(i).ok()) {
            if foreign(r.if_index) {
                p.warnings.push(format!(
                    "Your DNS server {v4} is only reachable through {}. Names may not load while the exit is mapped.",
                    named(table, r).name
                ));
            }
        }
    }
    Ok(p)
}

/// True when Session Router's own adapter carries ordinary internet traffic: a
/// full-tunnel exit's routes are in and winning.
pub fn own_tunnel_holds<R: RouteTable + ?Sized>(table: &R) -> io::Result<bool> {
    let routes = table.routes()?;
    Ok(PROBES.iter().any(|&dst| {
        route_for(&routes, dst, |i| table.interface_metric(i).ok())
            .and_then(|r| table.name_of(r.if_index))
            .is_some_and(|n| is_own_adapter(&n))
    }))
}

/// The `0.0.0.0/1` and `128.0.0.0/1` halves.
pub fn is_half_default(n: &Ipv4Net) -> bool {
    n.prefix == 1 && (n.addr == Ipv4Addr::UNSPECIFIED || n.addr == Ipv4Addr::new(128, 0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::MemRoutes;

    fn r(d: &str, h: &str, i: u32, m: u32) -> Route {
        Route {
            dest: d.parse().unwrap(),
            next_hop: h.parse().unwrap(),
            if_index: i,
            metric: m,
        }
    }

    /// Wi-Fi on 7 with metric 25+35.
    fn home() -> MemRoutes {
        let mut t = MemRoutes::with(vec![
            r("0.0.0.0/0", "192.168.1.1", 7, 25),
            r("192.168.1.0/24", "0.0.0.0", 7, 256),
        ]);
        t.if_metrics.insert(7, 35);
        t.names.insert("Wi-Fi".into(), 7);
        t
    }

    #[test]
    fn plain_wifi_is_fine() {
        let t = home();
        assert_eq!(other_vpn(&t).unwrap(), None);
        assert!(!own_tunnel_holds(&t).unwrap());
    }

    #[test]
    fn nord_openvpn_split_routes_are_caught() {
        let mut t = home();
        // TAP-NordVPN: 0/1 + 128/1 via its gateway, plus a /32 to the VPN server.
        t.table.extend([
            r("0.0.0.0/1", "10.8.1.1", 23, 0),
            r("128.0.0.0/1", "10.8.1.1", 23, 0),
            r("10.8.1.0/24", "0.0.0.0", 23, 256),
            r("185.1.2.3/32", "192.168.1.1", 7, 0),
        ]);
        t.if_metrics.insert(23, 5);
        t.tunnels.push(23);
        t.names.insert("Ethernet 3".into(), 23);
        t.descriptions
            .insert(23, "TAP-NordVPN Windows Adapter V9".into());
        let v = other_vpn(&t).unwrap().expect("Nord holds the route");
        assert_eq!(v.name, "NordVPN");
        assert_eq!(v.adapter, "Ethernet 3");
        assert_eq!(v.route, "0.0.0.0/1");
        assert_eq!(
            v.message(),
            "Another VPN is still holding your connection (NordVPN). Disconnect it or turn off its kill switch, then map again."
        );
        // Nord off: its routes go, and so does the complaint.
        t.table.retain(|x| x.if_index != 23);
        assert_eq!(other_vpn(&t).unwrap(), None);
    }

    #[test]
    fn vpn_default_route_with_lower_metric_is_caught() {
        let mut t = home();
        // NordLynx (WireGuard): an on-link default route with a lower metric.
        t.table.push(r("0.0.0.0/0", "0.0.0.0", 31, 0));
        t.if_metrics.insert(31, 1);
        t.tunnels.push(31);
        t.names.insert("NordLynx".into(), 31);
        t.descriptions.insert(31, "NordLynx Tunnel".into());
        let v = other_vpn(&t).unwrap().unwrap();
        assert_eq!(
            (v.name.as_str(), v.route.as_str()),
            ("NordVPN", "0.0.0.0/0")
        );
    }

    #[test]
    fn vpn_app_running_but_disconnected_is_fine() {
        // NordVPN open but not connected: its adapter is there, with only its own
        // link routes, no default or /1 routes.
        let mut t = home();
        t.table.push(r("10.5.0.0/16", "0.0.0.0", 31, 256));
        t.if_metrics.insert(31, 1);
        t.tunnels.push(31);
        t.names.insert("NordLynx".into(), 31);
        t.descriptions.insert(31, "NordLynx Tunnel".into());
        assert_eq!(other_vpn(&t).unwrap(), None);
    }

    #[test]
    fn idle_vpn_adapter_with_a_worse_metric_is_ignored() {
        let mut t = home();
        // A VPN adapter that has a default route but loses to Wi-Fi isn't handling traffic.
        t.table.push(r("0.0.0.0/0", "10.3.0.1", 12, 500));
        t.if_metrics.insert(12, 50);
        t.tunnels.push(12);
        t.names.insert("ProtonVPN".into(), 12);
        assert_eq!(other_vpn(&t).unwrap(), None);
    }

    #[test]
    fn interface_without_a_metric_is_ignored() {
        let mut t = home();
        // The VPN adapter is disconnected: no IPv4 interface entry, so Windows skips it.
        t.table.push(r("0.0.0.0/1", "10.8.1.1", 23, 0));
        t.table.push(r("128.0.0.0/1", "10.8.1.1", 23, 0));
        t.tunnels.push(23);
        t.missing_metric.push(23);
        assert_eq!(other_vpn(&t).unwrap(), None);
    }

    #[test]
    fn our_own_tunnel_is_not_another_vpn() {
        let mut t = home();
        t.table.extend([
            r("0.0.0.0/1", "172.16.0.0", 49, 5),
            r("128.0.0.0/1", "172.16.0.0", 49, 5),
        ]);
        t.if_metrics.insert(49, 5);
        t.tunnels.push(49);
        t.names.insert("sr-tun0".into(), 49);
        assert_eq!(other_vpn(&t).unwrap(), None);
        assert!(own_tunnel_holds(&t).unwrap());
    }

    #[test]
    fn other_vpn_split_beating_ours_is_caught() {
        // Both have the /1 pair; Nord's metric is lower, so its routes win and the exit's
        // don't carry anything.
        let mut t = home();
        t.table.extend([
            r("0.0.0.0/1", "172.16.0.0", 49, 5),
            r("128.0.0.0/1", "172.16.0.0", 49, 5),
            r("0.0.0.0/1", "10.8.1.1", 23, 0),
            r("128.0.0.0/1", "10.8.1.1", 23, 0),
        ]);
        t.if_metrics.insert(49, 5);
        t.if_metrics.insert(23, 1);
        t.tunnels.extend([49, 23]);
        t.names.insert("sr-tun0".into(), 49);
        t.names.insert("NordVPN".into(), 23);
        assert_eq!(other_vpn(&t).unwrap().unwrap().name, "NordVPN");
        assert!(!own_tunnel_holds(&t).unwrap());
    }

    #[test]
    fn brands() {
        assert_eq!(
            vpn_brand("Local Area Connection", "Mullvad Wintun"),
            "Mullvad"
        );
        assert_eq!(vpn_brand("Ethernet 2", "TAP-Windows Adapter V9"), "OpenVPN");
        assert_eq!(vpn_brand("pia", ""), "Private Internet Access");
        assert_eq!(vpn_brand("Pianoforte", "Some Tunnel"), "Pianoforte");
        assert_eq!(vpn_brand("", ""), "a VPN");
    }

    #[test]
    fn route_choice_matches_windows() {
        let routes = vec![
            r("0.0.0.0/0", "192.168.1.1", 7, 25),
            r("0.0.0.0/0", "192.168.2.1", 8, 10),
            r("1.1.1.0/24", "192.168.1.1", 7, 900),
        ];
        let m = |i: u32| Some(if i == 7 { 35 } else { 60 });
        // Longest prefix wins regardless of metric.
        assert_eq!(
            route_for(&routes, "1.1.1.1".parse().unwrap(), m)
                .unwrap()
                .if_index,
            7
        );
        // Among defaults: 25+35=60 beats 10+60=70.
        assert_eq!(
            route_for(&routes, "9.9.9.9".parse().unwrap(), m)
                .unwrap()
                .if_index,
            7
        );
    }

    #[test]
    fn preflight_blocks_leftover_split_routes_even_when_not_winning() {
        // Disconnected but its /1 pair is still there (interface down: no metric).
        let mut t = home();
        t.table.push(r("0.0.0.0/1", "10.8.1.1", 23, 0));
        t.table.push(r("128.0.0.0/1", "10.8.1.1", 23, 0));
        t.tunnels.push(23);
        t.missing_metric.push(23);
        t.names.insert("Ethernet 3".into(), 23);
        t.descriptions
            .insert(23, "TAP-NordVPN Windows Adapter V9".into());
        let p = preflight(&t, &[]).unwrap();
        let b = p.block.expect("blocked");
        assert_eq!(b.name, "NordVPN");
        assert_eq!(b.route, "0.0.0.0/1 + 128.0.0.0/1");
        assert_eq!(
            b.message(),
            "Another VPN is still holding your connection (NordVPN). Disconnect it or turn off its kill switch, then map again."
        );
    }

    #[test]
    fn preflight_warns_about_a_leftover_default_route_and_dns() {
        let mut t = home();
        t.table.push(r("0.0.0.0/0", "10.3.0.1", 12, 500));
        t.table.push(r("103.86.96.100/32", "10.3.0.1", 12, 0));
        t.if_metrics.insert(12, 50);
        t.tunnels.push(12);
        t.names.insert("ProtonVPN".into(), 12);
        let dns = [
            "103.86.96.100".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];
        let p = preflight(&t, &dns).unwrap();
        assert_eq!(p.block, None);
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
        assert!(p.warnings[0].starts_with("Proton VPN still has a default route"));
        assert!(p.warnings[1].contains("DNS server 103.86.96.100"));
    }

    #[test]
    fn preflight_clean_on_plain_wifi_and_with_our_own_tunnel() {
        let mut t = home();
        assert_eq!(
            preflight(&t, &["192.168.1.1".parse().unwrap()]).unwrap(),
            Preflight::default()
        );
        t.table.extend([
            r("0.0.0.0/1", "172.16.0.0", 49, 5),
            r("128.0.0.0/1", "172.16.0.0", 49, 5),
        ]);
        t.tunnels.push(49);
        t.names.insert("sr-tun0".into(), 49);
        assert_eq!(preflight(&t, &[]).unwrap(), Preflight::default());
    }
}
