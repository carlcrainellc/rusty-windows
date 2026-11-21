//! Cleaning up after a router that died without removing its routes.
//!
//! On Windows the router adds its routes with `route.exe`: a /32 to each first hop via the
//! physical gateway, `0.0.0.0/1` and `128.0.0.0/1` through the tunnel for full-tunnel
//! exits, and a `127.0.0.0/8` hole. If it crashes, the /32s stay. We take a snapshot of the
//! route table before starting it and, after a crash, remove only routes of those shapes
//! that weren't there before. Anything else that appeared meanwhile (another VPN, a new
//! Wi-Fi network) is left alone.

use rusty_net::{Ipv4Net, Route};
use std::net::Ipv4Addr;

fn router_shaped(r: &Route) -> bool {
    let half_lo = Ipv4Net {
        addr: Ipv4Addr::UNSPECIFIED,
        prefix: 1,
    };
    let half_hi = Ipv4Net {
        addr: Ipv4Addr::new(128, 0, 0, 0),
        prefix: 1,
    };
    let loopback = Ipv4Net {
        addr: Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
    };
    (r.dest.prefix == 32
        && !r.next_hop.is_unspecified()
        && !r.dest.addr.is_loopback()
        && !r.dest.addr.is_broadcast()
        && !r.dest.addr.is_multicast())
        || r.dest == half_lo
        || r.dest == half_hi
        || r.dest == loopback
}

/// Routes to remove: new since `before` and shaped like something the router adds.
pub fn leftovers(before: &[Route], after: &[Route]) -> Vec<Route> {
    leftovers_except(before, after, |_| false)
}

/// The router's `route.exe` metric for its first-hop pins (`m_Metric` in vpn/win32.hpp).
pub const ROUTER_PIN_METRIC: u32 = 2;

/// Like [`leftovers`], but never touches another VPN. `other_vpn_iface` says whether an
/// interface is someone else's tunnel adapter. Routes on those stay. If such a VPN holds
/// a default route, its own host route to its server looks just like a first-hop pin, so
/// then only pins with the router's metric are removed.
pub fn leftovers_except(
    before: &[Route],
    after: &[Route],
    other_vpn_iface: impl Fn(u32) -> bool,
) -> Vec<Route> {
    let vpn_up = after.iter().any(|r| {
        (r.dest.prefix == 0 || rusty_net::vpn::is_half_default(&r.dest))
            && other_vpn_iface(r.if_index)
    });
    after
        .iter()
        .filter(|r| {
            !before
                .iter()
                .any(|b| b.dest == r.dest && b.next_hop == r.next_hop && b.if_index == r.if_index)
        })
        .filter(|r| router_shaped(r))
        .filter(|r| !other_vpn_iface(r.if_index))
        .filter(|r| !(vpn_up && r.dest.prefix == 32 && r.metric != ROUTER_PIN_METRIC))
        .cloned()
        .collect()
}

/// Loopback routes (127.0.0.0/8 and inside it) that were there before and are gone now.
/// Older Windows router builds tear down their 127.0.0.0/8 hole with a `route DELETE`
/// that also takes out the system's own loopback routes, so we put those back.
pub fn vanished_loopback(before: &[Route], after: &[Route]) -> Vec<Route> {
    before
        .iter()
        .filter(|b| b.dest.addr.is_loopback())
        .filter(|b| {
            !after
                .iter()
                .any(|a| a.dest == b.dest && a.next_hop == b.next_hop && a.if_index == b.if_index)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(d: &str, h: &str, i: u32) -> Route {
        Route {
            dest: d.parse().unwrap(),
            next_hop: h.parse().unwrap(),
            if_index: i,
            metric: 5,
        }
    }

    #[test]
    fn only_new_router_shaped_routes() {
        let before = vec![
            r("0.0.0.0/0", "192.168.1.1", 7),
            r("192.168.1.0/24", "0.0.0.0", 7),
            r("203.0.113.1/32", "192.168.1.1", 7),
        ];
        let mut after = before.clone();
        after.extend([
            r("198.51.100.4/32", "192.168.1.1", 7), // first-hop pin: remove
            r("0.0.0.0/1", "172.16.0.1", 40),       // full-tunnel half: remove
            r("128.0.0.0/1", "172.16.0.1", 40),     // full-tunnel half: remove
            r("10.8.0.0/24", "10.8.0.1", 50),       // someone else's VPN subnet: keep
            r("10.8.0.5/32", "0.0.0.0", 50),        // on-link host route: keep
            r("224.0.0.0/4", "0.0.0.0", 7),         // multicast: keep
        ]);
        let gone = leftovers(&before, &after);
        let dests: Vec<String> = gone.iter().map(|r| r.dest.to_string()).collect();
        assert_eq!(dests, vec!["198.51.100.4/32", "0.0.0.0/1", "128.0.0.0/1"]);
        // A /32 that was already there before the router started stays.
        assert!(!gone.iter().any(|g| g.dest.to_string() == "203.0.113.1/32"));
    }

    #[test]
    fn vanished_loopback_routes_come_back() {
        let before = vec![
            r("127.0.0.0/8", "0.0.0.0", 1),
            r("127.0.0.1/32", "0.0.0.0", 1),
            r("127.255.255.255/32", "0.0.0.0", 1),
            r("0.0.0.0/0", "192.168.1.1", 7),
        ];
        // The router's DELETE took the /8 and the broadcast route; the default went too
        // (not ours to judge here, so it isn't touched).
        let after = vec![r("127.0.0.1/32", "0.0.0.0", 1)];
        let back: Vec<String> = vanished_loopback(&before, &after)
            .iter()
            .map(|r| r.dest.to_string())
            .collect();
        assert_eq!(back, vec!["127.0.0.0/8", "127.255.255.255/32"]);
        assert!(vanished_loopback(&before, &before).is_empty());
    }

    #[test]
    fn another_vpn_that_came_up_meanwhile_is_left_alone() {
        let before = vec![r("0.0.0.0/0", "192.168.1.1", 7)];
        let mut after = before.clone();
        let pin = |d: &str, m: u32| Route {
            dest: d.parse().unwrap(),
            next_hop: "192.168.1.1".parse().unwrap(),
            if_index: 7,
            metric: m,
        };
        after.extend([
            pin("198.51.100.4/32", ROUTER_PIN_METRIC), // router pin: remove
            r("0.0.0.0/1", "172.16.0.1", 40),          // our tunnel half: remove
            r("0.0.0.0/1", "10.8.1.1", 23),            // Nord's half: keep
            r("128.0.0.0/1", "10.8.1.1", 23),          // Nord's half: keep
            pin("185.1.2.3/32", 0),                    // Nord's route to its server: keep
        ]);
        let gone: Vec<String> = leftovers_except(&before, &after, |i| i == 23)
            .iter()
            .map(|r| r.dest.to_string())
            .collect();
        assert_eq!(gone, vec!["198.51.100.4/32", "0.0.0.0/1"]);
    }
}
