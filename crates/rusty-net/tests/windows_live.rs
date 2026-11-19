//! Read-only checks against the real Windows network stack. Nothing is changed.
#![cfg(windows)]

use rusty_net::windows::{IpHelperDns, IpHelperRoutes};
use rusty_net::{default_gateway, DnsSettings, RouteTable};

#[test]
fn reads_routes_and_finds_a_gateway() {
    let routes = IpHelperRoutes.routes().expect("GetIpForwardTable2");
    assert!(!routes.is_empty());
    println!("{} IPv4 routes", routes.len());
    let gw = default_gateway(&routes, &[]).expect("a default gateway");
    println!(
        "default gateway {} on interface {}",
        gw.next_hop, gw.if_index
    );
    let dns = IpHelperDns
        .servers(gw.if_index)
        .expect("GetInterfaceDnsSettings");
    println!("DNS on that interface: {dns:?} (empty means automatic)");
}

#[test]
fn unknown_interface_is_not_found() {
    let e = IpHelperDns.servers(0x7fff_fff0).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn deleting_a_missing_route_is_fine() {
    let routes = IpHelperRoutes.routes().unwrap();
    let gw = default_gateway(&routes, &[]).unwrap();
    // A documentation-range host route that was never added.
    let r = rusty_net::Route {
        dest: "192.0.2.123/32".parse().unwrap(),
        next_hop: gw.next_hop,
        if_index: gw.if_index,
        metric: rusty_net::PIN_METRIC,
    };
    IpHelperRoutes.delete(&r).unwrap();
}

/// Adds a real host route through NetGuard, then restores. Only runs when
/// RUSTY_LIVE_WRITE=1 (CI sets it; the runner is a throwaway machine).
#[test]
fn pin_and_restore_a_real_route() {
    if std::env::var("RUSTY_LIVE_WRITE").as_deref() != Ok("1") {
        println!("skipped: set RUSTY_LIVE_WRITE=1 to run");
        return;
    }
    let journal = std::env::temp_dir().join("rusty-live-journal.json");
    let _ = std::fs::remove_file(&journal);
    let gw = default_gateway(&IpHelperRoutes.routes().unwrap(), &[]).unwrap();
    let host: std::net::Ipv4Addr = "192.0.2.77".parse().unwrap();
    let present = || {
        IpHelperRoutes
            .routes()
            .unwrap()
            .iter()
            .any(|r| r.dest.prefix == 32 && r.dest.addr == host)
    };
    assert!(!present());

    let (mut g, _) =
        rusty_net::NetGuard::open(IpHelperRoutes, IpHelperDns, journal.clone()).unwrap();
    g.pin_hosts(&[host], gw).unwrap();
    assert!(present(), "route was not added");
    assert!(journal.exists(), "journal not written");

    // Pretend we crashed: a fresh guard must find and remove it.
    drop(g);
    let (g2, rep) =
        rusty_net::NetGuard::open(IpHelperRoutes, IpHelperDns, journal.clone()).unwrap();
    assert_eq!(rep.routes_removed, 1);
    assert!(!present(), "route was not removed");
    assert!(g2.journal().is_empty());
    assert!(!journal.exists());
}

#[test]
fn physical_gateway_uses_effective_metric() {
    use rusty_net::physical_gateway;
    let t = IpHelperRoutes;
    let gw = physical_gateway(&t, &[])
        .unwrap()
        .expect("a physical gateway");
    let eff = |r: &rusty_net::Route| r.metric + t.interface_metric(r.if_index).unwrap();
    let best = t
        .routes()
        .unwrap()
        .into_iter()
        .filter(|r| r.dest.is_default() && !r.next_hop.is_unspecified() && !t.is_tunnel(r.if_index))
        .map(|r| eff(&r))
        .min()
        .unwrap();
    let picked = t
        .routes()
        .unwrap()
        .into_iter()
        .find(|r| r.dest.is_default() && r.if_index == gw.if_index && r.next_hop == gw.next_hop)
        .unwrap();
    assert_eq!(eff(&picked), best);
    assert!(!t.is_tunnel(gw.if_index));
    println!("uplink interface {} effective metric {best}", gw.if_index);
}
