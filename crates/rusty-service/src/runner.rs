//! Wires the supervisor to the real router process, its RPC and the platform network.

use crate::config::Config;
use crate::process::{RouterProcess, RpcControl};
use crate::supervisor::{Options, Outcome, StopFlag, Supervisor};
use std::time::Duration;

#[cfg(windows)]
pub fn platform_net() -> (
    rusty_net::windows::IpHelperRoutes,
    rusty_net::windows::IpHelperDns,
) {
    (
        rusty_net::windows::IpHelperRoutes,
        rusty_net::windows::IpHelperDns,
    )
}

pub fn platform_ipv6() -> Box<dyn rusty_net::Ipv6Bindings + Send> {
    #[cfg(windows)]
    return Box::new(rusty_net::windows::PsIpv6);
    #[cfg(not(windows))]
    return Box::new(rusty_net::NoIpv6);
}

/// Off Windows there's nothing to configure; supervision still works for testing.
#[cfg(not(windows))]
pub fn platform_net() -> (rusty_net::mem::MemRoutes, rusty_net::mem::MemDns) {
    eprintln!("note: not on Windows, so route and DNS changes are only simulated");
    Default::default()
}

/// Undoes whatever the journal holds. At boot, network adapters can show up after the
/// service starts, so `wait` gives the interfaces the journal names time to appear before
/// one that is still missing is taken as gone.
pub fn restore_now(cfg: &Config, wait: Duration) -> Result<rusty_net::RestoreReport, String> {
    use rusty_net::DnsSettings;
    let (routes, dns) = platform_net();
    let j = rusty_net::Journal::load(&cfg.journal).map_err(|e| e.to_string())?;
    let end = std::time::Instant::now() + wait;
    for d in &j.dns {
        while std::time::Instant::now() < end
            && matches!(dns.servers(d.if_index), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let (_, rep) =
        rusty_net::NetGuard::open_with_ipv6(routes, dns, platform_ipv6(), cfg.journal.clone())
            .map_err(|e| e.to_string())?;
    Ok(rep)
}

/// What `rusty-service net` prints: every default route with its effective metric, which
/// ones are tunnels, the uplink Rusty would pick and that adapter's DNS.
pub fn describe_net<R: rusty_net::RouteTable, D: rusty_net::DnsSettings>(
    routes: &R,
    dns: &D,
    dns_interface: Option<&str>,
) -> std::io::Result<String> {
    use std::fmt::Write;
    let mut out = String::new();
    for r in routes.routes()?.iter().filter(|r| r.dest.is_default()) {
        let ifm = routes.interface_metric(r.if_index);
        let _ = writeln!(
            out,
            "default via {} on interface {}: route metric {}, interface metric {}, effective {}{}",
            r.next_hop,
            r.if_index,
            r.metric,
            ifm.as_ref().map_or("?".to_string(), |m| m.to_string()),
            ifm.as_ref()
                .map_or("?".to_string(), |m| (r.metric + m).to_string()),
            if routes.is_tunnel(r.if_index) {
                " (tunnel, skipped)"
            } else {
                ""
            }
        );
    }
    let pick = match dns_interface {
        Some(n) => routes.index_of(n)?,
        None => rusty_net::physical_gateway(routes, &[])?.map(|g| g.if_index),
    };
    match pick {
        Some(i) => {
            let _ = writeln!(
                out,
                "uplink for DNS: interface {i}; DNS there: {}",
                dns.servers(i)
                    .map(|s| if s.is_empty() {
                        "automatic".to_string()
                    } else {
                        rusty_net::format_server_list(&s)
                    })
                    .unwrap_or_else(|e| e.to_string())
            );
        }
        None => out.push_str("uplink for DNS: none\n"),
    }
    Ok(out)
}

pub fn supervise(
    cfg: &Config,
    stop: &StopFlag,
    log: &mut dyn FnMut(&str),
) -> Result<Outcome, String> {
    let (routes, dns) = platform_net();
    let (net, rep) =
        rusty_net::NetGuard::open_with_ipv6(routes, dns, platform_ipv6(), cfg.journal.clone())
            .map_err(|e| e.to_string())?;
    if !rep.is_empty() {
        log(&format!(
            "undid changes from an earlier run that didn't stop cleanly: {} route(s), DNS on {} interface(s){}{}",
            rep.routes_removed,
            rep.dns_restored,
            if rep.ipv6_reenabled.is_empty() {
                String::new()
            } else {
                format!(", IPv6 back on for {}", rep.ipv6_reenabled.join(", "))
            },
            if rep.ipv6_gone.is_empty() {
                String::new()
            } else {
                format!(", forgot IPv6 state for gone adapter(s) {}", rep.ipv6_gone.join(", "))
            }
        ));
    }
    let mut sup = Supervisor {
        launcher: {
            let mut l = RouterProcess::new(cfg.router_exe.clone(), cfg.router_args.clone());
            l.console_log = cfg.router_console_log.clone();
            l
        },
        control: RpcControl {
            addr: cfg.rpc.clone(),
            auth: cfg.rpc_auth.clone(),
        },
        net,
        opts: Options {
            policy: cfg.policy(),
            set_dns: cfg.set_dns.as_ref().and_then(|d| d.parse().ok()),
            dns_interface: cfg.dns_interface.clone(),
            dns_recheck: Duration::from_secs(5),
            stop_timeout: Duration::from_secs(cfg.stop_timeout_secs),
            poll: Duration::from_millis(250),
        },
    };
    sup.run(stop, log).map_err(|e| e.to_string())
}
