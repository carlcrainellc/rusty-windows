//! `rusty-ctl`: check on and steer a running Session Router from the command line.

use clap::{Parser, Subcommand};
use rusty_rpc::{Client, MapExit, DEFAULT_ADDR};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "rusty-ctl",
    version,
    about = "Control a running Session Router"
)]
struct Cli {
    /// Router RPC address ([api] bind in the router config).
    #[arg(long, default_value = DEFAULT_ADDR, global = true)]
    rpc: String,
    /// The router's `[api] auth=` value, if its build requires one.
    #[arg(long, env = "RUSTY_RPC_AUTH", global = true, hide_env_values = true)]
    auth: Option<String>,
    /// Seconds to wait for the router.
    #[arg(long, default_value_t = 10, global = true)]
    timeout: u64,
    /// Print raw JSON instead of a summary.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Router version and whether exit routes are up.
    Status,
    /// List mapped exits.
    Exits,
    /// Send traffic through an exit.
    Map {
        /// Exit address, e.g. `abc...xyz.sesh`.
        address: String,
        /// Send all traffic through the exit.
        #[arg(long, conflicts_with = "range")]
        full: bool,
        /// Send only these ranges through the exit (repeatable), e.g. `--range 10.0.0.0/8`.
        #[arg(long)]
        range: Vec<String>,
        /// Access token for a paid exit.
        #[arg(long, default_value = "")]
        token: String,
        /// Map even if another VPN is holding your connection.
        #[arg(long)]
        anyway: bool,
    },
    /// Check this computer is ready for a full-tunnel exit (no other VPN holding the
    /// route). Exit code 3 if not. With --json, also what the exit guard last did.
    Preflight,
    /// Stop using an exit.
    Unmap { address: String },
    /// Move mappings from one exit to another.
    Swap {
        old: String,
        new: String,
        #[arg(long)]
        full: bool,
        #[arg(long)]
        range: Vec<String>,
        #[arg(long, default_value = "")]
        token: String,
    },
    /// Stop the RustySessionRouter service (unmaps exits and puts the network back).
    Stop,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Cmd::Preflight = cli.cmd {
        return main_preflight(cli.json);
    }
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rusty-ctl: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Exit code for `preflight` when mapping would not work.
const NOT_READY: u8 = 3;

fn main_preflight(json: bool) -> ExitCode {
    let p = preflight_now();
    let last = last_rollback();
    let (ok, v) = preflight_report(&p, last);
    if json {
        println!("{v}");
    } else {
        match &p.block {
            Some(o) => println!("{}", o.message()),
            None => println!("ok: no other VPN is holding your connection"),
        }
        for w in &p.warnings {
            println!("warning: {w}");
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(NOT_READY)
    }
}

/// `preflight --json`: `{"ok":true,"warnings":[...]}` or `{"ok":false,"code":"other_vpn",
/// "message":...,"vpn":{...},"warnings":[...]}`, plus `last_rollback` when the exit guard
/// has unmapped something.
fn preflight_report(
    p: &rusty_net::vpn::Preflight,
    last: Option<serde_json::Value>,
) -> (bool, serde_json::Value) {
    let other = p.block.as_ref();
    let mut v = match other {
        None => serde_json::json!({ "ok": true }),
        Some(o) => serde_json::json!({
            "ok": false,
            "code": "other_vpn",
            "message": o.message(),
            "vpn": o,
        }),
    };
    v["warnings"] = serde_json::json!(p.warnings);
    if let Some(l) = last {
        v["last_rollback"] = l;
    }
    (other.is_none(), v)
}

/// The live route table, adapters and the uplink's DNS servers, read now.
#[cfg(windows)]
fn preflight_now() -> rusty_net::vpn::Preflight {
    use rusty_net::DnsSettings;
    let routes = rusty_net::windows::IpHelperRoutes;
    let dns = rusty_net::physical_gateway(&routes, &[])
        .ok()
        .flatten()
        .and_then(|g| rusty_net::windows::IpHelperDns.servers(g.if_index).ok())
        .unwrap_or_default();
    rusty_net::vpn::preflight(&routes, &dns).unwrap_or_default()
}

#[cfg(not(windows))]
fn preflight_now() -> rusty_net::vpn::Preflight {
    Default::default()
}

/// `exit-guard.json`, which rusty-service writes next to itself when it unmaps an exit.
fn last_rollback() -> Option<serde_json::Value> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let b = std::fs::read(dir.join("exit-guard.json")).ok()?;
    serde_json::from_slice(&b).ok()
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Stopping goes through the service manager and works even when the router is down.
    if let Cmd::Stop = cli.cmd {
        stop_service()?;
        println!("RustySessionRouter stopped; network settings are back as they were");
        return Ok(());
    }
    let mut c =
        Client::connect(&cli.rpc, Duration::from_secs(cli.timeout))?.with_auth(cli.auth.clone());
    match &cli.cmd {
        Cmd::Status => {
            let version = c.version()?;
            // Some builds don't implement list_exits; the router is still up.
            let exits = c.list_exits();
            if cli.json {
                let exits = match &exits {
                    Ok(e) => serde_json::to_value(e)?,
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                };
                println!(
                    "{}",
                    serde_json::json!({ "version": version, "exits": exits })
                );
            } else {
                println!("router: {}", version_line(&version));
                match exits {
                    Ok(e) => {
                        println!("{}", routes_line(e.routes_up, e.routes_reason.as_deref()));
                        println!("exits mapped: {}", e.exits.len());
                    }
                    Err(e) => println!("exits: {e}"),
                }
                warn_other_vpns();
            }
        }
        Cmd::Exits => {
            let l = c.list_exits()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&l)?);
            } else {
                println!("{}", routes_line(l.routes_up, l.routes_reason.as_deref()));
                if l.exits.is_empty() {
                    println!("no exits mapped");
                }
                for e in &l.exits {
                    let state = session_state(e.session_live, e.exit_capable);
                    println!("{}  {}  [{}]", e.address, state, e.ranges.join(", "));
                }
            }
        }
        Cmd::Map {
            address,
            full,
            range,
            token,
            anyway,
        } => {
            let req = map_request(address, *full, range, token)?;
            if !*anyway && takes_default(&req) {
                let p = preflight_now();
                if let Some(o) = p.block {
                    return Err(format!("{} (or add --anyway)", o.message()).into());
                }
                for w in &p.warnings {
                    eprintln!("warning: {w}");
                }
            }
            let r = c.map_exit(&req)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                println!("{}", r.message);
                println!("{}", routes_line(r.routes_up, r.routes_reason.as_deref()));
                warn_other_vpns();
            }
        }
        Cmd::Unmap { address } => {
            c.unmap_exit(address)?;
            println!("unmapped {address}");
        }
        Cmd::Swap {
            old,
            new,
            full,
            range,
            token,
        } => {
            let full = *full || range.is_empty();
            println!("{}", c.swap_exits(old, new, full, range, token)?);
        }
        Cmd::Stop | Cmd::Preflight => unreachable!("handled above"),
    }
    Ok(())
}

/// Stops the service through the Service Control Manager. Asking the router itself to
/// halt over RPC would look like a crash to the service, which would start it again.
#[cfg(windows)]
fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("can't open the service manager (run as administrator): {e}"))?;
    let svc = mgr
        .open_service(
            "RustySessionRouter",
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| {
            format!(
                "can't open the RustySessionRouter service (not installed, or not running as administrator): {e}"
            )
        })?;
    if svc.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if let Err(e) = svc.stop() {
        // Already stopping is fine; we wait for it below.
        if svc.query_status()?.current_state != ServiceState::StopPending {
            return Err(format!("couldn't stop RustySessionRouter: {e}").into());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if svc.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("RustySessionRouter is still stopping after 60 s; check rusty-service.log".into())
}

#[cfg(not(windows))]
fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    Err("stop controls the Windows service; elsewhere, stop rusty-service with Ctrl-C".into())
}

/// Another VPN with its own default route fights with the exit's routes (and its own
/// firewall rules may drop our traffic), so say so where people look.
fn warn_other_vpns() {
    for line in vpn_warnings() {
        println!("{line}");
    }
}

#[cfg(windows)]
fn vpn_warnings() -> Vec<String> {
    other_vpn_lines(
        rusty_net::other_vpn_defaults(&rusty_net::windows::IpHelperRoutes).unwrap_or_default(),
    )
}

#[cfg(not(windows))]
fn vpn_warnings() -> Vec<String> {
    other_vpn_lines(Vec::new())
}

fn other_vpn_lines(names: Vec<String>) -> Vec<String> {
    names
        .into_iter()
        .map(|n| {
            format!(
                "warning: another VPN adapter has a default route: {n}. Disconnect it, or traffic may not go through the exit."
            )
        })
        .collect()
}

/// With no ranges given, map everything; that's what people mean by "use this exit".
fn map_request(
    address: &str,
    full: bool,
    range: &[String],
    token: &str,
) -> Result<MapExit, String> {
    if !address.ends_with(".sesh") {
        return Err(format!("{address} isn't a .sesh address"));
    }
    Ok(MapExit {
        address: address.to_string(),
        full_tunnel: full || range.is_empty(),
        ip_ranges: range.to_vec(),
        token: token.to_string(),
    })
}

/// Whether a map sends everything through the exit (the router reads no ranges as all).
fn takes_default(req: &MapExit) -> bool {
    req.full_tunnel
        || req.ip_ranges.is_empty()
        || req
            .ip_ranges
            .iter()
            .any(|r| r.ends_with("/0") || r.ends_with("/1"))
}

fn version_line(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(m) => m
            .get("version")
            .map(|x| match x {
                serde_json::Value::Array(a) => a
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
                other => other.to_string().trim_matches('"').to_string(),
            })
            .unwrap_or_else(|| v.to_string()),
        other => other.to_string(),
    }
}

/// Only says the routes are up when the router says so.
fn routes_line(up: Option<bool>, reason: Option<&str>) -> String {
    match (up, reason) {
        (Some(true), _) => "exit routes: up".to_string(),
        (Some(false), Some(r)) => format!("exit routes: down ({r})"),
        (Some(false), None) => "exit routes: down".to_string(),
        (None, _) => "exit routes: unknown (this router build doesn't report them)".to_string(),
    }
}

/// The router's session to an exit; says nothing about whether traffic is routed there.
fn session_state(live: bool, exit_capable: bool) -> &'static str {
    match (live, exit_capable) {
        (true, true) => "session to exit: live",
        (true, false) => "session live, but not an exit",
        _ => "session to exit: down",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn never_claims_connected() {
        for (a, b) in [(true, true), (true, false), (false, true), (false, false)] {
            assert!(!session_state(a, b).contains("connected"));
        }
        assert_eq!(session_state(true, true), "session to exit: live");
        assert_eq!(routes_line(Some(true), None), "exit routes: up");
        assert_eq!(
            routes_line(Some(false), Some("no gateway")),
            "exit routes: down (no gateway)"
        );
        assert!(routes_line(None, None).starts_with("exit routes: unknown"));
    }

    #[test]
    fn map_defaults_to_full_tunnel() {
        let r = map_request("a.sesh", false, &[], "").unwrap();
        assert!(r.full_tunnel);
        let r = map_request("a.sesh", false, &["10.0.0.0/8".into()], "t").unwrap();
        assert!(!r.full_tunnel);
        assert_eq!(r.token, "t");
        assert!(map_request("example.com", true, &[], "").is_err());
    }

    #[test]
    fn version_formats() {
        assert_eq!(version_line(&json!({"version": [1, 1, 1]})), "1.1.1");
        assert_eq!(
            version_line(&json!("session-router-1.1.1")),
            "session-router-1.1.1"
        );
        assert_eq!(
            routes_line(Some(false), Some("no vpn interface")),
            "exit routes: down (no vpn interface)"
        );
    }

    #[test]
    fn cli_parses() {
        Cli::try_parse_from([
            "rusty-ctl",
            "map",
            "a.sesh",
            "--range",
            "10.0.0.0/8",
            "--range",
            "1.2.3.0/24",
        ])
        .unwrap();
        assert!(Cli::try_parse_from([
            "rusty-ctl",
            "map",
            "a.sesh",
            "--full",
            "--range",
            "10.0.0.0/8"
        ])
        .is_err());
        Cli::try_parse_from([
            "rusty-ctl",
            "--rpc",
            "tcp://127.0.0.1:1190",
            "status",
            "--json",
        ])
        .unwrap();
    }

    #[test]
    fn other_vpn_warning_names_the_adapter() {
        let l = other_vpn_lines(vec!["NordWhisper".into()]);
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("NordWhisper") && l[0].starts_with("warning:"));
        assert!(!l[0].contains("connected"));
        assert!(other_vpn_lines(vec![]).is_empty());
    }

    #[test]
    fn preflight_says_why() {
        let nord = rusty_net::vpn::OtherVpn {
            name: "NordVPN".into(),
            adapter: "NordLynx".into(),
            if_index: 31,
            route: "0.0.0.0/1".into(),
        };
        let p = rusty_net::vpn::Preflight {
            block: Some(nord),
            warnings: vec!["w".into()],
        };
        let (ok, v) = preflight_report(&p, None);
        assert!(!ok);
        assert_eq!(v["code"], "other_vpn");
        assert_eq!(
            v["message"],
            "Another VPN is still holding your connection (NordVPN). Disconnect it or turn off its kill switch, then map again."
        );
        assert_eq!(v["vpn"]["adapter"], "NordLynx");
        assert_eq!(v["warnings"][0], "w");
        let (ok, v) = preflight_report(
            &Default::default(),
            Some(json!({"why": "exit_not_answering"})),
        );
        assert!(ok);
        assert_eq!(v["ok"], true);
        assert_eq!(v["last_rollback"]["why"], "exit_not_answering");
    }

    #[test]
    fn which_maps_take_the_default_route() {
        assert!(takes_default(
            &map_request("a.sesh", true, &[], "").unwrap()
        ));
        assert!(takes_default(
            &map_request("a.sesh", false, &[], "").unwrap()
        ));
        assert!(!takes_default(
            &map_request("a.sesh", false, &["10.0.0.0/8".into()], "").unwrap()
        ));
    }
}
