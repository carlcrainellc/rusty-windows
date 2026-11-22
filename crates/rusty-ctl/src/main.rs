//! `rusty-ctl`: check on and steer a running Session Router from the command line.

use clap::{Parser, Subcommand};
use rusty_rpc::{Client, ExitList, MapExit, DEFAULT_ADDR};
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

#[derive(Debug, Subcommand)]
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
        /// One of --full or --range is required: the router treats a map with no ranges as 0.0.0.0/0.
        #[arg(long)]
        range: Vec<String>,
        /// Access token for a paid exit.
        #[arg(long, default_value = "")]
        token: String,
        /// Map even if another VPN is holding your connection.
        #[arg(long)]
        anyway: bool,
        /// Seconds to wait for a live session to the exit before routing anything
        /// through it. 0 maps straight away (routes can go up before the exit answers).
        #[arg(long, default_value_t = DEFAULT_WAIT, value_name = "SECS")]
        wait: u64,
    },
    /// Check this computer is ready for a full-tunnel exit (no other VPN holding the
    /// route). Exit code 3 if not. With --json, also what the exit guard last did.
    Preflight,
    /// Stop using an exit. With no address, unmaps every mapped exit.
    Unmap { address: Option<String> },
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
        /// Seconds to wait for a live session to the new exit before moving anything.
        #[arg(long, default_value_t = DEFAULT_WAIT, value_name = "SECS")]
        wait: u64,
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
                        println!("{}", routes_summary(&e));
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
                println!("{}", routes_summary(&l));
                if l.exits.is_empty() {
                    println!("no exits mapped");
                }
                for e in &l.exits {
                    let state = session_state(e.session_live, e.exit_capable);
                    let ranges = if is_probe(e) {
                        "waiting for the session, nothing routed".to_string()
                    } else {
                        e.ranges.join(", ")
                    };
                    println!("{}  {}  [{}]", e.address, state, ranges);
                }
            }
        }
        Cmd::Map {
            address,
            full,
            range,
            token,
            anyway,
            wait,
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
            if *wait > 0 {
                wait_live(&mut c, address, token, Duration::from_secs(*wait))?;
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
            let addrs = match address {
                Some(a) => vec![a.clone()],
                None => c
                    .list_exits()
                    .map_err(|e| format!("{e}; give the exit address to unmap"))?
                    .exits
                    .into_iter()
                    .map(|e| e.address)
                    .collect(),
            };
            if addrs.is_empty() {
                println!("no exits mapped");
            }
            for a in &addrs {
                c.unmap_exit(a)?;
                println!("unmapped {a}");
            }
        }
        Cmd::Swap {
            old,
            new,
            full,
            range,
            token,
            wait,
        } => {
            if !*full && range.is_empty() {
                return Err(
                    "say --full to send all traffic through the new exit, or --range for a prefix"
                        .into(),
                );
            }
            if !new.ends_with(".sesh") {
                return Err(format!("{new} isn't a .sesh address").into());
            }
            // The old exit keeps its routes until the new one answers.
            if *wait > 0 && !same_exit(old, new) {
                wait_live(&mut c, new, token, Duration::from_secs(*wait))?;
            }
            let probed = *wait > 0 && !same_exit(old, new);
            match c.swap_exits(old, new, *full, range, token) {
                Ok(m) => println!("{m}"),
                Err(e) => {
                    if probed {
                        let _ = c.unmap_exit(new);
                    }
                    return Err(e.into());
                }
            }
        }
        Cmd::Stop | Cmd::Preflight => unreachable!("handled above"),
    }
    Ok(())
}

/// How long `map` and `swap` wait for the session to an exit by default.
const DEFAULT_WAIT: u64 = 45;

/// While waiting for a session, the exit is mapped for this one documentation address
/// only (TEST-NET-1, never used on the internet). That starts the session without putting
/// in the default route, so if the exit never answers nothing else is blackholed.
const PROBE_RANGE: &str = "192.0.2.1/32";

fn is_probe(e: &rusty_rpc::ExitEntry) -> bool {
    e.ranges.len() == 1 && e.ranges[0] == PROBE_RANGE
}

fn same_exit(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Why an exit didn't come up.
#[derive(Debug, PartialEq, Eq)]
enum WaitFail {
    /// No session at all: wrong or stale address, or the exit is offline.
    NoSession,
    /// A session, but the far end isn't an exit that lets us in.
    NotAnExit,
    /// The mapping went away while we waited (unmapped elsewhere).
    Gone,
    /// The router stopped answering.
    Rpc(String),
}

impl WaitFail {
    fn message(&self, secs: u64) -> String {
        match self {
            WaitFail::NoSession => format!(
                "Couldn't reach that exit. Check the address. (no session to it after {secs} s; your routes were not changed)"
            ),
            WaitFail::NotAnExit => format!(
                "Couldn't reach that exit. Check the address. If it's right, the exit may only let in known clients: give its operator your address from my-client-address.txt. (no working session after {secs} s; your routes were not changed)"
            ),
            WaitFail::Gone => "The exit was unmapped while waiting for it (your routes were not changed)".to_string(),
            WaitFail::Rpc(e) => format!("lost the router while waiting for the exit: {e}"),
        }
    }
}

/// Polls `list` until `address` has a live session to an exit. `sleep` is how time
/// passes (the real one sleeps; tests just count), so this gives up after about
/// `timeout`.
fn wait_for_session(
    address: &str,
    timeout: Duration,
    step: Duration,
    mut list: impl FnMut() -> Result<ExitList, String>,
    mut sleep: impl FnMut(Duration),
) -> Result<(), WaitFail> {
    let mut waited = Duration::ZERO;
    let mut answered = false;
    loop {
        let l = list().map_err(WaitFail::Rpc)?;
        match l.exits.iter().find(|e| same_exit(&e.address, address)) {
            None => return Err(WaitFail::Gone),
            Some(e) if e.session_live && e.exit_capable => return Ok(()),
            Some(e) => answered |= e.session_live,
        }
        if waited >= timeout {
            break;
        }
        sleep(step);
        waited += step;
    }
    Err(if answered {
        WaitFail::NotAnExit
    } else {
        WaitFail::NoSession
    })
}

/// Before routing anything through an exit, map it for the probe address only and wait
/// until the session to it is live. On failure the probe mapping is removed and nothing
/// else is touched. Skips the probe when the exit is already live.
fn wait_live(
    c: &mut Client,
    address: &str,
    token: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = c.list_exits().map_err(|e| {
        format!("{e}; can't check the session to the exit first (--wait 0 maps without checking)")
    })?;
    if before
        .exits
        .iter()
        .any(|e| same_exit(&e.address, address) && e.session_live && e.exit_capable)
    {
        return Ok(());
    }
    let probe = MapExit {
        address: address.to_string(),
        full_tunnel: false,
        ip_ranges: vec![PROBE_RANGE.into()],
        token: token.to_string(),
    };
    c.map_exit(&probe)?;
    eprintln!(
        "waiting up to {} s for the session to the exit...",
        timeout.as_secs()
    );
    let r = wait_for_session(
        address,
        timeout,
        Duration::from_secs(1),
        || c.list_exits().map_err(|e| e.to_string()),
        std::thread::sleep,
    );
    match r {
        Ok(()) => Ok(()),
        Err(f) => {
            if f != WaitFail::Gone {
                // Best effort: the service's exit guard also drops it later.
                let _ = c.unmap_exit(address);
            }
            Err(f.message(timeout.as_secs()).into())
        }
    }
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

/// `--full` is a full tunnel. `--range` sends only those ranges. One of them is
/// required: this router's map_exit treats an empty range list as 0.0.0.0/0, and
/// it does not read the full_tunnel field, so a bare `map` would steal all
/// traffic.
fn map_request(
    address: &str,
    full: bool,
    range: &[String],
    token: &str,
) -> Result<MapExit, String> {
    if !address.ends_with(".sesh") {
        return Err(format!("{address} isn't a .sesh address"));
    }
    if !full && range.is_empty() {
        return Err(
            "say --full to send all traffic through the exit, or --range for a prefix".into(),
        );
    }
    let ip_ranges = if full && range.is_empty() {
        vec!["0.0.0.0/0".into()]
    } else {
        range.to_vec()
    };
    Ok(MapExit {
        address: address.to_string(),
        full_tunnel: full,
        ip_ranges,
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

/// The routes line for status and exits. The router says routes are up as soon as an
/// exit is mapped, even when there is no session to it; that is the state where nothing
/// gets out, so say that instead of "up".
fn routes_summary(l: &ExitList) -> String {
    let real: Vec<_> = l.exits.iter().filter(|e| !is_probe(e)).collect();
    if !l.exits.is_empty() && real.is_empty() {
        return "exit routes: down (waiting for the session to the exit)".to_string();
    }
    if l.routes_up == Some(true)
        && !real.is_empty()
        && !real.iter().any(|e| e.session_live && e.exit_capable)
    {
        return "exit routes: blocked (session to exit: down, so nothing gets through; run rusty-ctl unmap)".to_string();
    }
    routes_line(l.routes_up, l.routes_reason.as_deref())
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
    fn map_requires_full_or_range() {
        let err = map_request("a.sesh", false, &[], "").unwrap_err();
        assert!(err.contains("--full"), "{err}");
        let r = map_request("a.sesh", true, &[], "").unwrap();
        assert!(r.full_tunnel);
        assert_eq!(r.ip_ranges, ["0.0.0.0/0"]);
        let r = map_request("a.sesh", false, &["10.0.0.0/8".into()], "t").unwrap();
        assert!(!r.full_tunnel);
        assert_eq!(r.ip_ranges, ["10.0.0.0/8"]);
        assert_eq!(r.token, "t");
        assert!(map_request("example.com", true, &[], "").is_err());
    }

    #[test]
    fn cli_map_without_flags_still_parses() {
        let c = Cli::try_parse_from(["rusty-ctl", "map", "a.sesh"]).unwrap();
        match c.cmd {
            Cmd::Map { full, range, .. } => {
                assert!(!full);
                assert!(range.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
        let c = Cli::try_parse_from(["rusty-ctl", "map", "a.sesh", "--full"]).unwrap();
        match c.cmd {
            Cmd::Map { full, range, .. } => {
                assert!(full);
                assert!(range.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    fn exits(v: serde_json::Value) -> ExitList {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn session_wait_returns_once_live() {
        let mut polls = 0;
        let r = wait_for_session(
            "A.sesh",
            Duration::from_secs(45),
            Duration::from_secs(1),
            || {
                polls += 1;
                let live = polls >= 3;
                Ok(exits(json!({"routes_up": false, "exits": [
                    {"address": "a.sesh", "ranges": [PROBE_RANGE], "session_live": live, "exit_capable": live}
                ]})))
            },
            |_| {},
        );
        assert_eq!(r, Ok(()));
        assert_eq!(polls, 3);
    }

    #[test]
    fn session_wait_times_out() {
        let mut slept = Duration::ZERO;
        let mut polls = 0;
        let r = wait_for_session(
            "a.sesh",
            Duration::from_secs(30),
            Duration::from_secs(1),
            || {
                polls += 1;
                Ok(exits(
                    json!({"exits": [{"address": "a.sesh", "ranges": [PROBE_RANGE]}]}),
                ))
            },
            |d| slept += d,
        );
        assert_eq!(r, Err(WaitFail::NoSession));
        assert_eq!(slept, Duration::from_secs(30));
        assert_eq!(polls, 31);
        let m = WaitFail::NoSession.message(30);
        assert!(
            m.starts_with("Couldn't reach that exit. Check the address."),
            "{m}"
        );
        assert!(m.contains("not changed"));
    }

    #[test]
    fn session_wait_tells_live_but_not_exit_and_gone() {
        let r = wait_for_session(
            "a.sesh",
            Duration::from_secs(2),
            Duration::from_secs(1),
            || {
                Ok(exits(
                    json!({"exits": [{"address": "a.sesh", "session_live": true, "exit_capable": false}]}),
                ))
            },
            |_| {},
        );
        assert_eq!(r, Err(WaitFail::NotAnExit));
        // A stale address shows up here too (the router keeps a pending session), so it
        // gets the same first line.
        assert!(WaitFail::NotAnExit
            .message(2)
            .starts_with("Couldn't reach that exit. Check the address."));
        let r = wait_for_session(
            "a.sesh",
            Duration::from_secs(2),
            Duration::from_secs(1),
            || Ok(exits(json!({"exits": []}))),
            |_| {},
        );
        assert_eq!(r, Err(WaitFail::Gone));
        let r = wait_for_session(
            "a.sesh",
            Duration::from_secs(2),
            Duration::from_secs(1),
            || Err("connection reset".into()),
            |_| {},
        );
        assert_eq!(r, Err(WaitFail::Rpc("connection reset".into())));
    }

    #[test]
    fn never_says_routes_up_without_a_session() {
        // The stale-address case: router has the full tunnel in, session down.
        let l = exits(json!({"routes_up": true, "exits": [
            {"address": "a.sesh", "ranges": ["0.0.0.0/0"], "session_live": false, "exit_capable": false}
        ]}));
        let s = routes_summary(&l);
        assert!(!s.contains("up"), "{s}");
        assert!(s.contains("blocked"), "{s}");
        // Live but not an exit is just as stuck.
        let l = exits(json!({"routes_up": true, "exits": [
            {"address": "a.sesh", "ranges": ["0.0.0.0/0"], "session_live": true, "exit_capable": false}
        ]}));
        assert!(routes_summary(&l).contains("blocked"));
        let l = exits(json!({"routes_up": true, "exits": [
            {"address": "a.sesh", "ranges": ["0.0.0.0/0"], "session_live": true, "exit_capable": true}
        ]}));
        assert_eq!(routes_summary(&l), "exit routes: up");
        // Only the probe mapping: we are still waiting, nothing is routed.
        let l = exits(json!({"routes_up": true, "exits": [
            {"address": "a.sesh", "ranges": [PROBE_RANGE]}
        ]}));
        assert!(routes_summary(&l).starts_with("exit routes: down"));
        let l = exits(json!({"routes_up": false, "routes_reason": "no exit mapped", "exits": []}));
        assert_eq!(routes_summary(&l), "exit routes: down (no exit mapped)");
    }

    #[test]
    fn map_and_swap_wait_by_default() {
        let c = Cli::try_parse_from(["rusty-ctl", "map", "a.sesh", "--full"]).unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::Map {
                wait: DEFAULT_WAIT,
                ..
            }
        ));
        let c =
            Cli::try_parse_from(["rusty-ctl", "map", "a.sesh", "--full", "--wait", "0"]).unwrap();
        assert!(matches!(c.cmd, Cmd::Map { wait: 0, .. }));
        let c = Cli::try_parse_from(["rusty-ctl", "swap", "a.sesh", "b.sesh", "--full"]).unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::Swap {
                wait: DEFAULT_WAIT,
                ..
            }
        ));
        assert!(!takes_default(&MapExit {
            address: "a.sesh".into(),
            full_tunnel: false,
            ip_ranges: vec![PROBE_RANGE.into()],
            token: String::new(),
        }));
    }

    #[test]
    fn unmap_address_is_optional() {
        let c = Cli::try_parse_from(["rusty-ctl", "unmap"]).unwrap();
        assert!(matches!(c.cmd, Cmd::Unmap { address: None }));
        let c = Cli::try_parse_from(["rusty-ctl", "unmap", "a.sesh"]).unwrap();
        match c.cmd {
            Cmd::Unmap { address } => assert_eq!(address.as_deref(), Some("a.sesh")),
            other => panic!("unexpected {other:?}"),
        }
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
        // What the router does with no ranges at all.
        assert!(takes_default(&MapExit {
            address: "a.sesh".into(),
            ..Default::default()
        }));
        assert!(!takes_default(
            &map_request("a.sesh", false, &["10.0.0.0/8".into()], "").unwrap()
        ));
    }
}
