use rusty_service::config::Config;
use rusty_service::runner::{platform_net, supervise};
use rusty_service::supervisor::{Outcome, StopFlag};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
rusty-service: run Session Router and keep the network sane

usage:
  rusty-service run [--config FILE]       run in this window until Ctrl-C
  rusty-service restore [--config FILE]   undo route/DNS changes left by a crash
  rusty-service net [--config FILE]       show default routes and the uplink DNS goes on
  rusty-service install [--config FILE]   register the Windows service (manual start)
                                          and the network restore that runs at boot
  rusty-service uninstall                 remove both

FILE defaults to rusty-service.json next to this program.";

fn default_config() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("rusty-service.json")))
        .unwrap_or_else(|| PathBuf::from("rusty-service.json"))
}

fn config_arg(args: &[String]) -> PathBuf {
    args.windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(default_config)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run_foreground(&config_arg(&args)),
        Some("restore") => restore(&config_arg(&args)),
        Some("net") => show_net(&config_arg(&args)),
        #[cfg(windows)]
        Some("install") => rusty_service::winsvc::install(&config_arg(&args)),
        #[cfg(windows)]
        Some("uninstall") => rusty_service::winsvc::uninstall(),
        #[cfg(windows)]
        Some("service") => rusty_service::winsvc::dispatch(),
        #[cfg(windows)]
        Some("boot-restore") => rusty_service::winsvc::dispatch_boot_restore(),
        #[cfg(not(windows))]
        Some("install" | "uninstall" | "service" | "boot-restore") => {
            Err("the Windows service commands only work on Windows".into())
        }
        _ => {
            println!("{USAGE}");
            return if args.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rusty-service: {e}");
            ExitCode::FAILURE
        }
    }
}

fn restore(cfg_path: &std::path::Path) -> Result<(), String> {
    let cfg = Config::load(cfg_path)?;
    let rep = rusty_service::runner::restore_now(&cfg, std::time::Duration::ZERO)?;
    if rep.is_empty() {
        println!("nothing to restore");
    } else {
        println!(
            "removed {} route(s), restored DNS on {} interface(s)",
            rep.routes_removed, rep.dns_restored
        );
        if !rep.ipv6_reenabled.is_empty() {
            println!("turned IPv6 back on for {}", rep.ipv6_reenabled.join(", "));
        }
        if !rep.ipv6_gone.is_empty() {
            println!(
                "forgot IPv6 state for adapter(s) that are gone: {}",
                rep.ipv6_gone.join(", ")
            );
        }
        for e in &rep.errors {
            println!("problem: {e}");
        }
    }
    Ok(())
}

/// Read-only. The config is optional here; it only supplies `dns_interface`.
fn show_net(cfg_path: &std::path::Path) -> Result<(), String> {
    let pick = Config::load(cfg_path).ok().and_then(|c| c.dns_interface);
    let (routes, dns) = platform_net();
    let out = rusty_service::runner::describe_net(&routes, &dns, pick.as_deref())
        .map_err(|e| e.to_string())?;
    print!("{out}");
    Ok(())
}

fn run_foreground(cfg_path: &std::path::Path) -> Result<(), String> {
    let cfg = Config::load(cfg_path)?;
    let stop = StopFlag::default();
    let s2 = stop.clone();
    ctrlc::set_handler(move || s2.stop()).map_err(|e| e.to_string())?;
    let out = supervise(&cfg, &stop, &mut |l| eprintln!("{l}"))?;
    match out {
        Outcome::Stopped => Ok(()),
        Outcome::GaveUp { crashes, last_code } => Err(format!(
            "router crashed {crashes} times (last exit code {}); network settings were put back",
            last_code.map_or("unknown".to_string(), |c| c.to_string())
        )),
    }
}
