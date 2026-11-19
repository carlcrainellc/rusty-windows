//! The Windows service: registration and the SCM entry point.
//!
//! The service is registered for manual start. A second, tiny service starts at boot,
//! undoes whatever the journal still holds (after a power cut, a hard reset, or a
//! shutdown that didn't give us time to clean up) and stops again. It runs as LocalSystem because changing
//! routes and DNS needs it. Stopping the service halts the router through its RPC,
//! kills it if it doesn't go, and puts routes and DNS back before reporting stopped.

use crate::config::Config;
use crate::runner::supervise;
use crate::supervisor::{Outcome, StopFlag};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "RustySessionRouter";
const DISPLAY: &str = "Session Router (Rusty)";
pub const RESTORE_NAME: &str = "RustyNetRestore";
const RESTORE_DISPLAY: &str = "Session Router (Rusty) network restore at boot";

static CONFIG: OnceLock<PathBuf> = OnceLock::new();

pub fn install(config: &Path) -> Result<(), String> {
    let config = std::fs::canonicalize(config).map_err(|e| format!("{}: {e}", config.display()))?;
    // canonicalize gives a \\?\ path; plain programs (the router among them) choke on it.
    let config = crate::config::plain_path(config);
    Config::load(&config)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("can't open the service manager (run as administrator): {e}"))?;
    let info = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from(DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: windows_service::service::ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            config.into_os_string(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    mgr.create_service(&info, ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("can't create the service: {e}"))?;
    let restore = ServiceInfo {
        name: OsString::from(RESTORE_NAME),
        display_name: OsString::from(RESTORE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: windows_service::service::ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: info.executable_path.clone(),
        launch_arguments: vec![
            OsString::from("boot-restore"),
            OsString::from("--config"),
            info.launch_arguments[2].clone(),
        ],
        // After the TCP/IP stack and DHCP client, so adapters and DNS settings exist.
        dependencies: vec![
            windows_service::service::ServiceDependency::Service(OsString::from("Tcpip")),
            windows_service::service::ServiceDependency::Service(OsString::from("Dhcp")),
        ],
        account_name: None,
        account_password: None,
    };
    mgr.create_service(&restore, ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("can't create {RESTORE_NAME}: {e}"))?;
    println!("installed {NAME} (manual start). Start it with: sc start {NAME}");
    println!("installed {RESTORE_NAME} (runs at boot, puts the network back if needed)");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("can't open the service manager (run as administrator): {e}"))?;
    remove(&mgr, NAME, true)?;
    // Older installs don't have it.
    remove(&mgr, RESTORE_NAME, false)
}

fn remove(mgr: &ServiceManager, name: &str, required: bool) -> Result<(), String> {
    let svc = match mgr.open_service(
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(_) if !required => return Ok(()),
        Err(e) => return Err(format!("can't open {name}: {e}")),
    };
    if let Ok(st) = svc.query_status() {
        if st.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            for _ in 0..60 {
                std::thread::sleep(Duration::from_millis(500));
                if matches!(
                    svc.query_status().map(|s| s.current_state),
                    Ok(ServiceState::Stopped)
                ) {
                    break;
                }
            }
        }
    }
    svc.delete()
        .map_err(|e| format!("can't remove {name}: {e}"))?;
    println!("removed {name}");
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);
define_windows_service!(ffi_restore_main, restore_main);

/// Called by `rusty-service service --config FILE`, which is how the SCM starts us.
pub fn dispatch() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cfg = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]))
        .ok_or("missing --config")?;
    let _ = CONFIG.set(cfg);
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| e.to_string())
}

/// `rusty-service boot-restore --config FILE`, the boot-time restore service.
pub fn dispatch_boot_restore() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cfg = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]))
        .ok_or("missing --config")?;
    let _ = CONFIG.set(cfg);
    service_dispatcher::start(RESTORE_NAME, ffi_restore_main).map_err(|e| e.to_string())
}

fn file_log(cfg_path: &Path) -> impl FnMut(&str) {
    let mut logf = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cfg_path.with_file_name("rusty-service.log"))
        .ok();
    move |l: &str| {
        if let Some(f) = logf.as_mut() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "{t} {l}");
        }
    }
}

fn restore_main(_args: Vec<OsString>) {
    let cfg_path = CONFIG.get().cloned().unwrap_or_default();
    let mut log = file_log(&cfg_path);
    let Ok(handle) = service_control_handler::register(RESTORE_NAME, |ev| match ev {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let _ = handle.set_service_status(ServiceStatus {
        controls_accepted: ServiceControlAccept::empty(),
        ..status(ServiceState::Running, 0, Duration::ZERO)
    });
    let code = match Config::load(&cfg_path)
        .and_then(|cfg| crate::runner::restore_now(&cfg, Duration::from_secs(90)))
    {
        Ok(rep) if rep.is_empty() => 0,
        Ok(rep) => {
            log(&format!(
                "at boot: undid changes left from before: {} route(s), DNS on {} interface(s){}{}{}",
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
                    format!(", forgot gone adapter(s) {}", rep.ipv6_gone.join(", "))
                },
                if rep.errors.is_empty() {
                    String::new()
                } else {
                    format!("; problems: {}", rep.errors.join("; "))
                }
            ));
            if rep.errors.is_empty() {
                0
            } else {
                1
            }
        }
        Err(e) => {
            log(&format!("at boot: couldn't restore: {e}"));
            1
        }
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, code, Duration::ZERO));
}

fn status(state: ServiceState, code: u32, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        // A service-specific code of 0 still reads as a failure to the service manager.
        exit_code: if code == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(code)
        },
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let cfg_path = CONFIG.get().cloned().unwrap_or_default();
    let mut log = file_log(&cfg_path);

    let stop = StopFlag::default();
    let s2 = stop.clone();
    let handle_cell: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let cell2 = handle_cell.clone();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s2.stop();
            // Tell the service manager we're on it: halting the router and putting the
            // network back can take a while.
            if let Some(h) = cell2.get() {
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    0,
                    Duration::from_secs(45),
                ));
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(NAME, handler) else {
        return;
    };
    let _ = handle_cell.set(handle);
    let set = |state, code: u32, wait: Duration| {
        let _ = handle.set_service_status(status(state, code, wait));
    };
    set(ServiceState::Running, 0, Duration::ZERO);

    let code = match Config::load(&cfg_path) {
        Err(e) => {
            log(&e);
            1
        }
        Ok(cfg) => match supervise(&cfg, &stop, &mut log) {
            Ok(Outcome::Stopped) => 0,
            Ok(Outcome::GaveUp { .. }) => 2,
            Err(e) => {
                log(&e);
                1
            }
        },
    };
    set(ServiceState::Stopped, code, Duration::ZERO);
}
