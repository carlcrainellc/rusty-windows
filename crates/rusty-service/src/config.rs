use crate::policy::RestartPolicy;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `rusty-service.json`, next to the executable unless given with `--config`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Path to `session-router.exe`.
    pub router_exe: PathBuf,
    /// Arguments, usually the path to the router's `.ini`.
    #[serde(default)]
    pub router_args: Vec<String>,
    #[serde(default = "default_rpc")]
    pub rpc: String,
    /// The router's `[api] auth=` value, for router builds that require it.
    #[serde(default)]
    pub rpc_auth: Option<String>,
    /// Where route and DNS changes are written down until undone.
    #[serde(default = "default_journal")]
    pub journal: PathBuf,
    /// Point the physical interface's DNS at the router's resolver while it runs.
    #[serde(default)]
    pub set_dns: Option<String>,
    /// Adapter to set DNS on, such as "Ethernet". By default, the physical adapter with
    /// the best default route; tunnel adapters are never picked.
    #[serde(default)]
    pub dns_interface: Option<String>,
    #[serde(default = "default_crashes")]
    pub max_crashes: usize,
    #[serde(default = "default_window")]
    pub crash_window_secs: u64,
    /// File for the router's console output. Defaults to `router-console.log` next to the
    /// config; set to null to discard it.
    #[serde(default = "default_console")]
    pub router_console_log: Option<PathBuf>,
    /// How long to wait after asking the router to stop before killing it.
    #[serde(default = "default_stop")]
    pub stop_timeout_secs: u64,
}

fn default_rpc() -> String {
    rusty_rpc::DEFAULT_ADDR.to_string()
}
fn default_journal() -> PathBuf {
    PathBuf::from("rusty-net.journal.json")
}
fn default_console() -> Option<PathBuf> {
    Some(PathBuf::from("router-console.log"))
}
fn default_crashes() -> usize {
    RestartPolicy::default().max_crashes
}
fn default_window() -> u64 {
    RestartPolicy::default().window.as_secs()
}
fn default_stop() -> u64 {
    15
}

/// Drops the `\\?\` prefix Windows' canonical paths carry, when the rest is an ordinary
/// drive path.
pub fn plain_path(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p,
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("can't read {}: {e}", path.display()))?;
        let mut c: Config =
            serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        // Relative paths are relative to the config file, not wherever the SCM started us.
        let base = path.parent().unwrap_or(Path::new("."));
        if c.router_exe.is_relative() {
            c.router_exe = base.join(&c.router_exe);
        }
        if c.journal.is_relative() {
            c.journal = base.join(&c.journal);
        }
        if let Some(l) = c.router_console_log.take() {
            c.router_console_log = Some(plain_path(if l.is_relative() { base.join(l) } else { l }));
        }
        c.router_exe = plain_path(c.router_exe);
        c.journal = plain_path(c.journal);
        if let Some(d) = &c.set_dns {
            d.parse::<std::net::IpAddr>()
                .map_err(|_| format!("set_dns: {d} isn't an IP address"))?;
        }
        Ok(c)
    }

    pub fn policy(&self) -> RestartPolicy {
        RestartPolicy {
            max_crashes: self.max_crashes,
            window: Duration::from_secs(self.crash_window_secs),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths() {
        assert_eq!(
            plain_path(PathBuf::from(r"\\?\C:\x\y.json")),
            PathBuf::from(r"C:\x\y.json")
        );
        assert_eq!(
            plain_path(PathBuf::from(r"\\?\UNC\srv\share")),
            PathBuf::from(r"\\?\UNC\srv\share")
        );
        assert_eq!(plain_path(PathBuf::from("/tmp/a")), PathBuf::from("/tmp/a"));
    }

    #[test]
    fn loads_with_defaults_and_relative_paths() {
        let dir = std::env::temp_dir().join(format!("rusty-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("rusty-service.json");
        std::fs::write(&p, br#"{"router_exe": "session-router.exe", "router_args": ["client.ini"], "set_dns": "127.0.0.1"}"#).unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.router_exe, dir.join("session-router.exe"));
        assert_eq!(c.journal, dir.join("rusty-net.journal.json"));
        assert_eq!(c.rpc, "127.0.0.1:1190");
        assert_eq!(c.policy().max_crashes, 5);
        std::fs::write(&p, br#"{"router_exe": "x", "set_dns": "localhost"}"#).unwrap();
        assert!(Config::load(&p).is_err());
        std::fs::write(&p, br#"{"router_exe": "x", "typo": 1}"#).unwrap();
        assert!(Config::load(&p).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
