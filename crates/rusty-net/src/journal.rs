//! A record of every change made to the system, kept on disk until it has been undone.

use crate::Route;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsBefore {
    pub if_index: u32,
    /// What the interface had before we changed it. Empty means automatic.
    pub servers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    #[serde(default)]
    pub pinned: Vec<Route>,
    #[serde(default)]
    pub dns: Vec<DnsBefore>,
    /// Adapters that had IPv6 turned on before the router started.
    #[serde(default)]
    pub ipv6_enabled: Vec<String>,
}

impl Journal {
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty() && self.dns.is_empty() && self.ipv6_enabled.is_empty()
    }

    /// A missing file is an empty journal.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Journal::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes to a temporary file and renames it over the old one, so a crash mid-write
    /// leaves either the old journal or the new one, never half of one.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if self.is_empty() {
            return match std::fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_empty_removes_file() {
        let p = std::env::temp_dir().join(format!("rusty-journal-{}.json", std::process::id()));
        let mut j = Journal::default();
        j.dns.push(DnsBefore {
            if_index: 3,
            servers: vec!["1.1.1.1".parse().unwrap()],
        });
        j.save(&p).unwrap();
        assert_eq!(Journal::load(&p).unwrap(), j);
        Journal::default().save(&p).unwrap();
        assert!(!p.exists());
        assert!(Journal::load(&p).unwrap().is_empty());
    }

    #[test]
    fn corrupt_journal_is_an_error_not_silence() {
        let p = std::env::temp_dir().join(format!("rusty-journal-bad-{}.json", std::process::id()));
        std::fs::write(&p, b"{not json").unwrap();
        assert!(Journal::load(&p).is_err());
        let _ = std::fs::remove_file(p);
    }
}
