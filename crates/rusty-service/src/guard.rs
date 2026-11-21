//! Exit guard: never leave the computer with dead routes.
//!
//! The router puts a full-tunnel exit's routes in as soon as it is connected to the
//! network, before the session to the exit is up. If the exit never answers, or stops
//! answering, or another VPN takes the traffic, those routes stay and nothing gets out
//! until someone stops the service. The guard watches `list_exits` and the route table and
//! unmaps the exit when:
//!
//! - the session to it isn't live within `map_timeout` of mapping (exit not answering),
//! - it was live and has been down for `lost_grace` (exit stopped answering, or the uplink
//!   changed and the router couldn't get back to it),
//! - another VPN carries the traffic (turned on before or after mapping).
//!
//! Unmapping makes the router take its routes down and turn IPv6 back on. The supervisor
//! then checks that nothing of ours is left holding the route. This module is the pure
//! state machine; the supervisor feeds it and carries out what it says.

use rusty_net::vpn::OtherVpn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// One mapped exit as the guard sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitView {
    pub address: String,
    /// Session up and the far end is an exit.
    pub live: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    OtherVpn,
    ExitNotAnswering,
    ExitLost,
}

/// What the guard wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmap {
    pub addresses: Vec<String>,
    pub why: Why,
    /// Plain message for the log, rusty-ctl and SeshSwap.
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
pub struct GuardTimes {
    pub map_timeout: Duration,
    pub lost_grace: Duration,
}

impl Default for GuardTimes {
    fn default() -> Self {
        GuardTimes {
            map_timeout: Duration::from_secs(90),
            lost_grace: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
struct Track {
    mapped_at: Instant,
    was_live: bool,
    down_since: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct Guard {
    pub times: GuardTimes,
    tracked: BTreeMap<String, Track>,
}

pub fn short(a: &str) -> String {
    if a.len() > 16 {
        format!("{}…{}", &a[..8], &a[a.len() - 6..])
    } else {
        a.to_string()
    }
}

impl Guard {
    pub fn new(times: GuardTimes) -> Self {
        Guard {
            times,
            tracked: BTreeMap::new(),
        }
    }

    /// Forget everything (router restarted).
    pub fn reset(&mut self) {
        self.tracked.clear();
    }

    /// Exits being watched right now.
    pub fn watching(&self) -> usize {
        self.tracked.len()
    }

    /// One look. `exits` is what `list_exits` said; `other` is another VPN carrying the
    /// traffic, if any.
    pub fn tick(
        &mut self,
        now: Instant,
        exits: &[ExitView],
        other: Option<&OtherVpn>,
    ) -> Option<Unmap> {
        self.tracked
            .retain(|a, _| exits.iter().any(|e| &e.address == a));
        for e in exits {
            self.tracked.entry(e.address.clone()).or_insert(Track {
                mapped_at: now,
                was_live: false,
                down_since: None,
            });
        }
        if exits.is_empty() {
            return None;
        }
        if let Some(v) = other {
            let addresses: Vec<String> = exits.iter().map(|e| e.address.clone()).collect();
            for a in &addresses {
                self.tracked.remove(a);
            }
            return Some(Unmap {
                addresses,
                why: Why::OtherVpn,
                message: format!(
                    "Another VPN is holding your connection ({}), so the exit was unmapped. Disconnect it or turn off its kill switch, then map again.",
                    v.name
                ),
            });
        }
        let mut not_answering = Vec::new();
        let mut lost = Vec::new();
        for e in exits {
            let t = self.tracked.get_mut(&e.address).expect("tracked above");
            if e.live {
                t.was_live = true;
                t.down_since = None;
                continue;
            }
            if !t.was_live {
                if now.saturating_duration_since(t.mapped_at) >= self.times.map_timeout {
                    not_answering.push(e.address.clone());
                }
                continue;
            }
            let since = *t.down_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= self.times.lost_grace {
                lost.push(e.address.clone());
            }
        }
        if !not_answering.is_empty() {
            for a in &not_answering {
                self.tracked.remove(a);
            }
            let secs = self.times.map_timeout.as_secs();
            return Some(Unmap {
                message: format!(
                    "Exit {} isn't answering (no path to it after {secs} s), so it was unmapped. Your normal connection is back.",
                    short(&not_answering[0])
                ),
                addresses: not_answering,
                why: Why::ExitNotAnswering,
            });
        }
        if !lost.is_empty() {
            for a in &lost {
                self.tracked.remove(a);
            }
            return Some(Unmap {
                message: format!(
                    "Exit {} stopped answering, so it was unmapped. Your normal connection is back.",
                    short(&lost[0])
                ),
                addresses: lost,
                why: Why::ExitLost,
            });
        }
        None
    }
}

/// What the guard last did, written to `exit-guard.json` next to the config so rusty-ctl
/// and SeshSwap can say why an exit went away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastRollback {
    /// Seconds since 1970.
    pub time: u64,
    pub addresses: Vec<String>,
    pub why: Why,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "9khgtg5qmi41uqzy9drufqso3ncwqdfz1d6jbjer5k1acqbbhcto.sesh";

    fn ex(live: bool) -> Vec<ExitView> {
        vec![ExitView {
            address: A.into(),
            live,
        }]
    }
    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }
    fn nord() -> OtherVpn {
        OtherVpn {
            name: "NordVPN".into(),
            adapter: "NordLynx".into(),
            if_index: 31,
            route: "0.0.0.0/1".into(),
        }
    }

    #[test]
    fn nothing_mapped_nothing_to_do() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        assert_eq!(g.tick(t0, &[], Some(&nord())), None);
        assert_eq!(g.tick(t0 + s(500), &[], None), None);
    }

    #[test]
    fn exit_that_never_answers_is_unmapped_after_90s() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        assert_eq!(g.tick(t0, &ex(false), None), None);
        assert_eq!(g.tick(t0 + s(60), &ex(false), None), None);
        assert_eq!(g.tick(t0 + s(89), &ex(false), None), None);
        let u = g.tick(t0 + s(90), &ex(false), None).expect("rolled back");
        assert_eq!(u.why, Why::ExitNotAnswering);
        assert_eq!(u.addresses, vec![A.to_string()]);
        assert!(u.message.contains("isn't answering"), "{}", u.message);
        assert!(u.message.contains("normal connection is back"));
        assert_eq!(g.watching(), 0);
    }

    #[test]
    fn slow_but_working_exit_is_kept() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        assert_eq!(g.tick(t0, &ex(false), None), None);
        assert_eq!(g.tick(t0 + s(70), &ex(true), None), None);
        // Live long after the map timeout: fine.
        assert_eq!(g.tick(t0 + s(600), &ex(true), None), None);
    }

    #[test]
    fn short_drop_is_tolerated_long_drop_unmaps() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        g.tick(t0, &ex(true), None);
        assert_eq!(g.tick(t0 + s(100), &ex(false), None), None); // drop starts
        assert_eq!(g.tick(t0 + s(120), &ex(true), None), None); // back within 30 s
        assert_eq!(g.tick(t0 + s(200), &ex(false), None), None); // drop again
        assert_eq!(g.tick(t0 + s(229), &ex(false), None), None);
        let u = g.tick(t0 + s(230), &ex(false), None).unwrap();
        assert_eq!(u.why, Why::ExitLost);
        assert!(u.message.contains("stopped answering"));
    }

    #[test]
    fn other_vpn_unmaps_at_once_while_mapping_or_mapped() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        let u = g.tick(t0, &ex(false), Some(&nord())).unwrap();
        assert_eq!(u.why, Why::OtherVpn);
        assert!(u
            .message
            .contains("Another VPN is holding your connection (NordVPN)"));
        // Mapped again, live, then a VPN is turned on underneath.
        let mut g = Guard::default();
        g.tick(t0, &ex(true), None);
        assert_eq!(g.tick(t0 + s(5), &ex(true), None), None);
        assert_eq!(
            g.tick(t0 + s(10), &ex(true), Some(&nord())).unwrap().why,
            Why::OtherVpn
        );
    }

    #[test]
    fn remapping_starts_the_clock_again() {
        let mut g = Guard::default();
        let t0 = Instant::now();
        g.tick(t0, &ex(false), None);
        // Unmapped by hand at 50 s, mapped again at 80 s.
        g.tick(t0 + s(50), &[], None);
        assert_eq!(g.tick(t0 + s(80), &ex(false), None), None);
        assert_eq!(g.tick(t0 + s(169), &ex(false), None), None);
        assert!(g.tick(t0 + s(170), &ex(false), None).is_some());
    }

    #[test]
    fn rollback_record_round_trips() {
        let r = LastRollback {
            time: 1,
            addresses: vec![A.into()],
            why: Why::ExitNotAnswering,
            message: "m".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"why\":\"exit_not_answering\""), "{j}");
        assert_eq!(serde_json::from_str::<LastRollback>(&j).unwrap(), r);
    }
}
