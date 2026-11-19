//! When to restart the router after it exits, and when to stop trying.
//!
//! A router that crashes on start would otherwise restart forever, and every restart
//! moves routes and DNS around. That's how a machine ends up with no internet until a
//! hard power-off. After too many crashes in a short time we stop, put the network back
//! the way it was, and leave the service stopped with a clear reason.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Give up after this many exits inside `window`.
    pub max_crashes: usize,
    pub window: Duration,
    pub first_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy {
            max_crashes: 5,
            window: Duration::from_secs(10 * 60),
            first_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    RestartAfter(Duration),
    GiveUp { crashes: usize },
}

#[derive(Debug, Default)]
pub struct CrashHistory {
    exits: Vec<Instant>,
}

impl CrashHistory {
    pub fn on_exit(&mut self, policy: &RestartPolicy, now: Instant) -> Decision {
        self.exits
            .retain(|t| now.saturating_duration_since(*t) < policy.window);
        self.exits.push(now);
        let n = self.exits.len();
        if n >= policy.max_crashes {
            return Decision::GiveUp { crashes: n };
        }
        let factor = 1u32 << (n.saturating_sub(1).min(16) as u32);
        let delay = policy
            .first_delay
            .saturating_mul(factor)
            .min(policy.max_delay);
        Decision::RestartAfter(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_off_then_gives_up() {
        let p = RestartPolicy::default();
        let mut h = CrashHistory::default();
        let t0 = Instant::now();
        assert_eq!(
            h.on_exit(&p, t0),
            Decision::RestartAfter(Duration::from_secs(2))
        );
        assert_eq!(
            h.on_exit(&p, t0 + Duration::from_secs(5)),
            Decision::RestartAfter(Duration::from_secs(4))
        );
        assert_eq!(
            h.on_exit(&p, t0 + Duration::from_secs(10)),
            Decision::RestartAfter(Duration::from_secs(8))
        );
        assert_eq!(
            h.on_exit(&p, t0 + Duration::from_secs(20)),
            Decision::RestartAfter(Duration::from_secs(16))
        );
        assert_eq!(
            h.on_exit(&p, t0 + Duration::from_secs(40)),
            Decision::GiveUp { crashes: 5 }
        );
    }

    #[test]
    fn old_crashes_age_out() {
        let p = RestartPolicy {
            max_crashes: 3,
            ..Default::default()
        };
        let mut h = CrashHistory::default();
        let t0 = Instant::now();
        h.on_exit(&p, t0);
        h.on_exit(&p, t0 + Duration::from_secs(1));
        // Eleven minutes later the first two no longer count.
        assert_eq!(
            h.on_exit(&p, t0 + Duration::from_secs(11 * 60)),
            Decision::RestartAfter(Duration::from_secs(2))
        );
    }

    #[test]
    fn delay_is_capped() {
        let p = RestartPolicy {
            max_crashes: 100,
            ..Default::default()
        };
        let mut h = CrashHistory::default();
        let t0 = Instant::now();
        let mut last = Decision::RestartAfter(Duration::ZERO);
        for i in 0..20 {
            last = h.on_exit(&p, t0 + Duration::from_millis(i));
        }
        assert_eq!(last, Decision::RestartAfter(Duration::from_secs(60)));
    }
}
