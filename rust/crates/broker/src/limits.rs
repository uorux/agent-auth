//! Per-agent limits on the spine's routes (one process; see ARCHITECTURE
//! "Deployment"): concurrent decision long-polls, and the rate of new
//! requests (a GCRA token bucket: `per_hour` requests per hour, all of them
//! at once at most).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use agent_auth_core::AgentId;

const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub struct Limits {
    /// Concurrent `/v1/requests/{id}/wait` per agent (0: no limit).
    pub max_waits: u32,
    /// New requests per agent per hour (0: no limit).
    pub requests_per_hour: u32,
    waits: Mutex<HashMap<AgentId, u32>>,
    /// Theoretical arrival time per agent.
    buckets: Mutex<HashMap<AgentId, Instant>>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits::new(16, 60)
    }
}

impl Limits {
    #[must_use]
    pub fn new(max_waits: u32, requests_per_hour: u32) -> Limits {
        Limits {
            max_waits,
            requests_per_hour,
            waits: Mutex::default(),
            buckets: Mutex::default(),
        }
    }

    /// Decision long-polls holding a slot right now, all agents together
    /// (diagnostics; tests wait on it instead of sleeping).
    #[must_use]
    pub fn waits_in_progress(&self) -> u32 {
        self.waits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .fold(0, |n, w| n.saturating_add(*w))
    }

    /// May `agent` file another request now? Spends one if so.
    pub fn take_request(&self, agent: AgentId, now: Instant) -> bool {
        if self.requests_per_hour == 0 {
            return true;
        }
        let interval = HOUR.checked_div(self.requests_per_hour).unwrap_or(HOUR);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        // Forget agents whose bucket is full again.
        if buckets.len() > 10_000 {
            buckets.retain(|_, tat| *tat > now);
        }
        let tat = buckets
            .get(&agent)
            .copied()
            .filter(|t| *t > now)
            .unwrap_or(now);
        let next = tat.checked_add(interval).unwrap_or(tat);
        if next.saturating_duration_since(now) > HOUR {
            return false;
        }
        buckets.insert(agent, next);
        true
    }
}

/// A long-poll in progress; dropping it frees the slot.
#[derive(Debug)]
pub struct WaitSlot {
    limits: Arc<crate::service::Spine>,
    agent: AgentId,
}

impl Drop for WaitSlot {
    fn drop(&mut self) {
        let mut waits = self
            .limits
            .limits
            .waits
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = waits.get_mut(&self.agent) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                waits.remove(&self.agent);
            }
        }
    }
}

/// A wait slot for `agent`, unless it has `max_waits` in progress.
#[must_use]
pub fn wait_slot(spine: &Arc<crate::service::Spine>, agent: AgentId) -> Option<WaitSlot> {
    let limits = &spine.limits;
    let mut waits = limits.waits.lock().unwrap_or_else(PoisonError::into_inner);
    let n = waits.entry(agent).or_insert(0);
    if limits.max_waits != 0 && *n >= limits.max_waits {
        return None;
    }
    *n = n.saturating_add(1);
    Some(WaitSlot {
        limits: Arc::clone(spine),
        agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_allows_its_rate_then_refills() {
        let l = Limits::new(0, 3);
        let a = AgentId::new();
        let t0 = Instant::now();
        assert!(l.take_request(a, t0));
        assert!(l.take_request(a, t0));
        assert!(l.take_request(a, t0));
        assert!(!l.take_request(a, t0));
        // Another agent has its own.
        assert!(l.take_request(AgentId::new(), t0));
        // A third of an hour later, one more.
        let later = t0.checked_add(Duration::from_secs(1201)).unwrap_or(t0);
        assert!(l.take_request(a, later));
        assert!(!l.take_request(a, later));
        assert!(Limits::new(0, 0).take_request(a, t0));
    }

    #[test]
    fn wait_slots_are_counted_and_freed() {
        let mut spine = crate::service::Spine::default();
        spine.limits = Limits::new(2, 0);
        let spine = Arc::new(spine);
        let a = AgentId::new();
        let s1 = wait_slot(&spine, a);
        let s2 = wait_slot(&spine, a);
        assert!(s1.is_some() && s2.is_some());
        assert!(wait_slot(&spine, a).is_none());
        drop(s1);
        assert!(wait_slot(&spine, a).is_some());
    }
}
