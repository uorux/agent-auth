//! A per-agent cap on concurrent long-polls (`GET …/messages?wait=`,
//! `GET /v1/a2a/events?wait=`): each parked poll holds a slot until it
//! returns; past the cap the call is 429.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use agent_auth_core::AgentId;

#[derive(Debug, Default)]
pub(crate) struct PollSlots {
    held: Mutex<HashMap<AgentId, u32>>,
}

/// A held slot; dropping it frees the slot.
#[derive(Debug)]
pub(crate) struct PollSlot<'a> {
    slots: &'a PollSlots,
    agent: AgentId,
}

impl PollSlots {
    /// A slot for `agent`, unless it already holds `cap`.
    pub(crate) fn take(&self, agent: AgentId, cap: u32) -> Option<PollSlot<'_>> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let n = held.entry(agent).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n = n.saturating_add(1);
        Some(PollSlot { slots: self, agent })
    }
}

impl PollSlots {
    /// Slots held right now, all agents together.
    pub(crate) fn in_use(&self) -> u32 {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .fold(0, |n, h| n.saturating_add(*h))
    }
}

impl Drop for PollSlot<'_> {
    fn drop(&mut self) {
        let mut held = self
            .slots
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = held.get_mut(&self.agent) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                held.remove(&self.agent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_capped_per_agent_and_freed_on_drop() {
        let slots = PollSlots::default();
        let (a, b) = (AgentId::new(), AgentId::new());
        let one = slots.take(a, 2).unwrap();
        let two = slots.take(a, 2).unwrap();
        assert!(slots.take(a, 2).is_none());
        assert!(slots.take(b, 2).is_some(), "per agent");
        drop(one);
        let three = slots.take(a, 2).unwrap();
        drop((two, three));
        assert!(slots.held.lock().unwrap().is_empty());
    }
}
