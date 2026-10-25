//! Recent security-relevant events (bad keys, refused credentials, ...),
//! kept in memory for the audit feed and logged as warnings. Bounded.
//!
//! Who can cause an event decides where it is kept, so nobody's noise can
//! evict anyone else's record:
//! - failed authentications (`bad_key`, `bad_admin_token`) come from anyone
//!   who can reach the broker: a ring of their own;
//! - events an agent causes (`credential_refused`: a held agent asking for
//!   a credential, as often as it likes) are kept per agent, at most
//!   [`PER_AGENT`] each, and when all agents' together pass [`KEEP`] the
//!   agent with the most loses its oldest: a flood from one agent evicts
//!   only its own events, never another agent's nor the operator's;
//! - the rest (`containment_lifted`: the operator's) has a ring of its own.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use agent_auth_wire::timestamp::truncate_to_micros;
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// Per ring, and all agents' events together.
const KEEP: usize = 5000;
/// One agent's events.
const PER_AGENT: usize = 200;

/// Kinds anyone unauthenticated can cause.
const UNAUTHENTICATED: [&str; 2] = ["bad_key", "bad_admin_token"];
/// Kinds an agent causes, attributed by their `agent` field.
const AGENT_CAUSED: [&str; 1] = ["credential_refused"];
const MAX_FIELD_CHARS: usize = 300;

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    /// `security.<kind>`
    pub kind: String,
    /// `s<seq>`
    pub id: String,
    /// Recording order, from 1.
    pub seq: u64,
    /// Truncated to microseconds, as on the wire (the audit cursor
    /// compares it with a time read back from one).
    pub at: OffsetDateTime,
    /// Each value cut to 300 characters.
    pub fields: Map<String, Value>,
}

#[derive(Debug, Default)]
struct Rings {
    seq: u64,
    unauthenticated: VecDeque<SecurityEvent>,
    /// By agent name.
    agents: BTreeMap<String, VecDeque<SecurityEvent>>,
    /// All of `agents`' events.
    agent_events: usize,
    other: VecDeque<SecurityEvent>,
}

impl Rings {
    fn push_agent(&mut self, agent: String, event: SecurityEvent) {
        let ring = self.agents.entry(agent).or_default();
        ring.push_back(event);
        self.agent_events = self.agent_events.saturating_add(1);
        if ring.len() > PER_AGENT {
            ring.pop_front();
            self.agent_events = self.agent_events.saturating_sub(1);
        }
        while self.agent_events > KEEP {
            // The noisiest agent pays.
            let Some(name) = self
                .agents
                .iter()
                .max_by_key(|(_, ring)| ring.len())
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            if let Some(ring) = self.agents.get_mut(&name) {
                ring.pop_front();
                if ring.is_empty() {
                    self.agents.remove(&name);
                }
            }
            self.agent_events = self.agent_events.saturating_sub(1);
        }
    }
}

fn push_ring(ring: &mut VecDeque<SecurityEvent>, event: SecurityEvent) {
    ring.push_back(event);
    while ring.len() > KEEP {
        ring.pop_front();
    }
}

#[derive(Debug, Default)]
pub struct SecurityLog {
    inner: Mutex<Rings>,
}

impl SecurityLog {
    /// Record an event. `fields` with `None` values are kept as null.
    pub fn record(&self, kind: &str, at: OffsetDateTime, fields: &[(&str, Option<&str>)]) {
        let mut map = Map::new();
        let mut line = String::new();
        for (k, v) in fields {
            let v = v.map(|s| s.chars().take(MAX_FIELD_CHARS).collect::<String>());
            if let Some(v) = &v {
                line.push_str(&format!(" {k}={v}"));
            }
            map.insert((*k).to_owned(), v.map_or(Value::Null, Value::String));
        }
        tracing::warn!("security.{kind}{line}");
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.seq = guard.seq.saturating_add(1);
        let event = SecurityEvent {
            kind: format!("security.{kind}"),
            id: format!("s{}", guard.seq),
            seq: guard.seq,
            at: truncate_to_micros(at),
            fields: map,
        };
        if UNAUTHENTICATED.contains(&kind) {
            push_ring(&mut guard.unauthenticated, event);
        } else if AGENT_CAUSED.contains(&kind) {
            let agent = event
                .fields
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            guard.push_agent(agent, event);
        } else {
            push_ring(&mut guard.other, event);
        }
    }

    /// Events at or after `when`, oldest first, at most `limit`.
    #[must_use]
    pub fn since(&self, when: OffsetDateTime, limit: usize) -> Vec<SecurityEvent> {
        self.since_after(when, None, limit)
    }

    /// Events after `when` and those at `when` recorded after `after`
    /// (all of them for `None`), oldest first, at most `limit`.
    #[must_use]
    pub fn since_after(
        &self,
        when: OffsetDateTime,
        after: Option<u64>,
        limit: usize,
    ) -> Vec<SecurityEvent> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<SecurityEvent> = guard
            .unauthenticated
            .iter()
            .chain(guard.agents.values().flatten())
            .chain(guard.other.iter())
            .filter(|e| e.at > when || (e.at == when && after.is_none_or(|a| e.seq > a)))
            .cloned()
            .collect();
        // Oldest first; the sequence breaks ties in recording order.
        out.sort_by_key(|e| (e.at, e.seq));
        out.truncate(limit);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flood_of_bad_keys_keeps_the_other_events() {
        let log = SecurityLog::default();
        let t0 = OffsetDateTime::UNIX_EPOCH;
        log.record("credential_refused", t0, &[("agent", Some("a"))]);
        for _ in 0..(KEEP + 10) {
            log.record("bad_key", t0, &[("reason", Some("malformed"))]);
        }
        let all = log.since(t0, usize::MAX);
        assert_eq!(all.len(), KEEP + 1);
        assert_eq!(
            all.first().map(|e| e.kind.as_str()),
            Some("security.credential_refused")
        );
    }

    fn refused(log: &SecurityLog, agent: &str, at: OffsetDateTime) {
        log.record(
            "credential_refused",
            at,
            &[
                ("agent", Some(agent)),
                ("grant", Some("g")),
                ("containment", Some("c1")),
            ],
        );
    }

    fn count(events: &[SecurityEvent], kind: &str, agent: &str) -> usize {
        events
            .iter()
            .filter(|e| {
                e.kind == kind && e.fields.get("agent").and_then(Value::as_str) == Some(agent)
            })
            .count()
    }

    #[test]
    fn one_agents_refusals_cannot_evict_anyone_elses_events() {
        let log = SecurityLog::default();
        let t0 = OffsetDateTime::UNIX_EPOCH;
        refused(&log, "quiet", t0);
        log.record(
            "containment_lifted",
            t0,
            &[("containment", Some("c1")), ("by", Some("operator"))],
        );
        // A held agent asking for its credential over and over.
        for _ in 0..(2 * KEEP) {
            refused(&log, "noisy", t0);
        }
        let all = log.since(t0, usize::MAX);
        assert_eq!(count(&all, "security.credential_refused", "quiet"), 1);
        assert_eq!(
            count(&all, "security.credential_refused", "noisy"),
            PER_AGENT
        );
        assert!(all.iter().any(|e| e.kind == "security.containment_lifted"));
    }

    #[test]
    fn since_after_is_exclusive_at_its_time() {
        let log = SecurityLog::default();
        let t0 = OffsetDateTime::UNIX_EPOCH;
        let t1 = t0 + time::Duration::microseconds(1);
        for _ in 0..3 {
            refused(&log, "a", t0);
        }
        refused(&log, "a", t1);
        let seqs = |v: Vec<SecurityEvent>| v.into_iter().map(|e| e.seq).collect::<Vec<_>>();
        assert_eq!(seqs(log.since_after(t0, None, 10)), [1, 2, 3, 4]);
        assert_eq!(seqs(log.since_after(t0, Some(2), 10)), [3, 4]);
        assert_eq!(seqs(log.since_after(t0, Some(u64::MAX), 10)), [4]);
        // Kept at the wire's precision, so a cursor read back matches.
        log.record("bad_key", t0 + time::Duration::nanoseconds(1500), &[]);
        assert_eq!(log.since(t0, 10).last().map(|e| e.at), Some(t1));
    }

    #[test]
    fn many_agents_together_stay_bounded_and_the_noisiest_pays() {
        let log = SecurityLog::default();
        let t0 = OffsetDateTime::UNIX_EPOCH;
        refused(&log, "quiet", t0);
        // Enough agents at their cap to pass KEEP together.
        let agents = KEEP / PER_AGENT + 5;
        for i in 0..agents {
            for _ in 0..PER_AGENT {
                refused(&log, &format!("noisy-{i}"), t0);
            }
        }
        let all = log.since(t0, usize::MAX);
        assert_eq!(all.len(), KEEP);
        assert_eq!(count(&all, "security.credential_refused", "quiet"), 1);
    }
}
