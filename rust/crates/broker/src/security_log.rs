//! Recent security-relevant events (bad keys, refused credentials, ...),
//! kept in memory for the audit feed and logged as warnings. Bounded.
//!
//! Failed authentications (`bad_key`, `bad_admin_token`) come from anyone
//! who can reach the broker, so they have a ring of their own: a flood of
//! them cannot evict the other events (refused credentials, lifted
//! containments).

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value};
use time::OffsetDateTime;

/// Per ring.
const KEEP: usize = 5000;

/// Kinds anyone unauthenticated can cause.
const UNAUTHENTICATED: [&str; 2] = ["bad_key", "bad_admin_token"];
const MAX_FIELD_CHARS: usize = 300;

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    /// `security.<kind>`
    pub kind: String,
    /// `s<seq>`
    pub id: String,
    pub at: OffsetDateTime,
    /// Each value cut to 300 characters.
    pub fields: Map<String, Value>,
}

#[derive(Debug, Default)]
struct Rings {
    seq: u64,
    unauthenticated: VecDeque<SecurityEvent>,
    other: VecDeque<SecurityEvent>,
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
            at,
            fields: map,
        };
        let ring = if UNAUTHENTICATED.contains(&kind) {
            &mut guard.unauthenticated
        } else {
            &mut guard.other
        };
        ring.push_back(event);
        while ring.len() > KEEP {
            ring.pop_front();
        }
    }

    /// Events at or after `when`, oldest first, at most `limit`.
    #[must_use]
    pub fn since(&self, when: OffsetDateTime, limit: usize) -> Vec<SecurityEvent> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<SecurityEvent> = guard
            .unauthenticated
            .iter()
            .chain(guard.other.iter())
            .filter(|e| e.at >= when)
            .cloned()
            .collect();
        // Oldest first; ids break ties in recording order.
        out.sort_by_key(|e| {
            (
                e.at,
                e.id.trim_start_matches('s').parse::<u64>().unwrap_or(0),
            )
        });
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
}
