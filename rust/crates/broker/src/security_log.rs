//! Recent security-relevant events (bad keys, refused credentials, ...),
//! kept in memory for the audit feed and logged as warnings. Bounded.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value};
use time::OffsetDateTime;

const KEEP: usize = 2000;
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
pub struct SecurityLog {
    inner: Mutex<(u64, VecDeque<SecurityEvent>)>,
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
        guard.0 = guard.0.saturating_add(1);
        let id = format!("s{}", guard.0);
        guard.1.push_back(SecurityEvent {
            kind: format!("security.{kind}"),
            id,
            at,
            fields: map,
        });
        while guard.1.len() > KEEP {
            guard.1.pop_front();
        }
    }

    /// Events at or after `when`, oldest first, at most `limit`.
    #[must_use]
    pub fn since(&self, when: OffsetDateTime, limit: usize) -> Vec<SecurityEvent> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .1
            .iter()
            .filter(|e| e.at >= when)
            .take(limit)
            .cloned()
            .collect()
    }
}
