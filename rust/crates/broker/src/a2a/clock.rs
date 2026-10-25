//! The time stamped into `a2a_threads.last_activity_at`, and the horizon
//! below which the events feed may trust it (a2a B3).
//!
//! The Python stamped activity with the application clock before commit,
//! so a transaction committing later could carry an earlier timestamp than
//! one a reader had already returned: the reader's cursor moved past it and
//! the strict `> after` never returned it. Here every write of
//! `last_activity_at` takes a [`Stamp`] from this clock and holds it until
//! its transaction has committed (or rolled back). Stamps are strictly
//! increasing and microsecond-precise (what Postgres keeps). A reader asks
//! for the [`ActivityClock::horizon`] before it queries: the oldest stamp
//! still in flight, or else a time no future stamp can be below. Rows
//! stamped at or after the horizon are left for the next poll, so:
//!
//! - everything a reader returns below the horizon was committed before its
//!   query started (a stamp below the horizon belongs to a writer that had
//!   already finished), and
//! - everything it leaves out is at or above the horizon, so above the
//!   cursor it returns.
//!
//! No activity is skipped and none is repeated. The overlap is only in
//! time: a reader may hold back a committed row for as long as an older
//! writer is still in flight (milliseconds); that writer's commit wakes the
//! reader. Like the long-poll wake-ups, this is per process: the broker
//! runs as one.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use agent_auth_wire::timestamp::truncate_to_micros;
use time::{Duration, OffsetDateTime};

const TICK: Duration = Duration::microseconds(1);

#[derive(Debug)]
struct State {
    /// The latest stamp handed out (or floor set by a horizon).
    last: OffsetDateTime,
    next_id: u64,
    in_flight: BTreeMap<u64, OffsetDateTime>,
}

#[derive(Debug)]
pub(crate) struct ActivityClock {
    state: Mutex<State>,
}

impl Default for ActivityClock {
    fn default() -> Self {
        ActivityClock {
            state: Mutex::new(State {
                last: OffsetDateTime::UNIX_EPOCH,
                next_id: 0,
                in_flight: BTreeMap::new(),
            }),
        }
    }
}

/// A stamp in flight. Drop it after the transaction that wrote it ended.
#[derive(Debug)]
pub(crate) struct Stamp<'c> {
    clock: &'c ActivityClock,
    id: u64,
    pub at: OffsetDateTime,
}

impl Drop for Stamp<'_> {
    fn drop(&mut self) {
        let mut s = self
            .clock
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        s.in_flight.remove(&self.id);
    }
}

fn now() -> OffsetDateTime {
    truncate_to_micros(OffsetDateTime::now_utc())
}

impl ActivityClock {
    /// A new stamp: now, but always after every earlier stamp and horizon.
    pub(crate) fn stamp(&self) -> Stamp<'_> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let at = now().max(s.last.saturating_add(TICK));
        s.last = at;
        let id = s.next_id;
        s.next_id = s.next_id.wrapping_add(1);
        s.in_flight.insert(id, at);
        Stamp {
            clock: self,
            id,
            at,
        }
    }

    /// Activity strictly below this is settled: committed and visible to a
    /// query started after this call. Every later stamp is at or above it.
    #[cfg(test)]
    pub(crate) fn horizon(&self) -> OffsetDateTime {
        self.horizon_settling().0
    }

    /// [`ActivityClock::horizon`], and whether a writer is still in flight
    /// (then committed activity at or above the horizon may be held back:
    /// a long-poll re-reads soon instead of waiting for its next round).
    pub(crate) fn horizon_settling(&self) -> (OffsetDateTime, bool) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(oldest) = s.in_flight.values().min() {
            return (*oldest, true);
        }
        let h = now().max(s.last.saturating_add(TICK));
        // Even if the wall clock steps back, no later stamp goes below h.
        s.last = s.last.max(h.saturating_sub(TICK));
        (h, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_increase_and_hold_the_horizon() {
        let c = ActivityClock::default();
        let a = c.stamp();
        let b = c.stamp();
        assert!(b.at > a.at);
        assert_eq!(c.horizon(), a.at);
        drop(a);
        assert_eq!(c.horizon(), b.at);
        let at_b = b.at;
        drop(b);
        let h = c.horizon();
        assert!(h > at_b);
        let d = c.stamp();
        assert!(d.at >= h, "no stamp goes below a horizon already given out");
        assert_eq!(d.at, truncate_to_micros(d.at));
    }
}
