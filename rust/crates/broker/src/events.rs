//! Wake-ups for long-polls, keyed by what changed (a request id, a thread
//! id, an agent's inbox). In-process only: the broker is one process.
//!
//! The pattern, which has no lost wake-ups:
//!
//! ```ignore
//! let mut listener = events.listen(&key);   // 1. subscribe
//! loop {
//!     let state = read_state().await;        // 2. read the truth
//!     if done(&state) || deadline_passed { return state; }
//!     listener.wait(remaining).await;        // 3. sleep until a change
//! }
//! ```
//!
//! Any `notify` after step 1 wakes step 3, even one that lands between 2
//! and 3.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::watch;

#[derive(Debug)]
pub struct KeyedEvents<K: Eq + Hash + Clone> {
    channels: Mutex<HashMap<K, watch::Sender<u64>>>,
}

impl<K: Eq + Hash + Clone> Default for KeyedEvents<K> {
    fn default() -> Self {
        KeyedEvents {
            channels: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash + Clone> KeyedEvents<K> {
    /// Wake everyone listening on `key`.
    pub fn notify(&self, key: &K) {
        let map = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tx) = map.get(key) {
            tx.send_modify(|v| *v = v.wrapping_add(1));
        }
    }

    /// Start listening on `key`. Changes from now on are seen by `wait`.
    pub fn listen(self: &Arc<Self>, key: &K) -> Listener<K> {
        let mut map = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        let rx = map
            .entry(key.clone())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe();
        Listener {
            events: Arc::clone(self),
            key: key.clone(),
            rx,
        }
    }
}

#[derive(Debug)]
pub struct Listener<K: Eq + Hash + Clone> {
    events: Arc<KeyedEvents<K>>,
    key: K,
    rx: watch::Receiver<u64>,
}

impl<K: Eq + Hash + Clone> Listener<K> {
    /// Sleep until a notify since the last `wait` (or `listen`), at most
    /// `timeout`. True if woken by a change.
    pub async fn wait(&mut self, timeout: Duration) -> bool {
        matches!(
            tokio::time::timeout(timeout, self.rx.changed()).await,
            Ok(Ok(()))
        )
    }
}

impl<K: Eq + Hash + Clone> Drop for Listener<K> {
    fn drop(&mut self) {
        let mut map = self
            .events
            .channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // This receiver still counts until the end of drop: 1 = only us.
        if map
            .get(&self.key)
            .is_some_and(|tx| tx.receiver_count() <= 1)
        {
            map.remove(&self.key);
        }
    }
}

/// Clamp a client-supplied long-poll duration in seconds. NaN means no
/// wait (a NaN timer would otherwise poison the runtime's timer).
#[must_use]
pub fn clamp_wait(secs: f64, lo: f64, hi: f64) -> Duration {
    let secs = if secs.is_nan() {
        lo
    } else {
        secs.clamp(lo, hi)
    };
    Duration::try_from_secs_f64(secs).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_handles_nan_and_infinities() {
        assert_eq!(clamp_wait(f64::NAN, 0.0, 60.0), Duration::ZERO);
        assert_eq!(
            clamp_wait(f64::INFINITY, 0.0, 60.0),
            Duration::from_secs(60)
        );
        assert_eq!(clamp_wait(f64::NEG_INFINITY, 0.0, 60.0), Duration::ZERO);
        assert_eq!(clamp_wait(-5.0, 0.0, 60.0), Duration::ZERO);
        assert_eq!(clamp_wait(1.5, 0.0, 60.0), Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn notify_between_check_and_wait_is_not_lost() {
        let events: Arc<KeyedEvents<u32>> = Arc::default();
        let mut listener = events.listen(&1);
        events.notify(&1); // lands before the wait starts
        assert!(listener.wait(Duration::from_secs(5)).await);
        assert!(!listener.wait(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn entries_are_dropped_with_their_last_listener() {
        let events: Arc<KeyedEvents<u32>> = Arc::default();
        let a = events.listen(&7);
        let b = events.listen(&7);
        drop(a);
        assert_eq!(events.channels.lock().map(|m| m.len()).unwrap_or(0), 1);
        drop(b);
        assert_eq!(events.channels.lock().map(|m| m.len()).unwrap_or(1), 0);
        events.notify(&7); // no listener: a no-op
    }
}
