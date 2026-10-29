//! Process limits (sandboxd B-4): at most `max_processes` agent processes
//! at once in the VM, and `max_processes_per_project` per project (the
//! orchestrator counts as a project of its own). A slot is held for as
//! long as its process runs, not only while it starts (the Python's
//! semaphore counted starts).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Debug, Default)]
struct Counts {
    total: u32,
    per: HashMap<String, u32>,
}

#[derive(Debug)]
struct Inner {
    max: u32,
    per_project: u32,
    counts: Mutex<Counts>,
    freed: Notify,
}

/// The limiter.
#[derive(Debug, Clone)]
pub struct Slots(Arc<Inner>);

/// One running process's slot, given back on drop.
#[derive(Debug)]
pub struct SlotPermit {
    slots: Arc<Inner>,
    project: String,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        {
            let mut c = self
                .slots
                .counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            c.total = c.total.saturating_sub(1);
            if let Some(n) = c.per.get_mut(&self.project) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    c.per.remove(&self.project);
                }
            }
        }
        self.slots.freed.notify_waiters();
    }
}

impl Slots {
    #[must_use]
    pub fn new(max: u32, per_project: u32) -> Slots {
        Slots(Arc::new(Inner {
            max,
            per_project,
            counts: Mutex::new(Counts::default()),
            freed: Notify::new(),
        }))
    }

    /// A slot now, if one is free.
    #[must_use]
    pub fn try_acquire(&self, project: &str) -> Option<SlotPermit> {
        let mut c = self.0.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let used = c.per.get(project).copied().unwrap_or(0);
        if c.total >= self.0.max || used >= self.0.per_project {
            return None;
        }
        c.total = c.total.saturating_add(1);
        c.per.insert(project.to_owned(), used.saturating_add(1));
        Some(SlotPermit {
            slots: Arc::clone(&self.0),
            project: project.to_owned(),
        })
    }

    /// A slot, waiting up to `wait` for one to free up.
    pub async fn acquire(&self, project: &str, wait: Duration) -> Result<SlotPermit, String> {
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let freed = self.0.freed.notified();
            if let Some(p) = self.try_acquire(project) {
                return Ok(p);
            }
            if tokio::time::timeout_at(deadline, freed).await.is_err() {
                return Err(format!(
                    "no free process slot (at most {} agent processes, {} per project)",
                    self.0.max, self.0.per_project
                ));
            }
        }
    }

    /// Processes running now (total).
    #[must_use]
    pub fn in_use(&self) -> u32 {
        self.0
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limits_hold_for_the_life_of_a_permit() {
        let s = Slots::new(3, 2);
        let a1 = s.try_acquire("a").unwrap();
        let _a2 = s.try_acquire("a").unwrap();
        assert!(s.try_acquire("a").is_none(), "per project");
        let _b1 = s.try_acquire("b").unwrap();
        assert!(s.try_acquire("c").is_none(), "total");
        assert_eq!(s.in_use(), 3);
        assert!(s.acquire("c", Duration::from_millis(20)).await.is_err());
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.acquire("a", Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(a1);
        assert!(waiter.await.unwrap().is_ok());
    }
}
