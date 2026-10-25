//! Long waits as several short requests (the Python's `_poll`).
//!
//! A reverse proxy in front of the broker cuts a request at about 100 s
//! (Cloudflare), so no single long-poll is longer than [`POLL_SLICE`]: a
//! longer wait is repeated slices until the answer is settled or the total
//! has gone by.

use std::future::Future;
use std::time::Duration;

use agent_auth_core::RequestStatus;
use agent_auth_wire::a2a::{EventsSnapshot, ThreadMessages, ThreadState};
use agent_auth_wire::agent::RequestOut;
use agent_auth_wire::hostexec::JobOut;
use tokio::time::Instant;

use crate::ClientError;

/// The longest single long-poll request, in seconds.
pub const POLL_SLICE: f64 = 60.0;

/// The longest total wait one call accepts, in seconds (a day). The Python
/// had no bound (and looped forever on NaN).
pub const MAX_TOTAL_WAIT: f64 = 86_400.0;

/// A total wait made usable: NaN and negative mean no wait.
#[must_use]
pub fn clamp_total(total: f64) -> f64 {
    if total.is_nan() || total <= 0.0 {
        0.0
    } else {
        total.min(MAX_TOTAL_WAIT)
    }
}

/// `fetch(slice)` repeatedly, each slice at most [`POLL_SLICE`] seconds,
/// until `settled(answer)` or `total` seconds have gone by; the last answer.
/// A zero total makes exactly one call, with a zero slice.
pub async fn sliced<T, F, Fut>(
    total: f64,
    mut fetch: F,
    settled: impl Fn(&T) -> bool,
) -> Result<T, ClientError>
where
    F: FnMut(f64) -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let total = clamp_total(total);
    let deadline = Instant::now()
        .checked_add(Duration::from_secs_f64(total))
        .unwrap_or_else(Instant::now);
    // The first slice is exact (no clock read in between).
    let mut left = total;
    loop {
        let out = fetch(left.min(POLL_SLICE)).await?;
        if settled(&out) || Instant::now() >= deadline {
            return Ok(out);
        }
        left = deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64();
    }
}

/// A request is settled once the broker is no longer working on it.
#[must_use]
pub fn request_settled(req: &RequestOut) -> bool {
    !is_waiting(req.status)
}

/// The statuses in which the broker is still working on a request
/// (`pending`, `llm_evaluating`, `awaiting_human`, `approved`,
/// `provisioning`).
#[must_use]
pub fn is_waiting(status: RequestStatus) -> bool {
    matches!(
        status,
        RequestStatus::Pending
            | RequestStatus::LlmEvaluating
            | RequestStatus::AwaitingHuman
            | RequestStatus::Approved
            | RequestStatus::Provisioning
    )
}

/// A thread read is settled with messages, or once the thread closed.
#[must_use]
pub fn messages_settled(read: &ThreadMessages) -> bool {
    !read.messages.is_empty() || read.thread.state == ThreadState::Closed
}

/// The events feed is settled with any pending open or activity.
#[must_use]
pub fn events_settled(snap: &EventsSnapshot) -> bool {
    !snap.pending_opens.is_empty() || !snap.activity.is_empty()
}

/// A job is settled once it ended (`done`, `refused`, `lost`).
#[must_use]
pub fn job_settled(job: &JobOut) -> bool {
    job.status.has_ended()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    async fn run(total: f64, settle_at: Option<usize>) -> Vec<f64> {
        let asked = RefCell::new(Vec::new());
        let out = sliced(
            total,
            |slice| {
                asked.borrow_mut().push(slice);
                let n = asked.borrow().len();
                async move {
                    // The broker holds the request for the whole slice.
                    tokio::time::sleep(Duration::from_secs_f64(slice)).await;
                    Ok::<usize, ClientError>(n)
                }
            },
            |n| settle_at.is_some_and(|at| *n >= at),
        )
        .await
        .unwrap();
        let asked = asked.into_inner();
        assert_eq!(out, asked.len());
        asked
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_wait_is_several_short_requests() {
        assert_eq!(run(150.0, None).await, [60.0, 60.0, 30.0]);
        assert_eq!(run(240.0, Some(1)).await, [60.0]);
        assert_eq!(run(240.0, Some(2)).await, [60.0, 60.0]);
        assert_eq!(run(60.0, None).await, [60.0]);
    }

    #[tokio::test(start_paused = true)]
    async fn no_wait_is_one_call_with_zero() {
        assert_eq!(run(0.0, None).await, [0.0]);
        assert_eq!(run(-5.0, None).await, [0.0]);
        assert_eq!(run(f64::NAN, None).await, [0.0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_huge_wait_is_bounded() {
        let asked = run(f64::INFINITY, None).await;
        assert_eq!(asked.len(), 1440);
        assert!(asked.iter().all(|s| *s <= POLL_SLICE));
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_comes_early_ends_the_slice_early() {
        // The broker answers before the slice is up (nothing new): the
        // next slice asks only for what is left.
        let asked = RefCell::new(Vec::new());
        let _ = sliced(
            100.0,
            |slice| {
                asked.borrow_mut().push(slice);
                async move {
                    tokio::time::sleep(Duration::from_secs_f64(slice / 2.0)).await;
                    Ok::<(), ClientError>(())
                }
            },
            |()| false,
        )
        .await;
        let asked = asked.into_inner();
        assert_eq!(asked.first().copied(), Some(60.0));
        assert_eq!(asked.get(1).copied(), Some(70.0f64.min(60.0)));
        assert!(asked.iter().all(|s| *s <= POLL_SLICE));
    }
}
