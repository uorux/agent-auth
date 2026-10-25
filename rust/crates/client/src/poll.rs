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
    let mut last: Option<T> = None;
    let mut backoff = RETRY_FIRST;
    loop {
        let out = match fetch(left.min(POLL_SLICE)).await {
            Ok(out) => out,
            // The broker answered once and is now away (a shutdown answers
            // every long-poll at once, then the broker restarts): keep
            // waiting through the restart, until the deadline.
            Err(e) if is_transient(&e) => match last.take() {
                Some(prev) if Instant::now() < deadline => {
                    let wait = deadline
                        .saturating_duration_since(Instant::now())
                        .min(backoff);
                    tokio::time::sleep(wait).await;
                    backoff = backoff.saturating_mul(2).min(RETRY_MAX);
                    left = deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs_f64();
                    last = Some(prev);
                    continue;
                }
                Some(prev) => return Ok(prev),
                None => return Err(e),
            },
            Err(e) => return Err(e),
        };
        if settled(&out) || Instant::now() >= deadline {
            return Ok(out);
        }
        backoff = RETRY_FIRST;
        last = Some(out);
        left = deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64();
    }
}

/// The first pause before asking a broker that went away again.
const RETRY_FIRST: Duration = Duration::from_secs(1);
/// The longest pause between those attempts.
const RETRY_MAX: Duration = Duration::from_secs(8);

/// The broker is away for now: no connection, or a proxy in front of it
/// saying so.
fn is_transient(e: &ClientError) -> bool {
    match e {
        ClientError::Transport(_) => true,
        ClientError::Broker { status, .. } => matches!(status, 502..=504),
        ClientError::Decode(_) => false,
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
    async fn a_broker_restart_is_waited_through() {
        // Answered (still waiting), then away twice, then answered settled.
        let calls = RefCell::new(0usize);
        let out = sliced(
            300.0,
            |_| {
                *calls.borrow_mut() += 1;
                let n = *calls.borrow();
                async move {
                    match n {
                        2 => Err(ClientError::Transport("refused".into())),
                        3 => Err(ClientError::broker(502, "bad gateway")),
                        _ => Ok(n),
                    }
                }
            },
            |n| *n >= 4,
        )
        .await
        .unwrap();
        assert_eq!(out, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_broker_is_still_an_error() {
        // Never answered: the error, at once.
        let r = sliced(
            300.0,
            |_| async { Err::<(), _>(ClientError::Transport("refused".into())) },
            |()| false,
        )
        .await;
        assert!(matches!(r, Err(ClientError::Transport(_))));
        // Answered, then away until the deadline: the last answer.
        let calls = RefCell::new(0usize);
        let started = Instant::now();
        let r = sliced(
            30.0,
            |_| {
                *calls.borrow_mut() += 1;
                let n = *calls.borrow();
                async move {
                    if n == 1 {
                        Ok(n)
                    } else {
                        Err(ClientError::Transport("refused".into()))
                    }
                }
            },
            |_| false,
        )
        .await;
        assert_eq!(r.unwrap(), 1);
        assert!(started.elapsed() >= Duration::from_secs(30));
        // Other refusals are not retried.
        let r = sliced(
            30.0,
            |_| async { Err::<(), _>(ClientError::broker(403, "no")) },
            |()| false,
        )
        .await;
        assert!(matches!(r, Err(ClientError::Broker { status: 403, .. })));
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
