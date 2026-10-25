//! `/v1/sessions*` and `/v1/a2a/*` (http-api §2.2). Every `/v1/a2a/*`
//! route answers 404 `a2a is disabled on this broker` (after auth) when
//! the relay is off; the session routes are not gated.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::ThreadId;
use agent_auth_wire::a2a::{
    A2aCheckOut, EventsSnapshot, MessageSent, SessionClosed, SessionCreate, SessionOut,
    ThreadCloseBody, ThreadMessageBody, ThreadMessages, ThreadOpenBody, ThreadOut,
    ThreadState as WireState,
};
use agent_auth_wire::query::{MAX_WAIT_SECS, RoleFilter};
use agent_auth_wire::{payload, timestamp};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::routing::{get, post};
use serde::de::DeserializeOwned;
use tokio::time::Instant;

use super::service::{self, Actor, CloseKind};
use super::{A2a, WakeKey};
use crate::auth::AgentCaller;
use crate::error::{ApiError, ApiResult};
use crate::events::{KeyedEvents, Listener, clamp_wait};
use crate::state::AppState;

/// A parked long-poll sleeps on its wake-up keys (no wake-up is lost: the
/// listener subscribes before the first read) and re-reads at least this
/// often anyway, re-checking that the caller is still enabled and its key
/// and session still valid.
pub(super) const POLL_ROUND: Duration = Duration::from_secs(15);
/// The re-read delay while a writer is in flight (activity held back by
/// the activity clock settles within milliseconds).
const SETTLE_ROUND: Duration = Duration::from_millis(100);

/// The slot a parked long-poll holds, or 429.
fn poll_slot<'a>(a2a: &'a A2a, caller: &AgentCaller) -> ApiResult<super::limits::PollSlot<'a>> {
    let cap = a2a.config.max_long_polls_per_agent;
    a2a.polls.take(caller.id(), cap).ok_or_else(|| {
        ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            format!(
                "too many concurrent a2a long-polls for this agent (at most {cap}); \
                 wait for one to return"
            ),
        )
    })
}

/// One parked round's bookkeeping: still the caller it was, and alive.
async fn recheck(state: &AppState, caller: &AgentCaller) -> ApiResult<()> {
    caller.revalidate(state).await?;
    service::touch(state, caller).await
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/close", post(close_session))
        .route("/v1/a2a/threads", post(open_thread).get(list_threads))
        .route("/v1/a2a/threads/{thread_id}", get(get_thread))
        .route("/v1/a2a/threads/{thread_id}/accept", post(accept))
        .route("/v1/a2a/threads/{thread_id}/reject", post(reject))
        .route("/v1/a2a/threads/{thread_id}/close", post(close))
        .route(
            "/v1/a2a/threads/{thread_id}/messages",
            post(send).get(read_messages),
        )
        .route("/v1/a2a/events", get(events))
        .route("/v1/a2a/check", get(check))
}

// ------------------------------------------------------------- inputs

/// A request body, with the field's own message on a 422.
pub(super) fn body<T: DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    agent_auth_wire::parse_body(bytes).map_err(|e| ApiError::unprocessable(e.message()))
}

/// A body carrying an a2a payload: out-of-range integers are refused too.
fn payload_body<T: DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    payload::parse_body(bytes).map_err(|e| ApiError::unprocessable(e.message()))
}

/// Query parameters (the last of repeated ones wins).
pub(super) fn query(raw: Option<&str>) -> HashMap<String, String> {
    url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

/// `wait=` as a clamped duration (NaN → none; http-api INV-8).
pub(super) fn wait_param(q: &HashMap<String, String>, max: f64) -> ApiResult<Duration> {
    let secs = match q.get("wait") {
        None => 0.0,
        Some(v) => v
            .trim()
            .parse::<f64>()
            .map_err(|_| ApiError::unprocessable("wait must be a number"))?,
    };
    Ok(clamp_wait(secs, 0.0, max))
}

pub(super) fn int_param(q: &HashMap<String, String>, name: &str, default: i64) -> ApiResult<i64> {
    match q.get(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<i64>()
            .map_err(|_| ApiError::unprocessable(format!("{name} must be an integer"))),
    }
}

/// A thread id from the path; anything that is not one is no thread.
pub(super) fn thread_id(text: &str, unknown: &str) -> ApiResult<ThreadId> {
    text.parse()
        .map_err(|_| ApiError::not_found(unknown.to_owned()))
}

/// Wake-ups for a parked long-poll: the caller's agent key and, with a
/// session, its session key. Subscribed before the first read.
pub(super) struct Waiter {
    agent: Listener<WakeKey>,
    session: Option<Listener<WakeKey>>,
}

impl std::fmt::Debug for Waiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Waiter").finish_non_exhaustive()
    }
}

impl Waiter {
    pub(super) fn new(a2a: &A2a, keys: (WakeKey, Option<WakeKey>)) -> Waiter {
        let events: &Arc<KeyedEvents<WakeKey>> = &a2a.events;
        Waiter {
            agent: events.listen(&keys.0),
            session: keys.1.map(|k| events.listen(&k)),
        }
    }

    pub(super) async fn wait(&mut self, timeout: Duration) {
        match &mut self.session {
            None => {
                self.agent.wait(timeout).await;
            }
            Some(s) => {
                let a = Box::pin(self.agent.wait(timeout));
                let b = Box::pin(s.wait(timeout));
                futures::future::select(a, b).await;
            }
        }
    }
}

fn keys(caller: &AgentCaller) -> (WakeKey, Option<WakeKey>) {
    (
        WakeKey::Agent(caller.id()),
        caller.session_id().map(WakeKey::Session),
    )
}

/// `wait` from now (clamped waits always fit).
pub(super) fn deadline_in(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or(now)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

// ----------------------------------------------------------- handlers

async fn create_session(
    State(state): State<AppState>,
    caller: AgentCaller,
    raw: Bytes,
) -> ApiResult<Json<SessionOut>> {
    let b: SessionCreate = body(&raw)?;
    let row = service::create_session(&state, &caller, b.label.as_str()).await?;
    Ok(Json(SessionOut {
        session_id: row.id,
        name: row.name,
        created_at: row.created_at,
    }))
}

async fn close_session(
    State(state): State<AppState>,
    caller: AgentCaller,
) -> ApiResult<Json<SessionClosed>> {
    Ok(Json(service::end_session(&state, &caller).await?))
}

async fn open_thread(
    State(state): State<AppState>,
    caller: AgentCaller,
    raw: Bytes,
) -> ApiResult<Json<ThreadOut>> {
    let b: ThreadOpenBody = payload_body(&raw)?;
    let out = service::open(
        &state,
        &Actor::agent_caller(&caller),
        b.to.as_str(),
        b.topic.as_deref(),
        b.payload.as_map(),
    )
    .await?;
    Ok(Json(out))
}

async fn list_threads(
    State(state): State<AppState>,
    caller: AgentCaller,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Vec<ThreadOut>>> {
    let q = query(raw.as_deref());
    let role = RoleFilter::parse(q.get("role").map(String::as_str));
    let out = service::list(&state, &caller, q.get("state").map(String::as_str), role).await?;
    Ok(Json(out))
}

async fn get_thread(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<ThreadOut>> {
    service::enabled(&state)?;
    let id = thread_id(&id, "unknown thread")?;
    Ok(Json(service::get_thread(&state, &caller, id).await?))
}

async fn accept(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<ThreadOut>> {
    service::enabled(&state)?;
    let id = thread_id(&id, "unknown thread")?;
    Ok(Json(service::accept(&state, &caller, id).await?))
}

async fn end(
    state: &AppState,
    caller: &AgentCaller,
    id: &str,
    raw: &[u8],
    kind: CloseKind,
) -> ApiResult<Json<ThreadOut>> {
    let b: ThreadCloseBody = body(raw)?;
    service::enabled(state)?;
    let id = thread_id(id, "unknown thread")?;
    let note = b.reason.as_deref();
    let out = service::close(state, &Actor::agent_caller(caller), id, kind, note).await?;
    Ok(Json(out))
}

async fn reject(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    raw: Bytes,
) -> ApiResult<Json<ThreadOut>> {
    end(&state, &caller, &id, &raw, CloseKind::Reject).await
}

async fn close(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    raw: Bytes,
) -> ApiResult<Json<ThreadOut>> {
    end(&state, &caller, &id, &raw, CloseKind::Close).await
}

async fn send(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    raw: Bytes,
) -> ApiResult<Json<MessageSent>> {
    let b: ThreadMessageBody = payload_body(&raw)?;
    service::enabled(&state)?;
    let id = thread_id(&id, "unknown thread")?;
    let out = service::send(
        &state,
        &Actor::agent_caller(&caller),
        id,
        b.payload.as_map(),
    )
    .await?;
    Ok(Json(out))
}

/// The cursor read; `wait > 0` long-polls until a new message or a change
/// of state. Parked rounds refresh the caller's liveness, but do not mark
/// it listening (a2a B2: only the inbound surfaces do).
async fn read_messages(
    State(state): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<ThreadMessages>> {
    let a2a = service::enabled(&state)?;
    let q = query(raw.as_deref());
    let wait = wait_param(&q, MAX_WAIT_SECS)?;
    let after_seq = int_param(&q, "after_seq", 0)?;
    let id = thread_id(&id, "unknown thread")?;
    let deadline = deadline_in(wait);
    let mut waiter = Waiter::new(a2a, keys(&caller));
    let mut last = service::read_messages(&state, &caller, id, after_seq).await?;
    let start = last.thread.state;
    if !last.messages.is_empty() || wait.is_zero() || start == WireState::Closed {
        return Ok(Json(last));
    }
    let _slot = poll_slot(a2a, &caller)?;
    loop {
        let left = remaining(deadline);
        if left.is_zero() {
            return Ok(Json(last));
        }
        waiter.wait(left.min(POLL_ROUND)).await;
        recheck(&state, &caller).await?;
        let r = service::read_messages(&state, &caller, id, after_seq).await?;
        if !r.messages.is_empty() || r.thread.state != start {
            return Ok(Json(r));
        }
        last = r;
    }
}

/// Pending opens and activity since the cursor. Polling this is what makes
/// an agent reachable (it is marked listening once per call).
async fn events(
    State(state): State<AppState>,
    caller: AgentCaller,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<EventsSnapshot>> {
    let a2a = service::enabled(&state)?;
    let q = query(raw.as_deref());
    let after = match q.get("after").filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => Some(
            timestamp::parse_query(v)
                .map_err(|e| ApiError::unprocessable(format!("after: {e}")))?,
        ),
    };
    let wait = wait_param(&q, MAX_WAIT_SECS)?;
    service::mark_listening(&state, caller.id()).await?;
    let deadline = deadline_in(wait);
    let mut waiter = Waiter::new(a2a, keys(&caller));
    let mut slot = None;
    loop {
        let (snapshot, settling) =
            service::events_snapshot_settling(&state, &caller, after).await?;
        if !snapshot.pending_opens.is_empty() || !snapshot.activity.is_empty() {
            return Ok(Json(snapshot));
        }
        let left = remaining(deadline);
        if left.is_zero() {
            return Ok(Json(snapshot));
        }
        if slot.is_none() {
            slot = Some(poll_slot(a2a, &caller)?);
        }
        let round = if settling { SETTLE_ROUND } else { POLL_ROUND };
        waiter.wait(left.min(round)).await;
        recheck(&state, &caller).await?;
    }
}

async fn check(
    State(state): State<AppState>,
    caller: AgentCaller,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<A2aCheckOut>> {
    service::enabled(&state)?;
    let q = query(raw.as_deref());
    let Some(peer) = q.get("peer") else {
        return Err(ApiError::unprocessable("peer is required"));
    };
    let direction = q.get("direction").map_or("out", String::as_str);
    let topic = q.get("topic").map(String::as_str);
    Ok(Json(
        service::check(&state, &caller, peer, direction, topic).await?,
    ))
}
