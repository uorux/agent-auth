//! The operator writing to agents from the admin panel (a2a spec §5):
//! ordinary threads opened by the operator's row, behind admin
//! authentication (the admin token, or a signed-in panel session with CSRF
//! checked by the extractor). No grant backs them; who wrote each message
//! is in its payload (`operator`) and the log.

use std::collections::HashMap;
use std::time::Duration;

use agent_auth_core::{AgentId, ThreadId};
use agent_auth_store::a2a::{self as store_a2a, MessageRow};
use agent_auth_store::{agents, requests};
use agent_auth_wire::a2a::{MessageSent, ThreadOut, ThreadState as WireState};
use agent_auth_wire::chat::{
    ChatClose, ChatMessage, ChatOpen, ChatPeer, ChatRequest, ChatSend, ChatThreadItem,
    ChatThreadView, OperatorPayload,
};
use agent_auth_wire::common::Placement as WirePlacement;
use agent_auth_wire::query::clamp_limit;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::routing::{get, post};
use serde_json::{Map, Value};
use tokio::time::Instant;

use super::WakeKey;
use super::reachability;
use super::routes::{Waiter, body, deadline_in, int_param, query, thread_id, wait_param};
use super::service::{self, Actor, CloseKind};
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The panel's long-poll cap.
const MAX_WAIT_SECS: f64 = 25.0;
const POLL_ROUND: Duration = Duration::from_secs(5);
const UNKNOWN: &str = "unknown conversation";

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/chat/peers", get(peers))
        .route("/admin/chat/threads", get(threads).post(open))
        .route("/admin/chat/threads/{thread_id}", get(read))
        .route("/admin/chat/threads/{thread_id}/messages", post(send))
        .route("/admin/chat/threads/{thread_id}/close", post(close))
}

fn text(p: &Map<String, Value>, key: &str) -> Option<String> {
    p.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// A message for the panel. `operator` is shown only on the operator's
/// own messages (a2a B18: an agent could write one into its reply).
fn message(m: &MessageRow, from: String, operator: AgentId) -> ApiResult<ChatMessage> {
    let p: Map<String, Value> =
        serde_json::from_str(&m.payload).map_err(|e| ApiError::internal(&e))?;
    let has_text = p.get("text").is_some_and(Value::is_string);
    Ok(ChatMessage {
        seq: u64::from(m.seq),
        at: m.created_at,
        from,
        kind: p.get("type").cloned(),
        text: text(&p, "text"),
        status: text(&p, "status"),
        summary: text(&p, "summary"),
        operator: (m.sender_agent_id == operator)
            .then(|| text(&p, "operator"))
            .flatten(),
        payload: (!has_text).then_some(p),
    })
}

/// The list's preview: text, else summary, else type, at most 200 chars.
fn preview(m: Option<&MessageRow>) -> String {
    let Some(m) = m else {
        return String::new();
    };
    let p: Map<String, Value> = serde_json::from_str(&m.payload).unwrap_or_default();
    text(&p, "text")
        .filter(|t| !t.is_empty())
        .or_else(|| text(&p, "summary").filter(|t| !t.is_empty()))
        .or_else(|| text(&p, "type"))
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

/// `GET /admin/chat/peers`: the service agents the operator can write to,
/// by name. No zone filter: the operator is on every side.
async fn peers(
    State(state): State<AppState>,
    _admin: AdminCaller,
) -> ApiResult<Json<Vec<ChatPeer>>> {
    service::enabled(&state)?;
    let now = state.now();
    let tx = state.store.begin().await?;
    let rows = agents::list_peers(&tx, None).await?;
    let out = rows
        .iter()
        .filter(|a| a.kind == agent_auth_core::containment::AgentKind::Service && !a.disabled)
        .map(|a| {
            let mut peer = reachability(a, state.a2a.config.listen_threshold, now);
            peer.description = Some(a.description.clone());
            ChatPeer {
                peer,
                runtime: a.runtime.clone(),
                project: a.project.clone(),
                host: a.host.clone(),
                placement: match a.placement {
                    agent_auth_core::containment::Placement::Host => WirePlacement::Host,
                    agent_auth_core::containment::Placement::Sandbox => WirePlacement::Sandbox,
                },
            }
        })
        .collect();
    Ok(Json(out))
}

async fn threads(
    State(state): State<AppState>,
    _admin: AdminCaller,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Vec<ChatThreadItem>>> {
    let op = service::operator(&state).await?;
    let q = query(raw.as_deref());
    let limit = clamp_limit(int_param(&q, "limit", 100)?, 500);
    let tx = state.store.begin().await?;
    let rows = store_a2a::initiated_by(&tx, op.id, i64::from(limit)).await?;
    let ids: Vec<ThreadId> = rows.iter().map(|t| t.id).collect();
    let last: HashMap<ThreadId, MessageRow> = store_a2a::last_messages(&tx, &ids)
        .await?
        .into_iter()
        .map(|m| (m.thread_id, m))
        .collect();
    let peers: Vec<AgentId> = rows.iter().map(|t| t.responder_agent_id).collect();
    let names: HashMap<AgentId, String> = agents::names(&tx, &peers).await?.into_iter().collect();
    let out = rows
        .iter()
        .map(|t| {
            let m = last.get(&t.id);
            ChatThreadItem {
                id: t.id,
                to: names
                    .get(&t.responder_agent_id)
                    .cloned()
                    .unwrap_or_else(|| "?".to_owned()),
                topic: t.topic.clone(),
                state: thread_state(t.state),
                close_reason: t.close_reason.map(close_reason),
                opened: t.created_at,
                last: t.last_activity_at,
                last_seq: u64::from(t.last_seq),
                preview: preview(m),
                last_from_operator: m.is_some_and(|m| m.sender_agent_id == op.id),
            }
        })
        .collect();
    Ok(Json(out))
}

fn thread_state(s: store_a2a::ThreadState) -> WireState {
    match s {
        store_a2a::ThreadState::PendingOpen => WireState::PendingOpen,
        store_a2a::ThreadState::Open => WireState::Open,
        store_a2a::ThreadState::Closed => WireState::Closed,
    }
}

fn close_reason(r: store_a2a::CloseReason) -> agent_auth_wire::a2a::CloseReason {
    use agent_auth_wire::a2a::CloseReason as W;
    match r {
        store_a2a::CloseReason::Rejected => W::Rejected,
        store_a2a::CloseReason::Closed => W::Closed,
        store_a2a::CloseReason::OpenTimeout => W::OpenTimeout,
        store_a2a::CloseReason::IdleTimeout => W::IdleTimeout,
        store_a2a::CloseReason::PeerGone => W::PeerGone,
        store_a2a::CloseReason::GrantRevoked => W::GrantRevoked,
    }
}

fn operator_payload(text: &str, admin: &AdminCaller) -> ApiResult<Map<String, Value>> {
    match serde_json::to_value(OperatorPayload::message(text, admin.label())) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Ok(Map::new()),
        Err(e) => Err(ApiError::internal(&e)),
    }
}

/// `POST /admin/chat/threads`: no grant needed; every other open check
/// applies (unknown 404, ephemeral 403, not listening 409).
async fn open(
    State(state): State<AppState>,
    admin: AdminCaller,
    raw: Bytes,
) -> ApiResult<Json<ThreadOut>> {
    let b: ChatOpen = body(&raw)?;
    let op = service::operator(&state).await?;
    let payload = operator_payload(b.text.as_str(), &admin)?;
    let actor = Actor::operator(&op, &admin);
    let out = service::open(&state, &actor, b.to.as_str(), b.topic.as_deref(), &payload).await?;
    tracing::info!(
        admin = %admin.label(),
        to = %b.to.as_str(),
        thread = %out.thread_id,
        "admin panel chat: thread opened"
    );
    Ok(Json(out))
}

async fn read_once(
    state: &AppState,
    op: &agents::AgentRow,
    id: ThreadId,
    after_seq: i64,
) -> ApiResult<ChatThreadView> {
    let tx = state.store.begin().await?;
    let Some(t) = store_a2a::get(&tx, id)
        .await?
        .filter(|t| t.initiator_agent_id == op.id)
    else {
        return Err(ApiError::not_found(UNKNOWN));
    };
    let after = i32::try_from(after_seq.max(-1)).unwrap_or(i32::MAX);
    let messages = store_a2a::messages_after(&tx, id, after)
        .await?
        .into_iter()
        .map(|m| message(&m.message, m.sender_name, op.id))
        .collect::<ApiResult<Vec<_>>>()?;
    let requests = requests::by_delegation_thread(&tx, id)
        .await?
        .into_iter()
        .map(|r| ChatRequest {
            id: r.id,
            platform: r.platform,
            what: r
                .authority
                .as_ref()
                .map_or_else(|| r.requested_capability.clone(), |a| a.label()),
            resource: r.resource.clone(),
            status: r.status,
            source: r.decision_source,
        })
        .collect();
    let thread = service::thread_out(&tx, &state.a2a.config, &t, op.id, state.now()).await?;
    Ok(ChatThreadView {
        thread,
        messages,
        requests,
    })
}

/// `GET /admin/chat/threads/{id}?after_seq=0&wait=0` (wait ≤ 25 s).
async fn read(
    State(state): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<ChatThreadView>> {
    let op = service::operator(&state).await?;
    let q = query(raw.as_deref());
    let wait = wait_param(&q, MAX_WAIT_SECS)?;
    let after_seq = int_param(&q, "after_seq", 0)?;
    let id = thread_id(&id, UNKNOWN)?;
    let deadline = deadline_in(wait);
    // Replies wake the initiator's key: the operator's agent id.
    let mut waiter = Waiter::new(&state.a2a, (WakeKey::Agent(op.id), None));
    let first = read_once(&state, &op, id, after_seq).await?;
    let start = first.thread.state;
    let mut out = first;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if !out.messages.is_empty()
            || out.thread.state != start
            || start == WireState::Closed
            || left.is_zero()
        {
            return Ok(Json(out));
        }
        waiter.wait(left.min(POLL_ROUND)).await;
        out = read_once(&state, &op, id, after_seq).await?;
    }
}

async fn send(
    State(state): State<AppState>,
    admin: AdminCaller,
    Path(id): Path<String>,
    raw: Bytes,
) -> ApiResult<Json<MessageSent>> {
    let b: ChatSend = body(&raw)?;
    let op = service::operator(&state).await?;
    let id = thread_id(&id, "unknown thread")?;
    let payload = operator_payload(b.text.as_str(), &admin)?;
    let out = service::send(&state, &Actor::operator(&op, &admin), id, &payload).await?;
    Ok(Json(out))
}

async fn close(
    State(state): State<AppState>,
    admin: AdminCaller,
    Path(id): Path<String>,
    raw: Bytes,
) -> ApiResult<Json<ThreadOut>> {
    let b: ChatClose = body(&raw)?;
    let op = service::operator(&state).await?;
    let id = thread_id(&id, "unknown thread")?;
    let actor = Actor::operator(&op, &admin);
    let out = service::close(&state, &actor, id, CloseKind::Close, b.reason.as_deref()).await?;
    Ok(Json(out))
}
