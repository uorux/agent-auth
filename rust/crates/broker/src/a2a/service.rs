//! The thread state machine (a2a spec §3): open, send, accept, reject,
//! close, sessions, reads, the events snapshot, the check, sweeps and the
//! closes other parts trigger.
//!
//! Locking (a2a B4) follows the global order — containment lock, agents,
//! grants, threads: an operation that may grant anything first reads the
//! thread without a lock (to learn its participants and refuse early), then
//! checks both participants (`lockdown::check_pair`, which share-locks
//! their rows), then loads the thread `FOR UPDATE` and checks everything
//! again on the locked row before writing. The store's conditional updates
//! back this up. Every write of `last_activity_at` holds an activity stamp
//! until after its commit (see `clock`).

use std::collections::HashMap;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::{self, AgentRef};
use agent_auth_core::pyfmt::repr;
use agent_auth_core::{AgentId, MessageId, Platform, SessionId, ThreadId, zones};
use agent_auth_store::a2a::{
    self as store_a2a, AppendRefused, CloseReason, NewMessage, NewThread, Role, ThreadRow,
    ThreadState, Viewer,
};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::lockdown::{self, Held, PairClear};
use agent_auth_store::sessions::{self, SessionCloseReason, SessionRow};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::a2a::{
    A2aCheckOut, CloseReason as WireReason, EventsSnapshot, MessageOut, MessageSent, PeerEntry,
    SessionClosed, ThreadMessages, ThreadOut, ThreadRole, ThreadState as WireState, WebhookPing,
};
use agent_auth_wire::catalog::PlatformCatalog;
use agent_auth_wire::literal::True;
use agent_auth_wire::query::{Direction, RoleFilter};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::webhook::{self, Ping};
use super::{A2a, A2aConfig, check_grant, reachability, unreachable_detail};
use crate::auth::{AdminCaller, AgentCaller};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Most threads a list or an events snapshot returns.
pub(crate) const LIST_LIMIT: i64 = 200;
/// Liveness bookkeeping: skip the write when the stored value is this fresh
/// (the extractor's 20 s; also for long-poll rounds, a2a B10).
const TOUCH_INTERVAL: Duration = Duration::seconds(20);

/// Who acts on a thread: an authenticated agent (with its session, if it
/// sent one), or the operator's row acting for an authenticated admin.
/// Only these two constructors exist, so no agent can act as the operator
/// (a2a INV-10).
#[derive(Debug)]
pub(crate) struct Actor<'a> {
    agent: &'a AgentRow,
    session: Option<&'a SessionRow>,
}

impl<'a> Actor<'a> {
    pub(crate) fn agent_caller(caller: &'a AgentCaller) -> Actor<'a> {
        Actor {
            agent: caller.agent(),
            session: caller.session(),
        }
    }

    /// The operator row (from [`operator`]) for a signed-in admin.
    pub(crate) fn operator(row: &'a AgentRow, _admin: &AdminCaller) -> Actor<'a> {
        Actor {
            agent: row,
            session: None,
        }
    }

    pub(crate) fn session_id(&self) -> Option<SessionId> {
        self.session.map(|s| s.id)
    }
}

// ------------------------------------------------------------- helpers

pub(crate) fn agent_ref(a: &AgentRow) -> AgentRef<'_> {
    AgentRef {
        name: &a.name,
        runtime: a.runtime.as_deref(),
        project: a.project.as_deref(),
        host: a.host.as_deref(),
        placement: match a.placement {
            Placement::Host => policy::Placement::Host,
            Placement::Sandbox => policy::Placement::Sandbox,
        },
        kind: match a.kind {
            AgentKind::Service => policy::AgentKind::Service,
            AgentKind::Ephemeral => policy::AgentKind::Ephemeral,
            AgentKind::Operator => policy::AgentKind::Operator,
        },
    }
}

fn wire_state(s: ThreadState) -> WireState {
    match s {
        ThreadState::PendingOpen => WireState::PendingOpen,
        ThreadState::Open => WireState::Open,
        ThreadState::Closed => WireState::Closed,
    }
}

fn wire_reason(r: CloseReason) -> WireReason {
    match r {
        CloseReason::Rejected => WireReason::Rejected,
        CloseReason::Closed => WireReason::Closed,
        CloseReason::OpenTimeout => WireReason::OpenTimeout,
        CloseReason::IdleTimeout => WireReason::IdleTimeout,
        CloseReason::PeerGone => WireReason::PeerGone,
        CloseReason::GrantRevoked => WireReason::GrantRevoked,
    }
}

fn require_enabled(state: &AppState) -> ApiResult<()> {
    if state.a2a.config.enabled {
        Ok(())
    } else {
        Err(ApiError::not_found("a2a is disabled on this broker"))
    }
}

pub(crate) fn enabled(state: &AppState) -> ApiResult<&A2a> {
    require_enabled(state)?;
    Ok(&state.a2a)
}

fn require_session(actor: &Actor<'_>) -> ApiResult<()> {
    if actor.agent.kind == AgentKind::Ephemeral && actor.session.is_none() {
        return Err(ApiError::bad_request(
            "ephemeral agents must open a session before using a2a \
             (POST /v1/sessions, then send X-Agent-Session)",
        ));
    }
    Ok(())
}

/// Participant check and session binding on both sides (§3.5): 404 to a
/// non-participant (as for a missing thread, a2a INV-1), 400 to an
/// ephemeral initiator without a session (INV-3), 403 to a session other
/// than the bound one (INV-2).
fn own_thread(actor: &Actor<'_>, thread: Option<ThreadRow>) -> ApiResult<ThreadRow> {
    let me = actor.agent.id;
    let Some(t) = thread.filter(|t| me == t.initiator_agent_id || me == t.responder_agent_id)
    else {
        return Err(ApiError::not_found("unknown thread"));
    };
    let bound = if me == t.initiator_agent_id {
        require_session(actor)?;
        t.initiator_session_id
    } else {
        t.responder_session_id
    };
    if let Some(b) = bound
        && actor.session_id() != Some(b)
    {
        return Err(ApiError::forbidden(
            "thread is bound to a different session of this agent",
        ));
    }
    Ok(t)
}

fn require_not_closed(t: &ThreadRow) -> ApiResult<()> {
    if t.state == ThreadState::Closed {
        let reason = t.close_reason.map_or("closed", CloseReason::as_str);
        return Err(ApiError::conflict(format!("thread is closed ({reason})")));
    }
    Ok(())
}

fn require_responder(t: &ThreadRow, me: AgentId) -> ApiResult<()> {
    if t.responder_agent_id != me {
        return Err(ApiError::forbidden("only the thread responder may do this"));
    }
    Ok(())
}

fn require_pending(t: &ThreadRow) -> ApiResult<()> {
    if t.state != ThreadState::PendingOpen {
        return Err(ApiError::conflict(format!(
            "thread is not pending_open (state {})",
            t.state.as_str()
        )));
    }
    Ok(())
}

fn held_error(name: &str, held: &Held) -> ApiError {
    match held {
        Held::Contained(e) => ApiError::forbidden(format!(
            "{name} is contained ({}): no a2a while it is held",
            e.id
        )),
        Held::Disabled | Held::Unknown => {
            ApiError::forbidden(format!("{name} is disabled: no a2a while it is held"))
        }
    }
}

/// Containment for both participants (skipped for the operator; disabled
/// or lapsed agents count as held), in this transaction (a2a INV-11).
async fn clear_pair<'t>(
    tx: &'t Tx<'_>,
    me: &AgentRow,
    peer: AgentId,
    now: OffsetDateTime,
) -> ApiResult<PairClear<'t>> {
    match lockdown::check_pair(tx, me.id, peer, now).await? {
        Ok(clear) => Ok(clear),
        Err((who, held)) => {
            let name = if who == me.id {
                me.name.clone()
            } else {
                agents::get(tx, who)
                    .await?
                    .map_or_else(|| "the peer".to_owned(), |a| a.name)
            };
            Err(held_error(&name, &held))
        }
    }
}

fn peer_row<'c>(clear: &'c PairClear<'_>, peer: AgentId) -> &'c AgentRow {
    let (a, b) = clear.agents();
    if a.id == peer { a } else { b }
}

fn no_grant(to: &str) -> ApiError {
    ApiError::forbidden(format!(
        "no active a2a grant to talk to {}; request one via POST /v1/requests \
         {{\"platform\": \"a2a\", \"capability\": \"talk\", \"resource\": \"{to}\"}} — \
         topic-scoped grants also require an explicit matching topic on the open",
        repr(to)
    ))
}

/// a2a B5: zones hold on open and send, not only when the grant is asked.
const ZONE_APART: &str =
    "a restricted zone separates you from this peer: no a2a across a zone's edge";

fn apart(state: &AppState, a: &AgentRow, b: &AgentRow) -> bool {
    zones::apart(&state.policy, &agent_ref(a), &agent_ref(b))
}

/// A thread as `viewer` sees it (§3.11).
pub(crate) async fn thread_out(
    tx: &Tx<'_>,
    config: &A2aConfig,
    t: &ThreadRow,
    viewer: AgentId,
    now: OffsetDateTime,
) -> Result<ThreadOut, StoreError> {
    let (role, peer_id, peer_session) = if viewer == t.initiator_agent_id {
        (
            ThreadRole::Initiator,
            t.responder_agent_id,
            t.responder_session_id,
        )
    } else {
        (
            ThreadRole::Responder,
            t.initiator_agent_id,
            t.initiator_session_id,
        )
    };
    let peer = agents::get(tx, peer_id).await?;
    let mut last_seen = peer.as_ref().and_then(|p| p.last_seen_at);
    // A session-bound side's liveness is the conversation's.
    if let Some(s) = peer_session
        && let Some(row) = sessions::get(tx, s).await?
    {
        last_seen = Some(row.last_seen_at);
    }
    let alive = last_seen.is_some_and(|l| now.saturating_sub(config.liveness_threshold) <= l);
    Ok(ThreadOut {
        thread_id: t.id,
        peer: peer.map(|p| p.name),
        role,
        topic: t.topic.clone(),
        state: wire_state(t.state),
        close_reason: t.close_reason.map(wire_reason),
        close_note: t.close_note.clone(),
        grant_id: t.grant_id,
        last_seq: u64::from(t.last_seq),
        created_at: t.created_at,
        accepted_at: t.accepted_at,
        closed_at: t.closed_at,
        last_activity_at: t.last_activity_at,
        peer_last_seen_at: last_seen,
        peer_alive: alive,
    })
}

/// Wake-ups and pings an operation owes once it has committed.
#[derive(Debug, Default)]
pub(crate) struct Fanout {
    wakes: Vec<(AgentId, Option<SessionId>)>,
    pings: Vec<Ping>,
    agents: HashMap<AgentId, Option<AgentRow>>,
}

impl Fanout {
    async fn agent(&mut self, tx: &Tx<'_>, id: AgentId) -> Result<Option<AgentRow>, StoreError> {
        if let Some(a) = self.agents.get(&id) {
            return Ok(a.clone());
        }
        let a = agents::get(tx, id).await?;
        self.agents.insert(id, a.clone());
        Ok(a)
    }

    /// A thread closed: wake and ping each participant but `exclude` (the
    /// agent that closed it, for agent-initiated closes).
    async fn closed(
        &mut self,
        tx: &Tx<'_>,
        config: &A2aConfig,
        t: &ThreadRow,
        exclude: Option<AgentId>,
    ) -> Result<(), StoreError> {
        for (agent, session) in [
            (t.initiator_agent_id, t.initiator_session_id),
            (t.responder_agent_id, t.responder_session_id),
        ] {
            if Some(agent) == exclude {
                continue;
            }
            self.wakes.push((agent, session));
            if let Some(row) = self.agent(tx, agent).await? {
                let event = WebhookPing::ThreadClosed {
                    thread_id: t.id,
                    topic: t.topic.clone(),
                    close_reason: t.close_reason.map(wire_reason),
                };
                self.pings.extend(webhook::target(config, &row, event));
            }
        }
        Ok(())
    }

    fn fire(self, a2a: &A2a) {
        for (agent, session) in self.wakes {
            a2a.wake(agent, session);
        }
        a2a.webhooks.deliver(&a2a.config, self.pings);
    }
}

/// `last_listen_at = now` (throttled): the events poll and accept only
/// (a2a B2: not the message long-poll).
pub(crate) async fn mark_listening(state: &AppState, agent: AgentId) -> ApiResult<()> {
    let now = state.now();
    let tx = state.store.begin().await?;
    agents::mark_listening(&tx, agent, now, now.saturating_sub(TOUCH_INTERVAL)).await?;
    tx.commit().await?;
    Ok(())
}

/// Liveness from a parked long-poll: the agent's and the session's
/// `last_seen_at`, throttled like every other touch (a2a B10).
pub(crate) async fn touch(state: &AppState, caller: &AgentCaller) -> ApiResult<()> {
    let now = state.now();
    let since = now.saturating_sub(TOUCH_INTERVAL);
    let tx = state.store.begin().await?;
    agents::touch_seen(&tx, caller.id(), now, since).await?;
    if let Some(s) = caller.session_id() {
        sessions::touch(&tx, s, now, since).await?;
    }
    tx.commit().await?;
    Ok(())
}

// ----------------------------------------------------------- sessions

/// `POST /v1/sessions`: `<label>-<4 hex>`, retried on a name clash.
pub(crate) async fn create_session(
    state: &AppState,
    caller: &AgentCaller,
    label: &str,
) -> ApiResult<SessionRow> {
    let cap = state.a2a.config.max_sessions_per_agent;
    for _ in 0..5 {
        let bytes = uuid::Uuid::new_v4().into_bytes();
        let name = format!(
            "{label}-{}",
            hex::encode(bytes.get(..2).unwrap_or_default())
        );
        let tx = state.store.begin().await?;
        // The agent row serializes this agent's session creations, so the
        // count cannot be raced past the cap (lock order: agents, then
        // sessions).
        agents::get_for_update(&tx, caller.id()).await?;
        if sessions::count_open(&tx, caller.id()).await? >= i64::from(cap) {
            return Err(ApiError::conflict(format!(
                "too many open sessions for this agent (at most {cap}); close one \
                 (POST /v1/sessions/close with its X-Agent-Session) or let idle ones expire"
            )));
        }
        match sessions::insert(&tx, SessionId::new(), caller.id(), &name, state.now()).await {
            Ok(row) => {
                tx.commit().await?;
                return Ok(row);
            }
            Err(e) if e.is_unique_violation() => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "could not allocate a session name",
    ))
}

/// `POST /v1/sessions/close`: the session ends `closed`; every thread bound
/// to it ends `peer_gone`, closed by this agent.
pub(crate) async fn end_session(
    state: &AppState,
    caller: &AgentCaller,
) -> ApiResult<SessionClosed> {
    let Some(sid) = caller.session_id() else {
        return Err(ApiError::bad_request("no X-Agent-Session header"));
    };
    let a2a = &state.a2a;
    let tx = state.store.begin().await?;
    let stamp = a2a.clock.stamp();
    sessions::close(&tx, sid, SessionCloseReason::Closed, stamp.at).await?;
    let closed = store_a2a::close_for_sessions(&tx, &[sid], Some(caller.id()), stamp.at).await?;
    let mut fanout = Fanout::default();
    for t in &closed {
        fanout
            .closed(&tx, &a2a.config, t, Some(caller.id()))
            .await?;
    }
    tx.commit().await?;
    drop(stamp);
    fanout.fire(a2a);
    Ok(SessionClosed {
        ok: True,
        threads_closed: u32::try_from(closed.len()).unwrap_or(u32::MAX),
    })
}

// ------------------------------------------------------------ threads

/// Open a thread with its first message (§3.6). The order of the checks
/// is observable and the Python's: unknown → held → not addressable →
/// session → grant → not listening.
pub(crate) async fn open(
    state: &AppState,
    actor: &Actor<'_>,
    to: &str,
    topic: Option<&str>,
    payload: &Map<String, Value>,
) -> ApiResult<ThreadOut> {
    let a2a = enabled(state)?;
    let now = state.now();
    let me = actor.agent;
    let tx = state.store.begin().await?;
    let unknown = || ApiError::not_found(format!("unknown agent {}", repr(to)));
    let responder = match agents::by_name(&tx, to).await? {
        Some(r) if !r.disabled => r,
        _ => return Err(unknown()),
    };
    // a2a B5: across a zone's edge the peer does not exist (as in the check).
    if apart(state, me, &responder) {
        return Err(unknown());
    }
    if responder.id == me.id {
        return Err(ApiError::forbidden(
            "an agent cannot open a thread to itself",
        ));
    }
    let clear = clear_pair(&tx, me, responder.id, now).await?;
    let reach = reachability(&responder, a2a.config.listen_threshold, now);
    if !reach.addressable {
        return Err(ApiError::forbidden(unreachable_detail(&reach)));
    }
    require_session(actor)?;
    let grant = if me.kind == AgentKind::Operator {
        None
    } else {
        let g = check_grant(&tx, me.id, &responder.name, topic, false, now).await?;
        Some(g.ok_or_else(|| no_grant(to))?.id)
    };
    if !reach.reachable {
        return Err(ApiError::conflict(unreachable_detail(&reach)));
    }
    let text = serde_json::to_string(payload).map_err(|e| ApiError::internal(&e))?;
    let stamp = a2a.clock.stamp();
    let new = NewThread {
        id: ThreadId::new(),
        initiator: me.id,
        initiator_session: actor.session_id(),
        responder: responder.id,
        topic,
        grant_id: grant,
        message_id: MessageId::new(),
        payload: &text,
        now: stamp.at,
    };
    let (thread, _) = store_a2a::open(&tx, &clear, &new)
        .await?
        .map_err(|_| no_grant(to))?;
    let out = thread_out(&tx, &a2a.config, &thread, me.id, now).await?;
    let event = WebhookPing::ThreadOpen {
        thread_id: thread.id,
        from: me.name.clone(),
        topic: thread.topic.clone(),
        seq: 1,
    };
    let ping = webhook::target(&a2a.config, &responder, event);
    drop(clear);
    tx.commit().await?;
    drop(stamp);
    a2a.wake(responder.id, None);
    a2a.webhooks
        .deliver(&a2a.config, ping.into_iter().collect());
    Ok(out)
}

/// Send a message (§3.7). A responder's first reply accepts the thread.
pub(crate) async fn send(
    state: &AppState,
    actor: &Actor<'_>,
    id: ThreadId,
    payload: &Map<String, Value>,
) -> ApiResult<MessageSent> {
    let a2a = enabled(state)?;
    let now = state.now();
    let me = actor.agent;
    let tx = state.store.begin().await?;
    let first = own_thread(actor, store_a2a::get(&tx, id).await?)?;
    require_not_closed(&first)?;
    let peer_id = first.peer_of(me.id);
    let clear = clear_pair(&tx, me, peer_id, now).await?;
    let peer = peer_row(&clear, peer_id).clone();
    if apart(state, me, &peer) {
        return Err(ApiError::forbidden(ZONE_APART));
    }
    let text = serde_json::to_string(payload).map_err(|e| ApiError::internal(&e))?;
    let stamp = a2a.clock.stamp();
    // Lock order: the backing grant (its id never changes on a thread),
    // then the thread.
    let grant_live = match first.grant_id {
        None => true,
        Some(g) => store_a2a::lock_backing_grant(&tx, g, stamp.at).await?,
    };
    // Locked from here: the binding and state may have moved meanwhile.
    let thread = own_thread(actor, store_a2a::get_for_update(&tx, id).await?)?;
    require_not_closed(&thread)?;
    let is_initiator = me.id == thread.initiator_agent_id;
    let stored = if grant_live {
        let cap = a2a.config.max_messages_per_thread;
        if thread.last_seq >= cap {
            return Err(ApiError::conflict(format!(
                "thread has reached its limit of {cap} messages; close it and open a new one"
            )));
        }
        if is_initiator && thread.state == ThreadState::PendingOpen {
            return Err(ApiError::conflict(
                "thread is pending_open: your opening message already rides the open; \
                 wait for the responder to accept or reply",
            ));
        }
        let mut thread = thread;
        if !is_initiator && thread.state == ThreadState::PendingOpen {
            // Replying accepts; a sessioned reply claims the thread.
            thread = store_a2a::accept(&tx, &clear, id, actor.session_id(), stamp.at)
                .await?
                .ok_or_else(|| ApiError::conflict("thread is not pending_open"))?;
        }
        let new = NewMessage {
            thread_id: id,
            id: MessageId::new(),
            sender: me.id,
            sender_session: actor.session_id(),
            payload: &text,
            now: stamp.at,
        };
        match store_a2a::append(&tx, &clear, &new).await? {
            Ok(m) => Some((thread, m)),
            Err(AppendRefused::GrantNotLive) => None,
            Err(AppendRefused::NotOpen) => {
                return Err(ApiError::conflict("thread is closed (closed)"));
            }
        }
    } else {
        None
    };
    match stored {
        Some((thread, m)) => {
            let (peer_session, seq) = if is_initiator {
                (thread.responder_session_id, m.seq)
            } else {
                (thread.initiator_session_id, m.seq)
            };
            let event = WebhookPing::Message {
                thread_id: id,
                message_id: m.id,
                from: me.name.clone(),
                topic: thread.topic.clone(),
                seq: u64::from(seq),
            };
            let ping = webhook::target(&a2a.config, &peer, event);
            drop(clear);
            tx.commit().await?;
            drop(stamp);
            a2a.wake(peer_id, peer_session);
            a2a.webhooks
                .deliver(&a2a.config, ping.into_iter().collect());
            Ok(MessageSent {
                message_id: m.id,
                seq: u64::from(seq),
                thread_state: WireState::Open,
            })
        }
        None => {
            // a2a INV-6: nothing stored; the thread ends, and that commits
            // even though the call fails.
            let mut fanout = Fanout::default();
            if let Some(closed) =
                store_a2a::close(&tx, id, CloseReason::GrantRevoked, None, None, stamp.at).await?
            {
                fanout.closed(&tx, &a2a.config, &closed, None).await?;
            }
            drop(clear);
            tx.commit().await?;
            drop(stamp);
            fanout.fire(a2a);
            Err(ApiError::forbidden(
                "backing grant is no longer active; thread closed",
            ))
        }
    }
}

/// Accept a pending thread (responder only, §3.8). With a session, the
/// thread is bound to it.
pub(crate) async fn accept(
    state: &AppState,
    caller: &AgentCaller,
    id: ThreadId,
) -> ApiResult<ThreadOut> {
    let a2a = enabled(state)?;
    let actor = Actor::agent_caller(caller);
    let now = state.now();
    let me = caller.agent();
    let tx = state.store.begin().await?;
    let first = own_thread(&actor, store_a2a::get(&tx, id).await?)?;
    require_responder(&first, me.id)?;
    require_pending(&first)?;
    let clear = clear_pair(&tx, me, first.initiator_agent_id, now).await?;
    let thread = own_thread(&actor, store_a2a::get_for_update(&tx, id).await?)?;
    require_pending(&thread)?;
    let stamp = a2a.clock.stamp();
    let thread = store_a2a::accept(&tx, &clear, id, caller.session_id(), stamp.at)
        .await?
        .ok_or_else(|| ApiError::conflict("thread is not pending_open"))?;
    let out = thread_out(&tx, &a2a.config, &thread, me.id, now).await?;
    drop(clear);
    tx.commit().await?;
    drop(stamp);
    a2a.wake(thread.initiator_agent_id, thread.initiator_session_id);
    // Accepting proves inbound threads are being read.
    mark_listening(state, me.id).await?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseKind {
    /// Responder only, pending only: `rejected`.
    Reject,
    /// Either side, any state but closed: `closed`.
    Close,
}

/// Reject or close (§3.8). No containment check: ending is always allowed.
pub(crate) async fn close(
    state: &AppState,
    actor: &Actor<'_>,
    id: ThreadId,
    kind: CloseKind,
    note: Option<&str>,
) -> ApiResult<ThreadOut> {
    let a2a = enabled(state)?;
    let now = state.now();
    let me = actor.agent;
    let tx = state.store.begin().await?;
    let thread = own_thread(actor, store_a2a::get_for_update(&tx, id).await?)?;
    let reason = match kind {
        CloseKind::Reject => {
            require_responder(&thread, me.id)?;
            require_pending(&thread)?;
            CloseReason::Rejected
        }
        CloseKind::Close => {
            require_not_closed(&thread)?;
            CloseReason::Closed
        }
    };
    let stamp = a2a.clock.stamp();
    let closed = store_a2a::close(&tx, id, reason, Some(me.id), note, stamp.at)
        .await?
        .ok_or_else(|| ApiError::conflict("thread is closed (closed)"))?;
    let out = thread_out(&tx, &a2a.config, &closed, me.id, now).await?;
    let mut fanout = Fanout::default();
    fanout
        .closed(&tx, &a2a.config, &closed, Some(me.id))
        .await?;
    tx.commit().await?;
    drop(stamp);
    fanout.fire(a2a);
    Ok(out)
}

// -------------------------------------------------------------- reads

fn viewer(caller: &AgentCaller) -> Viewer {
    Viewer {
        agent: caller.id(),
        session: caller.session_id(),
    }
}

pub(crate) async fn get_thread(
    state: &AppState,
    caller: &AgentCaller,
    id: ThreadId,
) -> ApiResult<ThreadOut> {
    let a2a = enabled(state)?;
    let tx = state.store.begin().await?;
    let t = own_thread(&Actor::agent_caller(caller), store_a2a::get(&tx, id).await?)?;
    Ok(thread_out(&tx, &a2a.config, &t, caller.id(), state.now()).await?)
}

pub(crate) async fn list(
    state: &AppState,
    caller: &AgentCaller,
    thread_state: Option<&str>,
    role: RoleFilter,
) -> ApiResult<Vec<ThreadOut>> {
    let a2a = enabled(state)?;
    require_session(&Actor::agent_caller(caller))?;
    let tx = state.store.begin().await?;
    let role = match role {
        RoleFilter::Both => None,
        RoleFilter::Initiator => Some(Role::Initiator),
        RoleFilter::Responder => Some(Role::Responder),
    };
    let rows = store_a2a::list(
        &tx,
        viewer(caller),
        role,
        thread_state.filter(|s| !s.is_empty()),
        LIST_LIMIT,
    )
    .await?;
    let now = state.now();
    let mut out = Vec::with_capacity(rows.len());
    for t in &rows {
        out.push(thread_out(&tx, &a2a.config, t, caller.id(), now).await?);
    }
    Ok(out)
}

fn message_out(m: store_a2a::NamedMessage) -> ApiResult<MessageOut> {
    let payload: Map<String, Value> =
        serde_json::from_str(&m.message.payload).map_err(|e| ApiError::internal(&e))?;
    Ok(MessageOut {
        message_id: m.message.id,
        seq: u64::from(m.message.seq),
        from: m.sender_name,
        payload,
        created_at: m.message.created_at,
    })
}

/// One read of a thread and its messages after `after_seq`.
pub(crate) async fn read_messages(
    state: &AppState,
    caller: &AgentCaller,
    id: ThreadId,
    after_seq: i64,
) -> ApiResult<ThreadMessages> {
    let a2a = enabled(state)?;
    let tx = state.store.begin().await?;
    let t = own_thread(&Actor::agent_caller(caller), store_a2a::get(&tx, id).await?)?;
    let after = i32::try_from(after_seq.max(-1)).unwrap_or(i32::MAX);
    let messages = store_a2a::messages_after(&tx, id, after)
        .await?
        .into_iter()
        .map(message_out)
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(ThreadMessages {
        thread: thread_out(&tx, &a2a.config, &t, caller.id(), state.now()).await?,
        messages,
    })
}

/// One events snapshot (§3.10): pending opens (sessionless callers only)
/// and activity strictly after `after` and below the activity horizon
/// (a2a B3), oldest first, at most [`LIST_LIMIT`].
#[cfg(test)]
pub(crate) async fn events_snapshot(
    state: &AppState,
    caller: &AgentCaller,
    after: Option<OffsetDateTime>,
) -> ApiResult<EventsSnapshot> {
    Ok(events_snapshot_settling(state, caller, after).await?.0)
}

/// One events snapshot, and whether a writer was in flight (activity may
/// have been held back: re-read soon).
pub(crate) async fn events_snapshot_settling(
    state: &AppState,
    caller: &AgentCaller,
    after: Option<OffsetDateTime>,
) -> ApiResult<(EventsSnapshot, bool)> {
    let a2a = enabled(state)?;
    require_session(&Actor::agent_caller(caller))?;
    let tx = state.store.begin().await?;
    let pending = if caller.session_id().is_none() {
        store_a2a::pending_opens(&tx, caller.id()).await?
    } else {
        Vec::new()
    };
    // The horizon before the query's snapshot: see `clock`.
    let (horizon, settling) = a2a.clock.horizon_settling();
    let limit = LIST_LIMIT.saturating_add(1);
    let mut activity =
        store_a2a::activity_before(&tx, viewer(caller), after, horizon, limit).await?;
    let cap = usize::try_from(LIST_LIMIT).unwrap_or(200);
    if activity.len() > cap {
        // Never split a run of equal timestamps across pages: the cursor is
        // compared strictly.
        let boundary = activity.get(cap).map(|t| t.last_activity_at);
        activity.truncate(cap);
        let kept: Vec<ThreadRow> = activity
            .iter()
            .filter(|t| Some(t.last_activity_at) != boundary)
            .cloned()
            .collect();
        if !kept.is_empty() {
            activity = kept;
        }
    }
    let cursor = activity
        .iter()
        .map(|t| t.last_activity_at)
        .chain(after)
        .max();
    let now = state.now();
    let mut pending_opens = Vec::with_capacity(pending.len());
    for t in &pending {
        pending_opens.push(thread_out(&tx, &a2a.config, t, caller.id(), now).await?);
    }
    let mut activity_out = Vec::with_capacity(activity.len());
    for t in &activity {
        activity_out.push(thread_out(&tx, &a2a.config, t, caller.id(), now).await?);
    }
    let snapshot = EventsSnapshot {
        pending_opens,
        activity: activity_out,
        cursor,
    };
    Ok((snapshot, settling))
}

/// `GET /v1/a2a/check` (§3.13): permission and reachability, separately.
pub(crate) async fn check(
    state: &AppState,
    caller: &AgentCaller,
    peer: &str,
    direction: &str,
    topic: Option<&str>,
) -> ApiResult<A2aCheckOut> {
    let a2a = enabled(state)?;
    let now = state.now();
    let tx = state.store.begin().await?;
    let unknown = || A2aCheckOut {
        allowed: false,
        grant_id: None,
        expires_at: None,
        reason: Some(format!("unknown agent {}", repr(peer))),
        peer: None,
    };
    // a2a B6: a disabled peer is unknown here too, as for the open.
    let Some(row) = agents::by_name(&tx, peer).await?.filter(|a| !a.disabled) else {
        return Ok(unknown());
    };
    if apart(state, caller.agent(), &row) {
        return Ok(unknown());
    }
    let mut entry = reachability(&row, a2a.config.listen_threshold, now);
    entry.description = Some(row.description.clone()).filter(|d| !d.is_empty());
    let direction = Direction::parse(direction).map_err(|e| ApiError::bad_request(e.message()))?;
    let any_topic = topic.is_none();
    let grant = match direction {
        Direction::Out => check_grant(&tx, caller.id(), &row.name, topic, any_topic, now).await?,
        Direction::In => {
            check_grant(&tx, row.id, &caller.agent().name, topic, any_topic, now).await?
        }
    };
    let Some(grant) = grant else {
        return Ok(A2aCheckOut {
            allowed: false,
            grant_id: None,
            expires_at: None,
            reason: Some("no active a2a grant".to_owned()),
            peer: Some(entry),
        });
    };
    let reason =
        (direction == Direction::Out && !entry.reachable).then(|| unreachable_detail(&entry));
    Ok(A2aCheckOut {
        allowed: true,
        grant_id: Some(grant.id),
        expires_at: Some(grant.expires_at),
        reason,
        peer: Some(entry),
    })
}

// ------------------------------------------------------------ catalog

/// The a2a entry of `GET /v1/catalog` for `agent`: the service agents it
/// could talk to (not itself, disabled or zone-apart ones), each with its
/// reachability, reachable first, then by name.
pub async fn catalog_entry(
    state: &AppState,
    tx: &Tx<'_>,
    agent: &AgentRow,
    now: OffsetDateTime,
) -> Result<PlatformCatalog, StoreError> {
    let rows = agents::list_peers(tx, Some(agent.id)).await?;
    let mut peers: Vec<PeerEntry> = rows
        .iter()
        .filter(|p| p.kind == AgentKind::Service && !p.disabled && !apart(state, agent, p))
        .map(|p| {
            let mut e = reachability(p, state.a2a.config.listen_threshold, now);
            e.description = Some(p.description.clone()).filter(|d| !d.is_empty());
            e
        })
        .collect();
    peers.sort_by(|a, b| (!a.reachable, &a.name).cmp(&(!b.reachable, &b.name)));
    let mut entry = PlatformCatalog::new(Platform::A2a, "talk", "<agent name>");
    entry.peers = Some(peers);
    Ok(entry)
}

// ---------------------------------------------------- operator's chat

/// The operator's row, created on first use and marked seen (unthrottled:
/// while the panel is open, agents see their operator peer alive).
pub(crate) async fn operator(state: &AppState) -> ApiResult<AgentRow> {
    enabled(state)?;
    let now = state.now();
    let tx = state.store.begin().await?;
    let id = AgentId::new();
    let key_id = hex::encode(
        uuid::Uuid::new_v4()
            .into_bytes()
            .get(..8)
            .unwrap_or_default(),
    );
    let Some(row) = agents::ensure_operator(&tx, id, &key_id, now).await? else {
        return Err(ApiError::conflict(
            "an agent is already named 'operator'; rename it to chat from the panel",
        ));
    };
    if row.disabled {
        return Err(ApiError::conflict("the operator's identity is disabled"));
    }
    agents::touch_seen(&tx, row.id, now, now).await?;
    tx.commit().await?;
    Ok(row)
}

// ------------------------------------------------------- system closes

/// What [`sweep`] closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct SweepCounts {
    /// Sessions idled out (their threads closed `peer_gone`, not counted).
    pub sessions_idled: usize,
    pub open_timeout: usize,
    pub idle_timeout: usize,
    pub grant_revoked: usize,
}

/// The scheduler's a2a step (§3.14), one transaction: idle sessions (their
/// threads → `peer_gone`), stale opens, idle threads, dead backing grants.
/// Cutoffs are taken from `now`.
pub async fn sweep(state: &AppState, now: OffsetDateTime) -> Result<SweepCounts, StoreError> {
    let a2a = &state.a2a;
    let cfg = &a2a.config;
    let tx = state.store.begin().await?;
    let stamp = a2a.clock.stamp();
    let mut counts = SweepCounts::default();
    let mut closed = Vec::new();
    let idle_sessions =
        sessions::close_idle(&tx, now.saturating_sub(cfg.session_idle_timeout), stamp.at).await?;
    counts.sessions_idled = idle_sessions.len();
    if !idle_sessions.is_empty() {
        closed.extend(store_a2a::close_for_sessions(&tx, &idle_sessions, None, stamp.at).await?);
    }
    let opens =
        store_a2a::close_open_timeouts(&tx, now.saturating_sub(cfg.open_timeout), stamp.at).await?;
    counts.open_timeout = opens.len();
    closed.extend(opens);
    let idle =
        store_a2a::close_idle(&tx, now.saturating_sub(cfg.thread_idle_timeout), stamp.at).await?;
    counts.idle_timeout = idle.len();
    closed.extend(idle);
    let dead = store_a2a::close_dead_grants(&tx, stamp.at).await?;
    counts.grant_revoked = dead.len();
    closed.extend(dead);
    let mut fanout = Fanout::default();
    for t in &closed {
        fanout.closed(&tx, cfg, t, None).await?;
    }
    tx.commit().await?;
    drop(stamp);
    fanout.fire(a2a);
    Ok(counts)
}

#[derive(Debug, Clone, Copy)]
enum SystemClose<'a> {
    AllFor(&'a str),
    Inbound,
    Agent,
}

async fn close_with(
    state: &AppState,
    agent: AgentId,
    how: SystemClose<'_>,
) -> Result<usize, StoreError> {
    let a2a = &state.a2a;
    let tx = state.store.begin().await?;
    let stamp = a2a.clock.stamp();
    let closed = match how {
        SystemClose::AllFor(note) => store_a2a::close_all_for(&tx, agent, note, stamp.at).await?,
        SystemClose::Inbound => store_a2a::orphan_inbound(&tx, agent, stamp.at).await?,
        SystemClose::Agent => store_a2a::close_for_agent(&tx, agent, stamp.at).await?,
    };
    let mut fanout = Fanout::default();
    for t in &closed {
        fanout.closed(&tx, &a2a.config, t, None).await?;
    }
    tx.commit().await?;
    drop(stamp);
    fanout.fire(a2a);
    Ok(closed.len())
}

/// Containment (§3.15): every non-closed thread of the agent, either side,
/// → `closed` with `note` (the containment sweep passes `contained`).
pub async fn close_all_for(
    state: &AppState,
    agent: AgentId,
    note: &str,
) -> Result<usize, StoreError> {
    close_with(state, agent, SystemClose::AllFor(note)).await
}

/// The agent can no longer receive threads (demoted to ephemeral, its host
/// locked down): every thread it responds on → `peer_gone`.
pub async fn orphan_inbound(state: &AppState, agent: AgentId) -> Result<usize, StoreError> {
    close_with(state, agent, SystemClose::Inbound).await
}

/// a2a B7: the agent was disabled. Every thread it is on, either side,
/// → `peer_gone` (it can no longer answer, and its own threads would only
/// wait for the idle sweep). Call after the disable committed.
pub async fn on_agent_disabled(state: &AppState, agent: AgentId) -> Result<usize, StoreError> {
    close_with(state, agent, SystemClose::Agent).await
}
