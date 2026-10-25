//! `a2a_threads` and `a2a_messages`: conversations between two agents.
//!
//! Every state change is a single conditional UPDATE on the thread row
//! (a2a B4: the Python read, checked, then wrote with no lock): accept only
//! from `pending_open`, close only from a non-closed state, and a message
//! only on an `open` thread, its `seq` taken from the same UPDATE that bumps
//! `last_seq` (contiguous from 1, a2a INV-9). Opening, accepting and
//! sending require a [`PairClear`] from the same transaction (neither
//! participant held, a2a INV-11). Triggers back this up: a closed thread
//! never changes again, a bound responder session never moves, and no
//! message lands on a closed thread.
//!
//! Payloads are stored as `json` and returned as their exact text.

use agent_auth_core::{AgentId, GrantId, MessageId, SessionId, ThreadId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::lockdown::PairClear;
use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

const T: &str = "a2a_threads";

text_enum! {
    ThreadState { PendingOpen = "pending_open", Open = "open", Closed = "closed" }
}

text_enum! {
    CloseReason {
        Rejected = "rejected",
        Closed = "closed",
        OpenTimeout = "open_timeout",
        IdleTimeout = "idle_timeout",
        PeerGone = "peer_gone",
        GrantRevoked = "grant_revoked",
    }
}

text_enum! {
    /// Which side of threads a listing is about.
    Role { Initiator = "initiator", Responder = "responder" }
}

#[derive(Debug, Clone)]
pub struct ThreadRow {
    pub id: ThreadId,
    pub initiator_agent_id: AgentId,
    pub initiator_session_id: Option<SessionId>,
    pub responder_agent_id: AgentId,
    pub responder_session_id: Option<SessionId>,
    pub topic: Option<String>,
    /// The initiator's a2a grant; `None` only on operator threads.
    pub grant_id: Option<GrantId>,
    pub state: ThreadState,
    pub accepted_at: Option<OffsetDateTime>,
    pub closed_at: Option<OffsetDateTime>,
    pub close_reason: Option<CloseReason>,
    /// The closing agent; `None` for system closes.
    pub closed_by: Option<AgentId>,
    pub close_note: Option<String>,
    pub last_activity_at: OffsetDateTime,
    pub last_seq: u32,
    pub created_at: OffsetDateTime,
}

impl ThreadRow {
    /// The other participant, from `me`'s side.
    #[must_use]
    pub fn peer_of(&self, me: AgentId) -> AgentId {
        if me == self.initiator_agent_id {
            self.responder_agent_id
        } else {
            self.initiator_agent_id
        }
    }
}

struct RawThread {
    id: Uuid,
    initiator_agent_id: Uuid,
    initiator_session_id: Option<Uuid>,
    responder_agent_id: Uuid,
    responder_session_id: Option<Uuid>,
    topic: Option<String>,
    grant_id: Option<Uuid>,
    state: String,
    accepted_at: Option<OffsetDateTime>,
    closed_at: Option<OffsetDateTime>,
    last_activity_at: OffsetDateTime,
    last_seq: i32,
    closed_by: Option<Uuid>,
    close_reason: Option<String>,
    close_note: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<RawThread> for ThreadRow {
    type Error = StoreError;
    fn try_from(r: RawThread) -> Result<ThreadRow, StoreError> {
        Ok(ThreadRow {
            id: ThreadId::from_uuid(r.id),
            initiator_agent_id: AgentId::from_uuid(r.initiator_agent_id),
            initiator_session_id: r.initiator_session_id.map(SessionId::from_uuid),
            responder_agent_id: AgentId::from_uuid(r.responder_agent_id),
            responder_session_id: r.responder_session_id.map(SessionId::from_uuid),
            topic: r.topic,
            grant_id: r.grant_id.map(GrantId::from_uuid),
            state: ThreadState::parse(&r.state)
                .ok_or_else(|| StoreError::corrupt(T, format!("state {:?}", r.state)))?,
            accepted_at: r.accepted_at,
            closed_at: r.closed_at,
            close_reason: r
                .close_reason
                .map(|s| {
                    CloseReason::parse(&s)
                        .ok_or_else(|| StoreError::corrupt(T, format!("close_reason {s:?}")))
                })
                .transpose()?,
            closed_by: r.closed_by.map(AgentId::from_uuid),
            close_note: r.close_note,
            last_activity_at: r.last_activity_at,
            last_seq: values::unsigned(T, r.last_seq)?,
            created_at: r.created_at,
        })
    }
}

fn threads(raw: Vec<RawThread>) -> Result<Vec<ThreadRow>, StoreError> {
    raw.into_iter().map(ThreadRow::try_from).collect()
}

fn thread(raw: Option<RawThread>) -> Result<Option<ThreadRow>, StoreError> {
    raw.map(ThreadRow::try_from).transpose()
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: MessageId,
    pub thread_id: ThreadId,
    pub seq: u32,
    pub sender_agent_id: AgentId,
    pub sender_session_id: Option<SessionId>,
    pub recipient_agent_id: AgentId,
    pub grant_id: Option<GrantId>,
    /// The JSON object exactly as sent.
    pub payload: String,
    pub created_at: OffsetDateTime,
}

/// A message with its sender's (current) name, for reading threads.
#[derive(Debug, Clone)]
pub struct NamedMessage {
    pub message: MessageRow,
    pub sender_name: String,
}

struct RawMessage {
    id: Uuid,
    thread_id: Uuid,
    seq: i32,
    sender_agent_id: Uuid,
    sender_session_id: Option<Uuid>,
    recipient_agent_id: Uuid,
    grant_id: Option<Uuid>,
    payload: String,
    created_at: OffsetDateTime,
}

impl TryFrom<RawMessage> for MessageRow {
    type Error = StoreError;
    fn try_from(r: RawMessage) -> Result<MessageRow, StoreError> {
        Ok(MessageRow {
            id: MessageId::from_uuid(r.id),
            thread_id: ThreadId::from_uuid(r.thread_id),
            seq: values::unsigned("a2a_messages", r.seq)?,
            sender_agent_id: AgentId::from_uuid(r.sender_agent_id),
            sender_session_id: r.sender_session_id.map(SessionId::from_uuid),
            recipient_agent_id: AgentId::from_uuid(r.recipient_agent_id),
            grant_id: r.grant_id.map(GrantId::from_uuid),
            payload: r.payload,
            created_at: r.created_at,
        })
    }
}

// ---------------------------------------------------------------- writes

/// A new thread and its opening message (seq 1).
#[derive(Debug, Clone)]
pub struct NewThread<'a> {
    pub id: ThreadId,
    pub initiator: AgentId,
    pub initiator_session: Option<SessionId>,
    pub responder: AgentId,
    pub topic: Option<&'a str>,
    /// `None` only for the operator's threads.
    pub grant_id: Option<GrantId>,
    pub message_id: MessageId,
    /// A JSON object's text (validated and size-limited by the caller).
    pub payload: &'a str,
    pub now: OffsetDateTime,
}

/// Open a thread (`pending_open`, `last_seq = 1`) with its first message.
pub async fn open(
    tx: &Tx<'_>,
    clear: &PairClear<'_>,
    n: &NewThread<'_>,
) -> Result<(ThreadRow, MessageRow), StoreError> {
    clear.verify(tx, n.initiator, n.responder)?;
    let mut c = tx.conn().await;
    let t = sqlx::query_as!(
        RawThread,
        "INSERT INTO a2a_threads (id, initiator_agent_id, initiator_session_id, responder_agent_id,
             topic, grant_id, state, last_activity_at, last_seq, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending_open', $7, 1, $7)
         RETURNING *",
        Uuid::from(n.id),
        Uuid::from(n.initiator),
        n.initiator_session.map(Uuid::from),
        Uuid::from(n.responder),
        n.topic,
        n.grant_id.map(Uuid::from),
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    let m = sqlx::query_as!(
        RawMessage,
        r#"INSERT INTO a2a_messages (id, thread_id, seq, sender_agent_id, sender_session_id,
               recipient_agent_id, grant_id, payload, created_at)
           VALUES ($1, $2, 1, $3, $4, $5, $6, $7::text::json, $8)
           RETURNING id, thread_id, seq, sender_agent_id, sender_session_id, recipient_agent_id,
                     grant_id, payload::text AS "payload!", created_at"#,
        Uuid::from(n.message_id),
        Uuid::from(n.id),
        Uuid::from(n.initiator),
        n.initiator_session.map(Uuid::from),
        Uuid::from(n.responder),
        n.grant_id.map(Uuid::from),
        n.payload,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    Ok((t.try_into()?, m.try_into()?))
}

/// `pending_open` → `open` (an accept, or the responder's first reply),
/// binding the responder's session if one is given. `None` if the thread
/// was not pending (already accepted, closed) — exactly one of two racing
/// accepts wins.
pub async fn accept(
    tx: &Tx<'_>,
    clear: &PairClear<'_>,
    id: ThreadId,
    responder_session: Option<SessionId>,
    now: OffsetDateTime,
) -> Result<Option<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let parties = sqlx::query!(
        "SELECT initiator_agent_id, responder_agent_id FROM a2a_threads WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(p) = parties else {
        return Ok(None);
    };
    clear.verify(
        tx,
        AgentId::from_uuid(p.initiator_agent_id),
        AgentId::from_uuid(p.responder_agent_id),
    )?;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'open', accepted_at = $2, last_activity_at = $2,
             responder_session_id = COALESCE(responder_session_id, $3)
         WHERE id = $1 AND state = 'pending_open'
         RETURNING *",
        Uuid::from(id),
        now,
        responder_session.map(Uuid::from)
    )
    .fetch_optional(&mut **c)
    .await?;
    thread(raw)
}

/// A message from one participant of a thread to the other.
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub thread_id: ThreadId,
    pub id: MessageId,
    pub sender: AgentId,
    pub sender_session: Option<SessionId>,
    /// A JSON object's text (validated and size-limited by the caller).
    pub payload: &'a str,
    pub now: OffsetDateTime,
}

/// Store a message on an `open` thread: the thread's `last_seq` is bumped
/// and the message takes it, in one transaction. `None` if the thread is
/// missing or not open, or the sender is not a participant (nothing is
/// stored).
pub async fn append(
    tx: &Tx<'_>,
    clear: &PairClear<'_>,
    n: &NewMessage<'_>,
) -> Result<Option<MessageRow>, StoreError> {
    let mut c = tx.conn().await;
    let parties = sqlx::query!(
        "SELECT initiator_agent_id, responder_agent_id FROM a2a_threads WHERE id = $1",
        Uuid::from(n.thread_id)
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(p) = parties else {
        return Ok(None);
    };
    let sender = Uuid::from(n.sender);
    let recipient = if p.initiator_agent_id == sender {
        p.responder_agent_id
    } else if p.responder_agent_id == sender {
        p.initiator_agent_id
    } else {
        return Ok(None);
    };
    clear.verify(tx, n.sender, AgentId::from_uuid(recipient))?;
    let bumped = sqlx::query!(
        "UPDATE a2a_threads SET last_seq = last_seq + 1, last_activity_at = $2
         WHERE id = $1 AND state = 'open'
         RETURNING last_seq, grant_id",
        Uuid::from(n.thread_id),
        n.now
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(b) = bumped else {
        return Ok(None);
    };
    let m = sqlx::query_as!(
        RawMessage,
        r#"INSERT INTO a2a_messages (id, thread_id, seq, sender_agent_id, sender_session_id,
               recipient_agent_id, grant_id, payload, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::json, $9)
           RETURNING id, thread_id, seq, sender_agent_id, sender_session_id, recipient_agent_id,
                     grant_id, payload::text AS "payload!", created_at"#,
        Uuid::from(n.id),
        Uuid::from(n.thread_id),
        b.last_seq,
        sender,
        n.sender_session.map(Uuid::from),
        recipient,
        b.grant_id,
        n.payload,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(Some(m.try_into()?))
}

/// Close a thread that is not closed yet (`None` otherwise). Sets
/// `last_activity_at` so events cursors see the close.
pub async fn close(
    tx: &Tx<'_>,
    id: ThreadId,
    reason: CloseReason,
    by: Option<AgentId>,
    note: Option<&str>,
    now: OffsetDateTime,
) -> Result<Option<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = $3, closed_by = $4,
             close_note = $5, last_activity_at = $2
         WHERE id = $1 AND state <> 'closed'
         RETURNING *",
        Uuid::from(id),
        now,
        reason.as_str(),
        by.map(Uuid::from),
        note
    )
    .fetch_optional(&mut **c)
    .await?;
    thread(raw)
}

/// Close (`peer_gone`) every non-closed thread bound to one of these
/// sessions on either side.
pub async fn close_for_sessions(
    tx: &Tx<'_>,
    sessions: &[SessionId],
    by: Option<AgentId>,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let s: Vec<Uuid> = sessions.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = 'peer_gone',
             closed_by = $3, close_note = NULL, last_activity_at = $2
         WHERE state <> 'closed'
           AND (initiator_session_id = ANY($1) OR responder_session_id = ANY($1))
         RETURNING *",
        &s,
        now,
        by.map(Uuid::from)
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Sweep: `pending_open` threads created before `cutoff` → `open_timeout`.
pub async fn close_open_timeouts(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = 'open_timeout',
             closed_by = NULL, close_note = NULL, last_activity_at = $2
         WHERE state = 'pending_open' AND created_at < $1
         RETURNING *",
        cutoff,
        now
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Sweep: `open` threads idle since before `cutoff` → `idle_timeout`.
pub async fn close_idle(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = 'idle_timeout',
             closed_by = NULL, close_note = NULL, last_activity_at = $2
         WHERE state = 'open' AND last_activity_at < $1
         RETURNING *",
        cutoff,
        now
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Sweep: non-closed threads whose backing grant is no longer active and
/// unexpired → `grant_revoked` (operator threads have none and stay).
pub async fn close_dead_grants(
    tx: &Tx<'_>,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads t SET state = 'closed', closed_at = $1, close_reason = 'grant_revoked',
             closed_by = NULL, close_note = NULL, last_activity_at = $1
         FROM grants g
         WHERE g.id = t.grant_id AND t.state <> 'closed'
           AND (g.status <> 'active' OR g.expires_at <= $1)
         RETURNING t.*",
        now
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Containment: every non-closed thread of the agent, either side →
/// `closed` with `note` (e.g. `contained`), `closed_by` NULL.
pub async fn close_all_for(
    tx: &Tx<'_>,
    agent: AgentId,
    note: &str,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = 'closed',
             closed_by = NULL, close_note = $3, last_activity_at = $2
         WHERE state <> 'closed' AND (initiator_agent_id = $1 OR responder_agent_id = $1)
         RETURNING *",
        Uuid::from(agent),
        now,
        note
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Every non-closed thread where the agent is the responder → `peer_gone`
/// (demotion to ephemeral, lockdown, disable).
pub async fn orphan_inbound(
    tx: &Tx<'_>,
    agent: AgentId,
    now: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "UPDATE a2a_threads SET state = 'closed', closed_at = $2, close_reason = 'peer_gone',
             closed_by = NULL, close_note = NULL, last_activity_at = $2
         WHERE state <> 'closed' AND responder_agent_id = $1
         RETURNING *",
        Uuid::from(agent),
        now
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

// ----------------------------------------------------------------- reads

pub async fn get(tx: &Tx<'_>, id: ThreadId) -> Result<Option<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    thread(raw)
}

/// Load and lock the thread until the transaction ends (send/accept/close
/// paths that check several things before writing; a2a B4).
pub async fn get_for_update(tx: &Tx<'_>, id: ThreadId) -> Result<Option<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE id = $1 FOR UPDATE",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    thread(raw)
}

/// Who is looking: an agent, and the session it sent (if any). With a
/// session, each side is limited to threads bound to it.
#[derive(Debug, Clone, Copy)]
pub struct Viewer {
    pub agent: AgentId,
    pub session: Option<SessionId>,
}

/// Threads of the viewer, most recently active first.
pub async fn list(
    tx: &Tx<'_>,
    viewer: Viewer,
    role: Option<Role>,
    state: Option<&str>,
    limit: i64,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads
         WHERE ((($3::text IS DISTINCT FROM 'responder') AND initiator_agent_id = $1
                 AND ($2::uuid IS NULL OR initiator_session_id = $2))
             OR (($3::text IS DISTINCT FROM 'initiator') AND responder_agent_id = $1
                 AND ($2::uuid IS NULL OR responder_session_id = $2)))
           AND ($4::text IS NULL OR state = $4)
         ORDER BY last_activity_at DESC, id
         LIMIT $5",
        Uuid::from(viewer.agent),
        viewer.session.map(Uuid::from),
        role.map(Role::as_str),
        state,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Events feed: the viewer's threads with activity after `after` (strict),
/// or, without a cursor, its non-closed threads; oldest activity first.
pub async fn activity(
    tx: &Tx<'_>,
    viewer: Viewer,
    after: Option<OffsetDateTime>,
    limit: i64,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads
         WHERE ((initiator_agent_id = $1 AND ($2::uuid IS NULL OR initiator_session_id = $2))
             OR (responder_agent_id = $1 AND ($2::uuid IS NULL OR responder_session_id = $2)))
           AND (CASE WHEN $3::timestamptz IS NULL THEN state <> 'closed'
                     ELSE last_activity_at > $3 END)
         ORDER BY last_activity_at, id
         LIMIT $4",
        Uuid::from(viewer.agent),
        viewer.session.map(Uuid::from),
        after,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Threads waiting for this responder to accept, oldest first.
pub async fn pending_opens(tx: &Tx<'_>, responder: AgentId) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE responder_agent_id = $1 AND state = 'pending_open'
         ORDER BY created_at, id",
        Uuid::from(responder)
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Messages after `after_seq`, in order, with their senders' names.
pub async fn messages_after(
    tx: &Tx<'_>,
    thread_id: ThreadId,
    after_seq: i32,
) -> Result<Vec<NamedMessage>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        r#"SELECT m.id, m.thread_id, m.seq, m.sender_agent_id, m.sender_session_id,
                  m.recipient_agent_id, m.grant_id, m.payload::text AS "payload!", m.created_at,
                  a.name AS sender_name
           FROM a2a_messages m JOIN agents a ON a.id = m.sender_agent_id
           WHERE m.thread_id = $1 AND m.seq > $2
           ORDER BY m.seq"#,
        Uuid::from(thread_id),
        after_seq
    )
    .fetch_all(&mut **c)
    .await?;
    out.into_iter()
        .map(|r| {
            Ok(NamedMessage {
                sender_name: r.sender_name,
                message: RawMessage {
                    id: r.id,
                    thread_id: r.thread_id,
                    seq: r.seq,
                    sender_agent_id: r.sender_agent_id,
                    sender_session_id: r.sender_session_id,
                    recipient_agent_id: r.recipient_agent_id,
                    grant_id: r.grant_id,
                    payload: r.payload,
                    created_at: r.created_at,
                }
                .try_into()?,
            })
        })
        .collect()
}

/// Threads the operator opened, most recently active first.
pub async fn initiated_by(
    tx: &Tx<'_>,
    agent: AgentId,
    limit: i64,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE initiator_agent_id = $1
         ORDER BY last_activity_at DESC, id LIMIT $2",
        Uuid::from(agent),
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// The latest message (`seq = last_seq`) of each of these threads.
pub async fn last_messages(tx: &Tx<'_>, ids: &[ThreadId]) -> Result<Vec<MessageRow>, StoreError> {
    let t: Vec<Uuid> = ids.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawMessage,
        r#"SELECT m.id, m.thread_id, m.seq, m.sender_agent_id, m.sender_session_id,
                  m.recipient_agent_id, m.grant_id, m.payload::text AS "payload!", m.created_at
           FROM a2a_messages m JOIN a2a_threads t ON t.id = m.thread_id
           WHERE t.id = ANY($1) AND m.seq = t.last_seq"#,
        &t
    )
    .fetch_all(&mut **c)
    .await?;
    raw.into_iter().map(MessageRow::try_from).collect()
}

/// Threads active at or after `since`, most recent first (admin graph).
pub async fn active_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE last_activity_at >= $1 ORDER BY last_activity_at DESC, id",
        since
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Message counts per thread.
pub async fn message_counts(
    tx: &Tx<'_>,
    ids: &[ThreadId],
) -> Result<Vec<(ThreadId, i64)>, StoreError> {
    let t: Vec<Uuid> = ids.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        r#"SELECT thread_id, count(*) AS "n!" FROM a2a_messages WHERE thread_id = ANY($1)
           GROUP BY thread_id"#,
        &t
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out
        .into_iter()
        .map(|r| (ThreadId::from_uuid(r.thread_id), r.n))
        .collect())
}

/// Opened at or after `since`, oldest first (audit feed).
pub async fn created_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE created_at >= $1 ORDER BY created_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}

/// Closed at or after `since`, oldest first (audit feed).
pub async fn closed_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ThreadRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawThread,
        "SELECT * FROM a2a_threads WHERE closed_at >= $1 ORDER BY closed_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    threads(raw)
}
