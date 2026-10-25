//! `agent_sessions`: one live instance of an agent (`X-Agent-Session`).

use agent_auth_core::{AgentId, SessionId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::text_enum;
use crate::{StoreError, Tx};

const T: &str = "agent_sessions";

text_enum! {
    /// Why a session ended.
    SessionCloseReason { Idle = "idle", Closed = "closed" }
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: SessionId,
    pub agent_id: AgentId,
    /// `<label>-<4 hex>`, unique per agent.
    pub name: String,
    pub last_seen_at: OffsetDateTime,
    /// Both set or neither.
    pub closed: Option<(OffsetDateTime, SessionCloseReason)>,
    pub created_at: OffsetDateTime,
}

impl SessionRow {
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.closed.is_none()
    }
}

struct RawSession {
    id: Uuid,
    agent_id: Uuid,
    name: String,
    last_seen_at: OffsetDateTime,
    closed_at: Option<OffsetDateTime>,
    close_reason: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<RawSession> for SessionRow {
    type Error = StoreError;
    fn try_from(r: RawSession) -> Result<SessionRow, StoreError> {
        let closed = match (r.closed_at, r.close_reason) {
            (None, None) => None,
            (Some(at), Some(reason)) => Some((
                at,
                SessionCloseReason::parse(&reason)
                    .ok_or_else(|| StoreError::corrupt(T, format!("close_reason {reason:?}")))?,
            )),
            _ => return Err(StoreError::corrupt(T, "half a close")),
        };
        Ok(SessionRow {
            id: SessionId::from_uuid(r.id),
            agent_id: AgentId::from_uuid(r.agent_id),
            name: r.name,
            last_seen_at: r.last_seen_at,
            closed,
            created_at: r.created_at,
        })
    }
}

/// Create a session. A name clash with another of the agent's sessions is
/// a unique violation (`StoreError::is_unique_violation`): pick another name.
pub async fn insert(
    tx: &Tx<'_>,
    id: SessionId,
    agent: AgentId,
    name: &str,
    now: OffsetDateTime,
) -> Result<SessionRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawSession,
        "INSERT INTO agent_sessions (id, agent_id, name, last_seen_at, created_at)
         VALUES ($1, $2, $3, $4, $4) RETURNING *",
        Uuid::from(id),
        Uuid::from(agent),
        name,
        now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

pub async fn get(tx: &Tx<'_>, id: SessionId) -> Result<Option<SessionRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawSession,
        "SELECT * FROM agent_sessions WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(SessionRow::try_from).transpose()
}

/// The agent's own open session (authentication of `X-Agent-Session`).
pub async fn get_open(
    tx: &Tx<'_>,
    agent: AgentId,
    id: SessionId,
) -> Result<Option<SessionRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawSession,
        "SELECT * FROM agent_sessions WHERE id = $1 AND agent_id = $2 AND closed_at IS NULL",
        Uuid::from(id),
        Uuid::from(agent)
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(SessionRow::try_from).transpose()
}

/// `last_seen_at = now` on an open session unless written after
/// `unless_after` (pass `now` for an unthrottled touch).
pub async fn touch(
    tx: &Tx<'_>,
    id: SessionId,
    now: OffsetDateTime,
    unless_after: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agent_sessions SET last_seen_at = $2
         WHERE id = $1 AND closed_at IS NULL AND last_seen_at < $3",
        Uuid::from(id),
        now,
        unless_after
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Close an open session. `false` if it was already closed (or missing).
pub async fn close(
    tx: &Tx<'_>,
    id: SessionId,
    reason: SessionCloseReason,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agent_sessions SET closed_at = $2, close_reason = $3
         WHERE id = $1 AND closed_at IS NULL",
        Uuid::from(id),
        now,
        reason.as_str()
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Close (reason `idle`) every open session last seen before `cutoff`;
/// returns their ids (their threads close `peer_gone`).
pub async fn close_idle(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Vec<SessionId>, StoreError> {
    let mut c = tx.conn().await;
    let ids = sqlx::query_scalar!(
        "UPDATE agent_sessions SET closed_at = $2, close_reason = 'idle'
         WHERE closed_at IS NULL AND last_seen_at < $1
         RETURNING id",
        cutoff,
        now
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(ids.into_iter().map(SessionId::from_uuid).collect())
}
