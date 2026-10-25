//! `shell_scopes`: scoped shells inside an umbrella shell grant, and which
//! scope each of their commands ran in (`shell_scope_jobs`).
//!
//! A scope is opened for the caller's own issuable umbrella grant (the
//! [`IssuableGrant`] of this transaction), never reopened, and closed once.
//! Lock order: a scope row after its grant (the grant is share-locked by
//! `issuable` first); closing locks only scope rows.

use agent_auth_core::{AgentId, GrantId, JobId, ScopeId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::grants::IssuableGrant;
use crate::{StoreError, Tx};

/// The most scopes open at once in one umbrella.
pub const MAX_OPEN: i64 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRow {
    pub id: ScopeId,
    pub grant_id: GrantId,
    pub agent_id: AgentId,
    pub purpose: String,
    /// The model's one sentence on why the purpose fits the umbrella.
    pub verdict: String,
    pub opened_at: OffsetDateTime,
    pub closed_at: Option<OffsetDateTime>,
}

struct RawScope {
    id: Uuid,
    grant_id: Uuid,
    agent_id: Uuid,
    purpose: String,
    verdict: String,
    opened_at: OffsetDateTime,
    closed_at: Option<OffsetDateTime>,
}

impl From<RawScope> for ScopeRow {
    fn from(r: RawScope) -> Self {
        ScopeRow {
            id: ScopeId::from_uuid(r.id),
            grant_id: GrantId::from_uuid(r.grant_id),
            agent_id: AgentId::from_uuid(r.agent_id),
            purpose: r.purpose,
            verdict: r.verdict,
            opened_at: r.opened_at,
            closed_at: r.closed_at,
        }
    }
}

/// Scopes still open in `grant`.
pub async fn count_open(tx: &Tx<'_>, grant: GrantId) -> Result<i64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM shell_scopes WHERE grant_id = $1 AND closed_at IS NULL"#,
        Uuid::from(grant)
    )
    .fetch_one(&mut **c)
    .await?)
}

/// Open a scope in the umbrella `issuing` (cleared in this transaction).
/// The database refuses it unless that grant is an active umbrella shell.
pub async fn open(
    tx: &Tx<'_>,
    issuing: &IssuableGrant<'_>,
    id: ScopeId,
    purpose: &str,
    verdict: &str,
    now: OffsetDateTime,
) -> Result<ScopeRow, StoreError> {
    if !issuing.belongs_to(tx) {
        return Err(StoreError::WrongProof);
    }
    let g = issuing.grant();
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawScope,
        "INSERT INTO shell_scopes (id, grant_id, agent_id, purpose, verdict, opened_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, grant_id, agent_id, purpose, verdict, opened_at, closed_at",
        Uuid::from(id),
        Uuid::from(g.id),
        Uuid::from(g.agent_id),
        purpose,
        verdict,
        now
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(raw.into())
}

/// The scope `id` of `grant`, if it is still open, share-locked until the
/// transaction ends (so it cannot close under a command being sent).
pub async fn open_for_share(
    tx: &Tx<'_>,
    grant: GrantId,
    id: ScopeId,
) -> Result<Option<ScopeRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawScope,
        "SELECT id, grant_id, agent_id, purpose, verdict, opened_at, closed_at
         FROM shell_scopes WHERE id = $1 AND grant_id = $2 AND closed_at IS NULL
         FOR SHARE",
        Uuid::from(id),
        Uuid::from(grant)
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(raw.map(Into::into))
}

/// The scope `id`, open or not, if it belongs to `agent`.
pub async fn get_owned(
    tx: &Tx<'_>,
    agent: AgentId,
    id: ScopeId,
) -> Result<Option<ScopeRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawScope,
        "SELECT id, grant_id, agent_id, purpose, verdict, opened_at, closed_at
         FROM shell_scopes WHERE id = $1 AND agent_id = $2",
        Uuid::from(id),
        Uuid::from(agent)
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(raw.map(Into::into))
}

/// Close one scope of `grant`. False if it was not open.
pub async fn close(
    tx: &Tx<'_>,
    grant: GrantId,
    id: ScopeId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE shell_scopes SET closed_at = greatest($3, opened_at)
         WHERE id = $1 AND grant_id = $2 AND closed_at IS NULL",
        Uuid::from(id),
        Uuid::from(grant),
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Close every scope of `grant` (its shell ended).
pub async fn close_all(
    tx: &Tx<'_>,
    grant: GrantId,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE shell_scopes SET closed_at = greatest($2, opened_at)
         WHERE id IN (SELECT id FROM shell_scopes WHERE grant_id = $1 AND closed_at IS NULL
                      ORDER BY id FOR NO KEY UPDATE)",
        Uuid::from(grant),
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

/// Record that `job` runs in `scope` (with the job, before it is sent).
pub async fn link_job(tx: &Tx<'_>, job: JobId, scope: ScopeId) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO shell_scope_jobs (job_id, scope_id) VALUES ($1, $2)",
        Uuid::from(job),
        Uuid::from(scope)
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// The specs of the commands sent in `scope` before, oldest first (the
/// guard's context), at most `limit` of the newest.
pub async fn earlier_specs(
    tx: &Tx<'_>,
    scope: ScopeId,
    limit: i64,
) -> Result<Vec<Value>, StoreError> {
    let mut c = tx.conn().await;
    let mut specs = sqlx::query_scalar!(
        "SELECT j.spec FROM shell_scope_jobs l JOIN host_jobs j ON j.id = l.job_id
         WHERE l.scope_id = $1 AND j.status <> 'refused'
         ORDER BY j.created_at DESC, j.id DESC LIMIT $2",
        Uuid::from(scope),
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    specs.reverse();
    Ok(specs)
}

/// The same for a guarded shell without scopes: the commands sent in the
/// shell `shell` (its request's id), oldest first, at most `limit`.
pub async fn earlier_in_shell_specs(
    tx: &Tx<'_>,
    shell: agent_auth_core::RequestId,
    limit: i64,
) -> Result<Vec<Value>, StoreError> {
    let mut c = tx.conn().await;
    let mut specs = sqlx::query_scalar!(
        "SELECT spec FROM host_jobs WHERE shell_id = $1 AND status <> 'refused'
         ORDER BY created_at DESC, id DESC LIMIT $2",
        Uuid::from(shell),
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    specs.reverse();
    Ok(specs)
}
