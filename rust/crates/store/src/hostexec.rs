//! `host_jobs`: commands run (or to run) on a host by its hostd: a run/tpl
//! grant's single job (id = the request's id) or one command of a shell.
//!
//! Status: `starting` → `running` → `done`, or `refused`/`lost`. A stored
//! result is never overwritten (daemons INV-32; a trigger enforces it), and
//! a result is stored only from the host the job was sent to.

use agent_auth_core::{AgentId, GrantId, JobId, RequestId, Tier};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

const T: &str = "host_jobs";

text_enum! {
    JobStatus {
        Starting = "starting",
        Running = "running",
        Done = "done",
        Refused = "refused",
        Lost = "lost",
    }
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: JobId,
    pub grant_id: Option<GrantId>,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub host: String,
    pub tier: Tier,
    /// The shell (its request's id) for a shell command.
    pub shell_id: Option<RequestId>,
    pub spec: Value,
    pub status: JobStatus,
    /// What hostd admitted it on (`totp`, `auto`, `armed+human`, ...).
    pub via: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: Option<String>,
    pub output_bytes: Option<u32>,
    pub output_sha256: Option<String>,
    pub truncated: bool,
    pub duration_ms: Option<i64>,
    pub finished_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

struct RawJob {
    id: Uuid,
    grant_id: Option<Uuid>,
    request_id: Uuid,
    agent_id: Uuid,
    host: String,
    tier: String,
    shell_id: Option<Uuid>,
    spec: Value,
    status: String,
    via: Option<String>,
    exit_code: Option<i32>,
    error: Option<String>,
    output: Option<String>,
    output_bytes: Option<i32>,
    output_sha256: Option<String>,
    truncated: bool,
    duration_ms: Option<i64>,
    finished_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl TryFrom<RawJob> for JobRow {
    type Error = StoreError;
    fn try_from(r: RawJob) -> Result<JobRow, StoreError> {
        Ok(JobRow {
            id: JobId::from_uuid(r.id),
            grant_id: r.grant_id.map(GrantId::from_uuid),
            request_id: RequestId::from_uuid(r.request_id),
            agent_id: AgentId::from_uuid(r.agent_id),
            tier: Tier::parse(&r.tier)
                .ok_or_else(|| StoreError::corrupt(T, format!("tier {:?}", r.tier)))?,
            status: JobStatus::parse(&r.status)
                .ok_or_else(|| StoreError::corrupt(T, format!("status {:?}", r.status)))?,
            host: r.host,
            shell_id: r.shell_id.map(RequestId::from_uuid),
            spec: r.spec,
            via: r.via,
            exit_code: r.exit_code,
            error: r.error,
            output: r.output,
            output_bytes: values::opt_unsigned(T, r.output_bytes)?,
            output_sha256: r.output_sha256,
            truncated: r.truncated,
            duration_ms: r.duration_ms,
            finished_at: r.finished_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

fn rows(raw: Vec<RawJob>) -> Result<Vec<JobRow>, StoreError> {
    raw.into_iter().map(JobRow::try_from).collect()
}

fn opt(raw: Option<RawJob>) -> Result<Option<JobRow>, StoreError> {
    raw.map(JobRow::try_from).transpose()
}

#[derive(Debug, Clone)]
pub struct NewJob<'a> {
    pub id: JobId,
    pub grant_id: Option<GrantId>,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub host: &'a str,
    pub tier: Tier,
    pub shell_id: Option<RequestId>,
    pub spec: &'a Value,
    pub now: OffsetDateTime,
}

/// Insert a job as `starting` (committed before the host is asked).
pub async fn insert(tx: &Tx<'_>, n: &NewJob<'_>) -> Result<JobRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "INSERT INTO host_jobs (id, grant_id, request_id, agent_id, host, tier, shell_id, spec,
             status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'starting', $9, $9)
         RETURNING *",
        Uuid::from(n.id),
        n.grant_id.map(Uuid::from),
        Uuid::from(n.request_id),
        Uuid::from(n.agent_id),
        n.host,
        n.tier.as_str(),
        n.shell_id.map(Uuid::from),
        n.spec,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

pub async fn get(tx: &Tx<'_>, id: JobId) -> Result<Option<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// The agent's own job (`None` for a missing one or another agent's).
pub async fn get_owned(
    tx: &Tx<'_>,
    agent: AgentId,
    id: JobId,
) -> Result<Option<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE id = $1 AND agent_id = $2",
        Uuid::from(id),
        Uuid::from(agent)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// The answer of `host` to a start: move a job of that host that is still
/// `starting` to `running` or `refused` (never over a result that already
/// arrived), recording `via` with it. `via` is also recorded on a job that
/// is still running (a late answer), never on a finished one. Returns
/// whether the status moved.
pub async fn set_status(
    tx: &Tx<'_>,
    id: JobId,
    host: &str,
    status: JobStatus,
    error: Option<&str>,
    via: Option<&str>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE host_jobs SET status = $3, error = COALESCE($4, error),
             via = COALESCE($5, via), updated_at = now()
         WHERE id = $1 AND host = $2 AND status = 'starting'",
        Uuid::from(id),
        host,
        status.as_str(),
        error,
        via
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    if n == 0
        && let Some(via) = via
    {
        sqlx::query!(
            "UPDATE host_jobs SET via = $3, updated_at = now()
             WHERE id = $1 AND host = $2 AND status IN ('starting', 'running')",
            Uuid::from(id),
            host,
            via
        )
        .execute(&mut **c)
        .await?;
    }
    Ok(n == 1)
}

/// A verified result from hostd.
#[derive(Debug, Clone)]
pub struct JobResult<'a> {
    pub exit_code: Option<i32>,
    pub error: Option<&'a str>,
    pub output: &'a str,
    pub output_bytes: u32,
    pub output_sha256: &'a str,
    pub truncated: bool,
    pub duration_ms: Option<i64>,
}

/// What happened to a reported result.
#[derive(Debug, Clone)]
pub enum Finished {
    /// No such job, or it was sent to another host: ignore (no ack).
    NotThisHosts,
    /// It already has a result (ack, nothing changes).
    AlreadyFinal(JobRow),
    /// Stored now (ack, wake waiters, notify).
    Stored(JobRow),
}

/// Store a job's result if it came from the job's host and the job is
/// still `starting`/`running`.
pub async fn finish(
    tx: &Tx<'_>,
    id: JobId,
    host: &str,
    r: &JobResult<'_>,
    now: OffsetDateTime,
) -> Result<Finished, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "UPDATE host_jobs SET status = 'done', exit_code = $3, error = $4, output = $5,
             output_bytes = $6, output_sha256 = $7, truncated = $8, duration_ms = $9,
             finished_at = $10, updated_at = $10
         WHERE id = $1 AND host = $2 AND status IN ('starting', 'running')
         RETURNING *",
        Uuid::from(id),
        host,
        r.exit_code,
        r.error,
        r.output,
        values::to_i32(r.output_bytes)?,
        r.output_sha256,
        r.truncated,
        r.duration_ms,
        now
    )
    .fetch_optional(&mut **c)
    .await?;
    if let Some(raw) = raw {
        return Ok(Finished::Stored(raw.try_into()?));
    }
    let current = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE id = $1 AND host = $2",
        Uuid::from(id),
        host
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(match opt(current)? {
        None => Finished::NotThisHosts,
        Some(j) => Finished::AlreadyFinal(j),
    })
}

/// Specs of a shell's commands created before `job` (the watcher's
/// context; daemons bug 10: strictly earlier, not merely "other").
pub async fn earlier_in_shell(
    tx: &Tx<'_>,
    shell: RequestId,
    job: JobId,
) -> Result<Vec<Value>, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_scalar!(
        "SELECT spec FROM host_jobs
         WHERE shell_id = $1 AND id <> $2
           AND created_at < (SELECT created_at FROM host_jobs WHERE id = $2)
         ORDER BY created_at",
        Uuid::from(shell),
        Uuid::from(job)
    )
    .fetch_all(&mut **c)
    .await?)
}

/// Newest first, optionally on one host (admin command log).
pub async fn recent(
    tx: &Tx<'_>,
    host: Option<&str>,
    limit: i64,
) -> Result<Vec<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE ($1::text IS NULL OR host = $1)
         ORDER BY created_at DESC, id LIMIT $2",
        host,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Jobs still `starting`/`running` that were created before `cutoff`
/// (candidates for `lost`; daemons bug 3).
pub async fn unfinished_before(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
) -> Result<Vec<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE status IN ('starting', 'running') AND created_at < $1
         ORDER BY created_at",
        cutoff
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Created at or after `since`, oldest first (audit feed).
pub async fn created_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE created_at >= $1 ORDER BY created_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Finished at or after `since`, oldest first (audit feed).
pub async fn finished_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "SELECT * FROM host_jobs WHERE finished_at >= $1 ORDER BY finished_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// A job whose outcome is unknown — hostd restarted while it ran, or no
/// result came long after its timeout (daemons bug 3) — becomes `lost`,
/// from `starting`/`running` only, and only for the job's own host.
/// `None`: it already had an outcome (or is not this host's).
pub async fn mark_lost(
    tx: &Tx<'_>,
    id: JobId,
    host: &str,
    error: &str,
    now: OffsetDateTime,
) -> Result<Option<JobRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawJob,
        "UPDATE host_jobs SET status = 'lost', error = $3, finished_at = $4, updated_at = $4
         WHERE id = $1 AND host = $2 AND status IN ('starting', 'running')
         RETURNING *",
        Uuid::from(id),
        host,
        error,
        now
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}
