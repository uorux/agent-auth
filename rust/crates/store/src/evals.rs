//! Evals: recorded model calls, their labels, and replays (`eval_runs`,
//! `eval_results`). Nothing here takes part in a decision: rows are written
//! after a decision is made, and replays only read calls and write results.

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{StoreError, Tx};

/// Keep a system prompt (once) under `sha256`, its lowercase hex SHA-256
/// (computed by the caller, checked here: a wrong digest is an error and
/// stores nothing).
pub async fn put_prompt(tx: &Tx<'_>, sha256: &str, text: &str) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    let actual = sqlx::query_scalar!(
        r#"SELECT encode(sha256(convert_to($1, 'UTF8')), 'hex') AS "sha!""#,
        text
    )
    .fetch_one(&mut **c)
    .await?;
    if actual != sha256 {
        return Err(StoreError::WrongProof);
    }
    sqlx::query!(
        "INSERT INTO model_prompts (sha256, text) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING",
        sha256,
        text
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

pub async fn get_prompt(tx: &Tx<'_>, sha: &str) -> Result<Option<String>, StoreError> {
    let mut c = tx.conn().await;
    Ok(
        sqlx::query_scalar!("SELECT text FROM model_prompts WHERE sha256 = $1", sha)
            .fetch_optional(&mut **c)
            .await?,
    )
}

/// A model call to record.
#[derive(Debug, Clone)]
pub struct NewCall<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub model: &'a str,
    pub facts: &'a Value,
    pub context: &'a Value,
    pub system_sha256: &'a str,
    pub user_message: &'a str,
    pub answer: Option<&'a Value>,
    pub class: Option<&'a str>,
    pub error: Option<&'a str>,
    pub latency_ms: i32,
    pub subject: &'a Value,
    pub now: OffsetDateTime,
}

pub async fn record_call(tx: &Tx<'_>, n: &NewCall<'_>) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO model_calls (id, kind, model, facts, context, system_sha256, user_message,
             answer, class, error, latency_ms, subject, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        n.id,
        n.kind,
        n.model,
        n.facts,
        n.context,
        n.system_sha256,
        n.user_message,
        n.answer,
        n.class,
        n.error,
        n.latency_ms,
        n.subject,
        n.now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// A label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub expected: String,
    pub note: String,
    pub source: String,
    pub labeled_by: String,
    pub labeled_at: OffsetDateTime,
}

/// A recorded call, with its label.
#[derive(Debug, Clone)]
pub struct CallRow {
    pub id: Uuid,
    pub kind: String,
    pub model: String,
    pub facts: Value,
    pub context: Value,
    pub system_sha256: String,
    pub user_message: String,
    pub answer: Option<Value>,
    pub class: Option<String>,
    pub error: Option<String>,
    pub latency_ms: i32,
    pub subject: Value,
    pub created_at: OffsetDateTime,
    pub label: Option<Label>,
}

struct RawCall {
    id: Uuid,
    kind: String,
    model: String,
    facts: Value,
    context: Value,
    system_sha256: String,
    user_message: String,
    answer: Option<Value>,
    class: Option<String>,
    error: Option<String>,
    latency_ms: i32,
    subject: Value,
    created_at: OffsetDateTime,
    expected: Option<String>,
    note: Option<String>,
    source: Option<String>,
    labeled_by: Option<String>,
    labeled_at: Option<OffsetDateTime>,
}

impl From<RawCall> for CallRow {
    fn from(r: RawCall) -> Self {
        let label = match (r.expected, r.source, r.labeled_by, r.labeled_at) {
            (Some(expected), Some(source), Some(labeled_by), Some(labeled_at)) => Some(Label {
                expected,
                note: r.note.unwrap_or_default(),
                source,
                labeled_by,
                labeled_at,
            }),
            _ => None,
        };
        CallRow {
            id: r.id,
            kind: r.kind,
            model: r.model,
            facts: r.facts,
            context: r.context,
            system_sha256: r.system_sha256,
            user_message: r.user_message,
            answer: r.answer,
            class: r.class,
            error: r.error,
            latency_ms: r.latency_ms,
            subject: r.subject,
            created_at: r.created_at,
            label,
        }
    }
}

pub async fn get_call(tx: &Tx<'_>, id: Uuid) -> Result<Option<CallRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawCall,
        r#"SELECT c.id, c.kind, c.model, c.facts, c.context, c.system_sha256, c.user_message,
                  c.answer, c.class, c.error, c.latency_ms, c.subject, c.created_at,
                  l.expected AS "expected?", l.note AS "note?", l.source AS "source?",
                  l.labeled_by AS "labeled_by?", l.labeled_at AS "labeled_at?"
           FROM model_calls c LEFT JOIN model_call_labels l ON l.call_id = c.id
           WHERE c.id = $1"#,
        id
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(raw.map(Into::into))
}

/// Which calls: of a kind, labelled or not, in a time window, newest
/// first, before a cursor `(created_at, id)`.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub kind: Option<String>,
    pub labeled: Option<bool>,
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub before: Option<(OffsetDateTime, Uuid)>,
    /// Only these (a replay of chosen calls).
    pub ids: Option<Vec<Uuid>>,
    pub limit: i64,
}

/// Calls matching `s`, newest first, without their facts and user message.
pub async fn list_calls(tx: &Tx<'_>, s: &Selection) -> Result<Vec<CallRow>, StoreError> {
    let mut c = tx.conn().await;
    let (before_at, before_id) = match s.before {
        Some((t, id)) => (Some(t), Some(id)),
        None => (None, None),
    };
    // Without the large columns (facts, user message): a list shows
    // summaries; `get_call` reads one whole.
    let raw = sqlx::query_as!(
        RawCall,
        r#"SELECT c.id, c.kind, c.model, '{}'::jsonb AS "facts!", c.context, c.system_sha256,
                  '' AS "user_message!",
                  c.answer, c.class, c.error, c.latency_ms, c.subject, c.created_at,
                  l.expected AS "expected?", l.note AS "note?", l.source AS "source?",
                  l.labeled_by AS "labeled_by?", l.labeled_at AS "labeled_at?"
           FROM model_calls c LEFT JOIN model_call_labels l ON l.call_id = c.id
           WHERE ($1::text IS NULL OR c.kind = $1)
             AND ($2::boolean IS NULL OR (l.call_id IS NOT NULL) = $2)
             AND ($3::timestamptz IS NULL OR c.created_at >= $3)
             AND ($4::timestamptz IS NULL OR c.created_at < $4)
             AND ($5::timestamptz IS NULL OR (c.created_at, c.id) < ($5, $6::uuid))
             AND ($7::uuid[] IS NULL OR c.id = ANY($7))
           ORDER BY c.created_at DESC, c.id DESC
           LIMIT $8"#,
        s.kind.as_deref(),
        s.labeled,
        s.since,
        s.until,
        before_at,
        before_id,
        s.ids.as_deref(),
        s.limit
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(raw.into_iter().map(Into::into).collect())
}

/// Label a call. An operator's label replaces any; a label from what
/// happened next (`outcome`) never replaces an operator's.
pub async fn set_label(
    tx: &Tx<'_>,
    call: Uuid,
    expected: &str,
    note: &str,
    source: &str,
    by: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "INSERT INTO model_call_labels (call_id, expected, note, source, labeled_by, labeled_at)
         SELECT id, $2, $3, $4, $5, $6 FROM model_calls WHERE id = $1
         ON CONFLICT (call_id) DO UPDATE
           SET expected = EXCLUDED.expected, note = EXCLUDED.note, source = EXCLUDED.source,
               labeled_by = EXCLUDED.labeled_by, labeled_at = EXCLUDED.labeled_at
           WHERE model_call_labels.source = 'outcome' OR EXCLUDED.source = 'operator'",
        call,
        expected,
        note,
        source,
        by,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub async fn delete_label(tx: &Tx<'_>, call: Uuid) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!("DELETE FROM model_call_labels WHERE call_id = $1", call)
        .execute(&mut **c)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// The newest call of `kind` whose subject contains `subject` (e.g.
/// `{"request_id": "..."}`).
pub async fn latest_about(
    tx: &Tx<'_>,
    kind: &str,
    subject: &Value,
) -> Result<Option<Uuid>, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_scalar!(
        "SELECT id FROM model_calls WHERE subject @> $2 AND kind = $1
         ORDER BY created_at DESC, id DESC LIMIT 1",
        kind,
        subject
    )
    .fetch_optional(&mut **c)
    .await?)
}

/// Forget at most `batch` calls older than `before`, except those an
/// operator labelled (the eval set; labels from what happened next do not
/// keep a call); and replays older than it. How many calls went.
pub async fn purge(tx: &Tx<'_>, before: OffsetDateTime, batch: i64) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    let calls = sqlx::query!(
        "DELETE FROM model_calls WHERE id IN (
           SELECT c.id FROM model_calls c WHERE c.created_at < $1
             AND NOT EXISTS (SELECT 1 FROM model_call_labels l
                             WHERE l.call_id = c.id AND l.source = 'operator')
           LIMIT $2)",
        before,
        batch
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    sqlx::query!(
        "DELETE FROM eval_runs WHERE id IN (
           SELECT id FROM eval_runs WHERE created_at < $1 AND status <> 'running' LIMIT $2)",
        before,
        batch
    )
    .execute(&mut **c)
    .await?;
    Ok(calls)
}

// ------------------------------------------------------------------ runs

#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: Uuid,
    pub kind: String,
    pub model: String,
    pub system_sha256: String,
    pub context: Value,
    pub selection: Value,
    pub status: String,
    pub total: i32,
    pub note: String,
    pub created_by: String,
    pub created_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct NewRun<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub model: &'a str,
    pub system_sha256: &'a str,
    pub context: &'a Value,
    pub selection: &'a Value,
    pub total: i32,
    pub note: &'a str,
    pub created_by: &'a str,
    pub now: OffsetDateTime,
}

pub async fn create_run(tx: &Tx<'_>, n: &NewRun<'_>) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO eval_runs (id, kind, model, system_sha256, context, selection, status, total,
             note, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'running', $7, $8, $9, $10)",
        n.id,
        n.kind,
        n.model,
        n.system_sha256,
        n.context,
        n.selection,
        n.total,
        n.note,
        n.created_by,
        n.now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// One replayed call's answer.
#[derive(Debug, Clone)]
pub struct NewResult<'a> {
    pub run: Uuid,
    pub call: Uuid,
    pub answer: Option<&'a Value>,
    pub class: Option<&'a str>,
    pub error: Option<&'a str>,
    pub latency_ms: i32,
}

pub async fn add_result(tx: &Tx<'_>, n: &NewResult<'_>) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO eval_results (run_id, call_id, answer, class, error, latency_ms)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        n.run,
        n.call,
        n.answer,
        n.class,
        n.error,
        n.latency_ms
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

pub async fn finish_run(
    tx: &Tx<'_>,
    run: Uuid,
    status: &str,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "UPDATE eval_runs SET status = $2, finished_at = $3 WHERE id = $1 AND status = 'running'",
        run,
        status,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

pub async fn get_run(tx: &Tx<'_>, id: Uuid) -> Result<Option<RunRow>, StoreError> {
    let mut c = tx.conn().await;
    Ok(
        sqlx::query_as!(RunRow, "SELECT * FROM eval_runs WHERE id = $1", id)
            .fetch_optional(&mut **c)
            .await?,
    )
}

pub async fn list_runs(
    tx: &Tx<'_>,
    kind: Option<&str>,
    limit: i64,
) -> Result<Vec<RunRow>, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_as!(
        RunRow,
        "SELECT * FROM eval_runs WHERE ($1::text IS NULL OR kind = $1)
         ORDER BY created_at DESC, id DESC LIMIT $2",
        kind,
        limit
    )
    .fetch_all(&mut **c)
    .await?)
}

/// A replayed call next to the original and its label.
#[derive(Debug, Clone)]
pub struct ResultRow {
    pub call_id: Uuid,
    pub original: Option<String>,
    pub expected: Option<String>,
    pub class: Option<String>,
    pub answer: Option<Value>,
    pub error: Option<String>,
    pub latency_ms: i32,
}

pub async fn run_results(tx: &Tx<'_>, run: Uuid) -> Result<Vec<ResultRow>, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_as!(
        ResultRow,
        r#"SELECT r.call_id, c.class AS "original?", l.expected AS "expected?", r.class,
                  r.answer, r.error, r.latency_ms
           FROM eval_results r JOIN model_calls c ON c.id = r.call_id
           LEFT JOIN model_call_labels l ON l.call_id = r.call_id
           WHERE r.run_id = $1 ORDER BY c.created_at, c.id"#,
        run
    )
    .fetch_all(&mut **c)
    .await?)
}

/// Replays a restart cut off: failed (they ran in the old process).
pub async fn fail_unfinished(tx: &Tx<'_>, now: OffsetDateTime) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE eval_runs SET status = 'failed', finished_at = $1 WHERE status = 'running'",
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

/// Replays still running.
pub async fn running_runs(tx: &Tx<'_>) -> Result<i64, StoreError> {
    let mut c = tx.conn().await;
    Ok(
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM eval_runs WHERE status = 'running'"#)
            .fetch_one(&mut **c)
            .await?,
    )
}

/// The ids of the calls `s` selects, newest first.
pub async fn select_ids(tx: &Tx<'_>, s: &Selection) -> Result<Vec<Uuid>, StoreError> {
    Ok(list_calls(tx, s).await?.into_iter().map(|c| c.id).collect())
}
