//! `llm_evaluations`: the LLM reviewer's recorded verdicts (errors are not
//! recorded). One per request and attempt.

use agent_auth_core::{EvaluationId, RequestId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

const T: &str = "llm_evaluations";

text_enum! {
    Verdict { Approve = "approve", Deny = "deny" }
}

#[derive(Debug, Clone)]
pub struct EvaluationRow {
    pub id: EvaluationId,
    pub request_id: RequestId,
    pub attempt: u32,
    pub model: String,
    pub verdict: Verdict,
    pub reasoning: String,
    pub suggested_duration_secs: Option<u32>,
    pub raw_response: Value,
    pub created_at: OffsetDateTime,
}

struct RawEvaluation {
    id: Uuid,
    request_id: Uuid,
    attempt: i32,
    model: String,
    verdict: String,
    reasoning: String,
    suggested_duration_secs: Option<i32>,
    raw_response: Value,
    created_at: OffsetDateTime,
}

impl TryFrom<RawEvaluation> for EvaluationRow {
    type Error = StoreError;
    fn try_from(r: RawEvaluation) -> Result<EvaluationRow, StoreError> {
        Ok(EvaluationRow {
            id: EvaluationId::from_uuid(r.id),
            request_id: RequestId::from_uuid(r.request_id),
            attempt: values::unsigned(T, r.attempt)?,
            verdict: Verdict::parse(&r.verdict)
                .ok_or_else(|| StoreError::corrupt(T, format!("verdict {:?}", r.verdict)))?,
            model: r.model,
            reasoning: r.reasoning,
            suggested_duration_secs: values::opt_unsigned(T, r.suggested_duration_secs)?,
            raw_response: r.raw_response,
            created_at: r.created_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewEvaluation<'a> {
    pub id: EvaluationId,
    pub request_id: RequestId,
    pub attempt: u32,
    pub model: &'a str,
    pub verdict: Verdict,
    pub reasoning: &'a str,
    /// Positive; validate the model's suggestion before storing it.
    pub suggested_duration_secs: Option<u32>,
    pub raw_response: &'a Value,
    pub now: OffsetDateTime,
}

/// Record a verdict. A second verdict for the same attempt is a unique
/// violation.
pub async fn insert(tx: &Tx<'_>, n: &NewEvaluation<'_>) -> Result<EvaluationRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEvaluation,
        "INSERT INTO llm_evaluations (id, request_id, attempt, model, verdict, reasoning,
             suggested_duration_secs, raw_response, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *",
        Uuid::from(n.id),
        Uuid::from(n.request_id),
        values::to_i32(n.attempt)?,
        n.model,
        n.verdict.as_str(),
        n.reasoning,
        values::opt_to_i32(n.suggested_duration_secs)?,
        n.raw_response,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

/// A request's earlier verdicts, by attempt (the reviewer's history).
pub async fn for_request(
    tx: &Tx<'_>,
    request: RequestId,
) -> Result<Vec<EvaluationRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEvaluation,
        "SELECT * FROM llm_evaluations WHERE request_id = $1 ORDER BY attempt",
        Uuid::from(request)
    )
    .fetch_all(&mut **c)
    .await?;
    raw.into_iter().map(EvaluationRow::try_from).collect()
}
