//! `access_requests` and the request state machine.
//!
//! A request is handled through a typed handle, [`Request<S>`], whose state
//! `S` is one of `agent_auth_core::lifecycle::state::*`. Only this module
//! makes handles: [`insert`] returns a `Request<Pending>`, loads return an
//! [`AnyRequest`] to match on, and [`transition`] turns a `Request<From>`
//! into a `Request<To>` by compare-and-swap, for exactly the edges
//! `From: CanMoveTo<To>` allows. An edge the state machine forbids does not
//! compile:
//!
//! ```compile_fail
//! use agent_auth_core::lifecycle::state;
//! use agent_auth_store::requests::{transition, Denial, Request};
//! use agent_auth_store::Tx;
//! async fn reopen(tx: &Tx<'_>, r: Request<state::Denied>, now: time::OffsetDateTime) {
//!     // DENIED is terminal: there is no `CanMoveTo<Approved>` for it.
//!     let _ = transition::<_, state::Approved>(tx, r, todo!(), now).await;
//! }
//! ```
//!
//! ```compile_fail
//! use agent_auth_core::lifecycle::state;
//! use agent_auth_store::requests::{transition, Request};
//! use agent_auth_store::Tx;
//! async fn skip(tx: &Tx<'_>, r: Request<state::Pending>, now: time::OffsetDateTime) {
//!     // Provisioning is reached only through APPROVED.
//!     let _ = transition::<_, state::Provisioning>(tx, r, (), now).await;
//! }
//! ```
//!
//! ```compile_fail
//! use agent_auth_core::lifecycle::state;
//! use agent_auth_store::requests::Request;
//! // Handles are made by the store only.
//! fn forge() -> Request<state::Approved> { Request { row: todo!(), state: std::marker::PhantomData } }
//! ```
//!
//! An approval needs a proof (a clearance from routing, or a human's
//! attestation); there is no other way to build one:
//!
//! ```compile_fail
//! use agent_auth_store::requests::Approval;
//! fn forge() -> Approval {
//!     Approval { basis: todo!(), decided_by: String::new(), reason: String::new(), duration_secs: 60 }
//! }
//! ```
//!
//! ```compile_fail
//! use agent_auth_core::AutoClearance;
//! use agent_auth_store::requests::Approval;
//! // `Route::Approve`'s clearance is not `Route::Llm`'s.
//! fn swap(c: AutoClearance) -> Approval { Approval::llm(c, "model", "why", 60) }
//! ```

use std::marker::PhantomData;

use agent_auth_core::lifecycle::{CanMoveTo, State, state};
use agent_auth_core::{
    AgentId, Authority, DecisionSource, Platform, RequestId, RequestStatus, SessionId, ThreadId,
};
use agent_auth_core::{AutoClearance, HumanApproval, LlmClearance};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, Delegation};
use crate::{Outcome, StoreError, Tx};

const T: &str = "access_requests";

/// A human's edit at approval: the final resource and privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedEdit {
    pub resource: String,
    pub authority: Authority,
}

/// Discord bookkeeping of the request's card.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscordRefs {
    pub channel_id: Option<i64>,
    pub message_id: Option<i64>,
    /// hostexec shells: the thread mirroring every command.
    pub thread_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RequestRow {
    pub id: RequestId,
    pub agent_id: AgentId,
    pub session_id: Option<SessionId>,
    pub delegation: Option<Delegation>,
    pub platform: Platform,
    pub resource: String,
    /// As submitted, before validation.
    pub requested_capability: String,
    pub requested_scope: Value,
    /// `None` only on a request refused before its capability/scope parsed
    /// (then the status is DENIED).
    pub authority: Option<Authority>,
    /// Agent-authored, untrusted.
    pub justification: String,
    pub requested_duration_secs: u32,
    /// Broker context lines (never agent-authored as such).
    pub risk_notes: Vec<String>,
    pub status: RequestStatus,
    /// LLM evaluations started.
    pub attempt: u32,
    pub decision_source: Option<DecisionSource>,
    pub decided_by: Option<String>,
    pub decision_reason: Option<String>,
    pub approved_duration_secs: Option<u32>,
    pub approved_edit: Option<ApprovedEdit>,
    pub decided_at: Option<OffsetDateTime>,
    pub discord: DiscordRefs,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl RequestRow {
    /// What a grant would be for: the human's edit, else the request.
    #[must_use]
    pub fn final_resource(&self) -> &str {
        self.approved_edit
            .as_ref()
            .map_or(self.resource.as_str(), |e| e.resource.as_str())
    }

    #[must_use]
    pub fn final_authority(&self) -> Option<&Authority> {
        self.approved_edit
            .as_ref()
            .map(|e| &e.authority)
            .or(self.authority.as_ref())
    }
}

pub(crate) struct RawRequest {
    id: Uuid,
    agent_id: Uuid,
    session_id: Option<Uuid>,
    delegation_thread_id: Option<Uuid>,
    delegator_agent_id: Option<Uuid>,
    platform: String,
    resource: String,
    requested_capability: String,
    requested_scope: Value,
    authority: Option<Value>,
    justification: String,
    requested_duration_secs: i32,
    risk_notes: Value,
    status: String,
    attempt: i32,
    decision_source: Option<String>,
    decided_by: Option<String>,
    decision_reason: Option<String>,
    approved_duration_secs: Option<i32>,
    approved_authority: Option<Value>,
    approved_resource: Option<String>,
    decided_at: Option<OffsetDateTime>,
    discord_channel_id: Option<i64>,
    discord_message_id: Option<i64>,
    discord_thread_id: Option<i64>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl TryFrom<RawRequest> for RequestRow {
    type Error = StoreError;
    fn try_from(r: RawRequest) -> Result<RequestRow, StoreError> {
        let platform = values::platform(T, &r.platform)?;
        let authority = r
            .authority
            .as_ref()
            .map(|a| values::authority(T, platform, a))
            .transpose()?;
        let approved_edit = match (r.approved_resource, r.approved_authority) {
            (None, None) => None,
            (Some(resource), Some(a)) => Some(ApprovedEdit {
                resource,
                authority: values::authority(T, platform, &a)?,
            }),
            _ => return Err(StoreError::corrupt(T, "half an approved edit")),
        };
        let status = values::request_status(&r.status)?;
        if authority.is_none() && !matches!(status, RequestStatus::Pending | RequestStatus::Denied)
        {
            return Err(StoreError::corrupt(T, "no authority past pending"));
        }
        Ok(RequestRow {
            id: RequestId::from_uuid(r.id),
            agent_id: AgentId::from_uuid(r.agent_id),
            session_id: r.session_id.map(SessionId::from_uuid),
            delegation: Delegation::from_columns(T, r.delegation_thread_id, r.delegator_agent_id)?,
            platform,
            resource: r.resource,
            requested_capability: r.requested_capability,
            requested_scope: r.requested_scope,
            authority,
            justification: r.justification,
            requested_duration_secs: values::unsigned(T, r.requested_duration_secs)?,
            risk_notes: values::string_list(T, r.risk_notes)?,
            status,
            attempt: values::unsigned(T, r.attempt)?,
            decision_source: values::decision_source(r.decision_source.as_deref())?,
            decided_by: r.decided_by,
            decision_reason: r.decision_reason,
            approved_duration_secs: values::opt_unsigned(T, r.approved_duration_secs)?,
            approved_edit,
            decided_at: r.decided_at,
            discord: DiscordRefs {
                channel_id: r.discord_channel_id,
                message_id: r.discord_message_id,
                thread_id: r.discord_thread_id,
            },
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

// ------------------------------------------------------------ handles

/// A request known (as of its load or last transition) to be in state `S`.
/// Not `Clone`: a transition consumes it. Made only by this module.
#[derive(Debug)]
pub struct Request<S: State> {
    row: RequestRow,
    state: PhantomData<S>,
}

impl<S: State> Request<S> {
    fn new(row: RequestRow) -> Result<Request<S>, StoreError> {
        if row.status == S::STATUS {
            Ok(Request {
                row,
                state: PhantomData,
            })
        } else {
            Err(StoreError::corrupt(T, "handle state mismatch"))
        }
    }

    #[must_use]
    pub fn row(&self) -> &RequestRow {
        &self.row
    }

    #[must_use]
    pub fn id(&self) -> RequestId {
        self.row.id
    }

    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.row.agent_id
    }

    #[must_use]
    pub fn into_row(self) -> RequestRow {
        self.row
    }
}

/// A loaded request, by state.
#[derive(Debug)]
pub enum AnyRequest {
    Pending(Request<state::Pending>),
    LlmEvaluating(Request<state::LlmEvaluating>),
    LlmDenied(Request<state::LlmDenied>),
    AwaitingHuman(Request<state::AwaitingHuman>),
    Approved(Request<state::Approved>),
    Provisioning(Request<state::Provisioning>),
    Granted(Request<state::Granted>),
    ProvisionFailed(Request<state::ProvisionFailed>),
    Denied(Request<state::Denied>),
}

impl AnyRequest {
    fn from_row(row: RequestRow) -> Result<AnyRequest, StoreError> {
        Ok(match row.status {
            RequestStatus::Pending => AnyRequest::Pending(Request::new(row)?),
            RequestStatus::LlmEvaluating => AnyRequest::LlmEvaluating(Request::new(row)?),
            RequestStatus::LlmDenied => AnyRequest::LlmDenied(Request::new(row)?),
            RequestStatus::AwaitingHuman => AnyRequest::AwaitingHuman(Request::new(row)?),
            RequestStatus::Approved => AnyRequest::Approved(Request::new(row)?),
            RequestStatus::Provisioning => AnyRequest::Provisioning(Request::new(row)?),
            RequestStatus::Granted => AnyRequest::Granted(Request::new(row)?),
            RequestStatus::ProvisionFailed => AnyRequest::ProvisionFailed(Request::new(row)?),
            RequestStatus::Denied => AnyRequest::Denied(Request::new(row)?),
        })
    }

    #[must_use]
    pub fn row(&self) -> &RequestRow {
        match self {
            AnyRequest::Pending(r) => r.row(),
            AnyRequest::LlmEvaluating(r) => r.row(),
            AnyRequest::LlmDenied(r) => r.row(),
            AnyRequest::AwaitingHuman(r) => r.row(),
            AnyRequest::Approved(r) => r.row(),
            AnyRequest::Provisioning(r) => r.row(),
            AnyRequest::Granted(r) => r.row(),
            AnyRequest::ProvisionFailed(r) => r.row(),
            AnyRequest::Denied(r) => r.row(),
        }
    }

    #[must_use]
    pub fn status(&self) -> RequestStatus {
        self.row().status
    }

    #[must_use]
    pub fn into_row(self) -> RequestRow {
        match self {
            AnyRequest::Pending(r) => r.into_row(),
            AnyRequest::LlmEvaluating(r) => r.into_row(),
            AnyRequest::LlmDenied(r) => r.into_row(),
            AnyRequest::AwaitingHuman(r) => r.into_row(),
            AnyRequest::Approved(r) => r.into_row(),
            AnyRequest::Provisioning(r) => r.into_row(),
            AnyRequest::Granted(r) => r.into_row(),
            AnyRequest::ProvisionFailed(r) => r.into_row(),
            AnyRequest::Denied(r) => r.into_row(),
        }
    }
}

// --------------------------------------------------------- transitions

/// What entering a state writes besides the status. Each target state's
/// `Data` says what the caller must supply (nothing, an approval, a
/// denial...), so the database CHECKs that tie decision fields to statuses
/// hold after every transition.
#[derive(Debug, Default)]
pub struct Changes {
    proof: Option<Proof>,
    bump_attempt: bool,
    justification: Option<String>,
    source: Option<DecisionSource>,
    decided_by: Option<String>,
    reason: Option<String>,
    reason_suffix: Option<String>,
    approved_duration_secs: Option<u32>,
    decided: bool,
    note: Option<String>,
}

/// What a proof-carrying entry (an approval, an LLM round) was made for:
/// the request, the authority (clearances), and the states it may come
/// from. `transition` refuses a mismatch with `StoreError::WrongProof`.
#[derive(Debug)]
struct Proof {
    request: RequestId,
    authority: Option<Authority>,
    from: &'static [RequestStatus],
}

/// A state a request can be moved into, and the data that takes.
pub trait Enter: State {
    type Data;
    #[doc(hidden)]
    fn changes(data: Self::Data) -> Changes;
}

/// Entering LLM_EVALUATING starts an evaluation round (`attempt += 1`).
/// It needs the [`LlmClearance`] routing gave this request (`Route::Llm`;
/// a retry re-routes with the current facts, core B-4). A retry replaces
/// the justification (core B-17: the old one is lost; the LLM evaluation
/// rows keep their reasoning).
#[derive(Debug)]
pub struct LlmRound {
    pub clearance: LlmClearance,
    pub justification: Option<String>,
}

impl Enter for state::LlmEvaluating {
    type Data = LlmRound;
    fn changes(d: LlmRound) -> Changes {
        Changes {
            proof: Some(Proof {
                request: d.clearance.request(),
                authority: Some(d.clearance.authority().clone()),
                from: &[RequestStatus::Pending, RequestStatus::LlmDenied],
            }),
            bump_attempt: true,
            justification: d.justification,
            ..Changes::default()
        }
    }
}

/// The LLM's denial (the agent may retry or escalate).
#[derive(Debug, Clone)]
pub struct LlmDenial {
    pub model: String,
    pub reasoning: String,
}

impl Enter for state::LlmDenied {
    type Data = LlmDenial;
    fn changes(d: LlmDenial) -> Changes {
        Changes {
            source: Some(DecisionSource::Llm),
            decided_by: Some(d.model),
            reason: Some(d.reasoning),
            ..Changes::default()
        }
    }
}

/// To a human; optionally with a risk note explaining why.
#[derive(Debug, Clone, Default)]
pub struct Escalation {
    pub note: Option<String>,
}

impl Enter for state::AwaitingHuman {
    type Data = Escalation;
    fn changes(d: Escalation) -> Changes {
        Changes {
            note: d.note,
            ..Changes::default()
        }
    }
}

/// An approval: on what grounds, who, why, and for how long. Built only
/// from a proof:
/// - [`Approval::auto`]: an [`AutoClearance`] (`Route::Approve`; source
///   `policy` or `rule`), from PENDING (creation) or AWAITING_HUMAN (a new
///   window rule);
/// - [`Approval::llm`]: an [`LlmClearance`] (`Route::Llm`, re-routed when
///   the verdict comes), from LLM_EVALUATING;
/// - [`Approval::human`]: a [`HumanApproval`], from AWAITING_HUMAN.
///
/// The proof names its request (and, for clearances, the authority);
/// `transition` refuses an approval for another request, authority or
/// starting state.
#[derive(Debug)]
pub struct Approval {
    basis: Basis,
    decided_by: String,
    reason: String,
    duration_secs: u32,
}

#[derive(Debug)]
enum Basis {
    Auto(AutoClearance),
    Llm(LlmClearance),
    Human(HumanApproval),
}

impl Approval {
    /// Policy or a saved rule cleared it (`decided_by`: `policy`, `rule` or
    /// `window:<rule id>`).
    #[must_use]
    pub fn auto(
        clearance: AutoClearance,
        decided_by: impl Into<String>,
        reason: impl Into<String>,
        duration_secs: u32,
    ) -> Approval {
        Approval {
            basis: Basis::Auto(clearance),
            decided_by: decided_by.into(),
            reason: reason.into(),
            duration_secs,
        }
    }

    /// The LLM reviewer approved it (`model` is recorded as the decider).
    #[must_use]
    pub fn llm(
        clearance: LlmClearance,
        model: impl Into<String>,
        reason: impl Into<String>,
        duration_secs: u32,
    ) -> Approval {
        Approval {
            basis: Basis::Llm(clearance),
            decided_by: model.into(),
            reason: reason.into(),
            duration_secs,
        }
    }

    /// A human approved it (the attestation's `decided_by` is recorded).
    #[must_use]
    pub fn human(
        approval: HumanApproval,
        reason: impl Into<String>,
        duration_secs: u32,
    ) -> Approval {
        Approval {
            decided_by: approval.decided_by().to_owned(),
            basis: Basis::Human(approval),
            reason: reason.into(),
            duration_secs,
        }
    }

    #[must_use]
    pub fn source(&self) -> DecisionSource {
        match &self.basis {
            Basis::Auto(c) => c.source(),
            Basis::Llm(_) => DecisionSource::Llm,
            Basis::Human(_) => DecisionSource::Human,
        }
    }

    #[must_use]
    pub fn decided_by(&self) -> &str {
        &self.decided_by
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn duration_secs(&self) -> u32 {
        self.duration_secs
    }
}

impl Enter for state::Approved {
    type Data = Approval;
    fn changes(d: Approval) -> Changes {
        let source = d.source();
        let proof = match &d.basis {
            Basis::Auto(c) => Proof {
                request: c.request(),
                authority: Some(c.authority().clone()),
                // A clearance never says "human"; refuse one that would.
                from: if c.source() == DecisionSource::Human {
                    &[]
                } else {
                    &[RequestStatus::Pending, RequestStatus::AwaitingHuman]
                },
            },
            Basis::Llm(c) => Proof {
                request: c.request(),
                authority: Some(c.authority().clone()),
                from: &[RequestStatus::LlmEvaluating],
            },
            Basis::Human(h) => Proof {
                request: h.request(),
                authority: None,
                from: &[RequestStatus::AwaitingHuman],
            },
        };
        Changes {
            proof: Some(proof),
            source: Some(source),
            decided_by: Some(d.decided_by),
            reason: Some(d.reason),
            approved_duration_secs: Some(d.duration_secs),
            decided: true,
            ..Changes::default()
        }
    }
}

/// A denial: by whom (if anyone named) and why (agent-visible).
#[derive(Debug, Clone)]
pub struct Denial {
    pub source: DecisionSource,
    pub decided_by: Option<String>,
    pub reason: String,
}

impl Enter for state::Denied {
    type Data = Denial;
    fn changes(d: Denial) -> Changes {
        Changes {
            source: Some(d.source),
            decided_by: d.decided_by,
            reason: Some(d.reason),
            decided: true,
            ..Changes::default()
        }
    }
}

impl Enter for state::Provisioning {
    type Data = ();
    fn changes((): ()) -> Changes {
        Changes::default()
    }
}

impl Enter for state::Granted {
    type Data = ();
    fn changes((): ()) -> Changes {
        Changes::default()
    }
}

/// Why provisioning failed; appended to the decision reason as
/// `" | provisioning failed: {why}"`.
#[derive(Debug, Clone)]
pub struct ProvisionFailure {
    pub why: String,
}

impl Enter for state::ProvisionFailed {
    type Data = ProvisionFailure;
    fn changes(d: ProvisionFailure) -> Changes {
        Changes {
            reason_suffix: Some(format!(" | provisioning failed: {}", d.why)),
            ..Changes::default()
        }
    }
}

/// Someone else moved the request first (or it is gone). The handle was
/// consumed: reload to see where it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("request {id} changed state concurrently")]
pub struct Lost {
    pub id: RequestId,
}

/// Move a request along an allowed edge: `UPDATE ... WHERE id = $1 AND
/// status = From::STATUS` (also bumping `updated_at`), writing what `To`
/// requires. Exactly one of two racing transitions from the same state
/// wins; the other gets `Lost`.
pub async fn transition<From, To>(
    tx: &Tx<'_>,
    request: Request<From>,
    data: To::Data,
    now: OffsetDateTime,
) -> Outcome<Request<To>, Lost>
where
    From: CanMoveTo<To>,
    To: Enter,
{
    let id = request.id();
    let ch = To::changes(data);
    if let Some(proof) = &ch.proof {
        let row = request.row();
        let authority_ok = proof
            .authority
            .as_ref()
            .is_none_or(|a| row.authority.as_ref() == Some(a));
        if proof.request != id || !authority_ok || !proof.from.contains(&From::STATUS) {
            return Err(StoreError::WrongProof);
        }
    }
    let decided_at = ch.decided.then_some(now);
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        r#"UPDATE access_requests SET
               status = $3,
               updated_at = $4,
               attempt = attempt + CASE WHEN $5 THEN 1 ELSE 0 END,
               justification = COALESCE($6, justification),
               decision_source = COALESCE($7, decision_source),
               decided_by = COALESCE($8, decided_by),
               decision_reason = CASE
                   WHEN $10::text IS NULL THEN COALESCE($9, decision_reason)
                   ELSE COALESCE($9, decision_reason, '') || $10
               END,
               approved_duration_secs = COALESCE($11, approved_duration_secs),
               decided_at = COALESCE($12, decided_at),
               risk_notes = CASE
                   WHEN $13::text IS NULL THEN risk_notes
                   ELSE risk_notes || jsonb_build_array($13::text)
               END
           WHERE id = $1 AND status = $2
           RETURNING *"#,
        Uuid::from(id),
        From::STATUS.as_str(),
        To::STATUS.as_str(),
        now,
        ch.bump_attempt,
        ch.justification,
        ch.source.map(DecisionSource::as_str),
        ch.decided_by,
        ch.reason,
        ch.reason_suffix,
        values::opt_to_i32(ch.approved_duration_secs)?,
        decided_at,
        ch.note,
    )
    .fetch_optional(&mut **c)
    .await?;
    match raw {
        None => Ok(Err(Lost { id })),
        Some(raw) => Ok(Ok(Request::new(raw.try_into()?)?)),
    }
}

// -------------------------------------------------------------- writes

/// A new request (always inserted PENDING, then moved by `transition` in
/// the same transaction).
#[derive(Debug, Clone)]
pub struct NewRequest<'a> {
    pub id: RequestId,
    pub agent_id: AgentId,
    pub session_id: Option<SessionId>,
    pub delegation: Option<Delegation>,
    pub platform: Platform,
    pub resource: &'a str,
    pub requested_capability: &'a str,
    pub requested_scope: &'a Value,
    /// Must be of `platform` (refused otherwise).
    pub authority: Option<&'a Authority>,
    pub justification: &'a str,
    pub requested_duration_secs: u32,
    pub risk_notes: &'a [String],
    pub now: OffsetDateTime,
}

pub async fn insert(
    tx: &Tx<'_>,
    n: &NewRequest<'_>,
) -> Result<Request<state::Pending>, StoreError> {
    if n.authority.is_some_and(|a| a.platform() != n.platform) {
        return Err(StoreError::OutOfRange(format!(
            "an authority of another platform than {}",
            n.platform
        )));
    }
    let authority = n.authority.map(Authority::to_json);
    let notes = serde_json::to_value(n.risk_notes)
        .map_err(|e| StoreError::OutOfRange(format!("risk notes: {e}")))?;
    let (thread, delegator) = match n.delegation {
        Some(d) => (
            Some(Uuid::from(d.thread_id)),
            Some(Uuid::from(d.delegator_agent_id)),
        ),
        None => (None, None),
    };
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        r#"INSERT INTO access_requests (id, agent_id, session_id, delegation_thread_id,
               delegator_agent_id, platform, resource, requested_capability, requested_scope,
               authority, justification, requested_duration_secs, risk_notes, status, attempt,
               created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending', 0, $14, $14)
           RETURNING *"#,
        Uuid::from(n.id),
        Uuid::from(n.agent_id),
        n.session_id.map(Uuid::from),
        thread,
        delegator,
        n.platform.as_str(),
        n.resource,
        n.requested_capability,
        n.requested_scope,
        authority,
        n.justification,
        values::to_i32(n.requested_duration_secs)?,
        notes,
        n.now,
    )
    .fetch_one(&mut **c)
    .await?;
    Request::new(raw.try_into()?)
}

/// Store a human's edited approval (resource and authority together).
pub async fn set_approved_edit(
    tx: &Tx<'_>,
    request: &mut Request<state::Approved>,
    edit: ApprovedEdit,
) -> Outcome<(), Lost> {
    if edit.authority.platform() != request.row.platform {
        return Err(StoreError::OutOfRange(
            "an approved authority of another platform".to_owned(),
        ));
    }
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE access_requests SET approved_resource = $2, approved_authority = $3, updated_at = now()
         WHERE id = $1 AND status = 'approved'",
        Uuid::from(request.id()),
        edit.resource,
        edit.authority.to_json()
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    if n != 1 {
        return Ok(Err(Lost { id: request.id() }));
    }
    request.row.approved_edit = Some(edit);
    Ok(Ok(()))
}

/// Append one risk note atomically (no lost append between concurrent
/// writers; core B-20).
pub async fn append_note(tx: &Tx<'_>, id: RequestId, note: &str) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE access_requests SET risk_notes = risk_notes || jsonb_build_array($2::text),
             updated_at = now()
         WHERE id = $1",
        Uuid::from(id),
        note
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Record where the request's Discord card lives (unset fields kept).
pub async fn set_discord(
    tx: &Tx<'_>,
    id: RequestId,
    refs: DiscordRefs,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE access_requests SET
             discord_channel_id = COALESCE($2, discord_channel_id),
             discord_message_id = COALESCE($3, discord_message_id),
             discord_thread_id = COALESCE($4, discord_thread_id)
         WHERE id = $1",
        Uuid::from(id),
        refs.channel_id,
        refs.message_id,
        refs.thread_id
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

// --------------------------------------------------------------- reads

fn any(raw: Option<RawRequest>) -> Result<Option<AnyRequest>, StoreError> {
    raw.map(|r| AnyRequest::from_row(r.try_into()?)).transpose()
}

fn rows(raw: Vec<RawRequest>) -> Result<Vec<RequestRow>, StoreError> {
    raw.into_iter().map(RequestRow::try_from).collect()
}

pub async fn get(tx: &Tx<'_>, id: RequestId) -> Result<Option<AnyRequest>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    any(raw)
}

/// Load and lock the row until the transaction ends (decisions that read,
/// check, then write several fields).
pub async fn get_for_update(tx: &Tx<'_>, id: RequestId) -> Result<Option<AnyRequest>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE id = $1 FOR UPDATE",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    any(raw)
}

/// The agent's own request; `None` for a missing one or another agent's
/// (the two are indistinguishable to the agent: `unknown request`).
pub async fn get_owned(
    tx: &Tx<'_>,
    agent: AgentId,
    id: RequestId,
) -> Result<Option<AnyRequest>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE id = $1 AND agent_id = $2",
        Uuid::from(id),
        Uuid::from(agent)
    )
    .fetch_optional(&mut **c)
    .await?;
    any(raw)
}

/// Requests of these agents a human could still decide (containment
/// denies them).
pub async fn decidable_of(tx: &Tx<'_>, agents: &[AgentId]) -> Result<Vec<RequestId>, StoreError> {
    let ids: Vec<Uuid> = agents.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT id FROM access_requests
         WHERE agent_id = ANY($1) AND status IN ('awaiting_human', 'llm_evaluating', 'llm_denied')
         ORDER BY created_at",
        &ids
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(RequestId::from_uuid).collect())
}

/// Requests awaiting a human on one platform (a new window rule may clear them).
pub async fn awaiting_human_on(
    tx: &Tx<'_>,
    platform: Platform,
) -> Result<Vec<RequestRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE status = 'awaiting_human' AND platform = $1
         ORDER BY created_at",
        platform.as_str()
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// LLM_EVALUATING requests not touched since `cutoff` (orphaned by a
/// restart; core B-3): to escalate or re-evaluate.
pub async fn stale_llm_evaluating(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
) -> Result<Vec<RequestId>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT id FROM access_requests WHERE status = 'llm_evaluating' AND updated_at <= $1
         ORDER BY updated_at",
        cutoff
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(RequestId::from_uuid).collect())
}

/// Newest first (admin list).
pub async fn recent(tx: &Tx<'_>, limit: i64) -> Result<Vec<RequestRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests ORDER BY created_at DESC, id LIMIT $1",
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Decisions log: newest first, optionally by source and agent.
pub async fn decisions(
    tx: &Tx<'_>,
    source: Option<DecisionSource>,
    agent: Option<AgentId>,
    limit: i64,
) -> Result<Vec<RequestRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests
         WHERE ($1::text IS NULL OR decision_source = $1) AND ($2::uuid IS NULL OR agent_id = $2)
         ORDER BY created_at DESC, id LIMIT $3",
        source.map(DecisionSource::as_str),
        agent.map(Uuid::from),
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Changed at or after `since`, oldest change first (audit feed).
pub async fn updated_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<RequestRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE updated_at >= $1 ORDER BY updated_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Requests delegated on a thread, oldest first.
pub async fn by_delegation_thread(
    tx: &Tx<'_>,
    thread: ThreadId,
) -> Result<Vec<RequestRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRequest,
        "SELECT * FROM access_requests WHERE delegation_thread_id = $1 ORDER BY created_at",
        Uuid::from(thread)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// How many requests were delegated on each of these threads.
pub async fn count_by_delegation_threads(
    tx: &Tx<'_>,
    threads: &[ThreadId],
) -> Result<Vec<(ThreadId, i64)>, StoreError> {
    let ids: Vec<Uuid> = threads.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        r#"SELECT delegation_thread_id AS "thread!", count(*) AS "n!"
           FROM access_requests WHERE delegation_thread_id = ANY($1)
           GROUP BY delegation_thread_id"#,
        &ids
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out
        .into_iter()
        .map(|r| (ThreadId::from_uuid(r.thread), r.n))
        .collect())
}
