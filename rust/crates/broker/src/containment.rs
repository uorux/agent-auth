//! Containment (core-lifecycle-policy §8.5, http-api §2.4): holding agents.
//!
//! An entry is recorded in its own transaction (`store::lockdown::record`,
//! which waits for every in-flight grant/issue check), then acted on:
//! pending requests denied, active grants revoked, a2a threads closed,
//! agent VMs told, the operator pinged. From the moment it commits, nothing
//! is provisioned or issued to a held agent (the `NotHeld` checks).
//!
//! Routes: the operator's `GET/POST /admin/containment` and
//! `POST /admin/containment/lift`; an allowed agent's `GET/POST
//! /v1/containment` (404 to every other agent, before the body is read).

use agent_auth_core::containment::{AgentKind, holds};
use agent_auth_core::policy::AgentMatch as PolicyMatch;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::lockdown::{self, ContainmentEntry, ContainmentSource, NewEntry};
use agent_auth_store::{StoreError, grants};
use agent_auth_wire::containment as wire;
use agent_auth_wire::error::parse_body;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value};

use crate::auth::{AdminCaller, AgentCaller};
use crate::error::{ApiError, ApiResult};
use crate::http::body::JsonBody;
use crate::notify::Notify;
use crate::service::{self, ServiceError, agent_ref_of};
use crate::state::AppState;

/// Why a containment change was refused.
#[derive(Debug, thiserror::Error)]
pub enum ContainError {
    /// 422 `not an agent match: ...`
    #[error("not an agent match: {0}")]
    BadMatch(String),
    /// 404 `no containment '<id>'`
    #[error("no containment {}", agent_auth_core::pyfmt::repr(.0))]
    Unknown(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("the system random number generator failed")]
    Random,
}

impl From<ContainError> for ApiError {
    fn from(e: ContainError) -> ApiError {
        match e {
            ContainError::BadMatch(_) => ApiError::unprocessable(e.to_string()),
            ContainError::Unknown(_) => ApiError::not_found(e.to_string()),
            other => ApiError::internal(&other),
        }
    }
}

fn wire_entry(e: &ContainmentEntry) -> wire::ContainmentEntry {
    wire::ContainmentEntry {
        id: e.id.clone(),
        matches: match &e.r#match {
            Value::Object(m) => m.clone(),
            _ => Map::new(),
        },
        reason: e.reason.clone(),
        evidence: e.evidence.clone(),
        by: e.by.clone(),
        source: e.source.as_str().to_owned(),
        at: e.at,
    }
}

fn at_text(e: &ContainmentEntry) -> String {
    agent_auth_wire::timestamp::format(e.at).unwrap_or_default()
}

/// Every standing entry, in order.
pub async fn list(st: &AppState) -> Result<Vec<wire::ContainmentEntry>, StoreError> {
    let tx = st.store.begin().await?;
    Ok(lockdown::entries(&tx)
        .await?
        .iter()
        .map(wire_entry)
        .collect())
}

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Record an entry and, in the same transaction, end the held agents'
/// grants: every active one expires now (so the scheduler revokes it
/// through its provisioner even if nothing else runs). Returns the entry
/// and the agents it holds.
pub async fn record(
    st: &AppState,
    r#match: &Value,
    reason: &str,
    evidence: &str,
    by: &str,
    source: ContainmentSource,
) -> Result<(ContainmentEntry, Vec<AgentRow>), ContainError> {
    let now = st.now();
    let id = crate::random::token_hex(4).map_err(|_| ContainError::Random)?;
    let tx = st.store.begin().await?;
    let recorded = lockdown::record(
        &tx,
        &NewEntry {
            id: &id,
            r#match,
            reason,
            evidence,
            by,
            source,
            at: now,
        },
    )
    .await?;
    let entry = recorded.map_err(|e| ContainError::BadMatch(e.to_string()))?;
    let held: Vec<AgentRow> = agents::list(&tx)
        .await?
        .into_iter()
        .filter(|a| a.kind != AgentKind::Operator && holds(&entry.r#match, &a.facts()))
        .collect();
    for a in &held {
        grants::expire_now_of_agent(&tx, a.id, now).await?;
    }
    tx.commit().await?;
    Ok((entry, held))
}

/// What acting on an entry did.
struct FollowUp {
    revoked: u32,
    denied: u32,
    closed: u32,
    daemons: Map<String, Value>,
}

/// Act on a recorded entry: deny what waits, fail what is being set up,
/// revoke what is live, close threads, tell agent VMs. Each step runs even
/// if an earlier one failed (what is left, the scheduler finishes).
async fn follow_up(st: &AppState, held: &[AgentRow], reason: &str, by: &str) -> FollowUp {
    let ids: Vec<_> = held.iter().map(|a| a.id).collect();
    let why = format!("contained: {}", cut(reason, 120));
    let denied = match service::deny_pending(st, &ids, &why, by).await {
        Ok(n) => u32::try_from(n).unwrap_or(u32::MAX),
        Err(e) => {
            tracing::error!(error = %e, "denying a held agent's pending requests failed");
            0
        }
    };
    service::reap_provisioning_of(st, &ids).await;
    let grant_ids = async {
        let tx = st.store.begin().await?;
        grants::active_of_agents(&tx, &ids).await
    }
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "listing a held agent's grants failed; the scheduler expires them");
        Vec::new()
    });
    let mut revoked = 0u32;
    for g in grant_ids {
        match service::revoke_grant(st, g, &why, by).await {
            Ok(_) => revoked = revoked.saturating_add(1),
            // Already expiring now: the scheduler retries the revoke.
            Err(e) => {
                tracing::warn!(grant = %g, error = %e, "revoking a held agent's grant failed")
            }
        }
    }
    let closed = close_threads(st, held).await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "closing a held agent's threads failed");
        0
    });
    let daemons = tell_sandboxes(st, held.to_vec()).await;
    FollowUp {
        revoked,
        denied,
        closed,
        daemons,
    }
}

/// Record an entry and act on it at once. The acting runs as a tracked
/// task: a caller that goes away does not stop it.
pub async fn contain(
    st: &AppState,
    r#match: Value,
    reason: &str,
    evidence: &str,
    by: &str,
    source: ContainmentSource,
) -> Result<wire::ContainResult, ContainError> {
    let reason = cut(reason, 500);
    let evidence = cut(evidence, 4000);
    let (entry, held) = record(st, &r#match, &reason, &evidence, by, source).await?;
    let task = {
        let (st2, held2, reason2, by2) = (st.clone(), held.clone(), reason.clone(), by.to_owned());
        async move { follow_up(&st2, &held2, &reason2, &by2).await }
    };
    let done = service::detached(st, task).await.ok_or_else(|| {
        ContainError::Store(StoreError::OutOfRange("containment task failed".to_owned()))
    })?;
    let out = wire::ContainResult {
        entry: wire_entry(&entry),
        agents: held.iter().map(|a| a.name.clone()).collect(),
        grants_revoked: done.revoked,
        requests_denied: done.denied,
        threads_closed: done.closed,
        daemons: done.daemons.into_iter().collect(),
    };
    tracing::warn!(
        "CONTAINED {} by {by}: {} agents, {} grants revoked",
        entry.describe(&at_text(&entry)),
        held.len(),
        done.revoked
    );
    match serde_json::to_value(&out) {
        Ok(v) => st.notifier.contained(&v).await,
        Err(e) => tracing::error!(error = %e, "could not announce a containment"),
    }
    Ok(out)
}

/// The scheduler's belt and braces: an active grant of an agent some entry
/// holds is revoked (or, if that fails, expires now). Returns how many.
pub async fn sweep_held(st: &AppState) -> usize {
    let now = st.now();
    let found = async {
        let tx = st.store.begin().await?;
        let entries = lockdown::entries(&tx).await?;
        if entries.is_empty() {
            return Ok::<_, StoreError>(Vec::new());
        }
        let held: Vec<(AgentRow, ContainmentEntry)> = agents::list(&tx)
            .await?
            .into_iter()
            .filter(|a| a.kind != AgentKind::Operator)
            .filter_map(|a| {
                let e = agent_auth_core::containment::first_holding(
                    &entries,
                    |e| &e.r#match,
                    &a.facts(),
                )
                .cloned();
                e.map(|e| (a, e))
            })
            .collect();
        let mut out = Vec::new();
        for (a, e) in held {
            for g in grants::active_of_agents(&tx, &[a.id]).await? {
                out.push((g, e.held_text()));
            }
        }
        Ok(out)
    }
    .await;
    let found = match found {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "listing held agents' grants failed");
            return 0;
        }
    };
    let mut n = 0usize;
    for (g, why) in found {
        match service::revoke_grant(st, g, &why, "containment").await {
            Ok(_) => n = n.saturating_add(1),
            Err(ServiceError::Transition(_)) => {}
            Err(e) => {
                tracing::error!(grant = %g, error = %e, "revoking a held agent's grant failed; expiring it");
                let expired = async {
                    let tx = st.store.begin().await?;
                    grants::expire_now(&tx, g, now).await?;
                    tx.commit().await
                }
                .await;
                if let Err(e) = expired {
                    tracing::error!(grant = %g, error = %e, "expiring failed");
                }
            }
        }
    }
    n
}

async fn close_threads(st: &AppState, held: &[AgentRow]) -> Result<u32, StoreError> {
    let mut closed = 0u32;
    for a in held {
        let n = crate::a2a::close_all_for(st, a.id, "contained").await?;
        closed = closed.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
    }
    Ok(closed)
}

async fn tell_sandboxes(st: &AppState, held: Vec<AgentRow>) -> Map<String, Value> {
    match &st.spine.hooks.tell_sandboxes {
        Some(hook) => hook(st.clone(), held).await,
        None => Map::new(),
    }
}

/// Lift one entry (`Some(id)`) or all (the operator's only), as stored.
pub async fn lift_entries(
    st: &AppState,
    which: Option<&str>,
    by: &str,
) -> Result<Vec<ContainmentEntry>, ContainError> {
    let lifted = {
        let tx = st.store.begin().await?;
        let lifted = lockdown::lift(&tx, which).await?;
        if let Some(id) = which
            && lifted.is_empty()
        {
            return Err(ContainError::Unknown(id.to_owned()));
        }
        tx.commit().await?;
        lifted
    };
    let now = st.now();
    for e in &lifted {
        let what = e.describe(&at_text(e));
        tracing::warn!("LIFTED containment {} ({what}) by {by}", e.id);
        st.security_log.record(
            "containment_lifted",
            now,
            &[
                ("containment", Some(&e.id)),
                ("what", Some(&what)),
                ("by", Some(by)),
            ],
        );
    }
    tell_sandboxes(st, Vec::new()).await;
    Ok(lifted)
}

/// Lift one entry or all, for the HTTP route.
pub async fn lift(
    st: &AppState,
    which: &wire::LiftBody,
    by: &str,
) -> Result<Vec<wire::ContainmentEntry>, ContainError> {
    let id = match which {
        wire::LiftBody::One(id) => Some(id.as_str()),
        wire::LiftBody::All => None,
    };
    Ok(lift_entries(st, id, by)
        .await?
        .iter()
        .map(wire_entry)
        .collect())
}

/// Would this match hold every agent? Refused to agents without
/// `allow_all` (http-api §8.2, core B-2): judged on the meaning of the
/// pattern (`AgentMatch::matches_everyone`: `{}`, `{"name": "*"}`,
/// `{"placement": ["host", "sandbox"]}`...), and also on whom it holds
/// today (as the Python: every enabled agent but the operator).
pub(crate) async fn holds_everyone(st: &AppState, r#match: &Value) -> Result<bool, StoreError> {
    let Ok(pattern) = PolicyMatch::from_value(r#match) else {
        return Ok(false); // refused as malformed by `contain` itself
    };
    if pattern.matches_everyone() {
        return Ok(true);
    }
    let tx = st.store.begin().await?;
    let current: Vec<AgentRow> = agents::list_enabled(&tx)
        .await?
        .into_iter()
        .filter(|a| a.kind != AgentKind::Operator)
        .collect();
    Ok(!current.is_empty() && current.iter().all(|a| pattern.matches(&agent_ref_of(a))))
}

fn allowed(st: &AppState, caller: &AgentCaller) -> ApiResult<()> {
    let me = agent_ref_of(caller.agent());
    if st
        .policy
        .containment()
        .agents
        .iter()
        .any(|p| p.matches(&me))
    {
        Ok(())
    } else {
        Err(ApiError::not_found("Not Found"))
    }
}

async fn admin_list(
    State(st): State<AppState>,
    _admin: AdminCaller,
) -> ApiResult<Json<Vec<wire::ContainmentEntry>>> {
    Ok(Json(list(&st).await?))
}

async fn admin_contain(
    State(st): State<AppState>,
    admin: AdminCaller,
    JsonBody(body): JsonBody<wire::ContainBody>,
) -> ApiResult<Json<wire::ContainResult>> {
    let out = contain(
        &st,
        Value::Object(body.matches.into_map()),
        body.reason.as_str(),
        body.evidence.as_str(),
        &admin.label(),
        ContainmentSource::Operator,
    )
    .await?;
    Ok(Json(out))
}

async fn admin_lift(
    State(st): State<AppState>,
    admin: AdminCaller,
    JsonBody(body): JsonBody<wire::LiftBody>,
) -> ApiResult<Json<wire::Lifted>> {
    let lifted = lift(&st, &body, &admin.label()).await?;
    Ok(Json(wire::Lifted { lifted }))
}

async fn agent_list(
    State(st): State<AppState>,
    caller: AgentCaller,
) -> ApiResult<Json<Vec<wire::ContainmentEntry>>> {
    allowed(&st, &caller)?;
    Ok(Json(list(&st).await?))
}

/// The body is read only once the caller is known to be allowed.
async fn agent_contain(
    State(st): State<AppState>,
    caller: AgentCaller,
    bytes: Bytes,
) -> ApiResult<Json<wire::ContainResult>> {
    allowed(&st, &caller)?;
    let body: wire::ContainBody =
        parse_body(&bytes).map_err(|e| ApiError::unprocessable(e.to_string()))?;
    let r#match = Value::Object(body.matches.into_map());
    if !st.policy.containment().allow_all && holds_everyone(&st, &r#match).await? {
        return Err(ApiError::forbidden(
            "containing every agent at once is the operator's",
        ));
    }
    let out = contain(
        &st,
        r#match,
        body.reason.as_str(),
        body.evidence.as_str(),
        &caller.agent().name,
        ContainmentSource::Agent,
    )
    .await?;
    Ok(Json(out))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/containment", get(admin_list).post(admin_contain))
        .route("/admin/containment/lift", post(admin_lift))
        .route("/v1/containment", get(agent_list).post(agent_contain))
}
