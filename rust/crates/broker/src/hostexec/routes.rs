//! `/v1/hostexec/*` (agents) and the admin's host routes: arming, the kill
//! switch, unlocking (spec §10.5, §10.7).

use std::collections::HashMap;
use std::sync::Arc;

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::{Authority, GrantId, JobId, Platform, Tier};
use agent_auth_wire::admin::{
    ArmBody, HostsOut, LockdownBody, LockdownFlag, LockdownResult, UnlockBody, UnlockResult,
};
use agent_auth_wire::hostexec::{JobOut, ShellClosed, ShellExecBody};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::routing::{get, post};
use serde_json::{Map, Value};

use super::lockdown::{lockdown, unlock};
use super::{HostExec, ShellExecError, job_out};
use crate::auth::{AdminCaller, AgentCaller, HumanDecider};
use crate::error::{ApiError, ApiResult};
use crate::events::clamp_wait;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/hostexec/jobs/{job_id}", get(get_job))
        .route("/v1/hostexec/shells/{grant_id}/exec", post(shell_exec))
        .route("/v1/hostexec/shells/{grant_id}/close", post(shell_close))
        .route("/admin/hosts", get(hosts))
        .route("/admin/hosts/{name}/arm", post(arm))
        .route("/admin/hosts/{name}/disarm", post(disarm))
        .route("/admin/lockdown", post(lockdown_route))
        .route("/admin/unlock", post(unlock_route))
}

/// Agents: 501 when hostexec is off.
fn agent_side(st: &AppState) -> ApiResult<Arc<HostExec>> {
    st.hostd
        .as_ref()
        .and_then(|p| p.hostexec.clone())
        .ok_or_else(|| {
            ApiError::new(
                axum::http::StatusCode::NOT_IMPLEMENTED,
                "hostexec is not enabled on this broker",
            )
        })
}

/// The admin: 503 when the channel is disabled.
fn admin_side(st: &AppState) -> ApiResult<Arc<HostExec>> {
    st.hostd
        .as_ref()
        .and_then(|p| p.hostexec.clone())
        .ok_or_else(|| ApiError::unavailable("the daemon channel is disabled (BROKER_SIGNING_KEY)"))
}

fn body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    agent_auth_wire::parse_body(bytes).map_err(|e| ApiError::unprocessable(e.message()))
}

fn query(raw: Option<&str>) -> HashMap<String, String> {
    url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

fn wait_param(q: &HashMap<String, String>) -> ApiResult<std::time::Duration> {
    let secs = match q.get("wait") {
        None => 0.0,
        Some(v) => v
            .trim()
            .parse::<f64>()
            .map_err(|_| ApiError::unprocessable("wait must be a number"))?,
    };
    Ok(clamp_wait(secs, 0.0, 300.0))
}

async fn get_job(
    caller: AgentCaller,
    State(st): State<AppState>,
    Path(job_id): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<JobOut>> {
    let hostexec = agent_side(&st)?;
    let wait = wait_param(&query(raw.as_deref()))?;
    let unknown = || ApiError::not_found("unknown job");
    let id: JobId = job_id.parse().map_err(|_| unknown())?;
    let job = hostexec
        .get_job(caller.id(), id, wait)
        .await?
        .ok_or_else(unknown)?;
    Ok(Json(job_out(&job, true)))
}

async fn shell_exec(
    caller: AgentCaller,
    State(st): State<AppState>,
    Path(grant_id): Path<String>,
    bytes: Bytes,
) -> ApiResult<Json<JobOut>> {
    let hostexec = agent_side(&st)?;
    let body: ShellExecBody = body(&bytes)?;
    let grant: GrantId = grant_id
        .parse()
        .map_err(|_| ApiError::not_found("unknown shell"))?;
    let job = hostexec
        .shell_exec(caller.id(), grant, &body)
        .await
        .map_err(|e| match e {
            ShellExecError::NotFound => ApiError::not_found("unknown shell"),
            ShellExecError::Spec(m) => ApiError::bad_request(m),
            ShellExecError::Refused(m) => ApiError::conflict(m),
            ShellExecError::Internal(m) => ApiError::internal(&m),
        })?;
    let wait = clamp_wait(body.wait, 0.0, 300.0);
    let job = hostexec
        .get_job(caller.id(), job.id, wait)
        .await?
        .unwrap_or(job);
    Ok(Json(job_out(&job, true)))
}

async fn shell_close(
    caller: AgentCaller,
    State(st): State<AppState>,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<ShellClosed>> {
    agent_side(&st)?;
    let unknown = || ApiError::not_found("unknown shell");
    let id: GrantId = grant_id.parse().map_err(|_| unknown())?;
    let grant = {
        let tx = st.store.begin().await?;
        let g = agent_auth_store::grants::get_owned(&tx, caller.id(), id).await?;
        tx.commit().await?;
        g
    };
    let is_shell = grant.as_ref().is_some_and(|g| {
        g.platform == Platform::Hostexec
            && matches!(
                g.authority,
                Authority::Hostexec(HostexecAuthority::Shell { .. })
            )
    });
    if !is_shell {
        return Err(unknown());
    }
    // Already ended is fine.
    let _ = crate::service::revoke_grant(&st, id, "closed by the agent", "").await;
    Ok(Json(ShellClosed { closed: true }))
}

async fn hosts(_admin: AdminCaller, State(st): State<AppState>) -> ApiResult<Json<HostsOut>> {
    let hostexec = admin_side(&st)?;
    let flag = hostexec.lockdown_state().await?;
    let lockdown: LockdownFlag = serde_json::from_value(flag).unwrap_or_default();
    Ok(Json(HostsOut {
        lockdown,
        hosts: hostexec.hosts().await?,
    }))
}

async fn arm(
    _admin: AdminCaller,
    State(st): State<AppState>,
    Path(name): Path<String>,
    bytes: Bytes,
) -> ApiResult<Json<Map<String, Value>>> {
    let hostexec = admin_side(&st)?;
    let body: ArmBody = body(&bytes)?;
    hostexec
        .arm(
            &name,
            Tier::from(body.tier),
            &body.duration,
            body.totp.expose(),
        )
        .await
        .map(Json)
        .map_err(|e| ApiError::conflict(e.0))
}

async fn disarm(
    _admin: AdminCaller,
    State(st): State<AppState>,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Map<String, Value>>> {
    let hostexec = admin_side(&st)?;
    let q = query(raw.as_deref());
    let tier = match q.get("tier").map(String::as_str) {
        None | Some("") => None,
        Some(t) => Some(
            Tier::parse(t)
                .ok_or_else(|| ApiError::unprocessable("tier must be \"user\" or \"root\""))?,
        ),
    };
    hostexec
        .disarm(&name, tier)
        .await
        .map(Json)
        .map_err(|e| ApiError::conflict(e.0))
}

async fn lockdown_route(
    admin: AdminCaller,
    State(st): State<AppState>,
    bytes: Bytes,
) -> ApiResult<Json<LockdownResult>> {
    let hostexec = admin_side(&st)?;
    let body: LockdownBody = body(&bytes)?;
    let by = HumanDecider::from(&admin);
    lockdown(
        &st,
        &hostexec,
        body.scope,
        body.host.as_ref().map(|h| h.as_str()),
        body.kill_vm,
        by.label(),
    )
    .await
    .map(Json)
    .map_err(|e| ApiError::unprocessable(e.0))
}

async fn unlock_route(
    admin: AdminCaller,
    State(st): State<AppState>,
    bytes: Bytes,
) -> ApiResult<Json<UnlockResult>> {
    let hostexec = admin_side(&st)?;
    let body: UnlockBody = body(&bytes)?;
    let by = HumanDecider::from(&admin);
    unlock(
        &st,
        &hostexec,
        body.host.as_ref().map(|h| h.as_str()),
        body.totp.as_ref().map(|t| t.expose()),
        by.label(),
    )
    .await
    .map(Json)
    .map_err(|e| ApiError::conflict(e.0))
}
