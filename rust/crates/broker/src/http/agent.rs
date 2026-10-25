//! The agent API core (http-api §2.1): `/v1/me`, `/v1/catalog`,
//! `/v1/requests*`, `/v1/grants*`.

use std::time::Duration;

use agent_auth_core::{GrantId, RequestId};
use agent_auth_store::grants::{self, NotIssuable};
use agent_auth_store::requests;
use agent_auth_wire::agent::{
    CredentialKind, CredentialOut, GrantOut, Me, ReleaseOut, RequestCreate, RequestOut, RetryBody,
    SessionRef,
};
use agent_auth_wire::query::GrantFilter;
use agent_auth_wire::secret::WireSecret;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;

use super::body::JsonBody;
use super::catalog::catalog;
use super::query_params;
use super::serialize::{grant_out, request_out, wire_kind, wire_placement};
use crate::auth::{AgentCaller, AgentCredentialKind};
use crate::error::{ApiError, ApiResult};
use crate::events::clamp_wait;
use crate::provisioners::{ProvisionError, Provisioner, not_enabled};
use crate::service;
use crate::state::AppState;

/// The longest a decision long-poll sleeps before re-reading the row. Every
/// change to a request notifies `request_events`, so this is only the
/// fallback against a lost wake-up.
const RECHECK: Duration = Duration::from_secs(10);

fn unknown_request() -> ApiError {
    ApiError::not_found("unknown request")
}

async fn me(caller: AgentCaller) -> Json<Me> {
    let a = caller.agent();
    Json(Me {
        id: a.id,
        name: a.name.clone(),
        description: a.description.clone(),
        kind: wire_kind(a.kind),
        webhook_url: a.webhook_url.clone(),
        lldap_username: a.lldap_username.clone(),
        runtime: a.runtime.clone(),
        project: a.project.clone(),
        host: a.host.clone(),
        placement: wire_placement(a.placement),
        session: caller.session().map(|s| SessionRef {
            id: s.id,
            name: s.name.clone(),
        }),
    })
}

async fn get_catalog(State(st): State<AppState>, caller: AgentCaller) -> ApiResult<Json<Value>> {
    Ok(Json(catalog(&st, caller.agent()).await?))
}

async fn out(st: &AppState, row: &agent_auth_store::requests::RequestRow) -> ApiResult<RequestOut> {
    let tx = st.store.begin().await?;
    Ok(request_out(&tx, row).await?)
}

async fn create(
    State(st): State<AppState>,
    caller: AgentCaller,
    JsonBody(body): JsonBody<RequestCreate>,
) -> ApiResult<Json<RequestOut>> {
    if !st
        .spine
        .limits
        .take_request(caller.id(), std::time::Instant::now())
    {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            format!(
                "at most {} access requests an hour; wait before asking again",
                st.spine.limits.requests_per_hour
            ),
        ));
    }
    let row = service::create(&st, &caller, body).await?;
    Ok(Json(out(&st, &row).await?))
}

fn parse_request_id(id: &str) -> ApiResult<RequestId> {
    id.parse().map_err(|_| unknown_request())
}

async fn get_request(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<RequestOut>> {
    let id = parse_request_id(&id)?;
    let tx = st.store.begin().await?;
    let row = requests::get_owned(&tx, caller.id(), id)
        .await?
        .ok_or_else(unknown_request)?
        .into_row();
    Ok(Json(request_out(&tx, &row).await?))
}

/// `GET /v1/requests/{id}/wait?timeout=60`: until the request leaves the
/// waiting states, at most `timeout` (clamped to 1..300 s, NaN = 1).
async fn wait(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    uri: Uri,
) -> ApiResult<Json<RequestOut>> {
    let id = parse_request_id(&id)?;
    let Some(_slot) = crate::limits::wait_slot(&st.spine, caller.id()) else {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            format!(
                "at most {} decision waits at once per agent; let one finish first",
                st.spine.limits.max_waits
            ),
        ));
    };
    let params = query_params(&uri);
    let secs = match params.get("timeout") {
        None => 60.0,
        Some(t) => t
            .trim()
            .parse::<f64>()
            .map_err(|_| ApiError::unprocessable("timeout: a number"))?,
    };
    let timeout = clamp_wait(secs, 1.0, 300.0);
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    // Subscribe first: a change between the read and the sleep still wakes.
    let mut listener = st.request_events.listen(&id);
    loop {
        let tx = st.store.begin().await?;
        let row = requests::get_owned(&tx, caller.id(), id)
            .await?
            .ok_or_else(unknown_request)?
            .into_row();
        let now = tokio::time::Instant::now();
        if !row.status.is_waiting() || now >= deadline {
            return Ok(Json(request_out(&tx, &row).await?));
        }
        drop(tx);
        listener
            .wait(deadline.saturating_duration_since(now).min(RECHECK))
            .await;
    }
}

async fn retry(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<RetryBody>,
) -> ApiResult<Json<RequestOut>> {
    let id: RequestId = id
        .parse()
        .map_err(|_| ApiError::conflict("unknown request"))?;
    let row = service::retry(&st, &caller, id, body.justification.into_string()).await?;
    Ok(Json(out(&st, &row).await?))
}

async fn escalate(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<RequestOut>> {
    let id: RequestId = id
        .parse()
        .map_err(|_| ApiError::conflict("unknown request"))?;
    let row = service::escalate(&st, &caller, id).await?;
    Ok(Json(out(&st, &row).await?))
}

async fn list_grants(
    State(st): State<AppState>,
    caller: AgentCaller,
    uri: Uri,
) -> ApiResult<Json<Vec<GrantOut>>> {
    let params = query_params(&uri);
    let filter = match params.get("status") {
        None => GrantFilter::Active,
        Some(s) => GrantFilter::parse(s).map_err(|e| ApiError::bad_request(e.message()))?,
    };
    let tx = st.store.begin().await?;
    let rows = grants::of_agent(&tx, caller.id(), filter.status()).await?;
    let mut out = Vec::with_capacity(rows.len());
    for g in &rows {
        out.push(grant_out(&tx, caller.agent(), g).await?);
    }
    Ok(Json(out))
}

/// `GET /v1/grants/{id}/credential`. The store decides issuability (own
/// grant, active, unexpired, agent not held, delegation thread open:
/// INV-3, INV-6, INV-17); then the provisioner mints. A web UI connector's
/// token never gets a credential (it would land in a third party's chat:
/// human-and-agent-surfaces Bug-C1).
async fn credential(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<CredentialOut>> {
    let grant_id: GrantId = id
        .parse()
        .map_err(|_| ApiError::not_found("unknown grant"))?;
    if caller.via() == AgentCredentialKind::OAuthConnector
        || caller.agent().runtime.as_deref() == Some("web")
    {
        return Err(ApiError::forbidden(
            "credentials are not issued to a web UI connector",
        ));
    }
    let now = st.now();
    let tx = st.store.begin().await?;
    let issuable = match grants::issuable(&tx, caller.id(), grant_id, now).await? {
        Ok(g) => g,
        Err(refusal) => {
            if let NotIssuable::Held(held) = &refusal {
                let containment = match held {
                    agent_auth_store::lockdown::Held::Contained(e) => e.id.clone(),
                    other => other.text(),
                };
                let grant = grant_id.to_string();
                st.security_log.record(
                    "credential_refused",
                    now,
                    &[
                        ("agent", Some(&caller.agent().name)),
                        ("grant", Some(&grant)),
                        ("containment", Some(&containment)),
                    ],
                );
            }
            let detail = refusal.detail();
            return Err(if refusal.is_not_found() {
                ApiError::not_found(detail)
            } else {
                ApiError::forbidden(detail)
            });
        }
    };
    let platform = issuable.grant().platform;
    let provisioner = st
        .registry
        .get(platform)
        .ok_or_else(|| ApiError::forbidden(not_enabled(platform)))?;
    let cred = match provisioner.credential(&tx, &issuable, now).await {
        Ok(c) => c,
        Err(ProvisionError::NotImplemented) => {
            let detail = if platform == agent_auth_core::Platform::Google {
                "no google account is configured on this broker"
            } else {
                "not implemented"
            };
            return Err(ApiError::new(
                axum::http::StatusCode::NOT_IMPLEMENTED,
                detail,
            ));
        }
        Err(ProvisionError::Failed(m)) => return Err(ApiError::forbidden(m)),
    };
    drop(issuable);
    tx.commit().await?;
    let kind: CredentialKind = super::serialize::by_name(&cred.kind)
        .ok_or_else(|| ApiError::internal(&format!("unknown credential kind {:?}", cred.kind)))?;
    let value = match cred.value {
        Some(v) => Some(WireSecret::new(v.expose().clone()).map_err(|e| ApiError::internal(&e))?),
        None => None,
    };
    Ok(Json(CredentialOut {
        kind,
        value,
        username: cred.username,
        url: cred.url,
        expires_at: cred.expires_at,
        note: cred.note,
        properties: cred.properties,
    }))
}

/// `POST /v1/grants/{id}/release`: an agent ends one of its own grants
/// early (done with it: a pool item others are waiting for, a token).
/// Ending access is always allowed, contained or not; nothing comes back.
async fn release(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<ReleaseOut>> {
    let unknown = || ApiError::not_found("unknown grant");
    let grant_id: GrantId = id.parse().map_err(|_| unknown())?;
    {
        let tx = st.store.begin().await?;
        if grants::get_owned(&tx, caller.id(), grant_id)
            .await?
            .is_none()
        {
            return Err(unknown());
        }
    }
    match service::revoke_grant(&st, grant_id, "released by the agent", &caller.agent().name).await
    {
        Ok(_) => Ok(Json(ReleaseOut {
            released: true,
            status: None,
        })),
        Err(service::ServiceError::Transition(_)) => {
            let tx = st.store.begin().await?;
            let status = grants::get_owned(&tx, caller.id(), grant_id)
                .await?
                .map(|g| g.status);
            Ok(Json(ReleaseOut {
                released: false,
                status,
            }))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/me", get(me))
        .route("/v1/catalog", get(get_catalog))
        .route("/v1/requests", post(create))
        .route("/v1/requests/{id}", get(get_request))
        .route("/v1/requests/{id}/wait", get(wait))
        .route("/v1/requests/{id}/retry", post(retry))
        .route("/v1/requests/{id}/escalate", post(escalate))
        .route("/v1/grants", get(list_grants))
        .route("/v1/grants/{id}/credential", get(credential))
        .route("/v1/grants/{id}/release", post(release))
}
