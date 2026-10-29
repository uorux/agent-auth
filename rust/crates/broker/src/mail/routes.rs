//! The mail gateway's endpoints (upstream `api/mail_routes.py`). Agents
//! read and send under their "mail" grants; the operator releases or
//! discards what was held. Asking for access is an ordinary request
//! (`POST /v1/requests`, platform "mail").

use std::sync::Arc;

use agent_auth_core::{GrantId, MailItemId, Platform};
use agent_auth_store::grants::{self, GrantRow, NotIssuable};
use agent_auth_wire::error::parse_body;
use agent_auth_wire::mail::{
    DecideBody, MailAttachment, MailItem, MailList, MailMessage, SendBody, SendOut,
};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use super::{Mail, MailError};
use crate::auth::{AdminCaller, AgentCaller};
use crate::error::{ApiError, ApiResult};
use crate::http::body::{JsonBody, body_error};
use crate::state::AppState;

impl From<MailError> for ApiError {
    fn from(e: MailError) -> ApiError {
        ApiError::new(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            e.detail,
        )
    }
}

fn gateway(st: &AppState) -> ApiResult<Arc<Mail>> {
    st.mail.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "mail is not enabled on this broker",
        )
    })
}

/// `require_web_tool` then `usable_grant`: a web UI's connector gets what
/// `remote_mcp.tools` gives it; the grant is the caller's own mail grant,
/// its agent not held, its delegation thread open.
async fn grant(st: &AppState, caller: &AgentCaller, id: &str, tool: &str) -> ApiResult<GrantRow> {
    if caller.agent().runtime.as_deref() == Some(agent_auth_core::policy::WEB_RUNTIME)
        && !st.policy.remote_mcp().tools.iter().any(|t| t == tool)
    {
        return Err(ApiError::forbidden(format!(
            "not available to a web UI connector ({tool} is not in remote_mcp.tools)"
        )));
    }
    let unknown = || ApiError::not_found("unknown grant");
    let grant_id: GrantId = id.parse().map_err(|_| unknown())?;
    let now = st.now();
    let tx = st.store.begin().await?;
    match grants::get(&tx, grant_id).await? {
        Some(g) if g.agent_id == caller.id() && g.platform == Platform::Mail => {}
        _ => return Err(unknown()),
    }
    let row = match grants::issuable(&tx, caller.id(), grant_id, now).await? {
        Ok(g) => g.grant().clone(),
        Err(refusal) => {
            if let NotIssuable::Held(held) = &refusal {
                let containment = match held {
                    agent_auth_store::lockdown::Held::Contained(e) => e.id.clone(),
                    other => other.text(),
                };
                let g = grant_id.to_string();
                st.security_log.record(
                    "credential_refused",
                    now,
                    &[
                        ("agent", Some(&caller.agent().name)),
                        ("grant", Some(&g)),
                        ("containment", Some(&containment)),
                    ],
                );
            }
            return Err(if refusal.is_not_found() {
                unknown()
            } else {
                ApiError::forbidden(refusal.detail())
            });
        }
    };
    tx.commit().await?;
    Ok(row)
}

async fn list(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(grant_id): Path<String>,
    uri: Uri,
) -> ApiResult<Json<MailList>> {
    let gw = gateway(&st)?;
    let q = crate::http::query_params(&uri);
    let limit = match q.get("limit") {
        None => 20,
        Some(l) => l
            .trim()
            .parse::<i64>()
            .map_err(|_| ApiError::unprocessable("query parameter 'limit' must be an integer"))?,
    };
    let g = grant(&st, &caller, &grant_id, "mail_list").await?;
    let page = q.get("page").map(String::as_str).filter(|p| !p.is_empty());
    let search = q
        .get("search")
        .map(|s| s.chars().take(500).collect::<String>())
        .filter(|s| !s.is_empty());
    Ok(Json(
        gw.list(&g, limit, page, search.as_deref(), st.now())
            .await?,
    ))
}

async fn read(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path((grant_id, item)): Path<(String, String)>,
) -> ApiResult<Json<MailMessage>> {
    let gw = gateway(&st)?;
    let g = grant(&st, &caller, &grant_id, "mail_read").await?;
    Ok(Json(gw.read(&g, &item, st.now()).await?))
}

async fn attachment(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path((grant_id, item, index)): Path<(String, String, String)>,
) -> ApiResult<Json<MailAttachment>> {
    let gw = gateway(&st)?;
    let index: usize = index
        .parse()
        .map_err(|_| ApiError::unprocessable("path parameter 'index' must be an integer"))?;
    let g = grant(&st, &caller, &grant_id, "mail_attachment").await?;
    Ok(Json(gw.attachment(&g, &item, index, st.now()).await?))
}

async fn send(
    State(st): State<AppState>,
    caller: AgentCaller,
    Path(grant_id): Path<String>,
    JsonBody(body): JsonBody<SendBody>,
) -> ApiResult<Json<SendOut>> {
    let gw = gateway(&st)?;
    let g = grant(&st, &caller, &grant_id, "mail_send").await?;
    let to = body.to.map(|t| {
        t.into_vec()
            .into_iter()
            .map(|a| a.as_str().to_owned())
            .collect()
    });
    let out = gw
        .send(
            &g,
            to,
            body.subject.map(|s| s.as_str().to_owned()),
            body.body.as_str(),
            body.reply_to.as_ref().map(|r| r.as_str()),
            st.now(),
        )
        .await?;
    Ok(Json(out))
}

async fn held(State(st): State<AppState>, _admin: AdminCaller) -> ApiResult<Json<Vec<MailItem>>> {
    Ok(Json(gateway(&st)?.held().await?))
}

fn item_id(id: &str) -> ApiResult<MailItemId> {
    id.parse()
        .map_err(|_| ApiError::not_found("unknown mail item"))
}

async fn item(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<MailItem>> {
    let gw = gateway(&st)?;
    Ok(Json(gw.show(item_id(&id)?).await?))
}

/// An optional body: none (or `null`) is the default.
fn decide_body(bytes: &Bytes) -> Result<DecideBody, agent_auth_wire::BodyError> {
    if bytes.iter().all(u8::is_ascii_whitespace) || bytes.as_ref() == b"null" {
        return Ok(DecideBody::default());
    }
    parse_body(bytes)
}

async fn decide(st: AppState, id: String, bytes: Bytes, release: bool) -> Response {
    let gw = match gateway(&st) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let body = match decide_body(&bytes) {
        Ok(b) => b,
        Err(e) => return body_error(&e),
    };
    let id = match item_id(&id) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let out = if release {
        gw.release(id, body.by.as_str()).await
    } else {
        gw.discard(id, body.by.as_str()).await
    };
    match out {
        Ok(item) => Json(item).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn release(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    bytes: Bytes,
) -> Response {
    decide(st, id, bytes, true).await
}

async fn discard(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    bytes: Bytes,
) -> Response {
    decide(st, id, bytes, false).await
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/mail/{grant_id}/messages", get(list))
        .route("/v1/mail/{grant_id}/messages/{item}", get(read))
        .route(
            "/v1/mail/{grant_id}/messages/{item}/attachments/{index}",
            get(attachment),
        )
        .route("/v1/mail/{grant_id}/send", post(send))
        .route("/admin/mail/held", get(held))
        .route("/admin/mail/items/{id}", get(item))
        .route("/admin/mail/items/{id}/release", post(release))
        .route("/admin/mail/items/{id}/discard", post(discard))
}
