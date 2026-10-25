//! `/v1/wiki` (a2a-wiki-desktop spec §7.3): any agent reads; who may write
//! a page is the service's decision, from the agent's record. A held agent
//! still reads but writes nothing (INV-14).

use std::collections::HashMap;
use std::sync::Arc;

use agent_auth_store::lockdown::{self, Held};
use agent_auth_wire::wiki::{
    PageDelete, PageWrite, WikiDeleted, WikiList, WikiPage, WikiSearch, WikiWritten,
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use super::Wiki;
use crate::auth::AgentCaller;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/wiki", get(list))
        .route("/v1/wiki/page", get(read).put(write))
        .route("/v1/wiki/search", get(search))
        .route("/v1/wiki/delete", post(delete))
}

fn wiki(state: &AppState) -> ApiResult<Arc<Wiki>> {
    state
        .platform_services
        .wiki
        .clone()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_IMPLEMENTED, "this broker has no wiki"))
}

/// A contained agent still reads, but writes nothing every other agent
/// would read.
async fn not_held(state: &AppState, caller: &AgentCaller) -> ApiResult<()> {
    let tx = state.store.begin().await?;
    let held = lockdown::check(&tx, caller.id(), state.now()).await?.err();
    tx.rollback().await?;
    match held {
        None => Ok(()),
        Some(Held::Contained(e)) => Err(ApiError::forbidden(format!(
            "contained ({}): no wiki writes while you are held",
            e.id
        ))),
        Some(h) => Err(ApiError::forbidden(format!(
            "{}: no wiki writes while you are held",
            h.text()
        ))),
    }
}

fn param<'a>(q: &'a HashMap<String, String>, name: &str) -> ApiResult<&'a str> {
    q.get(name)
        .map(String::as_str)
        .ok_or_else(|| ApiError::unprocessable(format!("query parameter '{name}' is required")))
}

async fn list(
    State(state): State<AppState>,
    caller: AgentCaller,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<WikiList>> {
    let prefix = q.get("prefix").map_or("", String::as_str);
    Ok(Json(
        wiki(&state)?
            .list(caller.agent(), prefix, state.now())
            .await?,
    ))
}

async fn read(
    State(state): State<AppState>,
    _caller: AgentCaller,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<WikiPage>> {
    let w = wiki(&state)?;
    Ok(Json(w.read(param(&q, "path")?, state.now()).await?))
}

async fn search(
    State(state): State<AppState>,
    _caller: AgentCaller,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<WikiSearch>> {
    let w = wiki(&state)?;
    let limit = match q.get("limit") {
        None => 8,
        Some(l) => l
            .trim()
            .parse::<i64>()
            .map_err(|_| ApiError::unprocessable("limit must be an integer"))?,
    };
    Ok(Json(w.search(param(&q, "q")?, limit, state.now()).await?))
}

async fn write(
    State(state): State<AppState>,
    caller: AgentCaller,
    Json(body): Json<PageWrite>,
) -> ApiResult<Json<WikiWritten>> {
    let w = wiki(&state)?;
    not_held(&state, &caller).await?;
    let out = w
        .write(
            caller.agent(),
            body.path.as_str(),
            body.content.as_str(),
            body.summary.as_str(),
            body.base_sha.as_ref().map(|s| s.as_str()),
            state.now(),
        )
        .await?;
    Ok(Json(out))
}

async fn delete(
    State(state): State<AppState>,
    caller: AgentCaller,
    Json(body): Json<PageDelete>,
) -> ApiResult<Json<WikiDeleted>> {
    let w = wiki(&state)?;
    not_held(&state, &caller).await?;
    let out = w
        .delete(
            caller.agent(),
            body.path.as_str(),
            body.summary.as_str(),
            body.base_sha.as_ref().map(|s| s.as_str()),
            state.now(),
        )
        .await?;
    Ok(Json(out))
}
