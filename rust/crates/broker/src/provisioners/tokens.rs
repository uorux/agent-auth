//! The broker as a token issuer (provisioners spec §6.4): its public keys,
//! and a check a reverse proxy calls per request (Traefik forwardAuth,
//! nginx auth_request). Unauthenticated on purpose: the keys are public,
//! and verify answers only yes or no about a token the caller holds.

use std::collections::HashMap;
use std::str::FromStr;

use agent_auth_core::{GrantId, Platform};
use agent_auth_store::{agents, grants};
use agent_auth_wire::oauth::AuthorizationServerMetadata;
use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::Value;

use super::mcp::audience;
use crate::error::ApiError;
use crate::state::AppState;

/// `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`,
/// `GET /v1/tokens/verify`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/v1/tokens/verify", get(verify))
}

fn not_found() -> ApiError {
    ApiError::not_found("Not Found")
}

async fn jwks(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let tokens = state
        .platform_services
        .tokens
        .as_ref()
        .ok_or_else(not_found)?;
    Ok(Json(tokens.jwks()))
}

async fn discovery(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let mut found = state
        .platform_services
        .tokens
        .as_ref()
        .map(|t| t.discovery());
    if let Some(oauth) = &state.web.oauth {
        // Clients that look for the authorization server here (RFC 8414's
        // fallback) find it too, when it is the same issuer.
        let base = oauth.base().trim_end_matches('/');
        let same = found.as_ref().is_none_or(|f| {
            f.get("issuer")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_end_matches('/')
                == base
        });
        if same {
            let mut merged = match found.take() {
                Some(Value::Object(m)) => m,
                _ => serde_json::Map::new(),
            };
            if let Ok(Value::Object(meta)) =
                serde_json::to_value(AuthorizationServerMetadata::for_base(oauth.base()))
            {
                merged.extend(meta);
            }
            found = Some(Value::Object(merged));
        }
    }
    found.map(Json).ok_or_else(not_found)
}

fn no(why: &str) -> Response {
    let mut r = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "Bearer error=\"invalid_token\", error_description=\"{why}\""
    )) {
        r.headers_mut().insert(WWW_AUTHENTICATE, v);
    }
    r
}

/// 200 if the bearer token is one of the broker's for that server and its
/// grant can still be issued for (INV-P2; also: the agent is not held and
/// a delegation thread is open, B20). On 200, `X-Agent-Auth-Agent` and
/// `X-Agent-Auth-Tools` say who and for which tools.
async fn verify(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tokens = state
        .platform_services
        .tokens
        .as_ref()
        .ok_or_else(not_found)?;
    let Some(server) = q.get("server") else {
        return Err(ApiError::unprocessable(
            "query parameter 'server' is required",
        ));
    };
    let entry = state.policy.platforms().mcp.servers.get(server.as_str());
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (scheme, token) = auth.split_once(' ').unwrap_or((auth, ""));
    let token = token.trim();
    let Some(entry) = entry.filter(|_| scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
    else {
        return Ok(no("a bearer token for a known server is required"));
    };
    let now = state.now();
    #[allow(clippy::as_conversions)] // seconds since 1970 as f64: exact for any real time
    let now_f = now.unix_timestamp() as f64 + f64::from(now.microsecond()) / 1e6;
    let Ok(claims) = tokens.verify(token, audience(entry), now_f) else {
        return Ok(no("not a valid token for this server"));
    };
    if claims.get("server").and_then(Value::as_str) != Some(server.as_str()) {
        return Ok(no("not a valid token for this server"));
    }
    let ended = || Ok(no("the grant behind this token has ended"));
    let Some(grant_id) = claims
        .get("grant")
        .and_then(Value::as_str)
        .and_then(|g| GrantId::from_str(g).ok())
    else {
        return ended();
    };
    let tx = state.store.begin().await?;
    let Some(grant) = grants::get(&tx, grant_id).await? else {
        return ended();
    };
    // The credential route's own check: active, unexpired, agent not held
    // or disabled, delegation thread open.
    let issuable = grants::issuable(&tx, grant.agent_id, grant.id, now).await?;
    let live = matches!(&issuable, Ok(g) if g.grant().platform == Platform::Mcp && g.grant().resource == *server);
    drop(issuable);
    let agent = agents::get(&tx, grant.agent_id).await?;
    tx.rollback().await?;
    let Some(agent) = agent.filter(|a| live && !a.disabled) else {
        return ended();
    };
    let tools: Vec<&str> = claims
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let (Ok(name), Ok(tools)) = (
        HeaderValue::from_str(&agent.name),
        HeaderValue::from_str(&tools.join(",")),
    ) else {
        return ended();
    };
    let mut r = StatusCode::OK.into_response();
    r.headers_mut().insert("x-agent-auth-agent", name);
    r.headers_mut().insert("x-agent-auth-tools", tools);
    Ok(r)
}
