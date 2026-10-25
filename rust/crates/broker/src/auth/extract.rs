//! The extractors: the only code that turns an HTTP request into a
//! principal (rust/spec/http-api.md §3).

use std::net::SocketAddr;

use agent_auth_core::SessionId;
use agent_auth_core::containment::AgentKind;
use agent_auth_crypto::Secret;
use agent_auth_crypto::api_key;
use agent_auth_store::{Tx, agents, oauth, sessions};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use time::{Duration, OffsetDateTime};

use super::{AdminCaller, AdminIdentity, AgentCaller, AgentCredentialKind};
use crate::error::ApiError;
use crate::state::AppState;

/// Liveness bookkeeping: skip the write when last_seen is this fresh.
const TOUCH_INTERVAL: Duration = Duration::seconds(20);

/// A web UI connector's OAuth access token (core/oauth.py ACCESS_PREFIX).
pub const OAUTH_ACCESS_PREFIX: &str = "aat_";

/// How callers authenticate: the admin token, and whether OAuth access
/// tokens are accepted (the remote MCP is enabled).
#[derive(Debug, Default)]
pub struct AuthConfig {
    /// `ADMIN_TOKEN`; none: the admin API answers 503.
    pub admin_token: Option<Secret<String>>,
    /// Accept `aat_` tokens as agent credentials.
    pub oauth_enabled: bool,
}

/// The bearer token, if the request carries `Authorization: Bearer <t>`
/// (scheme case-insensitive). Anything else, including a header that is
/// not visible ASCII, is treated as no token.
#[must_use]
pub fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Who called, as the reverse proxy saw them (`X-Real-IP`), else the peer.
#[must_use]
pub fn client_address(parts: &Parts) -> Option<String> {
    if let Some(ip) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return Some(ip.chars().take(64).collect());
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}

fn record(
    state: &AppState,
    parts: &Parts,
    kind: &str,
    now: OffsetDateTime,
    fields: &[(&str, Option<&str>)],
) {
    let client = client_address(parts);
    let mut all: Vec<(&str, Option<&str>)> = vec![
        ("client", client.as_deref()),
        ("path", Some(parts.uri.path())),
    ];
    all.extend_from_slice(fields);
    state.security_log.record(kind, now, &all);
}

fn sha256_hex(text: &str) -> String {
    api_key::hash_secret(text).as_str().to_owned()
}

impl FromRequestParts<AppState> for AgentCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Some(token) = bearer_token(parts) else {
            return Err(ApiError::unauthorized("missing bearer token"));
        };
        let now = state.now();
        let tx = state.store.begin().await?;

        let (agent, via) = if state.auth.oauth_enabled && token.starts_with(OAUTH_ACCESS_PREFIX) {
            let id = oauth::agent_for_access(&tx, &sha256_hex(token), now).await?;
            let agent = match id {
                Some(id) => agents::get(&tx, id).await?,
                None => None,
            };
            match agent {
                Some(a) if !a.disabled => (a, AgentCredentialKind::OAuthConnector),
                other => {
                    let name = other.as_ref().map(|a| a.name.clone());
                    record(
                        state,
                        parts,
                        "bad_key",
                        now,
                        &[("agent", name.as_deref()), ("reason", Some("oauth token"))],
                    );
                    return Err(ApiError::unauthorized("invalid or expired access token"));
                }
            }
        } else {
            let Some(parsed) = api_key::parse(token) else {
                record(
                    state,
                    parts,
                    "bad_key",
                    now,
                    &[("reason", Some("malformed"))],
                );
                return Err(ApiError::unauthorized("malformed API key"));
            };
            let found = agents::by_key_id(&tx, parsed.key_id.as_str()).await?;
            let refusal = match &found {
                None => Some("unknown key"),
                Some(a) if a.disabled => Some("disabled"),
                // The operator's row speaks only through the admin panel.
                Some(a) if a.kind == AgentKind::Operator => Some("operator"),
                Some(a) => match api_key::SecretHash::parse(&a.api_key_hash) {
                    Some(stored) if api_key::verify(&parsed.secret, &stored) => None,
                    _ => Some("wrong secret"),
                },
            };
            match (found, refusal) {
                (Some(a), None) => (a, AgentCredentialKind::ApiKey),
                (found, Some(reason)) => {
                    let name = found.as_ref().map(|a| a.name.clone());
                    record(
                        state,
                        parts,
                        "bad_key",
                        now,
                        &[
                            ("key_id", Some(parsed.key_id.as_str())),
                            ("agent", name.as_deref()),
                            ("reason", Some(reason)),
                        ],
                    );
                    return Err(ApiError::unauthorized("invalid API key"));
                }
                (None, None) => return Err(ApiError::unauthorized("invalid API key")),
            }
        };

        let session = with_session(&tx, parts, &agent, now).await?;
        agents::touch_seen(&tx, agent.id, now, now.saturating_sub(TOUCH_INTERVAL)).await?;
        tx.commit().await?;
        Ok(AgentCaller::new(agent, session, via))
    }
}

async fn with_session(
    tx: &Tx<'_>,
    parts: &Parts,
    agent: &agents::AgentRow,
    now: OffsetDateTime,
) -> Result<Option<sessions::SessionRow>, ApiError> {
    let Some(header) = parts.headers.get("x-agent-session") else {
        return Ok(None);
    };
    // 401 (not 404): the auth context is stale — mint a new session.
    let stale = || ApiError::unauthorized("unknown or closed session");
    let id: SessionId = header
        .to_str()
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(stale)?;
    let session = sessions::get_open(tx, agent.id, id)
        .await?
        .ok_or_else(stale)?;
    sessions::touch(tx, id, now, now.saturating_sub(TOUCH_INTERVAL)).await?;
    Ok(Some(session))
}

impl FromRequestParts<AppState> for AdminCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        // The admin panel's signed-in session (cookie + CSRF on writes) is
        // checked here first when the panel is enabled: added with the
        // panel (broker::webui).
        let Some(expected) = &state.auth.admin_token else {
            return Err(ApiError::unavailable(
                "admin API disabled: ADMIN_TOKEN not configured",
            ));
        };
        let presented = bearer_token(parts);
        let ok = presented
            .is_some_and(|t| agent_auth_crypto::ct_eq(t.as_bytes(), expected.expose().as_bytes()));
        if !ok {
            if presented.is_some() || parts.headers.contains_key(AUTHORIZATION) {
                record(state, parts, "bad_admin_token", state.now(), &[]);
            }
            return Err(ApiError::unauthorized("invalid admin token"));
        }
        Ok(AdminCaller::new(AdminIdentity::Token))
    }
}
