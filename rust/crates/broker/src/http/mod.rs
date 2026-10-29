//! The HTTP surface: [`router`] merges every part's `routes()` and wraps
//! them in the transport rules (http-api §6).
//!
//! - A body limit on every request (the Python had none, §8.8).
//! - A request timeout longer than the longest long-poll (300 s).
//! - Security headers on every response (`nosniff`, no framing, no
//!   referrer, no caching).
//! - No CORS, no OpenAPI or docs routes; unknown routes answer 404
//!   `{"detail": "Not Found"}`, wrong methods 405.
//! - Every handler takes an authenticated principal, except the routes
//!   listed (with the reason) in `tests/route_auth.rs`, which fails for any
//!   other route that answers without credentials.

pub mod admin;
pub mod admin_log;
pub mod agent;
pub mod audit;
pub mod body;
pub mod catalog;
pub mod serialize;

use std::collections::HashMap;
use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::state::AppState;

/// The largest request body accepted (a 1 MiB wiki page with its JSON
/// escaping fits).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Longer than any long-poll (300 s) with room to answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(330);

/// Query-string parameters (the last value of a repeated key wins).
#[must_use]
pub fn query_params(uri: &Uri) -> HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

/// The routes that take no credentials.
pub mod public {
    use axum::Json;
    use serde_json::{Value, json};

    /// `GET /healthz`.
    pub async fn healthz() -> Json<Value> {
        Json(json!({"ok": true}))
    }
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"detail": "Not Found"}))).into_response()
}

/// The spine's own routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(public::healthz))
        .merge(agent::routes())
        .merge(admin::routes())
        .merge(admin_log::routes())
        .merge(audit::routes())
        .merge(crate::containment::routes())
}

/// Every part's routes, with the transport middleware. One `merge` line
/// per part as parts land.
pub fn router(state: AppState) -> Router {
    // Every part's routes at the root (the panel's allowlist reads the
    // full path).
    let all = Router::new()
        .merge(routes())
        .merge(crate::a2a::routes())
        .merge(crate::webui::routes())
        .merge(crate::provisioners::tokens::routes())
        .merge(crate::wiki::routes::routes())
        .merge(crate::daemons::routes())
        .merge(crate::hostexec::routes())
        .merge(crate::attention::routes())
        .merge(crate::mail::routes::routes())
        .merge(crate::models::routes::routes());
    // The remote MCP's tools call the agent API in process.
    if let Some(mcp) = &state.web.remote_mcp {
        mcp.set_agent_api(
            all.clone().with_state(state.clone()),
            state.shutdown.clone(),
        );
    }
    let headers = [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("content-security-policy"),
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ];
    let mut app = all
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state);
    for (name, value) in headers {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ));
    }
    app.layer(TimeoutLayer::with_status_code(
        StatusCode::SERVICE_UNAVAILABLE,
        REQUEST_TIMEOUT,
    ))
    .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
}

async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({"detail": "Method Not Allowed"})),
    )
        .into_response()
}
