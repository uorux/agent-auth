//! The admin panel (surfaces spec §B): its page and assets, signing in and
//! out, and what a signed-in session may call of the admin API.
//!
//! A session is not the admin token: [`allowed`] lists the admin routes it
//! reaches (looking, and setting agents and hosts up). Deciding requests,
//! arming hosts, lockdown and unlock stay on Discord, the CLI and the
//! hosts' TOTP codes. Every write needs the session's CSRF token in
//! `X-CSRF-Token`.
//!
//! The panel is served only under its own name (`ui.base_url`'s host, or
//! loopback): a request a proxy forwarded for another name gets 404 here
//! and its session cookie is not looked at on the admin API.

use std::sync::Arc;

use agent_auth_crypto::{ct_eq, token_urlsafe};
use axum::Json;
use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

use super::cookies::{self, Kind, Sealer};
use super::oidc::{LoginAttempt, OidcClient, SignInError};
use super::{authority, escape_html};
use crate::error::ApiError;
use crate::state::AppState;

/// The session cookie.
pub const SESSION_COOKIE: &str = "__Host-aa_ui";
/// The sign-in-in-progress cookie.
pub const LOGIN_COOKIE: &str = "__Host-aa_ui_login";
/// How long a sign-in may take, seconds.
pub const LOGIN_TTL: i64 = 600;
/// The CSRF header the page sends on every write.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Nothing from anywhere else, no inline script or style, never in a frame.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const INDEX_HTML: &str = include_str!("assets/index.html");
const MESSAGE_HTML: &str = include_str!("assets/message.html");
const APP_JS: &str = include_str!("assets/app.js");
const APP_CSS: &str = include_str!("assets/app.css");

/// What a signed-in session may call: `(method, path)`, where `{}` is one
/// path segment (`[^/]+`) and the whole path must match.
pub const ALLOWED: [(&str, &str); 28] = [
    ("GET", "/admin/agents"),
    ("GET", "/admin/rules"),
    ("GET", "/admin/daemons"),
    ("GET", "/admin/hosts"),
    ("GET", "/admin/broker-key"),
    ("GET", "/admin/projects"),
    ("GET", "/admin/log/decisions"),
    ("GET", "/admin/log/commands"),
    ("GET", "/admin/log/commands/{}"),
    ("GET", "/admin/a2a/graph"),
    ("GET", "/admin/a2a/threads/{}"),
    ("GET", "/admin/models/usage"),
    ("GET", "/admin/connectors"),
    ("POST", "/admin/connectors/{}/revoke"),
    ("GET", "/admin/chat/peers"),
    ("GET", "/admin/chat/threads"),
    ("GET", "/admin/chat/threads/{}"),
    ("POST", "/admin/chat/threads"),
    ("POST", "/admin/chat/threads/{}/messages"),
    ("POST", "/admin/chat/threads/{}/close"),
    ("POST", "/admin/agents"),
    ("PATCH", "/admin/agents/{}/attributes"),
    ("POST", "/admin/agents/{}/rename"),
    ("POST", "/admin/agents/{}/rotate-key"),
    ("POST", "/admin/agents/{}/disable"),
    ("DELETE", "/admin/rules/{}"),
    ("POST", "/admin/daemons/pairing-codes"),
    ("DELETE", "/admin/daemons/{}"),
];

/// Whether a session may call `method path`.
#[must_use]
pub fn allowed(method: &str, path: &str) -> bool {
    ALLOWED.iter().any(|(m, pattern)| {
        *m == method && {
            let mut want = pattern.split('/');
            let mut have = path.split('/');
            loop {
                match (want.next(), have.next()) {
                    (None, None) => break true,
                    (Some("{}"), Some(seg)) if !seg.is_empty() => {}
                    (Some(w), Some(h)) if w == h => {}
                    _ => break false,
                }
            }
        }
    })
}

/// A signed-in session (sealed into [`SESSION_COOKIE`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    /// Unix seconds; the lifetime is absolute.
    pub exp: i64,
}

/// The admin panel.
#[derive(Debug)]
pub struct Panel {
    base: String,
    own: Option<String>,
    ttl: i64,
    sealer: Arc<Sealer>,
    sign_in: Arc<OidcClient>,
}

impl Panel {
    #[must_use]
    pub fn new(
        base_url: &str,
        ttl_secs: i64,
        sealer: Arc<Sealer>,
        sign_in: Arc<OidcClient>,
    ) -> Panel {
        let base = base_url.trim_end_matches('/').to_owned();
        Panel {
            own: authority(&base),
            base,
            ttl: ttl_secs,
            sealer,
            sign_in,
        }
    }

    /// Where the provider sends the browser back.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("{}/ui/callback", self.base)
    }

    /// Whether this request came for the panel's own address: `Host` and
    /// `X-Forwarded-Host` (first value) are each absent, the panel's own
    /// `host[:port]` (default ports ignored), or loopback.
    #[must_use]
    pub fn serves(&self, headers: &HeaderMap) -> bool {
        let default_port = if self.base.starts_with("http://") {
            "80"
        } else {
            "443"
        };
        ["host", "x-forwarded-host"].iter().all(|name| {
            let Some(raw) = headers.get(*name) else {
                return true;
            };
            let Ok(text) = raw.to_str() else {
                return false;
            };
            let value = text
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if value.is_empty() {
                return true;
            }
            // `host`, `host:port`, `[v6]`, `[v6]:port`.
            let split = if value.starts_with('[') {
                value.find(']').map(|i| i.saturating_add(1))
            } else {
                value.find(':')
            };
            let (host, port) = match split {
                Some(i) => value.split_at_checked(i).unwrap_or((value.as_str(), "")),
                None => (value.as_str(), ""),
            };
            if matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
                return true;
            }
            let normalized = match port.strip_prefix(':') {
                Some(p) if p == default_port => host,
                _ => value.as_str(),
            };
            self.own.as_deref() == Some(normalized)
        })
    }

    /// The signed-in session the request's cookie holds, if any.
    #[must_use]
    pub fn session(&self, headers: &HeaderMap, now: OffsetDateTime) -> Option<Session> {
        let cookie = cookies::get(headers, SESSION_COOKIE)?;
        self.open_session(cookie, now)
    }

    /// Opens a session cookie value: sealed by this broker, of the session
    /// kind, within its TTL, and before its `exp`.
    #[must_use]
    pub fn open_session(&self, cookie: &str, now: OffsetDateTime) -> Option<Session> {
        let session: Session = self.sealer.open(Kind::Session, cookie, self.ttl, now)?;
        (session.exp > now.unix_timestamp()).then_some(session)
    }

    /// A new session for `user` (sealed), as the callback sets it.
    #[must_use]
    pub fn seal_session(&self, user: &str, now: OffsetDateTime) -> Option<String> {
        let session = Session {
            user: user.to_owned(),
            csrf: token_urlsafe(24).ok()?,
            exp: now.unix_timestamp().saturating_add(self.ttl),
        };
        self.sealer.seal(Kind::Session, &session, now)
    }

    #[must_use]
    pub fn ttl(&self) -> i64 {
        self.ttl
    }
}

/// For the `AdminCaller` extractor (spec §B.6, step 1): when the panel is
/// on, no `Authorization` header was sent, the request is for the panel's
/// own address and its cookie holds a session, the session decides:
/// `Some(Ok(user))` if the route is on the allowed list and (for anything
/// but GET) the CSRF header matches; `Some(Err(403))` otherwise. `None`:
/// no session here, check the admin token.
pub(crate) fn admin_session(state: &AppState, parts: &Parts) -> Option<Result<String, ApiError>> {
    let panel = state.web.panel.as_ref()?;
    if parts
        .headers
        .contains_key(axum::http::header::AUTHORIZATION)
        || !panel.serves(&parts.headers)
    {
        return None;
    }
    let session = panel.session(&parts.headers, state.now())?;
    // The full path: the admin routes are merged at the root, not nested
    // (a nested router would see its own suffix here).
    let path = parts.uri.path();
    let method = parts.method.as_str();
    if !allowed(method, path) {
        return Some(Err(ApiError::forbidden(
            "not available from the admin panel",
        )));
    }
    if parts.method != Method::GET {
        let sent = parts
            .headers
            .get(CSRF_HEADER)
            .map_or(&[][..], HeaderValue::as_bytes);
        if !ct_eq(sent, session.csrf.as_bytes()) {
            return Some(Err(ApiError::forbidden("missing or wrong CSRF token")));
        }
        tracing::info!("admin panel: {} {method} {path}", session.user);
    }
    Some(Ok(session.user))
}

// ------------------------------------------------------------------ routes

fn page_headers() -> [(HeaderName, HeaderValue); 4] {
    [
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(CSP),
        ),
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ),
        (CACHE_CONTROL, HeaderValue::from_static("no-store")),
    ]
}

fn not_found() -> Response {
    ApiError::not_found("Not Found").into_response()
}

/// The panel, if it is on and this request is for its address.
fn panel_for(state: &AppState, headers: &HeaderMap) -> Option<Arc<Panel>> {
    state
        .web
        .panel
        .as_ref()
        .filter(|p| p.serves(headers))
        .cloned()
}

fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        page_headers(),
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// `message.html` with the text, HTML-escaped.
fn message(text: &str, status: StatusCode) -> Response {
    html(
        status,
        MESSAGE_HTML.replace("{{message}}", &escape_html(text)),
    )
}

fn see_other(location: &str) -> Response {
    let mut res = StatusCode::SEE_OTHER.into_response();
    let headers = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(location) {
        headers.insert(LOCATION, v);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn with_cookie(mut res: Response, (name, value): (HeaderName, HeaderValue)) -> Response {
    res.headers_mut().append(name, value);
    res
}

async fn page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(panel) = panel_for(&state, &headers) else {
        return not_found();
    };
    if panel.session(&headers, state.now()).is_none() {
        return see_other("/ui/login");
    }
    html(StatusCode::OK, INDEX_HTML.to_owned())
}

const UNREACHABLE: &str = "The sign-in provider could not be reached.";

async fn login(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(panel) = panel_for(&state, &headers) else {
        return not_found();
    };
    let now = state.now();
    let begun = panel.sign_in.begin(&panel.redirect_uri(), None).await;
    let sealed = begun
        .as_ref()
        .ok()
        .and_then(|(_, attempt)| panel.sealer.seal(Kind::Login, attempt, now));
    match (begun, sealed) {
        (Ok((url, _)), Some(cookie)) => with_cookie(
            see_other(&url),
            cookies::set(LOGIN_COOKIE, &cookie, "/", LOGIN_TTL),
        ),
        (Err(SignInError::Refused(text)), _) => message(&text, StatusCode::BAD_GATEWAY),
        _ => message(UNREACHABLE, StatusCode::BAD_GATEWAY),
    }
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(panel) = panel_for(&state, &headers) else {
        return not_found();
    };
    let params: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
    if !get("error").is_empty() {
        let error: String = get("error").chars().take(200).collect();
        return message(
            &format!("The provider refused the sign-in ({error})."),
            StatusCode::FORBIDDEN,
        );
    }
    let now = state.now();
    let attempt: Option<LoginAttempt> = cookies::get(&headers, LOGIN_COOKIE)
        .and_then(|c| panel.sealer.open(Kind::Login, c, LOGIN_TTL, now));
    match panel
        .sign_in
        .identify(attempt, get("code"), get("state"), now)
        .await
    {
        Ok((user, _)) => {
            let Some(session) = panel.seal_session(&user, now) else {
                return message(UNREACHABLE, StatusCode::BAD_GATEWAY);
            };
            tracing::info!(user, "admin panel: signed in");
            let res = with_cookie(
                see_other("/ui/"),
                cookies::set(SESSION_COOKIE, &session, "/", panel.ttl),
            );
            with_cookie(res, cookies::delete(LOGIN_COOKIE, "/"))
        }
        Err(SignInError::Refused(text)) => message(&text, StatusCode::FORBIDDEN),
        Err(SignInError::Unreachable) => message(UNREACHABLE, StatusCode::BAD_GATEWAY),
    }
}

/// Who is signed in and the CSRF token the page sends back with every
/// change.
async fn session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(panel) = panel_for(&state, &headers) else {
        return not_found();
    };
    match panel.session(&headers, state.now()) {
        None => ApiError::unauthorized("not signed in").into_response(),
        Some(s) => (
            [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(json!({"user": s.user, "csrf": s.csrf, "expires": s.exp})),
        )
            .into_response(),
    }
}

async fn asset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if panel_for(&state, &headers).is_none() {
        return not_found();
    }
    let (body, mime) = match name.as_str() {
        "app.js" => (APP_JS, "text/javascript; charset=utf-8"),
        "app.css" => (APP_CSS, "text/css; charset=utf-8"),
        _ => return not_found(),
    };
    (
        page_headers(),
        [(CONTENT_TYPE, HeaderValue::from_static(mime))],
        body,
    )
        .into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(panel) = panel_for(&state, &headers) else {
        return not_found();
    };
    if let Some(current) = panel.session(&headers, state.now()) {
        let sent = headers
            .get(CSRF_HEADER)
            .map_or(&[][..], HeaderValue::as_bytes);
        if !ct_eq(sent, current.csrf.as_bytes()) {
            return ApiError::forbidden("missing or wrong CSRF token").into_response();
        }
    }
    with_cookie(
        StatusCode::NO_CONTENT.into_response(),
        cookies::delete(SESSION_COOKIE, "/"),
    )
}

async fn nothing() -> Response {
    not_found()
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/ui", get(page))
        .route("/ui/", get(page))
        .route("/ui/login", get(login))
        .route("/ui/callback", get(callback))
        .route("/ui/session", get(session))
        .route("/ui/logout", axum::routing::post(logout).get(nothing))
        .route("/ui/{name}", get(asset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_list() {
        assert!(allowed("GET", "/admin/agents"));
        assert!(allowed("PATCH", "/admin/agents/abc/attributes"));
        assert!(allowed("DELETE", "/admin/rules/abc"));
        assert!(!allowed("DELETE", "/admin/agents"));
        assert!(!allowed("PATCH", "/admin/agents/a/b/attributes"));
        assert!(!allowed("POST", "/admin/agents/abc/attributes"));
        assert!(!allowed("GET", "/admin/agents/"));
        assert!(!allowed("GET", "/admin/log/commands//"));
        assert!(!allowed("POST", "/admin/agents//rename"));
        assert!(!allowed("get", "/admin/agents"));
        for forbidden in [
            ("POST", "/admin/requests/x/decide"),
            ("POST", "/admin/hosts/h/arm"),
            ("POST", "/admin/hosts/h/disarm"),
            ("POST", "/admin/unlock"),
            ("POST", "/admin/lockdown"),
            ("POST", "/admin/agents/x/set-webhook"),
            ("POST", "/admin/agents/x/rotate-lldap-password"),
        ] {
            assert!(!allowed(forbidden.0, forbidden.1), "{forbidden:?}");
        }
        assert!(!ALLOWED.iter().any(|(_, p)| p.contains("decide")
            || p.contains("arm")
            || p.contains("unlock")
            || p.contains("lockdown")));
    }

    #[test]
    fn the_assets_parse_nothing_as_html() {
        for bad in ["innerHTML", "insertAdjacentHTML", "document.write"] {
            assert!(!APP_JS.contains(bad), "{bad}");
        }
        assert!(INDEX_HTML.contains("/ui/app.js") && !INDEX_HTML.contains("<script>"));
        assert!(MESSAGE_HTML.contains("{{message}}"));
    }
}
