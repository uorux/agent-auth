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

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use agent_auth_crypto::{ct_eq, token_urlsafe};
use agent_auth_store::{Store, StoreError, flags};
use axum::Json;
use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
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
/// The `broker_flags` key holding when each panel user last signed out:
/// `{"<user>": <unix milliseconds>}`. A session sealed before its user's
/// sign-out is void, wherever its cookie went.
pub const SIGNOUTS_FLAG: &str = "panel_signouts";
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
        *m == method && agent_auth_wire::mcp_tools::route_matches(pattern, path)
    })
}

/// A signed-in session (sealed into [`SESSION_COOKIE`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    /// Unix seconds; the lifetime is absolute.
    pub exp: i64,
    /// Unix milliseconds it was sealed: a sign-out by its user after that
    /// voids it.
    pub iat_ms: i64,
}

/// The admin panel.
#[derive(Debug)]
pub struct Panel {
    base: String,
    own: Option<String>,
    ttl: i64,
    sealer: Arc<Sealer>,
    sign_in: Arc<OidcClient>,
    /// [`SIGNOUTS_FLAG`]'s value, read at start and written through on
    /// every sign-out (one broker per database, so this copy is the
    /// truth): checked on every request without a database round trip.
    signouts: RwLock<HashMap<String, i64>>,
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
            signouts: RwLock::new(HashMap::new()),
        }
    }

    /// Reads the sign-outs from the database (at start, before serving).
    pub async fn load_signouts(&self, store: &Store) -> Result<(), StoreError> {
        let tx = store.begin().await?;
        let value = flags::get(&tx, SIGNOUTS_FLAG).await?;
        tx.commit().await?;
        let loaded = value.map(|v| signouts_from(&v)).unwrap_or_default();
        if let Ok(mut map) = self.signouts.write() {
            *map = loaded;
        }
        Ok(())
    }

    /// Signs `user` out everywhere: every session of theirs sealed before
    /// `now` is void from here on, this broker's restarts included. Entries
    /// older than a session's lifetime are dropped (nothing they void is
    /// still alive).
    pub async fn sign_out(
        &self,
        store: &Store,
        user: &str,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let at = unix_ms(now);
        let horizon = at.saturating_sub(self.ttl.saturating_mul(1000));
        let tx = store.begin().await?;
        let current = flags::get_for_update(&tx, SIGNOUTS_FLAG, &json!({}), now).await?;
        let mut map = signouts_from(&current);
        map.retain(|_, t| *t > horizon);
        map.insert(user.to_owned(), at);
        flags::set(&tx, SIGNOUTS_FLAG, &json!(map), now).await?;
        tx.commit().await?;
        if let Ok(mut held) = self.signouts.write() {
            *held = map;
        }
        Ok(())
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
    pub fn serves(&self, headers: &HeaderMap, uri: &Uri) -> bool {
        let first = |text: &str| {
            text.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        };
        // `Host`, else the request target's authority (HTTP/2 `:authority`
        // or an absolute-form target); neither: not for the panel.
        let host = match headers.get("host") {
            Some(raw) => raw.to_str().ok().map(first),
            None => uri.authority().map(|a| a.as_str().to_ascii_lowercase()),
        };
        if !host.is_some_and(|h| !h.is_empty() && self.own_name(&h)) {
            return false;
        }
        match headers.get("x-forwarded-host") {
            None => true,
            Some(raw) => raw.to_str().is_ok_and(|t| {
                let value = first(t);
                value.is_empty() || self.own_name(&value)
            }),
        }
    }

    /// `host`, `host:port`, `[v6]`, `[v6]:port`: the panel's own name
    /// (default port or none), or loopback.
    fn own_name(&self, value: &str) -> bool {
        let default_port = if self.base.starts_with("http://") {
            "80"
        } else {
            "443"
        };
        let split = if value.starts_with('[') {
            value.find(']').map(|i| i.saturating_add(1))
        } else {
            value.find(':')
        };
        let (host, port) = match split {
            Some(i) => value.split_at_checked(i).unwrap_or((value, "")),
            None => (value, ""),
        };
        if matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            return true;
        }
        let normalized = match port.strip_prefix(':') {
            Some(p) if p == default_port => host,
            _ => value,
        };
        self.own.as_deref() == Some(normalized)
    }

    /// The signed-in session the request's cookie holds, if any.
    #[must_use]
    pub fn session(&self, headers: &HeaderMap, now: OffsetDateTime) -> Option<Session> {
        let cookie = cookies::get(headers, SESSION_COOKIE)?;
        self.open_session(cookie, now)
    }

    /// Opens a session cookie value: sealed by this broker, of the session
    /// kind, within its TTL, before its `exp`, and after its user's last
    /// sign-out. A poisoned sign-out map opens nothing.
    #[must_use]
    pub fn open_session(&self, cookie: &str, now: OffsetDateTime) -> Option<Session> {
        let session: Session = self.sealer.open(Kind::Session, cookie, self.ttl, now)?;
        if session.exp <= now.unix_timestamp() {
            return None;
        }
        let signed_out = self.signouts.read().ok()?.get(&session.user).copied();
        signed_out
            .is_none_or(|t| session.iat_ms > t)
            .then_some(session)
    }

    /// A new session for `user` (sealed), as the callback sets it.
    #[must_use]
    pub fn seal_session(&self, user: &str, now: OffsetDateTime) -> Option<String> {
        let session = Session {
            user: user.to_owned(),
            csrf: token_urlsafe(24).ok()?,
            exp: now.unix_timestamp().saturating_add(self.ttl),
            iat_ms: unix_ms(now),
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
        || !panel.serves(&parts.headers, &parts.uri)
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
fn panel_for(state: &AppState, headers: &HeaderMap, uri: &Uri) -> Option<Arc<Panel>> {
    state
        .web
        .panel
        .as_ref()
        .filter(|p| p.serves(headers, uri))
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

async fn page(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(panel) = panel_for(&state, &headers, &uri) else {
        return not_found();
    };
    if panel.session(&headers, state.now()).is_none() {
        return see_other("/ui/login");
    }
    html(StatusCode::OK, INDEX_HTML.to_owned())
}

const UNREACHABLE: &str = "The sign-in provider could not be reached.";

async fn login(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(panel) = panel_for(&state, &headers, &uri) else {
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
    uri: Uri,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(panel) = panel_for(&state, &headers, &uri) else {
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
async fn session(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(panel) = panel_for(&state, &headers, &uri) else {
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
    uri: Uri,
    Path(name): Path<String>,
) -> Response {
    if panel_for(&state, &headers, &uri).is_none() {
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

/// Signs out: the cookie goes, and so does every session of its user,
/// copies of the cookie included (`Panel::sign_out`). Without a live
/// session there's nothing to void and only the cookie goes.
async fn logout(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(panel) = panel_for(&state, &headers, &uri) else {
        return not_found();
    };
    let now = state.now();
    if let Some(current) = panel.session(&headers, now) {
        let sent = headers
            .get(CSRF_HEADER)
            .map_or(&[][..], HeaderValue::as_bytes);
        if !ct_eq(sent, current.csrf.as_bytes()) {
            return ApiError::forbidden("missing or wrong CSRF token").into_response();
        }
        if let Err(e) = panel.sign_out(&state.store, &current.user, now).await {
            // Not signed out: say so, and keep the cookie, so a retry can
            // still void the session.
            tracing::error!("admin panel: signing {} out failed: {e}", current.user);
            return ApiError::from(e).into_response();
        }
        tracing::info!("admin panel: {} signed out", current.user);
    }
    with_cookie(
        StatusCode::NO_CONTENT.into_response(),
        cookies::delete(SESSION_COOKIE, "/"),
    )
}

/// Unix milliseconds (saturating).
fn unix_ms(at: OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// The sign-out map from its stored JSON; anything malformed is skipped
/// (the broker writes this key alone).
fn signouts_from(value: &serde_json::Value) -> HashMap<String, i64> {
    value
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(user, t)| Some((user.clone(), t.as_i64()?)))
                .collect()
        })
        .unwrap_or_default()
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
