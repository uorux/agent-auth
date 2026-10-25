//! The OAuth server's HTTP side (surfaces spec §C.2–C.6):
//!
//! ```text
//! GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728
//! GET  /.well-known/oauth-authorization-server       RFC 8414
//! POST /oauth/register                               RFC 7591, open
//! GET  /oauth/authorize                              PKCE; signs in at the provider
//! GET  /oauth/callback                               the provider's return: consent
//! POST /oauth/consent                                Allow or Deny
//! POST /oauth/token                                  authorization_code, refresh_token
//! POST /oauth/revoke                                 RFC 7009
//! GET  /admin/connectors, POST /admin/connectors/{id}/revoke
//! ```
//!
//! All of it answers 404 unless `remote_mcp` is enabled.

use std::collections::HashMap;
use std::sync::Arc;

use agent_auth_crypto::{ct_eq, token_urlsafe};
use agent_auth_store::agents;
use agent_auth_store::oauth as db;
use agent_auth_wire::oauth::{
    AuthorizationServerMetadata, ConnectorOut, ConnectorRevoked, ProtectedResourceMetadata,
};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, LOCATION, PRAGMA};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;

use super::{
    Authorization, ConsentBlob, OAuthFailure, OAuthServer, Refusal, TokenForm, agent_name,
};
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::webui::cookies::{self, Kind};
use crate::webui::escape_html;
use crate::webui::oidc::{LoginAttempt, SignInError};

pub const LOGIN_COOKIE: &str = "__Secure-aa_oauth_login";
pub const CONSENT_COOKIE: &str = "__Secure-aa_oauth_consent";
const COOKIE_PATH: &str = "/oauth";
const LOGIN_TTL: i64 = 600;
const CONSENT_TTL: i64 = 600;
/// The largest form or registration body read.
const MAX_BODY: usize = 64 * 1024;

fn not_found() -> ApiError {
    ApiError::not_found("Not Found")
}

fn server(state: &AppState) -> ApiResult<Arc<OAuthServer>> {
    state.web.oauth.clone().ok_or_else(not_found)
}

fn no_store() -> [(HeaderName, HeaderValue); 1] {
    [(CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}

fn refusal(r: &Refusal) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_REQUEST);
    (status, no_store(), Json(&r.body)).into_response()
}

fn failure(f: OAuthFailure) -> Response {
    match f {
        OAuthFailure::Refused(r) => refusal(&r),
        OAuthFailure::Store(e) => ApiError::from(e).into_response(),
    }
}

/// Parses a form (or query) body: the last value of a repeated key wins,
/// as Starlette's did.
fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

// ---------------------------------------------------------------- pages

/// The pages' one style block; the CSP allows exactly it, by hash.
const PAGE_CSS: &str = r#"
:root { color-scheme: light dark; --bg:#f6f5f2; --fg:#1d1d1b; --muted:#5f5e5a; --card:#fff; --line:#d9d7d0; --accent:#2a5bd7; --warn:#a4400a; }
@media (prefers-color-scheme: dark) { :root { --bg:#161614; --fg:#ecebe6; --muted:#a3a19a; --card:#21211f; --line:#3a3936; --accent:#7ea2ff; --warn:#ff9b5e; } }
body { background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; margin:0; padding:16px; }
main { max-width:34rem; margin:8vh auto; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }
h1 { font-size:1.25rem; margin:0 0 12px; } p { margin:8px 0; } .muted { color:var(--muted); }
.where { font-weight:600; color:var(--warn); word-break:break-all; }
label { display:block; margin:16px 0 4px; font-weight:600; }
input[type=text] { width:100%; box-sizing:border-box; padding:8px; border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg); font:inherit; }
.row { display:flex; gap:8px; margin-top:20px; } button { font:inherit; padding:8px 16px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; }
button.allow { background:var(--accent); border-color:var(--accent); color:#fff; }
code { font-family:ui-monospace, monospace; }
"#;

/// `default-src 'none'; style-src '<sha256 of the style>'; form-action
/// 'self' [the redirect's origin]; frame-ancestors 'none'`. (The Python
/// allowed any inline style; only this one is allowed here.)
fn page_csp(form_action_extra: Option<&str>) -> String {
    let hash = base64::engine::general_purpose::STANDARD
        .encode(agent_auth_crypto::digest::sha256(PAGE_CSS.as_bytes()));
    let extra = form_action_extra
        .map(|o| format!(" {o}"))
        .unwrap_or_default();
    format!(
        "default-src 'none'; style-src 'sha256-{hash}'; form-action 'self'{extra}; frame-ancestors 'none'"
    )
}

/// A page. `send_to`: the connector's redirect, whose origin the CSP's
/// `form-action` also allows (browsers apply it to the redirect after a
/// form post).
fn page(title: &str, body: &str, status: StatusCode, send_to: Option<&str>) -> Response {
    let doc = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title>\n\
<style>{PAGE_CSS}</style></head><body><main>{body}</main></body></html>",
        escape_html(title)
    );
    let origin = send_to
        .and_then(|u| url::Url::parse(u).ok())
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null");
    let csp = HeaderValue::from_str(&page_csp(origin.as_deref()))
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
    (
        status,
        [
            (HeaderName::from_static("content-security-policy"), csp),
            (
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            ),
            (
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            ),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
        ],
        doc,
    )
        .into_response()
}

fn message(text: &str, status: StatusCode) -> Response {
    page(
        "agent-auth",
        &format!("<h1>Can't connect</h1><p>{}</p>", escape_html(text)),
        status,
        None,
    )
}

const UNREACHABLE: &str = "The sign-in provider could not be reached.";

fn redirect(uri: &str, params: &[(&str, &str)]) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let has_query = url::Url::parse(uri).is_ok_and(|u| u.query().is_some());
    let location = format!("{uri}{}{query}", if has_query { '&' } else { '?' });
    let mut res = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(&location) {
        res.headers_mut().insert(LOCATION, v);
    }
    res.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn with_cookie(mut res: Response, (name, value): (HeaderName, HeaderValue)) -> Response {
    res.headers_mut().append(name, value);
    res
}

// ------------------------------------------------------------ discovery

async fn protected_resource(
    State(state): State<AppState>,
) -> ApiResult<Json<ProtectedResourceMetadata>> {
    let base = server(&state)?.base().to_owned();
    Ok(Json(ProtectedResourceMetadata {
        resource: format!("{base}/mcp"),
        authorization_servers: vec![base],
        bearer_methods_supported: vec!["header".into()],
        resource_name: "agent-auth".into(),
    }))
}

async fn authorization_server(
    State(state): State<AppState>,
) -> ApiResult<Json<AuthorizationServerMetadata>> {
    Ok(Json(AuthorizationServerMetadata::for_base(
        server(&state)?.base(),
    )))
}

// --------------------------------------------------------- registration

async fn register(State(state): State<AppState>, body: Bytes) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    match oauth.register(&state.store, &body, state.now()).await {
        Ok(out) => (StatusCode::CREATED, no_store(), Json(out)).into_response(),
        Err(f) => failure(f),
    }
}

// -------------------------------------------------------- authorization

async fn authorize(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let params = parse_form(query.unwrap_or_default().as_bytes());
    let now = state.now();
    let auth = match oauth.check_authorize(&state.store, &params, now).await {
        Ok(Ok(a)) => a,
        // Not sent back to the redirect: it isn't known good yet.
        Ok(Err(text)) => return message(&text, StatusCode::BAD_REQUEST),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let carry = serde_json::to_value(&auth).ok();
    let callback = format!("{}/oauth/callback", oauth.base());
    let begun = oauth.sign_in.begin(&callback, carry).await;
    let sealed = begun
        .as_ref()
        .ok()
        .and_then(|(_, attempt)| oauth.sealer.seal(Kind::Login, attempt, now));
    match (begun, sealed) {
        (Ok((url, _)), Some(cookie)) => {
            let mut res = StatusCode::SEE_OTHER.into_response();
            if let Ok(v) = HeaderValue::from_str(&url) {
                res.headers_mut().insert(LOCATION, v);
            }
            res.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            with_cookie(
                res,
                cookies::set(LOGIN_COOKIE, &cookie, COOKIE_PATH, LOGIN_TTL),
            )
        }
        _ => message(UNREACHABLE, StatusCode::BAD_GATEWAY),
    }
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let params = parse_form(query.unwrap_or_default().as_bytes());
    let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
    if !get("error").is_empty() {
        let error: String = get("error").chars().take(200).collect();
        return message(
            &format!("The sign-in provider said: {error}"),
            StatusCode::BAD_REQUEST,
        );
    }
    let now = state.now();
    let attempt: Option<LoginAttempt> = cookies::get(&headers, LOGIN_COOKIE)
        .and_then(|c| oauth.sealer.open(Kind::Login, c, LOGIN_TTL, now));
    let (user, carry) = match oauth
        .sign_in
        .identify(attempt, get("code"), get("state"), now)
        .await
    {
        Ok(found) => found,
        Err(SignInError::Refused(text)) => return message(&text, StatusCode::FORBIDDEN),
        Err(SignInError::Unreachable) => return message(UNREACHABLE, StatusCode::BAD_GATEWAY),
    };
    let auth: Option<Authorization> = carry.and_then(|c| serde_json::from_value(c).ok());
    let Some(auth) = auth.filter(|a| !a.client_id.is_empty()) else {
        return message(
            "This sign-in didn't start at a connector's authorization.",
            StatusCode::BAD_REQUEST,
        );
    };
    let looked_up = async {
        let tx = state.store.begin().await?;
        let client = oauth.client(&tx, &auth.client_id, now).await?;
        let bound = match &client {
            Some(c) => oauth.bound_agent(&tx, c).await?,
            None => None,
        };
        tx.commit().await?;
        Ok::<_, agent_auth_store::StoreError>((client, bound))
    };
    let (client, bound) = match looked_up.await {
        Ok(found) => found,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if client.is_none() {
        return message(
            "That connector is no longer registered.",
            StatusCode::BAD_REQUEST,
        );
    }
    let Ok(nonce) = token_urlsafe(24) else {
        return message(UNREACHABLE, StatusCode::BAD_GATEWAY);
    };
    let blob = ConsentBlob {
        auth: auth.clone(),
        user: user.clone(),
        nonce: nonce.clone(),
    };
    let Some(sealed) = oauth.sealer.seal(Kind::Consent, &blob, now) else {
        return message(UNREACHABLE, StatusCode::BAD_GATEWAY);
    };
    let host = url::Url::parse(&auth.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| auth.redirect_uri.clone());
    let name = escape_html(if auth.client_name.is_empty() {
        "An unnamed connector"
    } else {
        &auth.client_name
    });
    let who = match bound {
        Some(agent) => format!(
            "<p>It acts as <code>{}</code>, as it did before.</p>",
            escape_html(&agent)
        ),
        None => {
            let label = if auth.client_name.is_empty() {
                "connector"
            } else {
                &auth.client_name
            };
            format!(
                "<label for=\"name\">It will act as the agent</label>\
<input type=\"text\" id=\"name\" name=\"name\" value=\"{}\" maxlength=\"44\" pattern=\"(web-)?[a-z0-9][a-z0-9-]*\" required>\
<p class=\"muted\">Everything it asks for goes through policy and your approvals as that agent.</p>",
                escape_html(&agent_name(label))
            )
        }
    };
    let body = format!(
        "<h1>Connect {name} to agent-auth?</h1>
<p>Signed in as <strong>{}</strong>.</p>
<p>After you allow it, the browser goes back to <span class=\"where\">{}</span>. If you didn't start this from there, deny it.</p>
<form method=\"post\" action=\"/oauth/consent\">
<input type=\"hidden\" name=\"consent\" value=\"{}\">
{who}
<p class=\"muted\">It can see what exists, ask for access, talk to agents in threads, and read the wiki. It gets no credentials.</p>
<div class=\"row\"><button class=\"allow\" type=\"submit\" name=\"action\" value=\"allow\">Allow</button>
<button type=\"submit\" name=\"action\" value=\"deny\">Deny</button></div>
</form>",
        escape_html(&user),
        escape_html(&host),
        escape_html(&sealed),
    );
    let res = page(
        "Connect to agent-auth",
        &body,
        StatusCode::OK,
        Some(&auth.redirect_uri),
    );
    let res = with_cookie(
        res,
        cookies::set(CONSENT_COOKIE, &nonce, COOKIE_PATH, CONSENT_TTL),
    );
    with_cookie(res, cookies::delete(LOGIN_COOKIE, COOKIE_PATH))
}

async fn consent(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let form = parse_form(&body);
    let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let now = state.now();
    let blob: Option<ConsentBlob> =
        oauth
            .sealer
            .open(Kind::Consent, get("consent"), CONSENT_TTL, now);
    let cookie = cookies::get(&headers, CONSENT_COOKIE).unwrap_or("");
    let Some(blob) =
        blob.filter(|b| !cookie.is_empty() && ct_eq(cookie.as_bytes(), b.nonce.as_bytes()))
    else {
        return message(
            "This approval expired or didn't start in this browser; start again from the app.",
            StatusCode::BAD_REQUEST,
        );
    };
    let auth = &blob.auth;
    let base = oauth.base().to_owned();
    let res = if get("action") == "allow" {
        let label = match (get("name"), auth.client_name.as_str()) {
            ("", "") => "connector",
            ("", name) => name,
            (given, _) => given,
        };
        match oauth
            .approve(&state.store, auth, label, &blob.user, now)
            .await
        {
            Ok(Ok(code)) => redirect(
                &auth.redirect_uri,
                &[("code", &code), ("state", &auth.state), ("iss", &base)],
            ),
            Ok(Err(text)) => return message(&text, StatusCode::BAD_REQUEST),
            Err(e) => return ApiError::from(e).into_response(),
        }
    } else {
        redirect(
            &auth.redirect_uri,
            &[
                ("error", "access_denied"),
                ("state", &auth.state),
                ("iss", &base),
            ],
        )
    };
    with_cookie(res, cookies::delete(CONSENT_COOKIE, COOKIE_PATH))
}

// ---------------------------------------------------------------- tokens

/// HTTP Basic client credentials (each part URL-unquoted); a malformed
/// header is ignored.
fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, password) = text.split_once(':').unwrap_or((text.as_str(), ""));
    let unquote = |s: &str| {
        url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    Some((unquote(user), unquote(password)))
}

async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let mut form = parse_form(&body);
    let mut take = |k: &str| form.remove(k);
    let parsed = TokenForm {
        grant_type: take("grant_type"),
        code: take("code"),
        redirect_uri: take("redirect_uri"),
        code_verifier: take("code_verifier"),
        refresh_token: take("refresh_token"),
        client_id: take("client_id"),
        client_secret: take("client_secret"),
    };
    let basic = basic(&headers);
    match oauth
        .exchange(&state.store, &parsed, basic.as_ref(), state.now())
        .await
    {
        Ok(Ok(pair)) => (
            [
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (PRAGMA, HeaderValue::from_static("no-cache")),
            ],
            Json(pair),
        )
            .into_response(),
        Ok(Err(r)) => refusal(&r),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn revoke(State(state): State<AppState>, body: Bytes) -> Response {
    let oauth = match server(&state) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let form = parse_form(&body);
    let token = form.get("token").map(String::as_str).unwrap_or("");
    match oauth.revoke(&state.store, token, state.now()).await {
        Ok(()) => (no_store(), Json(serde_json::json!({}))).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

// -------------------------------------------------------- the operator's

async fn list_connectors(
    _admin: AdminCaller,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ConnectorOut>>> {
    server(&state)?;
    let now = state.now();
    let tx = state.store.begin().await?;
    let clients = db::list_clients(&tx).await?;
    let live: HashMap<String, i64> = db::live_authorizations(&tx, now)
        .await?
        .into_iter()
        .collect();
    let names: HashMap<_, _> = agents::list_web(&tx)
        .await?
        .into_iter()
        .map(|a| (a.id, a.name))
        .collect();
    tx.commit().await?;
    Ok(Json(
        clients
            .into_iter()
            .map(|c| ConnectorOut {
                live_authorizations: u32::try_from(live.get(&c.id).copied().unwrap_or(0))
                    .unwrap_or(u32::MAX),
                agent: c.agent_id.and_then(|id| names.get(&id).cloned()),
                client_id: c.id,
                name: Some(c.name),
                redirect_uris: c.redirect_uris,
                created_at: c.created_at,
                last_used_at: c.last_used_at,
                revoked_at: c.revoked_at,
            })
            .collect(),
    ))
}

async fn revoke_connector(
    admin: AdminCaller,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConnectorRevoked>> {
    server(&state)?;
    let tx = state.store.begin().await?;
    let found = db::revoke_client(&tx, &id, state.now()).await?;
    tx.commit().await?;
    if !found {
        return Err(ApiError::not_found("no such connector"));
    }
    tracing::warn!(client = id, by = admin.label(), "oauth: client revoked");
    Ok(Json(ConnectorRevoked { revoked: id }))
}

pub fn routes() -> Router<AppState> {
    let limit = axum::extract::DefaultBodyLimit::max(MAX_BODY);
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route("/oauth/register", post(register).layer(limit))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/callback", get(callback))
        .route("/oauth/consent", post(consent).layer(limit))
        .route("/oauth/token", post(token).layer(limit))
        .route("/oauth/revoke", post(revoke).layer(limit))
        .route("/admin/connectors", get(list_connectors))
        .route("/admin/connectors/{id}/revoke", post(revoke_connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials() {
        let mut h = HeaderMap::new();
        let enc = base64::engine::general_purpose::STANDARD.encode("mcpc_a%2Bb:s3%3Acret");
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {enc}")).unwrap_or(HeaderValue::from_static("")),
        );
        assert_eq!(basic(&h), Some(("mcpc_a+b".into(), "s3:cret".into())));
        h.insert(AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert_eq!(basic(&h), None);
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert_eq!(basic(&h), None);
    }
}
