//! The admin panel, the OAuth server and `/mcp` (surfaces spec §B, §C),
//! against a real database and a fake OpenID provider (a local axum server
//! issuing ID tokens signed with test keys).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use agent_auth_broker::auth::{AdminCaller, AgentCaller, AgentCredentialKind, AuthConfig};
use agent_auth_broker::oauth::OAuthServer;
use agent_auth_broker::remote_mcp::RemoteMcp;
use agent_auth_broker::state::AppState;
use agent_auth_broker::webui::cookies::{Kind, Sealer};
use agent_auth_broker::webui::oidc::{OidcClient, pkce_challenge};
use agent_auth_broker::webui::panel::{CSRF_HEADER, LOGIN_COOKIE, SESSION_COOKIE, Session};
use agent_auth_broker::webui::{self, Panel, Web};
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::{Policy, RemoteMcpConfig};
use agent_auth_core::{AgentId, SessionId};
use agent_auth_crypto::{Secret, api_key, b64url_encode};
use agent_auth_store::{Store, agents, sessions};
use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{Request, StatusCode};
use axum::routing::{any, get, post};
use axum::{Extension, Json, Router};
use http_body_util::BodyExt;
use ring::rand::SystemRandom;
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RsaKeyPair,
    RsaPublicKeyComponents,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;

const CLIENT: &str = "agent-auth-admin";
const GROUP: &str = "agent-auth-admins";
const BASE: &str = "https://broker.test";
const ADMIN: &str = "Bearer admin-secret";
const RSA_KEY: &[u8] = include_bytes!("fixtures/oidc-test-rsa.pkcs1.der");

// ------------------------------------------------------- the fake provider

struct ProviderState {
    issuer_claim: Option<String>,
    jwks: Value,
    id_token: String,
    token_status: u16,
    token_forms: Vec<HashMap<String, String>>,
    userinfo: Value,
}

#[derive(Clone)]
struct Provider {
    issuer: String,
    state: Arc<Mutex<ProviderState>>,
    rsa: Arc<RsaKeyPair>,
}

fn rsa_jwk(pair: &RsaKeyPair, kid: &str) -> Value {
    let c: RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
    json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
           "n": b64url_encode(&c.n), "e": b64url_encode(&c.e)})
}

fn ec_pair() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}

fn ec_jwk(pair: &EcdsaKeyPair, kid: &str) -> Value {
    let p = pair.public_key().as_ref();
    json!({"kty": "EC", "crv": "P-256", "kid": kid, "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..65])})
}

fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    )
}

fn sign_rs256(pair: &RsaKeyPair, kid: &str, claims: &Value) -> String {
    let input = signing_input(&json!({"alg": "RS256", "kid": kid, "typ": "JWT"}), claims);
    let mut sig = vec![0u8; pair.public().modulus_len()];
    pair.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

fn sign_es256(pair: &EcdsaKeyPair, kid: &str, claims: &Value) -> String {
    let input = signing_input(&json!({"alg": "ES256", "kid": kid}), claims);
    let sig = pair.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

impl Provider {
    async fn start() -> Provider {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let rsa = Arc::new(RsaKeyPair::from_der(RSA_KEY).unwrap());
        let state = Arc::new(Mutex::new(ProviderState {
            issuer_claim: None,
            jwks: json!({"keys": [rsa_jwk(&rsa, "k1")]}),
            id_token: String::new(),
            token_status: 200,
            token_forms: Vec::new(),
            userinfo: json!({"sub": "sub-1", "groups": [GROUP, "admin"], "preferred_username": "jrt"}),
        }));
        let p = Provider {
            issuer: issuer.clone(),
            state: state.clone(),
            rsa,
        };
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let p = p.clone();
                    move || async move {
                        let iss = p
                            .state
                            .lock()
                            .unwrap()
                            .issuer_claim
                            .clone()
                            .unwrap_or(p.issuer.clone());
                        Json(json!({
                            "issuer": iss,
                            "authorization_endpoint": format!("{}/authorize", p.issuer),
                            "token_endpoint": format!("{}/token", p.issuer),
                            "userinfo_endpoint": format!("{}/userinfo", p.issuer),
                            "jwks_uri": format!("{}/jwks.json", p.issuer),
                        }))
                    }
                }),
            )
            .route(
                "/jwks.json",
                get({
                    let p = p.clone();
                    move || async move { Json(p.state.lock().unwrap().jwks.clone()) }
                }),
            )
            .route(
                "/token",
                post({
                    let p = p.clone();
                    move |body: String| async move {
                        let mut s = p.state.lock().unwrap();
                        s.token_forms.push(
                            url::form_urlencoded::parse(body.as_bytes())
                                .into_owned()
                                .collect(),
                        );
                        let status = StatusCode::from_u16(s.token_status).unwrap();
                        (
                            status,
                            Json(json!({"id_token": s.id_token, "access_token": "at"})),
                        )
                    }
                }),
            )
            .route(
                "/userinfo",
                get({
                    let p = p.clone();
                    move |headers: axum::http::HeaderMap| async move {
                        assert_eq!(headers["authorization"], "Bearer at");
                        Json(p.state.lock().unwrap().userinfo.clone())
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        p
    }

    fn claims(&self, nonce: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        json!({"iss": self.issuer, "aud": CLIENT, "sub": "sub-1", "iat": now, "exp": now + 300,
               "nonce": nonce, "groups": [GROUP, "admin"], "preferred_username": "jrt"})
    }

    fn will_issue(&self, token: String) {
        self.state.lock().unwrap().id_token = token;
    }
}

// --------------------------------------------------------------- the app

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with(&format!("{name}=")))
            .map(|v| {
                assert!(
                    v.contains("HttpOnly") && v.contains("Secure") && v.contains("SameSite=Lax"),
                    "{v}"
                );
                v.split(';').next().unwrap()[name.len() + 1..].to_owned()
            })
    }
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
    fn location(&self) -> String {
        self.headers["location"].to_str().unwrap().to_owned()
    }
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, String)>,
) -> Resp {
    let mut req = Request::builder().method(method).uri(uri);
    // As a browser reaches the panel: at its own address, unless the test
    // names another (or `host: -` for none).
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req = req.header("host", "broker.test");
    }
    for (k, v) in headers {
        if !(k.eq_ignore_ascii_case("host") && *v == "-") {
            req = req.header(*k, *v);
        }
    }
    let req = match body {
        Some((ct, b)) => req.header("content-type", ct).body(Body::from(b)),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn query_of(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').map_or("", |(_, q)| q);
    url::form_urlencoded::parse(q.as_bytes())
        .into_owned()
        .collect()
}

fn encryption_key() -> String {
    b64url_encode(&[7u8; 32])
}

struct Setup {
    state: AppState,
    app: Router,
    provider: Provider,
    /// The queries `/v1/requests/{id}/wait` saw.
    waits: Arc<Mutex<Vec<String>>>,
    seen: Seen,
}

async fn admin_echo(caller: AdminCaller) -> Json<Value> {
    Json(json!({"by": caller.label()}))
}

async fn me(caller: AgentCaller) -> Json<Value> {
    Json(json!({
        "name": caller.agent().name,
        "kind": caller.agent().kind.as_str(),
        "runtime": caller.agent().runtime,
        "connector": caller.via() == AgentCredentialKind::OAuthConnector,
        "session": caller.session_id().map(|s| s.to_string()),
    }))
}

async fn new_session(
    State(state): State<AppState>,
    caller: AgentCaller,
    Json(body): Json<Value>,
) -> Json<Value> {
    let label = body["label"].as_str().unwrap();
    let id = SessionId::new();
    let tx = state.store.begin().await.unwrap();
    let name = format!("{label}-{}", &id.to_string()[..4]);
    sessions::insert(&tx, id, caller.id(), &name, state.now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    Json(json!({"session_id": id.to_string(), "name": name}))
}

async fn wait(
    caller: AgentCaller,
    Path(id): Path<String>,
    RawQuery(q): RawQuery,
    Extension(waits): Extension<Arc<Mutex<Vec<String>>>>,
) -> Json<Value> {
    let _ = caller;
    waits.lock().unwrap().push(q.unwrap_or_default());
    Json(json!({"id": id, "status": "denied"}))
}

async fn threads(caller: AgentCaller) -> Json<Value> {
    Json(json!({"threads": [], "session": caller.session_id().map(|s| s.to_string())}))
}

/// The broker with the panel and (optionally) the OAuth server and `/mcp`.
async fn setup(pool: sqlx::PgPool, panel: bool, remote: bool) -> Setup {
    setup_with(pool, panel, remote, |_| {}).await
}

/// Every agent-API request seen (method, path), before authentication.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

async fn catch_all(caller: AgentCaller) -> Json<Value> {
    let _ = caller;
    Json(json!({"status": "done", "id": "r-1", "job_id": "r-1", "messages": [], "threads": []}))
}

async fn setup_with(
    pool: sqlx::PgPool,
    panel: bool,
    remote: bool,
    tweak: impl FnOnce(&mut RemoteMcpConfig),
) -> Setup {
    let provider = Provider::start().await;
    let sealer = Arc::new(Sealer::new(&encryption_key()).unwrap());
    let sign_in = Arc::new(OidcClient::new(&provider.issuer, CLIENT, GROUP).unwrap());
    let mut config = RemoteMcpConfig {
        enabled: true,
        base_url: BASE.to_owned(),
        ..RemoteMcpConfig::default()
    };
    config
        .redirect_uris
        .push("https://claude.ai/other".to_owned());
    tweak(&mut config);
    let web = Web {
        panel: panel.then(|| Arc::new(Panel::new(BASE, 8 * 3600, sealer.clone(), sign_in.clone()))),
        oauth: remote
            .then(|| Arc::new(OAuthServer::new(&config, sealer.clone(), sign_in.clone()).unwrap())),
        remote_mcp: remote.then(|| Arc::new(RemoteMcp::new(&config).unwrap())),
    };
    let state = AppState::new(
        Store::from_pool(pool),
        Policy::default(),
        AuthConfig {
            admin_token: Some(Secret::new("admin-secret".to_owned())),
            oauth_enabled: false,
            trust_x_real_ip: true,
        },
    );
    let state = webui::install(state, web);
    let waits = Arc::new(Mutex::new(Vec::new()));
    let seen: Seen = Arc::default();
    let v1: Router<AppState> = Router::new()
        .route("/v1/me", get(me))
        .route("/v1/sessions", post(new_session))
        .route("/v1/requests/{id}/wait", get(wait))
        .route("/v1/a2a/threads", get(threads))
        .route("/v1/{*rest}", any(catch_all))
        .layer(Extension(waits.clone()))
        .layer(axum::middleware::from_fn({
            let seen = seen.clone();
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let seen = seen.clone();
                async move {
                    seen.lock()
                        .unwrap()
                        .push((req.method().to_string(), req.uri().path().to_owned()));
                    next.run(req).await
                }
            }
        }));
    if let Some(mcp) = &state.web.remote_mcp {
        mcp.set_agent_api(v1.clone().with_state(state.clone()));
    }
    let app = webui::routes()
        .merge(v1)
        .route("/admin/{*rest}", any(admin_echo))
        .with_state(state.clone());
    Setup {
        state,
        app,
        provider,
        waits,
        seen,
    }
}

// ------------------------------------------------------------ the panel

fn cookie_header(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Through the provider: returns the callback's response. `claims` may
/// change the ID token; `sign` signs it (RS256 with k1 by default).
async fn sign_in(
    s: &Setup,
    tweak: impl FnOnce(&mut Value),
    sign: Option<&dyn Fn(&Value) -> String>,
    tamper_state: Option<&str>,
) -> Resp {
    let start = send(&s.app, "GET", "/ui/login", &[], None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
    let login = start.cookie(LOGIN_COOKIE).expect("login cookie");
    let q = query_of(&start.location());
    assert!(
        start
            .location()
            .starts_with(&format!("{}/authorize?", s.provider.issuer))
    );
    assert_eq!(q["client_id"], CLIENT);
    assert_eq!(q["redirect_uri"], format!("{BASE}/ui/callback"));
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(q["scope"].contains("groups"));
    let mut claims = s.provider.claims(&q["nonce"]);
    tweak(&mut claims);
    let token = match sign {
        Some(f) => f(&claims),
        None => sign_rs256(&s.provider.rsa, "k1", &claims),
    };
    s.provider.will_issue(token);
    let state = tamper_state.unwrap_or(&q["state"]).to_owned();
    let uri = format!(
        "/ui/callback?code=c0de&state={}",
        url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
    );
    send(
        &s.app,
        "GET",
        &uri,
        &[("cookie", &cookie_header(&[(LOGIN_COOKIE, &login)]))],
        None,
    )
    .await
}

/// Signs in; returns the session's cookie header and CSRF token.
async fn session(s: &Setup) -> (String, String) {
    let done = sign_in(s, |_| {}, None, None).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert_eq!(done.location(), "/ui/");
    assert!(
        done.set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{LOGIN_COOKIE}=")) && c.contains("Max-Age=0"))
    );
    let cookie = cookie_header(&[(SESSION_COOKIE, &done.cookie(SESSION_COOKIE).unwrap())]);
    let info = send(&s.app, "GET", "/ui/session", &[("cookie", &cookie)], None).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.headers["cache-control"], "no-store");
    (cookie, info.json()["csrf"].as_str().unwrap().to_owned())
}

#[sqlx::test(migrations = "../store/migrations")]
async fn signing_in_gives_a_session_that_sets_agents_up(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let (cookie, csrf) = session(&s).await;
    let info = send(&s.app, "GET", "/ui/session", &[("cookie", &cookie)], None).await;
    assert_eq!(info.json()["user"], "jrt");
    // PKCE: the verifier sent to the token endpoint, and no client secret.
    let forms = s.provider.state.lock().unwrap().token_forms.clone();
    let sent = &forms[0];
    assert_eq!(sent["grant_type"], "authorization_code");
    assert_eq!(sent["client_id"], CLIENT);
    assert_eq!(sent["code"], "c0de");
    assert!(sent["code_verifier"].len() > 40);
    assert!(!sent.contains_key("client_secret"));

    let page = send(&s.app, "GET", "/ui/", &[("cookie", &cookie)], None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("app.js"));
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self'"));
    assert_eq!(page.headers["x-content-type-options"], "nosniff");
    assert_eq!(page.headers["referrer-policy"], "no-referrer");

    let list = send(&s.app, "GET", "/admin/agents", &[("cookie", &cookie)], None).await;
    assert_eq!(
        (list.status, list.json()["by"].clone()),
        (StatusCode::OK, json!("jrt"))
    );
    let made = send(
        &s.app,
        "POST",
        "/admin/agents",
        &[("cookie", &cookie), (CSRF_HEADER, &csrf)],
        Some(("application/json", "{}".into())),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_change_needs_the_csrf_token(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let (cookie, csrf) = session(&s).await;
    let post =
        async |headers: &[(&str, &str)]| send(&s.app, "POST", "/admin/agents", headers, None).await;
    let none = post(&[("cookie", &cookie)]).await;
    assert_eq!(
        (none.status, none.json()["detail"].clone()),
        (StatusCode::FORBIDDEN, json!("missing or wrong CSRF token"))
    );
    assert_eq!(
        post(&[("cookie", &cookie), (CSRF_HEADER, "guess")])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    // A non-ASCII header is a 403, not a 500 (Bug-B3).
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("host", "broker.test")
        .header("cookie", &cookie)
        .header(CSRF_HEADER, "gu\u{e9}ss".as_bytes())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        s.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&[("cookie", &cookie), (CSRF_HEADER, &csrf)])
            .await
            .status,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_session_is_not_the_admin_token(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let (cookie, csrf) = session(&s).await;
    for (method, path) in [
        ("POST", "/admin/requests/some-id/decide"),
        ("POST", "/admin/hosts/recusant/arm"),
        ("POST", "/admin/hosts/recusant/disarm"),
        ("POST", "/admin/unlock"),
        ("POST", "/admin/lockdown"),
        ("POST", "/admin/agents/some-id/set-webhook"),
        ("POST", "/admin/agents/some-id/rotate-lldap-password"),
    ] {
        let r = send(
            &s.app,
            method,
            path,
            &[("cookie", &cookie), (CSRF_HEADER, &csrf)],
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}");
        assert!(r.json()["detail"].as_str().unwrap().contains("admin panel"));
        let r = send(&s.app, method, path, &[("authorization", ADMIN)], None).await;
        assert_eq!(
            (r.status, r.json()["by"].clone()),
            (StatusCode::OK, json!("admin token"))
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn only_the_admin_group_gets_in(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let done = sign_in(
        &s,
        |c| c["groups"] = json!(["searxng-users", "admin"]),
        None,
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::FORBIDDEN);
    assert!(
        done.body
            .contains("jrt is not in the group agent-auth-admins")
    );
    assert!(done.cookie(SESSION_COOKIE).is_none());
    // No groups anywhere.
    s.provider.state.lock().unwrap().userinfo =
        json!({"sub": "sub-1", "preferred_username": "jrt"});
    let done = sign_in(
        &s,
        |c| {
            c.as_object_mut().unwrap().remove("groups");
        },
        None,
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::FORBIDDEN);
    assert!(done.cookie(SESSION_COOKIE).is_none());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn groups_may_come_from_userinfo(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let done = sign_in(
        &s,
        |c| {
            let m = c.as_object_mut().unwrap();
            m.remove("groups");
            m.remove("preferred_username");
        },
        None,
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    // Userinfo must speak of the same subject.
    s.provider.state.lock().unwrap().userinfo = json!({"sub": "someone-else", "groups": [GROUP]});
    let done = sign_in(
        &s,
        |c| {
            c.as_object_mut().unwrap().remove("groups");
        },
        None,
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::FORBIDDEN);
    assert!(done.body.contains("the provider did not say who signed in"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_id_token_that_does_not_check_out_is_refused(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let expect_refused = |r: &Resp| {
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
        assert!(
            r.body
                .contains("the provider&#x27;s ID token did not check out"),
            "{}",
            r.body
        );
        assert!(r.cookie(SESSION_COOKIE).is_none());
    };
    expect_refused(&sign_in(&s, |c| c["aud"] = json!("another-client"), None, None).await);
    expect_refused(&sign_in(&s, |c| c["iss"] = json!("https://evil.test"), None, None).await);
    let past = OffsetDateTime::now_utc().unix_timestamp() - 60;
    expect_refused(&sign_in(&s, |c| c["exp"] = json!(past), None, None).await);
    expect_refused(
        &sign_in(
            &s,
            |c| {
                c.as_object_mut().unwrap().remove("iat");
            },
            None,
            None,
        )
        .await,
    );
    // Signed by a key the provider does not publish, under its kid and not.
    let forger = ec_pair();
    let as_k1 = |c: &Value| sign_es256(&forger, "k1", c);
    expect_refused(&sign_in(&s, |_| {}, Some(&as_k1), None).await);
    let as_k9 = |c: &Value| sign_es256(&forger, "k9", c);
    expect_refused(&sign_in(&s, |_| {}, Some(&as_k9), None).await);
    // alg none.
    let none = |c: &Value| format!("{}.", signing_input(&json!({"alg": "none"}), c));
    expect_refused(&sign_in(&s, |_| {}, Some(&none), None).await);

    // A rotated key the provider now publishes (ES256): fetched again once.
    let new_key = Arc::new(ec_pair());
    {
        let mut st = s.provider.state.lock().unwrap();
        let rsa = st.jwks["keys"][0].clone();
        st.jwks = json!({"keys": [rsa, ec_jwk(&new_key, "k2")]});
    }
    let k2 = |c: &Value| sign_es256(&new_key, "k2", c);
    let ok = sign_in(&s, |_| {}, Some(&k2), None).await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_return_must_answer_the_sign_in_that_was_started(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let wrong_state = sign_in(&s, |_| {}, None, Some("another-state")).await;
    assert_eq!(wrong_state.status, StatusCode::FORBIDDEN);
    assert!(wrong_state.body.contains("not started here"));
    // An ID token minted for another sign-in (its nonce) is not replayed
    // into this one.
    let replayed = sign_in(&s, |c| c["nonce"] = json!("another-nonce"), None, None).await;
    assert_eq!(replayed.status, StatusCode::FORBIDDEN);
    assert!(replayed.body.contains("different sign-in"));
    // No login cookie at all (a callback opened cold).
    let cold = send(&s.app, "GET", "/ui/callback?code=c&state=s", &[], None).await;
    assert_eq!(cold.status, StatusCode::FORBIDDEN);
    // The provider said no.
    let said_no = send(&s.app, "GET", "/ui/callback?error=access_denied", &[], None).await;
    assert_eq!(said_no.status, StatusCode::FORBIDDEN);
    assert!(
        said_no
            .body
            .contains("The provider refused the sign-in (access_denied).")
    );
    // The token endpoint refused the code.
    s.provider.state.lock().unwrap().token_status = 400;
    let refused = sign_in(&s, |_| {}, None, None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.body.contains("the provider refused the sign-in"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_provider_naming_another_issuer_is_not_used(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    s.provider.state.lock().unwrap().issuer_claim = Some("https://evil.test".into());
    let start = send(&s.app, "GET", "/ui/login", &[], None).await;
    assert_eq!(start.status, StatusCode::BAD_GATEWAY);
    assert!(start.body.contains("names another issuer"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn without_a_session(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let page = send(&s.app, "GET", "/ui/", &[], None).await;
    assert_eq!(
        (page.status, page.location()),
        (StatusCode::SEE_OTHER, "/ui/login".to_owned())
    );
    assert_eq!(
        send(&s.app, "GET", "/ui/session", &[], None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &[], None).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A header a proxy might add proves nothing.
    let forged = [
        ("remote-user", "jrt"),
        ("remote-groups", GROUP),
        ("x-forwarded-user", "jrt"),
    ];
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &forged, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Nor a cookie this broker did not seal, or garbage.
    let now = OffsetDateTime::now_utc();
    let session = Session {
        user: "jrt".into(),
        csrf: "x".into(),
        exp: now.unix_timestamp() + 600,
    };
    let other = Sealer::new(&b64url_encode(&[9u8; 32])).unwrap();
    let stolen = other.seal(Kind::Session, &session, now).unwrap();
    for bad in [stolen.as_str(), "garbage"] {
        let c = cookie_header(&[(SESSION_COOKIE, bad)]);
        assert_eq!(
            send(&s.app, "GET", "/admin/agents", &[("cookie", &c)], None)
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    // Ours, tampered with.
    let ours = Sealer::new(&encryption_key()).unwrap();
    let good = ours.seal(Kind::Session, &session, now).unwrap();
    let c = cookie_header(&[(SESSION_COOKIE, &good)]);
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &[("cookie", &c)], None)
            .await
            .status,
        StatusCode::OK
    );
    let mut bytes = good.into_bytes();
    let i = bytes.len() / 2;
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let c = cookie_header(&[(SESSION_COOKIE, &tampered)]);
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &[("cookie", &c)], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // A login cookie is not a session.
    let start = send(&s.app, "GET", "/ui/login", &[], None).await;
    let login = start.cookie(LOGIN_COOKIE).unwrap();
    let c = cookie_header(&[(SESSION_COOKIE, &login)]);
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &[("cookie", &c)], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // A session past its exp.
    let old = Session {
        exp: now.unix_timestamp() - 1,
        ..session
    };
    let c = cookie_header(&[(
        SESSION_COOKIE,
        &ours.seal(Kind::Session, &old, now).unwrap(),
    )]);
    assert_eq!(
        send(&s.app, "GET", "/admin/agents", &[("cookie", &c)], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_session_ends(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let panel = s.state.web.panel.clone().unwrap();
    let now = OffsetDateTime::now_utc();
    let live = panel.seal_session("jrt", now).unwrap();
    assert_eq!(panel.open_session(&live, now).unwrap().user, "jrt");
    assert!(
        panel
            .open_session(
                &live,
                now + time::Duration::hours(8) + time::Duration::seconds(1)
            )
            .is_none()
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn signing_out(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let (cookie, csrf) = session(&s).await;
    assert_eq!(
        send(&s.app, "POST", "/ui/logout", &[("cookie", &cookie)], None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let out = send(
        &s.app,
        "POST",
        "/ui/logout",
        &[("cookie", &cookie), (CSRF_HEADER, &csrf)],
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(
        out.set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{SESSION_COOKIE}=")) && c.contains("Max-Age=0"))
    );
    assert_eq!(
        send(&s.app, "GET", "/ui/logout", &[], None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn no_panel_unless_enabled(pool: sqlx::PgPool) {
    let s = setup(pool, false, false).await;
    for path in ["/ui", "/ui/", "/ui/login", "/ui/app.js", "/ui/session"] {
        assert_eq!(
            send(&s.app, "GET", path, &[], None).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        send(
            &s.app,
            "GET",
            "/admin/agents",
            &[("authorization", ADMIN)],
            None
        )
        .await
        .status,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_pages_files(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let js = send(&s.app, "GET", "/ui/app.js", &[], None).await;
    assert_eq!(js.status, StatusCode::OK);
    assert!(
        js.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
    for bad in ["innerHTML", "insertAdjacentHTML", "document.write"] {
        assert!(!js.body.contains(bad));
    }
    let css = send(&s.app, "GET", "/ui/app.css", &[], None).await;
    assert!(
        css.status == StatusCode::OK
            && css.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/css")
    );
    assert_eq!(
        send(&s.app, "GET", "/ui/index.html", &[], None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&s.app, "GET", "/ui/..%2fmain.py", &[], None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_panel_is_served_at_its_own_address_only(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let (cookie, _) = session(&s).await;
    let get = async |headers: &[(&str, &str)], path: &str| {
        send(&s.app, "GET", path, headers, None).await.status
    };
    assert_eq!(
        get(
            &[("cookie", &cookie), ("host", "broker.test")],
            "/admin/agents"
        )
        .await,
        StatusCode::OK
    );
    // The default port is the same address (Bug-B2).
    assert_eq!(
        get(
            &[("cookie", &cookie), ("host", "broker.test:443")],
            "/admin/agents"
        )
        .await,
        StatusCode::OK
    );
    // Forwarded by a proxy for another host.
    let via = [
        ("cookie", cookie.as_str()),
        ("x-forwarded-host", "agent-auth.public.test"),
    ];
    assert_eq!(get(&via, "/ui/").await, StatusCode::NOT_FOUND);
    assert_eq!(get(&via, "/admin/agents").await, StatusCode::UNAUTHORIZED);
    let public = [
        ("cookie", cookie.as_str()),
        ("host", "agent-auth.public.test"),
    ];
    assert_eq!(get(&public, "/ui/login").await, StatusCode::NOT_FOUND);
    assert_eq!(
        get(&public, "/admin/agents").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(
            &[("host", "broker.test:8443"), ("cookie", &cookie)],
            "/admin/agents"
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(
            &[("host", "agent-auth.public.test"), ("authorization", ADMIN)],
            "/admin/agents"
        )
        .await,
        StatusCode::OK
    );
    // Behind a local proxy that does not pass the host on.
    assert_eq!(
        get(
            &[("host", "127.0.0.1:8400"), ("cookie", &cookie)],
            "/admin/agents"
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(
            &[("host", "[::1]:8400"), ("cookie", &cookie)],
            "/admin/agents"
        )
        .await,
        StatusCode::OK
    );
}

// --------------------------------------------------------- the OAuth server

const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";

async fn register(s: &Setup, body: Value) -> Resp {
    send(
        &s.app,
        "POST",
        "/oauth/register",
        &[],
        Some(("application/json", body.to_string())),
    )
    .await
}

async fn token(s: &Setup, form: &[(&str, &str)]) -> Resp {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    send(
        &s.app,
        "POST",
        "/oauth/token",
        &[],
        Some(("application/x-www-form-urlencoded", body)),
    )
    .await
}

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Through authorize, the provider and the consent page; returns the
/// consent POST's response.
async fn authorize(s: &Setup, client: &str, name: Option<&str>, with_cookie: bool) -> Resp {
    authorize_with(s, client, name, with_cookie, "allow").await
}

async fn authorize_with(
    s: &Setup,
    client: &str,
    name: Option<&str>,
    with_cookie: bool,
    action: &str,
) -> Resp {
    let challenge = pkce_challenge(VERIFIER);
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={}&state=xyz&code_challenge={challenge}&code_challenge_method=S256",
        url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect::<String>()
    );
    let start = send(&s.app, "GET", &uri, &[], None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
    let set = start.set_cookies();
    assert!(set.iter().any(|c| c.contains("Path=/oauth")));
    let login = start.cookie("__Secure-aa_oauth_login").unwrap();
    let q = query_of(&start.location());
    assert_eq!(q["redirect_uri"], format!("{BASE}/oauth/callback"));
    s.provider.will_issue(sign_rs256(
        &s.provider.rsa,
        "k1",
        &s.provider.claims(&q["nonce"]),
    ));
    let cb = send(
        &s.app,
        "GET",
        &format!("/oauth/callback?code=c0de&state={}", q["state"]),
        &[(
            "cookie",
            &cookie_header(&[("__Secure-aa_oauth_login", &login)]),
        )],
        None,
    )
    .await;
    assert_eq!(cb.status, StatusCode::OK, "{}", cb.body);
    let csp = cb.headers["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("form-action 'self' https://claude.ai")
            && csp.contains("frame-ancestors 'none'")
    );
    assert!(cb.body.contains("Signed in as <strong>jrt</strong>."));
    assert!(cb.body.contains("It gets no credentials."));
    let consent_nonce = cb.cookie("__Secure-aa_oauth_consent").unwrap();
    let blob = cb
        .body
        .split("name=\"consent\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let mut form = vec![("consent", blob.as_str()), ("action", action)];
    if let Some(n) = name {
        form.push(("name", n));
    }
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&form)
        .finish();
    let mut headers = vec![];
    let c = cookie_header(&[("__Secure-aa_oauth_consent", &consent_nonce)]);
    if with_cookie {
        headers.push(("cookie", c.as_str()));
    }
    send(
        &s.app,
        "POST",
        "/oauth/consent",
        &headers,
        Some(("application/x-www-form-urlencoded", body)),
    )
    .await
}

async fn new_client(s: &Setup, body: Value) -> (String, Option<String>) {
    let r = register(s, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.headers["cache-control"], "no-store");
    let j = r.json();
    (
        j["client_id"].as_str().unwrap().to_owned(),
        j["client_secret"].as_str().map(str::to_owned),
    )
}

/// A code for a public client named "Claude".
async fn code_for(s: &Setup) -> (String, String) {
    let (client, _) = new_client(
        s,
        json!({"redirect_uris": [REDIRECT], "client_name": "Claude"}),
    )
    .await;
    let done = authorize(s, &client, None, true).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    let q = query_of(&done.location());
    assert!(done.location().starts_with(REDIRECT));
    assert_eq!((q["state"].as_str(), q["iss"].as_str()), ("xyz", BASE));
    (client, q["code"].clone())
}

async fn me_with(s: &Setup, token: &str) -> Resp {
    send(
        &s.app,
        "GET",
        "/v1/me",
        &[("authorization", &format!("Bearer {token}"))],
        None,
    )
    .await
}

#[sqlx::test(migrations = "../store/migrations")]
async fn discovery_documents(pool: sqlx::PgPool) {
    let s = setup(pool.clone(), false, true).await;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let r = send(&s.app, "GET", path, &[], None).await;
        assert_eq!(
            r.json(),
            json!({"resource": "https://broker.test/mcp", "authorization_servers": ["https://broker.test"],
                   "bearer_methods_supported": ["header"], "resource_name": "agent-auth"})
        );
    }
    let r = send(
        &s.app,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        None,
    )
    .await;
    assert_eq!(
        r.json(),
        json!({"issuer": BASE, "authorization_endpoint": "https://broker.test/oauth/authorize",
               "token_endpoint": "https://broker.test/oauth/token",
               "registration_endpoint": "https://broker.test/oauth/register",
               "revocation_endpoint": "https://broker.test/oauth/revoke",
               "response_types_supported": ["code"],
               "grant_types_supported": ["authorization_code", "refresh_token"],
               "code_challenge_methods_supported": ["S256"],
               "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
               "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
               "authorization_response_iss_parameter_supported": true, "scopes_supported": []})
    );
    // Off: nothing of it.
    let off = setup(pool, true, false).await;
    for (m, p) in [
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("POST", "/oauth/register"),
        ("GET", "/oauth/authorize"),
        ("POST", "/oauth/token"),
        ("POST", "/mcp"),
    ] {
        assert_eq!(
            send(&off.app, m, p, &[], None).await.status,
            StatusCode::NOT_FOUND,
            "{p}"
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn registration(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    // Exact callbacks only: another path, port, case, scheme or a query
    // on an allowed host is refused.
    for uri in [
        "https://evil.test/cb",
        "http://claude.ai/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback#frag",
        "https://claude.ai/api/mcp/auth_callback?x=1",
        "https://claude.ai:8443/api/mcp/auth_callback",
        "https://Claude.AI/api/mcp/auth_callback",
        "https://claude.ai/cb",
        "not a url",
        // Userinfo, backslashes, whitespace (upstream review 2026-10).
        "https://evil.example\\@claude.ai/api/mcp/auth_callback",
        "https://u@claude.ai/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback ",
    ] {
        let r = register(&s, json!({"redirect_uris": [uri]})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(r.json()["error"], "invalid_redirect_uri");
        assert_eq!(
            r.json()["error_description"],
            "this broker sends the browser back only to https://claude.ai/api/mcp/auth_callback, \
https://claude.com/api/mcp/auth_callback, https://chatgpt.com/connector_platform_oauth_redirect, \
https://claude.ai/other"
        );
    }
    // Longer than the column took in the Python (a 500 there; Bug-C7).
    let long = format!("https://claude.ai/{}", "x".repeat(600));
    let r = register(&s, json!({"redirect_uris": [long]})).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_redirect_uri"))
    );
    let r = register(
        &s,
        json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "private_key_jwt"}),
    )
    .await;
    assert_eq!(r.json()["error"], "invalid_client_metadata");
    let (_, secret) = new_client(
        &s,
        json!({"redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"]}),
    )
    .await;
    assert!(secret.is_none());
    let r = register(&s, json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_post", "client_name": "C"})).await;
    let j = r.json();
    assert!(j["client_id"].as_str().unwrap().starts_with("mcpc_"));
    assert!(j["client_secret"].as_str().unwrap().len() >= 43);
    assert_eq!(j["client_secret_expires_at"], 0);
    assert_eq!(
        j["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
}

async fn register_from(s: &Setup, address: &str) -> Resp {
    send(
        &s.app,
        "POST",
        "/oauth/register",
        &[("x-real-ip", address)],
        Some((
            "application/json",
            json!({"redirect_uris": [REDIRECT]}).to_string(),
        )),
    )
    .await
}

async fn count(pool: &sqlx::PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrations = "../store/migrations")]
async fn registration_cannot_lock_connectors_out(pool: sqlx::PgPool) {
    let s = setup_with(pool.clone(), false, true, |c| c.max_clients = 2).await;
    // One address: 20 an hour, then 429.
    for _ in 0..20 {
        assert_eq!(
            register_from(&s, "203.0.113.1").await.status,
            StatusCode::CREATED
        );
    }
    let r = register_from(&s, "203.0.113.1").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        r.json()["error_description"],
        "too many registrations from this address; try again later"
    );
    // Many addresses: registrations nobody authorized evict each other
    // (at most 20 kept); they never fill max_clients.
    for i in 0..30 {
        let r = register_from(&s, &format!("198.51.100.{i}")).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    assert_eq!(count(&pool, "SELECT count(*) FROM oauth_clients").await, 20);
    // max_clients counts authorized clients.
    code_for(&s).await;
    code_for(&s).await;
    let full = register_from(&s, "192.0.2.9").await;
    assert_eq!(
        full.json()["error_description"],
        "too many registered clients; the operator can revoke some"
    );
    // An hour later, the unauthorized ones are gone.
    sqlx::query("UPDATE oauth_clients SET created_at = created_at - interval '2 hours' WHERE agent_id IS NULL")
        .execute(&pool)
        .await
        .unwrap();
    let s2 = setup_with(pool.clone(), false, true, |c| c.max_clients = 3).await;
    assert_eq!(
        register_from(&s2, "192.0.2.10").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM oauth_clients WHERE agent_id IS NULL"
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn authorization_errors_are_pages(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, _) = new_client(
        &s,
        json!({"redirect_uris": [REDIRECT, "https://claude.ai/other"]}),
    )
    .await;
    let challenge = pkce_challenge(VERIFIER);
    let page =
        async |q: String| send(&s.app, "GET", &format!("/oauth/authorize?{q}"), &[], None).await;
    let enc = |u: &str| url::form_urlencoded::byte_serialize(u.as_bytes()).collect::<String>();
    let r = page(format!("response_type=code&client_id={client}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=plain", enc(REDIRECT))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body.contains(
            "<h1>Can't connect</h1><p>PKCE with code_challenge_method=S256 is required</p>"
        ),
        "{}",
        r.body
    );
    assert!(r.headers.get("location").is_none());
    let r = page(format!("response_type=code&client_id={client}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256", enc("https://claude.ai/elsewhere"))).await;
    assert!(
        r.status == StatusCode::BAD_REQUEST
            && r.body
                .contains("redirect_uri is not one this client registered")
    );
    // Two registered: the parameter is needed.
    let r = page(format!("response_type=code&client_id={client}&code_challenge={challenge}&code_challenge_method=S256")).await;
    assert!(
        r.body
            .contains("redirect_uri is not one this client registered")
    );
    let r = page(format!("response_type=token&client_id={client}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256", enc(REDIRECT))).await;
    assert!(r.body.contains("only response_type=code"));
    let r = page("response_type=code&client_id=mcpc_nope".into()).await;
    assert!(r.body.contains("unknown client"));
    let r = page(format!("response_type=code&client_id={client}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state={}", enc(REDIRECT), "s".repeat(2000))).await;
    assert!(
        r.status == StatusCode::BAD_REQUEST && r.body.contains("state: at most 1024 characters")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_connector_end_to_end(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, code) = code_for(&s).await;
    let tx = s.state.store.begin().await.unwrap();
    let agent = agents::by_name(&tx, "web-claude").await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        (agent.runtime.as_deref(), agent.kind),
        (Some("web"), AgentKind::Ephemeral)
    );
    assert!(agent.description.contains("authorized by jrt"));

    let pair = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await;
    assert_eq!(pair.status, StatusCode::OK, "{}", pair.body);
    assert_eq!(
        (
            pair.headers["cache-control"].to_str().unwrap(),
            pair.headers["pragma"].to_str().unwrap()
        ),
        ("no-store", "no-cache")
    );
    let j = pair.json();
    let access = j["access_token"].as_str().unwrap().to_owned();
    let refresh = j["refresh_token"].as_str().unwrap().to_owned();
    assert!(access.starts_with("aat_") && refresh.starts_with("art_"));
    assert_eq!(
        (j["token_type"].clone(), j["expires_in"].clone()),
        (json!("Bearer"), json!(3600))
    );
    let me = me_with(&s, &access).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        (me.json()["name"].clone(), me.json()["connector"].clone()),
        (json!("web-claude"), json!(true))
    );
    // An access token is not a refresh token, nor a code.
    let r = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &access),
            ("client_id", &client),
        ],
    )
    .await;
    assert_eq!(
        r.json()["error_description"],
        "unknown or expired refresh token"
    );

    // The code again: refused, and what it gave is revoked.
    let again = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        again.json(),
        json!({"error": "invalid_grant", "error_description": "this code was already used"})
    );
    assert_eq!(me_with(&s, &access).await.status, StatusCode::UNAUTHORIZED);
    let r = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client),
        ],
    )
    .await;
    assert_eq!(
        r.json()["error_description"],
        "unknown or expired refresh token"
    );

    // A second authorization: the same agent, as before.
    let done = authorize(&s, &client, None, true).await;
    let code2 = query_of(&done.location())["code"].clone();
    let j = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code2),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
    .json();
    let (a1, r1) = (
        j["access_token"].as_str().unwrap().to_owned(),
        j["refresh_token"].as_str().unwrap().to_owned(),
    );
    // Refresh rotates.
    let j = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &r1),
            ("client_id", &client),
        ],
    )
    .await
    .json();
    let (a2, r2) = (
        j["access_token"].as_str().unwrap().to_owned(),
        j["refresh_token"].as_str().unwrap().to_owned(),
    );
    assert_ne!(r1, r2);
    assert_eq!(
        me_with(&s, &a1).await.status,
        StatusCode::OK,
        "rotation leaves the old access token to its TTL"
    );
    assert_eq!(me_with(&s, &a2).await.status, StatusCode::OK);
    // Another client's refresh token is not this one's.
    let (other, _) = new_client(&s, json!({"redirect_uris": [REDIRECT]})).await;
    let r = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &r2),
            ("client_id", &other),
        ],
    )
    .await;
    assert_eq!(
        r.json()["error_description"],
        "unknown or expired refresh token"
    );
    // The old refresh token again: the whole family goes.
    let r = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &r1),
            ("client_id", &client),
        ],
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error_description"].clone()),
        (
            StatusCode::BAD_REQUEST,
            json!("refresh token reused; sign in again")
        )
    );
    for t in [&a1, &a2] {
        assert_eq!(me_with(&s, t).await.status, StatusCode::UNAUTHORIZED);
    }
    let r = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &r2),
            ("client_id", &client),
        ],
    )
    .await;
    assert_eq!(
        r.json()["error_description"],
        "unknown or expired refresh token"
    );
    let r = token(&s, &[("grant_type", "password"), ("client_id", &client)]).await;
    assert_eq!(r.json()["error"], "unsupported_grant_type");
    let r = token(
        &s,
        &[("grant_type", "refresh_token"), ("client_id", "mcpc_nope")],
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("invalid_client"))
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn pkce_redirect_and_consent_checks(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, code) = code_for(&s).await;
    let r = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", "wrong-verifier"),
        ],
    )
    .await;
    assert_eq!(r.json()["error_description"], "PKCE verification failed");
    // Used now, even though it failed.
    let r = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(r.json()["error_description"], "this code was already used");

    let done = authorize(&s, &client, None, true).await;
    let code = query_of(&done.location())["code"].clone();
    let r = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
            ("redirect_uri", "https://claude.ai/other"),
        ],
    )
    .await;
    assert_eq!(
        r.json()["error_description"],
        "redirect_uri differs from the authorization's"
    );

    // A consent POST without the consent cookie.
    let r = authorize(&s, &client, None, false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body
            .contains("This approval expired or didn&#x27;t start in this browser")
    );

    // A confidential client must authenticate.
    let (conf, secret) = new_client(&s, json!({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic", "client_name": "Claude"})).await;
    let done = authorize(&s, &conf, None, true).await;
    let code = query_of(&done.location())["code"].clone();
    let r = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &conf),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error_description"].clone()),
        (
            StatusCode::UNAUTHORIZED,
            json!("client authentication failed")
        )
    );
    let basic = base64_basic(&conf, &secret.unwrap());
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", VERIFIER),
        ])
        .finish();
    let r = send(
        &s.app,
        "POST",
        "/oauth/token",
        &[("authorization", &basic)],
        Some(("application/x-www-form-urlencoded", body)),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

fn base64_basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

#[sqlx::test(migrations = "../store/migrations")]
async fn deny_sends_access_denied(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, _) = new_client(&s, json!({"redirect_uris": [REDIRECT]})).await;
    let done = authorize_with(&s, &client, None, true, "deny").await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert_eq!(
        done.location(),
        format!("{REDIRECT}?error=access_denied&state=xyz&iss=https%3A%2F%2Fbroker.test")
    );
    assert!(
        done.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Secure-aa_oauth_consent=") && c.contains("Max-Age=0"))
    );
    // Nothing was bound or issued.
    let tx = s.state.store.begin().await.unwrap();
    assert!(
        agents::by_name(&tx, "web-connector")
            .await
            .unwrap()
            .is_none()
    );
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_connector_cannot_take_a_non_web_agents_name(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let key = api_key::generate().unwrap();
    let tx = s.state.store.begin().await.unwrap();
    agents::insert(
        &tx,
        &agents::NewAgent {
            id: AgentId::new(),
            name: "web-hermes",
            description: "",
            key_id: key.key_id.as_str(),
            api_key_hash: key.hash.as_str(),
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: Some("hermes"),
            project: None,
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: OffsetDateTime::now_utc(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (client, _) = new_client(&s, json!({"redirect_uris": [REDIRECT]})).await;
    let r = authorize(&s, &client, Some("hermes"), true).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body
            .contains("web-hermes exists and is not a web connector&#x27;s agent"),
        "{}",
        r.body
    );
    let r = authorize(&s, &client, Some("-bad name-"), true).await;
    assert_eq!(
        r.status,
        StatusCode::SEE_OTHER,
        "normalized to web-bad-name"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_exchanges_of_one_code(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, code) = code_for(&s).await;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ])
        .finish();
    let tries = (0..8).map(|_| {
        let app = s.app.clone();
        let form = form.clone();
        tokio::spawn(async move {
            send(
                &app,
                "POST",
                "/oauth/token",
                &[],
                Some(("application/x-www-form-urlencoded", form)),
            )
            .await
            .status
        })
    });
    let statuses: Vec<StatusCode> = futures::future::join_all(tries)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::OK || *s == StatusCode::BAD_REQUEST)
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_operator_lists_and_revokes_connectors(pool: sqlx::PgPool) {
    let s = setup(pool, true, true).await;
    let (client, code) = code_for(&s).await;
    let j = token(
        &s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
    .json();
    let access = j["access_token"].as_str().unwrap().to_owned();
    let list = send(
        &s.app,
        "GET",
        "/admin/connectors",
        &[("authorization", ADMIN)],
        None,
    )
    .await;
    let items = list.json();
    assert_eq!(items[0]["agent"], "web-claude");
    assert_eq!(items[0]["live_authorizations"], 1);
    assert_eq!(
        send(&s.app, "GET", "/admin/connectors", &[], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // The panel may revoke (on its list), with CSRF.
    let (cookie, csrf) = session(&s).await;
    let path = format!("/admin/connectors/{client}/revoke");
    let r = send(
        &s.app,
        "POST",
        &path,
        &[("cookie", &cookie), (CSRF_HEADER, &csrf)],
        None,
    )
    .await;
    assert_eq!(
        (r.status, r.json()),
        (StatusCode::OK, json!({"revoked": client}))
    );
    assert_eq!(me_with(&s, &access).await.status, StatusCode::UNAUTHORIZED);
    let r = send(
        &s.app,
        "POST",
        "/admin/connectors/mcpc_nope/revoke",
        &[("authorization", ADMIN)],
        None,
    )
    .await;
    assert_eq!(
        (r.status, r.json()["detail"].clone()),
        (StatusCode::NOT_FOUND, json!("no such connector"))
    );
    new_client(&s, json!({"redirect_uris": [REDIRECT]})).await;
    // Revoking a token at /oauth/revoke ends its authorization.
    let done = authorize(
        &s,
        &new_client(
            &s,
            json!({"redirect_uris": [REDIRECT], "client_name": "Claude"}),
        )
        .await
        .0,
        None,
        true,
    )
    .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
}

// ------------------------------------------------------------- /mcp

async fn mcp(s: &Setup, token: Option<&str>, body: Value) -> Resp {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers = vec![
        ("accept", "application/json, text/event-stream"),
        ("host", "broker.test"),
    ];
    if let Some(a) = &auth {
        headers.push(("authorization", a.as_str()));
    }
    send(
        &s.app,
        "POST",
        "/mcp",
        &headers,
        Some(("application/json", body.to_string())),
    )
    .await
}

async fn connector_tokens(s: &Setup) -> (String, String, String) {
    let (client, code) = code_for(s).await;
    let j = token(
        s,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
    .json();
    (
        client,
        j["access_token"].as_str().unwrap().to_owned(),
        j["refresh_token"].as_str().unwrap().to_owned(),
    )
}

fn call_body(id: u32, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn tool_text(r: &Resp) -> String {
    let j = r.json();
    assert!(j["error"].is_null(), "{}", r.body);
    j["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", r.body))
        .to_owned()
}

#[sqlx::test(migrations = "../store/migrations")]
async fn mcp_needs_a_live_access_token(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    for token in [None, Some("aat_nope"), Some("aa_123456789abc_x")] {
        let r = mcp(
            &s,
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            r.headers["www-authenticate"],
            "Bearer resource_metadata=\"https://broker.test/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(r.headers["content-type"], "application/json");
        assert_eq!(
            r.json(),
            json!({"error": "invalid_token", "error_description": "sign in to use this server"})
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn mcp_tools_end_to_end(pool: sqlx::PgPool) {
    let s = setup(pool, false, true).await;
    let (client, access, refresh) = connector_tokens(&s).await;

    let init = mcp(&s, Some(&access), json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})).await;
    assert_eq!(init.status, StatusCode::OK, "{}", init.body);
    assert_eq!(
        init.json()["result"]["instructions"],
        agent_auth_broker::remote_mcp::INSTRUCTIONS
    );

    let list = mcp(
        &s,
        Some(&access),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let tools = list.json()["result"]["tools"].as_array().unwrap().clone();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, agent_auth_core::policy::REMOTE_MCP_TOOLS.to_vec());
    assert!(!names.contains(&"get_credential") && !names.contains(&"host_run"));
    let wait = tools
        .iter()
        .find(|t| t["name"] == "wait_for_decision")
        .unwrap();
    assert!(
        wait["description"]
            .as_str()
            .unwrap()
            .ends_with("decisions and replies often take longer.")
    );
    assert_eq!(wait["inputSchema"]["required"], json!(["request_id"]));
    assert_eq!(
        wait["inputSchema"]["properties"]["timeout_secs"]["default"],
        json!(120) // the Python's pydantic schema: the default as written, an int
    );

    // whoami reaches the agent API as the connector, with its own token.
    let r = mcp(&s, Some(&access), call_body(3, "whoami", json!({}))).await;
    let me: Value = serde_json::from_str(&tool_text(&r)).unwrap();
    assert_eq!(
        (
            me["name"].clone(),
            me["connector"].clone(),
            me["session"].clone()
        ),
        (json!("web-claude"), json!(true), Value::Null)
    );

    // A wait is capped at 50 s and says so.
    let r = mcp(
        &s,
        Some(&access),
        call_body(4, "wait_for_decision", json!({"request_id": "r-1"})),
    )
    .await;
    let out: Value = serde_json::from_str(&tool_text(&r)).unwrap();
    assert_eq!(out["status"], "denied");
    assert!(
        out["rerun"]
            .as_str()
            .unwrap()
            .contains("call wait_for_decision again")
    );
    let seen = s.waits.lock().unwrap().clone();
    assert!(
        seen[0].starts_with("timeout=50") || seen[0].starts_with("timeout=49"),
        "{seen:?}"
    );

    // Unknown tools, tools not served, bad arguments.
    let r = mcp(
        &s,
        Some(&access),
        call_body(5, "get_credential", json!({"grant_id": "g"})),
    )
    .await;
    assert_eq!(r.json()["result"]["isError"], true);
    let r = mcp(&s, Some(&access), call_body(6, "check_status", json!({}))).await;
    assert_eq!(r.json()["result"]["isError"], true);
    // The agent API answers in process.
    let r = mcp(&s, Some(&access), call_body(7, "list_grants", json!({}))).await;
    assert!(tool_text(&r).contains("\"status\": \"done\""));

    // a2a without a session_key: one session minted for this authorization,
    // kept across calls and across a refresh (Bug-C4).
    let r = mcp(&s, Some(&access), call_body(8, "a2a_threads", json!({}))).await;
    let first: Value = serde_json::from_str(&tool_text(&r)).unwrap();
    let session = first["session"].as_str().unwrap().to_owned();
    let r = mcp(&s, Some(&access), call_body(9, "a2a_threads", json!({}))).await;
    assert_eq!(
        serde_json::from_str::<Value>(&tool_text(&r)).unwrap()["session"],
        session.as_str()
    );
    let j = token(
        &s,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client),
        ],
    )
    .await
    .json();
    let access2 = j["access_token"].as_str().unwrap().to_owned();
    let r = mcp(&s, Some(&access2), call_body(10, "a2a_threads", json!({}))).await;
    assert_eq!(
        serde_json::from_str::<Value>(&tool_text(&r)).unwrap()["session"],
        session.as_str()
    );
    // A session the caller names is used as named.
    let r = mcp(
        &s,
        Some(&access2),
        call_body(11, "a2a_threads", json!({"session_key": "not-a-session"})),
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&tool_text(&r)).unwrap()["error"],
        "unknown or closed session"
    );
    // The broker closed the minted session: a new one, once.
    let tx = s.state.store.begin().await.unwrap();
    sessions::close(
        &tx,
        session.parse().unwrap(),
        sessions::SessionCloseReason::Closed,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let r = mcp(&s, Some(&access2), call_body(12, "a2a_threads", json!({}))).await;
    let fresh = serde_json::from_str::<Value>(&tool_text(&r)).unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(fresh, session);
    // create_session runs as the connector (Bug-C3).
    let r = mcp(
        &s,
        Some(&access2),
        call_body(13, "create_session", json!({"label": "chat"})),
    )
    .await;
    assert!(
        serde_json::from_str::<Value>(&tool_text(&r)).unwrap()["name"]
            .as_str()
            .unwrap()
            .starts_with("chat-")
    );
}

// -------------------------------------------- what a connector's token reaches

#[sqlx::test(migrations = "../store/migrations")]
async fn a_connector_token_reaches_only_its_tools_routes(pool: sqlx::PgPool) {
    let s = setup(pool.clone(), false, true).await;
    let (_, access, _) = connector_tokens(&s).await;
    let auth = format!("Bearer {access}");
    let call = async |method: &str, path: &str| {
        send(
            &s.app,
            method,
            path,
            &[("authorization", &auth)],
            Some(("application/json", "{}".into())),
        )
        .await
    };
    assert_eq!(call("GET", "/v1/me").await.status, StatusCode::OK);
    assert_eq!(call("GET", "/v1/a2a/threads").await.status, StatusCode::OK);
    for (m, p) in [
        ("PUT", "/v1/wiki/page"),
        ("POST", "/v1/wiki/delete"),
        ("GET", "/v1/grants/g-1/credential"),
        ("POST", "/v1/hostexec/shells/g/exec"),
        ("GET", "/v1/a2a/events"),
        ("GET", "/v1/me/"),
        ("GET", "/v1/some-route-added-later"),
    ] {
        let r = call(m, p).await;
        assert_eq!(
            (r.status, r.json()["detail"].clone()),
            (
                StatusCode::FORBIDDEN,
                json!("not available to a web UI connector")
            ),
            "{m} {p}"
        );
    }
    // What the operator adds to remote_mcp.tools, the token reaches.
    let wide = setup_with(pool, false, true, |c| c.tools.push("wiki_write".into())).await;
    let (_, access, _) = connector_tokens(&wide).await;
    let r = send(
        &wide.app,
        "PUT",
        "/v1/wiki/page",
        &[("authorization", &format!("Bearer {access}"))],
        Some(("application/json", "{}".into())),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// A value of each required parameter, and no wait.
fn arguments_for(def: &agent_auth_wire::mcp_tools::ToolDef) -> Value {
    use agent_auth_wire::mcp_tools::{DefaultValue, Ty};
    let mut args = serde_json::Map::new();
    for p in def.params {
        if agent_auth_wire::mcp_tools::wait_param(def.name) == Some(p.name) {
            args.insert(p.name.into(), json!(0));
        } else if p.default == DefaultValue::Required {
            let v = match p.ty {
                Ty::StrList => json!(["true"]),
                Ty::Obj | Ty::StrMap => json!({}),
                Ty::Int | Ty::Num => json!(1),
                Ty::Bool => json!(false),
                Ty::Str => json!("x"),
            };
            args.insert(p.name.into(), v);
        }
    }
    Value::Object(args)
}

#[sqlx::test(migrations = "../store/migrations")]
async fn every_tool_calls_only_its_routes(pool: sqlx::PgPool) {
    use agent_auth_wire::mcp_tools::{REMOTE_NEVER_SERVED, TOOLS, api_routes, route_matches};
    let s = setup_with(pool, false, true, |c| {
        c.tools = TOOLS
            .iter()
            .map(|t| t.name.to_owned())
            .filter(|n| !REMOTE_NEVER_SERVED.contains(&n.as_str()))
            .collect();
    })
    .await;
    let (_, access, _) = connector_tokens(&s).await;
    for (i, def) in TOOLS.iter().enumerate() {
        if REMOTE_NEVER_SERVED.contains(&def.name) {
            continue;
        }
        s.seen.lock().unwrap().clear();
        let r = mcp(
            &s,
            Some(&access),
            call_body(
                100 + u32::try_from(i).unwrap(),
                def.name,
                arguments_for(def),
            ),
        )
        .await;
        let text = tool_text(&r);
        assert!(
            !text.contains("not available to a web UI connector"),
            "{}: {text}",
            def.name
        );
        let seen = s.seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "{} called nothing", def.name);
        for (m, p) in &seen {
            assert!(
                api_routes(def.name)
                    .iter()
                    .any(|(rm, rp)| rm == m && route_matches(rp, p)),
                "{} called {m} {p}, not in its routes",
                def.name
            );
        }
    }
}

// ------------------------------------------------ a web agent stays web

#[sqlx::test(migrations = "../store/migrations")]
async fn a_connectors_agent_keeps_its_runtime(pool: sqlx::PgPool) {
    let s = setup(pool.clone(), false, true).await;
    code_for(&s).await;
    let tx = s.state.store.begin().await.unwrap();
    let agent = agents::by_name(&tx, "web-claude").await.unwrap().unwrap();
    tx.commit().await.unwrap();
    // The admin API refuses it (a panel session could otherwise clear the
    // runtime that keeps the connector a human's call)...
    let app = agent_auth_broker::http::router(s.state.clone());
    let r = send(
        &app,
        "PATCH",
        &format!("/admin/agents/{}/attributes", agent.id),
        &[("authorization", ADMIN)],
        Some(("application/json", json!({"runtime": "claude"}).to_string())),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert!(
        r.json()["detail"]
            .as_str()
            .unwrap()
            .contains("its runtime stays web")
    );
    let r = send(
        &app,
        "PATCH",
        &format!("/admin/agents/{}/attributes", agent.id),
        &[("authorization", ADMIN)],
        Some(("application/json", json!({"project": "x"}).to_string())),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // ... and so does the database.
    let tx = s.state.store.begin().await.unwrap();
    let e = agents::set_attributes(&tx, agent.id, None, None, None, Placement::Host)
        .await
        .unwrap_err();
    assert!(e.is_check_violation(), "{e}");
    drop(tx);
    // A client binds only to a web agent, and only once.
    let key = api_key::generate().unwrap();
    let tx = s.state.store.begin().await.unwrap();
    let other = agents::insert(
        &tx,
        &agents::NewAgent {
            id: AgentId::new(),
            name: "hermes",
            description: "",
            key_id: key.key_id.as_str(),
            api_key_hash: key.hash.as_str(),
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: Some("hermes"),
            project: None,
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: OffsetDateTime::now_utc(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for target in [other.id] {
        let r = sqlx::query("UPDATE oauth_clients SET agent_id = $1")
            .bind(uuid::Uuid::from(target))
            .execute(&pool)
            .await;
        assert!(r.is_err());
    }
    let r = sqlx::query("UPDATE oauth_clients SET agent_id = NULL")
        .execute(&pool)
        .await;
    assert!(r.is_err(), "a bound client stays bound");
}

// ------------------------------------------------------------- host check

#[sqlx::test(migrations = "../store/migrations")]
async fn no_host_no_panel(pool: sqlx::PgPool) {
    let s = setup(pool, true, false).await;
    let r = send(&s.app, "GET", "/ui/login", &[("host", "-")], None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The request target's authority stands for Host (HTTP/2 :authority).
    let r = send(
        &s.app,
        "GET",
        "https://broker.test/ui/login",
        &[("host", "-")],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = send(
        &s.app,
        "GET",
        "https://elsewhere.test/ui/login",
        &[("host", "-")],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An empty Host is no address either.
    let r = send(&s.app, "GET", "/ui/login", &[("host", "")], None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}
