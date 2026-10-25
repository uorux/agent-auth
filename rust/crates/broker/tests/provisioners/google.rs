//! Platform `google` (tests/test_google.py): tokens from a refresh token or
//! domain-wide delegation, checked against the scopes Google says it
//! issued; and the stub for brokers with no account.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_broker::provisioners::google::{
    GoogleProvisioner, GoogleStubProvisioner, GoogleTokens, scope_url,
};
use agent_auth_broker::provisioners::http::Http;
use agent_auth_broker::provisioners::{ProvisionError, Provisioner};
use agent_auth_core::policy::{GoogleConfig, Policy};
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::jwt::ServiceAccountKey;
use agent_auth_store::Store;
use base64::Engine as _;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::common::*;

const SA_KEY: &str = include_str!("../fixtures/google-sa-test-key.pem");

fn cal() -> String {
    scope_url("calendar.readonly").unwrap()
}

fn scope(short: &str) -> String {
    scope_url(short).unwrap()
}

fn form(call: &Call) -> std::collections::BTreeMap<String, String> {
    url::form_urlencoded::parse(call.raw.as_bytes())
        .into_owned()
        .collect()
}

fn token_answer(scope: &str) -> R {
    r(
        200,
        json!({"access_token": "ya29.tok", "expires_in": 3600, "scope": scope, "token_type": "Bearer"}),
    )
}

struct Setup {
    _dir: tempdir::Dir,
    config: GoogleConfig,
    fake: Fake,
}

mod tempdir {
    /// A directory removed when dropped.
    pub struct Dir(pub std::path::PathBuf);
    impl Dir {
        pub fn new() -> Dir {
            let p = std::env::temp_dir().join(format!("aa-google-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn file(&self, name: &str, text: &str) -> String {
            let p = self.0.join(name);
            std::fs::write(&p, text).unwrap();
            p.to_string_lossy().into_owned()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn config(accounts: Value) -> GoogleConfig {
    Policy::from_value(json!({"platforms": {"google": {"accounts": accounts}}}))
        .unwrap()
        .platforms()
        .google
        .clone()
}

/// An OAuth (refresh token) account `main` whose token endpoint is a fake.
async fn oauth(handler: impl Fn(&Call) -> R + Send + Sync + 'static) -> Setup {
    let fake = Fake::start(handler).await;
    let dir = tempdir::Dir::new();
    let client = dir.file(
        "client.json",
        &json!({"installed": {"client_id": "cid", "client_secret": "csec",
                              "token_uri": format!("{}/token", fake.url)}})
        .to_string(),
    );
    let refresh = dir.file("refresh", "1//refresh-token\n");
    let config = config(json!({"main": {
        "address": "Me@Example.com", "client_secret_file": client, "refresh_token_file": refresh,
    }}));
    Setup {
        _dir: dir,
        config,
        fake,
    }
}

fn tokens(s: &Setup) -> GoogleTokens {
    GoogleTokens::with_http(
        &s.config,
        Http::new().unwrap(),
        "https://unused.invalid/token",
    )
}

#[tokio::test]
async fn refresh_sends_scope_and_caches() {
    let s = oauth(|_| token_answer(&cal())).await;
    let t = tokens(&s);
    let (token, expires) = t
        .token("main", &["calendar.readonly"], true, now())
        .await
        .unwrap();
    let (again, _) = t
        .token("main", &["calendar.readonly"], true, now())
        .await
        .unwrap();
    assert_eq!(token.expose(), "ya29.tok");
    assert_eq!(again.expose(), "ya29.tok");
    assert_eq!(s.fake.calls().len(), 1);
    let call = &s.fake.calls()[0];
    assert!(call.is("POST", "/token"));
    assert_eq!(
        call.header("content-type"),
        "application/x-www-form-urlencoded"
    );
    let f = form(call);
    assert_eq!(f["grant_type"], "refresh_token");
    assert_eq!(f["refresh_token"], "1//refresh-token");
    assert_eq!(f["client_id"], "cid");
    assert_eq!(f["client_secret"], "csec");
    assert_eq!(f["scope"], cal());
    assert!(expires > now());
}

#[tokio::test]
async fn exact_refuses_wider_token_but_allows_identity() {
    let identity = format!(
        "{} openid https://www.googleapis.com/auth/userinfo.email",
        cal()
    );
    let s = oauth(move |_| token_answer(&identity)).await;
    let (token, _) = tokens(&s)
        .token("main", &["calendar.readonly"], true, now())
        .await
        .unwrap();
    assert_eq!(token.expose(), "ya29.tok");

    let wider = format!("{} {}", cal(), scope("gmail.readonly"));
    let s = oauth(move |_| token_answer(&wider)).await;
    let t = tokens(&s);
    let err = t
        .token("main", &["calendar.readonly"], true, now())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("wider than this grant"), "{err}");
    assert!(err.to_string().contains("also gmail.readonly"), "{err}");
    // The broker's own use takes a superset (from the cache).
    let (token, _) = t
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap();
    assert_eq!(token.expose(), "ya29.tok");
    assert_eq!(s.fake.calls().len(), 1);
}

#[tokio::test]
async fn missing_scope() {
    let s = oauth(|_| token_answer(&scope("gmail.readonly"))).await;
    let err = tokens(&s)
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("lacks calendar.readonly"), "{err}");
}

#[tokio::test]
async fn invalid_grant_explains_testing_status() {
    let s = oauth(|_| {
        r(
            400,
            json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}),
        )
    })
    .await;
    let err = tokens(&s)
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Testing") && err.contains("7 days"), "{err}");
    // Google's free text is logged, not shown.
    assert!(!err.contains("expired or revoked"), "{err}");
}

#[tokio::test]
async fn other_refusals_name_only_the_code() {
    let s = oauth(|_| {
        r(
            401,
            json!({"error": "invalid_client", "error_description": "<x>"}),
        )
    })
    .await;
    let err = tokens(&s)
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "google account me@example.com: token endpoint answered 401 invalid_client"
    );
}

#[tokio::test]
async fn malformed_answers_and_files_are_clean_errors() {
    let s = oauth(|_| r(200, json!({"token_type": "Bearer"}))).await;
    let err = tokens(&s)
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "google account me@example.com: no access token in the answer"
    );
    let missing = config(json!({"main": {
        "address": "a@b.example", "client_secret_file": "/nonexistent/c", "refresh_token_file": "/r",
    }}));
    let t = GoogleTokens::with_http(&missing, Http::new().unwrap(), "https://x.invalid/");
    let err = t
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "google account a@b.example: cannot read its login files (no such file)"
    );
}

#[tokio::test]
async fn a_plain_http_token_endpoint_is_refused() {
    let dir = tempdir::Dir::new();
    let client = dir.file(
        "client.json",
        &json!({"client_id": "cid", "token_uri": "http://oauth2.example/token"}).to_string(),
    );
    let refresh = dir.file("refresh", "r");
    let c = config(json!({"main": {
        "address": "a@b.example", "client_secret_file": client, "refresh_token_file": refresh,
    }}));
    let err = GoogleTokens::with_http(&c, Http::new().unwrap(), "https://x.invalid/")
        .token("main", &["calendar.readonly"], false, now())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("token_uri is not an https URL"), "{err}");
}

#[tokio::test]
async fn unknown_account() {
    let s = oauth(|_| token_answer(&cal())).await;
    let err = tokens(&s)
        .token("other", &["calendar.readonly"], false, now())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "no google account 'other'");
}

fn b64(part: &str) -> Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn domain_wide_delegation_jwt() {
    let fake = Fake::start(|_| token_answer(&cal())).await;
    let dir = tempdir::Dir::new();
    let token_uri = format!("{}/token", fake.url);
    let sa = dir.file(
        "sa.json",
        &json!({"client_email": "broker@proj.iam.gserviceaccount.com", "private_key": SA_KEY,
                "private_key_id": "kid1", "token_uri": token_uri})
        .to_string(),
    );
    let c = config(json!({"ws": {"address": "jacob@corp.example", "service_account_file": sa}}));
    let t = GoogleTokens::with_http(&c, Http::new().unwrap(), "https://x.invalid/");
    t.token("ws", &["calendar.readonly"], true, now())
        .await
        .unwrap();
    let f = form(&fake.calls()[0]);
    assert_eq!(
        f["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let parts: Vec<&str> = f["assertion"].split('.').collect();
    assert_eq!(b64(parts[0])["kid"], "kid1");
    assert_eq!(b64(parts[0])["alg"], "RS256");
    let claims = b64(parts[1]);
    assert_eq!(claims["iss"], "broker@proj.iam.gserviceaccount.com");
    assert_eq!(claims["sub"], "jacob@corp.example");
    assert_eq!(claims["scope"], cal());
    assert_eq!(claims["aud"], token_uri);
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        3600
    );
    let key = ServiceAccountKey::from_pem(SA_KEY).unwrap();
    let public = ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        key.public_key_der(),
    );
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .unwrap();
    public
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .unwrap();
}

#[tokio::test]
async fn delegation_refused_says_where_to_fix_it() {
    let fake = Fake::start(|_| r(401, json!({"error": "unauthorized_client"}))).await;
    let dir = tempdir::Dir::new();
    let sa = dir.file(
        "sa.json",
        &json!({"client_email": "b@p.iam.gserviceaccount.com", "private_key": SA_KEY,
                "token_uri": format!("{}/token", fake.url)})
        .to_string(),
    );
    let c = config(
        json!({"ws": {"address": "jacob@corp.example", "service_account_file": sa,
                                 "subject": "boss@corp.example"}}),
    );
    let err = GoogleTokens::with_http(&c, Http::new().unwrap(), "https://x.invalid/")
        .token("ws", &["calendar.readonly"], true, now())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("domain-wide delegation refused (unauthorized_client)"),
        "{err}"
    );
    let f = form(&fake.calls()[0]);
    let claims = b64(f["assertion"].split('.').nth(1).unwrap());
    assert_eq!(claims["sub"], "boss@corp.example");
}

/// The flagged upstream issue: one lock across every mint let a slow
/// Google for one account stall every other. Each (account, scopes) has
/// its own now.
#[tokio::test]
async fn a_slow_account_does_not_stall_another() {
    let slow = Fake::start(|_| {
        R(
            200,
            json!({"access_token": "slow", "scope": scope_url("calendar.readonly").unwrap()}),
            3000,
        )
    })
    .await;
    let fast = Fake::start(|_| token_answer(&cal())).await;
    let dir = tempdir::Dir::new();
    let mut accounts = serde_json::Map::new();
    for (name, fake) in [("slow", &slow), ("fast", &fast)] {
        let client = dir.file(
            &format!("{name}.json"),
            &json!({"client_id": "c", "token_uri": format!("{}/token", fake.url)}).to_string(),
        );
        let refresh = dir.file(&format!("{name}.rt"), "r");
        accounts.insert(
            name.to_owned(),
            json!({"address": format!("{name}@x.example"), "client_secret_file": client,
                   "refresh_token_file": refresh}),
        );
    }
    let t = Arc::new(GoogleTokens::with_http(
        &config(Value::Object(accounts)),
        Http::new().unwrap(),
        "https://x.invalid/",
    ));
    let t2 = Arc::clone(&t);
    let pending =
        tokio::spawn(async move { t2.token("slow", &["calendar.readonly"], true, now()).await });
    while slow.calls().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let started = Instant::now();
    t.token("fast", &["calendar.readonly"], true, now())
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(pending.await.unwrap().unwrap().0.expose(), "slow");
}

fn provisioner(s: &Setup) -> GoogleProvisioner {
    GoogleProvisioner::new(&s.config, Arc::new(tokens(s)))
}

fn google(action: &str) -> Authority {
    Authority::Google {
        action: action.into(),
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn provisioner_validate(pool: PgPool) {
    let store = Store::from_pool(pool);
    let s = oauth(|_| token_answer(&cal())).await;
    let p = provisioner(&s);
    let a = agent(&store, "g-agent").await;
    let v = |cap: &'static str, scope: Value, resource: &'static str| {
        let (store, p, a) = (&store, &p, &a);
        async move { validate(store, p, a, Platform::Google, cap, scope, resource).await }
    };
    let ok = v("calendar.read", json!({}), "ME@example.com")
        .await
        .unwrap();
    assert_eq!(ok.resource, "main");
    assert_eq!(
        ok.notes,
        [
            "an account-wide Google token: reads every calendar of me@example.com (scope \
          calendar.readonly), for up to an hour past the grant's end"
        ]
    );
    assert_eq!(
        v("drive.read", json!({}), "main").await.unwrap().resource,
        "main"
    );
    let gmail = v("gmail.read", json!({}), "main").await.unwrap_err();
    assert!(gmail.contains("platform \"mail\""), "{gmail}");
    assert_eq!(
        v("contacts.read", json!({}), "main").await.unwrap_err(),
        "unknown google capability 'contacts.read'; known: ['calendar.read', 'calendar.write', 'drive.read']"
    );
    let scoped = v("calendar.read", json!({"calendar": "x"}), "main")
        .await
        .unwrap_err();
    assert!(scoped.contains("no scope"), "{scoped}");
    assert_eq!(
        v("calendar.read", json!({}), "someone@else.example")
            .await
            .unwrap_err(),
        "no google account 'someone@else.example' (there is: main (me@example.com))"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn provision_and_credential(pool: PgPool) {
    let store = Store::from_pool(pool);
    let s = oauth(|_| token_answer(&cal())).await;
    let p = provisioner(&s);
    let a = agent(&store, "g-agent").await;
    let g = granted(&store, &p, a.id, &google("calendar.read"), "main").await;
    assert_eq!(g.provisioner_state, json!({"account": "main"}));
    assert_eq!(s.fake.calls().len(), 1);
    let cred = credential(&store, &p, &g).await.unwrap();
    assert_eq!(s.fake.calls().len(), 1, "cached");
    assert_eq!(cred.kind, "google_access_token");
    assert_eq!(expose(&cred), "ya29.tok");
    assert_eq!(cred.username.as_deref(), Some("me@example.com"));
    assert!(cred.expires_at.unwrap() <= g.expires_at + time::Duration::HOUR);
    assert_eq!(
        cred.note.as_deref(),
        Some(
            "Bearer token for the Google Calendar API (scope calendar.readonly), as \
             me@example.com. Re-fetch when it runs out; none is issued once the grant ends."
        )
    );
    expire(&store, &p, g.id).await.unwrap();
    let ended = credential(&store, &p, &g).await.unwrap_err().text();
    assert!(ended.contains("not active"), "{ended}");
    let entry = p.catalog(&a).unwrap();
    assert_eq!(
        entry["accounts"],
        json!([{"name": "main", "address": "me@example.com"}])
    );
    assert_eq!(
        entry["capabilities"],
        json!(["calendar.read", "calendar.write", "drive.read"])
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn provision_fails_on_wider_token(pool: PgPool) {
    let store = Store::from_pool(pool);
    let wider = format!("{} {}", scope("drive.readonly"), scope("calendar.events"));
    let s = oauth(move |_| token_answer(&wider)).await;
    let p = provisioner(&s);
    let a = agent(&store, "g-agent").await;
    let g = provisioning(&store, a.id, &google("drive.read"), "main", 3600).await;
    let err = provision(&store, &p, &g).await.unwrap_err();
    assert!(err.contains("wider"), "{err}");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn stub(pool: PgPool) {
    let store = Store::from_pool(pool);
    let p = GoogleStubProvisioner;
    let a = agent(&store, "g-agent").await;
    let gmail = validate(
        &store,
        &p,
        &a,
        Platform::Google,
        "gmail.read",
        json!({}),
        "*",
    )
    .await
    .unwrap_err();
    assert!(gmail.contains("platform \"mail\""), "{gmail}");
    assert_eq!(
        validate(
            &store,
            &p,
            &a,
            Platform::Google,
            "drive.write",
            json!({}),
            "*"
        )
        .await
        .unwrap_err(),
        "unknown google capability 'drive.write'; known: ['calendar.read', 'calendar.write', 'drive.read']"
    );
    let ok = validate(
        &store,
        &p,
        &a,
        Platform::Google,
        "calendar.read",
        json!({}),
        "primary",
    )
    .await
    .unwrap();
    assert_eq!(
        ok.notes,
        ["google is a stub here (no account configured): decision recorded, no credential minted"]
    );
    let g = granted(&store, &p, a.id, &google("calendar.read"), "primary").await;
    assert_eq!(g.provisioner_state, json!({"stub": true}));
    match credential(&store, &p, &g).await {
        Err(CredErr::Provision(ProvisionError::NotImplemented)) => {}
        other => panic!("{other:?}"),
    }
    expire(&store, &p, g.id).await.unwrap();
    assert_eq!(
        p.catalog(&a).unwrap()["capabilities"],
        json!(["calendar.read", "calendar.write", "drive.read"])
    );
}
