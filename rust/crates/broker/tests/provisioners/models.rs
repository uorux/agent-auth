//! Models / LiteLLM (provisioners spec §5, §14).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use agent_auth_broker::provisioners::Provisioner;
use agent_auth_broker::provisioners::http::Http;
use agent_auth_broker::provisioners::models::ModelsProvisioner;
use agent_auth_core::policy::schema::ModelsConfig;
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::common::*;

#[derive(Debug, Default)]
struct Gateway {
    users: BTreeMap<String, Value>,
    keys: BTreeSet<String>,
    n: usize,
}

fn gateway(s: &Arc<Mutex<Gateway>>, c: &Call) -> R {
    let mut st = s.lock().unwrap();
    if c.header("authorization") != "Bearer sk-master" {
        return r(401, json!({}));
    }
    match (c.method.as_str(), c.path.as_str()) {
        ("GET", "/admin/user/info") => {
            let id = c.query.strip_prefix("user_id=").unwrap_or("");
            match st.users.get(id) {
                Some(u) => r(200, json!({"user_info": u})),
                None => r(404, json!({"error": "not found"})),
            }
        }
        ("POST", "/admin/user/new") => {
            let id = c.body["user_id"].as_str().unwrap().to_owned();
            st.users.insert(id, json!({"user_id": c.body["user_id"], "user_role": c.body["user_role"], "metadata": c.body["metadata"], "spend": 1.5}));
            r(200, json!({}))
        }
        ("POST", "/admin/key/generate") => {
            st.n += 1;
            let key = format!("sk-agent-{}", st.n);
            st.keys.insert(key.clone());
            r(200, json!({"key": key}))
        }
        ("POST", "/admin/key/delete") => {
            let key = c.body["keys"][0].as_str().unwrap_or("");
            if st.keys.remove(key) {
                r(200, json!({}))
            } else {
                r(400, json!({"error": "Key Not Found"}))
            }
        }
        _ => r(404, json!({})),
    }
}

struct M {
    store: Store,
    fake: Fake,
    state: Arc<Mutex<Gateway>>,
    p: ModelsProvisioner,
}

fn config(url: &str) -> ModelsConfig {
    let mut c = ModelsConfig::default();
    c.url = "https://llm.example/".into();
    c.admin_url = Some(format!("{url}/admin/"));
    c.models = vec!["claude-sonnet".into(), "gpt-5".into()];
    c.max_budget = Some(25.0);
    c
}

async fn setup_with(pool: PgPool, edit: impl FnOnce(&mut ModelsConfig)) -> M {
    let state: Arc<Mutex<Gateway>> = Arc::default();
    let s2 = state.clone();
    let fake = Fake::start(move |c| gateway(&s2, c)).await;
    let mut cfg = config(&fake.url);
    edit(&mut cfg);
    let p = ModelsProvisioner::new(
        cfg,
        Secret::new("sk-master".into()),
        secret_box(),
        Http::new().unwrap(),
    );
    M {
        store: Store::from_pool(pool),
        fake,
        state,
        p,
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_key_per_grant_under_the_agents_user(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let a = agent(&t.store, "model-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Models, "litellm").await;
    let new = t.fake.find("POST", "/admin/user/new");
    assert_eq!(
        new[0].body,
        json!({"user_id": "model-agent", "user_alias": "model-agent", "user_role": "internal_user_viewer", "auto_create_key": false,
               "metadata": {"agent": "model-agent", "project": "agent-auth", "host": "excelsior", "runtime": "claude", "placement": "host"}})
    );
    let k = &t.fake.find("POST", "/admin/key/generate")[0].body;
    assert_eq!(k["user_id"], "model-agent");
    assert_eq!(
        k["key_alias"],
        json!(format!("model-agent/{}", &g.id.to_string()[..8]))
    );
    let secs: i64 = k["duration"]
        .as_str()
        .unwrap()
        .trim_end_matches('s')
        .parse()
        .unwrap();
    assert!((3500..=3600).contains(&secs));
    assert_eq!(k["models"], json!(["claude-sonnet", "gpt-5"]));
    assert_eq!(
        (k["max_budget"].clone(), k["budget_duration"].clone()),
        (json!(25.0), json!("30d"))
    );
    assert_eq!(k["metadata"]["grant_id"], json!(g.id.to_string()));
    assert_eq!(k["metadata"]["issued_by"], "agent-auth");
    // Stored sealed, never in the clear (INV-M2).
    assert!(!g.provisioner_state.to_string().contains("sk-agent-1"));
    assert_eq!(g.provisioner_state["user_id"], "model-agent");

    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(
        (kind_name(&c).as_str(), expose(&c), c.url.as_deref()),
        (
            "model_gateway_key",
            "sk-agent-1",
            Some("https://llm.example")
        )
    );
    assert_eq!(c.expires_at, Some(g.expires_at));
    assert!(c.note.unwrap().starts_with(
        "Claude Code: ANTHROPIC_BASE_URL=https://llm.example and ANTHROPIC_AUTH_TOKEN=<this key>."
    ));

    // A second grant reuses the user.
    let g2 = granted(&t.store, &t.p, a.id, &Authority::Models, "litellm").await;
    assert_eq!(t.fake.count("POST", "/admin/user/new"), 1);
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert_eq!(
        t.fake.find("POST", "/admin/key/delete")[0].body,
        json!({"keys": ["sk-agent-1"]})
    );
    // Already gone counts as deleted (INV-M4).
    t.state.lock().unwrap().keys.clear();
    expire(&t.store, &t.p, g2.id).await.unwrap();
    // The master key went only as a bearer header (INV-M1).
    assert!(
        t.fake
            .calls()
            .iter()
            .all(|c| !c.body.to_string().contains("sk-master") && !c.query.contains("sk-master"))
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_gateway_user_the_broker_did_not_make_is_not_reused(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    t.state.lock().unwrap().users.insert(
        "admin".into(),
        json!({"user_id": "admin", "user_role": "proxy_admin", "metadata": {}}),
    );
    let a = agent(&t.store, "admin").await;
    let g = provisioning(&t.store, a.id, &Authority::Models, "litellm", 3600).await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(
        err,
        "the model gateway has a user admin the broker did not create; refusing to issue a key under it"
    );
    assert_eq!(t.fake.count("POST", "/admin/key/generate"), 0);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn gateway_errors_carry_no_gateway_text(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let s = t.state.clone();
    t.fake.set(move |c| {
        if c.path == "/admin/key/generate" {
            r(500, json!({"error": "secret internals"}))
        } else {
            gateway(&s, c)
        }
    });
    let a = agent(&t.store, "model-agent").await;
    let g = provisioning(&t.store, a.id, &Authority::Models, "litellm", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "model gateway refused the key: 500"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_failed_delete_keeps_the_grant_for_a_retry(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let a = agent(&t.store, "model-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Models, "litellm").await;
    let s = t.state.clone();
    t.fake.set(move |c| {
        if c.path == "/admin/key/delete" {
            r(503, json!({}))
        } else {
            gateway(&s, c)
        }
    });
    let alias = format!("model-agent/{}", &g.id.to_string()[..8]);
    assert_eq!(
        expire(&t.store, &t.p, g.id).await.unwrap_err(),
        format!("model gateway did not delete {alias}: 503")
    );
    assert_eq!(
        grant(&t.store, g.id).await.status,
        agent_auth_core::GrantStatus::Active
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn validation(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let a = agent(&t.store, "model-agent").await;
    let ok = validate(
        &t.store,
        &t.p,
        &a,
        Platform::Models,
        "use",
        json!({}),
        "litellm",
    )
    .await
    .unwrap();
    assert_eq!(ok.notes, ["may call: claude-sonnet, gpt-5"]);
    assert_eq!(
        validate(
            &t.store,
            &t.p,
            &a,
            Platform::Models,
            "use",
            json!({}),
            "other"
        )
        .await
        .unwrap_err(),
        "unknown model gateway 'other' (this broker has 'litellm')"
    );
    // Capability and scope are the wire parser's.
    assert!(
        validate(
            &t.store,
            &t.p,
            &a,
            Platform::Models,
            "admin",
            json!({}),
            "litellm"
        )
        .await
        .is_err()
    );
    assert!(
        validate(
            &t.store,
            &t.p,
            &a,
            Platform::Models,
            "use",
            json!({"x": 1}),
            "litellm"
        )
        .await
        .is_err()
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn models_by_runtime(pool: PgPool) {
    let t = setup_with(pool.clone(), |c| {
        c.by_runtime = [
            ("claude".to_owned(), vec!["claude-sonnet".to_owned()]),
            ("codex".to_owned(), vec!["gpt-5".to_owned()]),
        ]
        .into();
    })
    .await;
    let claude = agent(&t.store, "c").await;
    let codex = agent_with(
        &t.store,
        AgentSpec {
            runtime: Some("codex"),
            ..AgentSpec::named("x")
        },
    )
    .await;
    let hermes = agent_with(
        &t.store,
        AgentSpec {
            runtime: Some("hermes"),
            ..AgentSpec::named("h")
        },
    )
    .await;
    let none = agent_with(
        &t.store,
        AgentSpec {
            runtime: None,
            ..AgentSpec::named("n")
        },
    )
    .await;
    let v = |a: &agent_auth_store::agents::AgentRow| {
        let (store, p, a) = (t.store.clone(), &t.p, a.clone());
        async move { validate(&store, p, &a, Platform::Models, "use", json!({}), "litellm").await }
    };
    assert_eq!(v(&claude).await.unwrap().notes, ["may call: claude-sonnet"]);
    assert_eq!(v(&codex).await.unwrap().notes, ["may call: gpt-5"]);
    assert_eq!(
        v(&hermes).await.unwrap_err(),
        "no models for runtime 'hermes' at this gateway (only claude, codex)"
    );
    assert_eq!(
        v(&none).await.unwrap_err(),
        "no models for runtime '(none)' at this gateway (only claude, codex)"
    );
    // Refused at provision too, with no gateway call (INV-M3).
    let g = provisioning(&t.store, hermes.id, &Authority::Models, "litellm", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "no models for runtime 'hermes'"
    );
    assert!(t.fake.calls().is_empty());
    granted(&t.store, &t.p, codex.id, &Authority::Models, "litellm").await;
    assert_eq!(
        t.fake.find("POST", "/admin/key/generate")[0].body["models"],
        json!(["gpt-5"])
    );

    let star = setup_with(pool, |c| {
        c.by_runtime = [
            ("claude".to_owned(), vec!["a".to_owned()]),
            ("*".to_owned(), vec!["b".to_owned()]),
        ]
        .into();
    })
    .await;
    for a in [&hermes, &none] {
        let ok = validate(
            &star.store,
            &star.p,
            a,
            Platform::Models,
            "use",
            json!({}),
            "litellm",
        )
        .await
        .unwrap();
        assert_eq!(ok.notes, ["may call: b"]);
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn usage_and_catalog(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let a = agent(&t.store, "model-agent").await;
    granted(&t.store, &t.p, a.id, &Authority::Models, "litellm").await;
    // A user whose id does not match is ignored; missing users are skipped.
    t.state
        .lock()
        .unwrap()
        .users
        .insert("liar".into(), json!({"user_id": "someone-else"}));
    let u =
        t.p.usage(&["model-agent".into(), "liar".into(), "ghost".into()])
            .await
            .unwrap();
    assert_eq!(u.len(), 1);
    assert_eq!(u[0]["user_id"], "model-agent");
    assert!(t.fake.calls().iter().all(|c| c.path != "/admin/user/list"));
    let c = t.p.catalog(&a).unwrap();
    assert_eq!(
        c["gateway"],
        json!({"name": "litellm", "url": "https://llm.example/", "models": ["claude-sonnet", "gpt-5"]})
    );
    assert_eq!(c["capabilities"], json!(["use"]));
    assert!(!c.to_string().contains("by_runtime"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_credential_route_serves_a_gateway_key(pool: PgPool) {
    let t = setup_with(pool, |_| {}).await;
    let a = agent(&t.store, "model-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Models, "litellm").await;
    let out = credentials_over_http(
        &t.store,
        agent_auth_broker::provisioners::AnyProvisioner::Models(t.p),
        &[&g],
    )
    .await;
    assert_eq!(out[0].0, axum::http::StatusCode::OK, "{}", out[0].1);
    assert_eq!(out[0].1["kind"], "model_gateway_key");
    assert_eq!(out[0].1["value"], "sk-agent-1");
    assert_eq!(out[0].1["url"], "https://llm.example");
}
