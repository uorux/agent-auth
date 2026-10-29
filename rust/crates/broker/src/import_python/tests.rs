//! The importer against Postgres, a served broker and a daemon on the real
//! channel. Synthetic exports only: every key is made here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::containment::AgentKind;
use agent_auth_crypto::api_key;
use agent_auth_crypto::daemon::{DaemonId as ChannelId, DaemonName, Role, SigningKey};
use agent_auth_daemon::channel::{Channel, Identity};
use agent_auth_store::Store;
use agent_auth_store::agents::{self, DisableReason};
use agent_auth_store::daemons::{self, DaemonRole};
use serde_json::{Map, Value, json};
use time::macros::datetime;
use uuid::Uuid;

use super::{A2aConfig, FORMAT, ImportError, apply, plan, timestamp};
use crate::config::Env;
use crate::daemons::testkit::{Broker, POLICY, tempdir, wait_until};

const HOST_ID: &str = "2b1c9a4e-6f0d-4b8e-9c3a-1d2e3f405162";
const VM_ID: &str = "7c3d1e2f-0a4b-4c5d-8e6f-708192a3b4c5";
const ORCH_ID: &str = "00000000-0000-4000-8000-0000000000a1";
const HELPER_ID: &str = "00000000-0000-4000-8000-0000000000a2";

struct Fixture {
    json: Value,
    host_key: SigningKey,
    worker_key: String,
    old_key: String,
}

fn agent(name: &str, key_id: &str, hash: &str) -> Value {
    json!({
        "id": Uuid::new_v4().to_string(), "name": name, "description": "",
        "key_id": key_id, "api_key_hash": hash, "webhook_url": null, "webhook_secret": null,
        "lldap_username": null, "lldap_managed": 0, "disabled": 0, "kind": "service",
        "last_seen_at": null, "last_listen_at": null, "parent_agent_id": null,
        "sandbox_id": null, "runtime": null, "project": null, "host": null,
        "placement": "host", "lease_expires_at": null, "created_at": "2026-09-01 10:00:00.000001",
    })
}

fn keyed(name: &str) -> (Value, String) {
    let k = api_key::generate().unwrap();
    (
        agent(name, k.key_id.as_str(), k.hash.as_str()),
        k.full_key.expose().clone(),
    )
}

fn set(v: &mut Value, pairs: Value) {
    for (k, x) in pairs.as_object().unwrap() {
        assert!(v.get(k).is_some(), "{k} is not an export column");
        v[k] = x.clone();
    }
}

/// A Python broker with one host, one agent VM (orchestrator, a minted
/// helper, a grandchild), a web connector, the operator stand-in and three
/// hand-registered agents.
fn fixture() -> Fixture {
    let host_key = SigningKey::generate().unwrap();
    let vm_key = SigningKey::generate().unwrap();
    let (mut worker, worker_key) = keyed("worker");
    set(
        &mut worker,
        json!({
            // SQLAlchemy wrote dashed uuids; a 32-hex one parses too.
            "id": "5f0e1d2c3b4a49588776655443322110",
            "description": "the always-on worker",
            "webhook_url": "https://hooks.example/worker", "webhook_secret": "s".repeat(43),
            "lldap_username": "svc-worker", "lldap_managed": 1,
            "runtime": "claude", "project": "agent-auth", "host": "excelsior",
            "created_at": "2026-08-01T09:30:00Z",
            "last_seen_at": "2026-10-01 12:00:00.5+02:00",
            "last_listen_at": "2026-10-01 10:00:00",
        }),
    );
    let (mut cli, _) = keyed("cli");
    set(
        &mut cli,
        json!({"kind": "ephemeral", "lldap_username": "jrt-cli",
               "webhook_url": "https://hooks.example/cli", "last_listen_at": "2026-10-01 10:00:00"}),
    );
    let (mut old, old_key) = keyed("old");
    set(
        &mut old,
        json!({"disabled": 1, "webhook_url": "http://10.0.0.5:9000/hook", "webhook_secret": ""}),
    );
    // The Python's stand-in: a 16-hex key id and a hash of nothing.
    let mut operator = agent("operator", "0123456789abcdef", &"!".repeat(64));
    set(&mut operator, json!({"kind": "operator"}));
    let (mut web, _) = keyed("claude-web");
    set(&mut web, json!({"kind": "ephemeral", "runtime": "web"}));
    let (mut orch, _) = keyed("orchestrator-excelsior-sandbox");
    set(
        &mut orch,
        json!({"id": ORCH_ID, "runtime": "orchestrator", "sandbox_id": VM_ID, "placement": "sandbox"}),
    );
    let (mut helper, _) = keyed("helper");
    set(
        &mut helper,
        json!({"id": HELPER_ID, "parent_agent_id": ORCH_ID, "sandbox_id": VM_ID,
               "placement": "sandbox", "lease_expires_at": "2026-11-01 00:00:00"}),
    );
    // Its VM unpaired (sandbox_id SET NULL): still minted, still skipped.
    let (mut grandchild, _) = keyed("grandchild");
    set(
        &mut grandchild,
        json!({"parent_agent_id": HELPER_ID, "placement": "sandbox"}),
    );
    let json = json!({
        "format": FORMAT,
        "agents": [worker, cli, old, operator, web, orch, helper, grandchild],
        "daemons": [
            {"id": HOST_ID, "role": "host", "name": "excelsior",
             "public_key": host_key.public_key().to_text(),
             "paired_at": "2026-09-01 10:00:00.123456", "last_seen_at": "2026-10-20 10:00:00",
             "created_at": "2026-08-15 08:00:00"},
            {"id": VM_ID, "role": "sandbox", "name": "excelsior",
             "public_key": vm_key.public_key().to_text(),
             "paired_at": "2026-09-02 10:00:00", "last_seen_at": null,
             "created_at": "2026-09-02 10:00:00"},
        ],
    });
    Fixture {
        json,
        host_key,
        worker_key,
        old_key,
    }
}

fn a2a() -> A2aConfig {
    A2aConfig::default()
}

async fn counts(store: &Store) -> (usize, usize) {
    let tx = store.begin().await.unwrap();
    let a = agents::list(&tx).await.unwrap().len();
    let d = daemons::list(&tx).await.unwrap().len();
    (a, d)
}

struct NullHandler;

impl agent_auth_daemon::channel::Handler for NullHandler {
    fn status(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("ok".into(), json!(true));
        m
    }

    async fn on_message(&self, _body: Map<String, Value>) {}
}

#[test]
fn timestamps_are_utc_whatever_the_shape() {
    let t = datetime!(2026-10-01 10:00:00 UTC);
    for text in [
        "2026-10-01 10:00:00",
        "2026-10-01T10:00:00",
        "2026-10-01 10:00:00.000000",
        "2026-10-01 10:00:00Z",
        "2026-10-01 12:00:00+02:00",
        "2026-10-01 05:00:00-0500",
        "2026-10-01 10:00:00+00",
    ] {
        assert_eq!(timestamp(text), Some(t), "{text}");
    }
    assert_eq!(
        timestamp("2026-10-01 10:00:00.123456"),
        Some(datetime!(2026-10-01 10:00:00.123456 UTC))
    );
    for bad in [
        "",
        "2026-10-01",
        "yesterday",
        "2026-13-01 10:00:00",
        "2026-10-01 10:00:00+99",
    ] {
        assert_eq!(timestamp(bad), None, "{bad}");
    }
}

#[test]
fn the_plan_says_what_stays_behind_and_why() {
    let f = fixture();
    let p = plan(&f.json.to_string(), &a2a()).unwrap();
    assert_eq!(p.daemon_names(), ["excelsior"]);
    assert_eq!(p.agent_names(), ["worker", "cli", "old"]);
    let skipped: Vec<&str> = p.skipped.iter().map(|s| s.what.as_str()).collect();
    assert_eq!(
        skipped,
        [
            "daemon sandbox/excelsior",
            "agent operator",
            "agent claude-web",
            "agent orchestrator-excelsior-sandbox",
            "agent helper",
            "agent grandchild",
        ]
    );
    let reason = |what: &str| {
        p.skipped
            .iter()
            .find(|s| s.what == what)
            .unwrap()
            .reason
            .clone()
    };
    assert!(reason("agent helper").contains("sandbox/excelsior"));
    assert!(reason("agent grandchild").contains("minted by helper"));
    assert!(reason("agent claude-web").contains("web UI connector"));
    assert!(reason("agent operator").contains("operator stand-in"));
    let warnings = p.warnings.join("\n");
    assert!(
        warnings
            .contains("agent worker: its broker-managed LLDAP account svc-worker is adopted again")
    );
    assert!(warnings.contains("agent cli: an ephemeral agent's webhook is dropped"));
    assert!(warnings.contains("agent old: its webhook is plain http to \"10.0.0.5\""));
    assert!(warnings.contains("agent old: a webhook without a signing secret"));
    assert_eq!(p.warnings.len(), 4, "{warnings}");
    // Listing the host for plain http silences that one.
    let listed =
        A2aConfig::from_lookup(|k| (k == "A2A_WEBHOOK_HTTP_HOSTS").then(|| "10.0.0.5".into()))
            .unwrap();
    let p = plan(&f.json.to_string(), &listed).unwrap();
    assert_eq!(p.warnings.len(), 3);
    // The summary names rows, never a secret.
    let s = p.summary(true);
    assert!(
        s.contains("would import 3 agent(s): worker, cli, old"),
        "{s}"
    );
    assert!(!s.contains(&"s".repeat(43)) && !s.contains(&f.worker_key));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn keys_and_pairings_carry_over(pool: sqlx::PgPool) {
    let f = fixture();
    let store = Store::from_pool(pool.clone());
    // The broker's own operator row may already be there.
    let tx = store.begin().await.unwrap();
    agents::ensure_operator(
        &tx,
        agent_auth_core::AgentId::new(),
        "aaaaaaaaaaaa",
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    let p = plan(&f.json.to_string(), &a2a()).unwrap();
    apply(&store, &p).await.unwrap();

    let tx = store.begin().await.unwrap();
    let rows = agents::list(&tx).await.unwrap();
    let names: Vec<&str> = rows.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["cli", "old", "operator", "worker"]);
    let get = |n: &str| rows.iter().find(|a| a.name == n).unwrap();
    let worker = get("worker");
    assert_eq!(
        worker.id.to_string(),
        "5f0e1d2c-3b4a-4958-8776-655443322110"
    );
    assert_eq!(worker.kind, AgentKind::Service);
    assert_eq!(worker.description, "the always-on worker");
    assert_eq!(
        worker.webhook_secret.as_deref(),
        Some("s".repeat(43).as_str())
    );
    // Managed LLDAP: no password carried, adopted again on demand.
    assert_eq!(worker.lldap_username, None);
    assert_eq!(worker.lldap_password_encrypted, None);
    assert_eq!(worker.runtime.as_deref(), Some("claude"));
    assert_eq!(worker.created_at, datetime!(2026-08-01 09:30:00 UTC));
    assert_eq!(
        worker.last_seen_at,
        Some(datetime!(2026-10-01 10:00:00.5 UTC))
    );
    assert_eq!(
        worker.last_listen_at,
        Some(datetime!(2026-10-01 10:00:00 UTC))
    );
    let cli = get("cli");
    assert_eq!(cli.kind, AgentKind::Ephemeral);
    assert_eq!(cli.lldap_username.as_deref(), Some("jrt-cli"));
    assert_eq!((cli.webhook_url.as_ref(), cli.last_listen_at), (None, None));
    let old = get("old");
    assert!(old.disabled);
    assert_eq!(old.disabled_reason, Some(DisableReason::Operator));
    assert_eq!(old.webhook_secret, None);
    let ds = daemons::list(&tx).await.unwrap();
    assert_eq!(ds.len(), 1);
    assert_eq!(
        (ds[0].role, ds[0].name.as_str()),
        (DaemonRole::Host, "excelsior")
    );
    assert_eq!(ds[0].id.to_string(), HOST_ID);
    assert_eq!(ds[0].public_key, f.host_key.public_key().to_text());
    assert_eq!(ds[0].created_at, datetime!(2026-08-15 08:00:00 UTC));
    assert_eq!(ds[0].paired_at, datetime!(2026-09-01 10:00:00.123456 UTC));
    assert_eq!(
        (ds[0].version.as_ref(), ds[0].last_status.as_ref()),
        (None, None)
    );
    drop(tx);

    // The Python-made keys open the agent API.
    let b = Broker::start_with(pool, POLICY, 1).await;
    let client = agent_auth_tls::reqwest_builder(
        agent_auth_tls::default_client_config().unwrap(),
        Duration::from_secs(10),
    )
    .build()
    .unwrap();
    let me = |key: String| {
        let client = client.clone();
        let url = format!("{}/v1/me", b.url());
        async move {
            let r = client.get(url).bearer_auth(key).send().await.unwrap();
            let status = r.status().as_u16();
            (status, r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let (status, body) = me(f.worker_key.clone()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "worker");
    assert_ne!(
        me(f.old_key.clone()).await.0,
        200,
        "a disabled agent stays disabled"
    );

    // The host's daemon, with its old identity key, connects without
    // pairing; its heartbeats are accepted (the stored key matches).
    let identity = Identity::new(
        ChannelId::new(Role::Host, DaemonName::parse("excelsior").unwrap()),
        SigningKey::from_text(f.host_key.to_text().expose()).unwrap(),
        agent_auth_daemon::url::BrokerUrl::parse(&b.url()).unwrap(),
        b.key.public_key(),
    );
    let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
    let channel = Channel::new(identity, "0.1.0-test", tls);
    let task = tokio::spawn(async move { channel.run(Arc::new(NullHandler)).await });
    wait_until(|| b.part.hub.is_online(Role::Host, "excelsior")).await;
    let mut status = None;
    for _ in 0..250 {
        let tx = b.st.store.begin().await.unwrap();
        let row = daemons::by_name(&tx, DaemonRole::Host, "excelsior")
            .await
            .unwrap()
            .unwrap();
        if row.last_status.is_some() {
            status = row.last_status;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status.unwrap()["ok"], json!(true));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(b.part.hub.is_online(Role::Host, "excelsior"));
    // The agent VM was not carried: it pairs again.
    assert!(!b.part.hub.is_online(Role::Sandbox, "excelsior"));
    task.abort();
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_used_database_is_refused(pool: sqlx::PgPool) {
    let f = fixture();
    let store = Store::from_pool(pool);
    let p = plan(&f.json.to_string(), &a2a()).unwrap();
    apply(&store, &p).await.unwrap();
    let err = apply(&store, &p).await.unwrap_err();
    assert!(matches!(err, ImportError::Refused(_)), "{err}");
    assert!(err.to_string().contains("not empty"), "{err}");

    // A paired daemon alone is enough to refuse.
    let mut only_daemons = f.json.clone();
    only_daemons["agents"] = json!([]);
    let p = plan(&only_daemons.to_string(), &a2a()).unwrap();
    let tx = store.begin().await.unwrap();
    for a in agents::list(&tx).await.unwrap() {
        sqlx::query("DELETE FROM agents WHERE id = $1")
            .bind(Uuid::from(a.id))
            .execute(store.pool())
            .await
            .unwrap();
    }
    drop(tx);
    assert_eq!(counts(&store).await, (0, 1));
    assert!(matches!(
        apply(&store, &p).await,
        Err(ImportError::Refused(_))
    ));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_bad_row_aborts_with_nothing_written(pool: sqlx::PgPool) {
    let f = fixture();
    let store = Store::from_pool(pool);

    // Refused while planning, naming the row and not the value.
    let mut bad = f.json.clone();
    bad["agents"][2]["api_key_hash"] = json!("not-a-hash-but-a-secret");
    let err = plan(&bad.to_string(), &a2a()).unwrap_err().to_string();
    assert!(
        err.contains("agent old") && err.contains("api_key_hash"),
        "{err}"
    );
    assert!(!err.contains("not-a-hash-but-a-secret"), "{err}");
    let mut bad = f.json.clone();
    bad["daemons"][0]["public_key"] = json!("ed25519:short");
    let err = plan(&bad.to_string(), &a2a()).unwrap_err().to_string();
    assert!(err.contains("daemon host/excelsior"), "{err}");
    let mut bad = f.json.clone();
    bad["agents"][1]["created_at"] = json!("last tuesday");
    assert!(
        plan(&bad.to_string(), &a2a())
            .unwrap_err()
            .to_string()
            .contains("agent cli")
    );
    let mut bad = f.json.clone();
    bad["agents"][1]["lldap_username"] = json!("SVC-Shared");
    bad["agents"][2]["lldap_username"] = json!("svc-shared");
    let err = plan(&bad.to_string(), &a2a()).unwrap_err().to_string();
    assert!(err.contains("shares its LLDAP account"), "{err}");
    let mut bad = f.json.clone();
    let mut twin = bad["agents"][0].clone();
    twin["id"] = json!(Uuid::new_v4().to_string());
    twin["name"] = json!("twin");
    bad["agents"].as_array_mut().unwrap().push(twin);
    let err = plan(&bad.to_string(), &a2a()).unwrap_err().to_string();
    assert!(
        err.contains("agent twin: has the same key id as worker"),
        "{err}"
    );
    let mut bad = f.json.clone();
    bad["agents"][0]["name"] = json!("operator");
    assert!(
        plan(&bad.to_string(), &a2a())
            .unwrap_err()
            .to_string()
            .contains("'operator'")
    );
    let mut bad = f.json.clone();
    bad["agents"][0]["surprise"] = json!(1);
    assert!(
        plan(&bad.to_string(), &a2a())
            .unwrap_err()
            .to_string()
            .contains("agent \"worker\"")
    );

    // Refused by the database halfway through (a key id twice, which the
    // plan itself would have named): the transaction takes everything
    // back, the daemon and the agents written before it included.
    let mut p = plan(&f.json.to_string(), &a2a()).unwrap();
    let twin = super::PlannedAgent {
        id: agent_auth_core::AgentId::new(),
        name: "twin".into(),
        lldap_username: None,
        ..clone_agent(&p.agents[0])
    };
    p.agents.push(twin);
    let err = apply(&store, &p).await.unwrap_err();
    assert!(err.to_string().starts_with("agent twin:"), "{err}");
    assert_eq!(counts(&store).await, (0, 0));
}

fn clone_agent(a: &super::PlannedAgent) -> super::PlannedAgent {
    super::PlannedAgent {
        id: a.id,
        name: a.name.clone(),
        description: a.description.clone(),
        key_id: a.key_id.clone(),
        api_key_hash: a.api_key_hash.clone(),
        kind: a.kind,
        webhook_url: a.webhook_url.clone(),
        webhook_secret: a.webhook_secret.clone(),
        lldap_username: a.lldap_username.clone(),
        disabled: a.disabled,
        runtime: a.runtime.clone(),
        project: a.project.clone(),
        host: a.host.clone(),
        lease_expires_at: a.lease_expires_at,
        last_seen_at: a.last_seen_at,
        last_listen_at: a.last_listen_at,
        created_at: a.created_at,
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_dry_run_touches_nothing(pool: sqlx::PgPool) {
    let f = fixture();
    let store = Store::from_pool(pool);
    let dir = tempdir("import");
    let path = dir.join("export.json");
    std::fs::write(&path, f.json.to_string()).unwrap();
    // No DATABASE_URL at all: a dry run never opens the database.
    let out = super::main(
        &Env::from_pairs([]),
        &["--dry-run".to_owned(), path.to_string_lossy().into_owned()],
    )
    .await
    .unwrap();
    assert!(
        out.contains("would import 1 host daemon(s): excelsior"),
        "{out}"
    );
    assert!(out.contains("nothing was written"), "{out}");
    assert_eq!(counts(&store).await, (0, 0));
    // Without --dry-run it needs the database.
    let err = super::main(&Env::from_pairs([]), &[path.to_string_lossy().into_owned()])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("DATABASE_URL"), "{err}");
    assert!(super::main(&Env::from_pairs([]), &[]).await.is_err());
    let _ = std::fs::remove_dir_all(dir);
}
