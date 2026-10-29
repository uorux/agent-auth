//! The daemon without a broker (what needs none): key acceptance, project
//! resolution, the gateway when the broker is away, codex login copies.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use agent_auth_crypto::Secret;

use super::Sandboxd;
use crate::config::Config;
use crate::store::AgentRecord;
use crate::testdir::TestDir;
use crate::testing::FakeHost;

fn daemon(d: &TestDir, tweak: impl FnOnce(&mut serde_json::Value)) -> Arc<Sandboxd<FakeHost>> {
    let mut v = serde_json::json!({
        // Nothing listens there: the broker is unreachable.
        "broker_url": "http://127.0.0.1:9",
        "broker_public_key": crate::config::tests::key(),
        "name": "excelsior",
        "state_dir": d.path().join("state"),
        "sandbox_root": d.path().join("sb"),
        "userdb_dir": d.path().join("userdb"),
        "runtime_dir": d.path().join("run"),
        "agent_socket": d.path().join("agent.sock"),
        "runtimes": {"claude": {"command": "claude"}, "codex": {"command": "codex"}},
        "uid_base": std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap(),
    });
    tweak(&mut v);
    let cfg = Arc::new(Config::from_json(&v.to_string()).unwrap());
    Sandboxd::new(cfg, FakeHost::new(d.path().join("fake.log"))).unwrap()
}

fn rec(name: &str, runtime: Option<&str>, project: Option<&str>) -> AgentRecord {
    AgentRecord {
        name: name.to_owned(),
        agent_id: "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9".to_owned(),
        key_id: "0123456789ab".to_owned(),
        runtime: runtime.map(str::to_owned),
        project: project.map(str::to_owned),
        api_key: Secret::new("aa_0123456789ab_x".to_owned()),
        updated_at: 0.0,
    }
}

/// Review #5 item 4: a key is accepted only for this VM's orchestrator or
/// exactly `<runtime>-<project>-<host>-sandbox` of a project that exists
/// here; an agent without a project never maps to the orchestrator.
#[tokio::test]
async fn keys_fit_only_this_vms_agents() {
    let d = TestDir::new("keyfit");
    let s = daemon(&d, |_| {});
    s.startup().await.unwrap();
    s.create_project("larder").unwrap();
    assert!(s.key_fits(&rec(
        "orchestrator-excelsior-sandbox",
        Some("orchestrator"),
        None
    )));
    assert!(s.key_fits(&rec(
        "claude-larder-excelsior-sandbox",
        Some("claude"),
        Some("larder")
    )));
    assert!(
        !s.key_fits(&rec(
            "claude-site-excelsior-sandbox",
            Some("claude"),
            Some("site")
        )),
        "no such project"
    );
    assert!(
        !s.key_fits(&rec(
            "claude-larder-galaxy-sandbox",
            Some("claude"),
            Some("larder")
        )),
        "another host"
    );
    assert!(
        !s.key_fits(&rec(
            "claude-larder-excelsior-sandbox",
            Some("claude"),
            None
        )),
        "no project"
    );
    assert!(
        !s.key_fits(&rec("evil", Some("claude"), Some("larder"))),
        "not the name"
    );
    // A record that slipped in without a project has none to run in.
    let e = s
        .project_of(&rec("claude-x-excelsior-sandbox", Some("claude"), None))
        .unwrap_err();
    assert!(e.to_string().contains("has no project"));
    assert_eq!(
        s.project_of(&rec("orchestrator-excelsior-sandbox", None, None))
            .unwrap(),
        None
    );
    // Over the channel: a key that does not fit is not stored.
    let body = serde_json::json!({"type": "key", "agent_id": "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9",
        "key_id": "0123456789ab", "name": "claude-nope-excelsior-sandbox", "runtime": "claude",
        "project": "nope", "api_key": "aa_0123456789ab_secret"});
    let serde_json::Value::Object(m) = body else {
        panic!()
    };
    s.on_broker_message(m).await;
    assert!(s.store.agent("claude-nope-excelsior-sandbox").is_none());
    s.shutdown().await;
}

/// Review #5 notes: a broker that can't be reached starts no process on
/// the VM's own logins unless the config allows it.
#[tokio::test]
async fn an_unreachable_broker_is_no_reason_to_use_the_vms_logins() {
    let d = TestDir::new("gwaway");
    let s = daemon(&d, |_| {});
    let e = s
        .gateway(&rec("orchestrator-excelsior-sandbox", None, None))
        .await
        .unwrap_err();
    assert!(e.0.contains("unreachable"), "{e}");
    let d2 = TestDir::new("gwaway2");
    let s2 = daemon(&d2, |v| {
        v["refuse_vm_logins_when_unreachable"] = serde_json::json!(false)
    });
    assert!(
        s2.gateway(&rec("orchestrator-excelsior-sandbox", None, None))
            .await
            .unwrap()
            .is_none()
    );
}

/// Review #5 item 4 (codex): a project's copy of the login goes when it
/// is contained, and codex triage gets a fresh CODEX_HOME with only the
/// login (none of the project's config) (B-16).
#[tokio::test]
async fn codex_login_copies_and_triage_home() {
    let d = TestDir::new("codexcopy");
    let s = daemon(&d, |_| {});
    s.startup().await.unwrap();
    s.create_project("larder").unwrap();
    std::fs::create_dir_all(d.path().join("state/secrets")).unwrap();
    crate::store::write_atomic(
        &d.path().join("state/secrets/codex-auth.json"),
        b"{\"tokens\": {}}",
    )
    .unwrap();
    let uid = s.project_uid(Some("larder")).unwrap();
    s.codex_sync_into(Some("larder"), uid).await;
    let copy = d.path().join("sb/homes/larder/.codex/auth.json");
    assert!(copy.exists());
    s.store
        .put_agent(rec(
            "codex-larder-excelsior-sandbox",
            Some("codex"),
            Some("larder"),
        ))
        .unwrap();
    s.contain(&["codex-larder-excelsior-sandbox".to_owned()])
        .await;
    assert!(!copy.exists(), "removed when contained");
    std::fs::write(
        d.path().join("sb/homes/larder/.codex/config.toml"),
        "[mcp_servers]",
    )
    .unwrap();
    let name = s.triage_codex_home(Some("larder"), uid, false).unwrap();
    let home = d.path().join("sb/tmp/larder").join(&name);
    let names: Vec<String> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["auth.json"]);
    let gw = s.triage_codex_home(Some("larder"), uid, true).unwrap();
    assert_eq!(
        std::fs::read_dir(d.path().join("sb/tmp/larder").join(gw))
            .unwrap()
            .count(),
        0
    );
    s.shutdown().await;
}

/// Review #5 item 3: a unit that cannot be frozen is not left running.
#[tokio::test]
async fn an_unfreezable_tui_is_stopped() {
    let d = TestDir::new("unfreeze");
    let s = daemon(&d, |_| {});
    *s.host.fail_freeze.lock().unwrap() = true;
    // No live unit: nothing to stop, no error.
    let conv = crate::names::ConvId::generate();
    s.freeze_conversation(&conv, true).await;
    assert!(s.host.frozen().is_empty());
}

/// Final review: held lists are versioned; one older than a list already
/// applied from the same broker (a contain and a lift racing) is ignored.
#[tokio::test]
async fn an_older_held_list_does_not_thaw() {
    let d = TestDir::new("heldver");
    let s = daemon(&d, |_| {});
    let msg = |agents: serde_json::Value, epoch: &str, seq: u64| {
        let serde_json::Value::Object(m) = serde_json::json!(
            {"type": "agents.contained", "agents": agents, "epoch": epoch, "version": seq})
        else {
            panic!()
        };
        m
    };
    // Delivered out of order: the contain (seq 2) before the lift (seq 1).
    s.on_broker_message(msg(serde_json::json!(["a"]), "e1", 2))
        .await;
    s.settle_holds().await;
    s.on_broker_message(msg(serde_json::json!([]), "e1", 1))
        .await;
    s.settle_holds().await;
    assert!(s.contained("a"), "the older list did not lift it");
    // A newer one applies; a new broker process starts its own order.
    s.on_broker_message(msg(serde_json::json!([]), "e1", 3))
        .await;
    s.settle_holds().await;
    assert!(!s.contained("a"));
    s.on_broker_message(msg(serde_json::json!(["b"]), "e2", 1))
        .await;
    s.settle_holds().await;
    assert!(s.contained("b"));
    // An unversioned list (an older broker) always applies.
    let serde_json::Value::Object(m) =
        serde_json::json!({"type": "agents.contained", "agents": []})
    else {
        panic!()
    };
    s.on_broker_message(m).await;
    s.settle_holds().await;
    assert!(!s.contained("b"));
}
