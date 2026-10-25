//! sandboxd end to end (`tests/test_sandboxd.py` and the upstream
//! snapshot's additions, plus the invariants and fixes of the sandboxd
//! spec): a real broker on loopback, the real daemon logic
//! (`agent_auth_sandboxd::daemon::Sandboxd`) paired over HTTP and connected
//! over the real signed channel, a host double (units are in-process fakes
//! or local processes) and a fake `claude` speaking stream-json.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::AgentId;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_daemon::channel::Channel;
use agent_auth_sandboxd::api::{AgentApi, OperatorApi};
use agent_auth_sandboxd::config::Config;
use agent_auth_sandboxd::daemon::Sandboxd;
use agent_auth_sandboxd::daemon::routing::ThreadView;
use agent_auth_sandboxd::names::ConvId;
use agent_auth_sandboxd::store::ConvState;
use agent_auth_sandboxd::testing::{AclCall, FAKE_TUI, FakeHost, read_log};
use agent_auth_store::agents::{self, AgentRow, NewAgent};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::testkit::{Broker, HOST, eventually};

const ORCH: &str = "orchestrator-excelsior-sandbox";

fn me() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

/// An agent VM: the broker, the daemon, its directory.
struct Vm {
    b: Broker,
    sbx: Arc<Sandboxd<FakeHost>>,
    dir: PathBuf,
    cfg: Value,
    task: Option<tokio::task::JoinHandle<()>>,
}

fn short_dir() -> PathBuf {
    // AF_UNIX paths are short: tmux's socket lives under the sandbox root.
    let d = PathBuf::from(format!(
        "/tmp/sbx-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

impl Vm {
    async fn start(pool: sqlx::PgPool) -> Vm {
        Vm::start_with(pool, |_| {}).await
    }

    async fn start_with(pool: sqlx::PgPool, tweak: impl FnOnce(&mut Value)) -> Vm {
        let b = Broker::start(pool).await;
        let dir = short_dir();
        let script = dir.join("fake-claude");
        std::fs::write(&script, FAKE_TUI).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cfg = json!({
            "broker_url": b.url(),
            "broker_public_key": b.public_key().to_text(),
            "name": HOST,
            "state_dir": dir.join("state"),
            "sandbox_root": dir.join("sb"),
            "userdb_dir": dir.join("userdb"),
            "runtime_dir": dir.join("run"),
            "agent_socket": dir.join("agent.sock"),
            "runtimes": {"claude": {"command": script}},
            "agent_path": std::env::var("PATH").unwrap_or_default(),
            "tmux": "tmux",
            "uid_base": me(),
            "park_grace_secs": 0.5,
        });
        tweak(&mut cfg);
        let mut vm = Vm {
            b,
            sbx: Vm::daemon(&cfg, &dir),
            dir,
            cfg,
            task: None,
        };
        let code = vm.b.pairing_code(HOST).await;
        let config = Config::from_json(&vm.cfg.to_string()).unwrap();
        let identity = agent_auth_sandboxd::identity(&config).unwrap();
        let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
        agent_auth_daemon::pair::pair(&identity, &code, tls)
            .await
            .unwrap();
        vm.run();
        let sbx = Arc::clone(&vm.sbx);
        assert!(eventually(|| async { sbx.store.agent(ORCH).is_some() }).await);
        vm
    }

    fn daemon(cfg: &Value, dir: &Path) -> Arc<Sandboxd<FakeHost>> {
        let config = Arc::new(Config::from_json(&cfg.to_string()).unwrap());
        Sandboxd::new(config, FakeHost::new(dir.join("fake.log"))).unwrap()
    }

    fn run(&mut self) {
        let config = Config::from_json(&self.cfg.to_string()).unwrap();
        let identity = agent_auth_sandboxd::identity(&config).unwrap();
        let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
        let channel = Channel::new(identity, "0.1.0-test", tls);
        let sbx = Arc::clone(&self.sbx);
        self.task = Some(tokio::spawn(async move {
            sbx.run(channel).await.unwrap();
        }));
    }

    /// Stop the daemon and start a new one over the same state.
    async fn restart(&mut self) {
        self.stop_daemon().await;
        self.sbx = Vm::daemon(&self.cfg, &self.dir);
        self.run();
    }

    async fn stop_daemon(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
        self.sbx.shutdown().await;
        self.sbx.host.stop_all().await;
    }

    async fn stop(mut self) {
        self.stop_daemon().await;
    }

    fn host(&self) -> &FakeHost {
        &self.sbx.host
    }

    fn log(&self) -> Vec<Value> {
        read_log(&self.dir.join("fake.log"))
    }

    fn turns(&self) -> Vec<String> {
        self.log()
            .iter()
            .filter_map(|e| e.get("turn").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    fn starts(&self) -> Vec<Value> {
        self.log()
            .into_iter()
            .filter(|e| e.get("start").is_some())
            .collect()
    }

    async fn saw_turn(&self, text: &str) -> bool {
        eventually(|| async { self.turns().iter().any(|t| t == text) }).await
    }

    /// A service agent outside the VM, with its key.
    async fn peer(&self, name: &str) -> (AgentRow, String) {
        let key = agent_auth_crypto::api_key::generate().unwrap();
        let tx = self.b.st.store.begin().await.unwrap();
        let row = agents::insert(
            &tx,
            &NewAgent {
                id: AgentId::new(),
                name,
                description: "",
                key_id: key.key_id.as_str(),
                api_key_hash: key.hash.as_str(),
                kind: AgentKind::Service,
                webhook_url: None,
                webhook_secret: None,
                lldap_username: None,
                parent_agent_id: None,
                sandbox_id: None,
                runtime: None,
                project: None,
                host: None,
                placement: Placement::Host,
                lease_expires_at: None,
                last_seen_at: Some(OffsetDateTime::now_utc()),
                now: OffsetDateTime::now_utc(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        (row, key.full_key.expose().clone())
    }

    /// Open a thread (with an a2a grant first) from `key` to `to`.
    async fn open_thread(&self, key: &str, to: &str, payload: Value) -> String {
        let (status, grant) = self
            .b
            .post_as(
                key,
                "/v1/requests",
                json!({"platform": "a2a", "capability": "talk", "resource": to, "scope": {},
                       "justification": "test", "requested_duration": "1h"}),
            )
            .await;
        assert_eq!(status, 200, "{grant}");
        assert_eq!(grant["status"], "granted", "{grant}");
        let (status, t) = self
            .b
            .post_as(
                key,
                "/v1/a2a/threads",
                json!({"to": to, "payload": payload}),
            )
            .await;
        assert_eq!(status, 200, "{t}");
        t["thread_id"].as_str().unwrap().to_owned()
    }

    /// Messages after `after`, waiting through state changes.
    async fn reply_on(&self, key: &str, tid: &str, after: u64) -> Vec<Value> {
        for _ in 0..8 {
            let (_, out) = self
                .b
                .get_as(
                    key,
                    &format!("/v1/a2a/threads/{tid}/messages?after_seq={after}&wait=5"),
                )
                .await;
            let msgs = out["messages"].as_array().cloned().unwrap_or_default();
            if !msgs.is_empty() {
                return msgs;
            }
        }
        Vec::new()
    }

    async fn conv_of(&self, tid: &str) -> ConvId {
        let sbx = Arc::clone(&self.sbx);
        let tid = tid.to_owned();
        assert!(eventually(|| async { sbx.store.thread(&tid).is_some() }).await);
        self.sbx.store.thread(&tid).unwrap().conversation_id
    }

    async fn orch_conv(&self) -> (ConvId, String) {
        let conv = self
            .sbx
            .new_conversation(ORCH, "test", "", "headless")
            .await
            .unwrap();
        let token = self.sbx.live(&conv.id).token().to_owned();
        (conv.id, token)
    }

    fn agent_api(&self) -> AgentApi<FakeHost> {
        AgentApi(Arc::clone(&self.sbx))
    }

    fn operator_api(&self) -> OperatorApi<FakeHost> {
        OperatorApi(Arc::clone(&self.sbx))
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // A failed test leaves nothing behind (its tmux servers are killed
        // by the host double's own drop).
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

async fn agent_call(
    vm: &Vm,
    method: &str,
    params: Value,
    token: &str,
    uid: u32,
) -> Result<Value, String> {
    vm.agent_api()
        .handle(method, &obj(params), Some(token), uid)
        .await
}

fn tmux() -> bool {
    std::process::Command::new("tmux")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

// ------------------------------------------------------------- routing

/// INV-19, INV-12: an a2a open is claimed by a new conversation (with its
/// own session), answered by its process (as the orchestrator, in its
/// workspace), parked when idle, and resumed on the same runtime session.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv19_an_open_is_answered_by_a_routed_conversation_that_parks_and_resumes(
    pool: sqlx::PgPool,
) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "ping"})).await;
    let msgs = vm.reply_on(&hermes, &tid, 1).await;
    assert!(!msgs.is_empty());
    assert_eq!(msgs[0]["payload"]["status"], "done");
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("ping")
    );
    let convs = vm.sbx.store.conversations(Some(ORCH), false);
    assert_eq!(convs.len(), 1);
    let conv = &convs[0];
    assert_eq!(vm.conv_of(&tid).await, conv.id);
    let start = vm.starts()[0].clone();
    assert!(start["cwd"].as_str().unwrap().ends_with("/orchestrator"));
    assert_eq!(start["session"].as_str(), conv.broker_session_id.as_deref());
    assert_eq!(start["uid"], json!(me()), "the orchestrator's uid");
    assert!(start["mcp"].as_bool().unwrap() && !start["resumed"].as_bool().unwrap());
    // Its own reply is not echoed back to it.
    assert!(!vm.turns().iter().any(|t| t.contains("echo")));

    let sbx = Arc::clone(&vm.sbx);
    let id = conv.id.clone();
    assert!(
        eventually(|| async { sbx.store.conversation(&id).unwrap().state == ConvState::Parked })
            .await
    );
    vm.b.post_as(
        &hermes,
        &format!("/v1/a2a/threads/{tid}/messages"),
        json!({"payload": {"task": "again"}}),
    )
    .await;
    let msgs = vm.reply_on(&hermes, &tid, 3).await;
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("again")
    );
    let starts = vm.starts();
    assert_eq!(starts.len(), 2);
    assert!(starts[1]["resumed"].as_bool().unwrap());
    assert_eq!(starts[1]["start"], start["start"]);
    vm.stop().await;
}

/// INV-21: a hint routes a second thread into the same conversation; a
/// hint naming a closed conversation (or another agent's) does not.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv21_a_hint_routes_into_an_existing_open_conversation_only(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let first = vm.open_thread(&hermes, ORCH, json!({"task": "one"})).await;
    vm.reply_on(&hermes, &first, 1).await;
    let conv = vm.conv_of(&first).await;
    let second = vm
        .open_thread(
            &hermes,
            ORCH,
            json!({"task": "two", "_sandbox": {"conversation": conv.as_str()}}),
        )
        .await;
    vm.reply_on(&hermes, &second, 1).await;
    assert_eq!(vm.conv_of(&second).await, conv);
    assert_eq!(vm.sbx.store.conversations(Some(ORCH), false).len(), 1);
    vm.sbx.close(&conv).await.unwrap();
    let third = vm
        .open_thread(
            &hermes,
            ORCH,
            json!({"task": "three", "_sandbox": {"conversation": conv.as_str()}}),
        )
        .await;
    vm.reply_on(&hermes, &third, 1).await;
    assert_ne!(vm.conv_of(&third).await, conv);
    vm.stop().await;
}

/// An open that can't be served here (no runtime) is rejected at once,
/// with a note naming the sandbox.
#[sqlx::test(migrations = "../store/migrations")]
async fn an_open_that_cannot_be_served_is_rejected_not_retried(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    vm.sbx.set_runtimes(BTreeMap::new());
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "ping"})).await;
    let b = &vm.b;
    let closed = eventually(|| async {
        let (_, t) = b.get_as(&hermes, &format!("/v1/a2a/threads/{tid}")).await;
        t["state"] == "closed" && t["close_note"].as_str().unwrap_or("").contains("sandbox:")
    })
    .await;
    assert!(closed);
    vm.stop().await;
}

/// B-17: a thread accepted by a conversation whose process then fails to
/// start is not rejected; its message waits and is delivered later.
#[sqlx::test(migrations = "../store/migrations")]
async fn b17_an_accepted_thread_is_not_rejected_when_its_process_fails(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    *vm.host().fail_start.lock().unwrap() = Some("the runtime broke".into());
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "ping"})).await;
    let conv = vm.conv_of(&tid).await;
    let sbx = Arc::clone(&vm.sbx);
    let c2 = conv.clone();
    assert!(eventually(|| async { !sbx.store.peek(&c2).unwrap().is_empty() }).await);
    let (_, t) =
        vm.b.get_as(&hermes, &format!("/v1/a2a/threads/{tid}"))
            .await;
    assert_eq!(t["state"], "open", "{t}");
    *vm.host().fail_start.lock().unwrap() = None;
    vm.sbx.deliver_queued(&conv).await;
    let msgs = vm.reply_on(&hermes, &tid, 1).await;
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("ping")
    );
    vm.stop().await;
}

/// B-9: a conversation whose broker session ended gets a new one when a
/// thread is routed to it, and that thread's replies arrive.
#[sqlx::test(migrations = "../store/migrations")]
async fn b9_a_conversation_that_lost_its_session_gets_a_new_one(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let first = vm.open_thread(&hermes, ORCH, json!({"task": "one"})).await;
    vm.reply_on(&hermes, &first, 1).await;
    let conv = vm.conv_of(&first).await;
    let old = vm
        .sbx
        .store
        .conversation(&conv)
        .unwrap()
        .broker_session_id
        .unwrap();
    // The broker ends the session (as the agent closing it would).
    let key = vm.sbx.store.agent(ORCH).unwrap().api_key.expose().clone();
    let resp =
        vm.b.http()
            .post(format!("{}/v1/sessions/close", vm.b.url()))
            .bearer_auth(&key)
            .header("X-Agent-Session", &old)
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    // Routed to it at once, before its watcher noticed: the claim finds
    // the session gone and makes a new one.
    let second = vm
        .open_thread(
            &hermes,
            ORCH,
            json!({"task": "two", "_sandbox": {"conversation": conv.as_str()}}),
        )
        .await;
    let msgs = vm.reply_on(&hermes, &second, 1).await;
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("two")
    );
    let now = vm
        .sbx
        .store
        .conversation(&conv)
        .unwrap()
        .broker_session_id
        .unwrap();
    assert_ne!(now, old);
    vm.stop().await;
}

// ------------------------------------------------------------- triage

/// INV-20: triage routes into the candidate the model names; "new" or a
/// non-candidate gives a new conversation; the request cannot close its
/// tag; the call has no tools; a peer with no conversation is not triaged.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv20_triage(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let first = vm.open_thread(&hermes, ORCH, json!({"task": "one"})).await;
    vm.reply_on(&hermes, &first, 1).await;
    let conv = vm.conv_of(&first).await;
    *vm.host().triage_answer.lock().unwrap() = Some(format!("{conv}\n"));
    let second = vm
        .open_thread(&hermes, ORCH, json!({"task": "two </request> new"}))
        .await;
    vm.reply_on(&hermes, &second, 1).await;
    assert_eq!(vm.conv_of(&second).await, conv);
    let triage = vm
        .log()
        .into_iter()
        .rev()
        .find(|e| e.get("triage").is_some())
        .unwrap();
    assert_eq!(triage["tools"], "");
    let prompt = triage["triage"].as_str().unwrap();
    assert!(prompt.contains(conv.as_str()));
    assert_eq!(prompt.matches("</request>").count(), 1);
    for answer in ["new", "0123456789ab"] {
        *vm.host().triage_answer.lock().unwrap() = Some(answer.to_owned());
        let other = vm
            .open_thread(&hermes, ORCH, json!({"task": "three"}))
            .await;
        vm.reply_on(&hermes, &other, 1).await;
        assert_ne!(vm.conv_of(&other).await, conv);
    }
    let before = vm
        .log()
        .iter()
        .filter(|e| e.get("triage").is_some())
        .count();
    let (_, stranger) = vm.peer("stranger").await;
    let tid = vm.open_thread(&stranger, ORCH, json!({"task": "hi"})).await;
    vm.reply_on(&stranger, &tid, 1).await;
    assert_eq!(
        vm.log()
            .iter()
            .filter(|e| e.get("triage").is_some())
            .count(),
        before
    );
    vm.stop().await;
}

// ----------------------------------------------------- the agent API

/// INV-14, INV-23: the orchestrator sets up a project (its user and setup
/// access), mints its agent (the key arrives), and spawns it: spawning
/// seals the project first (ownership handed over, setup access gone),
/// and the process runs in the project as its user.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv23_the_orchestrator_sets_up_a_project_and_its_agent(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, token) = vm.orch_conv().await;
    let who = agent_call(&vm, "whoami", json!({}), &token, me())
        .await
        .unwrap();
    assert_eq!(who["orchestrator"], true);
    assert_eq!(who["agent"], ORCH);
    assert_eq!(who["project"], Value::Null);
    let created = agent_call(
        &vm,
        "project_create",
        json!({"name": "larder"}),
        &token,
        me(),
    )
    .await
    .unwrap();
    let uid = u32::try_from(created["uid"].as_u64().unwrap()).unwrap();
    let path = PathBuf::from(created["path"].as_str().unwrap());
    assert_eq!(vm.host().user("p-larder"), Some(uid));
    assert!(vm.host().acls().contains(&AclCall::Grant {
        path: path.clone(),
        uid: me(),
        write: true
    }));
    let minted = agent_call(
        &vm,
        "agent_mint",
        json!({"runtime": "claude", "project": "larder"}),
        &token,
        me(),
    )
    .await
    .unwrap();
    assert_eq!(minted["status"], "granted", "{minted}");
    assert_eq!(minted["key_received"], true);
    let spawned = agent_call(
        &vm,
        "agent_spawn",
        json!({"agent": "claude-larder-excelsior-sandbox", "prompt": "hello"}),
        &token,
        me(),
    )
    .await
    .unwrap();
    assert_eq!(spawned["agent"], "claude-larder-excelsior-sandbox");
    assert!(spawned.get("broker_session_id").is_none(), "INV-16");
    assert!(
        vm.host()
            .chowns()
            .contains(&(path.clone(), uid, vec![me()]))
    );
    assert!(vm.host().acls().contains(&AclCall::Revoke {
        path: path.clone(),
        uid: me()
    }));
    assert!(vm.sbx.store.project("larder").unwrap().sealed);
    assert!(vm.saw_turn("hello").await);
    let start = vm.starts().last().cloned().unwrap();
    assert_eq!(start["cwd"].as_str().unwrap(), path.display().to_string());
    assert_eq!(start["uid"], json!(uid), "INV-12: the project's uid");
    vm.stop().await;
}

/// INV-14, INV-16: the token alone is never enough (the caller's uid must
/// be the conversation's); a forged token is refused; orchestrator calls
/// are refused to a project's agent; no key or session leaves the API.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv14_the_agent_api_checks_token_uid_and_orchestrator(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, token) = vm.orch_conv().await;
    let e = agent_call(&vm, "whoami", json!({}), &token, me() + 12345)
        .await
        .unwrap_err();
    assert!(e.contains("another user"), "{e}");
    let e = agent_call(&vm, "whoami", json!({}), "forged", me())
        .await
        .unwrap_err();
    assert!(e.contains("unknown conversation"), "{e}");
    let e = vm
        .agent_api()
        .handle("whoami", &Map::new(), None, me())
        .await
        .unwrap_err();
    assert!(e.contains("unknown conversation"), "{e}");
    vm.sbx.create_project("site").unwrap();
    let minted = vm.sbx.mint("claude", "site", "test", 120.0).await.unwrap();
    assert_eq!(minted["status"], "granted", "{minted}");
    let pconv = vm
        .sbx
        .new_conversation("claude-site-excelsior-sandbox", "test", "", "headless")
        .await
        .unwrap();
    let ptoken = vm.sbx.live(&pconv.id).token().to_owned();
    let puid = vm.sbx.project_uid(Some("site")).unwrap();
    let e = agent_call(
        &vm,
        "project_create",
        json!({"name": "evil"}),
        &ptoken,
        puid,
    )
    .await
    .unwrap_err();
    assert!(e.contains("for the orchestrator"), "{e}");
    let who = agent_call(&vm, "whoami", json!({}), &ptoken, puid)
        .await
        .unwrap();
    assert_eq!(who["project"], "site");
    // The orchestrator's token does not work for the project's user.
    assert!(
        agent_call(&vm, "whoami", json!({}), &token, puid)
            .await
            .is_err()
    );
    let convs = agent_call(&vm, "conversations", json!({}), &ptoken, puid)
        .await
        .unwrap();
    let text = convs.to_string();
    assert!(!text.contains("broker_session_id"));
    let key = vm.sbx.store.agent("claude-site-excelsior-sandbox").unwrap();
    assert!(!text.contains(key.api_key.expose().as_str()));
    // A closed conversation's token stops working (B-18).
    vm.sbx.close(&pconv.id).await.unwrap();
    assert!(
        agent_call(&vm, "whoami", json!({}), &ptoken, puid)
            .await
            .is_err()
    );
    vm.stop().await;
}

/// INV-22, INV-13: a broker `sandbox` grant becomes an ACL for the
/// requester project's uid on the target (read: no write); revoking takes
/// it away and keeps what another grant of the pair justifies; revoking
/// the last write grant hands the grantee's files back to the target.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv22_project_grants_are_applied_and_revoked(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    for p in ["larder", "site"] {
        vm.sbx.create_project(p).unwrap();
    }
    // Two projects, no grant: no ACL between them (INV-13).
    assert!(vm.host().acls().is_empty());
    vm.sbx
        .mint("claude", "larder", "test", 120.0)
        .await
        .unwrap();
    let rec = vm
        .sbx
        .store
        .agent("claude-larder-excelsior-sandbox")
        .unwrap();
    let (status, req) = vm
        .b
        .post_as(
            rec.api_key.expose(),
            "/v1/requests",
            json!({"platform": "sandbox", "capability": "project.read", "resource": "site",
                   "scope": {}, "justification": "read the shared schema", "requested_duration": "1h"}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(req["status"], "granted", "{req}");
    let site = vm.sbx.paths(Some("site")).0;
    let larder_uid = vm.sbx.project_uid(Some("larder")).unwrap();
    assert!(vm.host().acls().contains(&AclCall::Grant {
        path: site.clone(),
        uid: larder_uid,
        write: false
    }));
    let grant_id = req["grant_id"].as_str().unwrap().to_owned();
    let (status, _) =
        vm.b.post_as(
            super::testkit::ADMIN_TOKEN,
            &format!("/admin/grants/{grant_id}/revoke"),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    assert!(vm.host().acls().contains(&AclCall::Revoke {
        path: site.clone(),
        uid: larder_uid
    }));
    // An unknown grant id revokes fine (idempotent).
    vm.sbx
        .remove_project_grant("0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9")
        .await
        .unwrap();
    // Read + write of one pair; revoking the write keeps the read and hands
    // the grantee's files back; a read grant never takes write away.
    let site_uid = vm.sbx.project_uid(Some("site")).unwrap();
    vm.sbx
        .apply_project_grant("g-w", "larder", "site", "project.write")
        .await
        .unwrap();
    vm.sbx
        .apply_project_grant("g-r", "larder", "site", "project.read")
        .await
        .unwrap();
    let last = vm.host().acls().last().cloned().unwrap();
    assert_eq!(
        last,
        AclCall::Grant {
            path: site.clone(),
            uid: larder_uid,
            write: true
        }
    );
    vm.sbx.remove_project_grant("g-w").await.unwrap();
    let acls = vm.host().acls();
    assert_eq!(
        acls.last().unwrap(),
        &AclCall::Grant {
            path: site.clone(),
            uid: larder_uid,
            write: false
        }
    );
    // The last write grant gone: what the grantee owns there is reclaimed.
    assert!(
        vm.host()
            .reclaims
            .lock()
            .unwrap()
            .contains(&(site.clone(), larder_uid, site_uid))
    );
    // B-7: a revoke that comes before its grant leaves a tombstone, and the
    // late grant is refused.
    vm.sbx.remove_project_grant("g-late").await.unwrap();
    let e = vm
        .sbx
        .apply_project_grant("g-late", "larder", "site", "project.read")
        .await
        .unwrap_err();
    assert!(e.to_string().contains("was revoked"), "{e}");
    // A revoke that fails is reported and kept, to be done again.
    vm.sbx
        .apply_project_grant("g-w2", "larder", "site", "project.write")
        .await
        .unwrap();
    *vm.host().fail_tree.lock().unwrap() = Some("too deep".into());
    assert!(vm.sbx.remove_project_grant("g-w2").await.is_err());
    assert!(vm.sbx.store.project_grant("g-w2").is_some());
    *vm.host().fail_tree.lock().unwrap() = None;
    vm.sbx.remove_project_grant("g-w2").await.unwrap();
    assert!(vm.sbx.store.project_grant("g-w2").is_none());
    assert!(
        vm.sbx
            .apply_project_grant("g-x", "larder", "site", "project.admin")
            .await
            .is_err()
    );
    assert!(
        vm.sbx
            .apply_project_grant("g-y", "larder", "nope", "project.read")
            .await
            .is_err()
    );
    vm.stop().await;
}

// ---------------------------------------------------- the operator API

/// INV-15: root only; status, projects, mint, new, send, logs, close;
/// `secret_set` writes only its two names, root 0600; no key leaves.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv15_the_operator_api(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let op = vm.operator_api();
    let call = |m: &'static str, p: Value, uid: u32| {
        let op = &op;
        async move { op.handle(m, &obj(p), uid).await }
    };
    assert_eq!(
        call("status", json!({}), 1000).await.unwrap_err(),
        "operators only"
    );
    let status = call("status", json!({}), 0).await.unwrap();
    assert_eq!(status["host"], HOST);
    assert_eq!(status["agents"], 1);
    assert_eq!(status["role"], "sandbox");
    let agents = call("agents", json!({}), 0).await.unwrap();
    assert!(!agents.to_string().contains("aa_"), "no key in the listing");
    call("project_create", json!({"name": "larder"}), 0)
        .await
        .unwrap();
    assert!(vm.sbx.store.project("larder").unwrap().sealed);
    let minted = call("mint", json!({"runtime": "claude", "project": "larder"}), 0)
        .await
        .unwrap();
    assert_eq!(minted["status"], "granted", "{minted}");
    let out = call(
        "new",
        json!({"agent": "claude-larder-excelsior-sandbox", "prompt": "hi", "attach": false}),
        0,
    )
    .await
    .unwrap();
    let id = out["conversation"]["id"].as_str().unwrap().to_owned();
    assert!(vm.saw_turn("hi").await);
    call("send", json!({"conversation": id, "text": "more"}), 0)
        .await
        .unwrap();
    assert!(vm.saw_turn("more").await);
    let log_path = call("log_path", json!({"conversation": id}), 0)
        .await
        .unwrap();
    let text = std::fs::read_to_string(log_path.as_str().unwrap()).unwrap();
    let dirs: Vec<String> = text
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["dir"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(dirs.contains(&"in".to_owned()) && dirs.contains(&"out".to_owned()));
    call("close", json!({"conversation": id}), 0).await.unwrap();
    assert_eq!(
        vm.sbx
            .store
            .conversation(&ConvId::parse(&id).unwrap())
            .unwrap()
            .state,
        ConvState::Closed
    );
    let e = call(
        "secret_set",
        json!({"name": "../../etc/passwd", "value": "x"}),
        0,
    )
    .await
    .unwrap_err();
    assert!(e.starts_with("secrets:"), "{e}");
    call(
        "secret_set",
        json!({"name": "claude-oauth-token", "value": "tok"}),
        0,
    )
    .await
    .unwrap();
    let secret = vm.dir.join("state/secrets/claude-oauth-token");
    assert_eq!(
        std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let e = call("new", json!({"agent": "nobody", "attach": false}), 0)
        .await
        .unwrap_err();
    assert!(e.contains("mint it first"), "{e}");
    vm.stop().await;
}

/// INV-11: the key and the session are in the unit's environment only:
/// not in its argv, not in the MCP config or settings it gets.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv11_secrets_stay_out_of_argv_and_configs(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    vm.operator_api()
        .handle(
            "secret_set",
            &obj(json!({"name": "claude-oauth-token", "value": "oauth-secret"})),
            0,
        )
        .await
        .unwrap();
    let (conv, token) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    let start = vm.starts().last().cloned().unwrap();
    let argv = start["argv"].to_string();
    let key = vm.sbx.store.agent(ORCH).unwrap().api_key.expose().clone();
    for secret in [key.as_str(), token.as_str(), "oauth-secret"] {
        assert!(!argv.contains(secret), "a secret in argv");
    }
    let keys: Vec<String> = start["env_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    for k in [
        "AGENT_AUTH_API_KEY",
        "AGENT_AUTH_SESSION",
        "AGENT_AUTH_SANDBOX_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ] {
        assert!(keys.contains(&k.to_owned()), "{k}");
    }
    // The state files are private.
    for f in [
        "agents.json",
        "flags.json",
        "conversations.json",
        "projects.json",
    ] {
        let p = vm.dir.join("state").join(f);
        if p.exists() {
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600,
                "{f}"
            );
        }
    }
    vm.stop().await;
}

// ---------------------------------------------------- busy and the hook

/// A message for a busy claude waits for its hook (no double delivery);
/// leftovers become one joined next turn.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_message_for_a_busy_claude_waits_for_its_hook_or_the_next_turn(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, token) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "SLOW first").await.unwrap();
    assert!(vm.saw_turn("SLOW first").await);
    assert!(vm.sbx.live(&conv).run().unwrap().busy());
    vm.sbx.deliver(&conv, "[a2a] mid-turn").await.unwrap();
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["[a2a] mid-turn"]);
    let drained = agent_call(&vm, "inbox", json!({"drain": true}), &token, me())
        .await
        .unwrap();
    assert_eq!(drained, json!(["[a2a] mid-turn"]));
    let sbx = Arc::clone(&vm.sbx);
    let c2 = conv.clone();
    assert!(eventually(|| async { !sbx.live(&c2).run().is_some_and(|r| r.busy()) }).await);
    assert!(!vm.turns().contains(&"[a2a] mid-turn".to_owned()));
    vm.sbx.deliver(&conv, "SLOW second").await.unwrap();
    assert!(vm.saw_turn("SLOW second").await);
    vm.sbx.deliver(&conv, "[a2a] late one").await.unwrap();
    vm.sbx.deliver(&conv, "[a2a] late two").await.unwrap();
    assert!(vm.saw_turn("[a2a] late one\n\n[a2a] late two").await);
    assert!(vm.sbx.store.peek(&conv).unwrap().is_empty());
    vm.stop().await;
}

// ------------------------------------------------- lockdown, containment

/// INV-17: lockdown over the channel freezes the units, queues messages,
/// refuses mint and attach; unlock thaws and delivers the queue.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv17_lockdown_freezes_and_holds_work_until_it_is_lifted(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    let mut msg = Map::new();
    msg.insert("type".into(), json!("lockdown"));
    msg.insert("kill_vm".into(), json!(false));
    vm.b.part
        .hub
        .call(
            agent_auth_crypto::daemon::Role::Sandbox,
            HOST,
            msg,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(vm.sbx.locked());
    assert!(vm.host().frozen().contains(&(conv.unit(), true)));
    vm.sbx.deliver(&conv, "while locked").await.unwrap();
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["while locked"]);
    vm.sbx.create_project("larder").unwrap();
    let e = vm
        .sbx
        .mint("claude", "larder", "test", 1.0)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("locked down"));
    let e = vm.sbx.attach(&conv, true).await.unwrap_err();
    assert!(e.to_string().contains("locked down"));
    let mut msg = Map::new();
    msg.insert("type".into(), json!("unlock"));
    assert!(
        vm.b.part
            .hub
            .send_default(agent_auth_crypto::daemon::Role::Sandbox, HOST, &msg)
            .await
    );
    let sbx = Arc::clone(&vm.sbx);
    assert!(eventually(|| async { !sbx.locked() }).await);
    let host_frozen = || vm.host().frozen();
    assert!(eventually(|| async { host_frozen().contains(&(conv.unit(), false)) }).await);
    assert!(vm.saw_turn("while locked").await);
    vm.stop().await;
}

/// INV-17: a contained agent is frozen and its messages held; an empty
/// list releases it, thaws and delivers.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv17_a_contained_agent_is_frozen_and_held_until_released(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    let mut msg = Map::new();
    msg.insert("type".into(), json!("agents.contained"));
    msg.insert("agents".into(), json!([ORCH]));
    vm.b.part
        .hub
        .call(
            agent_auth_crypto::daemon::Role::Sandbox,
            HOST,
            msg,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(vm.sbx.contained(ORCH) && !vm.sbx.locked());
    assert!(vm.host().frozen().contains(&(conv.unit(), true)));
    vm.sbx.deliver(&conv, "while held").await.unwrap();
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["while held"]);
    let mut msg = Map::new();
    msg.insert("type".into(), json!("agents.contained"));
    msg.insert("agents".into(), json!([]));
    vm.b.part
        .hub
        .send_default(agent_auth_crypto::daemon::Role::Sandbox, HOST, &msg)
        .await;
    let sbx = Arc::clone(&vm.sbx);
    assert!(eventually(|| async { !sbx.contained(ORCH) }).await);
    let host_frozen = || vm.host().frozen();
    assert!(eventually(|| async { host_frozen().contains(&(conv.unit(), false)) }).await);
    assert!(vm.saw_turn("while held").await);
    vm.stop().await;
}

/// B-2 (upstream review 2026-10): lifting a lockdown keeps a contained
/// agent frozen and its queue undelivered.
#[sqlx::test(migrations = "../store/migrations")]
async fn b2_lifting_a_lockdown_keeps_a_contained_agent_frozen(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    vm.sbx.lockdown().await;
    vm.sbx.deliver(&conv, "while held").await.unwrap();
    vm.host().clear_frozen();
    vm.sbx.unlock().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!vm.host().frozen().contains(&(conv.unit(), false)));
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["while held"]);
    vm.stop().await;
}

/// B-2: lifting a containment during a lockdown thaws nothing; the unlock
/// then does.
#[sqlx::test(migrations = "../store/migrations")]
async fn b2_lifting_a_containment_during_a_lockdown_thaws_nothing(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    vm.sbx.lockdown().await;
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    vm.host().clear_frozen();
    vm.sbx.release(&[ORCH.to_owned()]).await;
    assert!(!vm.host().frozen().contains(&(conv.unit(), false)));
    vm.sbx.unlock().await;
    assert!(vm.host().frozen().contains(&(conv.unit(), false)));
    vm.stop().await;
}

/// INV-17: a conversation held while its process was starting is frozen
/// and sent nothing; attach and triage refuse.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv17_a_conversation_held_while_it_starts_is_frozen_and_sent_nothing(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    // The hold comes while the process is starting: it sees no process to
    // freeze. The start is held at a gate until the containment is in.
    let (open, gate) = tokio::sync::oneshot::channel();
    *vm.host().start_gate.lock().unwrap() = Some(gate);
    let sbx = Arc::clone(&vm.sbx);
    let c2 = conv.clone();
    let delivering = tokio::spawn(async move { sbx.deliver(&c2, "first").await });
    assert!(eventually(|| async { !vm.starts().is_empty() }).await);
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    open.send(()).unwrap();
    delivering.await.unwrap().unwrap();
    assert!(vm.host().frozen().contains(&(conv.unit(), true)));
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["first"]);
    assert!(!vm.turns().contains(&"first".to_owned()), "sent nothing");
    let e = vm.sbx.attach(&conv, true).await.unwrap_err();
    assert!(e.to_string().contains("contained"));
    let rec = vm.sbx.store.agent(ORCH).unwrap();
    let thread = ThreadView {
        thread_id: "t".into(),
        peer: Some("x".into()),
        role: "responder".into(),
        topic: None,
        last_seq: 0,
        closed: false,
        close_reason: None,
    };
    assert!(vm.sbx.triage(&rec, &thread, None).await.is_none());
    vm.stop().await;
}

/// INV-17: both holds survive a restart of the daemon.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv17_holds_persist_across_a_restart(pool: sqlx::PgPool) {
    let mut vm = Vm::start(pool).await;
    vm.sbx
        .contain(&["claude-x-excelsior-sandbox".to_owned()])
        .await;
    vm.sbx.lockdown().await;
    // The broker is not locked: on reconnect it sends `unlock` (B-3) and
    // the held list. Without a broker connection, both stay.
    vm.stop_daemon().await;
    let sbx = Vm::daemon(&vm.cfg, &vm.dir);
    assert!(sbx.locked());
    assert!(sbx.contained("claude-x-excelsior-sandbox"));
    drop(sbx);
    // B-3: connected again, the broker's state wins: unlocked, nothing held.
    vm.restart().await;
    let sbx = Arc::clone(&vm.sbx);
    assert!(
        eventually(|| async { !sbx.locked() && !sbx.contained("claude-x-excelsior-sandbox") })
            .await
    );
    vm.stop().await;
}

/// INV-18: an agent whose key the broker refuses gets no process (no
/// fallback to the VM's logins).
#[sqlx::test(migrations = "../store/migrations")]
async fn inv18_a_refused_agent_does_not_start_on_the_vms_logins(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    let orch = vm.b.agent(ORCH).await;
    let (status, _) =
        vm.b.post_as(
            super::testkit::ADMIN_TOKEN,
            &format!("/admin/agents/{}/disable", orch.id),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    let e = vm.sbx.deliver(&conv, "hello").await.unwrap_err();
    assert!(e.to_string().contains("401"), "{e}");
    assert!(vm.starts().is_empty());
    assert_eq!(vm.sbx.store.peek(&conv).unwrap(), vec!["hello"]);
    vm.stop().await;
}

// ----------------------------------------------------------- keys

/// B-6 end to end: the daemon's ack names the key, and the broker's
/// pending copy is gone after it.
#[sqlx::test(migrations = "../store/migrations")]
async fn b6_the_daemons_ack_clears_the_pending_key(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let b = &vm.b;
    let gone = eventually(|| async {
        let tx = b.st.store.begin().await.unwrap();
        let d = agent_auth_store::daemons::by_name(
            &tx,
            agent_auth_store::daemons::DaemonRole::Sandbox,
            HOST,
        )
        .await
        .unwrap()
        .unwrap();
        agent_auth_store::sandboxes::pending_for(&tx, d.id)
            .await
            .unwrap()
            .is_empty()
    })
    .await;
    assert!(gone);
    let rec = vm.sbx.store.agent(ORCH).unwrap();
    let (status, me_out) = vm.b.get_as(rec.api_key.expose(), "/v1/me").await;
    assert_eq!(status, 200);
    assert_eq!(me_out["name"], ORCH);
    vm.stop().await;
}

/// A key the broker no longer accepts is replaced: the daemon asks
/// (`key.rotate`), the broker sends a new one, the dispatcher restarts,
/// and threads are answered again.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_lost_key_is_rotated_and_dispatch_resumes(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let old = vm.sbx.store.agent(ORCH).unwrap().key_id.clone();
    // The broker forgets the key (as if replaced elsewhere).
    let orch = vm.b.agent(ORCH).await;
    {
        let k = agent_auth_crypto::api_key::generate().unwrap();
        let tx = vm.b.st.store.begin().await.unwrap();
        agents::set_key(&tx, orch.id, k.key_id.as_str(), k.hash.as_str())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    // The next thread wakes the dispatcher: its key is refused, it asks
    // for a new one, and the thread is answered with it.
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "ping"})).await;
    let msgs = vm.reply_on(&hermes, &tid, 1).await;
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("ping")
    );
    assert_ne!(vm.sbx.store.agent(ORCH).unwrap().key_id, old);
    vm.stop().await;
}

/// B-8: a minted agent whose lease ran out is re-enabled by a mint with a
/// new key, and its dispatcher answers threads again.
#[sqlx::test(migrations = "../store/migrations")]
async fn b8_a_lapsed_agent_reminted_answers_again(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    vm.sbx.create_project("larder").unwrap();
    let minted = vm
        .sbx
        .mint("claude", "larder", "test", 120.0)
        .await
        .unwrap();
    assert_eq!(minted["key_received"], true, "{minted}");
    let name = "claude-larder-excelsior-sandbox";
    let child = vm.b.agent(name).await;
    {
        let tx = vm.b.st.store.begin().await.unwrap();
        agents::set_lease(
            &tx,
            child.id,
            Some(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    crate::scheduler::sweep_leases(&vm.b.st).await;
    assert!(vm.b.agent(name).await.disabled);
    let old = vm.sbx.store.agent(name).unwrap().key_id.clone();
    let again = vm
        .sbx
        .mint("claude", "larder", "renew", 120.0)
        .await
        .unwrap();
    assert_eq!(again["status"], "granted", "{again}");
    let sbx = Arc::clone(&vm.sbx);
    assert!(eventually(|| async { sbx.store.agent(name).unwrap().key_id != old }).await);
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, name, json!({"task": "ping"})).await;
    let msgs = vm.reply_on(&hermes, &tid, 1).await;
    assert!(
        msgs[0]["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("ping")
    );
    vm.stop().await;
}

// ------------------------------------------------------- limits (B-4)

/// B-4: `max_processes` bounds running processes, not starts: a second
/// conversation's process starts only once the first has parked.
#[sqlx::test(migrations = "../store/migrations")]
async fn b4_process_limits_hold_for_the_life_of_a_process(pool: sqlx::PgPool) {
    let vm = Vm::start_with(pool, |c| c["max_processes"] = json!(1)).await;
    let (a, _) = vm.orch_conv().await;
    let (b2, _) = vm.orch_conv().await;
    vm.sbx.deliver(&a, "SLOW first").await.unwrap();
    assert!(vm.saw_turn("SLOW first").await);
    let sbx = Arc::clone(&vm.sbx);
    let second = tokio::spawn(async move { sbx.deliver(&b2, "second").await });
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(vm.starts().len(), 1, "the second waits for a slot");
    second.await.unwrap().unwrap();
    assert!(vm.saw_turn("second").await);
    assert_eq!(vm.starts().len(), 2);
    let sbx = Arc::clone(&vm.sbx);
    let a2 = a.clone();
    assert!(sbx.live(&a2).run().is_none(), "the first had parked");
    vm.stop().await;
}

// ----------------------------------------------------------- the TUI

/// Attach (claude): the headless run stops, the TUI resumes the same
/// session, a2a queues while attached, and stopping the TUI delivers the
/// queue headless.
#[sqlx::test(migrations = "../store/migrations")]
async fn interactive_attach_hands_the_session_to_a_tui(pool: sqlx::PgPool) {
    if !tmux() {
        return;
    }
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "ping"})).await;
    vm.reply_on(&hermes, &tid, 1).await;
    let conv = vm.conv_of(&tid).await;
    let info = vm.sbx.attach(&conv, true).await.unwrap();
    let argv: Vec<String> = serde_json::from_value(info["argv"].clone()).unwrap();
    assert_eq!(&argv[argv.len() - 3..], ["attach", "-t", "conv"]);
    assert!(vm.sbx.live(&conv).run().is_none());
    assert_eq!(
        vm.sbx.store.conversation(&conv).unwrap().state,
        ConvState::Attached
    );
    let tui_started = eventually(|| async {
        vm.log()
            .iter()
            .any(|e| e.get("tui").and_then(Value::as_bool) == Some(true))
    })
    .await;
    assert!(tui_started);
    let tui = vm
        .log()
        .into_iter()
        .rev()
        .find(|e| e["tui"] == true)
        .unwrap();
    let first = vm.starts()[0].clone();
    assert_eq!(tui["start"], first["start"]);
    assert_eq!(tui["resumed"], true);
    vm.sbx
        .deliver(&conv, "[a2a] queued while attached")
        .await
        .unwrap();
    assert_eq!(
        vm.sbx.store.peek(&conv).unwrap(),
        vec!["[a2a] queued while attached"]
    );
    vm.sbx.stop_tui(&conv).await;
    assert!(vm.saw_turn("[a2a] queued while attached").await);
    vm.stop().await;
}

/// A TUI that exits at once raises with its output, and its unit is gone.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_tui_that_fails_reports_its_output(pool: sqlx::PgPool) {
    if !tmux() {
        return;
    }
    let vm = Vm::start(pool).await;
    let broken = vm.dir.join("broken-claude");
    std::fs::write(&broken, "#!/bin/sh\necho 'boom: bad flag'\nexit 3\n").unwrap();
    std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut rts = BTreeMap::new();
    let mut rt = vm.sbx.runtime("claude").unwrap();
    rt.set_command(broken.to_str().unwrap());
    rts.insert("claude".to_owned(), rt);
    vm.sbx.set_runtimes(rts);
    let (conv, _) = vm.orch_conv().await;
    let e = vm.sbx.attach(&conv, false).await.unwrap_err();
    assert!(e.to_string().contains("boom: bad flag"), "{e}");
    assert!(!agent_auth_sandboxd::host::Host::unit_active(vm.host(), &conv.tui_unit()).await);
    vm.stop().await;
}

/// B-5: an attached TUI nobody uses is ended after
/// `interactive_idle_secs`; the conversation goes back to headless.
#[sqlx::test(migrations = "../store/migrations")]
async fn b5_an_idle_tui_is_reaped(pool: sqlx::PgPool) {
    if !tmux() {
        return;
    }
    let vm = Vm::start_with(pool, |c| c["interactive_idle_secs"] = json!(1)).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.attach(&conv, true).await.unwrap();
    assert!(vm.sbx.live(&conv).tui());
    tokio::time::sleep(Duration::from_millis(2200)).await;
    vm.sbx.reap_once().await;
    assert!(!vm.sbx.live(&conv).tui());
    assert_eq!(
        vm.sbx.store.conversation(&conv).unwrap().state,
        ConvState::Parked
    );
    vm.stop().await;
}

// ------------------------------------------------------ codex login

/// The shared codex login: every project but the designated owner gets a
/// read-only copy (its changes never go back); the owner's refreshed copy
/// goes back; a `.codex` symlink is never followed.
#[sqlx::test(migrations = "../store/migrations")]
async fn the_shared_codex_login_is_written_back_by_its_owner_only(pool: sqlx::PgPool) {
    let vm = Vm::start_with(pool, |c| c["codex_auth_owner"] = json!("owner")).await;
    for p in ["owner", "other"] {
        vm.sbx.create_project(p).unwrap();
    }
    vm.operator_api()
        .handle(
            "secret_set",
            &obj(json!({"name": "codex-auth.json", "value": "{\"tokens\": {\"refresh_token\": \"r1\", \"account_id\": \"acct\"}}"})),
            0,
        )
        .await
        .unwrap();
    let shared = vm.dir.join("state/secrets/codex-auth.json");
    let home = |p: &str| vm.dir.join("sb/homes").join(p).join(".codex/auth.json");
    vm.sbx.codex_sync_into(Some("other"), 1).await;
    assert_eq!(
        std::fs::read_to_string(home("other")).unwrap(),
        "{\"tokens\": {\"refresh_token\": \"r1\", \"account_id\": \"acct\"}}"
    );
    std::fs::write(home("other"), "{\"v\": \"theirs\"}").unwrap();
    vm.sbx.codex_sync_back(Some("other"), 1).await;
    assert_eq!(
        std::fs::read_to_string(&shared).unwrap(),
        "{\"tokens\": {\"refresh_token\": \"r1\", \"account_id\": \"acct\"}}",
        "never written back"
    );
    vm.sbx.codex_sync_into(Some("other"), 1).await;
    assert_eq!(
        std::fs::read_to_string(home("other")).unwrap(),
        "{\"tokens\": {\"refresh_token\": \"r1\", \"account_id\": \"acct\"}}",
        "the shared copy wins"
    );
    vm.sbx.codex_sync_into(Some("owner"), 1).await;
    std::fs::write(
        home("owner"),
        "{\"tokens\": {\"refresh_token\": \"r2\", \"account_id\": \"acct\"}}",
    )
    .unwrap();
    vm.sbx.codex_sync_back(Some("owner"), 1).await;
    assert_eq!(
        std::fs::read_to_string(&shared).unwrap(),
        "{\"tokens\": {\"refresh_token\": \"r2\", \"account_id\": \"acct\"}}"
    );
    // A login of another account is not copied back (the owner can't swap
    // in its own).
    std::fs::write(
        home("owner"),
        "{\"tokens\": {\"refresh_token\": \"r3\", \"account_id\": \"mine\"}}",
    )
    .unwrap();
    vm.sbx.codex_sync_back(Some("owner"), 1).await;
    assert_eq!(
        std::fs::read_to_string(&shared).unwrap(),
        "{\"tokens\": {\"refresh_token\": \"r2\", \"account_id\": \"acct\"}}"
    );
    // A project that swaps its .codex for a symlink gets nothing written
    // through it.
    let evil = vm.dir.join("sb/homes/other/.codex");
    std::fs::remove_dir_all(&evil).unwrap();
    let target = vm.dir.join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, &evil).unwrap();
    vm.sbx.codex_sync_into(Some("other"), 1).await;
    assert!(!target.join("auth.json").exists());
    vm.stop().await;
}

/// B-7 (review #5): on connect the broker lists the VM's live project
/// grants; a grant recorded in the VM and not listed is revoked.
#[sqlx::test(migrations = "../store/migrations")]
async fn b7_a_grant_the_broker_does_not_have_is_revoked_on_connect(pool: sqlx::PgPool) {
    let mut vm = Vm::start(pool).await;
    for p in ["larder", "site"] {
        vm.sbx.create_project(p).unwrap();
    }
    vm.sbx
        .apply_project_grant(
            "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9",
            "larder",
            "site",
            "project.read",
        )
        .await
        .unwrap();
    vm.restart().await;
    let sbx = Arc::clone(&vm.sbx);
    assert!(
        eventually(|| async {
            sbx.store
                .project_grant("0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9")
                .is_none()
        })
        .await
    );
    let site = vm.sbx.paths(Some("site")).0;
    let larder_uid = vm.sbx.project_uid(Some("larder")).unwrap();
    assert!(vm.host().acls().contains(&AclCall::Revoke {
        path: site,
        uid: larder_uid
    }));
    vm.stop().await;
}

/// Review #5 item 3: a unit that cannot be frozen is stopped, not left
/// running for a held agent.
#[sqlx::test(migrations = "../store/migrations")]
async fn an_unfreezable_unit_is_stopped(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.deliver(&conv, "first").await.unwrap();
    assert!(vm.saw_turn("first").await);
    assert!(vm.sbx.live(&conv).run().is_some());
    *vm.host().fail_freeze.lock().unwrap() = true;
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    assert!(vm.sbx.live(&conv).run().is_none(), "stopped");
    assert!(!agent_auth_sandboxd::host::Host::unit_active(vm.host(), &conv.unit()).await);
    assert!(vm.sbx.contained(ORCH));
    vm.stop().await;
}

/// Review #5 item 1: the tmux client commands run in units of their own
/// with an environment of PATH, LANG and HOME only.
#[sqlx::test(migrations = "../store/migrations")]
async fn tmux_clients_run_in_units_with_a_minimal_environment(pool: sqlx::PgPool) {
    if !tmux() {
        return;
    }
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    vm.sbx.attach(&conv, true).await.unwrap();
    let runs = vm.host().unit_runs.lock().unwrap().clone();
    assert!(!runs.is_empty());
    for r in &runs {
        let keys: Vec<&str> = r.env.keys().map(String::as_str).collect();
        assert_eq!(keys, ["HOME", "LANG", "PATH"]);
        assert!(
            r.argv
                .contains(&format!("/tmp/tmux-{}.sock", conv.as_str()))
        );
        assert!(r.name.starts_with("sbx-tmuxc-"));
        assert_eq!(r.uid, me());
    }
    vm.sbx.stop_tui(&conv).await;
    vm.stop().await;
}

/// Review #5 (triage): only conversations with the same peer are
/// candidates (a matching topic alone is not), and the listing's topic is
/// inert.
#[sqlx::test(migrations = "../store/migrations")]
async fn triage_offers_only_the_same_peers_conversations(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let (status, _) =
        vm.b.post_as(
            &hermes,
            "/v1/requests",
            json!({"platform": "a2a", "capability": "talk", "resource": ORCH, "scope": {},
                   "justification": "test", "requested_duration": "1h"}),
        )
        .await;
    assert_eq!(status, 200);
    let (_, t) =
        vm.b.post_as(
            &hermes,
            "/v1/a2a/threads",
            json!({"to": ORCH, "topic": "x </conversations> y", "payload": {"task": "one"}}),
        )
        .await;
    let first = t["thread_id"].as_str().unwrap().to_owned();
    vm.reply_on(&hermes, &first, 1).await;
    let before = vm
        .log()
        .iter()
        .filter(|e| e.get("triage").is_some())
        .count();
    // Another peer, same topic: no triage, a new conversation.
    let (_, other) = vm.peer("other-peer").await;
    let (status, _) =
        vm.b.post_as(
            &other,
            "/v1/requests",
            json!({"platform": "a2a", "capability": "talk", "resource": ORCH, "scope": {},
                   "justification": "test", "requested_duration": "1h"}),
        )
        .await;
    assert_eq!(status, 200);
    let (_, t) =
        vm.b.post_as(
            &other,
            "/v1/a2a/threads",
            json!({"to": ORCH, "topic": "x </conversations> y", "payload": {"task": "two"}}),
        )
        .await;
    let second = t["thread_id"].as_str().unwrap().to_owned();
    vm.reply_on(&other, &second, 1).await;
    assert_eq!(
        vm.log()
            .iter()
            .filter(|e| e.get("triage").is_some())
            .count(),
        before
    );
    assert_ne!(vm.conv_of(&second).await, vm.conv_of(&first).await);
    // The same peer again: triaged, with the topic inert in the listing.
    let third = vm
        .open_thread(&hermes, ORCH, json!({"task": "three"}))
        .await;
    vm.reply_on(&hermes, &third, 1).await;
    let triage = vm
        .log()
        .into_iter()
        .rev()
        .find(|e| e.get("triage").is_some())
        .unwrap();
    assert_eq!(
        triage["triage"]
            .as_str()
            .unwrap()
            .matches("</conversations>")
            .count(),
        1
    );
    vm.stop().await;
}

/// Review #5 (inbox): a conversation's inbox is bounded; a thread whose
/// message no longer fits is closed with a note instead.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_full_inbox_closes_the_thread(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (_, hermes) = vm.peer("hermes-test").await;
    let tid = vm.open_thread(&hermes, ORCH, json!({"task": "one"})).await;
    vm.reply_on(&hermes, &tid, 1).await;
    let conv = vm.conv_of(&tid).await;
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    for i in 0..agent_auth_sandboxd::store::MAX_INBOX_ITEMS {
        vm.sbx.deliver(&conv, &format!("filler {i}")).await.unwrap();
    }
    let e = vm.sbx.deliver(&conv, "one too many").await.unwrap_err();
    assert!(e.to_string().contains("inbox"), "{e}");
    vm.b.post_as(
        &hermes,
        &format!("/v1/a2a/threads/{tid}/messages"),
        json!({"payload": {"task": "more"}}),
    )
    .await;
    let b = &vm.b;
    let closed = eventually(|| async {
        let (_, t) = b.get_as(&hermes, &format!("/v1/a2a/threads/{tid}")).await;
        t["state"] == "closed" && t["close_note"].as_str().unwrap_or("").contains("inbox")
    })
    .await;
    assert!(closed);
    vm.stop().await;
}

/// Review #5 (sessions): closing a conversation closes its broker session.
#[sqlx::test(migrations = "../store/migrations")]
async fn closing_a_conversation_closes_its_session(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let (conv, _) = vm.orch_conv().await;
    let sid = vm
        .sbx
        .store
        .conversation(&conv)
        .unwrap()
        .broker_session_id
        .unwrap();
    vm.sbx.close(&conv).await.unwrap();
    assert!(
        vm.sbx
            .store
            .conversation(&conv)
            .unwrap()
            .broker_session_id
            .is_none()
    );
    let tx = vm.b.st.store.begin().await.unwrap();
    let row = agent_auth_store::sessions::get(&tx, sid.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(row.closed.is_some(), "the broker's session is closed");
    vm.stop().await;
}

/// Review #5 (codex): a contained agent's copy of the codex login goes.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_contained_agents_codex_login_copy_goes(pool: sqlx::PgPool) {
    let vm = Vm::start(pool).await;
    let codex = vm.dir.join("sb/homes/_orchestrator/.codex");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(codex.join("auth.json"), "{}").unwrap();
    vm.sbx.contain(&[ORCH.to_owned()]).await;
    assert!(!codex.join("auth.json").exists());
    vm.stop().await;
}
