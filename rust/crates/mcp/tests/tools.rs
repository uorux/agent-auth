//! The tools against a fake broker (tests/test_mcp_sessions.py): session
//! routing, the minted session's lifecycle, get_credential(to_file=True).

// Test code: helpers outside #[test] functions may unwrap and index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_auth_client::testing::{FakeBroker, Reply, Seen, shapes};
use agent_auth_client::{BrokerClient, Config};
use agent_auth_mcp::caller::{Caller, LocalCaller};
use agent_auth_mcp::dispatch::call;
use agent_auth_wire::common::AgentKind;
use serde_json::{Value, json};

const S1: &str = "a0000000-0000-4000-8000-000000000001";
const S2: &str = "a0000000-0000-4000-8000-000000000002";
const THEIRS: &str = "a0000000-0000-4000-8000-0000000000ff";

fn client(url: &str) -> BrokerClient {
    BrokerClient::new(Config {
        base_url: Some(url.to_owned()),
        api_key: Some("aa_abcdef_secret".into()),
        ..Config::default()
    })
    .unwrap()
}

fn service(url: &str) -> LocalCaller {
    LocalCaller::new(client(url)).with_kind(AgentKind::Service)
}

async fn tool(caller: &LocalCaller, name: &str, args: Value) -> Value {
    let text = call(caller, name, args.as_object()).await.unwrap();
    serde_json::from_str(&text).unwrap()
}

fn sessions(calls: &[Seen]) -> Vec<Option<String>> {
    calls
        .iter()
        .map(|c| c.header("x-agent-session").map(str::to_owned))
        .collect()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agent-auth-mcp-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn create_session_returns_an_id_without_touching_the_shared_client() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("POST", "/v1/sessions", 200, shapes::session(S1));
    fake.json("GET", "/v1/a2a/threads", 200, json!([]));
    let caller = service(&fake.url);

    let out = tool(&caller, "create_session", json!({"label": "task"})).await;
    assert_eq!(out["session_id"], S1);
    assert_eq!(
        fake.calls("POST", "/v1/sessions")[0].json(),
        json!({"label": "task"})
    );

    tool(&caller, "a2a_threads", json!({})).await;
    assert_eq!(sessions(&fake.calls("GET", "/v1/a2a/threads")), [None]);
    assert_eq!(caller.client().session_id(), None);
}

#[tokio::test]
async fn session_key_routes_each_call_on_its_own() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "POST",
        "/v1/a2a/threads/*/accept",
        200,
        shapes::thread(shapes::THREAD_ID, "open"),
    );
    let caller = service(&fake.url);
    tool(
        &caller,
        "a2a_accept",
        json!({"thread_id": "t1", "session_key": "sess-A"}),
    )
    .await;
    tool(
        &caller,
        "a2a_accept",
        json!({"thread_id": "t2", "session_key": "sess-B"}),
    )
    .await;
    tool(&caller, "a2a_accept", json!({"thread_id": "t3"})).await;
    assert_eq!(
        sessions(&fake.calls("POST", "/v1/a2a/threads/*/accept")),
        [Some("sess-A".into()), Some("sess-B".into()), None]
    );
    assert_eq!(caller.client().session_id(), None);
}

#[tokio::test]
async fn request_access_forwards_the_delegation_and_the_session_key() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("POST", "/v1/requests", 200, shapes::request("granted"));
    let caller = service(&fake.url);
    let out = tool(
        &caller,
        "request_access",
        json!({
            "platform": "homelab", "capability": "group", "resource": "svc-gitea",
            "justification": "claude asked in-thread",
            "on_behalf_of_thread": shapes::THREAD_ID, "session_key": "sess-A"
        }),
    )
    .await;
    assert_eq!(out["status"], "granted");
    let req = &fake.calls("POST", "/v1/requests")[0];
    assert_eq!(req.json()["on_behalf_of_thread"], shapes::THREAD_ID);
    assert_eq!(req.json()["requested_duration"], 3600);
    assert_eq!(req.json()["scope"], json!({}));
    assert_eq!(req.header("x-agent-session"), Some("sess-A"));
}

#[tokio::test]
async fn close_session_closes_the_given_key() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "POST",
        "/v1/sessions/close",
        200,
        json!({"ok": true, "threads_closed": 1}),
    );
    let caller = service(&fake.url);
    let out = tool(&caller, "close_session", json!({"session_key": "sess-A"})).await;
    assert_eq!(out, json!({"ok": true, "threads_closed": 1}));
    assert_eq!(
        sessions(&fake.calls("POST", "/v1/sessions/close")),
        [Some("sess-A".into())]
    );
    assert_eq!(caller.client().session_id(), None);
}

#[tokio::test]
async fn whoami() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("GET", "/v1/me", 200, shapes::me("ephemeral"));
    let caller = LocalCaller::new(client(&fake.url));
    assert_eq!(
        tool(&caller, "whoami", json!({})).await["name"],
        "claude-x-host"
    );
    // No session is minted for whoami.
    assert!(fake.calls("POST", "/v1/sessions").is_empty());
}

type Ids = Arc<Mutex<Vec<String>>>;

/// Sessions S1, S2, ... are minted in turn; those in `closed` are refused
/// the way the broker refuses an idled-out session.
fn idle_sweep(fake: &FakeBroker) -> (Ids, Ids) {
    let closed: Arc<Mutex<Vec<String>>> = Arc::default();
    let minted: Arc<Mutex<Vec<String>>> = Arc::default();
    let m = minted.clone();
    fake.on("POST", "/v1/sessions", move |_| {
        let mut m = m.lock().unwrap();
        let id = [S1, S2][m.len().min(1)].to_owned();
        m.push(id.clone());
        Reply::json(200, &shapes::session(&id))
    });
    let answer = |closed: Arc<Mutex<Vec<String>>>, ok: Value| {
        move |seen: &Seen| {
            let session = seen
                .header("x-agent-session")
                .unwrap_or_default()
                .to_owned();
            if closed.lock().unwrap().contains(&session) {
                Reply::detail(401, "unknown or closed session")
            } else {
                Reply::json(200, &ok)
            }
        }
    };
    fake.on(
        "GET",
        "/v1/me",
        answer(closed.clone(), shapes::me("ephemeral")),
    );
    fake.on("GET", "/v1/a2a/threads", answer(closed.clone(), json!([])));
    (closed, minted)
}

#[tokio::test]
async fn a_minted_session_the_broker_closed_is_replaced() {
    let fake = FakeBroker::start().await.unwrap();
    let (closed, minted) = idle_sweep(&fake);
    let caller = LocalCaller::new(client(&fake.url)).with_kind(AgentKind::Ephemeral);

    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([]));
    closed.lock().unwrap().push(S1.into()); // a long wait for a human: idled out
    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([]));
    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([]));

    assert_eq!(*minted.lock().unwrap(), [S1, S2]);
    assert_eq!(
        sessions(&fake.calls("GET", "/v1/a2a/threads")),
        [
            Some(S1.into()),
            Some(S1.into()),
            Some(S2.into()),
            Some(S2.into())
        ]
    );
    // The label is the working directory's name.
    assert_eq!(
        fake.calls("POST", "/v1/sessions")[0].json(),
        json!({"label": agent_auth_client::default_session_label()})
    );
}

#[tokio::test]
async fn a_session_the_caller_named_is_not_replaced() {
    let fake = FakeBroker::start().await.unwrap();
    let (closed, minted) = idle_sweep(&fake);
    closed.lock().unwrap().push(THEIRS.into());
    let caller = LocalCaller::new(client(&fake.url)).with_kind(AgentKind::Ephemeral);

    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([])); // mints S1
    let text = call(
        &caller,
        "a2a_threads",
        json!({"session_key": THEIRS}).as_object(),
    )
    .await
    .unwrap();
    assert_eq!(
        text,
        r#"{"error": "unknown or closed session", "status_code": 401}"#
    );
    assert_eq!(*minted.lock().unwrap(), [S1]);
    assert_eq!(caller.client().session_id().as_deref(), Some(S1));
}

#[tokio::test]
async fn the_kind_is_asked_once_and_a_service_agent_stays_sessionless() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("GET", "/v1/me", 200, shapes::me("service"));
    fake.json("GET", "/v1/a2a/threads", 200, json!([]));
    let caller = LocalCaller::new(client(&fake.url));
    tool(&caller, "a2a_threads", json!({})).await;
    tool(&caller, "a2a_threads", json!({})).await;
    assert_eq!(fake.calls("GET", "/v1/me").len(), 1);
    assert!(fake.calls("POST", "/v1/sessions").is_empty());
    assert_eq!(
        sessions(&fake.calls("GET", "/v1/a2a/threads")),
        [None, None]
    );
}

#[tokio::test]
async fn a_minted_session_is_kept_in_use_while_the_agent_is_quiet() {
    let fake = FakeBroker::start().await.unwrap();
    let (closed, minted) = idle_sweep(&fake);
    let caller = LocalCaller::new(client(&fake.url))
        .with_kind(AgentKind::Ephemeral)
        .with_keepalive(Duration::from_millis(20));

    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([]));
    tokio::time::sleep(Duration::from_millis(200)).await; // the agent does nothing
    let touched = sessions(&fake.calls("GET", "/v1/me"));
    assert!(touched.len() >= 3, "{touched:?}");
    assert!(touched.iter().all(|s| s.as_deref() == Some(S1)));

    // Closed all the same (the broker restarted, say): forgotten, and the
    // next call gets a new one, which is kept in use in its turn.
    closed.lock().unwrap().push(S1.into());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(caller.client().session_id(), None);
    let before = fake.calls("GET", "/v1/me").len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fake.calls("GET", "/v1/me").len(),
        before,
        "the old keep-alive stopped"
    );
    assert_eq!(tool(&caller, "a2a_threads", json!({})).await, json!([]));
    assert_eq!(*minted.lock().unwrap(), [S1, S2]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let last = fake.calls("GET", "/v1/me").last().cloned().unwrap();
    assert_eq!(last.header("x-agent-session"), Some(S2));
    caller.client().set_session_id(None); // stops it
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn get_credential_to_file_keeps_the_token_out_of_the_reply() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "GET",
        "/v1/grants/g-1/credential",
        200,
        shapes::credential(
            "github_installation_token",
            Some("ghs_secret"),
            Some(shapes::T),
        ),
    );
    fake.json(
        "GET",
        "/v1/grants/g-2/credential",
        200,
        shapes::credential("github_repo", Some("https://github.com/o/r"), None),
    );
    fake.json(
        "GET",
        "/v1/grants/g-3/credential",
        200,
        shapes::credential("kubernetes_token", Some("k8s_secret"), None),
    );
    let tmp = TempDir::new();
    let dir = tmp.0.join("agent-auth").join("credentials");
    let caller = service(&fake.url).with_credential_dir(dir.clone());

    let raw = call(
        &caller,
        "get_credential",
        json!({"grant_id": "g-1", "to_file": true}).as_object(),
    )
    .await
    .unwrap();
    let out: Value = serde_json::from_str(&raw).unwrap();
    let path = dir.join("g-1");
    assert!(!raw.contains("ghs_secret"));
    assert_eq!(out["value"], Value::Null);
    assert_eq!(out["kind"], "github_installation_token");
    assert_eq!(out["file"], json!(path.to_str().unwrap()));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "ghs_secret");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir), 0o700);
    let helper = out["git_helper"].as_str().unwrap();
    assert!(helper.contains(path.to_str().unwrap()));
    assert_eq!(
        helper,
        format!(
            "!f() {{ echo username=x-access-token; echo \"password=$(cat {})\"; }}; f",
            path.display()
        )
    );
    assert_eq!(
        out["git_example"],
        json!(format!(
            "git -c credential.helper= -c credential.helper='{helper}' push https://github.com/<owner>/<repo>.git <branch>"
        ))
    );
    // The reply's keys: the credential's, then the file's.
    let keys: Vec<&str> = raw
        .lines()
        .filter_map(|l| l.strip_prefix("  \""))
        .map(|l| l.split('"').next().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "kind",
            "value",
            "username",
            "url",
            "expires_at",
            "note",
            "file",
            "git_helper",
            "git_example"
        ]
    );

    // Not a secret: the URL of a created repo stays in the reply.
    let out = tool(
        &caller,
        "get_credential",
        json!({"grant_id": "g-2", "to_file": true}),
    )
    .await;
    assert_eq!(out["value"], "https://github.com/o/r");
    assert!(out.get("file").is_none());
    assert!(!dir.join("g-2").exists());
    // Without to_file, the value itself.
    assert_eq!(
        tool(&caller, "get_credential", json!({"grant_id": "g-1"})).await["value"],
        "ghs_secret"
    );
    // A kubernetes token: a file, no git helper.
    let out = tool(
        &caller,
        "get_credential",
        json!({"grant_id": "g-3", "to_file": true}),
    )
    .await;
    assert!(out.get("git_helper").is_none());
    assert_eq!(
        std::fs::read_to_string(dir.join("g-3")).unwrap(),
        "k8s_secret"
    );
}

#[tokio::test]
async fn to_file_refuses_a_symlink_and_tightens_what_exists() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "GET",
        "/v1/grants/*/credential",
        200,
        shapes::credential("mcp_token", Some("tok_secret"), None),
    );
    let tmp = TempDir::new();
    let dir = tmp.0.join("credentials");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let caller = service(&fake.url).with_credential_dir(dir.clone());

    // A link planted where the file goes, pointing at something of ours.
    let victim = tmp.0.join("victim");
    std::fs::write(&victim, "precious").unwrap();
    symlink(&victim, dir.join("g-link")).unwrap();
    let err = call(
        &caller,
        "get_credential",
        json!({"grant_id": "g-link", "to_file": true}).as_object(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("symbolic link"), "{err}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    assert!(
        std::fs::symlink_metadata(dir.join("g-link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // No temporary file left behind.
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");

    // An existing, readable file is replaced by a private one; the
    // directory is made private.
    let path = dir.join("g-old");
    std::fs::write(&path, "stale").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    tool(
        &caller,
        "get_credential",
        json!({"grant_id": "g-old", "to_file": true}),
    )
    .await;
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "tok_secret");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir), 0o700);

    // A directory that is a link is refused too.
    let real = tmp.0.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let linked = tmp.0.join("linked");
    symlink(&real, &linked).unwrap();
    let caller = service(&fake.url).with_credential_dir(linked);
    let err = call(
        &caller,
        "get_credential",
        json!({"grant_id": "g-x", "to_file": true}).as_object(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("not a directory"), "{err}");
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

#[tokio::test]
async fn host_run_asks_waits_and_returns_the_job() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "POST",
        "/v1/requests",
        200,
        shapes::request("awaiting_human"),
    );
    fake.json(
        "GET",
        "/v1/requests/*/wait",
        200,
        shapes::request("granted"),
    );
    fake.json(
        "GET",
        "/v1/hostexec/jobs/*",
        200,
        shapes::job(shapes::REQUEST_ID, "done"),
    );
    let caller = service(&fake.url);
    let out = tool(
        &caller,
        "host_run",
        json!({
            "host": "excelsior", "argv": ["systemctl", "--user", "status", "foo"],
            "justification": "check foo", "cwd": "", "env": {"A": "1"}, "stdin": "",
            "wait_secs": 30
        }),
    )
    .await;
    assert_eq!(out["request"]["status"], "granted");
    assert_eq!(out["job"]["status"], "done");
    let req = fake.calls("POST", "/v1/requests")[0].json();
    assert_eq!(req["platform"], "hostexec");
    assert_eq!(req["capability"], "run");
    assert_eq!(req["resource"], "excelsior");
    assert_eq!(req["requested_duration"], 3600);
    assert_eq!(
        req["scope"],
        json!({"tier": "user", "argv": ["systemctl", "--user", "status", "foo"], "timeout": 600,
               "env": {"A": "1"}, "stdin": ""})
    );
    assert_eq!(
        fake.calls("GET", "/v1/requests/*/wait")[0].param("timeout"),
        Some("30.0")
    );
    let job = &fake.calls("GET", "/v1/hostexec/jobs/*")[0];
    assert_eq!(
        job.path,
        format!("/v1/hostexec/jobs/{}", shapes::REQUEST_ID)
    );

    // Denied: no job.
    fake.json("GET", "/v1/requests/*/wait", 200, shapes::request("denied"));
    let out = tool(
        &caller,
        "host_run",
        json!({"host": "excelsior", "argv": ["true"], "justification": "j"}),
    )
    .await;
    assert!(out.get("job").is_none());
}
