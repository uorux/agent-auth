//! Test support: a broker with the daemon part, served on loopback, and a
//! real hostd (the `agent-auth-hostd` crate, jobs run by its direct
//! executor as this test's user) paired with it over HTTP and connected
//! over the WebSocket channel.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::Policy;
use agent_auth_core::{AgentId, Platform};
use agent_auth_crypto::Secret;
use agent_auth_crypto::daemon::{DaemonId as ChannelId, DaemonName, Role, SigningKey};
use agent_auth_crypto::totp::TotpSecret;
use agent_auth_daemon::channel::Channel;
use agent_auth_hostd::config::HostConfig;
use agent_auth_hostd::daemon::Hostd;
use agent_auth_hostd::executor::direct::DirectExecutor;
use agent_auth_store::Store;
use agent_auth_store::agents::{self, AgentRow, NewAgent};
use axum::response::IntoResponse as _;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{DaemonsConfig, HostdPart};
use crate::auth::{
    AdminCaller, AdminIdentity, AgentCaller, AgentCredentialKind, AuthConfig, HumanDecider,
};
use crate::notify::{Notifier, Recorder};
use crate::provisioners::{AnyProvisioner, FakeProvisioner, Registry};
use crate::service::Spine;
use crate::state::AppState;

pub const HOST: &str = "excelsior";

pub const POLICY: &str = r#"
defaults: {action: surface, max_duration: 24h}
desktop: {enabled: true, agents: ["desk-*"], timeout: 5s}
platforms:
  homelab: {allowed_groups: [svc-gitea]}
  hostexec:
    templates:
      greet: {tier: user, argv: [echo, hello, "{name}"], params: {name: "[a-z]+"}}
rules:
  - {match: {agent: "trusted-*", platform: hostexec, capability: run}, action: approve}
"#;

pub struct Broker {
    pub st: AppState,
    pub part: Arc<HostdPart>,
    pub addr: SocketAddr,
    pub key: SigningKey,
    _server: tokio::task::JoinHandle<()>,
}

impl Broker {
    pub async fn start(pool: sqlx::PgPool) -> Broker {
        Broker::start_with(pool, POLICY, 30).await
    }

    pub async fn start_with(pool: sqlx::PgPool, policy: &str, heartbeat_secs: u32) -> Broker {
        Broker::start_full(pool, policy, heartbeat_secs, false).await
    }

    /// Behind a trusted proxy (`X-Real-IP` believed) or not.
    pub async fn start_full(
        pool: sqlx::PgPool,
        policy: &str,
        heartbeat_secs: u32,
        trust_x_real_ip: bool,
    ) -> Broker {
        Broker::start_inner(pool, policy, heartbeat_secs, trust_x_real_ip, None).await
    }

    /// With the shell models (watcher, guard, scope check) asking `model`.
    pub async fn start_with_model(pool: sqlx::PgPool, policy: &str, model: &FakeModel) -> Broker {
        // Recording, as the broker does by default (evals).
        let client = Arc::new(
            crate::models::ModelClient::new(
                Secret::new("test-key".to_owned()),
                &model.url,
                Some(Store::from_pool(pool.clone())),
            )
            .unwrap(),
        );
        Broker::start_inner(pool, policy, 30, false, Some(client)).await
    }

    async fn start_inner(
        pool: sqlx::PgPool,
        policy: &str,
        heartbeat_secs: u32,
        trust_x_real_ip: bool,
        models: Option<Arc<crate::models::ModelClient>>,
    ) -> Broker {
        let watcher = models
            .clone()
            .map(|c| crate::hostexec::watcher::Watcher::new(c, "test-model"));
        let store = Store::from_pool(pool);
        let policy = Policy::from_yaml(policy).unwrap();
        let key = SigningKey::generate().unwrap();
        let mut st = AppState::new(
            store.clone(),
            policy.clone(),
            AuthConfig {
                admin_token: Some(Secret::new("admin-token".to_owned())),
                oauth_enabled: false,
                trust_x_real_ip,
            },
        );
        let part = HostdPart::build(
            store,
            DaemonsConfig {
                signing_key: Some(SigningKey::from_text(key.to_text().expose()).unwrap()),
                heartbeat_secs,
                ..DaemonsConfig::default()
            },
            Arc::clone(&st.policy),
            watcher,
        )
        .unwrap();
        let mut registry = Registry::default();
        registry.register(AnyProvisioner::Fake(FakeProvisioner::new(
            Platform::Homelab,
        )));
        if let Some(p) = part.provisioner() {
            registry.register(p);
        }
        st.registry = Arc::new(registry);
        let mut spine = Spine::default();
        part.install_hooks(&mut spine.hooks);
        st.spine = Arc::new(spine);
        st.notifier = Arc::new(part.wrap_notifier(Notifier::Recording(Recorder::default())));
        let part = Arc::new(part);
        st.hostd = Some(Arc::clone(&part));
        st.models = models;
        part.bind(&st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::http::router(st.clone());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Broker {
            st,
            part,
            addr,
            key,
            _server: server,
        }
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    #[must_use]
    pub fn hostexec(&self) -> Arc<crate::hostexec::HostExec> {
        self.part.hostexec.clone().unwrap()
    }

    /// The recording notifier.
    pub fn recorder(&self) -> &Recorder {
        match self.st.notifier.as_ref() {
            Notifier::Recording(r) => r,
            Notifier::Fanout(f) => match &f.primary {
                crate::desktop::Primary::Recording(r) => r,
                _ => panic!("not recording"),
            },
            _ => panic!("not recording"),
        }
    }

    pub fn recorded(&self) -> Vec<String> {
        match self.st.notifier.as_ref() {
            Notifier::Recording(r) => r.lines(),
            Notifier::Fanout(f) => match &f.primary {
                crate::desktop::Primary::Recording(r) => r.lines(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// Wait (up to 30 s) for a recorded notification starting with
    /// `prefix`: notifications are sent after the state they report is
    /// committed, so a test that reads the state first must wait for them.
    pub async fn wait_recorded(&self, prefix: &str) -> bool {
        for _ in 0..1500 {
            if self.recorded().iter().any(|l| l.starts_with(prefix)) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    /// Issue a pairing code for a host.
    pub async fn code(&self, name: &str) -> String {
        let id = ChannelId::new(Role::Host, DaemonName::parse(name).unwrap());
        self.part
            .hub
            .create_pairing_code(&id)
            .await
            .unwrap()
            .code
            .expose()
            .clone()
    }

    pub async fn agent(&self, name: &str) -> AgentRow {
        let key = agent_auth_crypto::api_key::generate().unwrap();
        let tx = self.st.store.begin().await.unwrap();
        let n = NewAgent {
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
        };
        let row = agents::insert(&tx, &n).await.unwrap();
        tx.commit().await.unwrap();
        row
    }
}

pub fn caller(a: &AgentRow) -> AgentCaller {
    AgentCaller::new(a.clone(), None, AgentCredentialKind::ApiKey)
}

pub fn jrt() -> HumanDecider {
    HumanDecider::from(&AdminCaller::new(AdminIdentity::Panel {
        user: "jrt".to_owned(),
    }))
}

/// A fresh temp directory.
pub fn tempdir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aa-broker-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn find(program: &str) -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let p = std::path::Path::new(dir).join(program);
        if p.is_file() {
            return p.to_string_lossy().into_owned();
        }
    }
    program.to_owned()
}

/// A real hostd for the broker's tests.
pub struct Host {
    pub hostd: Arc<Hostd<DirectExecutor>>,
    pub secrets: BTreeMap<String, TotpSecret>,
    pub dir: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Host {
    /// A host config: both tiers on, user shells, desk approvals for the
    /// user tier.
    pub fn config(b: &Broker, dir: &std::path::Path, extra: impl FnOnce(&mut Value)) -> HostConfig {
        let mut raw = json!({
            "broker_url": b.url(),
            "broker_public_key": b.key.public_key().to_text(),
            "name": HOST,
            "state_dir": dir.join("state").to_string_lossy(),
            "runtime_dir": dir.join("run").to_string_lossy(),
            "user": "jrt",
            "tiers": {
                "user": {"enable": true, "max_arm": "1h", "accept_approve_all": true,
                         "shell": {"enable": true, "max_duration": "1h"}},
                "root": {"enable": true, "max_arm": "30m"}
            },
            "deny_commands": [["rm", "**"]],
            "templates": {"greet": {"tier": "user", "argv": ["echo", "hello", "{name}"],
                                    "params": {"name": "[a-z]+"}}},
            "env_allow": ["LANG"],
            "desktop": {"enable": true, "approve": {"user": true}}
        });
        extra(&mut raw);
        HostConfig::from_json(&raw, false).unwrap()
    }

    /// Pair (over HTTP) and connect (over the channel); wait until online.
    pub async fn start(b: &Broker) -> Host {
        Host::start_with(b, |_| {}).await
    }

    pub async fn start_with(b: &Broker, extra: impl FnOnce(&mut Value)) -> Host {
        let dir = tempdir("host");
        let config = Host::config(b, &dir, extra);
        let identity = agent_auth_hostd::identity(&config).unwrap();
        let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
        let code = b.code(HOST).await;
        agent_auth_daemon::pair::pair(&identity, &code, Arc::clone(&tls))
            .await
            .unwrap();
        let exec = DirectExecutor::new(&std::env::var("PATH").unwrap_or_default(), &find("kill"));
        let hostd = Hostd::new(config, exec);
        hostd.pin_user_uid(Some(4242));
        let mut secrets = BTreeMap::new();
        for name in agent_auth_core::hostd::totp::SecretName::every() {
            secrets.insert(
                name.as_str().to_owned(),
                hostd.totp().enroll(name, false).unwrap(),
            );
        }
        let channel = Channel::new(identity, "0.1.0-test", tls);
        hostd.attach(channel.clone());
        let task = {
            let c = channel.clone();
            let h = Arc::clone(&hostd);
            tokio::spawn(async move { c.run(h).await })
        };
        let host = Host {
            hostd,
            secrets,
            dir,
            task,
        };
        wait_until(|| b.part.hub.is_online(Role::Host, HOST)).await;
        host
    }

    /// A code for `name` at `offset` steps from now (0 or 1: each code is
    /// single use, so a test takes at most two per secret).
    pub fn code(&self, name: &str, offset: u64) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp().unsigned_abs();
        self.secrets[name]
            .code_at(now / 30 + offset)
            .expose()
            .clone()
    }
}

/// A stand-in for the model gateway's `/chat/completions`: answers with
/// the JSON object `answer(system, user)` gives (`None`: a 500), and
/// records every `(system, user)` it was sent.
pub struct FakeModel {
    pub url: String,
    pub calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    _task: tokio::task::JoinHandle<()>,
}

type Answer = dyn Fn(&str, &str) -> Option<Value> + Send + Sync;

impl FakeModel {
    pub async fn start(
        answer: impl Fn(&str, &str) -> Option<Value> + Send + Sync + 'static,
    ) -> FakeModel {
        let calls: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
        let answer: Arc<Answer> = Arc::new(answer);
        let recorded = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/chat/completions",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let answer = Arc::clone(&answer);
                let recorded = Arc::clone(&recorded);
                async move {
                    let msg = |i: usize| {
                        body["messages"][i]["content"]
                            .as_str()
                            .unwrap_or("")
                            .to_owned()
                    };
                    let (system, user) = (msg(0), msg(1));
                    recorded
                        .lock()
                        .unwrap()
                        .push((system.clone(), user.clone()));
                    match answer(&system, &user) {
                        Some(a) => axum::Json(json!({
                            "choices": [{"message": {"content": a.to_string()}}]
                        }))
                        .into_response(),
                        None => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeModel {
            url: format!("http://{addr}"),
            calls,
            _task: task,
        }
    }

    /// The user messages of the calls made with system prompt `prompt`.
    pub fn calls_to(&self, prompt: &str) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _)| s == prompt)
            .map(|(_, u)| u.clone())
            .collect()
    }
}

/// Poll until `f` holds (30 s at most).
pub async fn wait_until(f: impl Fn() -> bool) {
    for _ in 0..1500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached");
}

/// A sandbox daemon on the real channel that stops reading its socket
/// once it is told to: its handler never returns from the next message,
/// so the channel's read loop (which awaits it) reads nothing more, while
/// its heartbeats keep the connection looking alive.
pub struct StallingDaemon {
    pub name: String,
    stall: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

struct StallingHandler {
    stall: Arc<std::sync::atomic::AtomicBool>,
}

impl agent_auth_daemon::channel::Handler for StallingHandler {
    fn status(&self) -> serde_json::Map<String, Value> {
        serde_json::Map::new()
    }

    async fn on_message(&self, _body: serde_json::Map<String, Value>) {
        if self.stall.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}

impl StallingDaemon {
    /// Pair sandbox `name` and connect; waits until it is online.
    pub async fn start(b: &Broker, name: &str) -> StallingDaemon {
        let id = ChannelId::new(Role::Sandbox, DaemonName::parse(name).unwrap());
        let code = b
            .part
            .hub
            .create_pairing_code(&id)
            .await
            .unwrap()
            .code
            .expose()
            .clone();
        let identity = agent_auth_daemon::channel::Identity::new(
            id,
            SigningKey::generate().unwrap(),
            agent_auth_daemon::url::BrokerUrl::parse(&b.url()).unwrap(),
            b.key.public_key(),
        );
        let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
        agent_auth_daemon::pair::pair(&identity, &code, Arc::clone(&tls))
            .await
            .unwrap();
        let channel = Channel::new(identity, "0.1.0-test", tls);
        let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler = Arc::new(StallingHandler {
            stall: Arc::clone(&stall),
        });
        let task = tokio::spawn(async move { channel.run(handler).await });
        wait_until(|| b.part.hub.is_online(Role::Sandbox, name)).await;
        StallingDaemon {
            name: name.to_owned(),
            stall,
            task,
        }
    }

    /// Stop reading, and fill the connection until a send to it no longer
    /// finishes (a background task, as an unrelated sender would be). The
    /// returned task ends when the broker gives up on the connection.
    pub async fn stall(&self, b: &Broker) -> tokio::task::JoinHandle<u32> {
        self.stall.store(true, std::sync::atomic::Ordering::SeqCst);
        let hub = Arc::clone(&b.part.hub);
        let name = self.name.clone();
        let done = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&done);
        let flood = tokio::spawn(async move {
            let filler = "x".repeat(512 * 1024);
            let mut msg = serde_json::Map::new();
            msg.insert("type".into(), json!("filler"));
            msg.insert("filler".into(), json!(filler));
            let mut sent = 0u32;
            while sent < 4096 && hub.send_default(Role::Sandbox, &name, &msg).await {
                sent += 1;
                counter.store(sent, std::sync::atomic::Ordering::SeqCst);
            }
            sent
        });
        // Stalled: no send has finished for a while, and it isn't over.
        let mut last = 0;
        let mut quiet = 0;
        while quiet < 10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = done.load(std::sync::atomic::Ordering::SeqCst);
            if now == last && now > 0 {
                quiet += 1;
            } else {
                quiet = 0;
            }
            last = now;
            assert!(!flood.is_finished(), "the connection never filled");
        }
        flood
    }
}

impl Drop for StallingDaemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}
