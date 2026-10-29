//! Test support: a broker with the daemon channel and the agent-VM part
//! (both provisioners, the spine hooks, a2a), served on loopback; and a
//! fake sandbox daemon on the real channel (paired over HTTP, connected
//! over the WebSocket) that records what the broker sends it, acks keys and
//! answers project calls as sandboxd does.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_auth_core::Platform;
use agent_auth_core::policy::Policy;
use agent_auth_crypto::Secret;
use agent_auth_crypto::daemon::{DaemonId as ChannelId, DaemonName, PublicKey, Role, SigningKey};
use agent_auth_crypto::secretbox::SecretBox;
use agent_auth_daemon::channel::{Channel, Handler, Identity};
use agent_auth_daemon::url::BrokerUrl;
use agent_auth_store::Store;
use agent_auth_store::agents::{self, AgentRow};
use serde_json::{Map, Value, json};

use super::Sandboxes;
use crate::auth::AuthConfig;
use crate::daemons::{DaemonsConfig, HostdPart};
use crate::notify::{Notifier, Recorder};
use crate::provisioners::{AnyProvisioner, Registry};
use crate::service::Spine;
use crate::state::AppState;

pub const HOST: &str = "excelsior";
pub const ADMIN_TOKEN: &str = "admin-token";

/// The policy of `tests/test_sandboxes.py`.
pub const POLICY: &str = r#"
defaults: {action: surface, max_duration: 24h}
platforms:
  agents: {runtimes: [claude, codex], lease: 30d}
rules:
  - {match: {agent: "orchestrator-*-sandbox", platform: agents, capability: mint}, action: approve}
  - {match: {agent: "catchall-*"}, action: approve}
  - {match: {platform: a2a}, action: approve}
  - {match: {platform: sandbox, capability: project.read}, action: approve}
"#;

/// A broker with the agent-VM part on loopback.
pub struct Broker {
    pub st: AppState,
    pub part: Arc<HostdPart>,
    pub sandboxes: Arc<Sandboxes>,
    pub addr: SocketAddr,
    pub key: SigningKey,
    _server: tokio::task::JoinHandle<()>,
}

impl Broker {
    pub async fn start(pool: sqlx::PgPool) -> Broker {
        Broker::start_with(pool, POLICY, true).await
    }

    /// `keys`: whether ENCRYPTION_KEY is set.
    pub async fn start_with(pool: sqlx::PgPool, policy: &str, keys: bool) -> Broker {
        Broker::start_full(pool, policy, keys, |_| {}).await
    }

    /// `tweak` may adjust the registered provisioners (e.g. a short
    /// `project` call timeout) before the state is built.
    pub async fn start_full(
        pool: sqlx::PgPool,
        policy: &str,
        keys: bool,
        tweak: impl FnOnce(&mut Vec<AnyProvisioner>),
    ) -> Broker {
        let store = Store::from_pool(pool);
        let policy = Policy::from_yaml(policy).unwrap();
        let key = SigningKey::generate().unwrap();
        let mut st = AppState::new(
            store.clone(),
            policy.clone(),
            AuthConfig {
                admin_token: Some(Secret::new(ADMIN_TOKEN.to_owned())),
                oauth_enabled: false,
                trust_x_real_ip: false,
            },
        );
        let part = HostdPart::build(
            store.clone(),
            DaemonsConfig {
                signing_key: Some(SigningKey::from_text(key.to_text().expose()).unwrap()),
                heartbeat_secs: 2,
                ..DaemonsConfig::default()
            },
            Arc::clone(&st.policy),
            None,
        )
        .unwrap();
        let secret_box = keys.then(|| {
            Arc::new(SecretBox::from_base64(SecretBox::generate_key().unwrap().expose()).unwrap())
        });
        let sandboxes = Sandboxes::new(Arc::clone(&part.hub), store, secret_box).unwrap();
        let mut registry = Registry::default();
        registry.register(AnyProvisioner::A2a(crate::a2a::provisioner::A2aProvisioner));
        if let Some(p) = part.provisioner() {
            registry.register(p);
        }
        let mut ours = sandboxes.provisioners(&st.policy);
        tweak(&mut ours);
        for p in ours {
            registry.register(p);
        }
        st.registry = Arc::new(registry);
        let mut spine = Spine::default();
        part.install_hooks(&mut spine.hooks);
        sandboxes.install_hooks(&mut spine.hooks);
        st.spine = Arc::new(spine);
        st.notifier = Arc::new(part.wrap_notifier(Notifier::Recording(Recorder::default())));
        let part = Arc::new(part);
        st.hostd = Some(Arc::clone(&part));
        st.sandboxes = Some(Arc::clone(&sandboxes));
        part.bind(&st);
        sandboxes.bind(st.clone());
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
            sandboxes,
            addr,
            key,
            _server: server,
        }
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    /// The broker's public key text (`ed25519:…`), for a daemon's config.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// A pairing code for the sandbox daemon `name` (as
    /// `POST /admin/daemons/pairing-codes` issues it).
    pub async fn pairing_code(&self, name: &str) -> String {
        let id = ChannelId::new(Role::Sandbox, DaemonName::parse(name).unwrap());
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
        let tx = self.st.store.begin().await.unwrap();
        let a = agents::by_name(&tx, name).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        a
    }

    pub async fn maybe_agent(&self, name: &str) -> Option<AgentRow> {
        let tx = self.st.store.begin().await.unwrap();
        let a = agents::by_name(&tx, name).await.unwrap();
        tx.commit().await.unwrap();
        a
    }

    /// An HTTP client (through the shared TLS config, as everything else).
    #[must_use]
    pub fn http(&self) -> reqwest::Client {
        agent_auth_tls::reqwest_builder(
            agent_auth_tls::default_client_config().unwrap(),
            Duration::from_secs(30),
        )
        .build()
        .unwrap()
    }

    /// `GET path` with `Authorization: Bearer token`: (status, body).
    pub async fn get_as(&self, token: &str, path: &str) -> (u16, Value) {
        let resp = self
            .http()
            .get(format!("{}{path}", self.url()))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// `POST path` with a JSON body as `token`.
    pub async fn post_as(&self, token: &str, path: &str, body: Value) -> (u16, Value) {
        let resp = self
            .http()
            .post(format!("{}{path}", self.url()))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    pub fn registry_has(&self, p: Platform) -> bool {
        self.st.registry.is_enabled(p)
    }
}

/// What the fake sandbox saw, and how it answers project calls.
#[derive(Default)]
pub struct Seen {
    /// Every message from the broker, in order (envelope keys dropped).
    pub messages: Vec<Map<String, Value>>,
    /// The last key delivered per agent name.
    pub keys: std::collections::BTreeMap<String, Map<String, Value>>,
    /// Refuse project calls with this error.
    pub refuse: Option<String>,
    /// Answer project calls after this long.
    pub delay: Option<Duration>,
    /// Do not ack keys.
    pub no_ack: bool,
}

/// A fake sandbox daemon on the real channel.
pub struct FakeSandbox {
    pub name: String,
    pub channel: Channel,
    pub seen: Arc<Mutex<Seen>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct FakeHandler {
    channel: Channel,
    seen: Arc<Mutex<Seen>>,
}

impl Handler for FakeHandler {
    fn status(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("role".into(), json!("sandbox"));
        m
    }

    async fn on_message(&self, mut body: Map<String, Value>) {
        for k in agent_auth_wire::daemon::channel::ENVELOPE_KEYS {
            body.remove(k);
        }
        let kind = body
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let (no_ack, refuse, delay) = {
            let mut seen = self.seen.lock().unwrap();
            seen.messages.push(body.clone());
            if kind == "key" {
                let name = body["name"].as_str().unwrap().to_owned();
                seen.keys.insert(name, body.clone());
            }
            (seen.no_ack, seen.refuse.clone(), seen.delay)
        };
        match kind.as_str() {
            "key" if !no_ack => {
                let ack = json!({"type": "key.ack", "agent_id": body["agent_id"],
                                 "key_id": body["key_id"]});
                self.channel.send(ack.as_object().unwrap()).await;
            }
            "project.grant" | "project.revoke" => {
                let channel = self.channel.clone();
                let call_id = body.get("call_id").cloned().unwrap_or(Value::Null);
                // Answered from a task, so a delay holds up nothing else.
                tokio::spawn(async move {
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    let reply = match refuse {
                        Some(e) => json!({"type": "reply", "call_id": call_id, "ok": false,
                                          "error": e}),
                        None => json!({"type": "reply", "call_id": call_id, "ok": true}),
                    };
                    channel.send(reply.as_object().unwrap()).await;
                });
            }
            "lockdown" | "unlock" | "agents.contained" => {
                if let Some(call_id) = body.get("call_id") {
                    let reply = json!({"type": "reply", "call_id": call_id, "ok": true});
                    self.channel.send(reply.as_object().unwrap()).await;
                }
            }
            _ => {}
        }
    }
}

impl FakeSandbox {
    /// Pair `name` with the broker over HTTP and connect; waits until the
    /// broker has it online.
    pub async fn start(b: &Broker, name: &str) -> FakeSandbox {
        FakeSandbox::start_with(b, name, Seen::default()).await
    }

    /// [`FakeSandbox::start`] with what it starts with (e.g. `no_ack`).
    pub async fn start_with(b: &Broker, name: &str, seen: Seen) -> FakeSandbox {
        let identity = Identity::new(
            ChannelId::new(Role::Sandbox, DaemonName::parse(name).unwrap()),
            SigningKey::generate().unwrap(),
            BrokerUrl::parse(&b.url()).unwrap(),
            b.public_key(),
        );
        let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
        let code = b.pairing_code(name).await;
        agent_auth_daemon::pair::pair(&identity, &code, Arc::clone(&tls))
            .await
            .unwrap();
        let channel = Channel::new(identity, "0.1.0-test", tls);
        let seen = Arc::new(Mutex::new(seen));
        let handler = Arc::new(FakeHandler {
            channel: channel.clone(),
            seen: Arc::clone(&seen),
        });
        let task = {
            let c = channel.clone();
            tokio::spawn(async move { c.run(handler).await })
        };
        let sb = FakeSandbox {
            name: name.to_owned(),
            channel,
            seen,
            task: Some(task),
        };
        wait_until(|| b.part.hub.is_online(Role::Sandbox, name)).await;
        sb
    }

    /// Disconnect.
    pub async fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
    }

    /// The key delivered for `agent`, if any.
    pub fn key(&self, agent: &str) -> Option<String> {
        self.seen
            .lock()
            .unwrap()
            .keys
            .get(agent)
            .and_then(|m| m.get("api_key"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    pub fn forget_key(&self, agent: &str) -> Option<String> {
        self.seen
            .lock()
            .unwrap()
            .keys
            .remove(agent)
            .and_then(|m| m.get("api_key").and_then(Value::as_str).map(str::to_owned))
    }

    /// Messages of `kind` seen so far.
    pub fn of_type(&self, kind: &str) -> Vec<Map<String, Value>> {
        self.seen
            .lock()
            .unwrap()
            .messages
            .iter()
            .filter(|m| m.get("type").and_then(Value::as_str) == Some(kind))
            .cloned()
            .collect()
    }

    /// The types seen so far, in order.
    pub fn types(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .messages
            .iter()
            .filter_map(|m| m.get("type").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    pub async fn send(&self, msg: Value) -> bool {
        self.channel.send(msg.as_object().unwrap()).await
    }

    /// Wait until a key for `agent` arrived.
    pub async fn wait_key(&self, agent: &str) -> String {
        for _ in 0..1500 {
            if let Some(k) = self.key(agent) {
                return k;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no key for {agent}");
    }
}

impl Drop for FakeSandbox {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
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

/// Poll an async condition until it holds (30 s at most); false if never.
pub async fn eventually<F, Fut>(f: F) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..1500 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}
