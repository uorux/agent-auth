//! The sandboxd daemon (sandboxd spec §4).
//!
//! Pieces, all on one runtime:
//! - the broker channel (role `sandbox`): agent keys arrive here (to this
//!   daemon alone) and are acknowledged; project grants are applied and
//!   answered; lockdown and containment hold agents. Each message is
//!   handled off the read loop, holds first (B-7): a hold takes effect in
//!   memory and on disk before the next message is read, and its freezing
//!   runs in order on a worker of its own;
//! - one sessionless a2a dispatcher per agent: pending opens are routed to
//!   a conversation, which claims the thread with its own broker session;
//! - one watcher per conversation: a session-scoped events long-poll that
//!   keeps the broker session alive and turns new thread messages into
//!   turns;
//! - processes: started on demand (within the process limits), parked
//!   after a grace period of idleness, resumed on the next message;
//! - interactive attach: claude hands the session to a TUI in tmux; codex's
//!   TUI joins the live app-server.

mod conversations;
mod gateway;
mod projects;
pub mod routing;
pub mod slots;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::Duration;

use agent_auth_core::sandbox::{Applied, HoldEvent, Holds, UnitAction};
use agent_auth_crypto::Secret;
use agent_auth_daemon::Channel;
use agent_auth_wire::daemon::channel::{CallId, Incoming, parse};
use agent_auth_wire::daemon::sandbox::{BrokerToSandbox, KeyDelivery};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::host::{Host, HostError, Tree};
use crate::names::{ConvId, ORCHESTRATOR_DIR, ORCHESTRATOR_USER};
use crate::runtime::{RunRef, Runtime, SpawnContext};
use crate::store::{AgentRecord, Store, StoreError};

pub use gateway::GatewayKey;
pub use slots::{SlotPermit, Slots};

/// This daemon's version, as the heartbeat reports it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ROLE: &str = "sandbox";
/// The events long-poll.
pub const EVENTS_WAIT: f64 = 60.0;
/// After a failed call to the broker.
pub const RETRY: Duration = Duration::from_secs(5);
/// At most one `key.rotate` per agent this often (B-8: the Python's
/// watchers asked every 5 s forever for a disabled agent).
pub const KEY_ROTATE_INTERVAL: Duration = Duration::from_secs(300);

/// What the daemon's operations fail with: the Python's exception kinds,
/// so the local API answers as it did (`LookupError`, `ValueError` and
/// `RuntimeError` give their message; anything else is `internal error:`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SbxError {
    #[error("{0}")]
    Lookup(String),
    #[error("{0}")]
    Value(String),
    #[error("{0}")]
    Runtime(String),
    #[error("{0}")]
    Internal(String),
    /// The broker refused the agent's key (401).
    #[error("{0}")]
    Unauthorized(String),
}

impl SbxError {
    /// The local API's error text.
    #[must_use]
    pub fn api_text(&self) -> String {
        match self {
            SbxError::Internal(m) | SbxError::Unauthorized(m) => format!("internal error: {m}"),
            SbxError::Lookup(m) | SbxError::Value(m) | SbxError::Runtime(m) => m.clone(),
        }
    }

    /// Could this request never be served here (the dispatcher refuses the
    /// thread instead of retrying)?
    #[must_use]
    pub fn refuses(&self) -> bool {
        !matches!(self, SbxError::Internal(_) | SbxError::Unauthorized(_))
    }
}

impl From<StoreError> for SbxError {
    fn from(e: StoreError) -> Self {
        SbxError::Internal(e.to_string())
    }
}

impl From<HostError> for SbxError {
    fn from(e: HostError) -> Self {
        SbxError::Runtime(e.0)
    }
}

impl From<agent_auth_client::ClientError> for SbxError {
    fn from(e: agent_auth_client::ClientError) -> Self {
        if e.status() == Some(401) && !e.is_stale_session() {
            SbxError::Unauthorized(e.to_string())
        } else {
            SbxError::Internal(e.to_string())
        }
    }
}

pub type SbxResult<T> = Result<T, SbxError>;

pub(crate) fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A delivery that failed is tried again later, less and less often.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Retry {
    pub at: Option<tokio::time::Instant>,
    pub backoff: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Retry {
            at: None,
            backoff: Duration::from_secs(30),
        }
    }
}

/// The in-memory side of a conversation.
pub struct Live {
    pub conv: ConvId,
    /// The conversation's lock (the Python's `lv.lock`).
    pub(crate) op: tokio::sync::Mutex<()>,
    pub(crate) run: Mutex<Option<(RunRef, SlotPermit)>>,
    pub(crate) ctx: Mutex<Option<SpawnContext>>,
    pub(crate) park_timer: Mutex<Option<JoinHandle<()>>>,
    pub(crate) watcher: Mutex<Option<JoinHandle<()>>>,
    pub(crate) tui: AtomicBool,
    pub(crate) tui_slot: Mutex<Option<SlotPermit>>,
    /// The agent API's token for this conversation (in memory only).
    pub(crate) token: Secret<String>,
    pub(crate) retry: Mutex<Retry>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("conv", &self.conv)
            .field("tui", &self.tui.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Live {
    fn new(conv: ConvId) -> Live {
        let token = agent_auth_crypto::token_urlsafe(24)
            .unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());
        Live {
            conv,
            op: tokio::sync::Mutex::new(()),
            run: Mutex::new(None),
            ctx: Mutex::new(None),
            park_timer: Mutex::new(None),
            watcher: Mutex::new(None),
            tui: AtomicBool::new(false),
            tui_slot: Mutex::new(None),
            token: Secret::new(token),
            retry: Mutex::new(Retry::default()),
        }
    }

    /// The live process, if any.
    #[must_use]
    pub fn run(&self) -> Option<RunRef> {
        locked(&self.run).as_ref().map(|(r, _)| Arc::clone(r))
    }

    #[must_use]
    pub fn tui(&self) -> bool {
        self.tui.load(Ordering::SeqCst)
    }

    /// The agent API token (tests use it to act as the conversation).
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.expose()
    }

    pub(crate) fn cancel_park(&self) {
        if let Some(t) = locked(&self.park_timer).take() {
            t.abort();
        }
    }
}

/// Serializes the grants of one (project, target) pair.
pub(crate) type PairLock = Arc<tokio::sync::Mutex<()>>;

/// A hold change waiting for its effects (freezing, thawing, delivering).
struct HoldJob {
    applied: Applied,
    call_id: Option<CallId>,
}

/// The daemon.
pub struct Sandboxd<H: Host> {
    pub config: Arc<Config>,
    pub host: H,
    pub store: Store,
    runtimes: RwLock<BTreeMap<String, Runtime>>,
    holds: RwLock<Holds>,
    live: Mutex<HashMap<ConvId, Arc<Live>>>,
    dispatchers: Mutex<HashMap<String, JoinHandle<()>>>,
    thread_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    grant_locks: Mutex<HashMap<(String, String), PairLock>>,
    /// Bumped whenever an agent's key arrives (what a dispatcher or watcher
    /// that got a 401 waits for).
    key_gen: watch::Sender<u64>,
    key_rotations: Mutex<HashMap<String, tokio::time::Instant>>,
    channel: Mutex<Option<Channel>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    pub(crate) slots: Slots,
    gateway_keys: Mutex<HashMap<String, GatewayKey>>,
    http: reqwest::Client,
    pub orchestrator: String,
    hold_jobs: mpsc::UnboundedSender<HoldJob>,
    hold_rx: Mutex<Option<mpsc::UnboundedReceiver<HoldJob>>>,
    /// Hold changes queued, and those whose effects are done.
    holds_queued: std::sync::atomic::AtomicU64,
    holds_done: watch::Sender<u64>,
    me: Weak<Sandboxd<H>>,
}

impl<H: Host> std::fmt::Debug for Sandboxd<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandboxd")
            .field("host", &self.config.name)
            .finish_non_exhaustive()
    }
}

impl<H: Host> Sandboxd<H> {
    /// The daemon over its state directory (opened now: a state file that
    /// does not read is an error).
    pub fn new(config: Arc<Config>, host: H) -> Result<Arc<Sandboxd<H>>, SbxError> {
        let store = Store::open(&config.state_dir)?;
        let mut runtimes = BTreeMap::new();
        for (name, rc) in &config.runtimes {
            if let Some(rt) = Runtime::from_config(name, &rc.command, rc.model.as_deref()) {
                runtimes.insert(name.clone(), rt);
            }
        }
        let holds = Holds::new(store.locked(), store.contained());
        let tls = agent_auth_tls::default_client_config()
            .map_err(|e| SbxError::Internal(e.to_string()))?;
        let http = agent_auth_tls::reqwest_builder(tls, Duration::from_secs(330))
            .build()
            .map_err(|e| SbxError::Internal(e.to_string()))?;
        let (hold_tx, hold_rx) = mpsc::unbounded_channel();
        let (key_gen, _) = watch::channel(0u64);
        let orchestrator = agent_auth_core::sandbox::orchestrator_name(config.name.as_str());
        let slots = Slots::new(config.max_processes, config.max_processes_per_project);
        Ok(Arc::new_cyclic(|me| Sandboxd {
            config,
            host,
            store,
            runtimes: RwLock::new(runtimes),
            holds: RwLock::new(holds),
            live: Mutex::new(HashMap::new()),
            dispatchers: Mutex::new(HashMap::new()),
            thread_locks: Mutex::new(HashMap::new()),
            grant_locks: Mutex::new(HashMap::new()),
            key_gen,
            key_rotations: Mutex::new(HashMap::new()),
            channel: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            slots,
            gateway_keys: Mutex::new(HashMap::new()),
            http,
            orchestrator,
            hold_jobs: hold_tx,
            hold_rx: Mutex::new(Some(hold_rx)),
            holds_queued: std::sync::atomic::AtomicU64::new(0),
            holds_done: watch::channel(0u64).0,
            me: me.clone(),
        }))
    }

    pub(crate) fn me(&self) -> Option<Arc<Sandboxd<H>>> {
        self.me.upgrade()
    }

    /// Run `fut` as a tracked task (aborted at shutdown).
    pub(crate) fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
        let handle = tokio::spawn(fut);
        let mut tasks = locked(&self.tasks);
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle.abort_handle());
        handle
    }

    // ---------------------------------------------------------- runtimes

    #[must_use]
    pub fn runtime(&self, name: &str) -> Option<Runtime> {
        self.runtimes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// Replace the configured runtimes (tests).
    pub fn set_runtimes(&self, runtimes: BTreeMap<String, Runtime>) {
        *self
            .runtimes
            .write()
            .unwrap_or_else(PoisonError::into_inner) = runtimes;
    }

    /// The runtime a conversation of `rec` runs: the orchestrator's is
    /// `orchestrator_runtime`, others their own if it is configured.
    pub fn runtime_of(&self, rec: &AgentRecord) -> SbxResult<String> {
        let runtime = if rec.name == self.orchestrator {
            Some(self.config.orchestrator_runtime.clone())
        } else {
            rec.runtime.clone()
        };
        match runtime {
            Some(r) if self.runtime(&r).is_some() => Ok(r),
            _ => Err(SbxError::Runtime(format!(
                "no runtime configured for {} ({})",
                rec.name,
                rec.runtime.as_deref().unwrap_or("None")
            ))),
        }
    }

    // ---------------------------------------------------------------- live

    /// The conversation's in-memory side (created on first use).
    pub fn live(&self, conv: &ConvId) -> Arc<Live> {
        let mut map = locked(&self.live);
        Arc::clone(
            map.entry(conv.clone())
                .or_insert_with(|| Arc::new(Live::new(conv.clone()))),
        )
    }

    pub(crate) fn lives(&self) -> Vec<Arc<Live>> {
        locked(&self.live).values().cloned().collect()
    }

    pub(crate) fn forget_live(&self, conv: &ConvId) {
        locked(&self.live).remove(conv);
    }

    /// The conversation a token belongs to (compared in constant time over
    /// every live conversation; a closed one has none).
    #[must_use]
    pub fn conversation_by_token(&self, token: &str) -> Option<crate::store::Conversation> {
        let mut found = None;
        for lv in self.lives() {
            if agent_auth_crypto::ct_eq(lv.token.expose().as_bytes(), token.as_bytes()) {
                found = Some(lv.conv.clone());
            }
        }
        let conv = self.store.conversation(&found?)?;
        (conv.state != crate::store::ConvState::Closed).then_some(conv)
    }

    // --------------------------------------------------------------- paths

    /// (workdir, home, tmp) of a project (`None`: the orchestrator).
    #[must_use]
    pub fn paths(&self, project: Option<&str>) -> (PathBuf, PathBuf, PathBuf) {
        let root = &self.config.sandbox_root;
        match project {
            None => (
                root.join("orchestrator"),
                root.join("homes").join(ORCHESTRATOR_DIR),
                root.join("tmp").join(ORCHESTRATOR_DIR),
            ),
            Some(p) => (
                root.join("projects").join(p),
                root.join("homes").join(p),
                root.join("tmp").join(p),
            ),
        }
    }

    /// The trees of [`Sandboxd::paths`], opened without following.
    #[must_use]
    pub fn trees(&self, project: Option<&str>) -> (Tree, Tree, Tree) {
        let root = &self.config.sandbox_root;
        match project {
            None => (
                Tree::new(root, &["orchestrator"]),
                Tree::new(root, &["homes", ORCHESTRATOR_DIR]),
                Tree::new(root, &["tmp", ORCHESTRATOR_DIR]),
            ),
            Some(p) => (
                Tree::new(root, &["projects", p]),
                Tree::new(root, &["homes", p]),
                Tree::new(root, &["tmp", p]),
            ),
        }
    }

    /// The project of an agent's processes (`None` for the orchestrator).
    #[must_use]
    pub fn project_of(&self, rec: &AgentRecord) -> Option<String> {
        if rec.name == self.orchestrator {
            None
        } else {
            rec.project.clone()
        }
    }

    /// The uid of a project (`None`: the orchestrator's, `uid_base`).
    pub fn project_uid(&self, project: Option<&str>) -> SbxResult<u32> {
        match project {
            None => Ok(self.config.uid_base),
            Some(p) => self.store.project(p).map(|r| r.uid).ok_or_else(|| {
                SbxError::Lookup(format!("no project {}", agent_auth_core::pyfmt::repr(p)))
            }),
        }
    }

    // --------------------------------------------------------- lifecycle

    /// A clean slate for processes (their pipes died with the previous
    /// daemon); conversations are kept and resume on their next message.
    pub async fn startup(&self) -> SbxResult<()> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let c = &self.config;
        for d in ["projects", "homes", "tmp"] {
            let p = c.sandbox_root.join(d);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o711)
                .create(&p)
                .map_err(|e| SbxError::Internal(format!("{}: {e}", p.display())))?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o711))
                .map_err(|e| SbxError::Internal(format!("{}: {e}", p.display())))?;
        }
        let (work, home, tmp) = self.trees(None);
        self.host
            .ensure_user(ORCHESTRATOR_USER, c.uid_base, &home.path())?;
        self.host.make_dirs(c.uid_base, &[work, home, tmp])?;
        let logs = c.state_dir.join("logs");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&logs)
            .map_err(|e| SbxError::Internal(format!("{}: {e}", logs.display())))?;
        for conv in self.store.conversations(None, false) {
            self.host.stop_unit(&conv.id.unit()).await;
            self.host.stop_unit(&conv.id.tui_unit()).await;
            self.store.update_conversation(&conv.id, |c| {
                c.state = crate::store::ConvState::Parked;
            })?;
            self.watch(&conv.id);
        }
        for agent in self.store.agents() {
            self.dispatch(&agent.name, false);
        }
        self.start_hold_worker();
        Ok(())
    }

    /// The daemon until the task is dropped (or the channel task ends).
    pub async fn run(self: &Arc<Self>, channel: Channel) -> SbxResult<()> {
        *locked(&self.channel) = Some(channel.clone());
        self.startup().await?;
        let me = Arc::clone(self);
        self.spawn(async move { me.reaper().await });
        channel
            .run(Arc::new(ChannelHandler(Arc::clone(self))))
            .await;
        Ok(())
    }

    /// Attach a channel without running it (tests that drive it themselves).
    pub fn attach_channel(&self, channel: Channel) {
        *locked(&self.channel) = Some(channel);
    }

    /// Stop polling and the processes' plumbing. Units are left to the next
    /// startup (it stops them); conversations stay resumable.
    pub async fn shutdown(&self) {
        let tasks: Vec<tokio::task::AbortHandle> = std::mem::take(&mut *locked(&self.tasks));
        for t in tasks {
            t.abort();
        }
        for (_, d) in std::mem::take(&mut *locked(&self.dispatchers)) {
            d.abort();
        }
        for lv in self.lives() {
            if let Some(w) = locked(&lv.watcher).take() {
                w.abort();
            }
            lv.cancel_park();
            let run = locked(&lv.run).take();
            if let Some((run, _slot)) = run {
                run.stop(&self.host).await;
            }
        }
    }

    /// The heartbeat's status (spec §4.10).
    #[must_use]
    pub fn status(&self) -> Map<String, Value> {
        let mut counts: BTreeMap<&'static str, u32> = BTreeMap::new();
        for c in self.store.conversations(None, false) {
            let n = counts.entry(c.state.as_str()).or_insert(0);
            *n = n.saturating_add(1);
        }
        let processes = self.lives().iter().filter(|lv| lv.run().is_some()).count();
        let v = json!({
            "version": VERSION,
            "role": ROLE,
            "host": self.config.name.as_str(),
            "agents": self.store.agents().len(),
            "projects": self.store.projects().len(),
            "conversations": counts,
            "lockdown": self.locked(),
            "processes": processes,
        });
        match v {
            Value::Object(m) => m,
            _ => Map::new(),
        }
    }

    // ----------------------------------------------------------- channel

    pub(crate) async fn send(&self, payload: Value) -> bool {
        let channel = locked(&self.channel).clone();
        match (channel, payload) {
            (Some(c), Value::Object(m)) => c.send(&m).await,
            _ => false,
        }
    }

    async fn reply(&self, call_id: Option<&CallId>, result: Result<(), String>) {
        let mut msg = json!({"type": "reply", "call_id": call_id.map(CallId::as_str)});
        if let Value::Object(m) = &mut msg {
            match result {
                Ok(()) => {
                    m.insert("ok".into(), json!(true));
                }
                Err(e) => {
                    m.insert("ok".into(), json!(false));
                    m.insert("error".into(), json!(e));
                }
            }
        }
        self.send(msg).await;
    }

    /// A verified message from the broker. Nothing slow runs here: a key
    /// is stored and acknowledged, a hold takes effect (its freezing is
    /// queued in order), a project grant runs in a task of its own.
    pub async fn on_broker_message(&self, body: Map<String, Value>) {
        let call_id = body
            .get("call_id")
            .and_then(Value::as_str)
            .and_then(|c| CallId::parse(c).ok());
        match parse::<BrokerToSandbox>(body) {
            Incoming::Message(m) => self.on_message(m).await,
            Incoming::UnknownType(t) => tracing::debug!(kind = %t, "ignored a broker message"),
            Incoming::Malformed { kind, error } => {
                tracing::warn!(kind = %kind, "malformed broker message: {error}");
                if call_id.is_some() {
                    self.reply(call_id.as_ref(), Err(format!("malformed {kind} message")))
                        .await;
                }
            }
        }
    }

    async fn on_message(&self, m: BrokerToSandbox) {
        match m {
            BrokerToSandbox::Key(k) => self.on_key(k).await,
            BrokerToSandbox::ProjectGrant(g) => {
                let Some(me) = self.me() else { return };
                self.spawn(async move {
                    let result = me
                        .apply_project_grant(
                            &g.grant_id.to_string(),
                            g.project.as_str(),
                            g.target.as_str(),
                            match g.access {
                                agent_auth_wire::daemon::sandbox::ProjectAccessName::Read => {
                                    "project.read"
                                }
                                agent_auth_wire::daemon::sandbox::ProjectAccessName::Write => {
                                    "project.write"
                                }
                            },
                        )
                        .await
                        .map_err(|e| e.to_string());
                    me.reply(g.call_id.as_ref(), result).await;
                });
            }
            BrokerToSandbox::ProjectRevoke(r) => {
                let Some(me) = self.me() else { return };
                self.spawn(async move {
                    let result = me
                        .remove_project_grant(&r.grant_id.to_string())
                        .await
                        .map_err(|e| e.to_string());
                    me.reply(r.call_id.as_ref(), result).await;
                });
            }
            BrokerToSandbox::Lockdown(l) => self.hold(HoldEvent::Lockdown, l.call_id),
            BrokerToSandbox::Unlock(u) => self.hold(HoldEvent::Unlock, u.call_id),
            BrokerToSandbox::AgentsContained(c) => {
                let set: BTreeSet<String> =
                    c.agents.iter().map(|a| a.as_str().to_owned()).collect();
                self.hold(HoldEvent::Contained(set), c.call_id);
            }
        }
    }

    /// A key, for this VM alone: stored, acknowledged (naming the key), and
    /// the agent's dispatcher restarted.
    async fn on_key(&self, k: KeyDelivery) {
        let rec = AgentRecord {
            name: k.name.as_str().to_owned(),
            agent_id: k.agent_id.to_string(),
            key_id: k.key_id.as_str().to_owned(),
            runtime: k.runtime.map(|r| r.as_str().to_owned()),
            project: k.project.map(|p| p.as_str().to_owned()),
            api_key: Secret::new(k.api_key.expose().to_owned()),
            updated_at: crate::store::now(),
        };
        // The same key again (pushed again before the broker saw the ack):
        // acknowledged, nothing restarted.
        let same = self.store.agent(&rec.name).is_some_and(|old| {
            old.key_id == rec.key_id
                && agent_auth_crypto::ct_eq(
                    old.api_key.expose().as_bytes(),
                    rec.api_key.expose().as_bytes(),
                )
                && old.agent_id == rec.agent_id
                && old.runtime == rec.runtime
                && old.project == rec.project
        });
        if same {
            self.send(json!({"type": "key.ack", "agent_id": rec.agent_id, "key_id": rec.key_id}))
                .await;
            return;
        }
        if let Err(e) = self.store.put_agent(rec.clone()) {
            // Not acknowledged: the broker sends it again.
            tracing::error!(agent = %rec.name, "could not store a key: {e}");
            return;
        }
        tracing::info!("received the key of {}", rec.name);
        self.send(json!({"type": "key.ack", "agent_id": rec.agent_id, "key_id": rec.key_id}))
            .await;
        locked(&self.gateway_keys).remove(&rec.name);
        locked(&self.key_rotations).remove(&rec.name);
        self.key_gen.send_modify(|g| *g = g.wrapping_add(1));
        self.dispatch(&rec.name, true);
    }

    /// The broker refused an agent's key (401): ask for a new one, at most
    /// once per [`KEY_ROTATE_INTERVAL`].
    pub(crate) async fn key_lost(&self, agent: &str) {
        let now = tokio::time::Instant::now();
        {
            let mut asked = locked(&self.key_rotations);
            if asked
                .get(agent)
                .is_some_and(|t| now.saturating_duration_since(*t) < KEY_ROTATE_INTERVAL)
            {
                return;
            }
            asked.insert(agent.to_owned(), now);
        }
        tracing::warn!("the broker no longer accepts the key of {agent}; asking for a new one");
        self.send(json!({"type": "key.rotate", "name": agent}))
            .await;
    }

    /// Wait until some agent's key arrives (after a 401), or `limit`.
    pub(crate) async fn wait_for_a_key(&self, limit: Duration) {
        let mut rx = self.key_gen.subscribe();
        rx.mark_unchanged();
        let _ = tokio::time::timeout(limit, rx.changed()).await;
    }

    // ------------------------------------------------------------- holds

    #[must_use]
    pub fn locked(&self) -> bool {
        self.holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .locked()
    }

    #[must_use]
    pub fn contained(&self, agent: &str) -> bool {
        self.holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_contained(agent)
    }

    /// Locked down, or this agent contained.
    #[must_use]
    pub fn held(&self, agent: &str) -> bool {
        self.holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .held(agent)
    }

    /// `locked down` or `<agent> is contained`, if held.
    #[must_use]
    pub fn hold_refusal(&self, agent: &str) -> Option<String> {
        self.holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .refusal(agent)
    }

    /// Apply a hold event now (in memory and on disk) and queue its
    /// effects. A hold that cannot be written still holds in memory (and
    /// the old state on disk holds at least as much); an event that only
    /// lifts holds is not applied unless it is written (fail closed).
    pub fn hold(&self, event: HoldEvent, call_id: Option<CallId>) {
        let applied = {
            let mut holds = self.holds.write().unwrap_or_else(PoisonError::into_inner);
            let applied = holds.apply(event);
            let adds = (applied.after.locked() && !applied.before.locked())
                || applied
                    .after
                    .contained_set()
                    .iter()
                    .any(|a| !applied.before.is_contained(a));
            let persisted = self
                .store
                .set_locked(applied.after.locked())
                .and_then(|()| {
                    self.store
                        .set_contained(applied.after.contained_set().clone())
                });
            if let Err(e) = persisted {
                if !adds && applied.changed() {
                    tracing::error!("could not record a lifted hold; it stays: {e}");
                    drop(holds);
                    if let Some(me) = self.me() {
                        let call_id = call_id.clone();
                        self.spawn(async move {
                            me.reply(call_id.as_ref(), Err(format!("could not record it: {e}")))
                                .await;
                        });
                    }
                    return;
                }
                tracing::error!("could not record a hold; it holds in memory: {e}");
            }
            *holds = applied.after.clone();
            applied
        };
        if applied.after.locked() && !applied.before.locked() {
            tracing::warn!("LOCKDOWN: freezing every agent unit");
        } else if applied.before.locked() && !applied.after.locked() {
            tracing::warn!("lockdown lifted: thawing the agent units nothing else holds");
        }
        for a in applied.after.contained_set() {
            if !applied.before.is_contained(a) {
                tracing::warn!("CONTAINED: freezing the conversations of {a}");
                locked(&self.gateway_keys).remove(a);
            }
        }
        for a in applied.before.contained_set() {
            if !applied.after.is_contained(a) {
                if applied.after.locked() {
                    tracing::warn!(
                        "containment of {a} lifted; the VM-wide lockdown still holds it"
                    );
                } else {
                    tracing::warn!("containment of {a} lifted: thawing");
                }
            }
        }
        self.start_hold_worker();
        self.holds_queued.fetch_add(1, Ordering::SeqCst);
        let _ = self.hold_jobs.send(HoldJob { applied, call_id });
    }

    /// Lock the VM down (and wait for the freezing).
    pub async fn lockdown(&self) {
        self.hold(HoldEvent::Lockdown, None);
        self.settle_holds().await;
    }

    /// Lift the VM-wide lockdown (contained agents stay held).
    pub async fn unlock(&self) {
        self.hold(HoldEvent::Unlock, None);
        self.settle_holds().await;
    }

    /// The broker's complete held set for this VM.
    pub async fn set_contained(&self, agents: &[String]) {
        self.hold(HoldEvent::Contained(agents.iter().cloned().collect()), None);
        self.settle_holds().await;
    }

    /// Hold these agents too.
    pub async fn contain(&self, agents: &[String]) {
        let mut set = self
            .holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contained_set()
            .clone();
        set.extend(agents.iter().cloned());
        self.hold(HoldEvent::Contained(set), None);
        self.settle_holds().await;
    }

    /// Stop holding these agents (the lockdown, if any, still holds them).
    pub async fn release(&self, agents: &[String]) {
        let mut set = self
            .holds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contained_set()
            .clone();
        for a in agents {
            set.remove(a);
        }
        self.hold(HoldEvent::Contained(set), None);
        self.settle_holds().await;
    }

    fn start_hold_worker(&self) {
        let Some(mut rx) = locked(&self.hold_rx).take() else {
            return;
        };
        let Some(me) = self.me() else { return };
        self.spawn(async move {
            while let Some(job) = rx.recv().await {
                me.hold_effects(&job.applied).await;
                if job.call_id.is_some() {
                    me.reply(job.call_id.as_ref(), Ok(())).await;
                }
                me.holds_done.send_modify(|n| *n = n.saturating_add(1));
            }
        });
    }

    /// Freeze what became held; thaw (and deliver to) what nothing holds
    /// any more. A thaw is checked against the holds as they are now, so a
    /// later event that held the agent again wins.
    async fn hold_effects(&self, applied: &Applied) {
        let mut released: Vec<String> = Vec::new();
        let convs = self.store.conversations(None, false);
        for conv in &convs {
            match applied.action(&conv.agent) {
                UnitAction::Keep => {}
                UnitAction::Freeze => self.freeze_conversation(&conv.id, true).await,
                UnitAction::Release => {
                    if self.held(&conv.agent) {
                        continue;
                    }
                    self.freeze_conversation(&conv.id, false).await;
                    if !released.contains(&conv.agent) {
                        released.push(conv.agent.clone());
                    }
                }
            }
        }
        for agent in released {
            if !self.held(&agent) {
                tracing::warn!("{agent} is no longer held: delivering what queued up");
            }
        }
        // What arrived meanwhile, off this worker.
        let Some(me) = self.me() else { return };
        let ids: Vec<ConvId> = convs
            .iter()
            .filter(|c| applied.action(&c.agent) == UnitAction::Release)
            .map(|c| c.id.clone())
            .collect();
        if !ids.is_empty() {
            self.spawn(async move {
                for id in ids {
                    me.deliver_queued(&id).await;
                }
            });
        }
    }

    /// Freeze or thaw a conversation's units (its process and its TUI).
    pub(crate) async fn freeze_conversation(&self, conv: &ConvId, frozen: bool) {
        let Some(lv) = locked(&self.live).get(conv).cloned() else {
            return;
        };
        if lv.run().is_some() {
            self.host.freeze_unit(&conv.unit(), frozen).await;
        }
        if lv.tui() {
            self.host.freeze_unit(&conv.tui_unit(), frozen).await;
        }
    }

    /// Wait until every hold change so far has had its freezing and
    /// thawing done (deliveries it started may still be running).
    pub async fn settle_holds(&self) {
        let target = self.holds_queued.load(Ordering::SeqCst);
        let mut rx = self.holds_done.subscribe();
        let _ = tokio::time::timeout(Duration::from_secs(60), async {
            while *rx.borrow_and_update() < target {
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
    }

    // ----------------------------------------------------------- logs

    #[must_use]
    pub fn log_path(&self, conv: &ConvId) -> PathBuf {
        self.config
            .state_dir
            .join("logs")
            .join(format!("{}.log", conv.as_str()))
    }

    /// One JSONL line of the transcript (`in`, `out`, `error`).
    pub(crate) fn log(&self, conv: &ConvId, dir: &str, text: &str) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let line = json!({"t": crate::store::now(), "dir": dir, "text": text}).to_string() + "\n";
        let opened = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.log_path(conv));
        if let Ok(mut f) = opened {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// The channel's view of the daemon.
pub struct ChannelHandler<H: Host>(pub Arc<Sandboxd<H>>);

impl<H: Host> std::fmt::Debug for ChannelHandler<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelHandler").finish_non_exhaustive()
    }
}

impl<H: Host> agent_auth_daemon::Handler for ChannelHandler<H> {
    fn status(&self) -> Map<String, Value> {
        self.0.status()
    }

    async fn on_message(&self, body: Map<String, Value>) {
        self.0.on_broker_message(body).await;
    }
}
