//! Paired daemons (hostd, sandboxd): pairing, the per-connection hello,
//! heartbeats, and the map of live connections other parts send calls
//! through (daemons-hostd spec §3-§4). Role-neutral: hostexec and the
//! sandboxes register their message handlers and hooks here.
//!
//! Daemons dial out and hold one WebSocket each (`/v1/daemons/connect`):
//!
//! ```text
//! broker → {"type": "challenge", "nonce": bn}
//! daemon → {"type": "hello", "role", "name", "nonce": dn, "params", "sig"}
//! broker → {"type": "welcome", "params", "sig"}
//! … then signed envelopes both ways, bound to this connection.
//! ```
//!
//! The hello is verified against the key bound at pairing; only a verified
//! hello yields a [`DaemonPeer`] and the connection's sealer and verifier.
//! Generations (bumped on re-pair and unpair) and the live map are guarded
//! by one lock, so a connection authenticated with a key that has since
//! been replaced is never registered (INV-6). Both are process-local: the
//! broker is one process (bug 16).

mod channel;
mod pairing;
mod routes;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use agent_auth_core::DaemonId;
use agent_auth_crypto::daemon::{
    DaemonId as ChannelId, DaemonName, EnvelopeSealer, PublicKey, Role, SigningKey,
};
use agent_auth_store::Store;
use agent_auth_wire::daemon::channel::{CallId, Reply};
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::SinkExt as _;
use futures::future::BoxFuture;
use futures::stream::SplitSink;
use serde_json::{Map, Value, json};
use tokio::sync::{Semaphore, oneshot, watch};

pub use pairing::{PairingError, PairingRefused};
pub use routes::routes;

/// Connections that haven't authenticated yet are anyone's: at most this
/// many handshakes at once.
pub const MAX_PENDING_HANDSHAKES: usize = 32;
/// Waiting for the hello.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection silent for this many heartbeat intervals is dropped.
pub const MISSED_HEARTBEATS: u32 = 3;
/// Heartbeat status is daemon-supplied: at most this much of it is stored.
pub const MAX_STATUS_BYTES: usize = 16 * 1024;
/// The largest frame accepted from a daemon (an output chunk is ~175 KB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub const CLOSE_BAD_HELLO: u16 = 4400;
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
pub const CLOSE_REPLACED: u16 = 4409;
pub const CLOSE_DISABLED: u16 = 4503;
pub const CLOSE_TRY_AGAIN: u16 = 1013;

/// The daemon settings (spec §13.1).
#[derive(Debug, Clone)]
pub struct DaemonsConfig {
    /// `BROKER_SIGNING_KEY`; `None`: the channel is disabled.
    pub signing_key: Option<SigningKey>,
    /// `DAEMON_HEARTBEAT_SECS` (30): sent in the welcome; the idle timeout
    /// is three of them.
    pub heartbeat_secs: u32,
    /// `DAEMON_PAIRING_CODE_TTL_SECS` (600).
    pub pairing_code_ttl_secs: u32,
    /// `DAEMON_PAIRING_MAX_ATTEMPTS` (5): wrong proofs before a code burns.
    pub pairing_max_attempts: u32,
}

impl Default for DaemonsConfig {
    fn default() -> Self {
        DaemonsConfig {
            signing_key: None,
            heartbeat_secs: 30,
            pairing_code_ttl_secs: 600,
            pairing_max_attempts: 5,
        }
    }
}

impl DaemonsConfig {
    /// From the environment (names case-insensitive as pydantic-settings
    /// read them; the upper-case spelling is what deployments use).
    pub fn from_env() -> Result<DaemonsConfig, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let num = |name: &str, default: u32| -> Result<u32, String> {
            match var(name) {
                None => Ok(default),
                Some(v) => v
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("{name} must be a positive integer")),
            }
        };
        let signing_key = match var("BROKER_SIGNING_KEY") {
            None => None,
            Some(k) => {
                Some(SigningKey::from_text(&k).map_err(|e| format!("BROKER_SIGNING_KEY: {e}"))?)
            }
        };
        Ok(DaemonsConfig {
            signing_key,
            heartbeat_secs: num("DAEMON_HEARTBEAT_SECS", 30)?,
            pairing_code_ttl_secs: num("DAEMON_PAIRING_CODE_TTL_SECS", 600)?,
            pairing_max_attempts: num("DAEMON_PAIRING_MAX_ATTEMPTS", 5)?,
        })
    }
}

/// A paired daemon whose hello verified on this connection. Only the hub
/// makes one; message handlers and hooks receive it.
#[derive(Debug)]
pub struct DaemonPeer {
    /// The `daemons` row.
    row: DaemonId,
    id: ChannelId,
    /// The key the hello was verified against.
    public_key: PublicKey,
}

impl DaemonPeer {
    #[must_use]
    pub fn row_id(&self) -> DaemonId {
        self.row
    }
    #[must_use]
    pub fn role(&self) -> Role {
        self.id.role
    }
    #[must_use]
    pub fn name(&self) -> &str {
        self.id.name.as_str()
    }
    #[must_use]
    pub fn principal(&self) -> String {
        self.id.principal()
    }
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// A call to a daemon failed: offline, timed out, or the daemon said no.
/// The text is for a human (the Python's `DaemonCallError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CallError {
    pub message: String,
    /// Sent, but no answer in time: the daemon may have acted on it.
    pub timed_out: bool,
}

impl CallError {
    fn new(message: String, timed_out: bool) -> CallError {
        CallError { message, timed_out }
    }
}

/// A handler for one message type from daemons. Runs inline in the
/// connection's receive loop; must not fail (errors are its own to log).
pub type MessageHandler =
    Arc<dyn Fn(Arc<DaemonPeer>, Map<String, Value>) -> BoxFuture<'static, ()> + Send + Sync>;
/// Run (in the background) when a daemon connects or heartbeats.
pub type PeerHook = Arc<dyn Fn(Arc<DaemonPeer>) -> BoxFuture<'static, ()> + Send + Sync>;
/// Run after a successful (re-)pairing: `(role, name, row id)`.
pub type PairedHook = Arc<dyn Fn(Role, String, DaemonId) -> BoxFuture<'static, ()> + Send + Sync>;

type Key = (Role, String);

struct Outbound {
    sink: SplitSink<WebSocket, Message>,
    sealer: EnvelopeSealer,
}

pub(crate) struct Live {
    peer: Arc<DaemonPeer>,
    generation: u64,
    out: tokio::sync::Mutex<Outbound>,
    close: watch::Sender<Option<(u16, String)>>,
    last_status_write: Mutex<Option<tokio::time::Instant>>,
}

impl Live {
    fn close(&self, code: u16, reason: &str) {
        self.close.send_replace(Some((code, reason.to_owned())));
    }
}

#[derive(Default)]
struct Registry {
    live: HashMap<Key, Arc<Live>>,
    generation: HashMap<Key, u64>,
}

#[derive(Default)]
struct Hooks {
    handlers: HashMap<String, MessageHandler>,
    on_connect: Vec<PeerHook>,
    on_heartbeat: Vec<PeerHook>,
    on_paired: Vec<PairedHook>,
}

/// The hub.
pub struct DaemonHub {
    store: Store,
    config: DaemonsConfig,
    registry: Mutex<Registry>,
    pending: Arc<Semaphore>,
    calls: Mutex<HashMap<String, (Key, oneshot::Sender<Reply>)>>,
    hooks: RwLock<Hooks>,
}

impl fmt::Debug for DaemonHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonHub")
            .field("enabled", &self.enabled())
            .finish_non_exhaustive()
    }
}

fn key_of(role: Role, name: &str) -> Key {
    (role, name.to_owned())
}

fn principal(role: Role, name: &str) -> String {
    format!("{role}:{name}")
}

impl DaemonHub {
    #[must_use]
    pub fn new(store: Store, config: DaemonsConfig) -> DaemonHub {
        DaemonHub {
            store,
            config,
            registry: Mutex::new(Registry::default()),
            pending: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
            calls: Mutex::new(HashMap::new()),
            hooks: RwLock::new(Hooks::default()),
        }
    }

    #[must_use]
    pub fn config(&self) -> &DaemonsConfig {
        &self.config
    }

    /// Whether `BROKER_SIGNING_KEY` is configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.config.signing_key.is_some()
    }

    /// The broker's public key text (`ed25519:…`), if enabled.
    #[must_use]
    pub fn public_key(&self) -> Option<PublicKey> {
        self.config.signing_key.as_ref().map(SigningKey::public_key)
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn hooks(&self) -> std::sync::RwLockReadGuard<'_, Hooks> {
        self.hooks.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn hooks_mut(&self) -> std::sync::RwLockWriteGuard<'_, Hooks> {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner)
    }

    // ------------------------------------------------- extension points

    /// Handle every message of `kind` from daemons. `heartbeat`, `reply`
    /// and a kind already handled are refused.
    pub fn handle(&self, kind: &str, handler: MessageHandler) -> Result<(), String> {
        let mut hooks = self.hooks_mut();
        if kind == "heartbeat" || kind == "reply" || hooks.handlers.contains_key(kind) {
            return Err(format!("message type {kind:?} is already handled"));
        }
        hooks.handlers.insert(kind.to_owned(), handler);
        Ok(())
    }

    pub fn on_connect(&self, hook: PeerHook) {
        self.hooks_mut().on_connect.push(hook);
    }

    pub fn on_heartbeat(&self, hook: PeerHook) {
        self.hooks_mut().on_heartbeat.push(hook);
    }

    pub fn on_paired(&self, hook: PairedHook) {
        self.hooks_mut().on_paired.push(hook);
    }

    // --------------------------------------------------------- liveness

    #[must_use]
    pub fn is_online(&self, role: Role, name: &str) -> bool {
        self.registry().live.contains_key(&key_of(role, name))
    }

    fn live(&self, role: Role, name: &str) -> Option<Arc<Live>> {
        self.registry().live.get(&key_of(role, name)).cloned()
    }

    /// Re-pair or unpair: bump the identity's generation and close its
    /// live connection (4409). A handshake in flight with the old key is
    /// refused when it tries to register.
    pub(crate) fn kick(&self, role: Role, name: &str, reason: &str) {
        let live = {
            let mut reg = self.registry();
            let key = key_of(role, name);
            let g = reg.generation.entry(key.clone()).or_insert(0);
            *g = g.saturating_add(1);
            reg.live.remove(&key)
        };
        if let Some(live) = live {
            live.close(CLOSE_REPLACED, reason);
        }
    }

    fn generation(&self, role: Role, name: &str) -> u64 {
        self.registry()
            .generation
            .get(&key_of(role, name))
            .copied()
            .unwrap_or(0)
    }

    // ------------------------------------------------------ sending

    /// Seal and send one message to a connected daemon (sealing and
    /// sending under one lock). False: offline, or the send failed.
    pub async fn send(
        &self,
        role: Role,
        name: &str,
        payload: &Map<String, Value>,
        ttl_secs: f64,
    ) -> bool {
        let Some(live) = self.live(role, name) else {
            return false;
        };
        let mut out = live.out.lock().await;
        let text = match out.sealer.seal_now(payload, ttl_secs) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(daemon = %principal(role, name), error = %e, "could not seal a message");
                return false;
            }
        };
        match out.sink.send(Message::text(text)).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(daemon = %principal(role, name), error = %e, "send failed");
                false
            }
        }
    }

    /// Send with the default lifetime (60 s).
    pub async fn send_default(&self, role: Role, name: &str, payload: &Map<String, Value>) -> bool {
        self.send(
            role,
            name,
            payload,
            agent_auth_crypto::daemon::DEFAULT_ENVELOPE_TTL_SECS,
        )
        .await
    }

    /// Send a request and wait for the daemon's reply. Its `data` (an
    /// object; `{}` otherwise), or why not: offline, no answer in time, or
    /// the daemon's refusal (at most 500 characters). Only a reply from the
    /// daemon the call went to counts (INV-10).
    pub async fn call(
        &self,
        role: Role,
        name: &str,
        payload: Map<String, Value>,
        timeout: Duration,
    ) -> Result<Map<String, Value>, CallError> {
        let call_id = CallId::new();
        let (tx, rx) = oneshot::channel();
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(call_id.as_str().to_owned(), (key_of(role, name), tx));
        let mut msg = payload;
        msg.insert("call_id".into(), json!(call_id.as_str()));
        let ttl = timeout
            .as_secs_f64()
            .clamp(1.0, agent_auth_crypto::daemon::MAX_ENVELOPE_TTL_SECS);
        let result = if self.send(role, name, &msg, ttl).await {
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(reply)) => Ok(reply),
                Ok(Err(_)) | Err(_) => Err(CallError::new(
                    format!(
                        "{} did not answer within {}s",
                        principal(role, name),
                        timeout.as_secs()
                    ),
                    true,
                )),
            }
        } else {
            Err(CallError::new(
                format!("{} is offline", principal(role, name)),
                false,
            ))
        };
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(call_id.as_str());
        let reply = result?;
        if !reply.ok {
            let text = reply
                .error
                .as_ref()
                .map(|e| e.as_str().chars().take(500).collect::<String>())
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| "refused by the daemon".to_owned());
            return Err(CallError::new(text, false));
        }
        Ok(reply.data.map(|d| d.into_map()).unwrap_or_default())
    }

    /// A reply arrived on `peer`'s connection.
    fn resolve(&self, peer: &DaemonPeer, reply: Reply) {
        let Some(call_id) = reply.call_id.as_ref().map(|c| c.as_str().to_owned()) else {
            return;
        };
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        let ours = calls
            .get(&call_id)
            .is_some_and(|(key, _)| *key == key_of(peer.role(), peer.name()));
        if ours && let Some((_, tx)) = calls.remove(&call_id) {
            let _ = tx.send(reply);
        }
    }

    /// Close every live connection (shutdown).
    pub fn close_all(&self, reason: &str) {
        let live: Vec<Arc<Live>> = self.registry().live.drain().map(|(_, l)| l).collect();
        for l in live {
            l.close(1001, reason);
        }
    }
}

/// A close frame.
pub(crate) fn close_frame(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// A daemon name from text (`[a-z0-9][a-z0-9-]{0,62}`).
#[must_use]
pub fn daemon_name(text: &str) -> Option<DaemonName> {
    DaemonName::parse(text)
}

// ------------------------------------------------------------- the part

/// This part's state in `AppState` (`hostd`): the hub, commands on hosts,
/// desk prompts and attention.
#[derive(Debug)]
pub struct HostdPart {
    pub hub: Arc<DaemonHub>,
    /// On when the daemon channel is (`BROKER_SIGNING_KEY`).
    pub hostexec: Option<Arc<crate::hostexec::HostExec>>,
    /// On when the policy's `desktop.enabled` is, and hostexec is.
    pub desktop: Option<Arc<crate::desktop::Desktop>>,
    pub attention: crate::attention::Attention,
}

impl HostdPart {
    /// Build the part. `watcher`: the hostexec watcher (OpenRouter
    /// configured and `platforms.hostexec.watch`).
    pub fn build(
        store: Store,
        config: DaemonsConfig,
        policy: Arc<agent_auth_core::policy::Policy>,
        watcher: Option<crate::hostexec::watcher::Watcher>,
    ) -> Result<HostdPart, String> {
        let enabled = config.signing_key.is_some();
        let hub = Arc::new(DaemonHub::new(store.clone(), config));
        let hostexec = if enabled {
            Some(crate::hostexec::HostExec::new(
                Arc::clone(&hub),
                store,
                Arc::clone(&policy),
                watcher,
            )?)
        } else {
            None
        };
        let desktop = match &hostexec {
            Some(h) if policy.desktop().enabled => Some(crate::desktop::Desktop::new(
                Arc::clone(&hub),
                Some(Arc::clone(h)),
            )?),
            _ => None,
        };
        Ok(HostdPart {
            hub,
            hostexec,
            desktop,
            attention: crate::attention::Attention::default(),
        })
    }

    /// The notifier to install: `primary`, with desk prompts alongside when
    /// the desktop is on.
    #[must_use]
    pub fn wrap_notifier(&self, primary: crate::notify::Notifier) -> crate::notify::Notifier {
        match &self.desktop {
            Some(d) => crate::notify::Notifier::Fanout(crate::desktop::Fanout {
                primary: crate::desktop::Primary::from_notifier(primary),
                desktop: Arc::clone(d),
            }),
            None => primary,
        }
    }

    /// The hostexec provisioner, to register (when on).
    #[must_use]
    pub fn provisioner(&self) -> Option<crate::provisioners::AnyProvisioner> {
        self.hostexec.as_ref().map(|h| {
            crate::provisioners::AnyProvisioner::Hostexec(
                crate::hostexec::provisioner::HostexecProvisioner {
                    hostexec: Arc::clone(h),
                },
            )
        })
    }

    /// Plug into the spine: hostexec's approval gate and scheduler step.
    pub fn install_hooks(&self, hooks: &mut crate::service::Hooks) {
        if let Some(h) = &self.hostexec {
            hooks.approval_gates.insert(
                agent_auth_core::Platform::Hostexec,
                crate::hostexec::approval_gate_hook(Arc::clone(h)),
            );
            hooks.hostexec_tick = Some(crate::hostexec::tick_hook(Arc::clone(h)));
        }
    }

    /// After `AppState` is built (once): the services reach the notifier
    /// and the request service through it.
    pub fn bind(&self, st: &crate::state::AppState) {
        if let Some(h) = &self.hostexec {
            h.bind(st.clone());
        }
        if let Some(d) = &self.desktop {
            d.bind(st.clone());
        }
    }
}
