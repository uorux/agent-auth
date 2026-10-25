//! Agent VMs as seen from the broker (sandboxd spec §2): the orchestrator
//! bootstrap, key custody and delivery, and what an agent VM is told about
//! lockdowns and containment.
//!
//! - Pairing a sandbox daemon (role `sandbox`) bootstraps
//!   `orchestrator-<host>-sandbox`; re-pairing rotates its key.
//! - Minting (`agents::AgentsProvisioner`) creates or renews
//!   `<runtime>-<project>-<host>-sandbox`. Its API key is generated here and
//!   handed ONLY to its sandbox daemon, over the signed channel, in a `key`
//!   message (INV-1). Until that daemon acknowledges that very key (the ack
//!   names its `key_id`: B-6) it waits encrypted in
//!   `pending_key_deliveries`, the one place it can be recovered (INV-2).
//! - A sandbox may ask for a fresh key for one of its own enabled agents.
//! - On every (re)connect a sandbox is told the broker's lock state
//!   (`lockdown` or `unlock`: a missed unlock is resent, B-3) and its held
//!   agents, then its pending keys. Whenever containment changes it gets
//!   its held list again (`tell_sandboxes`).
//! - Cross-project access (`project::SandboxProvisioner`) is applied by the
//!   daemon as ACLs.

pub mod agents;
pub mod project;
#[cfg(test)]
mod sandboxd_tests;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::sandbox::{ORCHESTRATOR_RUNTIME, orchestrator_name};
use agent_auth_core::{AgentId, DaemonId};
use agent_auth_crypto::api_key::{self, GeneratedKey};
use agent_auth_crypto::daemon::Role;
use agent_auth_crypto::secretbox::{Binding, SecretBox};
use agent_auth_store::agents::{self as agent_rows, AgentRow, NewAgent};
use agent_auth_store::daemons::{self, DaemonRole};
use agent_auth_store::{Store, StoreError, Tx, flags, lockdown, sandboxes as store};
use agent_auth_wire::daemon::channel::{Incoming, parse};
use agent_auth_wire::daemon::sandbox::SandboxToBroker;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::daemons::{DaemonHub, DaemonPeer};
use crate::state::AppState;

/// Without `ENCRYPTION_KEY` no key can wait for its sandbox (INV-2).
pub const NO_KEY_BOX: &str = "ENCRYPTION_KEY is required to hand keys to a sandbox";
/// A key is pushed this long after the transaction that queued it, so it
/// has committed (heartbeats and the scheduler retry anyway).
pub const NUDGE_DELAY: Duration = Duration::from_millis(500);

/// Where a pending key's ciphertext lives (its AEAD binding).
fn binding(delivery: &str) -> Binding<'_> {
    Binding::new("pending_key_deliveries", "key_encrypted", delivery)
}

/// Why a key could not be queued.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("{NO_KEY_BOX}")]
    NoKeyBox,
    #[error("no randomness for a new key")]
    Random,
    #[error("could not encrypt the key")]
    Seal,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The agent-VM part of the broker (one `AppState` field).
pub struct Sandboxes {
    hub: Arc<DaemonHub>,
    store: Store,
    secret_box: Option<Arc<SecretBox>>,
    me: Weak<Sandboxes>,
    st: OnceLock<AppState>,
    /// The connection of each VM that has had its greeting (lock state and
    /// held list): keys go only to a greeted connection, so a VM always
    /// knows it is locked or holding agents before any key arrives.
    greeted: std::sync::Mutex<std::collections::HashMap<String, Weak<DaemonPeer>>>,
    /// This process's held lists: an epoch and an increasing sequence,
    /// assigned under `tell_lock` with the read they report.
    held_epoch: String,
    held_seq: std::sync::atomic::AtomicU64,
    tell_lock: tokio::sync::Mutex<()>,
    /// `key.rotate` per agent name: a token bucket (review #5).
    rotations: std::sync::Mutex<std::collections::HashMap<String, (f64, tokio::time::Instant)>>,
}

/// `key.rotate`: at most [`ROTATE_BURST`] at once per agent, then one per
/// [`ROTATE_EVERY`].
pub const ROTATE_BURST: f64 = 2.0;
pub const ROTATE_EVERY: Duration = Duration::from_secs(300);

impl std::fmt::Debug for Sandboxes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandboxes")
            .field("keys", &self.secret_box.is_some())
            .finish_non_exhaustive()
    }
}

fn is_sandbox(peer: &DaemonPeer) -> bool {
    peer.role() == Role::Sandbox
}

fn payload(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

impl Sandboxes {
    /// The service, with its hooks and handlers registered on the hub.
    pub fn new(
        hub: Arc<DaemonHub>,
        store: Store,
        secret_box: Option<Arc<SecretBox>>,
    ) -> Result<Arc<Sandboxes>, String> {
        if secret_box.is_none() {
            tracing::warn!("ENCRYPTION_KEY unset: agent VMs can pair but receive no agent keys");
        }
        let me = Arc::new_cyclic(|weak| Sandboxes {
            hub: Arc::clone(&hub),
            store,
            secret_box,
            me: weak.clone(),
            st: OnceLock::new(),
            rotations: std::sync::Mutex::new(std::collections::HashMap::new()),
            greeted: std::sync::Mutex::new(std::collections::HashMap::new()),
            held_epoch: Uuid::new_v4().simple().to_string(),
            held_seq: std::sync::atomic::AtomicU64::new(0),
            tell_lock: tokio::sync::Mutex::new(()),
        });
        let s = Arc::clone(&me);
        hub.on_paired(Arc::new(move |role, name, id| {
            let s = Arc::clone(&s);
            Box::pin(async move {
                if role == Role::Sandbox {
                    s.bootstrap(&name, id).await;
                }
            })
        }));
        let s = Arc::clone(&me);
        hub.on_connect(Arc::new(move |peer| {
            let s = Arc::clone(&s);
            Box::pin(async move { s.on_connect(&peer).await })
        }));
        let s = Arc::clone(&me);
        hub.on_heartbeat(Arc::new(move |peer| {
            let s = Arc::clone(&s);
            Box::pin(async move {
                if is_sandbox(&peer) {
                    s.push(peer.name(), peer.row_id()).await;
                }
            })
        }));
        let s = Arc::clone(&me);
        hub.handle(
            "key.ack",
            Arc::new(move |peer, body| {
                let s = Arc::clone(&s);
                Box::pin(async move { s.on_key_ack(&peer, body).await })
            }),
        )?;
        let s = Arc::clone(&me);
        hub.handle(
            "key.rotate",
            Arc::new(move |peer, body| {
                let s = Arc::clone(&s);
                Box::pin(async move { s.on_key_rotate(&peer, body).await })
            }),
        )?;
        Ok(me)
    }

    /// Attach the broker's state (once, after `AppState` is built).
    pub fn bind(&self, st: AppState) {
        let _ = self.st.set(st);
    }

    #[must_use]
    pub fn hub(&self) -> &Arc<DaemonHub> {
        &self.hub
    }

    // ------------------------------------------------------------- keys

    /// Queue `key` for the agent's sandbox, replacing any older pending
    /// key of the agent. The agent's stored key must already be `key`.
    async fn queue_delivery(
        &self,
        tx: &Tx<'_>,
        agent: AgentId,
        sandbox: DaemonId,
        key: &GeneratedKey,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        let boxed = self.secret_box.as_ref().ok_or(QueueError::NoKeyBox)?;
        let id = Uuid::new_v4();
        let row = id.to_string();
        let sealed = boxed
            .seal_str(key.full_key.expose(), &binding(&row))
            .map_err(|_| QueueError::Seal)?;
        store::queue(tx, id, agent, sandbox, key.key_id.as_str(), &sealed, now).await?;
        Ok(())
    }

    /// A new key for an existing agent of `sandbox`, queued for it alone:
    /// the old key stops authenticating in this transaction (INV-4).
    async fn rotate_key(
        &self,
        tx: &Tx<'_>,
        agent: AgentId,
        sandbox: DaemonId,
        now: OffsetDateTime,
    ) -> Result<(), QueueError> {
        if self.secret_box.is_none() {
            return Err(QueueError::NoKeyBox);
        }
        let key = api_key::generate().map_err(|_| QueueError::Random)?;
        agent_rows::set_key(tx, agent, key.key_id.as_str(), key.hash.as_str()).await?;
        self.queue_delivery(tx, agent, sandbox, &key, now).await
    }

    /// Push every pending key of daemon `id` (named `name`) to it, if it is
    /// connected. The plaintext key exists only in the sealed `key`
    /// message (INV-1).
    pub async fn push(&self, name: &str, id: DaemonId) {
        if !self.greeted_now(name) {
            // Its greeting is still on its way; it pushes the keys itself.
            return;
        }
        self.push_greeted(name, id).await;
    }

    /// Whether `name`'s current connection has had its greeting.
    fn greeted_now(&self, name: &str) -> bool {
        let Some(current) = self.hub.current_peer(Role::Sandbox, name) else {
            return false;
        };
        self.greeted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .and_then(Weak::upgrade)
            .is_some_and(|g| Arc::ptr_eq(&g, &current))
    }

    async fn push_greeted(&self, name: &str, id: DaemonId) {
        let Some(boxed) = self.secret_box.as_ref() else {
            return;
        };
        if !self.hub.is_online(Role::Sandbox, name) {
            return;
        }
        // The held list goes first, read in the same snapshot as the keys
        // (review 2026-10): a key is committed with its agent row, so an
        // agent minted, re-enabled or re-keyed while some entry holds it
        // (its own, its orchestrator's, a lockdown's) is named in the list
        // the VM applies before it reads the key. Under `tell_lock`, so no
        // older list can follow it; a later list is newer.
        let told = self.tell_lock.lock().await;
        let pending = async {
            let tx = self.store.begin().await?;
            let rows = store::pending_for(&tx, id).await?;
            let held = if rows.is_empty() {
                Vec::new()
            } else {
                lockdown::held_in(&tx, id).await?
            };
            tx.commit().await?;
            Ok::<_, StoreError>((rows, held))
        }
        .await;
        let pending = match pending {
            Ok((p, _)) if p.is_empty() => return,
            Ok((p, held)) => {
                if !self
                    .hub
                    .send_default(Role::Sandbox, name, &payload(self.held_message(&held)))
                    .await
                {
                    // No key without the held list before it.
                    return;
                }
                p
            }
            Err(e) => {
                tracing::error!(sandbox = %name, error = %e, "listing pending keys failed");
                return;
            }
        };
        drop(told);
        for row in pending {
            let delivery = row.id.to_string();
            let Ok(key) = boxed.open_str(&row.key_encrypted, &binding(&delivery)) else {
                tracing::error!(sandbox = %name, agent = %row.agent_name, "a pending key does not decrypt; skipped");
                continue;
            };
            let msg = payload(json!({
                "type": "key",
                "agent_id": row.agent_id.to_string(),
                "key_id": row.key_id,
                "name": row.agent_name,
                "runtime": row.runtime,
                "project": row.project,
                "api_key": key.expose(),
            }));
            if self.hub.send_default(Role::Sandbox, name, &msg).await {
                tracing::info!(sandbox = %name, agent = %row.agent_name, "key delivered");
            }
        }
    }

    /// Push daemon `id`'s pending keys shortly (after the caller's
    /// transaction commits).
    pub fn nudge(&self, id: DaemonId) {
        let Some(me) = self.me.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(NUDGE_DELAY).await;
            let row = async {
                let tx = me.store.begin().await?;
                let row = daemons::get(&tx, id).await?;
                tx.commit().await?;
                Ok::<_, StoreError>(row)
            }
            .await;
            match row {
                Ok(Some(d)) if d.role == DaemonRole::Sandbox => me.push(&d.name, d.id).await,
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "loading a sandbox to push keys failed"),
            }
        });
    }

    /// `key.ack {agent_id, key_id}`: only the sandbox the key was meant
    /// for retires its delivery, and only for that key (INV-3, B-6).
    async fn on_key_ack(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if !is_sandbox(peer) {
            return;
        }
        let ack = match parse::<SandboxToBroker>(body) {
            Incoming::Message(SandboxToBroker::KeyAck(a)) => a,
            Incoming::Malformed { error, .. } => {
                tracing::warn!(daemon = %peer.principal(), "malformed key.ack: {error}");
                return;
            }
            _ => return,
        };
        let done = async {
            let tx = self.store.begin().await?;
            let n = store::ack(&tx, ack.agent_id, peer.row_id(), ack.key_id.as_str()).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(n)
        }
        .await;
        match done {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(daemon = %peer.principal(), "key.ack for no pending key (superseded or not its own)")
            }
            Err(e) => tracing::error!(daemon = %peer.principal(), error = %e, "key.ack failed"),
        }
    }

    /// `key.rotate {name}`: a sandbox lost one of its agents' keys. A new
    /// one is issued only for its own enabled agent, to it alone (INV-4).
    async fn on_key_rotate(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if !is_sandbox(peer) {
            return;
        }
        let name = match parse::<SandboxToBroker>(body) {
            Incoming::Message(SandboxToBroker::KeyRotate(r)) => r.name.as_str().to_owned(),
            Incoming::Malformed { error, .. } => {
                tracing::warn!(daemon = %peer.principal(), "malformed key.rotate: {error}");
                return;
            }
            _ => return,
        };
        if !self.rotation_allowed(&name) {
            tracing::warn!(
                daemon = %peer.principal(),
                agent = %name,
                "key.rotate refused: asked too often"
            );
            return;
        }
        let done = async {
            let now = OffsetDateTime::now_utc();
            let tx = self.store.begin().await?;
            let Some(agent) = agent_rows::by_name(&tx, &name).await? else {
                return Ok(false);
            };
            if agent.sandbox_id != Some(peer.row_id()) || agent.disabled {
                return Ok(false);
            }
            self.rotate_key(&tx, agent.id, peer.row_id(), now).await?;
            tx.commit().await?;
            Ok::<_, QueueError>(true)
        }
        .await;
        match done {
            Ok(true) => {
                tracing::info!(daemon = %peer.principal(), agent = %name, "rotated a key at its sandbox's request");
                self.push(peer.name(), peer.row_id()).await;
            }
            Ok(false) => tracing::warn!(
                daemon = %peer.principal(),
                "asked for a key it doesn't own (or a disabled agent's): {name:?}"
            ),
            Err(e) => tracing::error!(daemon = %peer.principal(), error = %e, "key.rotate failed"),
        }
    }

    /// Take one `key.rotate` token of the agent's bucket, if it has one.
    fn rotation_allowed(&self, name: &str) -> bool {
        let now = tokio::time::Instant::now();
        let mut buckets = self
            .rotations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tokens, last) = buckets
            .entry(name.to_owned())
            .or_insert((ROTATE_BURST, now));
        let refill =
            now.saturating_duration_since(*last).as_secs_f64() / ROTATE_EVERY.as_secs_f64();
        *tokens = (*tokens + refill).min(ROTATE_BURST);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// The operator re-enabled `agent`: a VM agent gets a new key for its
    /// sandbox (the old one, perhaps the reason it was disabled, never
    /// works again). Returns the sandbox to push to.
    pub async fn rekey_enabled(
        &self,
        tx: &Tx<'_>,
        agent: &AgentRow,
        now: OffsetDateTime,
    ) -> Result<Option<DaemonId>, QueueError> {
        let Some(sandbox) = agent.sandbox_id else {
            return Ok(None);
        };
        self.rotate_key(tx, agent.id, sandbox, now).await?;
        Ok(Some(sandbox))
    }

    // ---------------------------------------------------- orchestrator

    /// After a sandbox (re-)paired: create its orchestrator, or adopt it and
    /// rotate its key (INV-10). Never takes over a same-named agent of
    /// another daemon or another runtime.
    async fn bootstrap(&self, host: &str, daemon: DaemonId) {
        let done = async {
            if self.secret_box.is_none() {
                return Err(QueueError::NoKeyBox);
            }
            let name = orchestrator_name(host);
            let now = OffsetDateTime::now_utc();
            let tx = self.store.begin().await?;
            match agent_rows::by_name(&tx, &name).await? {
                None => {
                    let key = api_key::generate().map_err(|_| QueueError::Random)?;
                    let description = format!("orchestrator of the agent VM on {host}");
                    let row = agent_rows::insert(
                        &tx,
                        &NewAgent {
                            id: AgentId::new(),
                            name: &name,
                            description: &description,
                            key_id: key.key_id.as_str(),
                            api_key_hash: key.hash.as_str(),
                            kind: AgentKind::Service,
                            webhook_url: None,
                            webhook_secret: None,
                            lldap_username: None,
                            parent_agent_id: None,
                            sandbox_id: Some(daemon),
                            runtime: Some(ORCHESTRATOR_RUNTIME),
                            project: None,
                            host: Some(host),
                            placement: Placement::Sandbox,
                            lease_expires_at: None,
                            last_seen_at: Some(now),
                            now,
                        },
                    )
                    .await?;
                    self.queue_delivery(&tx, row.id, daemon, &key, now).await?;
                    tx.commit().await?;
                    tracing::info!(sandbox = %host, "orchestrator {name} created, key queued");
                }
                Some(a)
                    if a.sandbox_id.is_some_and(|s| s != daemon)
                        || a.runtime.as_deref() != Some(ORCHESTRATOR_RUNTIME) =>
                {
                    tracing::error!(
                        sandbox = %host,
                        "{name} exists and isn't this sandbox's orchestrator; not taking it over"
                    );
                }
                Some(a) => {
                    if !agent_rows::adopt_orchestrator(&tx, a.id, daemon, host).await? {
                        tracing::error!(sandbox = %host, "{name} could not be adopted");
                        return Ok(());
                    }
                    self.rotate_key(&tx, a.id, daemon, now).await?;
                    tx.commit().await?;
                    tracing::info!(sandbox = %host, "orchestrator {name} adopted, new key queued");
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = done {
            tracing::error!(sandbox = %host, error = %e, "orchestrator bootstrap failed");
        }
    }

    // ------------------------------------------------------- telling

    /// A sandbox (re)connected: its lock state (`lockdown`, or `unlock` so
    /// a missed unlock is not lost: B-3), its held agents, then its keys.
    /// One hook, so the order is fixed.
    async fn on_connect(&self, peer: &Arc<DaemonPeer>) {
        if !is_sandbox(peer) {
            return;
        }
        let told = self.tell_lock.lock().await;
        let facts = async {
            let tx = self.store.begin().await?;
            let locked = flags::locked(&tx, peer.name()).await?;
            let held = lockdown::held_in(&tx, peer.row_id()).await?;
            let grants = store::live_project_grants(&tx, peer.row_id()).await?;
            tx.commit().await?;
            Ok::<_, StoreError>((locked, held, grants))
        }
        .await;
        let (locked, held, grants) = match facts {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(daemon = %peer.principal(), error = %e, "sandbox on_connect failed");
                return;
            }
        };
        let lock = if locked {
            json!({"type": "lockdown", "kill_vm": false})
        } else {
            json!({"type": "unlock"})
        };
        self.hub
            .send_default(Role::Sandbox, peer.name(), &payload(lock))
            .await;
        self.hub
            .send_default(
                Role::Sandbox,
                peer.name(),
                &payload(self.held_message(&held)),
            )
            .await;
        drop(told);
        // The grants it should have (B-7): it revokes any other it holds.
        let ids: Vec<String> = grants.iter().map(ToString::to_string).collect();
        self.hub
            .send_default(
                Role::Sandbox,
                peer.name(),
                &payload(json!({"type": "project.grants", "grants": ids})),
            )
            .await;
        self.greeted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(peer.name().to_owned(), Arc::downgrade(peer));
        self.push_greeted(peer.name(), peer.row_id()).await;
    }

    /// Every agent VM gets its complete held list. Returns
    /// `{"sandbox:<name>": "<n> held" | "not connected; told when it reconnects"}`.
    pub async fn tell(&self) -> Map<String, Value> {
        // One list at a time, numbered in the order it was read: an older
        // list never arrives with a newer number.
        let _told = self.tell_lock.lock().await;
        let lists = async {
            let tx = self.store.begin().await?;
            let mut out = Vec::new();
            for d in daemons::list_role(&tx, DaemonRole::Sandbox).await? {
                let held = lockdown::held_in(&tx, d.id).await?;
                out.push((d.name, held));
            }
            tx.commit().await?;
            Ok::<_, StoreError>(out)
        }
        .await;
        let mut reports = Map::new();
        match lists {
            Ok(lists) => {
                // Every VM at once (each send is bounded): one that stopped
                // reading delays no other. Numbered here, under the lock.
                let sends = lists.into_iter().map(|(name, held)| {
                    let msg = payload(self.held_message(&held));
                    async move {
                        let sent = self.hub.send_default(Role::Sandbox, &name, &msg).await;
                        (name, held.len(), sent)
                    }
                });
                for (name, n, sent) in futures::future::join_all(sends).await {
                    reports.insert(
                        format!("sandbox:{name}"),
                        json!(if sent {
                            format!("{n} held")
                        } else {
                            "not connected; told when it reconnects".to_owned()
                        }),
                    );
                }
            }
            Err(e) => tracing::error!(error = %e, "telling agent VMs their held agents failed"),
        }
        reports
    }

    /// `agents.contained` with the next version.
    fn held_message(&self, held: &[String]) -> Value {
        let seq = self
            .held_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .saturating_add(1);
        json!({"type": "agents.contained", "agents": held, "epoch": self.held_epoch, "version": seq})
    }

    /// The scheduler's step: pending keys go to every connected sandbox.
    pub async fn tick(&self) {
        let rows = async {
            let tx = self.store.begin().await?;
            let rows = daemons::list_role(&tx, DaemonRole::Sandbox).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(rows)
        }
        .await;
        match rows {
            Ok(rows) => {
                for d in rows {
                    self.push(&d.name, d.id).await;
                }
            }
            Err(e) => tracing::error!(error = %e, "sandboxes tick failed"),
        }
    }

    /// The minting and project provisioners, to register.
    #[must_use]
    pub fn provisioners(
        self: &Arc<Self>,
        policy: &agent_auth_core::Policy,
    ) -> Vec<crate::provisioners::AnyProvisioner> {
        let a = &policy.platforms().agents;
        vec![
            crate::provisioners::AnyProvisioner::Agents(agents::AgentsProvisioner {
                sandboxes: Arc::clone(self),
                runtimes: a.runtimes.clone(),
                lease: a.lease,
            }),
            crate::provisioners::AnyProvisioner::Sandbox(project::SandboxProvisioner::new(
                Arc::clone(self),
            )),
        ]
    }

    /// Plug into the spine: the scheduler step and `tell_sandboxes`.
    pub fn install_hooks(self: &Arc<Self>, hooks: &mut crate::service::Hooks) {
        let s = Arc::clone(self);
        hooks.sandboxes_tick = Some(Arc::new(move |_st| {
            let s = Arc::clone(&s);
            Box::pin(async move { s.tick().await })
        }));
        let s = Arc::clone(self);
        hooks.tell_sandboxes = Some(Arc::new(move |_st, _held: Vec<AgentRow>| {
            let s = Arc::clone(&s);
            Box::pin(async move { s.tell().await })
        }));
    }
}
