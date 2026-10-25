//! hostd: what this host is willing to run for the broker, and under which
//! proof (daemons-hostd spec §8-§9).
//!
//! The broker proposes; hostd decides from its own state and config
//! (`agent_auth_core::hostd` makes the decisions; this module holds the
//! state, does the I/O, and journals everything):
//!
//! - local policy (the config file), TOTP secrets generated on this host,
//!   arm state in memory (a restart disarms), lockdown on disk;
//! - every decision is written to the audit journal (target
//!   `agent_auth.hostd.audit`, one JSON object per line) before or as it
//!   takes effect; stdin content never is.
//!
//! What this does NOT protect against (by design, spec §1): a compromised
//! broker can attach a direct TOTP code the human typed to a different
//! command (once per code), and while a tier is armed it can run anything
//! in that tier.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime};

use agent_auth_core::Tier;
use agent_auth_core::hostd::display::{command_extras, display_argv, fit, one_line};
use agent_auth_core::hostd::output::OutputTail;
use agent_auth_core::hostd::totp::{Purpose, SecretName};
use agent_auth_core::hostd::{
    self as core_hostd, ArmProof, ArmState, Authorizations, DeskPrompt, Evidence, HostView,
    LocalCaller, LocalId, LockState, OpenShell, Refused, Source, SpecDigest, TotpApproval,
    UnixMillis,
};
use agent_auth_core::hostexec::{MAX_OUTPUT_BYTES, OUTPUT_CHUNK_BYTES};
use agent_auth_core::lifecycle::DecisionSource;
use agent_auth_crypto::digest::{digest, sha256_hex};
use agent_auth_daemon::channel::{Channel, Handler};
use agent_auth_wire::daemon::channel::{CallId, Incoming, parse};
use agent_auth_wire::daemon::host as wire;
use agent_auth_wire::daemon::host::BrokerToHost;
use base64::Engine as _;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::config::HostConfig;
use crate::executor::{Executor, UnitAction};
use crate::fsutil;
use crate::presence::{Presence, PresenceEvent};
use crate::spool::{Done, Spool};
use crate::totp_store::{TotpError, TotpStore};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Unacknowledged results are resent this often.
pub const RESEND_SECS: u64 = 15;
pub const PROMPT_WHO_MAX: usize = 120;
pub const PROMPT_WHAT_MAX: usize = 600;
pub const PROMPT_DETAIL_MAX: usize = 800;
pub const POLKIT_MESSAGE_MAX: usize = 700;

/// Seconds since the epoch, as a float (the wire's timestamps).
#[must_use]
pub fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[must_use]
pub fn now_millis() -> UnixMillis {
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    UnixMillis(u64::try_from(ms).unwrap_or(u64::MAX))
}

/// One journal line.
pub fn audit(host: &str, event: &str, fields: Value) {
    let mut line = Map::new();
    line.insert("event".into(), json!(event));
    line.insert("host".into(), json!(host));
    if let Value::Object(f) = fields {
        line.extend(f);
    }
    let line = Value::Object(line).to_string();
    tracing::info!(target: "agent_auth.hostd.audit", "{line}");
}

fn source(s: Option<DecisionSource>) -> Option<Source> {
    s.and_then(|s| Source::parse(s.as_str()))
}

#[derive(Debug)]
struct RunningJob {
    shell: Option<LocalId>,
    killed: bool,
    kill: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug)]
struct Helper {
    conn: u64,
    pid: i32,
    tx: mpsc::UnboundedSender<String>,
}

#[derive(Debug, Default)]
struct State {
    arm: ArmState,
    auths: Authorizations,
    jobs: BTreeMap<LocalId, RunningJob>,
    shells: BTreeMap<LocalId, (OpenShell, Option<AbortHandle>)>,
    desk_prompts: BTreeMap<LocalId, DeskPrompt>,
    presence: Presence,
    /// Jobs still running from an earlier hostd (their units), killable.
    orphans: BTreeSet<LocalId>,
    vm_state: Option<String>,
    helper: Option<Helper>,
    stopping: bool,
}

/// The daemon.
pub struct Hostd<E: Executor> {
    pub config: HostConfig,
    executor: E,
    totp: TotpStore,
    spool: Spool,
    state: Mutex<State>,
    channel: OnceLock<Channel>,
    started_at: f64,
    user_uid: OnceLock<Option<u32>>,
    /// Locked down in memory too: holds even if the flag file could not
    /// be written (cleared by an unlock).
    locked: std::sync::atomic::AtomicBool,
    /// Tests move the TOTP clock forward to use more than two codes.
    #[cfg(test)]
    totp_skew: std::sync::atomic::AtomicU64,
    me: Weak<Hostd<E>>,
}

impl<E: Executor> std::fmt::Debug for Hostd<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hostd")
            .field("name", &self.config.name)
            .finish_non_exhaustive()
    }
}

type HandlerResult = Result<Map<String, Value>, String>;

fn data(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn refused(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl<E: Executor> Hostd<E> {
    pub fn new(config: HostConfig, executor: E) -> Arc<Hostd<E>> {
        let mut presence = Presence::default();
        presence.load(&config.runtime_dir.join("presence.json"));
        Arc::new_cyclic(|me| Hostd {
            totp: TotpStore::new(config.totp_dir()),
            spool: Spool::new(&config.state_dir),
            config,
            executor,
            state: Mutex::new(State {
                presence,
                ..State::default()
            }),
            channel: OnceLock::new(),
            started_at: now_f64(),
            user_uid: OnceLock::new(),
            locked: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            totp_skew: std::sync::atomic::AtomicU64::new(0),
            me: me.clone(),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn name(&self) -> &str {
        self.config.name.as_str()
    }

    fn audit(&self, event: &str, fields: Value) {
        audit(self.name(), event, fields);
    }

    #[must_use]
    pub fn executor(&self) -> &E {
        &self.executor
    }

    #[must_use]
    pub fn totp(&self) -> &TotpStore {
        &self.totp
    }

    /// The channel this daemon sends on (set once, before it runs).
    pub fn attach(&self, channel: Channel) {
        let _ = self.channel.set(channel);
    }

    async fn send(&self, msg: Map<String, Value>) -> bool {
        match self.channel.get() {
            Some(c) => c.send(&msg).await,
            None => false,
        }
    }

    fn lockdown_path(&self) -> std::path::PathBuf {
        self.config.state_dir.join("lockdown")
    }

    /// The lockdown file exists (or cannot be checked: fail closed).
    #[must_use]
    pub fn lock_state(&self) -> LockState {
        if self.locked.load(std::sync::atomic::Ordering::SeqCst)
            || fsutil::exists_or_unknown(&self.lockdown_path())
        {
            LockState::Locked
        } else {
            LockState::Unlocked
        }
    }

    /// The time TOTP codes are checked at (Unix seconds).
    #[must_use]
    pub fn totp_now(&self) -> u64 {
        #[cfg(test)]
        {
            now_millis()
                .secs()
                .saturating_add(self.totp_skew.load(std::sync::atomic::Ordering::Relaxed))
        }
        #[cfg(not(test))]
        {
            now_millis().secs()
        }
    }

    /// Pin the configured user's uid when it is known without a lookup
    /// (tests; a host whose account database hostd cannot read).
    pub fn pin_user_uid(&self, uid: Option<u32>) {
        let _ = self.user_uid.set(uid);
    }

    /// The configured user's uid (looked up once).
    pub async fn user_uid(&self) -> Option<u32> {
        if let Some(uid) = self.user_uid.get() {
            return *uid;
        }
        let uid = match &self.config.user {
            Some(name) => crate::executor::passwd::lookup(name)
                .await
                .ok()
                .map(|p| p.uid),
            None => None,
        };
        let _ = self.user_uid.set(uid);
        uid
    }

    // ------------------------------------------------------------ status

    fn away_reason(&self, st: &State) -> Option<String> {
        st.presence.away_reason(
            self.config.desktop.enable,
            self.config.desktop.max_idle_secs,
            now_f64(),
        )
    }

    fn desktop_status(&self, st: &State) -> Map<String, Value> {
        let now = now_f64();
        let away = self.away_reason(st);
        data(json!({
            "enabled": self.config.desktop.enable,
            "present": away.is_none(),
            "away_reason": away,
            "dnd_until": (st.presence.dnd_until > now).then_some(st.presence.dnd_until),
        }))
    }

    /// The heartbeat's status (§8.13), plus each tier's TOTP lock.
    #[must_use]
    pub fn status(&self) -> Map<String, Value> {
        let now = now_millis();
        let st = self.state();
        let mut tiers = Map::new();
        for tier in [Tier::User, Tier::Root] {
            let cfg = self.config.policy.tier(tier);
            let until = st.arm.armed_until(tier);
            let arm = SecretName::new(tier, Purpose::Arm);
            let direct = SecretName::new(tier, Purpose::Direct);
            tiers.insert(
                tier.as_str().into(),
                json!({
                    "enabled": cfg.enable,
                    "armed_until": (until > now).then(|| until.as_secs_f64()),
                    "shell": cfg.shell_enable,
                    "totp": self.totp.enrolled(arm) && self.totp.enrolled(direct),
                    "totp_locked": self.totp.locked(arm, now.secs()) || self.totp.locked(direct, now.secs()),
                }),
            );
        }
        data(json!({
            "version": VERSION,
            "role": "host",
            "started_at": self.started_at,
            "tiers": tiers,
            "jobs": st.jobs.len(),
            "shells": st.shells.len(),
            "lockdown": self.lock_state().is_locked(),
            "vm": self.config.vm_unit.as_ref().map(|u| json!({"unit": u, "state": st.vm_state})),
            "templates": self.config.policy.templates.keys().collect::<Vec<_>>(),
            "desktop": self.desktop_status(&st),
        }))
    }

    // ----------------------------------------------------- the channel

    /// Handle one verified broker message; the reply to send, if it was a
    /// call.
    pub async fn handle(&self, body: Map<String, Value>) -> Option<Map<String, Value>> {
        let call_id = body
            .get("call_id")
            .and_then(Value::as_str)
            .and_then(|s| CallId::parse(s).ok());
        let result = match parse::<BrokerToHost>(body) {
            Incoming::Message(m) => self.dispatch(m).await,
            Incoming::UnknownType(t) => {
                tracing::debug!("ignoring {t:?} from the broker");
                return None;
            }
            Incoming::Malformed { kind, error } => {
                tracing::warn!("malformed {kind:?} from the broker: {error}");
                Err(format!("malformed {kind} message"))
            }
        };
        let call_id = call_id?;
        let mut reply = Map::new();
        reply.insert("type".into(), json!("reply"));
        reply.insert("call_id".into(), json!(call_id.as_str()));
        match result {
            Ok(d) => {
                reply.insert("ok".into(), json!(true));
                reply.insert("data".into(), Value::Object(d));
            }
            Err(e) => {
                reply.insert("ok".into(), json!(false));
                reply.insert("error".into(), json!(e));
            }
        }
        Some(reply)
    }

    async fn dispatch(&self, m: BrokerToHost) -> HandlerResult {
        match m {
            BrokerToHost::Precheck(p) => self.precheck(p),
            BrokerToHost::Authorize(a) => self.authorize(a),
            BrokerToHost::JobStart(s) => self.job_start(s),
            BrokerToHost::JobKill(k) => {
                let id = LocalId::parse(&k.job_id.to_string()).map_err(refused)?;
                Ok(data(json!({"killed": self.kill(&id).await})))
            }
            BrokerToHost::JobAck(a) => {
                if let Ok(id) = LocalId::parse(&a.job_id.to_string()) {
                    self.spool.ack(&id);
                }
                Ok(Map::new())
            }
            BrokerToHost::ShellOpen(o) => self.shell_open(o),
            BrokerToHost::ShellExec(x) => self.shell_exec(x),
            BrokerToHost::ShellClose(c) => {
                let id = LocalId::parse(&c.shell_id.to_string()).map_err(refused)?;
                Ok(data(
                    json!({"closed": self.end_shell(&id, "closed by the broker").await}),
                ))
            }
            BrokerToHost::Arm(a) => self.arm_remote(a),
            BrokerToHost::Disarm(d) => {
                self.disarm(d.tier.map(Tier::from), "the broker");
                Ok(data(json!({"disarmed": true})))
            }
            BrokerToHost::Lockdown(l) => self.lockdown("the broker", l.kill_vm).await,
            BrokerToHost::Unlock(u) => {
                let code = self.verify(
                    SecretName::new(Tier::Root, Purpose::Arm),
                    u.totp.expose(),
                    None,
                )?;
                ArmState::check_unlock(&ArmProof::Totp(code)).map_err(refused)?;
                self.unlock("root arm code via the broker").await
            }
            BrokerToHost::Dnd(d) => {
                let secs = d.duration.map_or(0, |d| d.secs());
                Ok(data(json!({"dnd_until": self.set_dnd(secs)})))
            }
            BrokerToHost::Prompt(p) => self.prompt(p).await,
            BrokerToHost::PromptCancel(c) => {
                let id = LocalId::parse(&c.prompt_id.to_string()).map_err(refused)?;
                let tx = {
                    let mut st = self.state();
                    st.desk_prompts.remove(&id);
                    st.helper.as_ref().map(|h| h.tx.clone())
                };
                if let Some(tx) = tx {
                    let _ = tx.send(json!({"type": "cancel", "id": id.as_str()}).to_string());
                }
                Ok(Map::new())
            }
            BrokerToHost::Notify(n) => self.notify(n),
        }
    }

    fn view<'a>(&'a self, arm: &'a ArmState) -> HostView<'a> {
        HostView {
            policy: &self.config.policy,
            arm,
            lock: self.lock_state(),
            now: now_millis(),
        }
    }

    // ------------------------------------------------------- decisions

    fn precheck(&self, p: wire::Precheck) -> HandlerResult {
        match p {
            wire::Precheck::Shell(s) => {
                let tier = json!(Tier::from(s.tier).as_str());
                core_hostd::precheck_shell(
                    &self.config.policy,
                    Some(&tier),
                    Some(&json!(s.duration)),
                    self.lock_state(),
                )
                .map_err(refused)?;
                Ok(data(json!({"needs": "totp"})))
            }
            wire::Precheck::Job(j) => {
                let raw = Value::Object(j.spec.into_map());
                let d = spec_digest(&raw)?;
                let job_id = j.job_id.map(|i| i.to_string());
                let st = self.state();
                let via = core_hostd::precheck_job(
                    self.view(&st.arm),
                    &raw,
                    &d,
                    j.totp,
                    job_id.as_deref(),
                    Evidence {
                        source: source(j.source),
                        window: j.window,
                    },
                    &st.auths,
                )
                .map_err(refused)?;
                Ok(data(json!({"via": via.as_str()})))
            }
        }
    }

    /// Verify a code for `name` (the per-secret lock and the lockouts are
    /// the store's). `job`: for the journal.
    fn verify(
        &self,
        name: SecretName,
        code: &str,
        job: Option<&LocalId>,
    ) -> Result<agent_auth_core::hostd::totp::AcceptedCode, String> {
        match self.totp.verify(name, code, self.totp_now()) {
            Ok(c) => Ok(c),
            Err(e) => {
                self.audit(
                    "totp.refused",
                    json!({"secret": name.as_str(), "job": job.map(LocalId::as_str), "why": e.to_string()}),
                );
                if matches!(
                    e,
                    TotpError::Refused(
                        agent_auth_core::hostd::totp::TotpRefusal::HardLocked { .. }
                    )
                ) {
                    tracing::error!(secret = %name, "TOTP secret hard-locked after repeated wrong codes");
                }
                Err(e.to_string())
            }
        }
    }

    fn authorize(&self, a: wire::Authorize) -> HandlerResult {
        let job = LocalId::parse(&a.job_id.to_string()).map_err(refused)?;
        let tier = Tier::from(a.tier);
        let tier = core_hostd::check_tier(&self.config.policy, Some(&json!(tier.as_str())))
            .map_err(refused)?;
        let d = SpecDigest::parse(a.digest.as_str()).map_err(refused)?;
        if self.lock_state().is_locked() {
            return Err(format!("{} is locked down", self.name()));
        }
        let code = self.verify(
            SecretName::new(tier, Purpose::Direct),
            a.totp.expose(),
            Some(&job),
        )?;
        let approval = TotpApproval::new(code, d.clone()).map_err(refused)?;
        let mut st = self.state();
        // A lockdown that landed while the code was checked wins.
        if self.lock_state().is_locked() {
            return Err(format!("{} is locked down", self.name()));
        }
        st.auths.record_totp(job.clone(), approval, now_millis());
        drop(st);
        self.audit(
            "totp.accepted",
            json!({"job": job.as_str(), "tier": tier.as_str(), "digest": d.as_str()}),
        );
        Ok(data(json!({"authorized": true})))
    }

    fn already_ran(&self, st: &State, id: &LocalId) -> bool {
        st.jobs.contains_key(id) || st.orphans.contains(id) || self.spool.exists(id)
    }

    fn job_start(&self, s: wire::JobStart) -> HandlerResult {
        let id = LocalId::parse(&s.job_id.to_string()).map_err(refused)?;
        let raw = Value::Object(s.spec.into_map());
        let evidence = json!({
            "request_id": s.evidence.request_id.to_string(),
            "decided_by": s.evidence.decided_by.as_ref().map(|d| d.as_str()),
            "source": s.evidence.source.map(DecisionSource::as_str),
            "window": s.evidence.window,
        });
        let mut guard = self.state();
        let st: &mut State = &mut guard;
        if self.already_ran(st, &id) {
            return Err("that job already ran here".to_owned());
        }
        let admitted = spec_digest(&raw).and_then(|d| {
            let job = core_hostd::normalize(&self.config.policy, &raw, false).map_err(refused)?;
            core_hostd::admit(
                self.view(&st.arm),
                id.clone(),
                job,
                &d,
                Evidence {
                    source: source(s.evidence.source),
                    window: s.evidence.window,
                },
                &mut st.auths,
            )
            .map_err(refused)
        });
        let job = match admitted {
            Ok(j) => j,
            Err(why) => {
                drop(guard);
                self.audit(
                    "job.refused",
                    json!({"job": id.as_str(), "why": why, "evidence": evidence,
                           "spec": core_hostd::loggable(&raw, None)}),
                );
                return Err(why);
            }
        };
        let via = job.via();
        self.audit(
            "job.admitted",
            json!({"job": id.as_str(), "via": via.as_str(), "evidence": evidence, "spec": job.loggable()}),
        );
        self.launch(st, job)?;
        Ok(data(json!({"started": true, "via": via.as_str()})))
    }

    /// Spool, register and start an admitted job (under the state lock, so
    /// a lockdown sees it).
    fn launch(&self, st: &mut State, job: core_hostd::AdmittedJob) -> Result<(), String> {
        let id = job.id().clone();
        self.spool
            .write_running(&id, job.tier(), now_f64())
            .map_err(|e| format!("hostd error: could not spool the job: {e}"))?;
        let (kill, kill_rx) = tokio::sync::watch::channel(false);
        st.jobs.insert(
            id,
            RunningJob {
                shell: job.shell().cloned(),
                killed: false,
                kill,
            },
        );
        let me = self.me.clone();
        tokio::spawn(async move {
            if let Some(me) = me.upgrade() {
                me.run_job(job, kill_rx).await;
            }
        });
        Ok(())
    }

    async fn run_job(
        self: Arc<Self>,
        job: core_hostd::AdmittedJob,
        kill: tokio::sync::watch::Receiver<bool>,
    ) {
        let started = Instant::now();
        let mut tail = OutputTail::new(MAX_OUTPUT_BYTES);
        let outcome = self.executor.run(&job, &mut tail, kill).await;
        let id = job.id().clone();
        let (killed, stopping) = {
            let st = self.state();
            (st.jobs.get(&id).is_some_and(|j| j.killed), st.stopping)
        };
        let (exit_code, mut error) = match outcome {
            Ok(code) => (Some(code), None),
            Err(e) => (None, Some(format!("could not run: {e}"))),
        };
        if stopping {
            error = Some("hostd stopped while the job was running".to_owned());
        } else if killed {
            error = Some("killed".to_owned());
        }
        let kept = tail.finish();
        let secs = (started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0;
        let result = data(json!({
            "job_id": id.as_str(),
            "exit_code": exit_code,
            "error": error,
            "duration_secs": secs,
            "bytes": kept.bytes.len(),
            "sha256": sha256_hex(&kept.bytes),
            "truncated": kept.truncated,
        }));
        let mut journal = result.clone();
        journal.remove("job_id");
        journal.insert("job".into(), json!(id.as_str()));
        journal.insert("produced".into(), json!(kept.produced));
        self.audit("job.done", Value::Object(journal));
        let done = Done {
            result,
            output: kept.bytes,
        };
        if let Err(e) = self.spool.write_done(&id, &done, now_f64()) {
            tracing::error!(job = %id, error = %e, "could not spool a result");
        }
        self.state().jobs.remove(&id);
        self.send_result(&id).await;
    }

    /// Send a spooled result: its output in chunks, then `job.done`. False
    /// if anything failed (it is resent later).
    pub async fn send_result(&self, id: &LocalId) -> bool {
        let Some(done) = self.spool.done(id) else {
            return false;
        };
        for (i, chunk) in done.output.chunks(OUTPUT_CHUNK_BYTES).enumerate() {
            let msg = data(json!({
                "type": "job.output",
                "job_id": id.as_str(),
                "chunk": i,
                "data": base64::engine::general_purpose::STANDARD.encode(chunk),
            }));
            if !self.send(msg).await {
                return false;
            }
        }
        let mut msg = done.result;
        msg.insert("type".into(), json!("job.done"));
        self.send(msg).await
    }

    /// Kill a running job (or one left from an earlier hostd).
    pub async fn kill(&self, id: &LocalId) -> bool {
        let running = {
            let mut st = self.state();
            if let Some(job) = st.jobs.get_mut(id) {
                job.killed = true;
                job.kill.send_replace(true);
                Some(true)
            } else if st.orphans.remove(id) {
                Some(false)
            } else {
                None
            }
        };
        let Some(running) = running else {
            return false;
        };
        self.audit("job.kill", json!({"job": id.as_str()}));
        if !running {
            // Left by an earlier hostd: only its unit knows it.
            self.executor.kill(id).await;
        }
        true
    }

    // ----------------------------------------------------------- shells

    fn shell_open(&self, o: wire::ShellOpen) -> HandlerResult {
        let id = LocalId::parse(&o.shell_id.to_string()).map_err(refused)?;
        let raw = Value::Object(o.spec.into_map());
        let spec = core_hostd::parse_shell_request(&self.config.policy, &raw).map_err(refused)?;
        let d = spec_digest(&spec.to_json())?;
        let mut st = self.state();
        let opened = core_hostd::open_shell(
            &self.config.policy,
            id.clone(),
            &spec,
            &d,
            &mut st.auths,
            self.lock_state(),
            now_millis(),
        );
        let shell = match opened {
            Ok(s) => s,
            Err(e) => {
                drop(st);
                self.audit(
                    "shell.refused",
                    json!({"shell": id.as_str(), "tier": spec.tier().as_str(), "why": e.0}),
                );
                return Err(e.0);
            }
        };
        let expires = shell.expires_at();
        // The expiry is kept here: the broker can end a shell, never extend it.
        let me = self.me.clone();
        let sid = id.clone();
        let duration = u64::from(spec.duration());
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(duration)).await;
            if let Some(me) = me.upgrade() {
                me.end_shell(&sid, "expired").await;
            }
        });
        st.shells
            .insert(id.clone(), (shell, Some(timer.abort_handle())));
        drop(st);
        self.audit(
            "shell.open",
            json!({"shell": id.as_str(), "tier": spec.tier().as_str(), "expires_at": expires.as_secs_f64()}),
        );
        Ok(data(json!({"expires_at": expires.as_secs_f64()})))
    }

    fn shell_exec(&self, x: wire::ShellExec) -> HandlerResult {
        let shell_id = LocalId::parse(&x.shell_id.to_string()).map_err(refused)?;
        let id = LocalId::parse(&x.job_id.to_string()).map_err(refused)?;
        let raw = Value::Object(x.spec.into_map());
        let mut st = self.state();
        if self.already_ran(&st, &id) {
            return Err("that job already ran here".to_owned());
        }
        let admitted = core_hostd::admit_shell_command(
            &self.config.policy,
            st.shells.get(&shell_id).map(|s| &s.0),
            id.clone(),
            &raw,
            self.lock_state(),
            now_millis(),
        );
        let job = match admitted {
            Ok(j) => j,
            Err(e) => {
                drop(st);
                self.audit(
                    "shell.exec.refused",
                    json!({"shell": shell_id.as_str(), "job": id.as_str(), "why": e.0,
                           "spec": core_hostd::loggable(&raw, None)}),
                );
                return Err(e.0);
            }
        };
        // Journaled before it runs.
        self.audit(
            "shell.exec",
            json!({"shell": shell_id.as_str(), "job": id.as_str(), "spec": job.loggable()}),
        );
        self.launch(&mut st, job)?;
        Ok(data(json!({"started": true})))
    }

    /// End a shell: its timer, and every command still running in it.
    pub async fn end_shell(&self, id: &LocalId, why: &str) -> bool {
        let (removed, jobs) = {
            let mut st = self.state();
            let removed = st.shells.remove(id);
            let jobs: Vec<LocalId> = st
                .jobs
                .iter()
                .filter(|(_, j)| j.shell.as_ref() == Some(id))
                .map(|(k, _)| k.clone())
                .collect();
            (removed, jobs)
        };
        let Some((_, timer)) = removed else {
            return false;
        };
        if why != "expired"
            && let Some(t) = timer
        {
            t.abort();
        }
        for job in jobs {
            self.kill(&job).await;
        }
        self.audit("shell.close", json!({"shell": id.as_str(), "why": why}));
        true
    }

    // ----------------------------------------------------------- arming

    fn arm_remote(&self, a: wire::Arm) -> HandlerResult {
        let tier = Tier::from(a.tier);
        // Everything that would refuse the arming, before the code is spent
        // (daemons bug 8).
        ArmState::check_can_arm(&self.config.policy, tier, self.lock_state()).map_err(refused)?;
        let secs = a.duration.secs();
        let code = self.verify(SecretName::new(tier, Purpose::Arm), a.totp.expose(), None)?;
        let until = self.arm(tier, secs, ArmProof::Totp(code), "totp via the broker")?;
        Ok(data(json!({"armed_until": until.as_secs_f64()})))
    }

    /// Arm a tier on `proof` (capped at its max_arm).
    pub fn arm(
        &self,
        tier: Tier,
        secs: u64,
        proof: ArmProof,
        via: &str,
    ) -> Result<UnixMillis, String> {
        let now = now_millis();
        let lock = self.lock_state();
        let until = self
            .state()
            .arm
            .arm(&self.config.policy, tier, secs, proof, lock, now)
            .map_err(refused)?;
        let granted = until.0.saturating_sub(now.0) / 1000;
        self.audit(
            "arm",
            json!({"tier": tier.as_str(), "seconds": granted, "via": via}),
        );
        Ok(until)
    }

    pub fn disarm(&self, tier: Option<Tier>, via: &str) {
        self.state().arm.disarm(tier);
        self.audit(
            "disarm",
            json!({"tier": tier.map_or("all", Tier::as_str), "via": via}),
        );
    }

    // --------------------------------------------------- the kill switch

    /// Refuse everything from now on (the flag is on disk first), disarm,
    /// drop every approval and desk prompt, end every shell, kill every job
    /// (also those left from an earlier hostd), and freeze or stop the VM.
    pub async fn lockdown(&self, via: &str, kill_vm: bool) -> HandlerResult {
        // The flag first; whatever happens to it, everything below still
        // runs (stopping things never waits on the disk).
        self.locked.store(true, std::sync::atomic::Ordering::SeqCst);
        let flag = fsutil::private_dir(&self.config.state_dir, 0o700)
            .and_then(|()| {
                fsutil::write_atomic(
                    &self.lockdown_path(),
                    json!({"at": now_f64(), "via": via}).to_string().as_bytes(),
                    0o600,
                )
            })
            .map_err(|e| format!("hostd error: could not write the lockdown flag: {e}"));
        let (shells, jobs, orphans) = {
            let mut st = self.state();
            st.arm.disarm(None);
            st.auths.clear();
            st.desk_prompts.clear();
            let shells: Vec<LocalId> = st.shells.keys().cloned().collect();
            let jobs: Vec<LocalId> = st.jobs.keys().cloned().collect();
            let orphans: Vec<LocalId> = st.orphans.iter().cloned().collect();
            (shells, jobs, orphans)
        };
        self.audit(
            "disarm",
            json!({"tier": "all", "via": format!("lockdown ({via})")}),
        );
        for shell in &shells {
            self.end_shell(shell, "lockdown").await;
        }
        // In parallel: one slow kill must not hold up the others (bug 17).
        let kills = jobs.iter().chain(orphans.iter()).map(|j| self.kill(j));
        futures::future::join_all(kills).await;
        let mut vm = None;
        if let Some(unit) = &self.config.vm_unit {
            // From outside: nothing inside the guest is asked to cooperate.
            let action = if kill_vm {
                UnitAction::Stop
            } else {
                UnitAction::Freeze
            };
            vm = Some(self.unit_report(action, unit).await);
        }
        self.audit(
            "lockdown",
            json!({"via": via, "vm": vm, "flag_written": flag.is_ok()}),
        );
        flag?;
        Ok(data(json!({"locked": true, "vm": vm})))
    }

    async fn unit_report(&self, action: UnitAction, unit: &str) -> String {
        match self.executor.unit_action(action, unit).await {
            Ok((0, _)) => format!("{}: ok", action.as_str()),
            Ok((code, out)) if out.is_empty() => format!("{}: {code}", action.as_str()),
            Ok((_, out)) => format!("{}: {out}", action.as_str()),
            Err(e) => format!("{}: {e}", action.as_str()),
        }
    }

    /// Lift this host's lockdown (the caller checked the proof). Unlocking
    /// does not arm.
    pub async fn unlock(&self, via: &str) -> HandlerResult {
        fsutil::remove_durably(&self.lockdown_path())
            .map_err(|e| format!("hostd error: could not remove the lockdown flag: {e}"))?;
        self.locked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let mut vm = None;
        if let Some(unit) = &self.config.vm_unit {
            vm = Some(self.unit_report(UnitAction::Thaw, unit).await);
        }
        self.audit("unlock", json!({"via": via, "vm": vm}));
        Ok(data(json!({"locked": false, "vm": vm})))
    }

    // ---------------------------------------------------------- desktop

    /// Do-not-disturb for `secs` (0: off). Returns `dnd_until` or null.
    pub fn set_dnd(&self, secs: u64) -> Option<f64> {
        let mut st = self.state();
        st.presence.dnd_until = if secs == 0 {
            0.0
        } else {
            now_f64() + f64::from(u32::try_from(secs).unwrap_or(u32::MAX))
        };
        (st.presence.dnd_until > 0.0).then_some(st.presence.dnd_until)
    }

    /// Tell the broker the desktop part of the status.
    pub async fn presence_changed(&self) {
        let mut msg = {
            let st = self.state();
            self.desktop_status(&st)
        };
        msg.insert("type".into(), json!("presence"));
        self.send(msg).await;
    }

    /// A `presence` event from hostctl.
    pub fn presence_event(&self, event: PresenceEvent) -> bool {
        let mut st = self.state();
        st.presence.apply(event, now_f64());
        st.presence
            .save(&self.config.runtime_dir.join("presence.json"));
        self.away_reason(&st).is_none()
    }

    fn present(&self) -> bool {
        self.away_reason(&self.state()).is_none()
    }

    fn to_helper(&self, msg: &Value) -> bool {
        let st = self.state();
        st.helper
            .as_ref()
            .is_some_and(|h| h.tx.send(msg.to_string()).is_ok())
    }

    async fn prompt(&self, p: wire::Prompt) -> HandlerResult {
        let prompt_id = LocalId::parse(&p.prompt_id.to_string()).map_err(refused)?;
        if !self.present() {
            return Err("nobody is at this desktop".to_owned());
        }
        let who_raw = if p.who.as_str().is_empty() {
            "an agent"
        } else {
            p.who.as_str()
        };
        let who = one_line(who_raw, PROMPT_WHO_MAX);
        let mut what = one_line(p.what.as_str(), PROMPT_WHAT_MAX);
        let mut detail = one_line(p.detail.as_str(), PROMPT_DETAIL_MAX);
        if let Some(job) = &p.job {
            // What will run comes from this host, not from the broker's text.
            let (w, extra) = self.desk_job(&prompt_id, job, &who)?;
            what = w;
            detail = [extra, detail]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
        }
        let timeout = p
            .timeout
            .min(u32::try_from(self.config.desktop.prompt_timeout_secs).unwrap_or(u32::MAX));
        let timeout = if timeout == 0 {
            90.min(self.config.desktop.prompt_timeout_secs)
        } else {
            u64::from(timeout)
        };
        let shown = self.to_helper(&json!({
            "type": "prompt", "id": prompt_id.as_str(), "who": who, "what": what,
            "detail": detail, "timeout": timeout,
        }));
        if !shown {
            self.state().desk_prompts.remove(&prompt_id);
            return Err("nobody is at this desktop".to_owned());
        }
        self.audit(
            "prompt.shown",
            json!({"prompt": prompt_id.as_str(), "request": p.request_id.to_string()}),
        );
        let approves = self.state().desk_prompts.contains_key(&prompt_id);
        Ok(data(json!({"shown": true, "approves": approves})))
    }

    /// A prompt about a command on this host: (what, extra detail) from
    /// what this host would run, the whole of it or a notice that it was
    /// cut with the digest it approves (daemons bug 5). Registers a desk
    /// prompt when Allow here approves it.
    fn desk_job(
        &self,
        prompt_id: &LocalId,
        job: &wire::DeskJob,
        who: &str,
    ) -> Result<(String, String), String> {
        let job_id = LocalId::parse(&job.job_id.to_string()).map_err(refused)?;
        let raw = Value::Object(job.spec.as_map().clone());
        let d = spec_digest(&raw)?;
        let normalized =
            core_hostd::normalize(&self.config.policy, &raw, false).map_err(refused)?;
        let tier = normalized.tier();
        let as_whom = match tier {
            Tier::Root => "ROOT".to_owned(),
            Tier::User => self
                .config
                .user
                .clone()
                .unwrap_or_else(|| "your user".to_owned()),
        };
        let spec = normalized.spec();
        let env: BTreeMap<String, String> = spec
            .env()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
            .collect();
        let full_what = format!(
            "run on {} as {as_whom}: {}",
            self.name(),
            display_argv(normalized.argv())
        );
        let extras = command_extras(spec.cwd(), &env, spec.stdin()).join(" · ");
        let what = fit(&full_what, PROMPT_WHAT_MAX, d.as_str());
        let extra = fit(&extras, PROMPT_DETAIL_MAX, d.as_str());
        let message = fit(
            &format!("{who} asks to {full_what} {extras}"),
            POLKIT_MESSAGE_MAX,
            d.as_str(),
        );
        let mut guard = self.state();
        let st: &mut State = &mut guard;
        let prompt = core_hostd::desk_prompt(self.view(&st.arm), job_id, d, &normalized, message)
            .map_err(refused)?;
        if let Some(prompt) = prompt {
            st.desk_prompts.insert(prompt_id.clone(), prompt);
        }
        Ok((what, extra))
    }

    fn notify(&self, n: wire::Notify) -> HandlerResult {
        if !self.present() {
            return Err("nobody is at this desktop".to_owned());
        }
        let title = if n.title.as_str().is_empty() {
            "agent-auth"
        } else {
            n.title.as_str()
        };
        let urgency = match n.urgency {
            wire::Urgency::Low => "low",
            wire::Urgency::Normal => "normal",
            wire::Urgency::Critical => "critical",
        };
        let shown = self.to_helper(&json!({
            "type": "notify", "title": one_line(title, 120),
            "text": one_line(n.text.as_str(), 600), "urgency": urgency,
        }));
        if !shown {
            return Err("nobody is at this desktop".to_owned());
        }
        Ok(data(json!({"shown": true})))
    }

    /// hostd-user attached (its uid was checked): it replaces any earlier
    /// helper connection. Returns the connection's id and its outbox.
    pub async fn helper_attached(&self, conn: u64, pid: i32) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut st = self.state();
            st.helper = Some(Helper { conn, pid, tx });
            st.presence.connected = true;
        }
        self.presence_changed().await;
        rx
    }

    /// Is `conn` the current helper connection?
    #[must_use]
    pub fn helper_is(&self, conn: u64) -> bool {
        self.state().helper.as_ref().is_some_and(|h| h.conn == conn)
    }

    pub async fn helper_detached(&self, conn: u64) {
        let was = {
            let mut st = self.state();
            if st.helper.as_ref().is_some_and(|h| h.conn == conn) {
                st.helper = None;
                st.presence.connected = false;
                true
            } else {
                false
            }
        };
        if was {
            self.presence_changed().await;
        }
    }

    /// A presence report from hostd-user.
    pub async fn helper_presence(&self, msg: &Map<String, Value>) {
        let changed = {
            let mut st = self.state();
            let was = self.away_reason(&st).is_none();
            let p = &mut st.presence;
            p.idle_secs = msg
                .get("idle_secs")
                .and_then(Value::as_f64)
                .filter(|f| f.is_finite() && *f >= 0.0);
            p.locked = msg.get("locked").and_then(Value::as_bool);
            p.fullscreen = msg
                .get("fullscreen")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            p.reported_at = now_f64();
            let fresh = msg.get("fresh").and_then(Value::as_bool).unwrap_or(false);
            if fresh
                && self.config.desktop.idle_source == crate::config::IdleSource::Hooks
                && p.explicit_idle.is_none()
                && p.explicit_locked.is_none()
            {
                // The helper just started with the session and no hook said
                // otherwise yet: you just logged in.
                p.apply(PresenceEvent::Unlocked, now_f64());
                p.save(&self.config.runtime_dir.join("presence.json"));
            }
            was != self.away_reason(&st).is_none()
        };
        if changed {
            self.presence_changed().await;
        }
    }

    /// The desk answered a prompt (over connection `conn`). For a command
    /// on this host, Allow is this host's own approval of exactly what it
    /// showed (with the user's password, for root).
    pub async fn answered(&self, prompt: &str, answer: &str, conn: u64) {
        let mut answer = match answer {
            "allow" | "deny" | "mute" | "discord" | "timeout" => answer.to_owned(),
            _ => "timeout".to_owned(),
        };
        let Ok(prompt_id) = LocalId::parse(prompt) else {
            return;
        };
        let (desk, current, pid) = {
            let mut st = self.state();
            let desk = st.desk_prompts.remove(&prompt_id);
            let current = st.helper.as_ref().filter(|h| h.conn == conn);
            (desk, current.is_some(), current.map_or(0, |h| h.pid))
        };
        let mut authorized = false;
        if let Some(desk) = desk
            && answer == "allow"
        {
            let mut polkit = None;
            if desk.tier() == Tier::Root && current && !self.lock_state().is_locked() {
                let uid = self.user_uid().await.unwrap_or(u32::MAX);
                polkit = self
                    .executor
                    .polkit_auth(
                        pid,
                        uid,
                        desk.message(),
                        Duration::from_secs(self.config.desktop.prompt_timeout_secs),
                    )
                    .await;
            }
            let job = desk.job().clone();
            let tier = desk.tier();
            // Still the current helper and still unlocked, after the password.
            let still_current = self.state().helper.as_ref().is_some_and(|h| h.conn == conn);
            match core_hostd::desk_approval(desk, still_current, self.lock_state(), polkit) {
                Ok((job, approval)) => {
                    self.state()
                        .auths
                        .record_desk(job.clone(), approval, now_millis());
                    authorized = true;
                    self.audit(
                        "desk.accepted",
                        json!({"job": job.as_str(), "tier": tier.as_str()}),
                    );
                }
                Err(_) => {
                    // No password, or things changed meanwhile: not a
                    // denial; the request stays where it was (Discord).
                    answer = "discord".to_owned();
                    self.audit(
                        "desk.refused",
                        json!({"job": job.as_str(), "tier": tier.as_str()}),
                    );
                }
            }
        }
        self.audit(
            "prompt.answer",
            json!({"prompt": prompt_id.as_str(), "answer": answer}),
        );
        self.send(data(json!({
            "type": "prompt.answer", "prompt_id": prompt_id.as_str(),
            "answer": answer, "authorized": authorized,
        })))
        .await;
    }

    // ------------------------------------------------------- lifecycle

    /// Startup: report jobs that were running when hostd last stopped as
    /// lost, and keep track of those whose units still run.
    pub async fn recover(&self) {
        let lost = self.spool.recover(now_f64());
        for id in &lost {
            self.audit("job.lost", json!({"job": id.as_str()}));
        }
        let leftover = self.executor.running_jobs().await;
        if !leftover.is_empty() {
            tracing::warn!(
                count = leftover.len(),
                "jobs from an earlier hostd are still running"
            );
        }
        let mut st = self.state();
        st.orphans.extend(leftover);
    }

    /// Unacknowledged results, again: after a reconnect and every 15 s.
    pub async fn resend_loop(&self) {
        let Some(channel) = self.channel.get() else {
            return;
        };
        let mut connected = channel.connected();
        loop {
            if !*connected.borrow_and_update() {
                if connected.changed().await.is_err() {
                    return;
                }
                continue;
            }
            for (id, age) in self.spool.list() {
                let running = self.state().jobs.contains_key(&id);
                if !running && age >= f64::from(u32::try_from(RESEND_SECS).unwrap_or(15)) {
                    self.send_result(&id).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(RESEND_SECS)).await;
        }
    }

    /// The VM unit's state, every 30 s.
    pub async fn watch_vm(&self) {
        let Some(unit) = self.config.vm_unit.clone() else {
            return;
        };
        loop {
            let state = match self.executor.unit_action(UnitAction::IsActive, &unit).await {
                Ok((code, out)) => out.lines().next().map(str::to_owned).unwrap_or_else(|| {
                    if code == 0 {
                        "active".into()
                    } else {
                        "unknown".into()
                    }
                }),
                Err(_) => "unknown".into(),
            };
            let locked = self.lock_state().is_locked();
            self.state().vm_state = Some(if locked && state == "active" {
                "frozen".to_owned()
            } else {
                state
            });
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    /// Stopping (SIGTERM): kill what runs; its results say hostd stopped.
    pub async fn shutdown(&self) {
        {
            let mut st = self.state();
            st.stopping = true;
            for job in st.jobs.values() {
                job.kill.send_replace(true);
            }
        }
        let until = crate::executor::after(Duration::from_secs(10));
        while tokio::time::Instant::now() < until && !self.state().jobs.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Local arming over hostctl (no TOTP: someone at the host).
    pub fn arm_local(
        &self,
        tier: Tier,
        secs: u64,
        caller: LocalCaller,
        uid: u32,
    ) -> Result<UnixMillis, String> {
        self.arm(
            tier,
            secs,
            ArmProof::Local(caller),
            &format!("local uid {uid}"),
        )
    }

    /// Whether `uid` is the configured desktop/user-tier account.
    pub async fn is_user(&self, uid: u32) -> bool {
        self.user_uid().await == Some(uid)
    }

    /// Number of running jobs (tests, status).
    #[must_use]
    pub fn running(&self) -> usize {
        self.state().jobs.len()
    }

    /// Ids of jobs left running by an earlier hostd.
    #[must_use]
    pub fn orphans(&self) -> Vec<LocalId> {
        self.state().orphans.iter().cloned().collect()
    }
}

/// `digest(spec)` over the spec exactly as received.
fn spec_digest(raw: &Value) -> Result<SpecDigest, String> {
    let d = digest(raw).map_err(|_| "malformed job".to_owned())?;
    SpecDigest::parse(&d).map_err(refused)
}

impl<E: Executor> Handler for Hostd<E> {
    fn status(&self) -> Map<String, Value> {
        Hostd::status(self)
    }

    async fn on_message(&self, body: Map<String, Value>) {
        if let Some(reply) = self.handle(body).await {
            self.send(reply).await;
        }
    }
}

/// Refused → its text (for the local API).
#[must_use]
pub fn refusal_text(r: &Refused) -> String {
    r.0.clone()
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
