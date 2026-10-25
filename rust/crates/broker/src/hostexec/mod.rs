//! Commands on hosts, as seen from the broker (daemons-hostd spec §9-§10).
//!
//! The broker's part is bookkeeping and relaying: it validates and records
//! what was asked, carries the human's decision (and TOTP code) to the
//! host's hostd, keeps the job's result, and mirrors shells to the
//! operator. Whether anything runs is decided on the host — a `run` the
//! broker approved still fails if the host isn't armed and no code came
//! with it.
//!
//! - A `run` / `tpl.<name>` grant is ONE execution: provisioning it starts
//!   the job (id = the request's id); its result is kept in `host_jobs`.
//! - A `shell` grant is a window in which the agent runs commands; each is
//!   its own job, shown to the operator ([`crate::notify::Notify::shell_command`])
//!   before it is sent, and not sent if that fails.
//! - Lockdown revokes grants here and tells every hostd (and sandboxd) to
//!   stop; hosts stay locked until unlocked with their own code or locally.
//!
//! Public service functions (also for the Discord follow-up: TOTP modal,
//! arm buttons, `/hosts`): [`HostExec::approval_gate`], [`HostExec::arm`],
//! [`HostExec::disarm`], [`HostExec::open_window`], [`HostExec::hosts`],
//! [`lockdown::lockdown`], [`lockdown::unlock`], [`HostExec::shell_exec`],
//! [`HostExec::get_job`], [`scheduler_tick`].

mod gate;
pub mod lockdown;
pub mod provisioner;
mod results;
mod routes;
#[cfg(test)]
mod shell_mode_tests;
mod shells;
#[cfg(test)]
mod tests;
pub mod watcher;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use agent_auth_core::authority::{CommandOptions, HostexecAuthority, Tier};
use agent_auth_core::hostexec::{Command, CommandSpec};
use agent_auth_core::policy::Policy;
use agent_auth_core::pyfmt::{escape_unprintable, repr, shlex_join};
use agent_auth_core::{Authority, DecisionSource, JobId, RequestId, RuleId};
use agent_auth_crypto::daemon::Role;
use agent_auth_store::daemons::{self, DaemonRole};
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::requests::RequestRow;
use agent_auth_store::{Store, StoreError, Tx, flags};
use agent_auth_wire::admin::HostOut;
use agent_auth_wire::common::TierName;
use agent_auth_wire::daemon::host::{DesktopStatus, HostStatus, TierStatus, VmStatus};
use agent_auth_wire::hostexec::{JobCommand, JobOut, JobStatus as WireJobStatus};
use futures::future::BoxFuture;
use serde_json::{Map, Value, json};

pub use gate::{GateRefusal, HUMAN_MAX_DURATION_SECS, approval_gate_hook};
pub use routes::routes;
pub use shells::ShellExecError;

use crate::daemons::{CallError, DaemonHub};
use crate::events::KeyedEvents;
use crate::notify::Notifier;
use crate::provisioners::{Refused, Validated};

/// Calls to a host wait this long.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(20);
/// A kill or a shell close.
pub const SHORT_CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// `job.kill` again this often until the host answers.
pub const KILL_RETRY: Duration = Duration::from_secs(2);
/// A sandbox gets this long to lock itself before its host freezes the VM.
pub const SANDBOX_LOCKDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Output arrives in chunks; a job's buffer is dropped past this.
pub const MAX_BUFFER_BYTES: usize =
    agent_auth_core::hostexec::MAX_OUTPUT_BYTES + agent_auth_core::hostexec::OUTPUT_CHUNK_BYTES;
pub const TAIL_LINES: usize = 30;
/// A job still without a result this long after its timeout is `lost`.
pub const LOST_GRACE_SECS: i64 = 3600;

/// The host said no, or couldn't be asked. The text is for a human.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HostExecError(pub String);

impl From<CallError> for HostExecError {
    fn from(e: CallError) -> Self {
        HostExecError(e.message)
    }
}

/// The hostexec part's state.
pub struct HostExec {
    pub(crate) hub: Arc<DaemonHub>,
    pub(crate) store: Store,
    pub(crate) policy: Arc<Policy>,
    /// Wakes `GET /v1/hostexec/jobs/{id}?wait=` when a job ends.
    pub(crate) job_events: Arc<KeyedEvents<JobId>>,
    buffers: Mutex<HashMap<(String, JobId), Vec<u8>>>,
    st: OnceLock<crate::state::AppState>,
    pub(crate) watcher: Option<watcher::Watcher>,
    /// One command or scope change of a shell at a time (`shells`).
    pub(crate) shell_locks: Mutex<HashMap<agent_auth_core::GrantId, Arc<tokio::sync::Mutex<()>>>>,
    me: std::sync::Weak<HostExec>,
}

impl std::fmt::Debug for HostExec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostExec").finish_non_exhaustive()
    }
}

/// `tail(output)`: the last 30 lines, at most 1500 characters.
#[must_use]
pub fn tail(output: Option<&str>) -> String {
    let text = output.unwrap_or("");
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(TAIL_LINES);
    let joined = lines.get(start..).unwrap_or_default().join("\n");
    let n = joined.chars().count();
    joined.chars().skip(n.saturating_sub(1500)).collect()
}

fn wire_status(s: agent_auth_store::hostexec::JobStatus) -> WireJobStatus {
    use agent_auth_store::hostexec::JobStatus as S;
    match s {
        S::Starting => WireJobStatus::Starting,
        S::Running => WireJobStatus::Running,
        S::Done => WireJobStatus::Done,
        S::Refused => WireJobStatus::Refused,
        S::Lost => WireJobStatus::Lost,
    }
}

/// `job_out(job, full)`.
#[must_use]
pub fn job_out(job: &JobRow, full: bool) -> JobOut {
    let command = match (job.spec.get("argv"), job.spec.get("template")) {
        (Some(Value::Array(argv)), _) if !argv.is_empty() => Some(JobCommand::Argv(
            argv.iter()
                .filter_map(|a| a.as_str().map(str::to_owned))
                .collect(),
        )),
        (_, Some(Value::String(t))) => Some(JobCommand::Template(t.clone())),
        _ => None,
    };
    let status = wire_status(job.status);
    let output = status.has_ended().then(|| {
        if full {
            job.output.clone().unwrap_or_default()
        } else {
            tail(job.output.as_deref())
        }
    });
    JobOut {
        job_id: job.id,
        host: job.host.clone(),
        tier: TierName::from(job.tier),
        status,
        exit_code: job.exit_code,
        error: job.error.clone(),
        duration_ms: job.duration_ms.and_then(|d| u64::try_from(d).ok()),
        output_bytes: job.output_bytes.map(u64::from),
        output_sha256: job.output_sha256.clone(),
        truncated: Some(job.truncated),
        command,
        output,
    }
}

/// A float a daemon reported, if it is a plausible Unix time.
fn plausible_time(f: Option<f64>) -> Option<f64> {
    f.filter(|t| t.is_finite() && (0.0..1.0e11).contains(t))
}

fn bounded(text: &str, max: usize) -> String {
    escape_unprintable(&text.chars().take(max).collect::<String>())
}

/// A host's last heartbeat, re-validated: daemon-supplied text is escaped
/// and bounded, times must be plausible, template names valid (review
/// finding 3). Informational only (INV-34).
#[must_use]
pub fn sanitize_status(raw: Option<&Value>) -> HostStatus {
    let parsed: HostStatus = raw
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    HostStatus {
        version: parsed
            .version
            .filter(|v| agent_auth_wire::daemon::handshake::version_ok(v)),
        role: parsed.role.filter(|r| r == "host" || r == "sandbox"),
        started_at: plausible_time(parsed.started_at),
        tiers: parsed
            .tiers
            .into_iter()
            .map(|(k, t)| {
                (
                    k,
                    TierStatus {
                        armed_until: plausible_time(t.armed_until),
                        ..t
                    },
                )
            })
            .collect(),
        jobs: parsed.jobs,
        shells: parsed.shells,
        lockdown: parsed.lockdown,
        vm: parsed.vm.map(|vm| VmStatus {
            unit: bounded(&vm.unit, 128),
            state: bounded(&vm.state, 64),
        }),
        templates: parsed
            .templates
            .into_iter()
            .filter(|t| agent_auth_core::names::TemplateName::parse(t).is_ok())
            .take(256)
            .collect(),
        desktop: parsed.desktop.map(|d| DesktopStatus {
            away_reason: d.away_reason.map(|r| bounded(&r, 256)),
            dnd_until: plausible_time(d.dnd_until),
            ..d
        }),
        error: parsed.error.map(|e| bounded(&e, 256)),
    }
}

impl HostExec {
    /// The service, with its handlers registered on the hub.
    pub fn new(
        hub: Arc<DaemonHub>,
        store: Store,
        policy: Arc<Policy>,
        watcher: Option<watcher::Watcher>,
    ) -> Result<Arc<HostExec>, String> {
        let me = Arc::new_cyclic(|weak| HostExec {
            hub: Arc::clone(&hub),
            store,
            policy,
            job_events: Arc::default(),
            buffers: Mutex::new(HashMap::new()),
            st: OnceLock::new(),
            watcher,
            shell_locks: Mutex::new(HashMap::new()),
            me: weak.clone(),
        });
        let h = Arc::clone(&me);
        hub.handle(
            "job.output",
            Arc::new(move |peer, body| {
                let h = Arc::clone(&h);
                Box::pin(async move { h.on_output(&peer, body) })
            }),
        )?;
        let h = Arc::clone(&me);
        hub.handle(
            "job.done",
            Arc::new(move |peer, body| {
                let h = Arc::clone(&h);
                Box::pin(async move { h.on_done(&peer, body).await })
            }),
        )?;
        let h = Arc::clone(&me);
        hub.on_connect(Arc::new(move |peer| {
            let h = Arc::clone(&h);
            Box::pin(async move { h.on_connect(&peer).await })
        }));
        Ok(me)
    }

    /// Attach the broker's state (once, by `main`, after `AppState` is
    /// built): the notifier and the request service are reached through it.
    pub fn bind(&self, st: crate::state::AppState) {
        let _ = self.st.set(st);
    }

    pub(crate) fn app(&self) -> Option<&crate::state::AppState> {
        self.st.get()
    }

    /// The notifier (a headless one until bound).
    pub(crate) fn notifier(&self) -> &Notifier {
        static NULL: Notifier = Notifier::Null;
        self.st.get().map_or(&NULL, |s| s.notifier.as_ref())
    }

    pub(crate) fn self_arc(&self) -> Option<Arc<HostExec>> {
        self.me.upgrade()
    }

    #[must_use]
    pub fn hub(&self) -> &Arc<DaemonHub> {
        &self.hub
    }

    // ------------------------------------------------------- talking to hosts

    /// A call to a host.
    pub async fn call(
        &self,
        host: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Map<String, Value>, CallError> {
        let Value::Object(payload) = payload else {
            return Err(CallError {
                message: "not a message".into(),
                timed_out: false,
            });
        };
        self.hub.call(Role::Host, host, payload, timeout).await
    }

    /// Paired hosts with what their hostd last reported (re-validated).
    pub async fn hosts(&self) -> Result<Vec<HostOut>, StoreError> {
        let tx = self.store.begin().await?;
        let rows = daemons::list_role(&tx, DaemonRole::Host).await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let status = sanitize_status(row.last_status.as_ref());
                HostOut {
                    online: self.hub.is_online(Role::Host, &row.name),
                    name: row.name,
                    tiers: status.tiers,
                    lockdown: status.lockdown,
                    templates: status.templates,
                    vm: status.vm,
                    desktop: status.desktop,
                }
            })
            .collect())
    }

    /// The broker's lockdown flag (`{}` when not locked down).
    pub async fn lockdown_state(&self) -> Result<Value, StoreError> {
        let tx = self.store.begin().await?;
        let v = flags::get(&tx, flags::LOCKDOWN).await?;
        tx.commit().await?;
        Ok(v.unwrap_or_else(|| json!({})))
    }

    // ------------------------------------------------------------ validation

    /// The platform's validation (spec §10.1), at request time and again on
    /// approval with the final resource and authority. Normalizes the
    /// authority exactly as the grant will carry it (so the gate's spec and
    /// the started spec digest the same).
    pub async fn validate(
        &self,
        tx: &Tx<'_>,
        resource: &str,
        authority: &Authority,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let refuse = |m: String| Ok(Err(Refused(m)));
        let host = resource.trim().to_lowercase();
        if agent_auth_crypto::daemon::DaemonName::parse(&host).is_none() {
            return refuse("resource is the host's name".into());
        }
        let Some(row) = daemons::by_name(tx, DaemonRole::Host, &host).await? else {
            return refuse(format!(
                "no host {} is paired with this broker",
                repr(&host)
            ));
        };
        if !self.hub.is_online(Role::Host, &host) {
            return refuse(format!("host {host} is offline"));
        }
        if flags::locked(tx, &host).await? {
            return refuse(format!(
                "locked down: nothing runs on {host} until it is unlocked"
            ));
        }
        let Authority::Hostexec(h) = authority else {
            return refuse("hostexec capability is \"run\", \"tpl.<name>\" or \"shell\"".into());
        };
        let mut notes = Vec::new();
        let (normalized, tier, shell) = match h {
            HostexecAuthority::Shell { tier, mode } => {
                // A guard that cannot exist would refuse every command.
                if mode.guarded() && self.watcher.is_none() {
                    return refuse(format!(
                        "a {mode} shell needs a model to check its commands, and this broker \
                         has none (OPENROUTER_API_KEY): ask for a watched or general shell"
                    ));
                }
                notes.push(format!(
                    "{} shell on {host}: any command, one at a time, each shown here before it runs",
                    if *tier == Tier::Root { "ROOT" } else { "user" }
                ));
                let watching = self.watcher.is_some() && self.policy.platforms().hostexec.watch;
                notes.push(mode.describe(watching).to_owned());
                (
                    HostexecAuthority::Shell {
                        tier: *tier,
                        mode: *mode,
                    },
                    *tier,
                    true,
                )
            }
            HostexecAuthority::Run { .. } | HostexecAuthority::Template { .. } => {
                let spec = match CommandSpec::from_authority(&host, h) {
                    Ok(s) => s,
                    Err(e) => return refuse(e.0),
                };
                let options = CommandOptions {
                    tier: spec.tier(),
                    cwd: spec.cwd().map(str::to_owned),
                    env: spec
                        .env()
                        .iter()
                        .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
                        .collect(),
                    timeout: Some(spec.timeout()),
                    stdin: spec.stdin().map(str::to_owned),
                };
                let normalized = match spec.command() {
                    Command::Run { argv } => {
                        notes.push(format!(
                            "runs as {} on {host}: {}",
                            if spec.tier() == Tier::Root {
                                "ROOT"
                            } else {
                                "your user"
                            },
                            escape_unprintable(&shlex_join(argv))
                        ));
                        HostexecAuthority::Run {
                            argv: argv.clone(),
                            options,
                        }
                    }
                    Command::Template { template, params } => {
                        match self.template_note(&host, &spec, template.as_str(), params) {
                            Ok(note) => notes.push(note),
                            Err(e) => return refuse(e),
                        }
                        HostexecAuthority::Template {
                            template: template.as_str().to_owned(),
                            params: params.clone(),
                            options,
                        }
                    }
                };
                (normalized, spec.tier(), false)
            }
            HostexecAuthority::Window { .. } => {
                return refuse(
                    "hostexec capability is \"run\", \"tpl.<name>\" or \"shell\"".into(),
                );
            }
        };
        // What the host last said it accepts: no point asking a human for
        // something it will refuse whatever they answer (it checks again).
        let status = sanitize_status(row.last_status.as_ref());
        if let Some(reported) = status.tiers.get(&TierName::from(tier)) {
            if !reported.enabled {
                return refuse(format!("the {tier} tier is not enabled on {host}"));
            }
            if shell && !reported.shell {
                return refuse(format!("{tier} shells are not enabled on {host}"));
            }
        }
        Ok(Ok(Validated {
            resource: host,
            authority: Authority::Hostexec(normalized),
            notes,
        }))
    }

    /// A template request against the broker's mirror, if it has one.
    fn template_note(
        &self,
        host: &str,
        spec: &CommandSpec,
        template: &str,
        params: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let mirror = self
            .policy
            .platforms()
            .hostexec
            .templates
            .iter()
            .find(|(name, _)| name.as_str() == template)
            .map(|(_, t)| t);
        let Some(t) = mirror else {
            return Ok(format!(
                "template {} with {}: not mirrored in the broker's policy, so what it runs is \
                 known only to the host",
                repr(template),
                agent_auth_core::pyfmt::json_str_map(
                    params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
                )
            ));
        };
        if t.tier != spec.tier() {
            return Err(format!(
                "template {} is a {}-tier template",
                repr(template),
                t.tier
            ));
        }
        let argv = t.expand(params).map_err(|e| e.0)?;
        Ok(format!(
            "template {} on {host} ({}) expands to: {}",
            repr(template),
            spec.tier(),
            escape_unprintable(&shlex_join(&argv))
        ))
    }

    // ------------------------------------------------------------- jobs

    /// What the host is told about why the broker approved (believed only
    /// while the tier is armed; a TOTP code needs no believing).
    #[must_use]
    pub fn evidence(request: &RequestRow) -> Value {
        let decided_by = request.decided_by.clone();
        json!({
            "request_id": request.id.to_string(),
            "decided_by": decided_by.as_deref().map(|d| d.chars().take(256).collect::<String>()),
            "source": request.decision_source.map(DecisionSource::as_str),
            "window": decided_by.as_deref().is_some_and(|d| d.starts_with("window:")),
        })
    }

    /// A job of the agent's own, after waiting up to `wait` for it to end
    /// (or until the broker is stopping: then as it is).
    pub async fn get_job(
        &self,
        agent: agent_auth_core::AgentId,
        job: JobId,
        wait: Duration,
        shutdown: &crate::events::Shutdown,
    ) -> Result<Option<JobRow>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(tokio::time::Instant::now);
        let mut listener = self.job_events.listen(&job);
        loop {
            let tx = self.store.begin().await?;
            let row = agent_auth_store::hostexec::get_owned(&tx, agent, job).await?;
            tx.commit().await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let now = tokio::time::Instant::now();
            if wire_status(row.status).has_ended() || now >= deadline || shutdown.is_triggered() {
                return Ok(Some(row));
            }
            let slice = deadline
                .saturating_duration_since(now)
                .min(Duration::from_secs(2));
            listener.wait_or_shutdown(slice, shutdown).await;
        }
    }

    /// Kill a job that may still run (best effort).
    pub async fn kill(&self, job: &JobRow) -> Result<(), crate::daemons::CallError> {
        use agent_auth_store::hostexec::JobStatus as S;
        if !matches!(job.status, S::Starting | S::Running) {
            return Ok(());
        }
        self.call(
            &job.host,
            json!({"type": "job.kill", "job_id": job.id.to_string()}),
            SHORT_CALL_TIMEOUT,
        )
        .await
        .map(|_| ())
        .inspect_err(|e| tracing::info!(job = %job.id, host = %job.host, "could not kill: {e}"))
    }

    // ----------------------------------------------------------- arming

    /// Arm a tier: the host then believes the broker's approvals for it.
    /// The code is for the host's `<tier>-arm` secret; the host checks it.
    pub async fn arm(
        &self,
        host: &str,
        tier: Tier,
        duration: &agent_auth_wire::duration::HostDuration,
        totp: &str,
    ) -> Result<Map<String, Value>, HostExecError> {
        Ok(self
            .call(
                host,
                json!({"type": "arm", "tier": tier.as_str(), "duration": duration, "totp": totp}),
                CALL_TIMEOUT,
            )
            .await?)
    }

    /// Disarm one tier, or both.
    pub async fn disarm(
        &self,
        host: &str,
        tier: Option<Tier>,
    ) -> Result<Map<String, Value>, HostExecError> {
        Ok(self
            .call(
                host,
                json!({"type": "disarm", "tier": tier.map(Tier::as_str)}),
                CALL_TIMEOUT,
            )
            .await?)
    }

    /// Would this host honour an approve-all window for the tier now?
    pub async fn precheck_window(&self, host: &str, tier: Tier) -> Result<(), HostExecError> {
        let probe = json!({"kind": "run", "host": host, "tier": tier.as_str(), "argv": ["true"],
                           "cwd": null, "env": {}, "timeout": 600, "stdin": null});
        self.call(
            host,
            json!({"type": "hostexec.precheck", "spec": probe, "source": "rule", "window": true}),
            CALL_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    /// "Approve all": an expiring rule for this agent, host and tier (any
    /// command, never a shell), which also approves what already waits.
    /// The host must be armed and accept windows — checked now, and again
    /// by the host for every job.
    pub async fn open_window(
        &self,
        request: &RequestRow,
        agent_name: &str,
        delegator_name: Option<&str>,
        duration_secs: u32,
        created_by: &str,
    ) -> Result<(agent_auth_store::rules::RuleRow, Vec<RequestId>), HostExecError> {
        let Some(Authority::Hostexec(h)) = request.final_authority() else {
            return Err(HostExecError("not a host command".into()));
        };
        if matches!(h, HostexecAuthority::Shell { .. }) {
            return Err(HostExecError(
                "shells are approved one at a time, with a TOTP code".into(),
            ));
        }
        let tier = h.tier();
        let host = request.final_resource().to_owned();
        self.precheck_window(&host, tier).await?;
        let now = time::OffsetDateTime::now_utc();
        let authority = Authority::Hostexec(HostexecAuthority::Window { tier });
        let notes = format!("approve-all window ({tier} on {host})");
        let rule = async {
            let tx = self.store.begin().await?;
            let rule = agent_auth_store::rules::insert(
                &tx,
                &agent_auth_store::rules::NewRule {
                    id: RuleId::new(),
                    action: agent_auth_store::rules::RuleAction::AutoApprove,
                    agent_pattern: &agent_auth_core::glob::escape(agent_name),
                    delegator_pattern: delegator_name.map(agent_auth_core::glob::escape).as_deref(),
                    platform: agent_auth_core::Platform::Hostexec,
                    resource_pattern: &agent_auth_core::glob::escape(&host),
                    authority: Some(&authority),
                    max_duration_secs: None,
                    created_by,
                    notes: &notes,
                    expires_at: Some(
                        now.saturating_add(time::Duration::seconds(i64::from(duration_secs))),
                    ),
                    now,
                },
            )
            .await?;
            tx.commit().await?;
            Ok::<_, StoreError>(rule)
        }
        .await
        .map_err(|e| HostExecError(format!("could not save the window: {e}")))?;
        let approved = match self.app() {
            Some(st) => crate::service::apply_rule_to_pending(st, rule.id)
                .await
                .map_err(|e| HostExecError(e.to_string()))?,
            None => Vec::new(),
        };
        Ok((rule, approved))
    }

    // ------------------------------------------------------- connecting

    /// A host that was offline when it mattered is told now: the broker's
    /// lockdown, shells that ended while it was away. (An agent VM is told
    /// its lock state and held agents by `crate::sandboxes`, in one hook.)
    async fn on_connect(&self, peer: &crate::daemons::DaemonPeer) {
        if peer.role() != Role::Host {
            return;
        }
        let result = async {
            let tx = self.store.begin().await?;
            let locked = flags::locked(&tx, peer.name()).await?;
            let mut stale = Vec::new();
            let since = time::OffsetDateTime::now_utc().saturating_sub(time::Duration::days(1));
            for g in agent_auth_store::grants::ended_on(
                &tx,
                agent_auth_core::Platform::Hostexec,
                peer.name(),
                since,
            )
            .await?
            {
                if matches!(
                    g.authority,
                    Authority::Hostexec(HostexecAuthority::Shell { .. })
                ) {
                    stale.push(g.request_id);
                }
            }
            tx.commit().await?;
            Ok::<_, StoreError>((locked, stale))
        }
        .await;
        let (locked, stale) = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(daemon = %peer.principal(), error = %e, "on_connect failed");
                return;
            }
        };
        let send = |payload: Value| async move {
            if let Value::Object(m) = payload {
                self.hub.send_default(peer.role(), peer.name(), &m).await;
            }
        };
        if locked {
            send(json!({"type": "lockdown", "kill_vm": false})).await;
        }
        for shell in stale {
            send(json!({"type": "shell.close", "shell_id": shell.to_string()})).await;
        }
    }
}

/// The scheduler's hostexec step (call it every tick): jobs with no
/// result long after their timeout become `lost` (daemons bug 3). Returns
/// how many.
pub async fn scheduler_tick(
    hostexec: &HostExec,
    now: time::OffsetDateTime,
) -> Result<usize, StoreError> {
    let tx = hostexec.store.begin().await?;
    let cutoff = now.saturating_sub(time::Duration::seconds(LOST_GRACE_SECS));
    let candidates = agent_auth_store::hostexec::unfinished_before(&tx, cutoff).await?;
    let mut lost = Vec::new();
    for job in candidates {
        let timeout = job
            .spec
            .get("timeout")
            .and_then(Value::as_i64)
            .unwrap_or(i64::from(agent_auth_core::hostexec::DEFAULT_TIMEOUT_SECS));
        let due = job.created_at.saturating_add(time::Duration::seconds(
            timeout.saturating_add(LOST_GRACE_SECS),
        ));
        if due < now
            && let Some(row) = agent_auth_store::hostexec::mark_lost(
                &tx,
                job.id,
                &job.host,
                "no result from the host; its outcome is unknown",
                now,
            )
            .await?
        {
            lost.push(row);
        }
    }
    tx.commit().await?;
    for row in &lost {
        hostexec.job_events.notify(&row.id);
        tracing::warn!(job = %row.id, host = %row.host, "job lost: no result from its host");
    }
    Ok(lost.len())
}

/// The Discord bot's view of a host (its card's host line).
impl crate::discord::ops::HostsOps for HostExec {
    fn host(&self, name: &str) -> BoxFuture<'_, Option<Value>> {
        let name = name.to_owned();
        Box::pin(async move {
            let hosts = self.hosts().await.ok()?;
            hosts
                .into_iter()
                .find(|h| h.name == name)
                .and_then(|h| serde_json::to_value(h).ok())
        })
    }
}

/// The spine's scheduler hook: [`scheduler_tick`].
#[must_use]
pub fn tick_hook(hostexec: Arc<HostExec>) -> crate::service::TickHook {
    Arc::new(move |st| {
        let hostexec = Arc::clone(&hostexec);
        Box::pin(async move {
            match scheduler_tick(&hostexec, st.now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(lost = n, "hostexec: jobs marked lost"),
                Err(e) => tracing::error!(error = %e, "hostexec tick failed"),
            }
        })
    })
}
