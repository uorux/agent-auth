//! Shell commands (spec §10.6) and the watcher's hook (§10.8).

use std::sync::Arc;

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::hostexec::{SpecFields, make_spec};
use agent_auth_core::shell_mode::{self, GuardOutcome, ShellRefusal};
use agent_auth_core::{AgentId, Authority, GrantId, JobId, Platform, ScopeId, ShellMode, Tier};

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
use agent_auth_store::grants::{self, IssuableGrant, NotIssuable};
use agent_auth_store::hostexec::{self as store, JobRow, JobStatus, NewJob};
use agent_auth_store::shell_scopes::{self, RefusalKind, ScopeRow};
use agent_auth_store::{StoreError, flags};
use agent_auth_wire::hostexec::ShellExecBody;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::watcher::{EarlierCommand, GuardVerdict, Guarded, Level, Watched};
use super::{CALL_TIMEOUT, HostExec};
use crate::notify::{Notify as _, ShellEvent};

/// Earlier commands of the shell the guard is shown at most (newest).
const GUARD_HISTORY: i64 = 40;
/// ... and at most this much of their text (older ones are left out, and
/// the guard is told how many).
const GUARD_HISTORY_CHARS: usize = 160_000;
/// Refusals after which a guarded shell is ended (an alarming one ends it
/// at once).
const MAX_REFUSALS: i64 = 5;

/// What a guarded shell passes in `env`: nothing that changes what runs.
fn guarded_env_ok(key: &str) -> bool {
    matches!(key, "LANG" | "TZ" | "TERM") || key.starts_with("LC_")
}

/// The newest earlier commands that fit the guard's budget, oldest first,
/// and how many older ones were left out.
fn guard_context(history: &[shell_scopes::Earlier], total: i64) -> (Vec<EarlierCommand>, usize) {
    let mut kept = Vec::new();
    let mut used = 0usize;
    for e in history.iter().rev() {
        let size = e
            .spec
            .to_string()
            .len()
            .saturating_add(e.error.as_ref().map_or(0, String::len))
            .saturating_add(e.scope_purpose.as_ref().map_or(0, String::len));
        if used.saturating_add(size) > GUARD_HISTORY_CHARS {
            break;
        }
        used = used.saturating_add(size);
        kept.push(EarlierCommand {
            spec: e.spec.clone(),
            status: e.status.clone(),
            error: e.error.clone(),
            scope_purpose: e.scope_purpose.clone(),
        });
    }
    kept.reverse();
    let total = usize::try_from(total).unwrap_or(usize::MAX);
    let omitted = total.max(history.len()).saturating_sub(kept.len());
    (kept, omitted)
}

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Why a shell command did not go out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShellExecError {
    /// 404 `unknown shell`.
    #[error("unknown shell")]
    NotFound,
    /// 400: the spec does not validate.
    #[error("{0}")]
    Spec(String),
    /// 409: the shell ended, the host is locked, the operator could not be
    /// shown it, or the host refused.
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Internal(String),
}

impl From<StoreError> for ShellExecError {
    fn from(e: StoreError) -> Self {
        ShellExecError::Internal(e.to_string())
    }
}

impl HostExec {
    /// The shell grant, if a command may go out on it now, checked in
    /// `tx`: the caller's own, issuable (ACTIVE, unexpired, its agent not
    /// held, a delegated one's thread open), a shell, its host not locked.
    /// Its share locks (and the containment lock) last until `tx` ends.
    async fn shell_grant<'t>(
        &self,
        tx: &'t agent_auth_store::Tx<'_>,
        agent: AgentId,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<(IssuableGrant<'t>, Tier, ShellMode), ShellExecError> {
        let grant = match grants::issuable(tx, agent, grant_id, now).await? {
            Ok(g) => g,
            Err(NotIssuable::UnknownGrant) => return Err(ShellExecError::NotFound),
            Err(NotIssuable::Held(held)) => return Err(ShellExecError::Refused(held.text())),
            Err(NotIssuable::DelegationClosed) => {
                return Err(ShellExecError::Refused(
                    "that shell's delegation thread is closed".into(),
                ));
            }
            Err(NotIssuable::NotActive { .. }) => {
                // Another platform's grant is not a shell at all.
                let g = grants::get_owned(tx, agent, grant_id).await?;
                if g.is_some_and(|g| g.platform == Platform::Hostexec) {
                    return Err(ShellExecError::Refused("that shell has ended".into()));
                }
                return Err(ShellExecError::NotFound);
            }
        };
        let g = grant.grant();
        if g.platform != Platform::Hostexec {
            return Err(ShellExecError::NotFound);
        }
        let Authority::Hostexec(HostexecAuthority::Shell { tier, mode }) = g.authority else {
            return Err(ShellExecError::NotFound);
        };
        if flags::locked(tx, &g.resource).await? {
            return Err(ShellExecError::Refused("locked down".into()));
        }
        Ok((grant, tier, mode))
    }

    /// The scoped shell a command names, checked in `tx` (share-locked
    /// until it ends, so it cannot close under the command): an umbrella's
    /// command needs an open scope of that umbrella, any other shell's
    /// command none.
    async fn command_scope(
        tx: &agent_auth_store::Tx<'_>,
        grant: GrantId,
        mode: ShellMode,
        scope: Option<ScopeId>,
    ) -> Result<Option<ScopeRow>, ShellExecError> {
        match shell_mode::scope_rule(mode, scope.is_some()) {
            Err(ShellRefusal::NeedsScope) => {
                return Err(ShellExecError::Refused(
                    "this is an umbrella shell: commands run only in a scoped shell; open one \
                     with host_shell_scope(grant_id, purpose) and pass its scope_id"
                        .into(),
                ));
            }
            Err(_) => {
                return Err(ShellExecError::Spec(
                    "only an umbrella shell has scoped shells: leave out scope_id".into(),
                ));
            }
            Ok(()) => {}
        }
        let Some(id) = scope else {
            return Ok(None);
        };
        match shell_scopes::open_for_share(tx, grant, id).await? {
            Some(s) => Ok(Some(s)),
            None => Err(ShellExecError::Refused(
                "that scoped shell is closed, or not one of this shell's".into(),
            )),
        }
    }

    /// One command in an open shell: in a guarded shell or an umbrella's
    /// scope first cleared by the guard (fail closed), then shown to the
    /// operator before it is sent, and not sent if that fails (INV-31). The
    /// grant (and scope) are checked again after the operator was shown
    /// it, in the transaction that writes the job and holds their locks
    /// while the host is asked, so a revoke, a containment, a closed
    /// delegation thread, a closed scope or a lockdown that landed
    /// meanwhile stops it (security review 2026-10). One command (or scope
    /// change) of a shell at a time: the guard judges each in the light of
    /// all before it.
    pub async fn shell_exec(
        &self,
        agent: AgentId,
        grant_id: GrantId,
        body: &ShellExecBody,
    ) -> Result<JobRow, ShellExecError> {
        let scope_id =
            match &body.scope_id {
                None => None,
                Some(t) => Some(t.as_str().parse::<ScopeId>().map_err(|_| {
                    ShellExecError::Spec("scope_id is not a scoped shell's id".into())
                })?),
            };
        let serial = self.shell_lock(grant_id);
        let _one_at_a_time = serial.lock().await;
        let now = OffsetDateTime::now_utc();
        let (grant, tier, mode, request, scope, agent_name, history) = {
            let tx = self.store.begin().await?;
            let (issuable, tier, mode) = self.shell_grant(&tx, agent, grant_id, now).await?;
            let grant = issuable.grant().clone();
            let scope = Self::command_scope(&tx, grant.id, mode, scope_id).await?;
            let request = agent_auth_store::requests::get(&tx, grant.request_id)
                .await?
                .ok_or(ShellExecError::NotFound)?
                .into_row();
            let (agent_name, history) = if mode.guarded() {
                Self::within_budget(&tx, grant.id).await?;
                let name = agent_auth_store::agents::get(&tx, agent)
                    .await?
                    .map_or_else(|| "?".to_owned(), |a| a.name);
                let history = shell_scopes::history(&tx, request.id, GUARD_HISTORY).await?;
                (name, history)
            } else {
                (String::new(), (Vec::new(), 0))
            };
            tx.commit().await?;
            (grant, tier, mode, request, scope, agent_name, history)
        };
        // Variables that change what runs are not the guard's to weigh.
        if mode.guarded()
            && let Some((k, _)) = body.env.iter().find(|(k, _)| !guarded_env_ok(k.as_str()))
        {
            return Err(ShellExecError::Spec(format!(
                "a {mode} shell passes only LANG, LC_*, TZ and TERM in env, not {}",
                agent_auth_core::pyfmt::repr(k.as_str())
            )));
        }
        let host = grant.resource.clone();
        let argv = json!(body.argv.iter().map(|a| a.as_str()).collect::<Vec<_>>());
        let env: Map<String, Value> = body
            .env
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), json!(v.as_str())))
            .collect();
        let env = Value::Object(env);
        let tier_v = json!(tier.as_str());
        let cwd = body.cwd.as_ref().map(|c| json!(c.as_str()));
        let stdin = body.stdin.as_ref().map(|s| json!(s.as_str()));
        let timeout = body.timeout.map(|t| json!(t));
        let spec = make_spec(&SpecFields {
            kind: "run",
            host: &host,
            tier: Some(&tier_v),
            argv: Some(&argv),
            cwd: cwd.as_ref(),
            env: Some(&env),
            timeout: timeout.as_ref(),
            stdin: stdin.as_ref(),
            ..SpecFields::default()
        })
        .map_err(|e| ShellExecError::Spec(e.0))?;
        let spec_json = spec.to_json();
        let job_id = JobId::new();
        let new_job = NewJob {
            id: job_id,
            grant_id: Some(grant.id),
            request_id: request.id,
            agent_id: agent,
            host: &host,
            tier,
            shell_id: Some(request.id),
            spec: &spec_json,
            now,
        };
        // The guard first, before anyone is shown it: it can only refuse.
        let mut guard_why = String::new();
        let outcome = if mode.guarded() {
            let (earlier, omitted) = guard_context(&history.0, history.1);
            match &self.watcher {
                None => GuardOutcome::Unavailable,
                Some(w) => match w
                    .guard(&Guarded {
                        agent: &agent_name,
                        host: &host,
                        tier: tier.as_str(),
                        approved_purpose: &request.justification,
                        scope_purpose: scope.as_ref().map(|s| s.purpose.as_str()),
                        earlier: &earlier,
                        omitted,
                        spec: &spec_json,
                    })
                    .await
                {
                    GuardVerdict::Allow(_) => GuardOutcome::Allow,
                    GuardVerdict::Refuse { alarming, why } => {
                        guard_why = why;
                        GuardOutcome::Refuse { alarming }
                    }
                    GuardVerdict::Unavailable => GuardOutcome::Unavailable,
                },
            }
        } else {
            GuardOutcome::NotAsked
        };
        if let Err(refusal) = shell_mode::after_guard(mode, outcome) {
            let mut text = match refusal {
                ShellRefusal::Guard { .. } => format!("the shell's guard refused it: {guard_why}"),
                _ => "the shell's guard could not be asked, so it did not run \
                      (guarded shells fail closed); try again shortly"
                    .to_owned(),
            };
            let ended = match refusal {
                ShellRefusal::Guard { alarming } => {
                    self.count_refusal(grant.id, RefusalKind::Command, alarming)
                        .await?
                }
                _ => None,
            };
            if let Some(why) = &ended {
                text.push_str(&format!("; {why}"));
            }
            let job = self.record_refused(&new_job, scope.as_ref(), &text).await?;
            let event = match refusal {
                ShellRefusal::Guard { alarming } => ShellEvent::GuardRefused {
                    job: &job,
                    scope: scope.as_ref(),
                    why: &guard_why,
                    alarming,
                },
                _ => ShellEvent::GuardUnavailable {
                    job: &job,
                    scope: scope.as_ref(),
                },
            };
            self.notifier().shell_event(&request, event).await;
            if let Some(why) = ended {
                self.end_shell(grant.id, &why).await;
            }
            return Err(ShellExecError::Refused(text));
        }
        // Before dispatch, and failing closed: a command nobody was shown
        // does not run.
        let shown = self
            .notifier()
            .shell_command(&request, &new_job.to_row(), scope.as_ref())
            .await;
        let tx = self.store.begin().await?;
        if !shown {
            store::insert(&tx, &new_job).await?;
            store::set_status(
                &tx,
                job_id,
                &host,
                JobStatus::Refused,
                Some("could not show the command on Discord"),
                None,
            )
            .await?;
            tx.commit().await?;
            self.job_events.notify(&job_id);
            return Err(ShellExecError::Refused(
                "could not show the command on Discord; not run".into(),
            ));
        }
        // Again, now: the operator was shown it a moment ago.
        match self.shell_grant(&tx, agent, grant_id, now_utc()).await {
            Ok((_, _, again)) if again == mode => {}
            Ok(_) => {
                drop(tx);
                return Err(ShellExecError::Refused("that shell has changed".into()));
            }
            Err(e) => {
                drop(tx);
                return Err(e);
            }
        }
        if let Err(e) = Self::command_scope(&tx, grant.id, mode, scope_id).await {
            drop(tx);
            return Err(e);
        }
        let job = store::insert(&tx, &new_job).await?;
        if let Some(s) = &scope {
            shell_scopes::link_job(&tx, job_id, s.id).await?;
        }
        let sent = self
            .call(
                &host,
                json!({"type": "shell.exec", "shell_id": request.id.to_string(),
                       "job_id": job_id.to_string(), "spec": spec_json}),
                CALL_TIMEOUT,
            )
            .await;
        match sent {
            Ok(_) => {
                store::set_status(&tx, job_id, &host, JobStatus::Running, None, None).await?;
                tx.commit().await?;
                self.watch(job_id);
                Ok(self.reload(job_id).await?.unwrap_or(job))
            }
            Err(e) if e.timed_out => {
                // As for job.start (bug 2): it may run; its result, if any,
                // is stored, otherwise it becomes lost.
                tx.commit().await?;
                self.watch(job_id);
                Err(ShellExecError::Refused(e.message))
            }
            Err(e) => {
                store::set_status(
                    &tx,
                    job_id,
                    &host,
                    JobStatus::Refused,
                    Some(&e.message),
                    None,
                )
                .await?;
                tx.commit().await?;
                self.job_events.notify(&job_id);
                if let Some(refused) = self.reload(job_id).await? {
                    self.job_finished(&refused).await;
                }
                Err(ShellExecError::Refused(e.message))
            }
        }
    }

    /// The lock that keeps one command or scope change of a shell at a
    /// time (one broker per database: in memory is enough).
    fn shell_lock(&self, grant: GrantId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .shell_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, l| Arc::strong_count(l) > 1);
        Arc::clone(locks.entry(grant).or_default())
    }

    /// A shell whose models refused too much is ended, not argued with.
    async fn within_budget(
        tx: &agent_auth_store::Tx<'_>,
        grant: GrantId,
    ) -> Result<(), ShellExecError> {
        let (n, alarming) = shell_scopes::refusals(tx, grant).await?;
        if alarming > 0 || n >= MAX_REFUSALS {
            return Err(ShellExecError::Refused(
                "this shell's guard refused too much; it is being ended: ask the operator for a new one"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Count a refusal; `Some(why)` when the shell must now end (an
    /// alarming refusal, or the budget spent).
    async fn count_refusal(
        &self,
        grant: GrantId,
        kind: RefusalKind,
        alarming: bool,
    ) -> Result<Option<String>, ShellExecError> {
        let tx = self.store.begin().await?;
        shell_scopes::record_refusal(&tx, grant, kind, alarming, now_utc()).await?;
        let (n, _) = shell_scopes::refusals(&tx, grant).await?;
        tx.commit().await?;
        Ok(if alarming {
            Some("the shell was ended: its guard found that alarming".to_owned())
        } else if n >= MAX_REFUSALS {
            Some(format!(
                "the shell was ended: its guard refused {n} times; ask the operator for a new one"
            ))
        } else {
            None
        })
    }

    /// End a shell (revoke its grant), as the guard's budget says.
    async fn end_shell(&self, grant: GrantId, why: &str) {
        let Some(st) = self.st.get() else {
            return;
        };
        if let Err(e) = crate::service::revoke_grant(st, grant, why, "shell guard").await {
            tracing::warn!(grant = %grant, "ending a shell the guard refused failed: {e}");
        }
    }

    /// A command that was not sent (the guard refused it), on record as
    /// refused, in its scope if that is still open.
    async fn record_refused(
        &self,
        new_job: &NewJob<'_>,
        scope: Option<&ScopeRow>,
        why: &str,
    ) -> Result<JobRow, ShellExecError> {
        let tx = self.store.begin().await?;
        store::insert(&tx, new_job).await?;
        if let Some(s) = scope
            && shell_scopes::open_for_share(&tx, s.grant_id, s.id)
                .await?
                .is_some()
        {
            shell_scopes::link_job(&tx, new_job.id, s.id).await?;
        }
        store::set_status(
            &tx,
            new_job.id,
            new_job.host,
            JobStatus::Refused,
            Some(&cut(why, 1000)),
            None,
        )
        .await?;
        let job = store::get(&tx, new_job.id)
            .await?
            .ok_or_else(|| ShellExecError::Internal("the refused command vanished".into()))?;
        tx.commit().await?;
        self.job_events.notify(&new_job.id);
        Ok(job)
    }

    /// Open a scoped shell in the caller's umbrella shell `grant_id`, for
    /// `purpose`, if the scope check finds it within the umbrella's concept
    /// (the request's justification). Fail closed: no model, no scope.
    pub async fn open_scope(
        &self,
        agent: AgentId,
        grant_id: GrantId,
        purpose: &str,
    ) -> Result<ScopeRow, ShellExecError> {
        let purpose = purpose.trim();
        if purpose.is_empty() {
            return Err(ShellExecError::Spec(
                "a scoped shell needs a purpose".into(),
            ));
        }
        let serial = self.shell_lock(grant_id);
        let _one_at_a_time = serial.lock().await;
        let now = now_utc();
        let (host, tier, request, agent_name, earlier) = {
            let tx = self.store.begin().await?;
            let (issuable, tier, mode) = self.shell_grant(&tx, agent, grant_id, now).await?;
            if mode != ShellMode::Umbrella {
                return Err(ShellExecError::Refused(format!(
                    "only an umbrella shell has scoped shells (this one is {mode})"
                )));
            }
            let g = issuable.grant().clone();
            Self::within_budget(&tx, g.id).await?;
            if shell_scopes::count_open(&tx, g.id).await? >= shell_scopes::MAX_OPEN {
                return Err(ShellExecError::Refused(format!(
                    "at most {} scoped shells are open at once: close one first",
                    shell_scopes::MAX_OPEN
                )));
            }
            let request = agent_auth_store::requests::get(&tx, g.request_id)
                .await?
                .ok_or(ShellExecError::NotFound)?
                .into_row();
            let name = agent_auth_store::agents::get(&tx, agent)
                .await?
                .map_or_else(|| "?".to_owned(), |a| a.name);
            let earlier = shell_scopes::purposes(&tx, g.id, 20).await?;
            tx.commit().await?;
            (g.resource, tier, request, name, earlier)
        };
        let verdict = match &self.watcher {
            None => None,
            Some(w) => {
                w.scope_fits(
                    &agent_name,
                    &host,
                    tier.as_str(),
                    &request.justification,
                    &earlier,
                    purpose,
                )
                .await
            }
        };
        let summary = match verdict {
            Some((true, summary)) => summary,
            Some((false, why)) => {
                let ended = self
                    .count_refusal(grant_id, RefusalKind::Scope, false)
                    .await?;
                self.notifier()
                    .shell_event(&request, ShellEvent::ScopeRefused { purpose, why: &why })
                    .await;
                let mut text = format!("the umbrella's guard refused that purpose: {why}");
                if let Some(e) = ended {
                    text.push_str(&format!("; {e}"));
                    self.end_shell(grant_id, &e).await;
                }
                return Err(ShellExecError::Refused(text));
            }
            None => {
                let why =
                    "the guard could not be asked (umbrella shells fail closed); try again shortly";
                self.notifier()
                    .shell_event(&request, ShellEvent::ScopeRefused { purpose, why })
                    .await;
                return Err(ShellExecError::Refused(why.to_owned()));
            }
        };
        let tx = self.store.begin().await?;
        let (issuable, _, mode) = self.shell_grant(&tx, agent, grant_id, now_utc()).await?;
        if mode != ShellMode::Umbrella {
            return Err(ShellExecError::Refused("that shell has changed".into()));
        }
        if shell_scopes::count_open(&tx, grant_id).await? >= shell_scopes::MAX_OPEN {
            return Err(ShellExecError::Refused(format!(
                "at most {} scoped shells are open at once: close one first",
                shell_scopes::MAX_OPEN
            )));
        }
        let scope = shell_scopes::open(
            &tx,
            &issuable,
            ScopeId::new(),
            &cut(purpose, 2000),
            &cut(&summary, 1000),
            now_utc(),
        )
        .await?;
        drop(issuable);
        tx.commit().await?;
        self.notifier()
            .shell_event(&request, ShellEvent::ScopeOpened { scope: &scope })
            .await;
        Ok(scope)
    }

    /// Close one of the caller's scoped shells. False if it was not open.
    pub async fn close_scope(
        &self,
        agent: AgentId,
        grant_id: GrantId,
        scope_id: ScopeId,
    ) -> Result<bool, ShellExecError> {
        let serial = self.shell_lock(grant_id);
        let _one_at_a_time = serial.lock().await;
        let tx = self.store.begin().await?;
        let Some(scope) = shell_scopes::get_owned(&tx, agent, scope_id).await? else {
            return Err(ShellExecError::NotFound);
        };
        if scope.grant_id != grant_id {
            return Err(ShellExecError::NotFound);
        }
        let closed = shell_scopes::close(&tx, grant_id, scope_id, now_utc()).await?;
        let request = match closed {
            true => match grants::get_owned(&tx, agent, grant_id).await? {
                Some(g) => agent_auth_store::requests::get(&tx, g.request_id)
                    .await?
                    .map(agent_auth_store::requests::AnyRequest::into_row),
                None => None,
            },
            false => None,
        };
        tx.commit().await?;
        if let Some(request) = request {
            self.notifier()
                .shell_event(&request, ShellEvent::ScopeClosed { scope: &scope })
                .await;
        }
        Ok(closed)
    }

    async fn reload(&self, job: JobId) -> Result<Option<JobRow>, StoreError> {
        let tx = self.store.begin().await?;
        let j = store::get(&tx, job).await?;
        tx.commit().await?;
        Ok(j)
    }

    /// Have the watcher look at a command that is now running: a task of
    /// its own, and only ever a message to the operator.
    pub(crate) fn watch(&self, job: JobId) {
        if self.watcher.is_none() || !self.policy.platforms().hostexec.watch {
            return;
        }
        let Some(me) = self.self_arc() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = me.watched(job).await {
                tracing::warn!(job = %job, "watching failed: {e}");
            }
        });
    }

    async fn watched(self: Arc<Self>, job_id: JobId) -> Result<(), StoreError> {
        let Some(watcher) = &self.watcher else {
            return Ok(());
        };
        // Started in a provisioning transaction that may not have
        // committed yet.
        let mut found = None;
        for _ in 0..10 {
            let tx = self.store.begin().await?;
            found = store::get(&tx, job_id).await?;
            tx.commit().await?;
            if found.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let Some(job) = found else {
            return Ok(());
        };
        let tx = self.store.begin().await?;
        let agent = agent_auth_store::agents::get(&tx, job.agent_id).await?;
        let request = agent_auth_store::requests::get(&tx, job.request_id)
            .await?
            .map(agent_auth_store::requests::AnyRequest::into_row);
        // A general shell's watcher holds it to no purpose.
        let general = match job.grant_id {
            Some(g) => agent_auth_store::grants::get(&tx, g)
                .await?
                .is_some_and(|g| {
                    matches!(
                        g.authority,
                        Authority::Hostexec(HostexecAuthority::Shell {
                            mode: ShellMode::General,
                            ..
                        })
                    )
                }),
            None => false,
        };
        let earlier: Vec<Vec<String>> = match job.shell_id {
            Some(shell) => store::earlier_in_shell(&tx, shell, job.id)
                .await?
                .iter()
                .map(argv_of)
                .collect(),
            None => Vec::new(),
        };
        tx.commit().await?;
        let Some(request) = request else {
            return Ok(());
        };
        let argv = argv_of(&job.spec);
        let verdict = watcher
            .assess(&Watched {
                agent: agent.as_ref().map_or("?", |a| a.name.as_str()),
                host: &job.host,
                tier: job.tier.as_str(),
                purpose: &request.justification,
                earlier: &earlier,
                argv: &argv,
                general,
            })
            .await;
        if let Some((Level::Alarming, summary)) = verdict {
            tracing::warn!(job = %job.id, host = %job.host, "watch: {summary}");
            self.notifier()
                .watch_alert(
                    &request,
                    &job,
                    &format!("watch ({}, advisory): {summary}", watcher.model),
                )
                .await;
        }
        Ok(())
    }
}

/// What a spec runs, for the watcher: the argv, or for a template its name
/// and parameters (daemons bug 10: the Python saw `[]` for templates).
fn argv_of(spec: &Value) -> Vec<String> {
    if let Some(Value::Array(argv)) = spec.get("argv") {
        return argv
            .iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect();
    }
    let mut out = Vec::new();
    if let Some(t) = spec.get("template").and_then(Value::as_str) {
        out.push(format!("template:{t}"));
        if let Some(Value::Object(params)) = spec.get("params") {
            for (k, v) in params {
                out.push(format!("{k}={}", v.as_str().unwrap_or("")));
            }
        }
    }
    out
}
