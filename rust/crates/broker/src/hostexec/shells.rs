//! Shell commands (spec §10.6) and the watcher's hook (§10.8).

use std::sync::Arc;

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::hostexec::{SpecFields, make_spec};
use agent_auth_core::{AgentId, Authority, GrantId, JobId, Platform};

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
use agent_auth_store::grants::{self, IssuableGrant, NotIssuable};
use agent_auth_store::hostexec::{self as store, JobRow, JobStatus, NewJob};
use agent_auth_store::{StoreError, flags};
use agent_auth_wire::hostexec::ShellExecBody;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::watcher::{Level, Watched};
use super::{CALL_TIMEOUT, HostExec};
use crate::notify::Notify as _;

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
    ) -> Result<(IssuableGrant<'t>, agent_auth_core::Tier), ShellExecError> {
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
        let Authority::Hostexec(HostexecAuthority::Shell { tier }) = g.authority else {
            return Err(ShellExecError::NotFound);
        };
        if flags::locked(tx, &g.resource).await? {
            return Err(ShellExecError::Refused("locked down".into()));
        }
        Ok((grant, tier))
    }

    /// One command in an open shell: shown to the operator before it is
    /// sent, and not sent if that fails (INV-31). The grant is checked
    /// again after the operator was shown it, in the transaction that
    /// writes the job and holds its locks while the host is asked, so a
    /// revoke, a containment, a closed delegation thread or a lockdown that
    /// landed meanwhile stops it (security review 2026-10).
    pub async fn shell_exec(
        &self,
        agent: AgentId,
        grant_id: GrantId,
        body: &ShellExecBody,
    ) -> Result<JobRow, ShellExecError> {
        let now = OffsetDateTime::now_utc();
        let (grant, tier, request) = {
            let tx = self.store.begin().await?;
            let (issuable, tier) = self.shell_grant(&tx, agent, grant_id, now).await?;
            let grant = issuable.grant().clone();
            let request = agent_auth_store::requests::get(&tx, grant.request_id)
                .await?
                .ok_or(ShellExecError::NotFound)?
                .into_row();
            tx.commit().await?;
            (grant, tier, request)
        };
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
        // Before dispatch, and failing closed: a command nobody was shown
        // does not run.
        let shown = self
            .notifier()
            .shell_command(&request, &new_job.to_row())
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
        if let Err(e) = self.shell_grant(&tx, agent, grant_id, now_utc()).await {
            drop(tx);
            return Err(e);
        }
        let job = store::insert(&tx, &new_job).await?;
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

    async fn reload(&self, job: JobId) -> Result<Option<JobRow>, StoreError> {
        let tx = self.store.begin().await?;
        let j = store::get(&tx, job).await?;
        tx.commit().await?;
        Ok(j)
    }

    /// Have the watcher look at a command that is now running: a task of
    /// its own, and only ever a message to the operator.
    pub(crate) fn watch(&self, job: JobId) {
        if self.watcher.is_none() {
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
