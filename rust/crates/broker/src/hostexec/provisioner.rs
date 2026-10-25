//! Platform `hostexec` (spec §10): a command, a template, or a time-boxed
//! shell on a host, run by that host's hostd.
//!
//! ```text
//! capability "run"         scope {"tier", "argv", "cwd"?, "env"?, "timeout"?, "stdin"?}
//! capability "tpl.<name>"  scope {"tier", "params", "cwd"?, ...}
//! capability "shell"       scope {"tier"}   (duration = the grant's)
//! resource                 the host
//! ```
//!
//! A run/tpl grant is one execution, started when the grant is provisioned;
//! a refusal by the host fails provisioning with the host's reason.

use std::sync::Arc;

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::hostexec::{CommandSpec, ShellSpec};
use agent_auth_core::{Authority, DecisionSource, JobId, Platform};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::hostexec::{self as store, JobStatus, NewJob};
use agent_auth_store::{StoreError, Tx};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{CALL_TIMEOUT, HostExec, KILL_RETRY, SHORT_CALL_TIMEOUT, job_out, tail};
use crate::provisioners::{
    Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

/// The hostexec provisioner (an `AnyProvisioner` variant).
#[derive(Debug, Clone)]
pub struct HostexecProvisioner {
    pub hostexec: Arc<HostExec>,
}

fn failed(host: &str, e: impl std::fmt::Display) -> ProvisionError {
    ProvisionError::failed(format!("{host} refused: {e}"))
}

impl HostExec {
    /// Provision a hostexec grant: start its one job, or open its shell.
    /// Every write goes through the provisioning transaction (`tx`), which
    /// holds the grant: a separate one would wait for it (the job row's
    /// foreign key) while it waits for this. A result that arrives before
    /// that transaction commits is retried briefly (`results`).
    pub async fn start(&self, tx: &Tx<'_>, grant: &GrantRow) -> Result<Value, ProvisionError> {
        let host = grant.resource.clone();
        let Authority::Hostexec(h) = &grant.authority else {
            return Err(failed(&host, "not a host command"));
        };
        let request = agent_auth_store::requests::get(tx, grant.request_id)
            .await
            .map_err(|e| failed(&host, e))?
            .ok_or_else(|| failed(&host, "no such request"))?
            .into_row();
        if let HostexecAuthority::Shell { tier } = h {
            let duration = request
                .approved_duration_secs
                .ok_or_else(|| failed(&host, "the shell has no approved duration"))?;
            let spec = ShellSpec::new(&host, *tier, duration).map_err(|e| failed(&host, e))?;
            let data = self
                .call(
                    &host,
                    json!({"type": "shell.open", "shell_id": request.id.to_string(), "spec": spec.to_json()}),
                    CALL_TIMEOUT,
                )
                .await
                .map_err(|e| failed(&host, e))?;
            return Ok(json!({"shell_id": request.id.to_string(), "host": host,
                             "tier": tier.as_str(), "expires_at": data.get("expires_at")}));
        }
        let spec = CommandSpec::from_authority(&host, h).map_err(|e| failed(&host, e))?;
        let spec_json = spec.to_json();
        let job_id = JobId::for_request(request.id);
        store::insert(
            tx,
            &NewJob {
                id: job_id,
                grant_id: Some(grant.id),
                request_id: request.id,
                agent_id: grant.agent_id,
                host: &host,
                tier: spec.tier(),
                shell_id: None,
                spec: &spec_json,
                now: OffsetDateTime::now_utc(),
            },
        )
        .await
        .map_err(|e| failed(&host, e))?;
        let evidence = HostExec::evidence(&request);
        let started = self
            .call(
                &host,
                json!({"type": "job.start", "job_id": job_id.to_string(), "spec": spec_json,
                       "evidence": evidence}),
                CALL_TIMEOUT,
            )
            .await;
        match started {
            Ok(data) => {
                let via = data.get("via").and_then(Value::as_str);
                store::set_status(tx, job_id, &host, JobStatus::Running, None, via)
                    .await
                    .map_err(|e| failed(&host, e))?;
                let window = evidence.get("window").and_then(Value::as_bool) == Some(true);
                if request.decision_source != Some(DecisionSource::Human) || window {
                    // Nobody looked at this one command: a rule, a window or
                    // the reviewer let it through.
                    self.watch(job_id);
                }
                Ok(json!({"job_id": job_id.to_string(), "host": host}))
            }
            Err(e) if e.timed_out => {
                // Daemons bug 2: no answer is not a refusal — the host may
                // have started it. The row stays `starting` (its result is
                // stored if it comes; else it becomes `lost`), the host is
                // told to stop it, and provisioning fails.
                tracing::warn!(job = %job_id, host = %host, "no answer to job.start; killing it to be safe");
                if let Some(me) = self.self_arc() {
                    let me_host = host.clone();
                    tokio::spawn(async move { me.kill_until_acked(&me_host, job_id).await });
                }
                Err(failed(
                    &host,
                    format!("{e}; the host was told to stop the job in case it started"),
                ))
            }
            Err(e) => {
                store::set_status(
                    tx,
                    job_id,
                    &host,
                    JobStatus::Refused,
                    Some(&e.message),
                    None,
                )
                .await
                .map_err(|e| failed(&host, e))?;
                self.job_events.notify(&job_id);
                Err(failed(&host, e))
            }
        }
    }

    /// `job.kill` until hostd answers (it then has stopped the job, or
    /// never had it), or the job's row says it ended; every
    /// [`KILL_RETRY`] for up to a day.
    pub(crate) async fn kill_until_acked(&self, host: &str, job: JobId) {
        let deadline = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(86_400))
            .unwrap_or_else(tokio::time::Instant::now);
        while tokio::time::Instant::now() < deadline {
            let acked = self
                .call(
                    host,
                    json!({"type": "job.kill", "job_id": job.to_string()}),
                    SHORT_CALL_TIMEOUT,
                )
                .await
                .is_ok();
            if acked {
                return;
            }
            let ended = async {
                let tx = self.store.begin().await?;
                let j = store::get(&tx, job).await?;
                tx.commit().await?;
                Ok::<_, StoreError>(j)
            }
            .await
            .ok()
            .flatten()
            .is_some_and(|j| !matches!(j.status, JobStatus::Starting | JobStatus::Running));
            if ended {
                return;
            }
            tokio::time::sleep(KILL_RETRY).await;
        }
    }

    /// Ending the grant ends what it started: a running job is killed, a
    /// shell is closed. Unless the host says it did, this fails, so the
    /// grant stays ACTIVE (and is expired now) and the revoke is retried on
    /// every expiry pass until the host answers (security review 2026-10).
    pub async fn stop(&self, grant: &GrantRow) -> Result<(), ProvisionError> {
        if matches!(
            grant.authority,
            Authority::Hostexec(HostexecAuthority::Shell { .. })
        ) {
            return self
                .call(
                    &grant.resource,
                    json!({"type": "shell.close", "shell_id": grant.request_id.to_string()}),
                    SHORT_CALL_TIMEOUT,
                )
                .await
                .map(|_| ())
                .map_err(|e| {
                    ProvisionError::failed(format!(
                        "{}: the shell was not closed: {e}",
                        grant.resource
                    ))
                });
        }
        let job = async {
            let tx = self.store.begin().await?;
            let j = store::get(&tx, JobId::for_request(grant.request_id)).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(j)
        }
        .await
        .map_err(|e| ProvisionError::failed(e.to_string()))?;
        match job {
            Some(job) => self.kill(&job).await.map_err(|e| {
                ProvisionError::failed(format!("{}: the job was not killed: {e}", job.host))
            }),
            None => Ok(()),
        }
    }
}

impl Provisioner for HostexecProvisioner {
    fn platform(&self) -> Platform {
        Platform::Hostexec
    }

    async fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        self.hostexec
            .validate(tx, &spec.resource, &spec.authority)
            .await
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        self.hostexec.start(tx, grant.grant()).await
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        self.hostexec.stop(grant).await
    }

    async fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let g = grant.grant();
        if let Authority::Hostexec(HostexecAuthority::Shell { tier }) = &g.authority {
            return Ok(Credential {
                kind: "hostexec_shell".into(),
                value: Some(agent_auth_crypto::Secret::new(g.id.to_string())),
                expires_at: Some(g.expires_at),
                note: Some(format!(
                    "A {tier} shell on {}. Run commands with host_shell_exec(grant_id, argv) — one \
                     at a time, each shown to the operator before it runs — and end it with \
                     host_shell_close(grant_id).",
                    g.resource
                )),
                ..Credential::default()
            });
        }
        let job = store::get(tx, JobId::for_request(g.request_id))
            .await
            .map_err(|e| ProvisionError::failed(e.to_string()))?
            .ok_or_else(|| ProvisionError::failed("no job was started for this grant"))?;
        let out = job_out(&job, false);
        let mut summary = serde_json::to_value(&out).unwrap_or_else(|_| json!({}));
        if let Value::Object(m) = &mut summary {
            m.remove("output");
            m.insert("output_tail".into(), json!(tail(job.output.as_deref())));
        }
        Ok(Credential {
            kind: "hostexec_job".into(),
            value: Some(agent_auth_crypto::Secret::new(summary.to_string())),
            note: Some(format!(
                "The command ran once; this grant does not run it again. Full output: \
                 host_job(\"{}\") / GET /v1/hostexec/jobs/{} (which also waits while it runs).",
                job.id, job.id
            )),
            ..Credential::default()
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        // The catalog's hosts list comes from `HostExec::hosts` (the spine's
        // catalog route calls it); nothing platform-level here.
        None
    }
}
