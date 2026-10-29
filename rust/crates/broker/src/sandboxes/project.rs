//! Platform `sandbox`: access to another project's files inside an agent
//! VM (sandboxd spec §2.7).
//!
//! capability `project.read` | `project.write`, resource = the target
//! project. Requested by a project's agent for its own project's unix
//! user; the sandbox daemon applies it as ACLs (and removes them at
//! revoke), answering over the daemon channel. `project.write` is
//! sensitive (always a human).

use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::authority::ProjectAccess;
use agent_auth_core::names::SandboxProject;
use agent_auth_core::pyfmt::repr;
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::daemon::Role;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::daemons::{self, DaemonRole, DaemonRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::PlatformCatalog;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::Sandboxes;
use crate::provisioners::{
    Credential, CredentialKind, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

/// A call to the daemon waits this long (the hub's default).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The best-effort revoke after a grant call that timed out.
pub const UNDO_TIMEOUT: Duration = Duration::from_secs(10);

/// The `sandbox` provisioner (an `AnyProvisioner` variant).
#[derive(Debug, Clone)]
pub struct SandboxProvisioner {
    pub sandboxes: Arc<Sandboxes>,
    /// How long `project.grant`/`project.revoke` wait for the daemon.
    pub call_timeout: Duration,
}

impl SandboxProvisioner {
    #[must_use]
    pub fn new(sandboxes: Arc<Sandboxes>) -> SandboxProvisioner {
        SandboxProvisioner {
            sandboxes,
            call_timeout: CALL_TIMEOUT,
        }
    }

    /// The grant's agent and its agent VM.
    async fn daemon(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
    ) -> Result<(AgentRow, DaemonRow), ProvisionError> {
        let store = |e: StoreError| ProvisionError::failed(e.to_string());
        let agent = agents::get(tx, grant.agent_id).await.map_err(store)?;
        let daemon = match agent.as_ref().and_then(|a| a.sandbox_id) {
            Some(id) => daemons::get(tx, id).await.map_err(store)?,
            None => None,
        };
        match (agent, daemon) {
            (Some(a), Some(d)) if d.role == DaemonRole::Sandbox => Ok((a, d)),
            _ => Err(ProvisionError::failed(super::agents::NO_LONGER_IN_VM)),
        }
    }

    async fn call(
        &self,
        daemon: &DaemonRow,
        payload: Value,
        timeout: Duration,
    ) -> Result<Map<String, Value>, crate::daemons::CallError> {
        let Value::Object(m) = payload else {
            return Ok(Map::new());
        };
        self.sandboxes
            .hub
            .call(Role::Sandbox, &daemon.name, m, timeout)
            .await
    }
}

fn access_of(grant: &GrantRow) -> &'static str {
    match &grant.authority {
        Authority::Sandbox {
            access: ProjectAccess::Write,
        } => "project.write",
        _ => "project.read",
    }
}

impl Provisioner for SandboxProvisioner {
    fn platform(&self) -> Platform {
        Platform::Sandbox
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let refuse = |m: String| Ok(Err(Refused(m)));
        let Authority::Sandbox { access } = &spec.authority else {
            return refuse("sandbox capability must be one of project.read, project.write".into());
        };
        let agent = spec.agent;
        let Some(own) = agent
            .project
            .as_deref()
            .filter(|_| agent.sandbox_id.is_some())
        else {
            return refuse("only a project's agent in an agent VM can ask for this".into());
        };
        let target = spec.resource.trim().to_lowercase();
        if SandboxProject::parse(&target).is_err() {
            return refuse(format!("invalid project name {}", repr(&target)));
        }
        if target == own {
            return refuse("that's your own project".into());
        }
        let verb = match access {
            ProjectAccess::Read => "reads",
            ProjectAccess::Write => "WRITES",
        };
        let note = format!("{verb} project {target} from project {own}");
        Ok(Ok(Validated {
            resource: target,
            authority: spec.authority.clone(),
            notes: vec![note],
        }))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let g = grant.grant();
        let (agent, daemon) = self.daemon(tx, g).await?;
        let project = agent.project.clone().unwrap_or_default();
        let access = access_of(g);
        let host = daemon.name.clone();
        let called = self
            .call(
                &daemon,
                json!({"type": "project.grant", "grant_id": g.id.to_string(), "project": project,
                       "target": g.resource, "access": access}),
                self.call_timeout,
            )
            .await;
        if let Err(e) = called {
            if e.timed_out {
                // The daemon may still apply it (B-7): take it back, so a
                // grant that failed here leaves no ACL there. An unknown
                // grant id's revoke is a no-op on the daemon.
                let me = self.clone();
                let undo = json!({"type": "project.revoke", "grant_id": g.id.to_string(),
                                  "project": project, "target": g.resource});
                tokio::spawn(async move {
                    if let Err(e) = me.call(&daemon, undo, UNDO_TIMEOUT).await {
                        tracing::warn!(sandbox = %daemon.name, "undoing a timed-out project.grant failed: {e}");
                    }
                });
            }
            return Err(ProvisionError::failed(format!("sandbox {host}: {e}")));
        }
        Ok(json!({"project": project, "target": g.resource, "access": access}))
    }

    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        let (agent, daemon) = self.daemon(tx, grant).await?;
        self.call(
            &daemon,
            json!({"type": "project.revoke", "grant_id": grant.id.to_string(),
                   "project": agent.project, "target": grant.resource}),
            self.call_timeout,
        )
        .await
        // Retried by the scheduler until the daemon answers.
        .map_err(|e| ProvisionError::failed(format!("sandbox {}: {e}", daemon.name)))?;
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let g = grant.grant();
        Ok(Credential {
            note: Some(format!(
                "{} on /var/lib/sandbox/projects/{} is applied to your project's user; it ends \
                 with the grant.",
                access_of(g),
                g.resource
            )),
            ..Credential::of(CredentialKind::ProjectAccess)
        })
    }

    fn catalog(&self, agent: &AgentRow) -> Option<Value> {
        if agent.sandbox_id.is_none() || agent.project.is_none() {
            return None;
        }
        let mut c = PlatformCatalog::new(
            Platform::Sandbox,
            "project.read | project.write (write: always a human)",
            "<another project in this agent VM>",
        );
        c.capabilities = Some(vec!["project.read".into(), "project.write".into()]);
        serde_json::to_value(c).ok()
    }
}
