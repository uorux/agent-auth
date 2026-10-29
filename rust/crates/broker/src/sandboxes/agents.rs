//! Platform `agents`: minting identities in an agent VM (sandboxd spec
//! §2.5).
//!
//! capability `mint`, resource `<runtime>-<project>-<host>-sandbox`, scope
//! `{"runtime": …}` (optional; derived from the name). Only the VM's
//! orchestrator may ask (B-14), and only for its own VM's host; the name is
//! checked against the structured fields, never parsed for trust. The new
//! agent's key goes to the sandbox daemon alone. Minting an existing agent
//! of the same VM renews its lease; one whose lease ran out comes back
//! with a new key (B-8); one the operator disabled stays disabled (B-1).
//! Nothing is undone when the mint grant ends: the identity lives by its
//! lease.

use std::sync::Arc;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::sandbox::{orchestrator_name, parse_mint_name};
use agent_auth_core::{AgentId, Authority, DurationSecs, Platform};
use agent_auth_crypto::api_key;
use agent_auth_store::agents::{self, AgentRow, DisableReason, NewAgent};
use agent_auth_store::daemons::{self, DaemonRole, DaemonRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx, flags};
use agent_auth_wire::catalog::PlatformCatalog;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{QueueError, Sandboxes};
use crate::provisioners::{
    Credential, CredentialKind, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

pub const NOT_IN_VM: &str = "only agents running in an agent VM can mint identities";
pub const NOT_ORCHESTRATOR: &str = "only an agent VM's orchestrator can mint identities";
pub const LOCKED: &str = "locked down: no identities are minted until it is lifted";
pub const NO_LONGER_IN_VM: &str = "the requesting agent is no longer in an agent VM";

/// `<name> was disabled by the operator; …` (B-1).
#[must_use]
pub fn operator_disabled(name: &str) -> String {
    format!("{name} was disabled by the operator; minting it again does not re-enable it")
}

/// The `agents` provisioner (an `AnyProvisioner` variant).
#[derive(Debug, Clone)]
pub struct AgentsProvisioner {
    pub sandboxes: Arc<Sandboxes>,
    /// `platforms.agents.runtimes` (empty: minting is disabled).
    pub runtimes: Vec<String>,
    /// `platforms.agents.lease`.
    pub lease: DurationSecs,
}

/// An agent disabled in a way a renewal must not undo (B-1).
fn renewal_refused(a: &AgentRow) -> bool {
    a.disabled && a.disabled_reason != Some(DisableReason::Lease)
}

/// The requester's agent VM, if it is in one.
async fn vm_of(tx: &Tx<'_>, agent: &AgentRow) -> Result<Option<DaemonRow>, StoreError> {
    let Some(id) = agent.sandbox_id else {
        return Ok(None);
    };
    Ok(daemons::get(tx, id)
        .await?
        .filter(|d| d.role == DaemonRole::Sandbox))
}

/// The VM's orchestrator: by its name for this daemon, its VM and having
/// no parent (review #5: a runtime called `orchestrator` proves nothing).
fn is_orchestrator(agent: &AgentRow, daemon: &DaemonRow) -> bool {
    agent.name == orchestrator_name(&daemon.name)
        && agent.sandbox_id == Some(daemon.id)
        && agent.parent_agent_id.is_none()
}

/// The same without the daemon row (the catalog): the broker sets `host`
/// (the daemon's name) and nobody can change it for a VM agent.
fn looks_like_orchestrator(agent: &AgentRow) -> bool {
    agent.sandbox_id.is_some()
        && agent.parent_agent_id.is_none()
        && agent
            .host
            .as_deref()
            .is_some_and(|h| agent.name == orchestrator_name(h))
}

fn iso(t: OffsetDateTime) -> String {
    agent_auth_wire::timestamp::format(t).unwrap_or_default()
}

fn queue_failed(e: QueueError) -> ProvisionError {
    match e {
        QueueError::Store(e) => ProvisionError::failed(e.to_string()),
        other => ProvisionError::failed(other.to_string()),
    }
}

impl Provisioner for AgentsProvisioner {
    fn platform(&self) -> Platform {
        Platform::Agents
    }

    async fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let refuse = |m: String| Ok(Err(Refused(m)));
        let Authority::Agents { action, runtime } = &spec.authority else {
            return refuse("agents capability must be 'mint'".into());
        };
        if action != "mint" {
            return refuse("agents capability must be 'mint'".into());
        }
        if self.runtimes.is_empty() {
            return refuse("minting is disabled (platforms.agents.runtimes is empty)".into());
        }
        let Some(daemon) = vm_of(tx, spec.agent).await? else {
            return refuse(NOT_IN_VM.into());
        };
        // B-14: a project's agent minting another project's agent would
        // cross the project boundary without a `sandbox` grant.
        if !is_orchestrator(spec.agent, &daemon) {
            return refuse(NOT_ORCHESTRATOR.into());
        }
        if flags::locked(tx, &daemon.name).await? {
            return refuse(LOCKED.into());
        }
        let minted = match parse_mint_name(&spec.resource, &self.runtimes, &daemon.name) {
            Ok(m) => m,
            Err(e) => return refuse(e),
        };
        if runtime.as_ref().is_some_and(|r| *r != minted.runtime) {
            return refuse("scope may only repeat the name's runtime".into());
        }
        if let Some(existing) = agents::by_name(tx, &minted.name).await?
            && existing.sandbox_id == Some(daemon.id)
            && renewal_refused(&existing)
        {
            return refuse(operator_disabled(&minted.name));
        }
        let note = format!(
            "mints {} ({} on project {}) in the agent VM on {}",
            minted.name, minted.runtime, minted.project, daemon.name
        );
        Ok(Ok(Validated {
            resource: minted.name,
            authority: Authority::Agents {
                action: "mint".into(),
                runtime: Some(minted.runtime),
            },
            notes: vec![note],
        }))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let g = grant.grant();
        let store = |e: StoreError| ProvisionError::failed(e.to_string());
        let parent = agents::get(tx, g.agent_id).await.map_err(store)?;
        let daemon = match &parent {
            Some(p) => vm_of(tx, p).await.map_err(store)?,
            None => None,
        };
        let (Some(parent), Some(daemon)) = (parent, daemon) else {
            return Err(ProvisionError::failed(NO_LONGER_IN_VM));
        };
        if !is_orchestrator(&parent, &daemon) {
            return Err(ProvisionError::failed(NOT_ORCHESTRATOR));
        }
        let Authority::Agents {
            runtime: Some(runtime),
            ..
        } = &g.authority
        else {
            return Err(ProvisionError::failed("the grant names no runtime"));
        };
        let minted = parse_mint_name(&g.resource, std::slice::from_ref(runtime), &daemon.name)
            .map_err(ProvisionError::failed)?;
        let name = minted.name;
        let project = minted.project.as_str().to_owned();
        let lease = now.saturating_add(self.lease.as_duration());
        let existing = agents::by_name(tx, &name).await.map_err(store)?;
        let (agent_id, outcome) = match existing {
            Some(a) => {
                if a.sandbox_id != Some(daemon.id)
                    || a.runtime.as_deref() != Some(runtime.as_str())
                    || a.project.as_deref() != Some(project.as_str())
                {
                    return Err(ProvisionError::failed(format!(
                        "{name} exists and doesn't belong to this sandbox"
                    )));
                }
                if renewal_refused(&a) {
                    return Err(ProvisionError::failed(operator_disabled(&name)));
                }
                if a.disabled {
                    // Its lease ran out: back with a new key (the old one
                    // stays dead), which also restarts its dispatcher in
                    // the VM (B-8).
                    let key = api_key::generate()
                        .map_err(|_| ProvisionError::failed("no randomness for a new key"))?;
                    if self.sandboxes.secret_box.is_none() {
                        return Err(ProvisionError::failed(super::NO_KEY_BOX));
                    }
                    if !agents::reenable_after_lease(
                        tx,
                        a.id,
                        key.key_id.as_str(),
                        key.hash.as_str(),
                        lease,
                    )
                    .await
                    .map_err(store)?
                    {
                        return Err(ProvisionError::failed(operator_disabled(&name)));
                    }
                    self.sandboxes
                        .queue_delivery(tx, a.id, daemon.id, &key, now)
                        .await
                        .map_err(queue_failed)?;
                    (a.id, "re-enabled")
                } else {
                    // Renewal: the key the sandbox holds stays valid.
                    agents::set_lease(tx, a.id, Some(lease))
                        .await
                        .map_err(store)?;
                    (a.id, "renewed")
                }
            }
            None => {
                if self.sandboxes.secret_box.is_none() {
                    return Err(ProvisionError::failed(super::NO_KEY_BOX));
                }
                let key = api_key::generate()
                    .map_err(|_| ProvisionError::failed("no randomness for a new key"))?;
                let description = format!(
                    "{runtime} on project {project} in the agent VM on {}",
                    daemon.name
                );
                let row = agents::insert(
                    tx,
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
                        parent_agent_id: Some(parent.id),
                        sandbox_id: Some(daemon.id),
                        runtime: Some(runtime),
                        project: Some(&project),
                        // Where it runs is the VM the request came through,
                        // whatever was asked (INV-5).
                        host: Some(&daemon.name),
                        placement: Placement::Sandbox,
                        lease_expires_at: Some(lease),
                        last_seen_at: Some(now),
                        now,
                    },
                )
                .await
                .map_err(store)?;
                self.sandboxes
                    .queue_delivery(tx, row.id, daemon.id, &key, now)
                    .await
                    .map_err(queue_failed)?;
                (row.id, "minted")
            }
        };
        // The daemon collects the key on its next heartbeat at the latest.
        self.sandboxes.nudge(daemon.id);
        Ok(json!({
            "agent_id": agent_id.to_string(),
            "name": name,
            "created": outcome == "minted",
            "outcome": outcome,
            "lease_expires_at": iso(lease),
        }))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        // The identity lives by its lease, not by the mint grant.
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let state = &grant.grant().provisioner_state;
        let s = |k: &str| state.get(k).and_then(Value::as_str).map(str::to_owned);
        let outcome = s("outcome").unwrap_or_else(|| {
            if state.get("created").and_then(Value::as_bool) == Some(true) {
                "minted".to_owned()
            } else {
                "renewed".to_owned()
            }
        });
        Ok(Credential {
            value: s("name").map(agent_auth_crypto::Secret::new),
            note: Some(format!(
                "{outcome}; lease until {}. Its key went to the sandbox daemon, which runs it — \
                 you never hold it.",
                s("lease_expires_at").unwrap_or_else(|| "None".to_owned())
            )),
            ..Credential::of(CredentialKind::AgentIdentity)
        })
    }

    fn catalog(&self, agent: &AgentRow) -> Option<Value> {
        // Only the VM's orchestrator may mint (B-14).
        if !looks_like_orchestrator(agent) {
            return None;
        }
        let mut c = PlatformCatalog::new(
            Platform::Agents,
            "mint",
            "<runtime>-<project>-<this host>-sandbox",
        );
        c.capabilities = Some(self.runtimes.clone());
        serde_json::to_value(c).ok()
    }
}
