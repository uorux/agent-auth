//! The a2a platform (`provisioners/a2a.py`): check-based grants. The active
//! grant row is the artifact; provision and revoke do nothing external,
//! and the thread layer enforces the grant on every open and send.
//! Convention: capability `talk`, resource the responder's name, scope
//! `{"topic": <glob>}` or empty.

use agent_auth_core::containment::AgentKind;
use agent_auth_core::pyfmt::repr;
use agent_auth_core::{Authority, Platform};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant};
use agent_auth_store::{StoreError, Tx};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::provisioners::{
    Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

#[derive(Debug, Default)]
pub struct A2aProvisioner;

impl Provisioner for A2aProvisioner {
    fn platform(&self) -> Platform {
        Platform::A2a
    }

    /// The target must exist, be enabled, not be the requester, and be a
    /// service agent (a2a INV-4). Zones are checked before this, by the
    /// request service.
    async fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        if !matches!(spec.authority, Authority::A2a { .. }) {
            return Ok(Err(Refused("a2a capability must be 'talk'".to_owned())));
        }
        let target = agents::by_name(tx, &spec.resource).await?;
        let Some(target) = target.filter(|t| !t.disabled) else {
            return Ok(Err(Refused(format!(
                "unknown target agent {}",
                repr(&spec.resource)
            ))));
        };
        if target.id == spec.agent.id {
            return Ok(Err(Refused(
                "agent cannot request a2a access to itself".to_owned(),
            )));
        }
        if target.kind != AgentKind::Service {
            return Ok(Err(Refused(format!(
                "a2a targets must be service agents; {} is ephemeral and can only initiate \
                 threads itself",
                repr(&spec.resource)
            ))));
        }
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: spec.authority,
            notes: Vec::new(),
        }))
    }

    async fn provision(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        Ok(json!({"mode": "check_based"}))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        Ok(())
    }

    async fn credential(
        &self,
        _tx: &Tx<'_>,
        _grant: &IssuableGrant<'_>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        Ok(Credential {
            kind: "a2a_grant".to_owned(),
            note: Some(
                "a2a grants are check-based; open a thread via POST /v1/a2a/threads".to_owned(),
            ),
            ..Credential::default()
        })
    }

    /// Listed by the catalog route with live peers ([`super::catalog_entry`]),
    /// which needs the database.
    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        None
    }
}
