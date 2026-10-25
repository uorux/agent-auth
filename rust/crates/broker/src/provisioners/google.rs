//! Google Workspace: a stub (provisioners spec §10). Decisions are recorded;
//! no credential is minted (the credential route answers 501).

use agent_auth_core::{Authority, Platform};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::PlatformCatalog;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::common::{repr, repr_list};
use super::{Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated};

/// Sorted.
const KNOWN: [&str; 4] = [
    "calendar.read",
    "calendar.write",
    "drive.read",
    "gmail.read",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct GoogleProvisioner;

impl Provisioner for GoogleProvisioner {
    fn platform(&self) -> Platform {
        Platform::Google
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let action = match &spec.authority {
            Authority::Google { action } => action.as_str(),
            _ => "",
        };
        if !KNOWN.contains(&action) {
            return Ok(Err(Refused(format!(
                "unknown google capability {}; known: {}",
                repr(action),
                repr_list(&KNOWN)
            ))));
        }
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: spec.authority,
            notes: vec![
                "google provisioning is a stub: decision recorded, no credential minted".to_owned(),
            ],
        }))
    }

    async fn provision<'t>(
        &self,
        _tx: &'t Tx<'_>,
        _grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        Ok(json!({"stub": true}))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        _grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        Err(ProvisionError::NotImplemented)
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(
            Platform::Google,
            "<calendar.read | gmail.read | ...>",
            "<calendar id / label / folder>",
        );
        c.capabilities = Some(KNOWN.iter().map(|s| (*s).to_owned()).collect());
        serde_json::to_value(c).ok()
    }
}
