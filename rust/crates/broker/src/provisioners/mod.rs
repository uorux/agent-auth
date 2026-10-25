//! The provisioner contract and the registry of enabled platforms.
//!
//! Static dispatch: every provisioner implements [`Provisioner`] (native
//! async fns), and [`AnyProvisioner`] is an enum over them, so there are no
//! trait objects and the compiler sees every implementation.
//!
//! Contract (rust/spec/provisioners.md §1):
//! - `validate` normalizes and checks a request against hard ceilings and
//!   allowlists. It may read the database; it never does external I/O.
//!   It runs at request time and again on approval with the final
//!   (possibly human-edited) resource and authority.
//! - `provision` applies the grant externally, idempotently, for a grant
//!   row already committed in status `provisioning` (so a crash leaves
//!   evidence for the reaper). Its JSON result is stored as the grant's
//!   `provisioner_state`.
//! - `revoke` removes external access, idempotently, and must cope with an
//!   empty `provisioner_state` (an interrupted provision). An error means
//!   "retry later"; the grant stays as it was.
//! - `credential` mints or returns the credential for an [`IssuableGrant`]
//!   (the store already checked owner, status, expiry, containment and
//!   delegation).
//!
//! Every error text may reach the agent (it is appended to the request's
//! decision reason), so it never contains secrets or upstream bodies.

use agent_auth_core::{Authority, Platform};
use agent_auth_store::Tx;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant};
use serde_json::Value;
use time::OffsetDateTime;

/// What a request asks for, after `Authority::from_wire` parsed its
/// structure.
#[derive(Debug, Clone)]
pub struct RequestSpec<'a> {
    pub agent: &'a AgentRow,
    pub resource: String,
    pub authority: Authority,
}

/// A request the platform accepts, normalized, with notes for the human
/// and the LLM reviewer (merged into the request's risk notes).
#[derive(Debug, Clone, PartialEq)]
pub struct Validated {
    pub resource: String,
    pub authority: Authority,
    pub notes: Vec<String>,
}

/// Refused at validation: the request is denied with `"validator: {0}"`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

/// An external failure or a refusal to issue. Shown to the agent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionError {
    #[error("{0}")]
    Failed(String),
    /// The platform cannot issue this kind of credential (HTTP 501).
    #[error("not implemented")]
    NotImplemented,
}

impl ProvisionError {
    pub fn failed(msg: impl Into<String>) -> ProvisionError {
        ProvisionError::Failed(msg.into())
    }
}

/// What the credential route returns (`CredentialOut` on the wire: all six
/// keys always present).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credential {
    pub kind: String,
    /// The secret itself, when there is one. (Becomes `crypto::Secret` once
    /// that crate is merged.)
    pub value: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub note: Option<String>,
}

pub trait Provisioner {
    fn platform(&self) -> Platform;

    fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Result<Validated, Refused>, agent_auth_store::StoreError>> + Send;

    fn provision(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Value, ProvisionError>> + Send;

    fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<(), ProvisionError>> + Send;

    fn credential(
        &self,
        tx: &Tx<'_>,
        grant: &IssuableGrant<'_>,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Credential, ProvisionError>> + Send;

    /// This platform's entry in `GET /v1/catalog` (`None`: not listed).
    fn catalog(&self, agent: &AgentRow) -> Option<Value>;
}

/// `platform '{p}' is not enabled on this broker`
#[must_use]
pub fn not_enabled(platform: Platform) -> String {
    format!("platform '{platform}' is not enabled on this broker")
}

/// The enabled provisioners. A platform is enabled when its configuration
/// is present at startup (spec §1.3); `get` on another is an error with
/// [`not_enabled`]'s text.
#[derive(Debug, Default)]
pub struct Registry {
    enabled: Vec<AnyProvisioner>,
}

impl Registry {
    pub fn register(&mut self, p: AnyProvisioner) {
        let platform = p.platform();
        self.enabled.retain(|q| q.platform() != platform);
        self.enabled.push(p);
    }

    #[must_use]
    pub fn get(&self, platform: Platform) -> Option<&AnyProvisioner> {
        self.enabled.iter().find(|p| p.platform() == platform)
    }

    #[must_use]
    pub fn is_enabled(&self, platform: Platform) -> bool {
        self.get(platform).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AnyProvisioner> {
        self.enabled.iter()
    }
}

/// Every provisioner. Each variant's type lives in its own module
/// (`provisioners/github.rs`, ...); add a variant and a match arm per method
/// below when adding one.
#[derive(Debug)]
pub enum AnyProvisioner {
    /// Test double: accepts everything, records nothing external.
    Fake(FakeProvisioner),
    /// Check-based agent-to-agent grants (`crate::a2a::provisioner`).
    A2a(crate::a2a::provisioner::A2aProvisioner),
}

macro_rules! dispatch {
    ($self:ident, $p:ident => $e:expr) => {
        match $self {
            AnyProvisioner::Fake($p) => $e,
            AnyProvisioner::A2a($p) => $e,
        }
    };
}

impl Provisioner for AnyProvisioner {
    fn platform(&self) -> Platform {
        dispatch!(self, p => p.platform())
    }
    async fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, agent_auth_store::StoreError> {
        dispatch!(self, p => p.validate(tx, spec, now).await)
    }
    async fn provision(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        dispatch!(self, p => p.provision(tx, grant, now).await)
    }
    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        dispatch!(self, p => p.revoke(tx, grant, now).await)
    }
    async fn credential(
        &self,
        tx: &Tx<'_>,
        grant: &IssuableGrant<'_>,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        dispatch!(self, p => p.credential(tx, grant, now).await)
    }
    fn catalog(&self, agent: &AgentRow) -> Option<Value> {
        dispatch!(self, p => p.catalog(agent))
    }
}

/// A provisioner for tests: validates by passing the spec through, and
/// records provision/revoke calls so tests can assert on them.
#[derive(Debug)]
pub struct FakeProvisioner {
    pub platform: Platform,
    pub calls: std::sync::Mutex<Vec<String>>,
    /// When set, provision fails with this text.
    pub fail_provision: Option<String>,
}

impl FakeProvisioner {
    #[must_use]
    pub fn new(platform: Platform) -> FakeProvisioner {
        FakeProvisioner {
            platform,
            calls: std::sync::Mutex::new(Vec::new()),
            fail_provision: None,
        }
    }
    fn record(&self, what: String) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(what);
    }
}

impl Provisioner for FakeProvisioner {
    fn platform(&self) -> Platform {
        self.platform
    }
    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, agent_auth_store::StoreError> {
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: spec.authority,
            notes: Vec::new(),
        }))
    }
    async fn provision(
        &self,
        _tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        self.record(format!("provision {}", grant.id));
        match &self.fail_provision {
            Some(msg) => Err(ProvisionError::failed(msg.clone())),
            None => Ok(serde_json::json!({"fake": true})),
        }
    }
    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        self.record(format!("revoke {}", grant.id));
        Ok(())
    }
    async fn credential(
        &self,
        _tx: &Tx<'_>,
        grant: &IssuableGrant<'_>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        Ok(Credential {
            kind: "fake".to_owned(),
            note: Some(grant.grant().resource.clone()),
            ..Credential::default()
        })
    }
    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        None
    }
}
