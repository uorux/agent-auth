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
//!   row already committed in status `provisioning` (a `ProvisioningGrant`
//!   loaded in the finishing transaction) (so a crash leaves
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

pub(crate) mod common;
pub mod github;
pub mod google;
pub mod http;
pub mod kubernetes;
pub mod ldap;
pub mod lldap;
pub mod mcp;
pub mod models;
pub mod pool;
#[cfg(test)]
mod pool_tests;
pub mod setup;
pub mod tokens;

pub use setup::{ConfigError, PlatformServices};

use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_store::Tx;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
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

/// What the credential route returns (`CredentialOut` on the wire: all
/// seven keys always present).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credential {
    pub kind: String,
    /// The secret itself, when there is one (or a non-secret value such as
    /// a repo URL); never printed.
    pub value: Option<Secret<String>>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub note: Option<String>,
    /// What it is for, when that is part of it (a pool item's properties).
    pub properties: Option<serde_json::Map<String, Value>>,
}

pub trait Provisioner {
    fn platform(&self) -> Platform;

    fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Result<Validated, Refused>, agent_auth_store::StoreError>> + Send;

    /// For a grant row committed PROVISIONING and loaded (locked) in this
    /// transaction (`store::grants::load_provisioning`).
    fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Value, ProvisionError>> + Send;

    fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<(), ProvisionError>> + Send;

    /// For a grant `store::grants::issuable` cleared in this transaction.
    fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
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
    Github(github::GithubProvisioner),
    Homelab(lldap::LldapProvisioner),
    Kubernetes(kubernetes::KubernetesProvisioner),
    Models(models::ModelsProvisioner),
    Mcp(mcp::McpProvisioner),
    Google(google::GoogleProvisioner),
    /// Commands on hosts (`crate::hostexec::provisioner`).
    Hostexec(crate::hostexec::provisioner::HostexecProvisioner),
    /// Google with no account configured (decisions only).
    GoogleStub(google::GoogleStubProvisioner),
    Pool(pool::PoolProvisioner),
}

macro_rules! dispatch {
    ($self:ident, $p:ident => $e:expr) => {
        match $self {
            AnyProvisioner::Fake($p) => $e,
            AnyProvisioner::A2a($p) => $e,
            AnyProvisioner::Github($p) => $e,
            AnyProvisioner::Homelab($p) => $e,
            AnyProvisioner::Kubernetes($p) => $e,
            AnyProvisioner::Models($p) => $e,
            AnyProvisioner::Mcp($p) => $e,
            AnyProvisioner::Google($p) => $e,
            AnyProvisioner::Hostexec($p) => $e,
            AnyProvisioner::GoogleStub($p) => $e,
            AnyProvisioner::Pool($p) => $e,
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
    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
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
    async fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
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
    /// `(resource, text)`: validation refuses that resource with that text.
    pub refusals: Vec<(String, String)>,
}

impl FakeProvisioner {
    #[must_use]
    pub fn new(platform: Platform) -> FakeProvisioner {
        FakeProvisioner {
            platform,
            calls: std::sync::Mutex::new(Vec::new()),
            fail_provision: None,
            refusals: Vec::new(),
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
        if let Some((_, text)) = self.refusals.iter().find(|(r, _)| *r == spec.resource) {
            return Ok(Err(Refused(text.clone())));
        }
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: spec.authority,
            notes: Vec::new(),
        }))
    }
    async fn provision<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        self.record(format!("provision {}", grant.grant().id));
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
    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        Ok(Credential {
            // A real kind, so the credential route can serve it in tests.
            kind: "a2a_grant".to_owned(),
            note: Some(grant.grant().resource.clone()),
            ..Credential::default()
        })
    }
    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        None
    }
}
