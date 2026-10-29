//! What the bot needs from other parts of the broker, as narrow
//! interfaces (they are not merged yet; main attaches the real ones):
//!
//! - [`RequestOps`]: the spine's `RequestService::decide` (every state
//!   check — already resolved, concurrent change, the TOTP gate, platform
//!   ceilings on an edited resource or scope — is the service's; the bot
//!   never writes request status itself, INV-A3), and revoking a grant
//!   (End shell).
//! - [`ContainmentOps`]: the spine's containment service.
//! - [`HostsOps`]: hostexec's view of a host's state, for the card's host
//!   line.
//!
//! Each takes a [`HumanDecider`], which only an authenticated human surface
//! makes (here: an interaction from the configured owner).

use agent_auth_core::durations::DurationSecs;
use agent_auth_core::{GrantId, HumanApproval, RequestId};
use agent_auth_store::lockdown::ContainmentEntry;
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleAction;
use futures::future::BoxFuture;
use serde_json::{Map, Value};

use crate::auth::HumanDecider;

/// A human's decision on a request (the Python's `HumanDecision`, minus
/// `decided_by`, which is the [`HumanDecider`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HumanDecision {
    pub approve: bool,
    pub reason: String,
    /// `None`: the requested duration, capped by policy.
    pub duration_secs: Option<DurationSecs>,
    pub resource_override: Option<String>,
    pub scope_override: Option<Map<String, Value>>,
    /// A persistent rule saved with the decision. Breadth widens the
    /// resource only (`rule_resource_pattern`); the approved authority is
    /// pinned unless `rule_any_authority`.
    pub rule_action: Option<RuleAction>,
    pub rule_resource_pattern: Option<String>,
    pub rule_any_authority: bool,
    /// hostexec: a TOTP code for the host's direct secret, typed by the
    /// human; passed to the host by the platform's gate, never stored.
    pub totp: Option<String>,
}

/// The service refused (the Python's `TransitionError` text).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OpError(pub String);

pub trait RequestOps: Send + Sync {
    /// `RequestService::decide`: the request after the decision.
    /// `approval` is the owner's attestation for this request, present
    /// exactly when `decision.approve` (made by the bot after the owner
    /// check; the store's `Approval::human` takes it).
    fn decide<'a>(
        &'a self,
        who: &'a HumanDecider,
        request: RequestId,
        decision: HumanDecision,
        approval: Option<HumanApproval>,
    ) -> BoxFuture<'a, Result<RequestRow, OpError>>;

    /// `RequestService::revoke_grant`.
    fn revoke_grant<'a>(
        &'a self,
        who: &'a HumanDecider,
        grant: GrantId,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), OpError>>;
}

/// What a containment did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contained {
    pub id: String,
    pub agents: usize,
    pub grants_revoked: usize,
}

pub trait ContainmentOps: Send + Sync {
    /// `ContainmentService.contain(match, reason, by, source="operator")`.
    /// `allow_all` is the `everyone` option: a match holding every agent
    /// is refused without it.
    fn contain<'a>(
        &'a self,
        who: &'a HumanDecider,
        r#match: Value,
        reason: &'a str,
        allow_all: bool,
    ) -> BoxFuture<'a, Result<Contained, OpError>>;

    /// `ContainmentService.lift(entry, by)`: one entry, or every one
    /// (`None`). The entries lifted.
    fn lift<'a>(
        &'a self,
        who: &'a HumanDecider,
        entry: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ContainmentEntry>, OpError>>;
}

pub trait HostsOps: Send + Sync {
    /// The host's status entry from `hostexec.hosts()`, if it is known.
    fn host(&self, name: &str) -> BoxFuture<'_, Option<Value>>;
}
