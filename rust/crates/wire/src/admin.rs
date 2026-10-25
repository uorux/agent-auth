//! The admin API (`/admin/*`; http-api §2.7) and the host and daemon
//! routes' envelopes (hostexec spec §10.7, daemon spec §3).

use std::collections::BTreeMap;

use agent_auth_core::{AgentId, DaemonId, GrantId, GrantStatus, Platform, RuleId};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::common::{AgentKind, DaemonRole, Placement, SettableKind, TierName};
use crate::duration::{DurationSecs, HostDuration};
use crate::error::ValidationError;
use crate::json::{Scope, StatusObject};
use crate::literal::True;
use crate::secret::{TotpCode, WireSecret};
use crate::text::{
    AgentNameInput, Attribute, DaemonName, ProjectOrHost, Runtime, Text, WebhookUrl,
};

/// `POST /admin/agents` (Python `AgentCreate`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    pub name: AgentNameInput,
    #[serde(default)]
    pub description: Text<0, 2000>,
    #[serde(default)]
    pub kind: SettableKind,
    #[serde(default)]
    pub webhook_url: Option<WebhookUrl>,
    #[serde(default)]
    pub lldap_username: Option<Text<0, 128>>,
    #[serde(default)]
    pub runtime: Option<Runtime>,
    #[serde(default)]
    pub project: Option<ProjectOrHost>,
    #[serde(default)]
    pub host: Option<ProjectOrHost>,
}

/// A PATCH field: absent (leave it), or set — where null and `""` both
/// clear it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Patch<T> {
    #[default]
    Keep,
    Set(Option<T>),
}

impl<T> Patch<T> {
    #[must_use]
    pub fn is_keep(&self) -> bool {
        matches!(self, Patch::Keep)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(d).map(Patch::Set)
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Patch::Keep | Patch::Set(None) => s.serialize_none(),
            Patch::Set(Some(v)) => v.serialize(s),
        }
    }
}

/// `PATCH /admin/agents/{id-or-name}/attributes`: only the fields present
/// are applied; null or `""` clears one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAttributesBody {
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub runtime: Patch<Attribute<16, true>>,
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub project: Patch<Attribute<64, true>>,
    #[serde(default, skip_serializing_if = "Patch::is_keep")]
    pub host: Patch<Attribute<64, true>>,
}

/// `POST /admin/agents/{id-or-name}/rename`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRenameBody {
    pub name: AgentNameInput,
}

/// `POST /admin/agents/{id}/set-kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetKindBody {
    pub kind: SettableKind,
}

/// `POST /admin/agents/{id}/set-webhook`: null (or `{}`) clears the webhook
/// and its secret.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetWebhookBody {
    #[serde(default)]
    pub webhook_url: Option<WebhookUrl>,
}

/// An agent as the admin sees it (Python `AgentOut`). `api_key` is set only
/// in the create and rotate-key responses, `webhook_secret` only in create,
/// rotate-webhook-secret and set-webhook. Some routes drop null fields
/// ([`AgentOut::without_nulls`]): create, rotate-webhook-secret,
/// rotate-lldap-password, set-kind, set-webhook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentOut {
    pub id: AgentId,
    pub name: String,
    pub description: String,
    pub kind: AgentKind,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub lldap_username: Option<String>,
    pub lldap_managed: bool,
    pub disabled: bool,
    #[serde(default, with = "crate::timestamp::option")]
    pub last_seen_at: Option<OffsetDateTime>,
    /// The minting agent's id.
    #[serde(default)]
    pub parent: Option<AgentId>,
    /// The agent VM's daemon id.
    #[serde(default)]
    pub sandbox: Option<DaemonId>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    pub placement: Placement,
    #[serde(default, with = "crate::timestamp::option")]
    pub lease_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub api_key: Option<WireSecret<512>>,
    #[serde(default)]
    pub webhook_secret: Option<WireSecret<512>>,
}

impl AgentOut {
    /// The JSON with null-valued keys left out (the Python's
    /// `response_model_exclude_none` routes).
    pub fn without_nulls(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.retain(|_, v| !v.is_null());
        }
        Ok(value)
    }
}

/// `POST /admin/agents/{id}/rename` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRenamed {
    pub agent: AgentOut,
    pub previous_name: String,
    /// Saved rules that named the agent and now carry the new name.
    pub rules: u64,
    /// Active a2a grants retargeted.
    pub grants: u64,
}

/// `POST /admin/agents/{id}/disable` → 200: it and its minted descendants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disabled {
    pub disabled: Vec<String>,
}

/// A saved rule's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    AutoApprove,
    AutoDeny,
}

/// `GET /admin/rules` items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOut {
    pub id: RuleId,
    pub action: RuleAction,
    pub agent_pattern: String,
    /// Null: the rule never clears delegated requests.
    pub delegator_pattern: Option<String>,
    pub platform: Platform,
    /// The pinned authority's label, or `*`.
    pub capability_pattern: String,
    pub resource_pattern: String,
    /// The pinned authority (stored form); null for any.
    pub authority: Option<Map<String, Value>>,
    pub max_duration_secs: Option<u32>,
    pub enabled: bool,
    pub created_by: String,
    pub notes: String,
}

/// `POST /admin/requests/{id}/decide`. A bad `duration` is the route's
/// string-detail 422 (`invalid duration 'x': ...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBody {
    pub approve: bool,
    #[serde(default)]
    pub reason: Text<0, 4000>,
    #[serde(default)]
    pub duration: Option<DurationSecs>,
    #[serde(default)]
    pub resource_override: Option<Text<1, 512>>,
    #[serde(default)]
    pub scope_override: Option<Scope>,
    /// hostexec: a code for the host's direct TOTP secret.
    #[serde(default)]
    pub totp: Option<TotpCode>,
}

/// `POST /admin/grants/{id}/revoke` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    pub ok: True,
    pub grant_id: GrantId,
    pub status: GrantStatus,
}

/// `GET /admin/projects` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Projects {
    pub projects: BTreeMap<String, ProjectOut>,
    /// The wiki's repo, if one is configured.
    pub wiki: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectOut {
    pub description: String,
    pub repos: Vec<String>,
    /// False for projects agents carry but policy does not declare.
    pub in_policy: bool,
    /// Its enabled agents.
    pub agents: Vec<String>,
}

/// `POST /admin/daemons/pairing-codes`. Role and name are checked by
/// [`PairingCodeCreate::identity`] so the route keeps its 400s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingCodeCreate {
    pub role: Text<0, 64>,
    pub name: Text<0, 128>,
}

impl PairingCodeCreate {
    /// The daemon identity, or the Python's 400 message.
    pub fn identity(&self) -> Result<(DaemonRole, DaemonName), ValidationError> {
        let role = match self.role.as_str() {
            "host" => DaemonRole::Host,
            "sandbox" => DaemonRole::Sandbox,
            _ => return Err(ValidationError::new("role must be one of host, sandbox")),
        };
        Ok((role, DaemonName::new(self.name.as_str())?))
    }
}

/// `POST /admin/daemons/pairing-codes` → 200. The code is shown once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingCodeOut {
    pub role: DaemonRole,
    pub name: DaemonName,
    pub code: WireSecret<64>,
    #[serde(with = "crate::timestamp")]
    pub expires_at: OffsetDateTime,
    pub broker_public_key: String,
}

/// `GET /admin/daemons` items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonOut {
    pub id: DaemonId,
    pub role: DaemonRole,
    pub name: String,
    pub fingerprint: String,
    pub online: bool,
    #[serde(default, with = "crate::timestamp::option")]
    pub paired_at: Option<OffsetDateTime>,
    #[serde(default, with = "crate::timestamp::option")]
    pub last_seen_at: Option<OffsetDateTime>,
    pub version: Option<String>,
    /// Its last heartbeat (informational only).
    pub status: Option<StatusObject>,
}

/// `GET /admin/broker-key` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerKey {
    pub broker_public_key: String,
}

/// `GET /admin/hosts` → 200.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostsOut {
    pub lockdown: LockdownFlag,
    pub hosts: Vec<HostOut>,
}

/// The broker's lockdown flag: `{}` when not locked down.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LockdownFlag {
    /// Locked host names; `*` is every host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(
        default,
        with = "crate::timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<LockdownScope>,
}

/// A paired host and what its hostd last reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostOut {
    pub name: String,
    pub online: bool,
    pub tiers: BTreeMap<TierName, crate::daemon::host::TierStatus>,
    pub lockdown: bool,
    pub templates: Vec<String>,
    pub vm: Option<crate::daemon::host::VmStatus>,
    #[serde(default)]
    pub desktop: Option<crate::daemon::host::DesktopStatus>,
}

/// `POST /admin/hosts/{name}/arm`. The code is for the host's
/// `<tier>-arm` secret; the host checks it and the duration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmBody {
    #[serde(default = "user_tier")]
    pub tier: TierName,
    #[serde(default = "one_hour")]
    pub duration: HostDuration,
    pub totp: TotpCode,
}

fn user_tier() -> TierName {
    TierName::User
}

fn one_hour() -> HostDuration {
    HostDuration::parse("1h").unwrap_or(HostDuration::MIN)
}

/// The kill switch's reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockdownScope {
    /// Every agent VM's agents lose their grants; hosts disarm and freeze
    /// their VMs.
    #[default]
    Sandboxes,
    /// Every agent's grants.
    All,
    /// One host and its VM's agents.
    Host,
}

/// `POST /admin/lockdown`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownBody {
    #[serde(default)]
    pub scope: LockdownScope,
    #[serde(default)]
    pub host: Option<DaemonName>,
    #[serde(default)]
    pub kill_vm: bool,
}

/// `POST /admin/lockdown` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownResult {
    pub scope: LockdownScope,
    pub host: Option<String>,
    /// Per `role:name`: `locked[ · vm ...]`, or why it was not reached.
    pub daemons: BTreeMap<String, String>,
    pub grants_revoked: u32,
    /// Waiting requests of the affected agents, denied.
    #[serde(default)]
    pub requests_denied: u32,
    pub threads_closed: u32,
}

/// `POST /admin/unlock`. With a host and its root-unlock code, the host's own
/// lock is lifted too.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockBody {
    #[serde(default)]
    pub host: Option<DaemonName>,
    #[serde(default)]
    pub totp: Option<TotpCode>,
}

/// `POST /admin/unlock` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockResult {
    pub host: Option<String>,
    pub daemons: BTreeMap<String, String>,
    /// What stays locked on the broker.
    pub broker_locked: Vec<String>,
}
