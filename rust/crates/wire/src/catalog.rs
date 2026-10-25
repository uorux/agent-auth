//! `GET /v1/catalog`: what an agent may ask for (http-api §4).
//!
//! Python served it with `response_model_exclude_none`, which drops `None`
//! fields of the models (here: every optional field of [`PlatformCatalog`]
//! and [`CatalogEntry`]) but not inside plain dicts (`servers[].tools`,
//! `gateway.models` stay `null`).

use std::collections::BTreeMap;

use agent_auth_core::Platform;
use serde::{Deserialize, Serialize};

use crate::a2a::PeerEntry;
use crate::common::TierName;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogOut {
    pub platforms: Vec<PlatformCatalog>,
}

/// One platform's menu. Field order is the Python model's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformCatalog {
    pub platform: Platform,
    pub capability_hint: String,
    pub resource_hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<CatalogEntry>>,
    /// Roles requestable cluster-wide via resource `"*"` (always a human).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_ceiling: Option<BTreeMap<String, String>>,
    /// github: orgs where `create` makes a new repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_owners: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_disposition: Option<Disposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<CatalogEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<CatalogHost>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<McpServerEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayEntry>,
    /// google: the accounts (name, address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<GoogleAccountEntry>>,
    /// pool: each pool the agent may lease from, its items and who holds
    /// them now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pools: Option<Vec<PoolEntry>>,
}

impl PlatformCatalog {
    /// A platform entry with only its hints; fill the rest as needed.
    #[must_use]
    pub fn new(
        platform: Platform,
        capability_hint: impl Into<String>,
        resource_hint: impl Into<String>,
    ) -> Self {
        PlatformCatalog {
            platform,
            capability_hint: capability_hint.into(),
            resource_hint: resource_hint.into(),
            roles: None,
            cluster_roles: None,
            namespace_allowlist: None,
            repo_allowlist: None,
            permission_ceiling: None,
            create_owners: None,
            create_disposition: None,
            groups: None,
            capabilities: None,
            peers: None,
            hosts: None,
            servers: None,
            gateway: None,
            accounts: None,
            pools: None,
        }
    }
}

/// A role or group, with what policy usually does with a request for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typical_disposition: Option<Disposition>,
}

/// Resource-agnostic routing, best effort (http-api §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Disposition {
    #[serde(rename = "auto-approve")]
    AutoApprove,
    #[serde(rename = "human review")]
    HumanReview,
    #[serde(rename = "llm review")]
    LlmReview,
    #[serde(rename = "denied")]
    Denied,
}

/// hostexec: a host with a hostd, and per enabled tier whether it is armed
/// and takes shells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogHost {
    pub name: String,
    pub online: bool,
    pub lockdown: bool,
    pub tiers: BTreeMap<TierName, CatalogTier>,
    pub templates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogTier {
    pub armed: bool,
    pub shell: bool,
}

/// mcp: a server that takes this broker's tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    pub url: String,
    pub description: String,
    /// Null when the server's tools are not listed.
    pub tools: Option<Vec<String>>,
}

/// google: an account the broker holds a login for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleAccountEntry {
    pub name: String,
    pub address: String,
}

/// pool: one pool, as the agent asking sees it (items it may not hold are
/// left out).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolEntry {
    pub name: String,
    pub description: String,
    pub capacity: u32,
    pub max_per_agent: u32,
    pub items: Vec<PoolItemEntry>,
    /// The item of this pool the agent held last, if any.
    pub you_held_last: Option<String>,
}

/// pool: one item and its availability now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolItemEntry {
    pub name: String,
    pub description: String,
    /// Strings, numbers, booleans, lists of strings.
    pub properties: serde_json::Map<String, serde_json::Value>,
    /// Leased by name only, and always by a human.
    pub sensitive: bool,
    /// Holders now.
    pub in_use: u32,
    /// A slot is free now.
    pub free: bool,
    /// When the first of its holders' grants ends.
    #[serde(default, with = "crate::timestamp::option")]
    pub frees_at: Option<time::OffsetDateTime>,
    /// The agent asking holds it.
    pub yours: bool,
}

/// models: the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayEntry {
    pub name: String,
    pub url: String,
    pub models: Option<Vec<String>>,
}
