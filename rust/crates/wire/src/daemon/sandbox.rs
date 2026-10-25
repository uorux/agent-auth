//! The broker ↔ sandboxd channel (sandboxd spec §3).

use std::collections::BTreeMap;

use agent_auth_core::{AgentId, GrantId};
use serde::{Deserialize, Serialize};

use crate::daemon::channel::{CallId, ChannelMessage, Heartbeat, Reply};
use crate::daemon::host::Lockdown;
use crate::secret::WireSecret;
use crate::text::{BoundedVec, Text};

/// What the broker sends an agent VM's daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BrokerToSandbox {
    /// An agent's API key for the VM to run it with (answered `key.ack`).
    #[serde(rename = "key")]
    Key(KeyDelivery),
    /// Apply a cross-project grant (a call).
    #[serde(rename = "project.grant")]
    ProjectGrant(ProjectGrant),
    /// Remove one (a call).
    #[serde(rename = "project.revoke")]
    ProjectRevoke(ProjectRevoke),
    #[serde(rename = "lockdown")]
    Lockdown(Lockdown),
    #[serde(rename = "unlock")]
    Unlock(SandboxUnlock),
    /// The complete set of this VM's agents that are held.
    #[serde(rename = "agents.contained")]
    AgentsContained(AgentsContained),
}

impl ChannelMessage for BrokerToSandbox {
    const TYPES: &'static [&'static str] = &[
        "key",
        "project.grant",
        "project.revoke",
        "lockdown",
        "unlock",
        "agents.contained",
    ];
}

impl BrokerToSandbox {
    #[must_use]
    pub fn call_id(&self) -> Option<&CallId> {
        match self {
            BrokerToSandbox::Key(m) => m.call_id.as_ref(),
            BrokerToSandbox::ProjectGrant(m) => m.call_id.as_ref(),
            BrokerToSandbox::ProjectRevoke(m) => m.call_id.as_ref(),
            BrokerToSandbox::Lockdown(m) => m.call_id.as_ref(),
            BrokerToSandbox::Unlock(m) => m.call_id.as_ref(),
            BrokerToSandbox::AgentsContained(m) => m.call_id.as_ref(),
        }
    }
}

/// What an agent VM's daemon sends the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SandboxToBroker {
    #[serde(rename = "heartbeat")]
    Heartbeat(Heartbeat),
    #[serde(rename = "reply")]
    Reply(Reply),
    /// The key is persisted: the broker deletes its pending copy.
    #[serde(rename = "key.ack")]
    KeyAck(KeyAck),
    /// An agent's key was refused (401): mint it a new one.
    #[serde(rename = "key.rotate")]
    KeyRotate(KeyRotate),
}

impl ChannelMessage for SandboxToBroker {
    const TYPES: &'static [&'static str] = &["heartbeat", "reply", "key.ack", "key.rotate"];
}

/// `key`: the only place a plaintext agent key travels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDelivery {
    pub agent_id: AgentId,
    pub name: Text<1, 128>,
    pub runtime: Option<Text<0, 64>>,
    pub project: Option<Text<0, 64>>,
    pub api_key: WireSecret<512>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// Which way a project grant reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectAccessName {
    #[serde(rename = "project.read")]
    Read,
    #[serde(rename = "project.write")]
    Write,
}

/// `project.grant`: `project`'s agents get `access` to `target`'s files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGrant {
    pub grant_id: GrantId,
    pub project: Text<1, 64>,
    pub target: Text<1, 64>,
    pub access: ProjectAccessName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `project.revoke` (only the grant id is used).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRevoke {
    pub grant_id: GrantId,
    pub project: Text<1, 64>,
    pub target: Text<1, 64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `unlock` to a sandbox: no proof (the broker's lock was the only one).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxUnlock {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `agents.contained`: the names, replacing the previous set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsContained {
    pub agents: BoundedVec<Text<1, 128>, 0, 10_000>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAck {
    pub agent_id: AgentId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotate {
    pub name: Text<1, 128>,
}

/// sandboxd's heartbeat status (sandboxd spec §4.10), read leniently.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxStatus {
    pub version: Option<String>,
    pub role: Option<String>,
    pub host: Option<String>,
    pub agents: u32,
    pub projects: u32,
    /// Non-closed conversations by state.
    pub conversations: BTreeMap<String, u32>,
    pub lockdown: bool,
    pub processes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
