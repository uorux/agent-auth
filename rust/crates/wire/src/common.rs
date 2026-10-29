//! Small types used across the API: error bodies, `{"ok": true}`, and the
//! enums that are plain strings on the wire.

use agent_auth_core::Tier;
use agent_auth_core::authority::Authority;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::literal::True;

/// `{"ok": true}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ok {
    pub ok: True,
}

/// Every HTTP error: `{"detail": "..."}`, or FastAPI's list for a request
/// that failed validation (agents only rely on the status and the key).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub detail: Detail,
}

impl ErrorBody {
    #[must_use]
    pub fn text(detail: impl Into<String>) -> Self {
        ErrorBody {
            detail: Detail::Text(detail.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Detail {
    Text(String),
    Issues(Vec<Issue>),
}

/// One entry of a 422's list: `{"type", "loc", "msg", "input"?, "ctx"?}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    #[serde(rename = "type")]
    pub kind: String,
    pub loc: Vec<Value>,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctx: Option<Map<String, Value>>,
}

/// A host command's tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    User,
    Root,
}

impl From<Tier> for TierName {
    fn from(t: Tier) -> Self {
        match t {
            Tier::User => TierName::User,
            Tier::Root => TierName::Root,
        }
    }
}

impl From<TierName> for Tier {
    fn from(t: TierName) -> Self {
        match t {
            TierName::User => Tier::User,
            TierName::Root => Tier::Root,
        }
    }
}

/// `agents.kind`. `operator` is the admin panel's own row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentKind {
    Service,
    Ephemeral,
    Operator,
}

/// The kinds an admin may give an agent (`^(service|ephemeral)$`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettableKind {
    #[default]
    Service,
    Ephemeral,
}

impl From<SettableKind> for AgentKind {
    fn from(k: SettableKind) -> Self {
        match k {
            SettableKind::Service => AgentKind::Service,
            SettableKind::Ephemeral => AgentKind::Ephemeral,
        }
    }
}

/// Where an agent runs: on a host, or in an agent VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Placement {
    #[default]
    Host,
    Sandbox,
}

/// A paired daemon's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonRole {
    Host,
    Sandbox,
}

impl DaemonRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DaemonRole::Host => "host",
            DaemonRole::Sandbox => "sandbox",
        }
    }
}

/// A grant's privilege as a response carries it: `(capability, scope)`,
/// from the stored authority (Python `authority.split`).
#[must_use]
pub fn split(authority: &Authority) -> (String, Map<String, Value>) {
    (authority.capability(), authority.scope())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn error_bodies() {
        let text: ErrorBody = serde_json::from_value(json!({"detail": "unknown request"})).unwrap();
        assert_eq!(text, ErrorBody::text("unknown request"));
        let list = json!({"detail": [{"type": "missing", "loc": ["body", "capability"],
                                      "msg": "Field required", "input": {}}]});
        let parsed: ErrorBody = serde_json::from_value(list.clone()).unwrap();
        assert!(matches!(parsed.detail, Detail::Issues(ref i) if i.len() == 1));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), list);
        assert_eq!(
            serde_json::to_value(Ok::default()).unwrap(),
            json!({"ok": true})
        );
    }

    #[test]
    fn tiers_convert() {
        for t in [Tier::User, Tier::Root] {
            assert_eq!(Tier::from(TierName::from(t)), t);
            assert_eq!(
                serde_json::to_value(TierName::from(t)).unwrap(),
                json!(t.as_str())
            );
        }
    }
}
