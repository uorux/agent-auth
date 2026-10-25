//! The VM's names (sandboxd spec §1): conversation ids, unit names, the
//! orchestrator's user and directories.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The orchestrator's unix user (uid = `uid_base`).
pub const ORCHESTRATOR_USER: &str = "sbx-orchestrator";
/// The orchestrator's home and tmp directory name under the roots.
pub const ORCHESTRATOR_DIR: &str = "_orchestrator";

/// A conversation id: 12 lowercase hex digits (`uuid4().hex[:12]`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConvId(String);

impl ConvId {
    /// A fresh random id.
    #[must_use]
    pub fn generate() -> ConvId {
        let hex = uuid::Uuid::new_v4().simple().to_string();
        ConvId(hex.chars().take(12).collect())
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<ConvId> {
        (text.len() == 12
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| ConvId(text.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `sbx-conv-<id>`: its headless process.
    #[must_use]
    pub fn unit(&self) -> String {
        format!("sbx-conv-{}", self.0)
    }

    /// `sbx-tui-<id>`: its interactive TUI.
    #[must_use]
    pub fn tui_unit(&self) -> String {
        format!("sbx-tui-{}", self.0)
    }
}

impl fmt::Debug for ConvId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for ConvId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ConvId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ConvId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ConvId::parse(&s).ok_or_else(|| serde::de::Error::custom("not a conversation id"))
    }
}

/// `sbx-triage-<12 hex>`.
#[must_use]
pub fn triage_unit() -> String {
    format!("sbx-triage-{}", ConvId::generate().as_str())
}

/// An MCP server name a bridge may be started for
/// (`[a-z0-9][a-z0-9-]{0,62}`).
#[must_use]
pub fn mcp_name_ok(name: &str) -> bool {
    agent_auth_core::names::McpServerName::parse(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_ids() {
        let id = ConvId::generate();
        assert_eq!(id.as_str().len(), 12);
        assert!(ConvId::parse(id.as_str()).is_some());
        for bad in [
            "",
            "0123456789aB",
            "0123456789a",
            "0123456789abc",
            "../../etc/x",
        ] {
            assert!(ConvId::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(id.unit(), format!("sbx-conv-{id}"));
        assert!(triage_unit().starts_with("sbx-triage-"));
        assert!(mcp_name_ok("gitea") && !mcp_name_ok("Gitea") && !mcp_name_ok("a/b"));
    }
}
