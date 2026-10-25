use std::fmt;

use serde::{Deserialize, Serialize};

/// What a grant is access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Github,
    Homelab,
    Kubernetes,
    A2a,
    Google,
    /// Identities minted in an agent VM (docs/sandbox-design.md §5).
    Agents,
    /// Access between projects inside one VM.
    Sandbox,
    /// Commands (and time-boxed shells) on a host, run by its hostd.
    Hostexec,
    Mcp,
    /// Model calls through the LiteLLM gateway.
    Models,
    /// Scarce things held by one agent at a time (a pool's items).
    Pool,
    /// Mail the broker reads and sends for the agent (an address).
    Mail,
}

impl Platform {
    pub const ALL: [Platform; 12] = [
        Platform::Github,
        Platform::Homelab,
        Platform::Kubernetes,
        Platform::A2a,
        Platform::Google,
        Platform::Agents,
        Platform::Sandbox,
        Platform::Hostexec,
        Platform::Mcp,
        Platform::Models,
        Platform::Pool,
        Platform::Mail,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Github => "github",
            Platform::Homelab => "homelab",
            Platform::Kubernetes => "kubernetes",
            Platform::A2a => "a2a",
            Platform::Google => "google",
            Platform::Agents => "agents",
            Platform::Sandbox => "sandbox",
            Platform::Hostexec => "hostexec",
            Platform::Mcp => "mcp",
            Platform::Models => "models",
            Platform::Pool => "pool",
            Platform::Mail => "mail",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Platform> {
        Platform::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for p in Platform::ALL {
            assert_eq!(Platform::parse(p.as_str()), Some(p));
            let json = serde_json::to_string(&p).ok();
            assert_eq!(json, Some(format!("\"{}\"", p.as_str())));
        }
    }
}
