#![forbid(unsafe_code)]
//! The agents' (and the operator's) HTTP client for the broker, shared by
//! the `agent-auth` CLI, the stdio MCP server and the daemons.
//!
//! - [`BrokerClient`]: every agent and admin route, typed with the `wire`
//!   crate. Agent calls carry `Authorization: Bearer <AGENT_AUTH_API_KEY>`
//!   and, when the client has one, `X-Agent-Session`; admin calls carry
//!   `AGENT_AUTH_ADMIN_TOKEN` and never a session.
//! - Long waits are sliced ([`poll`]): no single HTTP long-poll is longer
//!   than 60 s.
//! - Errors carry the broker's status and `detail` ([`ClientError`]).
//! - [`pyjson`]: the JSON text Python's `json.dumps` would print, which is
//!   what the CLI and the MCP tools show.
//!
//! The broker URL must be `https://` unless it is a loopback address.

mod client;
mod error;
pub mod poll;
pub mod pyjson;
#[cfg(feature = "testing")]
pub mod testing;

pub use client::{BrokerClient, Config, DEFAULT_TIMEOUT, DEFAULT_URL, SESSION_HEADER, broker_url};
pub use error::{ClientError, STALE_SESSION};

/// A session label from the working directory's name: its characters in
/// `[A-Za-z0-9._-]`, at most 64, else `session` (what the CLI and the MCP
/// server name the sessions they make).
#[must_use]
pub fn default_session_label() -> String {
    let dir = std::env::current_dir().ok();
    let name = dir
        .as_deref()
        .and_then(std::path::Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    session_label(&name)
}

/// [`default_session_label`] for a given directory name.
#[must_use]
pub fn session_label(name: &str) -> String {
    let label: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    if label.is_empty() {
        "session".to_owned()
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_labels() {
        assert_eq!(super::session_label("agent-auth"), "agent-auth");
        assert_eq!(super::session_label("my project (1)"), "myproject1");
        assert_eq!(super::session_label("café"), "caf");
        assert_eq!(super::session_label("()"), "session");
        assert_eq!(super::session_label(""), "session");
        assert_eq!(super::session_label(&"x".repeat(100)).len(), 64);
    }
}
