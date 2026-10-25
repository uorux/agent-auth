#![forbid(unsafe_code)]
//! Every JSON body that crosses a process boundary, as serde types shared by
//! the broker, the agent client, CLI and MCP servers, and the daemons.
//!
//! Conventions:
//! - **Request bodies** (what a server parses from someone else) are
//!   `#[serde(deny_unknown_fields)]` and built from validating newtypes
//!   ([`text`], [`json`], [`duration`]), so a value of a request type is
//!   always within the limits the spec gives. Parse them with
//!   [`error::parse_body`], which yields the exact messages agents see.
//! - **Responses** keep the Python's field names and shapes; they accept
//!   unknown fields so an older client keeps working against a newer broker.
//! - **Timestamps** are one format everywhere: RFC 3339, UTC, microseconds,
//!   `Z` ([`timestamp`]).
//! - **Secrets** in transit ([`secret::WireSecret`]) never print and are
//!   wiped on drop.
//! - **Daemon channel** messages are one tagged enum per direction
//!   ([`daemon`]), discriminated by `type` as in the Python.

pub mod a2a;
pub mod admin;
pub mod admin_log;
pub mod agent;
pub mod audit;
pub mod catalog;
pub mod chat;
pub mod common;
pub mod containment;
pub mod daemon;
pub mod duration;
pub mod error;
pub mod hostexec;
pub mod json;
pub mod literal;
pub mod mcp_tools;
pub mod oauth;
pub mod payload;
pub mod pyrepr;
pub mod query;
pub mod secret;
pub mod text;
pub mod timestamp;
pub mod wiki;

#[cfg(test)]
mod tests;

pub use error::{BodyError, ValidationError, parse_body};
