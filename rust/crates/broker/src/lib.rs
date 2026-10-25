#![forbid(unsafe_code)]
//! The broker: the HTTP API agents and the operator use, the request
//! lifecycle, provisioners, the Discord bot, the admin panel, the daemon
//! hub, and the scheduler. Binary: `agent-auth-server`.
//!
//! Layout (one module per area; see rust/ARCHITECTURE.md):
//! - `auth`: principals (`AgentCaller`, `AdminCaller`, `DiscordOwner`,
//!   `HumanDecider`) and their extractors.
//! - `error`: `ApiError` (`{"detail": ...}`).
//! - `events`: subscribe-first wake-ups for long-polls.
//! - `notify`: the human surface (`Notifier`).
//! - `provisioners`: the contract, the registry, one module per platform.

pub mod auth;
pub mod error;
pub mod events;
pub mod notify;
pub mod provisioners;
pub mod security_log;
pub mod state;
