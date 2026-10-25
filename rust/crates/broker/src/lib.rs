#![forbid(unsafe_code)]
//! The broker: the HTTP API agents and the operator use, the request
//! lifecycle, provisioners, the Discord bot, the admin panel, the daemon
//! hub, and the scheduler. Binary: `agent-auth-server`.
//!
//! Layout (one module per area; see rust/ARCHITECTURE.md):
//! - `a2a`: threads, sessions, webhook pings, the operator's chat.
//! - `auth`: principals (`AgentCaller`, `AdminCaller`, `DiscordOwner`,
//!   `HumanDecider`) and their extractors.
//! - `discord`: the Discord bot and its notifier.
//! - `error`: `ApiError` (`{"detail": ...}`).
//! - `events`: subscribe-first wake-ups for long-polls.
//! - `notify`: the human surface (`Notifier`).
//! - `provisioners`: the contract, the registry, one module per platform.
//! - `webui`: the admin panel (`/ui`) and its OpenID sign-in; `oauth`: the
//!   OAuth server for web-UI connectors; `remote_mcp`: `/mcp` for them.

pub mod a2a;
pub mod auth;
pub mod discord;
pub mod error;
pub mod events;
pub mod notify;
pub mod oauth;
pub mod provisioners;
pub mod remote_mcp;
pub mod security_log;
pub mod state;
pub mod webui;
