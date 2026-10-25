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
//! - `wiki`: the agents' shared wiki (a GitHub repo the broker writes).
//! - `service`: the request lifecycle (the spine), `llm` its reviewer,
//!   `containment`, `scheduler`.
//! - `http`: the router (every part's routes) and the spine's routes.
//! - `config`, `server`: the environment and startup.
//! - `daemons` (paired daemons: pairing, the channel hub), `hostexec`
//!   (commands on hosts), `desktop` (desk prompts), `attention`.

pub mod a2a;
pub mod attention;
pub mod auth;
pub mod config;
pub mod containment;
pub mod daemons;
pub mod desktop;
pub mod discord;
pub mod error;
pub mod events;
pub mod hostexec;
pub mod http;
pub mod limits;
pub mod llm;
pub mod notify;
pub mod oauth;
pub mod provisioners;
pub mod random;
pub mod remote_mcp;
pub mod scheduler;
pub mod security_log;
pub mod server;
pub mod service;
pub mod state;
pub mod webui;
pub mod wiki;
