#![forbid(unsafe_code)]
//! `agent-auth`: the agents' and the operator's command line (the Python's
//! cli.py): every command, option, environment variable and output format,
//! plus `admin ...` and `a2a serve`.
//!
//! Environment: `AGENT_AUTH_URL` (default `https://agent-auth.rooty.dev`),
//! `AGENT_AUTH_API_KEY`, `AGENT_AUTH_ADMIN_TOKEN` (admin commands),
//! `AGENT_AUTH_SESSION`; `a2a serve` reads its HMAC secret from the variable
//! `--hmac-env` names (default `AGENT_AUTH_WEBHOOK_SECRET`).
//!
//! Secrets the operator types (TOTP and arm codes) are prompted for without
//! echo, never taken as arguments, and nothing prints a traceback.

pub mod args;
pub mod google_consent;
pub mod run;
pub mod serve;

pub use args::Cli;
pub use run::{Io, run};
