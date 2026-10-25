//! Agent-to-agent threads, sessions, webhook pings and the operator's chat
//! (rust/spec/a2a-wiki-desktop.md §3-§6, http-api.md §2.2).
//!
//! - `service`: the thread state machine. Every transition loads the thread
//!   `FOR UPDATE` (a2a B4) after the participants were checked for
//!   containment ([`agent_auth_store::lockdown::check_pair`]), in the global
//!   lock order: containment lock, agents, grants, threads.
//! - `routes` (`/v1/sessions*`, `/v1/a2a/*`) and `chat` (`/admin/chat/*`):
//!   the HTTP surfaces; [`routes`] returns both.
//! - `webhook`: signed, notify-only pings, delivered from a background task
//!   after commit (a2a B9); the URL rules are in [`webhook::check_url`].
//! - `delegation`: anchoring a request to a thread (§6), for the request
//!   service.
//! - [`sweep`] (the scheduler's step) and [`catalog_entry`] (`/v1/catalog`).
//!
//! The events cursor (a2a B3) is exact within this process: see
//! [`clock::ActivityClock`].

mod chat;
pub(crate) mod clock;
mod config;
pub mod delegation;
mod grant;
mod limits;
pub mod provisioner;
mod reach;
mod routes;
mod service;
#[cfg(test)]
mod tests;
pub mod webhook;

use std::sync::Arc;

use agent_auth_core::{AgentId, SessionId};
use axum::Router;

pub use config::A2aConfig;
pub use grant::check_grant;
pub use reach::{reachability, unreachable_detail};
pub use service::{
    SweepCounts, catalog_entry, close_all_for, on_agent_disabled, orphan_inbound, sweep,
};

use crate::events::KeyedEvents;
use crate::state::AppState;

/// What a long-poll waits on: an agent's inbox, or one of its sessions'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeKey {
    Agent(AgentId),
    Session(SessionId),
}

/// The a2a part's state (one `AppState` field).
#[derive(Debug, Default)]
pub struct A2a {
    pub config: A2aConfig,
    pub(crate) events: Arc<KeyedEvents<WakeKey>>,
    pub(crate) clock: clock::ActivityClock,
    pub(crate) webhooks: webhook::Webhooks,
    pub(crate) polls: limits::PollSlots,
}

impl A2a {
    #[must_use]
    pub fn new(config: A2aConfig) -> A2a {
        A2a {
            config,
            ..A2a::default()
        }
    }

    /// a2a long-polls parked right now (holding a slot), all agents
    /// together (diagnostics; tests wait on it instead of sleeping).
    #[must_use]
    pub fn long_polls_in_progress(&self) -> u32 {
        self.polls.in_use()
    }

    /// Wake the long-polls of one side of a thread: its session (if bound)
    /// and its agent.
    pub(crate) fn wake(&self, agent: AgentId, session: Option<SessionId>) {
        if let Some(s) = session {
            self.events.notify(&WakeKey::Session(s));
        }
        self.events.notify(&WakeKey::Agent(agent));
    }
}

/// `/v1/sessions*`, `/v1/a2a/*` and `/admin/chat/*`.
pub fn routes() -> Router<AppState> {
    routes::routes().merge(chat::routes())
}
