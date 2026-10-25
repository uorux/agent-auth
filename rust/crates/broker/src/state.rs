//! What every handler and background task shares.
//!
//! Each part of the broker keeps its own state in its own module and adds
//! one field here (an `Arc`, or `Option<Arc<..>>` when the part may be
//! disabled by configuration). Each part also loads its own configuration
//! from the environment in its own module; `main` wires them together.

use std::sync::Arc;

use agent_auth_core::RequestId;
use agent_auth_core::policy::Policy;
use agent_auth_store::Store;
use time::OffsetDateTime;

use crate::a2a::A2a;
use crate::auth::AuthConfig;
use crate::events::KeyedEvents;
use crate::notify::Notifier;
use crate::provisioners::Registry;
use crate::security_log::SecurityLog;
use crate::webui::Web;

#[derive(Debug, Clone)]
pub struct AppState {
    pub store: Store,
    pub policy: Arc<Policy>,
    pub registry: Arc<Registry>,
    pub notifier: Arc<Notifier>,
    /// Wakes `GET /v1/requests/{id}/wait` when a request changes.
    pub request_events: Arc<KeyedEvents<RequestId>>,
    pub auth: Arc<AuthConfig>,
    pub security_log: Arc<SecurityLog>,
    /// The admin panel, the OAuth server and `/mcp` (`webui::install`).
    pub web: Arc<Web>,
    /// a2a threads and sessions: config, wake-ups, the activity clock,
    /// webhook delivery.
    pub a2a: Arc<A2a>,
}

impl AppState {
    /// The time used for every decision in one operation: read once, pass
    /// down (core functions take `now` as an argument).
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

impl AppState {
    /// The core of a state: everything optional left at its default
    /// (no provisioners, no notifier). Tests and `main` start from here.
    #[must_use]
    pub fn new(store: Store, policy: Policy, auth: AuthConfig) -> AppState {
        AppState {
            store,
            policy: Arc::new(policy),
            registry: Arc::default(),
            notifier: Arc::default(),
            request_events: Arc::default(),
            auth: Arc::new(auth),
            security_log: Arc::default(),
            web: Arc::default(),
            a2a: Arc::default(),
        }
    }
}
