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

use crate::events::KeyedEvents;
use crate::notify::Notifier;
use crate::provisioners::Registry;

#[derive(Debug, Clone)]
pub struct AppState {
    pub store: Store,
    pub policy: Arc<Policy>,
    pub registry: Arc<Registry>,
    pub notifier: Arc<Notifier>,
    /// Wakes `GET /v1/requests/{id}/wait` when a request changes.
    pub request_events: Arc<KeyedEvents<RequestId>>,
}

impl AppState {
    /// The time used for every decision in one operation: read once, pass
    /// down (core functions take `now` as an argument).
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
