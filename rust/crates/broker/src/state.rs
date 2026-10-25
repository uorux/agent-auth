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
use crate::events::{KeyedEvents, Shutdown};
use crate::notify::Notifier;
use crate::provisioners::{PlatformServices, Registry};
use crate::security_log::SecurityLog;
use crate::service::Spine;
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
    /// The provisioners' part: MCP token issuer, wiki, GitHub App.
    pub platform_services: Arc<PlatformServices>,
    /// The request lifecycle's own state: LLM reviewer, risk summarizer,
    /// approval gates and the hooks other parts plug in (`service`).
    pub spine: Arc<Spine>,
    /// Paired daemons, commands on hosts, desk prompts, attention
    /// (`daemons::HostdPart`); none: those routes answer 503/501.
    pub hostd: Option<Arc<crate::daemons::HostdPart>>,
    /// The mail gateway (`mail`); none: `/v1/mail` answers 501.
    pub mail: Option<Arc<crate::mail::Mail>>,
    /// Agent VMs: orchestrator bootstrap, key delivery, minting and
    /// cross-project access (`sandboxes`); on with the daemon channel.
    pub sandboxes: Option<Arc<crate::sandboxes::Sandboxes>>,
    /// Set at SIGTERM: parked long-polls answer with their current state
    /// instead of waiting to be cut off by the drain (`events::Shutdown`).
    pub shutdown: Shutdown,
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
            platform_services: Arc::default(),
            spine: Arc::default(),
            hostd: None,
            mail: None,
            sandboxes: None,
            shutdown: Shutdown::default(),
        }
    }
}
