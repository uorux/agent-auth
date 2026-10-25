//! Who is calling. Every authenticated caller is a value only this module
//! builds (private fields; no `Default`, `Clone` only where harmless, no
//! `Deserialize`). Handlers that change or reveal anything take one as an
//! axum extractor; service functions acting for someone take a reference.
//!
//! The extractors (`FromRequestParts`) and the verification itself live in
//! `auth::extract` (agent API keys and OAuth access tokens, the admin token
//! and the admin panel's session + CSRF), which is the only code that may
//! call the `pub(crate)` constructors below.

use agent_auth_core::{AgentId, SessionId};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::sessions::SessionRow;

/// How an agent proved itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCredentialKind {
    /// Its own API key.
    ApiKey,
    /// A web UI connector's OAuth access token (always human-decided; the
    /// remote MCP tool list and the credential route treat it specially).
    OAuthConnector,
}

/// An authenticated agent, with the session it named (`X-Agent-Session`),
/// if any. Built only after the key/token verified, the agent is enabled,
/// not the operator row, and the session (if named) is its own and open.
#[derive(Debug)]
pub struct AgentCaller {
    agent: AgentRow,
    session: Option<SessionRow>,
    via: AgentCredentialKind,
}

impl AgentCaller {
    pub(crate) fn new(
        agent: AgentRow,
        session: Option<SessionRow>,
        via: AgentCredentialKind,
    ) -> AgentCaller {
        AgentCaller {
            agent,
            session,
            via,
        }
    }
    #[must_use]
    pub fn agent(&self) -> &AgentRow {
        &self.agent
    }
    #[must_use]
    pub fn id(&self) -> AgentId {
        self.agent.id
    }
    #[must_use]
    pub fn session(&self) -> Option<&SessionRow> {
        self.session.as_ref()
    }
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        self.session.as_ref().map(|s| s.id)
    }
    #[must_use]
    pub fn via(&self) -> AgentCredentialKind {
        self.via
    }
}

/// Who acted as the administrator: the admin token, or a person signed in
/// to the admin panel (whose CSRF token was checked for any write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminIdentity {
    Token,
    Panel { user: String },
}

#[derive(Debug)]
pub struct AdminCaller {
    who: AdminIdentity,
}

impl AdminCaller {
    pub(crate) fn new(who: AdminIdentity) -> AdminCaller {
        AdminCaller { who }
    }
    #[must_use]
    pub fn identity(&self) -> &AdminIdentity {
        &self.who
    }
    /// For audit fields (`decided_by`, `created_by`): "admin token" or the
    /// panel user's name.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.who {
            AdminIdentity::Token => "admin token".to_owned(),
            AdminIdentity::Panel { user } => user.clone(),
        }
    }
}

/// The configured Discord owner, acting through an interaction. Built only
/// by the Discord bot after checking the interaction's user id.
#[derive(Debug)]
pub struct DiscordOwner {
    user_id: u64,
    name: String,
}

impl DiscordOwner {
    /// The interaction's user, if it is the configured owner: `configured`
    /// is non-zero and equal to `user_id` (spec A.3, INV-A1). The only way
    /// to make a `DiscordOwner`; the Discord bot calls it for every
    /// interaction, modal submissions included (INV-A2).
    pub(crate) fn check(configured: u64, user_id: u64, name: String) -> Option<DiscordOwner> {
        (configured != 0 && user_id == configured).then_some(DiscordOwner { user_id, name })
    }
    #[must_use]
    pub fn user_id(&self) -> u64 {
        self.user_id
    }
    #[must_use]
    pub fn label(&self) -> &str {
        &self.name
    }
}

/// A person entitled to decide requests. Only an authenticated human
/// surface converts into one, so `RequestService::decide` cannot be called
/// for anyone else.
#[derive(Debug)]
pub struct HumanDecider {
    label: String,
}

impl HumanDecider {
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl From<&AdminCaller> for HumanDecider {
    /// `decided_by`: `admin-api` for the admin token (as the Python's admin
    /// decide route), the panel user's name for a panel session.
    fn from(admin: &AdminCaller) -> HumanDecider {
        HumanDecider {
            label: match admin.identity() {
                AdminIdentity::Token => "admin-api".to_owned(),
                AdminIdentity::Panel { user } => user.clone(),
            },
        }
    }
}

impl From<&DiscordOwner> for HumanDecider {
    fn from(owner: &DiscordOwner) -> HumanDecider {
        HumanDecider {
            label: owner.label().to_owned(),
        }
    }
}

mod extract;
pub use extract::{AuthConfig, bearer_token, client_address};
