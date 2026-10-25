//! The agent API core: `/v1/me`, `/v1/attention`, `/v1/requests*`,
//! `/v1/grants*` (http-api §2.1, §5.2, §5.3).

use agent_auth_core::{
    AgentId, DecisionSource, GrantId, GrantStatus, Platform, RequestId, RequestStatus, SessionId,
    ThreadId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::common::{AgentKind, Placement};
use crate::duration::DurationSecs;
use crate::json::Scope;
use crate::secret::WireSecret;
use crate::text::Text;

/// `GET /v1/me`. Every key is present (null when unset) except `session`,
/// which appears only for a call made with a valid `X-Agent-Session`.
/// Never carries `webhook_secret`, `api_key`, `disabled`, `parent`,
/// `sandbox` or `last_seen_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Me {
    pub id: AgentId,
    pub name: String,
    pub description: String,
    pub kind: AgentKind,
    pub webhook_url: Option<String>,
    pub lldap_username: Option<String>,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRef {
    pub id: SessionId,
    pub name: String,
}

/// `POST /v1/attention`. The urgency is checked by the service (400
/// `urgency is normal or high`), so it is only bounded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionBody {
    pub text: Text<1, 2000>,
    #[serde(default = "normal")]
    pub urgency: Text<0, 32>,
}

fn normal() -> Text<0, 32> {
    Text::new("normal").unwrap_or_default()
}

/// `POST /v1/attention` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttentionOut {
    pub sent: bool,
    pub desktops: Vec<String>,
}

/// `POST /v1/requests` (Python `RequestCreate`).
///
/// `on_behalf_of_thread` stays text (at most 36 characters): a value that is
/// not a thread id is a policy denial ("unknown thread"), not a 422.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCreate {
    pub platform: Platform,
    pub capability: Text<1, 128>,
    pub resource: Text<1, 512>,
    #[serde(default)]
    pub scope: Scope,
    pub justification: Text<1, 4000>,
    pub requested_duration: DurationSecs,
    #[serde(default)]
    pub on_behalf_of_thread: Option<Text<0, 36>>,
}

/// `POST /v1/requests/{id}/retry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryBody {
    pub justification: Text<1, 4000>,
}

/// An access request as its agent sees it (Python `RequestOut`). Every key
/// is always present. `capability`/`scope` and `approved_scope` come from
/// the stored authorities ([`crate::common::split`]); the raw authorities,
/// risk notes, who decided, the session and the Discord ids never appear.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestOut {
    pub id: RequestId,
    /// The requester's name, `"?"` if it is gone.
    pub agent: String,
    pub platform: Platform,
    pub capability: String,
    pub resource: String,
    pub scope: Map<String, Value>,
    pub justification: String,
    pub requested_duration_secs: u32,
    pub status: RequestStatus,
    pub attempt: u32,
    pub decision_source: Option<DecisionSource>,
    pub decision_reason: Option<String>,
    pub approved_duration_secs: Option<u32>,
    pub approved_scope: Option<Map<String, Value>>,
    pub approved_resource: Option<String>,
    pub grant_id: Option<GrantId>,
    /// The delegator's name, `"?"` if it is gone, null if not delegated.
    pub delegator: Option<String>,
    pub delegation_thread_id: Option<ThreadId>,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    pub guidance: Option<String>,
}

/// What an agent should do next, for a request in `status` (http-api §5.2,
/// verbatim). Null while the broker is still working on it.
#[must_use]
pub fn guidance(status: RequestStatus, id: RequestId, grant: Option<GrantId>) -> Option<String> {
    let template = match status {
        RequestStatus::LlmDenied => {
            "Denied by LLM review — see decision_reason. Retry with a revised justification \
             that answers it (retry_request / POST /v1/requests/{id}/retry), or ask for human \
             review (escalate_request / POST /v1/requests/{id}/escalate)."
        }
        RequestStatus::AwaitingHuman => {
            "Waiting for a human decision on Discord; this can take a while. Keep waiting \
             (wait_for_decision / GET /v1/requests/{id}/wait)."
        }
        RequestStatus::LlmEvaluating => {
            "Under LLM review. Keep waiting (wait_for_decision / GET /v1/requests/{id}/wait)."
        }
        RequestStatus::Granted => {
            "Granted. If the grant carries a credential (a token, an account, a created repo's \
             URL), fetch it with get_credential(\"{grant_id}\") / \
             GET /v1/grants/{grant_id}/credential — and re-fetch rather than caching it."
        }
        RequestStatus::Denied => {
            "Denied — see decision_reason. Final: don't resubmit it unchanged. A narrower \
             request, or one with a materially better justification, is a new request."
        }
        RequestStatus::ProvisionFailed => {
            "Approved, but setting it up failed (see decision_reason). Not your request's \
             fault; tell the user, or try again later as a new request."
        }
        RequestStatus::Pending | RequestStatus::Approved | RequestStatus::Provisioning => {
            return None;
        }
    };
    let grant = grant.map_or_else(|| "?".to_owned(), |g| g.to_string());
    Some(
        template
            .replace("{id}", &id.to_string())
            .replace("{grant_id}", &grant),
    )
}

/// A grant as its agent sees it (Python `GrantOut`). Hidden: the raw
/// authority, revocation details, provisioner state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantOut {
    pub id: GrantId,
    pub request_id: RequestId,
    pub agent: String,
    pub platform: Platform,
    pub capability: String,
    pub resource: String,
    pub scope: Map<String, Value>,
    #[serde(with = "crate::timestamp")]
    pub granted_at: OffsetDateTime,
    #[serde(with = "crate::timestamp")]
    pub expires_at: OffsetDateTime,
    pub status: GrantStatus,
    /// The delegator's name, null if not delegated or unknown.
    pub delegator: Option<String>,
    pub delegation_thread_id: Option<ThreadId>,
}

/// `POST /v1/grants/{id}/release`: `{"released": true}`, or
/// `{"released": false, "status": ...}` for a grant that had already ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseOut {
    pub released: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<GrantStatus>,
}

/// What `GET /v1/grants/{id}/credential` hands out, per platform
/// (provisioners spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// An installation token for one repo.
    GithubInstallationToken,
    /// A repo the broker created: `value` is its URL.
    GithubRepo,
    /// A ServiceAccount token.
    KubernetesToken,
    /// The agent's managed LLDAP account (`username` + password).
    LldapAccount,
    /// Group membership for an account the agent already has.
    LldapGroup,
    /// A short-lived token for one MCP server.
    McpToken,
    /// A key for the model gateway (`url` is the gateway).
    ModelGatewayKey,
    /// Check-based: nothing to hand out.
    A2aGrant,
    /// A minted identity's name; its key went to the sandbox daemon.
    AgentIdentity,
    /// ACLs applied in the agent VM.
    ProjectAccess,
    /// An open shell: `value` is the grant id to run commands with.
    HostexecShell,
    /// A run/tpl job: `value` is a JSON summary ([`crate::hostexec::JobSummary`]).
    HostexecJob,
    /// A pool item leased: its secret in `value`, its properties in
    /// `properties`.
    PoolItem,
}

/// `GET /v1/grants/{id}/credential` (Python `CredentialOut`). All seven
/// keys always present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialOut {
    pub kind: CredentialKind,
    pub value: Option<WireSecret>,
    /// The login name when the credential is an account.
    pub username: Option<String>,
    /// Where to use it, when that is part of it (the model gateway).
    pub url: Option<String>,
    #[serde(default, with = "crate::timestamp::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub note: Option<String>,
    /// What the credential is for, when that is part of it (a pool item's
    /// properties).
    #[serde(default)]
    pub properties: Option<serde_json::Map<String, serde_json::Value>>,
}

impl CredentialOut {
    /// A credential with only a kind and a note (a2a, sandbox, ...).
    #[must_use]
    pub fn note_only(kind: CredentialKind, note: impl Into<String>) -> Self {
        CredentialOut {
            kind,
            value: None,
            username: None,
            url: None,
            expires_at: None,
            note: Some(note.into()),
            properties: None,
        }
    }
}
