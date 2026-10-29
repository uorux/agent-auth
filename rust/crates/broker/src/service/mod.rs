//! The request lifecycle (rust/spec/core-lifecycle-policy.md §4): create,
//! the LLM review task, retry and escalate, human decisions, two-phase
//! provisioning, reaping, revocation and expiry.
//!
//! Every function takes the shared [`AppState`]; what only this part needs
//! (the LLM reviewer, the risk summarizer, the per-platform approval gates
//! and the hooks other parts plug in) lives in [`Spine`], one field of the
//! state.
//!
//! How the types keep the rules:
//! - a status change goes through `store::requests::transition`, which
//!   compiles only for edges of the state machine and is a compare-and-swap;
//! - an automatic approval needs the `AutoClearance` that only
//!   `Policy::route` makes (after every gate) for that request;
//! - a human decision needs a [`HumanDecider`], which only an
//!   authenticated human surface makes;
//! - a grant row needs a `NotHeld` proof from the same transaction
//!   (`store::grants::begin` / `activate`).

mod create;
mod decide;
mod llm_task;
mod ops;
pub(crate) mod provision;
mod routing;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use agent_auth_core::Platform;
use agent_auth_core::policy::AgentRef;
use agent_auth_store::StoreError;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleAction;
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use tokio::task::JoinHandle;

use crate::error::ApiError;
use crate::llm::{LlmReviewer, RiskSummarizer};
use crate::provisioners::{ProvisionError, not_enabled};
use crate::state::AppState;

pub use create::create;
pub use decide::{apply_rule_to_pending, decide, decide_attested, deny_pending};
pub use llm_task::{escalate, resume, retry};
pub use ops::SpineOps;
pub use provision::{
    expire_due_grants, reap_provisioning_of, reap_stale_provisioning,
    revoke_delegated_for_closed_threads, revoke_grant,
};
pub use routing::disposition;

pub use crate::auth::HumanDecider;

/// A refusal of a lifecycle operation (Python `TransitionError` and
/// friends), or a failure underneath.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Not allowed now (409 with this text).
    #[error("{0}")]
    Transition(String),
    /// `platform '{p}' is not enabled on this broker` (400).
    #[error("{}", not_enabled(*.0))]
    NotEnabled(Platform),
    /// A provisioner failed where the caller should hear about it (an
    /// admin revoke): 500, the text logged.
    #[error("provisioner: {0}")]
    Provision(#[from] ProvisionError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ServiceError {
    pub(crate) fn transition(text: impl Into<String>) -> ServiceError {
        ServiceError::Transition(text.into())
    }
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> ApiError {
        match e {
            ServiceError::Transition(t) => ApiError::conflict(t),
            ServiceError::NotEnabled(p) => ApiError::bad_request(not_enabled(p)),
            other => ApiError::internal(&other),
        }
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

/// A saved rule born from a human decision (Discord's Edit modal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFromDecision {
    pub action: RuleAction,
    /// Default: the approved resource, else the request's.
    pub resource_pattern: Option<String>,
    /// Leave the rule's authority open (it then never clears a sensitive
    /// request). Ignored for deny rules, which are never pinned.
    pub any_authority: bool,
}

/// What a human decided (Python `HumanDecision`, minus `decided_by`, which
/// comes from the [`HumanDecider`]).
#[derive(Clone, Default)]
pub struct HumanDecision {
    pub approve: bool,
    pub reason: String,
    /// None: the request's duration capped by the policy default.
    pub duration_secs: Option<u32>,
    pub resource_override: Option<String>,
    pub scope_override: Option<Map<String, Value>>,
    pub rule: Option<RuleFromDecision>,
    /// hostexec: a TOTP code for the host, handed to the approval gate and
    /// never stored.
    pub totp: Option<String>,
}

impl fmt::Debug for HumanDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HumanDecision")
            .field("approve", &self.approve)
            .field("reason", &self.reason)
            .field("duration_secs", &self.duration_secs)
            .field("resource_override", &self.resource_override)
            .field("scope_override", &self.scope_override)
            .field("rule", &self.rule)
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl HumanDecision {
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> HumanDecision {
        HumanDecision {
            approve: false,
            reason: reason.into(),
            ..HumanDecision::default()
        }
    }
}

/// Runs before a human approval takes effect, outside any transaction; an
/// `Err(text)` stops it with a 409 `text` and the request stays as it was.
/// hostexec registers one (it asks the host and hands it the TOTP code).
pub type ApprovalGate = Arc<
    dyn Fn(AppState, RequestRow, AgentRow, HumanDecision) -> BoxFuture<'static, Result<(), String>>
        + Send
        + Sync,
>;

/// A periodic job another part runs on the scheduler's tick.
pub type TickHook = Arc<dyn Fn(AppState) -> BoxFuture<'static, ()> + Send + Sync>;

/// Something done for a set of agents just contained (closing their a2a
/// threads, telling their agent VMs). Returns a count or a per-target
/// report, as the hook's slot says.
pub type AgentsHook<R> =
    Arc<dyn Fn(AppState, Vec<AgentRow>) -> BoxFuture<'static, R> + Send + Sync>;

/// Where other parts plug into the spine. Each slot is optional; an empty
/// one means the feature is off (or the fallback described on it runs).
#[derive(Default, Clone)]
pub struct Hooks {
    /// Per-platform approval gates (hostexec).
    pub approval_gates: HashMap<Platform, ApprovalGate>,
    /// Scheduler: hostexec's periodic work.
    pub hostexec_tick: Option<TickHook>,
    /// Scheduler: agent VMs' periodic work (key deliveries...).
    pub sandboxes_tick: Option<TickHook>,
    /// Containment and lift: tell each agent VM which of its agents are
    /// held. Returns `{"<vm>": "<n> held" | "not connected; ..."}`.
    pub tell_sandboxes: Option<AgentsHook<serde_json::Map<String, Value>>>,
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut gates: Vec<&str> = self.approval_gates.keys().map(|p| p.as_str()).collect();
        gates.sort_unstable();
        f.debug_struct("Hooks")
            .field("approval_gates", &gates)
            .field("hostexec_tick", &self.hostexec_tick.is_some())
            .field("sandboxes_tick", &self.sandboxes_tick.is_some())
            .field("tell_sandboxes", &self.tell_sandboxes.is_some())
            .finish()
    }
}

/// The spine's own state (one `AppState` field).
#[derive(Debug, Default)]
pub struct Spine {
    /// The LLM reviewer (`OPENROUTER_API_KEY`); none: `llm` routes go to a
    /// human with the note `llm evaluator unavailable`.
    pub llm: Option<LlmReviewer>,
    /// Advisory risk lines on hostexec requests shown to a human.
    pub risk: Option<RiskSummarizer>,
    pub hooks: Hooks,
    /// Per-agent limits on long-polls and new requests.
    pub limits: crate::limits::Limits,
    /// Background LLM evaluations in flight (awaited by [`Spine::settle`]).
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Spine {
    pub(crate) fn track(&self, task: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
    }

    /// Wait for every background evaluation started so far (and those they
    /// start). Tests use it; shutdown too.
    pub async fn settle(&self) {
        loop {
            let pending: Vec<JoinHandle<()>> = {
                let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
                std::mem::take(&mut *tasks)
            };
            if pending.is_empty() {
                return;
            }
            for task in pending {
                if let Err(e) = task.await {
                    tracing::error!(error = %e, "background evaluation task failed");
                }
            }
        }
    }
}

/// Run `fut` as a tracked task and wait for its result. If the caller is
/// dropped (a client disconnects mid-request), the task still runs to its
/// end, and shutdown waits for it (`Spine::settle`). `None`: it panicked.
pub(crate) async fn detached<T: Send + 'static>(
    st: &AppState,
    fut: impl Future<Output = T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _ = tx.send(fut.await);
    });
    st.spine.track(handle);
    rx.await.ok()
}

/// An agent as policy sees it.
#[must_use]
pub fn agent_ref_of(agent: &AgentRow) -> AgentRef<'_> {
    AgentRef {
        name: &agent.name,
        runtime: agent.runtime.as_deref(),
        project: agent.project.as_deref(),
        host: agent.host.as_deref(),
        placement: agent.placement,
        kind: agent.kind,
    }
}
