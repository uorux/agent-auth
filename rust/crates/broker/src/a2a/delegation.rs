//! Anchoring an access request to a thread (a2a spec §6): what the request
//! service calls for a body's `on_behalf_of_thread`.
//!
//! The delegator is derived from the thread (its initiator, the side that
//! asked), never taken from the client. Only the responder may cite a
//! thread, only an open one, only from the bound session if its side is
//! bound (a2a INV-13), and a2a access itself is never delegable.
//!
//! Threads opened by the operator from the admin panel cannot back a
//! delegated request: they have no backing grant, so in the Python every
//! such request failed at provisioning with a misleading reason (a2a B1).
//! Whether to support it is an open question (DEVIATIONS.md); until then it
//! is refused here, up front, with a reason that says so.

use agent_auth_core::containment::AgentKind;
use agent_auth_core::{Platform, ThreadId, canonical_json};
use agent_auth_store::a2a::{self, ThreadState};
use agent_auth_store::{Delegation, Outcome, Tx, agents};
use serde_json::Value;

use crate::auth::AgentCaller;

/// A delegation the request may carry, and the risk note to add to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub delegation: Delegation,
    /// `on behalf of <delegator> (a2a thread topic <json or "(none)">)`.
    pub risk_note: String,
}

/// The refusal for an operator thread (a2a B1, see the module docs).
pub const OPERATOR_THREAD: &str = "a thread with the operator cannot back a delegated request \
     (not supported yet); request the access on your own behalf";

/// Resolve `thread` (as the client sent it) for a request on `platform`.
/// `Ok(Err(reason))`: the request is denied (source policy) with reason
/// `"delegation: " + reason`.
pub async fn resolve(
    tx: &Tx<'_>,
    caller: &AgentCaller,
    platform: Platform,
    thread: &str,
) -> Outcome<Resolved, String> {
    if platform == Platform::A2a {
        return Ok(Err(
            "a2a access cannot be requested on behalf of another agent".to_owned(),
        ));
    }
    let unknown = || "unknown thread (you must be a participant of the thread you cite)".to_owned();
    let Ok(id) = thread.parse::<ThreadId>() else {
        return Ok(Err(unknown()));
    };
    let me = caller.id();
    let Some(t) = a2a::get(tx, id)
        .await?
        .filter(|t| t.initiator_agent_id == me || t.responder_agent_id == me)
    else {
        return Ok(Err(unknown()));
    };
    if t.state != ThreadState::Open {
        return Ok(Err(format!(
            "thread is {}; delegation requires an OPEN thread (the other side must have accepted)",
            t.state.as_str()
        )));
    }
    if t.responder_agent_id != me {
        return Ok(Err(
            "you opened this thread; only the responder may act on a thread's behalf \
             (the delegator must be the side that asked)"
                .to_owned(),
        ));
    }
    if let Some(bound) = t.responder_session_id
        && caller.session_id() != Some(bound)
    {
        return Ok(Err(
            "thread belongs to a different session of this agent".to_owned()
        ));
    }
    let Some(delegator) = agents::get(tx, t.initiator_agent_id)
        .await?
        .filter(|a| !a.disabled)
    else {
        return Ok(Err("delegator agent is disabled".to_owned()));
    };
    if delegator.kind == AgentKind::Operator || t.grant_id.is_none() {
        return Ok(Err(OPERATOR_THREAD.to_owned()));
    }
    let topic = t.topic.as_ref().map_or_else(
        || "(none)".to_owned(),
        |s| canonical_json::to_python_default_string(&Value::String(s.clone())),
    );
    Ok(Ok(Resolved {
        delegation: Delegation {
            thread_id: t.id,
            delegator_agent_id: delegator.id,
        },
        risk_note: format!("on behalf of {} (a2a thread topic {topic})", delegator.name),
    }))
}
