//! The LLM review task (spec §4.3), the agent's retry and escalate (§4.4,
//! §4.5), surfacing to a human (§4.11) and recovery after a restart (B-3).

use agent_auth_core::lifecycle::state;
use agent_auth_core::routing::Route;
use agent_auth_core::{EvaluationId, RequestId};
use agent_auth_store::agents;
use agent_auth_store::llm::{self, NewEvaluation, Verdict};
use agent_auth_store::requests::{
    self, AnyRequest, Approval, Escalation, LlmDenial, LlmRound, RequestRow,
};
use agent_auth_store::{StoreError, lockdown};
use serde_json::json;

use super::create::announce_auto_approval;
use super::provision::{begin_provision, finish_detached, step};
use super::routing::{Subject, clamp_duration, delegator_of, reroute};
use super::{ServiceError, ServiceResult};
use crate::auth::AgentCaller;
use crate::llm::{LlmVerdict, Prior};
use crate::notify::Notify;
use crate::state::AppState;

/// Start an evaluation in the background. Whatever goes wrong in it sends
/// the request to a human (INV-18).
pub(crate) fn spawn(st: &AppState, id: RequestId) {
    let task_state = st.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = evaluate(&task_state, id).await {
            tracing::error!(request = %id, error = %e, "llm evaluation crashed; escalating");
            if let Err(e) =
                escalate_from_llm(&task_state, id, "internal error during LLM evaluation").await
            {
                tracing::error!(request = %id, error = %e, "escalation after a crash failed");
            }
        }
    });
    st.spine.track(handle);
}

/// Evaluations lost by a restart or stalled (core B-3): each is evaluated
/// again, or goes to a human when there is no reviewer. The scheduler
/// finds them (every LLM_EVALUATING request at boot, later those untouched
/// for 15 minutes).
pub async fn resume(st: &AppState, ids: &[RequestId]) -> ServiceResult<()> {
    for id in ids {
        if st.spine.llm.is_some() {
            spawn(st, *id);
        } else {
            escalate_from_llm(st, *id, "llm evaluator unavailable after a restart").await?;
        }
    }
    Ok(())
}

async fn load(st: &AppState, id: RequestId) -> Result<Option<RequestRow>, StoreError> {
    let tx = st.store.begin().await?;
    Ok(requests::get(&tx, id).await?.map(AnyRequest::into_row))
}

async fn evaluate(st: &AppState, id: RequestId) -> ServiceResult<()> {
    let Some(reviewer) = st.spine.llm.as_ref() else {
        return escalate_from_llm(st, id, "llm evaluator unavailable").await;
    };
    // Read what the reviewer needs.
    let (request, agent, decision, priors) = {
        let now = st.now();
        let tx = st.store.begin().await?;
        let Some(request) = requests::get(&tx, id).await?.map(AnyRequest::into_row) else {
            return Ok(());
        };
        if request.status != agent_auth_core::RequestStatus::LlmEvaluating {
            return Ok(());
        }
        let agent = agents::get(&tx, request.agent_id)
            .await?
            .ok_or_else(|| ServiceError::transition("unknown agent"))?;
        let authority = request
            .authority
            .clone()
            .ok_or_else(|| ServiceError::transition("request has no authority"))?;
        let delegator = delegator_of(&tx, &request).await?;
        let rerouted = reroute(
            &st.policy,
            &tx,
            Subject {
                request: id,
                agent: &agent,
                delegator: &delegator,
                resource: &request.resource,
                authority: &authority,
            },
            now,
        )
        .await?;
        let priors: Vec<Prior> = llm::for_request(&tx, id)
            .await?
            .into_iter()
            .map(|e| Prior {
                attempt: e.attempt,
                verdict: e.verdict.as_str().to_owned(),
                reasoning: e.reasoning,
            })
            .collect();
        (request, agent, rerouted.decision, priors)
    };
    let max_duration = st.policy.cap_duration(
        clamp_duration(request.requested_duration_secs),
        Some(decision.max_duration),
    );
    let model = decision.llm_model.clone();
    let budget = decision.retry_budget;

    let verdict = reviewer
        .evaluate(&model, &agent, &request, max_duration.get(), &priors)
        .await;

    // Record and act, if nobody decided meanwhile.
    let now = st.now();
    let tx = st.store.begin().await?;
    let Some(AnyRequest::LlmEvaluating(current)) = requests::get_for_update(&tx, id).await? else {
        return Ok(());
    };
    // A retry started a newer round meanwhile: that round's evaluation
    // decides, not this one.
    if current.row().attempt != request.attempt {
        return Ok(());
    }
    let attempt = current.row().attempt;
    if let Some((v, reasoning, suggested)) = match &verdict {
        LlmVerdict::Approve {
            reasoning,
            suggested_duration_secs,
        } => Some((Verdict::Approve, reasoning, *suggested_duration_secs)),
        LlmVerdict::Deny { reasoning } => Some((Verdict::Deny, reasoning, None)),
        LlmVerdict::Error => None,
    } {
        llm::insert(
            &tx,
            &NewEvaluation {
                id: EvaluationId::new(),
                request_id: id,
                attempt,
                model: &model,
                verdict: v,
                reasoning,
                suggested_duration_secs: suggested,
                raw_response: &json!({}),
                now,
            },
        )
        .await?;
    }

    let mut grant = None;
    let status_after;
    match verdict {
        LlmVerdict::Approve {
            reasoning,
            suggested_duration_secs,
        } => {
            // Re-run the policy and every gate with today's facts (B-4): a
            // rule added or a containment recorded since routing wins over
            // the reviewer. Only a route still to the LLM is cleared.
            let agent_now = lockdown::holding(&tx, &agent).await?;
            let authority = current
                .row()
                .authority
                .clone()
                .ok_or_else(|| ServiceError::transition("request has no authority"))?;
            let delegator = delegator_of(&tx, current.row()).await?;
            let rerouted = reroute(
                &st.policy,
                &tx,
                Subject {
                    request: id,
                    agent: &agent,
                    delegator: &delegator,
                    resource: &current.row().resource,
                    authority: &authority,
                },
                now,
            )
            .await?;
            // The cap of the policy as it is now (INV-19).
            let max_now = st.policy.cap_duration(
                clamp_duration(current.row().requested_duration_secs),
                Some(rerouted.decision.max_duration),
            );
            match (rerouted.routed.map(|r| r.route), agent_now) {
                (Some(Route::Llm(clearance)), None) => {
                    let mut duration = max_now.get().min(max_duration.get());
                    if let Some(s) = suggested_duration_secs.filter(|s| *s > 0) {
                        duration = duration.min(s);
                    }
                    let approved = step::<_, state::Approved>(
                        &tx,
                        current,
                        Approval::llm(clearance, model.clone(), reasoning, duration),
                        now,
                    )
                    .await?;
                    grant = begin_provision(&tx, approved, now).await?;
                    status_after = agent_auth_core::RequestStatus::Provisioning;
                }
                _ => {
                    step::<_, state::AwaitingHuman>(
                        &tx,
                        current,
                        Escalation {
                            note: Some(format!(
                                "LLM approved, but the policy no longer routes this to the LLM: {reasoning}"
                            )),
                        },
                        now,
                    )
                    .await?;
                    status_after = agent_auth_core::RequestStatus::AwaitingHuman;
                }
            }
        }
        LlmVerdict::Deny { reasoning } => {
            if attempt >= budget {
                step::<_, state::AwaitingHuman>(
                    &tx,
                    current,
                    Escalation {
                        note: Some(format!(
                            "LLM denied (attempt {attempt}/{budget}): {reasoning}"
                        )),
                    },
                    now,
                )
                .await?;
                status_after = agent_auth_core::RequestStatus::AwaitingHuman;
            } else {
                step::<_, state::LlmDenied>(
                    &tx,
                    current,
                    LlmDenial {
                        model: model.clone(),
                        reasoning,
                    },
                    now,
                )
                .await?;
                status_after = agent_auth_core::RequestStatus::LlmDenied;
            }
        }
        LlmVerdict::Error => {
            step::<_, state::AwaitingHuman>(
                &tx,
                current,
                Escalation {
                    note: Some(crate::llm::ERROR_REASONING.to_owned()),
                },
                now,
            )
            .await?;
            status_after = agent_auth_core::RequestStatus::AwaitingHuman;
        }
    }
    tx.commit().await?;

    if let Some(grant) = grant {
        finish_detached(st, grant).await;
        if let Some(row) = load(st, id).await? {
            announce_auto_approval(st, &row).await;
        }
    }
    st.request_events.notify(&id);
    if status_after == agent_auth_core::RequestStatus::AwaitingHuman {
        surface(st, id).await;
    }
    Ok(())
}

/// To a human from LLM_EVALUATING (crash, no reviewer). Notifies and
/// surfaces even if nothing changed.
pub(crate) async fn escalate_from_llm(
    st: &AppState,
    id: RequestId,
    note: &str,
) -> ServiceResult<()> {
    let now = st.now();
    let tx = st.store.begin().await?;
    if let Some(AnyRequest::LlmEvaluating(r)) = requests::get(&tx, id).await? {
        // A lost race means someone else moved it: fine.
        let _ = requests::transition::<_, state::AwaitingHuman>(
            &tx,
            r,
            Escalation {
                note: Some(note.to_owned()),
            },
            now,
        )
        .await?;
    }
    tx.commit().await?;
    st.request_events.notify(&id);
    surface(st, id).await;
    Ok(())
}

/// The refusal text for a held agent's retry or escalation.
async fn refuse_if_held(
    tx: &agent_auth_store::Tx<'_>,
    agent: agent_auth_core::AgentId,
    now: time::OffsetDateTime,
) -> ServiceResult<()> {
    match lockdown::check(tx, agent, now).await? {
        Ok(_) => Ok(()),
        Err(held) => Err(ServiceError::Transition(held.text())),
    }
}

/// `POST /v1/requests/{id}/retry`: another LLM round with a new
/// justification, within the retry budget (INV-23).
pub async fn retry(
    st: &AppState,
    caller: &AgentCaller,
    id: RequestId,
    justification: String,
) -> ServiceResult<RequestRow> {
    let now = st.now();
    let tx = st.store.begin().await?;
    // Lock order: the request row, then containment.
    let request = requests::get_for_update(&tx, id)
        .await?
        .filter(|r| r.row().agent_id == caller.id())
        .ok_or_else(|| ServiceError::transition("unknown request"))?;
    let AnyRequest::LlmDenied(denied) = request else {
        return Err(ServiceError::Transition(format!(
            "cannot retry from status {}",
            request.status()
        )));
    };
    refuse_if_held(&tx, caller.id(), now).await?;
    let authority = denied
        .row()
        .authority
        .clone()
        .ok_or_else(|| ServiceError::transition("request has no authority"))?;
    let delegator = delegator_of(&tx, denied.row()).await?;
    let rerouted = reroute(
        &st.policy,
        &tx,
        Subject {
            request: id,
            agent: caller.agent(),
            delegator: &delegator,
            resource: &denied.row().resource,
            authority: &authority,
        },
        now,
    )
    .await?;
    if denied.row().attempt >= rerouted.decision.retry_budget {
        return Err(ServiceError::transition(
            "retry budget exhausted; use escalate",
        ));
    }
    // Another round needs the policy to route it to the LLM still.
    let Some(Route::Llm(clearance)) = rerouted.routed.map(|r| r.route) else {
        return Err(ServiceError::transition(
            "the policy no longer routes this request to LLM review; use escalate",
        ));
    };
    let evaluating = requests::transition::<_, state::LlmEvaluating>(
        &tx,
        denied,
        LlmRound {
            clearance,
            justification: Some(justification),
        },
        now,
    )
    .await?
    .map_err(|_| ServiceError::transition("request was decided concurrently"))?;
    tx.commit().await?;
    spawn(st, id);
    Ok(evaluating.into_row())
}

/// `POST /v1/requests/{id}/escalate`: from an LLM denial to a human.
pub async fn escalate(
    st: &AppState,
    caller: &AgentCaller,
    id: RequestId,
) -> ServiceResult<RequestRow> {
    let now = st.now();
    let tx = st.store.begin().await?;
    // Lock order: the request row, then containment.
    let request = requests::get_for_update(&tx, id)
        .await?
        .filter(|r| r.row().agent_id == caller.id())
        .ok_or_else(|| ServiceError::transition("unknown request"))?;
    let AnyRequest::LlmDenied(denied) = request else {
        return Err(ServiceError::Transition(format!(
            "cannot escalate from status {}",
            request.status()
        )));
    };
    refuse_if_held(&tx, caller.id(), now).await?;
    let reason = denied.row().decision_reason.clone().unwrap_or_default();
    let escalated = requests::transition::<_, state::AwaitingHuman>(
        &tx,
        denied,
        Escalation {
            note: Some(format!("escalated by agent after LLM denial: {reason}")),
        },
        now,
    )
    .await?
    .map_err(|_| ServiceError::transition("request was decided concurrently"))?;
    tx.commit().await?;
    surface(st, id).await;
    Ok(escalated.into_row())
}

/// Show a request to a human: an advisory risk line first (hostexec), then
/// the notifier. Never fails its caller.
pub(crate) async fn surface(st: &AppState, id: RequestId) {
    let loaded = async {
        let tx = st.store.begin().await?;
        let Some(request) = requests::get(&tx, id).await?.map(AnyRequest::into_row) else {
            return Ok(None);
        };
        let agent = agents::get(&tx, request.agent_id).await?;
        Ok::<_, StoreError>(agent.map(|a| (request, a)))
    }
    .await;
    let (mut request, agent) = match loaded {
        Ok(Some(x)) => x,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(request = %id, error = %e, "loading a request to surface failed");
            return;
        }
    };
    if let Some(risk) = st.spine.risk.as_ref()
        && risk.wants(&request)
        && let Some(line) = risk.summarize(&request, &agent).await
    {
        let appended = async {
            let tx = st.store.begin().await?;
            requests::append_note(&tx, id, &line).await?;
            tx.commit().await
        }
        .await;
        match appended {
            Ok(()) => request.risk_notes.push(line),
            Err(e) => tracing::warn!(request = %id, error = %e, "storing the risk line failed"),
        }
    }
    st.notifier.surface(&request, &agent).await;
}
