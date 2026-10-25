//! `create_request` (spec §4.1) and delegation resolution (§4.2).

use agent_auth_core::lifecycle::state;
use agent_auth_core::policy::PolicyInput;
use agent_auth_core::routing::Route;
use agent_auth_core::{Authority, DecisionSource, RequestId, RuleId};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::requests::{
    self, Approval, Denial, Escalation, LlmRound, NewRequest, Request, RequestRow,
};
use agent_auth_store::{Delegation, Tx, lockdown};
use agent_auth_wire::agent::RequestCreate;
use serde_json::Value;
use time::OffsetDateTime;

use super::provision::{begin_provision, finish_provision, step};
use super::routing::{Delegator, clamp_duration, evaluate_and_route, saved_rules, zone_check};
use super::{ServiceError, ServiceResult, agent_ref_of, llm_task};
use crate::auth::AgentCaller;
use crate::notify::Notify;
use crate::provisioners::{Provisioner, RequestSpec};
use crate::state::AppState;

/// What the request row starts from, refused or not.
struct Draft<'a> {
    id: RequestId,
    agent: &'a AgentRow,
    session: Option<agent_auth_core::SessionId>,
    delegation: Option<Delegation>,
    body: &'a RequestCreate,
    requested_scope: Value,
    notes: Vec<String>,
    now: OffsetDateTime,
}

impl Draft<'_> {
    async fn insert(
        &self,
        tx: &Tx<'_>,
        resource: &str,
        authority: Option<&Authority>,
    ) -> ServiceResult<Request<state::Pending>> {
        Ok(requests::insert(
            tx,
            &NewRequest {
                id: self.id,
                agent_id: self.agent.id,
                session_id: self.session,
                delegation: self.delegation,
                platform: self.body.platform,
                resource,
                requested_capability: self.body.capability.as_str(),
                requested_scope: &self.requested_scope,
                authority,
                justification: self.body.justification.as_str(),
                requested_duration_secs: self.body.requested_duration.get(),
                risk_notes: &self.notes,
                now: self.now,
            },
        )
        .await?)
    }

    /// Persist the request refused (`decision_source = policy`).
    async fn refuse(
        &self,
        tx: &Tx<'_>,
        resource: &str,
        authority: Option<&Authority>,
        reason: String,
    ) -> ServiceResult<RequestRow> {
        let pending = self.insert(tx, resource, authority).await?;
        let denied = step::<_, state::Denied>(
            tx,
            pending,
            Denial {
                source: DecisionSource::Policy,
                decided_by: None,
                reason,
            },
            self.now,
        )
        .await?;
        Ok(denied.into_row())
    }
}

/// What happens after the creating transaction commits.
enum After {
    Nothing,
    Llm,
    Surface,
    /// A saved rule decided (approve or deny): its audit line.
    RuleApplied(RuleId),
    /// The policy file approved: announced if `notify.auto_approvals`.
    PolicyApproved,
}

/// `POST /v1/requests`. A refusal is a request recorded DENIED, not an
/// error; the one error is a platform this broker does not run (400, and
/// nothing is recorded).
pub async fn create(
    st: &AppState,
    caller: &AgentCaller,
    body: RequestCreate,
) -> ServiceResult<RequestRow> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let mut draft = Draft {
        id: RequestId::new(),
        agent: caller.agent(),
        session: caller.session_id(),
        delegation: None,
        body: &body,
        requested_scope: Value::Object(body.scope.as_map().clone()),
        notes: Vec::new(),
        now,
    };
    let resource = body.resource.as_str();

    // Containment, and an agent disabled (or out of lease) since it
    // authenticated: nothing new (INV-1). The proof also holds the
    // containment lock until this transaction ends.
    let not_held = match lockdown::check(&tx, caller.id(), now).await? {
        Ok(n) => n,
        Err(held) => {
            let row = draft.refuse(&tx, resource, None, held.text()).await?;
            tx.commit().await?;
            return Ok(row);
        }
    };
    let agent = not_held.agent().clone();
    draft.agent = &agent;

    let mut delegator = Delegator::None;
    if let Some(cited) = body.on_behalf_of_thread.as_ref().map(|t| t.as_str())
        && !cited.is_empty()
    {
        match crate::a2a::delegation::resolve(&tx, caller, body.platform, cited).await? {
            Ok(resolved) => {
                let (delegation, note) = (resolved.delegation, resolved.risk_note);
                draft.delegation = Some(delegation);
                draft.notes.push(note);
                delegator = match agents::get(&tx, delegation.delegator_agent_id).await? {
                    Some(d) => Delegator::Agent(Box::new(d)),
                    None => Delegator::Gone,
                };
            }
            Err(problem) => {
                let row = draft
                    .refuse(&tx, resource, None, format!("delegation: {problem}"))
                    .await?;
                tx.commit().await?;
                return Ok(row);
            }
        }
    }

    // A platform this broker does not run: 400, nothing recorded.
    let provisioner = st
        .registry
        .get(body.platform)
        .ok_or(ServiceError::NotEnabled(body.platform))?;

    let parsed = Authority::from_wire(body.platform, body.capability.as_str(), body.scope.as_map());
    let authority = match parsed {
        Ok(a) => a,
        Err(e) => {
            let row = draft
                .refuse(&tx, resource, None, format!("validator: {e}"))
                .await?;
            tx.commit().await?;
            return Ok(row);
        }
    };
    let spec = RequestSpec {
        agent: &agent,
        resource: resource.to_owned(),
        authority: authority.clone(),
    };
    let validated = match provisioner.validate(&tx, spec, now).await? {
        Ok(v) => v,
        Err(refused) => {
            let row = draft
                .refuse(
                    &tx,
                    resource,
                    Some(&authority),
                    format!("validator: {refused}"),
                )
                .await?;
            tx.commit().await?;
            return Ok(row);
        }
    };
    if validated.authority.platform() != body.platform {
        return Err(ServiceError::Store(
            agent_auth_store::StoreError::OutOfRange(
                "a validator returned another platform's authority".to_owned(),
            ),
        ));
    }

    // Restricted zones, before any rule (INV-9).
    let zone = match zone_check(
        &st.policy,
        &tx,
        &agent,
        &validated.authority,
        &validated.resource,
    )
    .await?
    {
        Ok(z) => z,
        Err(denied) => {
            let row = draft
                .refuse(
                    &tx,
                    &validated.resource,
                    Some(&validated.authority),
                    denied.request_reason(),
                )
                .await?;
            tx.commit().await?;
            return Ok(row);
        }
    };
    draft.notes.extend(validated.notes.iter().cloned());

    let (saved, rows) = saved_rules(&tx, body.platform, now).await?;
    let input = PolicyInput {
        agent: agent_ref_of(&agent),
        delegation: delegator.as_policy(),
        resource: &validated.resource,
        authority: &validated.authority,
    };
    let (decision, routed) =
        evaluate_and_route(&st.policy, draft.id, &input, &saved, &rows, &zone, now);
    draft.notes.extend(routed.notes.iter().cloned());
    let source = decision.source();
    let final_action = routed.route.action();
    let applied_rule = decision.rule_id().filter(|_| {
        source == DecisionSource::Rule
            && matches!(
                final_action,
                agent_auth_core::PolicyAction::Approve | agent_auth_core::PolicyAction::Deny
            )
    });

    let pending = draft
        .insert(&tx, &validated.resource, Some(&validated.authority))
        .await?;
    let mut grant = None;
    let (row, after) = match routed.route {
        Route::Deny => {
            let r = step::<_, state::Denied>(
                &tx,
                pending,
                Denial {
                    source,
                    decided_by: None,
                    reason: decision.reason.clone(),
                },
                now,
            )
            .await?;
            let after = applied_rule.map_or(After::Nothing, After::RuleApplied);
            (r.into_row(), after)
        }
        Route::Approve(clearance) => {
            let requested = clamp_duration(body.requested_duration.get());
            let duration = st
                .policy
                .cap_duration(requested, Some(decision.max_duration));
            let decided_by = match (decision.window, decision.rule_id()) {
                (true, Some(id)) => format!("window:{id}"),
                _ => "policy".to_owned(),
            };
            let approved = step::<_, state::Approved>(
                &tx,
                pending,
                Approval::auto(
                    clearance,
                    decided_by,
                    decision.reason.clone(),
                    duration.get(),
                ),
                now,
            )
            .await?;
            let id = approved.id();
            grant = begin_provision(&tx, approved, now).await?;
            let row = requests::get(&tx, id)
                .await?
                .map(requests::AnyRequest::into_row)
                .ok_or_else(|| ServiceError::transition(super::provision::CONCURRENT))?;
            let after = match applied_rule {
                Some(rule) => After::RuleApplied(rule),
                None if source == DecisionSource::Policy => After::PolicyApproved,
                None => After::Nothing,
            };
            (row, after)
        }
        Route::Llm(_) if st.spine.llm.is_none() => {
            let r = step::<_, state::AwaitingHuman>(
                &tx,
                pending,
                Escalation {
                    note: Some("llm evaluator unavailable".to_owned()),
                },
                now,
            )
            .await?;
            (r.into_row(), After::Surface)
        }
        Route::Llm(clearance) => {
            let r = step::<_, state::LlmEvaluating>(
                &tx,
                pending,
                LlmRound {
                    clearance,
                    justification: None,
                },
                now,
            )
            .await?;
            (r.into_row(), After::Llm)
        }
        Route::Surface => {
            let r =
                step::<_, state::AwaitingHuman>(&tx, pending, Escalation::default(), now).await?;
            (r.into_row(), After::Surface)
        }
    };
    drop(not_held);
    tx.commit().await?;

    let id = row.id;
    let mut row = row;
    if let Some(grant) = grant {
        finish_provision(st, grant).await;
        if let Some(r) = super::decide::reload(st, id).await? {
            row = r;
        }
    }
    match after {
        After::Nothing => {}
        After::Llm => llm_task::spawn(st, id),
        After::Surface => llm_task::surface(st, id).await,
        After::RuleApplied(rule) => notify_rule_applied(st, id, Some(rule)).await,
        After::PolicyApproved => announce_auto_approval(st, &row).await,
    }
    Ok(row)
}

/// `notify.auto_approvals`: the policy file's and the LLM's approvals get
/// the same audit line a saved rule's do.
pub(crate) async fn announce_auto_approval(st: &AppState, request: &RequestRow) {
    let notify = st.policy.notify();
    if notify.auto_approvals && !notify.skip_platforms.contains(&request.platform) {
        notify_rule_applied(st, request.id, None).await;
    }
}

pub(crate) async fn notify_rule_applied(st: &AppState, id: RequestId, rule: Option<RuleId>) {
    let loaded = async {
        let tx = st.store.begin().await?;
        let Some(request) = requests::get(&tx, id)
            .await?
            .map(requests::AnyRequest::into_row)
        else {
            return Ok(None);
        };
        let agent = agents::get(&tx, request.agent_id).await?;
        let rule = match rule {
            Some(r) => agent_auth_store::rules::get(&tx, r).await?,
            None => None,
        };
        let grant = agent_auth_store::grants::by_request(&tx, id).await?;
        Ok::<_, agent_auth_store::StoreError>(agent.map(|a| (request, a, rule, grant)))
    }
    .await;
    match loaded {
        Ok(Some((request, agent, rule, grant))) => {
            st.notifier
                .rule_applied(&request, &agent, rule.as_ref(), grant.as_ref())
                .await;
        }
        Ok(None) => {}
        Err(e) => tracing::error!(request = %id, error = %e, "loading for rule_applied failed"),
    }
}
