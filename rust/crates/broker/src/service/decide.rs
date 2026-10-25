//! Human decisions (spec §4.6), containment's denials, and applying a new
//! "approve all" window to requests already waiting (§4.11).

use agent_auth_core::lifecycle::state;
use agent_auth_core::policy::glob_literal;
use agent_auth_core::routing::Route;
use agent_auth_core::{
    AgentId, Authority, DecisionSource, HumanApproval, RequestId, RequestStatus, RuleId,
};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::requests::{
    self, AnyRequest, Approval, ApprovedEdit, Denial, Escalation, Request, RequestRow,
};
use agent_auth_store::rules::{self, NewRule, RuleAction};
use agent_auth_store::{StoreError, Tx, lockdown};
use time::OffsetDateTime;

use super::provision::{begin_provision, finish_detached, step};
use super::routing::{Delegator, Subject, clamp_duration, delegator_of, reroute, zone_check};
use super::{HumanDecider, HumanDecision, ServiceError, ServiceResult};
use crate::notify::Notify;
use crate::provisioners::{Provisioner, RequestSpec};
use crate::state::AppState;

/// A human approval may exceed policy caps deliberately, but not a year.
const HUMAN_MAX_DURATION_SECS: u32 = agent_auth_core::durations::MAX_DURATION_SECS;

pub(crate) async fn reload(st: &AppState, id: RequestId) -> Result<Option<RequestRow>, StoreError> {
    let tx = st.store.begin().await?;
    Ok(requests::get(&tx, id).await?.map(AnyRequest::into_row))
}

async fn reload_with_grant(
    st: &AppState,
    id: RequestId,
) -> Result<Option<(RequestRow, Option<GrantRow>)>, StoreError> {
    let tx = st.store.begin().await?;
    let Some(request) = requests::get(&tx, id).await?.map(AnyRequest::into_row) else {
        return Ok(None);
    };
    let grant = grants::by_request(&tx, id).await?;
    Ok(Some((request, grant)))
}

fn resolved(status: RequestStatus) -> ServiceError {
    ServiceError::Transition(format!("request already resolved (status {status})"))
}

/// Who decides: a person, or containment denying what was pending.
enum Decider<'a> {
    Human(&'a HumanDecider),
    /// Only ever denies.
    Containment(&'a str),
}

impl Decider<'_> {
    fn label(&self) -> &str {
        match self {
            Decider::Human(h) => h.label(),
            Decider::Containment(by) => by,
        }
    }
}

/// A human approval: only for a [`HumanDecider`], whose name is recorded
/// as `decided_by`.
async fn approve_human(
    tx: &Tx<'_>,
    request: Request<state::AwaitingHuman>,
    decider: &HumanDecider,
    attested: Option<HumanApproval>,
    reason: String,
    duration_secs: u32,
    now: OffsetDateTime,
) -> ServiceResult<Request<state::Approved>> {
    let attestation = match attested {
        // Made by the surface itself (the Discord bot, after its owner
        // check): it must be this decider's, for this request.
        Some(a) if a.request() == request.id() && a.decided_by() == decider.label() => a,
        Some(_) => {
            return Err(ServiceError::transition(
                "the approval is for another request or person",
            ));
        }
        // Otherwise attested here: an authenticated human surface made
        // the `HumanDecider`.
        None => HumanApproval::attest(request.id(), decider.label()),
    };
    let approval = Approval::human(attestation, reason, duration_secs);
    step::<_, state::Approved>(tx, request, approval, now).await
}

/// A human decides a request that awaits one (or pre-empts the LLM).
/// An approval first passes the platform's approval gate (hostexec), then
/// is re-validated with any edits, including restricted zones (B-5); a
/// rejected edit leaves the request unchanged (INV-20). With `rule`, a
/// saved rule is created as INV-14 says.
pub async fn decide(
    st: &AppState,
    id: RequestId,
    decider: &HumanDecider,
    decision: HumanDecision,
) -> ServiceResult<RequestRow> {
    decide_attested(st, id, decider, decision, None).await
}

/// [`decide`] with the approving surface's own attestation (the Discord
/// bot attests after checking the owner).
pub async fn decide_attested(
    st: &AppState,
    id: RequestId,
    decider: &HumanDecider,
    decision: HumanDecision,
    attested: Option<HumanApproval>,
) -> ServiceResult<RequestRow> {
    if decision.approve {
        run_gate(st, id, &decision).await?;
    }
    let approve = decision.approve;
    let decided = decide_inner(st, id, Decider::Human(decider), attested, decision).await?;
    // A human decided a request the reviewer saw: what its last review
    // should have said (evals; a human's edit is still an approval).
    crate::models::label_outcome(
        &st.store,
        crate::models::Kind::RequestReview,
        "request_id",
        &id.to_string(),
        if approve { "approve" } else { "deny" },
        decider.label(),
    )
    .await;
    Ok(decided)
}

async fn run_gate(st: &AppState, id: RequestId, decision: &HumanDecision) -> ServiceResult<()> {
    let now = st.now();
    let (request, agent) = {
        let tx = st.store.begin().await?;
        let request = requests::get(&tx, id)
            .await?
            .ok_or_else(|| ServiceError::transition("unknown request"))?
            .into_row();
        if !request.status.is_human_decidable() {
            return Err(resolved(request.status));
        }
        // A shell is never approved without a code for the host's own
        // secret, whatever gate is (or is not) registered.
        let shell = matches!(
            request.authority,
            Some(Authority::Hostexec(
                agent_auth_core::authority::HostexecAuthority::Shell { .. }
            ))
        );
        if shell && decision.totp.as_deref().is_none_or(|t| t.trim().is_empty()) {
            return Err(ServiceError::transition(
                "a shell is approved with a TOTP code only (Approve with TOTP)",
            ));
        }
        if !st
            .spine
            .hooks
            .approval_gates
            .contains_key(&request.platform)
        {
            // hostexec approvals always go through the host: without its
            // gate there is nothing to approve with (fail closed).
            if request.platform == agent_auth_core::Platform::Hostexec {
                return Err(ServiceError::transition(
                    "host approvals are unavailable: this broker has no hostexec gate running",
                ));
            }
            return Ok(());
        }
        // Nothing for the gate to spend (a TOTP code) on an agent that
        // would get nothing anyway: the decision goes on and fails at
        // provisioning.
        if lockdown::check(&tx, request.agent_id, now).await?.is_err() {
            return Ok(());
        }
        let agent = agents::get(&tx, request.agent_id)
            .await?
            .ok_or_else(|| ServiceError::transition("unknown request"))?;
        (request, agent)
    };
    if let Some(gate) = st.spine.hooks.approval_gates.get(&request.platform) {
        gate(st.clone(), request, agent, decision.clone())
            .await
            .map_err(ServiceError::Transition)?;
    }
    Ok(())
}

/// The final resource and authority of an approval, validated as at
/// creation (provisioner, then zones).
async fn revalidate(
    st: &AppState,
    tx: &Tx<'_>,
    agent: &AgentRow,
    row: &RequestRow,
    decision: &HumanDecision,
    now: OffsetDateTime,
) -> ServiceResult<ApprovedEdit> {
    let rejected = |why: String| {
        ServiceError::Transition(format!("edited approval rejected by validator: {why}"))
    };
    let current = row
        .authority
        .clone()
        .ok_or_else(|| ServiceError::transition("request has no authority"))?;
    let resource = decision
        .resource_override
        .clone()
        .unwrap_or_else(|| row.resource.clone());
    let authority = match &decision.scope_override {
        Some(scope) => Authority::from_wire(row.platform, &current.capability(), scope)
            .map_err(|e| rejected(e.to_string()))?,
        None => current,
    };
    let provisioner = st
        .registry
        .get(row.platform)
        .ok_or(ServiceError::NotEnabled(row.platform))?;
    let validated = provisioner
        .validate(
            tx,
            RequestSpec {
                agent,
                resource,
                authority,
            },
            now,
        )
        .await?
        .map_err(|r| rejected(r.0))?;
    if validated.authority.platform() != row.platform {
        return Err(rejected("another platform's authority".to_owned()));
    }
    if let Err(denied) = zone_check(
        &st.policy,
        tx,
        agent,
        &validated.authority,
        &validated.resource,
    )
    .await?
    {
        return Err(rejected(denied.text().to_owned()));
    }
    Ok(ApprovedEdit {
        resource: validated.resource,
        authority: validated.authority,
    })
}

async fn decide_inner(
    st: &AppState,
    id: RequestId,
    who: Decider<'_>,
    attested: Option<HumanApproval>,
    decision: HumanDecision,
) -> ServiceResult<RequestRow> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let loaded = requests::get_for_update(&tx, id)
        .await?
        .ok_or_else(|| ServiceError::transition("unknown request"))?;
    // A human overrides the LLM states: hop through AWAITING_HUMAN.
    let awaiting: Request<state::AwaitingHuman> = match loaded {
        AnyRequest::AwaitingHuman(r) => r,
        AnyRequest::LlmEvaluating(r) => {
            step::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now).await?
        }
        AnyRequest::LlmDenied(r) => {
            step::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now).await?
        }
        other => return Err(resolved(other.status())),
    };
    let row = awaiting.row().clone();
    let agent = agents::get(&tx, row.agent_id)
        .await?
        .ok_or_else(|| ServiceError::transition("unknown request"))?;
    let decided_by = who.label().to_owned();
    let approving = match who {
        Decider::Human(h) if decision.approve => Some(h),
        _ => None,
    };

    let edit = match approving {
        Some(_) => Some(revalidate(st, &tx, &agent, &row, &decision, now).await?),
        None => None,
    };

    if let Some(rule) = &decision.rule {
        let delegator = delegator_of(&tx, &row).await?;
        let resource_pattern = match &rule.resource_pattern {
            Some(p) => p.clone(),
            // "Exact": this resource, as a literal (a resource holding `*`
            // must not become a wildcard rule).
            None => glob_literal(edit.as_ref().map_or(&row.resource, |e| &e.resource)),
        };
        let authority = match (&edit, rule.any_authority) {
            (Some(e), false) => Some(&e.authority),
            _ => None,
        };
        let notes = if decision.reason.is_empty() {
            "created from decision"
        } else {
            &decision.reason
        };
        rules::insert(
            &tx,
            &NewRule {
                id: RuleId::new(),
                action: rule.action,
                agent_pattern: &agent.name,
                delegator_pattern: delegator.name(),
                platform: row.platform,
                resource_pattern: &resource_pattern,
                authority,
                max_duration_secs: decision
                    .duration_secs
                    .map(|d| d.min(HUMAN_MAX_DURATION_SECS)),
                created_by: &decided_by,
                notes,
                expires_at: None,
                now,
            },
        )
        .await?;
    }

    let mut grant = None;
    match (approving, edit) {
        (Some(human), Some(edit)) => {
            let base = match decision.duration_secs {
                Some(d) => d,
                None => st
                    .policy
                    .cap_duration(clamp_duration(row.requested_duration_secs), None)
                    .get(),
            };
            let mut approved = approve_human(
                &tx,
                awaiting,
                human,
                attested,
                decision.reason.clone(),
                base.clamp(1, HUMAN_MAX_DURATION_SECS),
                now,
            )
            .await?;
            requests::set_approved_edit(&tx, &mut approved, edit)
                .await?
                .map_err(|_| ServiceError::transition(super::provision::CONCURRENT))?;
            grant = begin_provision(&tx, approved, now).await?;
        }
        _ => {
            step::<_, state::Denied>(
                &tx,
                awaiting,
                Denial {
                    source: DecisionSource::Human,
                    decided_by: Some(decided_by),
                    reason: decision.reason.clone(),
                },
                now,
            )
            .await?;
        }
    }
    tx.commit().await?;

    if let Some(g) = grant {
        finish_detached(st, g).await;
    }
    let (request, grant) = reload_with_grant(st, id)
        .await?
        .ok_or_else(|| ServiceError::transition("unknown request"))?;
    st.request_events.notify(&id);
    st.notifier.update_outcome(&request, grant.as_ref()).await;
    Ok(request)
}

/// Containment: deny every request of these agents still waiting on the
/// LLM or a human (`decided_by` = who contained). Returns how many.
pub async fn deny_pending(
    st: &AppState,
    agents_held: &[AgentId],
    reason: &str,
    by: &str,
) -> ServiceResult<usize> {
    if agents_held.is_empty() {
        return Ok(0);
    }
    let ids = {
        let tx = st.store.begin().await?;
        requests::decidable_of(&tx, agents_held).await?
    };
    let mut denied = 0usize;
    for id in ids {
        match decide_inner(
            st,
            id,
            Decider::Containment(by),
            None,
            HumanDecision::deny(reason),
        )
        .await
        {
            Ok(_) => denied = denied.saturating_add(1),
            Err(ServiceError::Transition(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(denied)
}

/// A saved rule was just created (an "approve all" window): approve the
/// requests already waiting for a human that the policy now clears through
/// that rule. Each is routed again with every gate, so a web connector's,
/// a restricted zone's or a shell's request still waits for a person (B-6).
/// Returns the approved ids.
pub async fn apply_rule_to_pending(
    st: &AppState,
    rule_id: RuleId,
) -> ServiceResult<Vec<RequestId>> {
    let now = st.now();
    let (rule, waiting) = {
        let tx = st.store.begin().await?;
        let Some(rule) = rules::get(&tx, rule_id).await? else {
            return Ok(Vec::new());
        };
        if rule.action != RuleAction::AutoApprove || !rule.is_live(now) {
            return Ok(Vec::new());
        }
        let waiting = requests::awaiting_human_on(&tx, rule.platform).await?;
        (rule, waiting)
    };
    let window = matches!(
        rule.authority,
        Some(Authority::Hostexec(
            agent_auth_core::authority::HostexecAuthority::Window { .. }
        ))
    );
    let mut approved = Vec::new();
    for request in waiting {
        let id = request.id;
        let grant = match apply_one(st, id, &rule, window).await {
            Ok(Some(g)) => g,
            Ok(None) | Err(ServiceError::Transition(_)) => continue,
            Err(e) => {
                tracing::error!(request = %id, error = %e, "applying a window rule failed");
                continue;
            }
        };
        if let Some(g) = grant {
            finish_detached(st, g).await;
        }
        if let Some((request, grant)) = reload_with_grant(st, id).await? {
            st.request_events.notify(&id);
            st.notifier.update_outcome(&request, grant.as_ref()).await;
        }
        approved.push(id);
    }
    Ok(approved)
}

/// `Ok(None)`: not cleared by this rule. `Ok(Some(grant))`: approved.
async fn apply_one(
    st: &AppState,
    id: RequestId,
    rule: &rules::RuleRow,
    window: bool,
) -> ServiceResult<Option<Option<agent_auth_core::GrantId>>> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get_for_update(&tx, id).await? else {
        return Ok(None);
    };
    let Some(agent) = agents::get(&tx, r.agent_id()).await? else {
        return Ok(None);
    };
    let Some(authority) = r.row().authority.clone() else {
        return Ok(None);
    };
    let delegator: Delegator = delegator_of(&tx, r.row()).await?;
    let rerouted = reroute(
        &st.policy,
        &tx,
        Subject {
            request: id,
            agent: &agent,
            delegator: &delegator,
            resource: &r.row().resource,
            authority: &authority,
        },
        now,
    )
    .await?;
    if rerouted.decision.rule_id() != Some(rule.id) {
        return Ok(None);
    }
    let Some(Route::Approve(clearance)) = rerouted.routed.map(|x| x.route) else {
        return Ok(None);
    };
    let duration = st.policy.cap_duration(
        clamp_duration(r.row().requested_duration_secs),
        rule.max_duration_secs.map(clamp_duration),
    );
    let (decided_by, reason) = if window {
        (format!("window:{}", rule.id), "approve-all window")
    } else {
        ("rule".to_owned(), "matched saved rule")
    };
    let approved = step::<_, state::Approved>(
        &tx,
        r,
        Approval::auto(clearance, decided_by, reason, duration.get()),
        now,
    )
    .await?;
    let grant = begin_provision(&tx, approved, now).await?;
    tx.commit().await?;
    Ok(Some(grant))
}
