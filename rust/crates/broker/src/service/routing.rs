//! From a request to a route: the facts zones need, the saved rules, the
//! policy evaluation and its gates (spec §4.1 steps 6-9, §5.3, §8.6).

use agent_auth_core::authority::{Authority, SensitivityConfig};
use agent_auth_core::policy::{
    AgentRef, Delegation, PolicyDecision, PolicyInput, RoutedRequest, SavedRule, SavedRuleAction,
    sort_saved_rules,
};
use agent_auth_core::routing::{Downgrade, PolicyAction, Route};
use agent_auth_core::zones::{self, ZoneDenied, ZoneFacts, ZonePassed};
use agent_auth_core::{DurationSecs, Glob, Platform, Policy, RequestId};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::{self, RuleAction, RuleRow};
use agent_auth_store::{StoreError, Tx, daemons};
use agent_auth_wire::catalog::Disposition;
use time::OffsetDateTime;

use super::agent_ref_of;

/// The delegator of a request, as loaded.
#[derive(Debug, Clone)]
pub(crate) enum Delegator {
    /// Not delegated.
    None,
    /// Delegated, but the delegator's row is gone.
    Gone,
    Agent(Box<AgentRow>),
}

impl Delegator {
    pub(crate) fn as_policy(&self) -> Delegation<'_> {
        match self {
            Delegator::None => Delegation::None,
            Delegator::Gone => Delegation::Gone,
            Delegator::Agent(a) => Delegation::Agent(agent_ref_of(a)),
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Delegator::Agent(a) => Some(&a.name),
            _ => None,
        }
    }
}

pub(crate) async fn delegator_of(
    tx: &Tx<'_>,
    request: &RequestRow,
) -> Result<Delegator, StoreError> {
    let Some(d) = request.delegation else {
        return Ok(Delegator::None);
    };
    Ok(match agents::get(tx, d.delegator_agent_id).await? {
        Some(a) => Delegator::Agent(Box::new(a)),
        None => Delegator::Gone,
    })
}

/// `Zones.check` with the facts it needs read from the database.
pub(crate) async fn zone_check(
    policy: &Policy,
    tx: &Tx<'_>,
    agent: &AgentRow,
    authority: &Authority,
    resource: &str,
) -> Result<Result<ZonePassed, ZoneDenied>, StoreError> {
    let me = agent_ref_of(agent);
    if policy.restricted().is_empty() {
        return Ok(zones::check(
            policy,
            &me,
            authority,
            resource,
            &ZoneFacts::Nothing,
        ));
    }
    let daemon_name = match agent.sandbox_id {
        Some(id) => daemons::get(tx, id).await?.map(|d| d.name),
        None => None,
    };
    let result = match authority.platform() {
        Platform::A2a => {
            let peer = agents::by_name(tx, resource).await?;
            let facts = ZoneFacts::A2aPeer(peer.as_ref().map(agent_ref_of));
            zones::check(policy, &me, authority, resource, &facts)
        }
        Platform::Sandbox => {
            let in_vm: Vec<AgentRow> = match agent.sandbox_id {
                Some(id) => agents::list_in_sandbox(tx, id)
                    .await?
                    .into_iter()
                    .filter(|a| a.project.as_deref() == Some(resource))
                    .collect(),
                None => Vec::new(),
            };
            let refs: Vec<AgentRef<'_>> = in_vm.iter().map(agent_ref_of).collect();
            let facts = ZoneFacts::Sandbox {
                daemon: daemon_name.as_deref(),
                project_agents: &refs,
            };
            zones::check(policy, &me, authority, resource, &facts)
        }
        Platform::Agents => {
            let facts = ZoneFacts::Agents {
                daemon: daemon_name.as_deref(),
            };
            zones::check(policy, &me, authority, resource, &facts)
        }
        _ => zones::check(policy, &me, authority, resource, &ZoneFacts::Nothing),
    };
    Ok(result)
}

fn saved_rule(r: &RuleRow) -> SavedRule {
    SavedRule {
        id: r.id,
        action: match r.action {
            RuleAction::AutoApprove => SavedRuleAction::AutoApprove,
            RuleAction::AutoDeny => SavedRuleAction::AutoDeny,
        },
        agent_pattern: Glob::new(&r.agent_pattern),
        delegator_pattern: r.delegator_pattern.as_deref().map(Glob::new),
        platform: r.platform,
        resource_pattern: Glob::new(&r.resource_pattern),
        authority: r.authority.clone(),
        max_duration: r.max_duration_secs.map(clamp_duration),
        enabled: r.enabled,
        notes: r.notes.clone(),
        expires_at: r.expires_at,
        created_at: r.created_at,
    }
}

/// Seconds as a policy duration: at least 1, at most 365 days (longer
/// values are capped there, as every grant is).
#[must_use]
pub(crate) fn clamp_duration(secs: u32) -> DurationSecs {
    DurationSecs::from_secs(i64::from(secs.clamp(1, DurationSecs::MAX.get())))
        .unwrap_or(DurationSecs::MAX)
}

/// The live saved rules of a platform, in evaluation order, with the rows
/// (to find a matched rule's resource pattern).
pub(crate) async fn saved_rules(
    tx: &Tx<'_>,
    platform: Platform,
    now: OffsetDateTime,
) -> Result<(Vec<SavedRule>, Vec<RuleRow>), StoreError> {
    let rows = rules::live_for(tx, platform, now).await?;
    let mut saved: Vec<SavedRule> = rows.iter().map(saved_rule).collect();
    sort_saved_rules(&mut saved);
    Ok((saved, rows))
}

/// Sensitive because of *where* (a sensitive Kubernetes namespace), not
/// *what* (the role).
fn sensitive_by_resource(cfg: &SensitivityConfig, authority: &Authority, resource: &str) -> bool {
    match authority {
        Authority::Kubernetes(k) => {
            !k.cluster
                && !cfg.kubernetes_sensitive_roles.contains(&k.role)
                && cfg.namespace_is_sensitive(resource)
        }
        _ => false,
    }
}

/// Evaluate the policy and apply the gates, for request `request`. A
/// saved rule pinned to the authority clears a request that is sensitive
/// only because of its namespace when the rule names that exact resource
/// (the Python's `pinned_here`, commit 4da3f4e): a pinned `view` rule for
/// `apps-*` does not open `kube-system`. Otherwise an automatic route
/// becomes a human's, as the sensitive gate would have made it.
pub(crate) fn evaluate_and_route(
    policy: &Policy,
    request: RequestId,
    input: &PolicyInput<'_>,
    saved: &[SavedRule],
    rows: &[RuleRow],
    zone: &ZonePassed,
    now: OffsetDateTime,
) -> (PolicyDecision, RoutedRequest) {
    let (decision, mut routed) = policy.evaluate_and_route(request, input, saved, zone, now);
    let names_it = || {
        decision
            .rule_id()
            .and_then(|id| rows.iter().find(|r| r.id == id))
            .is_some_and(|r| r.resource_pattern == input.resource)
    };
    if decision.pinned
        && routed.route.action().is_auto()
        && sensitive_by_resource(&policy.sensitivity(), input.authority, input.resource)
        && !names_it()
    {
        routed.route = Route::Surface;
        routed.downgrades.push(Downgrade::Sensitive);
        routed
            .notes
            .push("sensitive capability — routed to human review".to_owned());
    }
    (decision, routed)
}

/// Everything about routing a stored request again (the LLM-approve path,
/// a window rule, the catalog probe): loads the rules and zone facts.
pub(crate) struct Rerouted {
    pub decision: PolicyDecision,
    /// None: the zone check refused it (membership changed since).
    pub routed: Option<RoutedRequest>,
}

/// A stored request, as routing sees it.
pub(crate) struct Subject<'a> {
    pub request: RequestId,
    pub agent: &'a AgentRow,
    pub delegator: &'a Delegator,
    pub resource: &'a str,
    pub authority: &'a Authority,
}

pub(crate) async fn reroute(
    policy: &Policy,
    tx: &Tx<'_>,
    subject: Subject<'_>,
    now: OffsetDateTime,
) -> Result<Rerouted, StoreError> {
    let Subject {
        request,
        agent,
        delegator,
        resource,
        authority,
    } = subject;
    let (saved, rows) = saved_rules(tx, authority.platform(), now).await?;
    let input = PolicyInput {
        agent: agent_ref_of(agent),
        delegation: delegator.as_policy(),
        resource,
        authority,
    };
    match zone_check(policy, tx, agent, authority, resource).await? {
        Ok(zone) => {
            let (decision, routed) =
                evaluate_and_route(policy, request, &input, &saved, &rows, &zone, now);
            Ok(Rerouted {
                decision,
                routed: Some(routed),
            })
        }
        Err(_) => Ok(Rerouted {
            decision: policy.evaluate(&input, &saved, now),
            routed: None,
        }),
    }
}

/// The catalog's "typical disposition" of a capability (http-api §4.1): a
/// probe for resource `*` with an empty scope, not persisted, best effort
/// (no sensitive, zone or human-only gates).
pub async fn disposition(
    policy: &Policy,
    tx: &Tx<'_>,
    agent: &AgentRow,
    authority: &Authority,
    now: OffsetDateTime,
) -> Result<Disposition, StoreError> {
    let (saved, _) = saved_rules(tx, authority.platform(), now).await?;
    let input = PolicyInput {
        agent: agent_ref_of(agent),
        delegation: Delegation::None,
        resource: "*",
        authority,
    };
    let decision = policy.evaluate(&input, &saved, now);
    if decision.action.is_auto() && !decision.explicit && authority.needs_explicit_rule() {
        return Ok(Disposition::HumanReview);
    }
    Ok(match decision.action {
        PolicyAction::Approve => Disposition::AutoApprove,
        PolicyAction::Surface => Disposition::HumanReview,
        PolicyAction::Llm => Disposition::LlmReview,
        PolicyAction::Deny => Disposition::Denied,
    })
}
