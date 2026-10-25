//! Evaluation (`PolicyEngine.evaluate`, spec §5.3) and the gates after it
//! (§4.1 step 9), as pure functions: saved rules (newest first) → policy
//! file rules (first match) → the default; then `routing::route`.

use std::cmp::Reverse;

use time::OffsetDateTime;

use crate::authority::{Authority, HostexecAuthority, rule_covers};
use crate::durations::DurationSecs;
use crate::glob::Glob;
use crate::ids::{RequestId, RuleId};
use crate::lifecycle::DecisionSource;
use crate::platform::Platform;
use crate::pyfmt::repr;
use crate::routing::{Downgrade, GateFacts, PolicyAction, Route, RuleStrength, gate, route};
use crate::zones::ZonePassed;

use super::Policy;
use super::agents::{AgentRef, Delegation, delegator_axis, delegator_matches, resources_for};

/// What a saved rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SavedRuleAction {
    AutoApprove,
    AutoDeny,
}

impl SavedRuleAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SavedRuleAction::AutoApprove => "auto_approve",
            SavedRuleAction::AutoDeny => "auto_deny",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto_approve" => Some(Self::AutoApprove),
            "auto_deny" => Some(Self::AutoDeny),
            _ => None,
        }
    }
}

/// A saved ("DB") rule, as the broker loads it from the `rules` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRule {
    pub id: RuleId,
    pub action: SavedRuleAction,
    /// Glob on the agent's name.
    pub agent_pattern: Glob,
    /// Glob on the delegator's name; None = written without delegation.
    pub delegator_pattern: Option<Glob>,
    pub platform: Platform,
    pub resource_pattern: Glob,
    /// None = any privilege (never counts as pinned); else the rule matches
    /// only requests whose authority it covers (`rule_covers`).
    pub authority: Option<Authority>,
    pub max_duration: Option<DurationSecs>,
    pub enabled: bool,
    pub notes: String,
    /// Past it the rule never matches ("approve all" windows).
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Order saved rules for evaluation: newest first, the id breaking ties so
/// the order is total (bug B-22).
pub fn sort_saved_rules(rules: &mut [SavedRule]) {
    rules.sort_by_key(|r| Reverse((r.created_at, r.id)));
}

/// What is being decided.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    pub agent: AgentRef<'a>,
    pub delegation: Delegation<'a>,
    /// The normalized resource.
    pub resource: &'a str,
    /// The request's authority; its platform is the request's.
    pub authority: &'a Authority,
}

impl PolicyInput<'_> {
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.authority.platform()
    }
}

/// Which layer decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched {
    SavedRule(RuleId),
    /// Index into the policy file's `rules`.
    PolicyRule(usize),
    Default,
}

/// `PolicyDecision`. Only [`Policy::evaluate`] makes one. The public fields
/// are for reading; [`Policy::route`] uses the values evaluation sealed in
/// (changing a field cannot widen what routing clears), and refuses to
/// clear a request whose authority or resource differ from what was
/// evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub reason: String,
    pub matched: Matched,
    /// The rule's cap, or the default maximum.
    pub max_duration: DurationSecs,
    /// The reviewer model and retry budget for this request (the rule's
    /// constraints, else `llm.*`; saved rules have none).
    pub llm_model: String,
    pub retry_budget: u32,
    /// A saved rule pinned to an authority covering this one: the only
    /// thing that clears a sensitive authority without a human.
    pub pinned: bool,
    /// The rule names this privilege (pinned, or a policy rule for this
    /// platform whose capability is literally the request's).
    pub explicit: bool,
    /// A hostexec "approve all" window.
    pub window: bool,
    sealed: Sealed,
}

/// What evaluation decided, as routing reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sealed {
    action: PolicyAction,
    pinned: bool,
    explicit: bool,
    source: DecisionSource,
    authority: Authority,
    resource: String,
}

impl Sealed {
    fn of(
        input: &PolicyInput<'_>,
        action: PolicyAction,
        pinned: bool,
        explicit: bool,
        matched: Matched,
    ) -> Sealed {
        Sealed {
            action,
            pinned,
            explicit,
            source: match matched {
                Matched::SavedRule(_) => DecisionSource::Rule,
                Matched::PolicyRule(_) | Matched::Default => DecisionSource::Policy,
            },
            authority: input.authority.clone(),
            resource: input.resource.to_owned(),
        }
    }
}

impl PolicyDecision {
    /// `rule` for a saved rule, else `policy`.
    #[must_use]
    pub fn source(&self) -> DecisionSource {
        match self.matched {
            Matched::SavedRule(_) => DecisionSource::Rule,
            Matched::PolicyRule(_) | Matched::Default => DecisionSource::Policy,
        }
    }

    #[must_use]
    pub fn rule_id(&self) -> Option<RuleId> {
        match self.matched {
            Matched::SavedRule(id) => Some(id),
            _ => None,
        }
    }
}

/// `cap_duration`: the smallest of the request, the default maximum and
/// the rule's cap.
#[must_use]
pub fn cap_duration(
    requested: DurationSecs,
    default_max: DurationSecs,
    rule_max: Option<DurationSecs>,
) -> DurationSecs {
    let capped = requested.min(default_max);
    rule_max.map_or(capped, |m| capped.min(m))
}

/// The default action for a request. A delegated request is never cleared
/// by the default (bug B-7): the default is treated like a rule written
/// without delegation in mind.
#[must_use]
pub fn default_action(configured: PolicyAction, delegated: bool) -> PolicyAction {
    if delegated && configured.is_auto() {
        PolicyAction::Surface
    } else {
        configured
    }
}

/// The request after the gates: the route, which gates fired, and the risk
/// notes to append (in order).
#[derive(Debug, PartialEq, Eq)]
pub struct RoutedRequest {
    pub route: Route,
    pub downgrades: Vec<Downgrade>,
    pub notes: Vec<String>,
}

impl Policy {
    /// Evaluate the policy for a request. `saved` are the saved rules in
    /// evaluation order (newest first; see [`sort_saved_rules`]); disabled
    /// rules and rules of other platforms are skipped here.
    #[must_use]
    pub fn evaluate(
        &self,
        input: &PolicyInput<'_>,
        saved: &[SavedRule],
        now: OffsetDateTime,
    ) -> PolicyDecision {
        if let Some(decision) = self.match_saved(input, saved, now) {
            return decision;
        }
        let capability = input.authority.capability();
        for (i, rule) in self.rules().iter().enumerate() {
            let m = &rule.matches;
            if m.platform.is_some_and(|p| p != input.platform()) {
                continue;
            }
            let resource_ok = || {
                resources_for(&m.resource, &input.agent, self.projects())
                    .iter()
                    .any(|r| Glob::new(r).matches(input.resource))
            };
            let matches = m.agent.matches(&input.agent)
                && m.capability.matches(&capability)
                && resource_ok()
                && delegator_matches(
                    m.delegator.as_ref(),
                    &input.delegation,
                    rule.action.is_auto(),
                );
            if !matches {
                continue;
            }
            let c = &rule.constraints;
            let explicit = m.platform.is_some() && m.capability.as_str() == capability;
            return PolicyDecision {
                action: rule.action,
                reason: if rule.reason.is_empty() {
                    "matched policy rule".to_owned()
                } else {
                    rule.reason.clone()
                },
                matched: Matched::PolicyRule(i),
                max_duration: c.max_duration.unwrap_or(self.defaults().max_duration),
                llm_model: c
                    .llm_model
                    .clone()
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| self.llm().model.clone()),
                retry_budget: c.retry_budget.unwrap_or(self.llm().retry_budget),
                pinned: false,
                // Literal equality, and only for a rule about this platform
                // (bug B-16: `capability: use` without a platform named
                // both mcp and models).
                explicit,
                window: false,
                sealed: Sealed::of(input, rule.action, false, explicit, Matched::PolicyRule(i)),
            };
        }
        let action = default_action(self.defaults().action, input.delegation.is_delegated());
        PolicyDecision {
            action,
            reason: "no matching rule; policy default".to_owned(),
            matched: Matched::Default,
            max_duration: self.defaults().max_duration,
            llm_model: self.llm().model.clone(),
            retry_budget: self.llm().retry_budget,
            pinned: false,
            explicit: false,
            window: false,
            sealed: Sealed::of(input, action, false, false, Matched::Default),
        }
    }

    fn match_saved(
        &self,
        input: &PolicyInput<'_>,
        saved: &[SavedRule],
        now: OffsetDateTime,
    ) -> Option<PolicyDecision> {
        let platform = input.platform();
        let rule = saved.iter().find(|rule| {
            let fits = match (&rule.delegator_pattern, &input.delegation) {
                (Some(g), Delegation::Agent(d)) => g.matches(d.name),
                _ => false,
            };
            rule.enabled
                && rule.platform == platform
                && rule.expires_at.is_none_or(|e| e > now)
                && rule.agent_pattern.matches(input.agent.name)
                && rule.resource_pattern.matches(input.resource)
                && delegator_axis(
                    rule.delegator_pattern.is_some(),
                    fits,
                    input.delegation.is_delegated(),
                    rule.action == SavedRuleAction::AutoApprove,
                )
                && rule_covers(rule.authority.as_ref(), input.authority)
        })?;
        let pinned = rule.authority.is_some();
        let action = match rule.action {
            SavedRuleAction::AutoApprove => PolicyAction::Approve,
            SavedRuleAction::AutoDeny => PolicyAction::Deny,
        };
        Some(PolicyDecision {
            action,
            reason: if rule.notes.is_empty() {
                "matched saved rule".to_owned()
            } else {
                format!("matched saved rule ({})", rule.notes)
            },
            matched: Matched::SavedRule(rule.id),
            max_duration: rule.max_duration.unwrap_or(self.defaults().max_duration),
            llm_model: self.llm().model.clone(),
            retry_budget: self.llm().retry_budget,
            pinned,
            explicit: pinned,
            window: matches!(
                rule.authority,
                Some(Authority::Hostexec(HostexecAuthority::Window { .. }))
            ),
            sealed: Sealed::of(input, action, pinned, pinned, Matched::SavedRule(rule.id)),
        })
    }

    /// The facts the gates read, all derived from the request and the
    /// zone check (none from the agent's say-so).
    #[must_use]
    pub fn gate_facts(&self, input: &PolicyInput<'_>, zone: &ZonePassed) -> GateFacts {
        GateFacts {
            zone_requires_human: zone.human_note().is_some(),
            human_only: input.authority.human_only(),
            web_connector: input.agent.is_web() || input.delegation.is_web(),
            sensitive: input
                .authority
                .is_sensitive(&self.sensitivity(), input.resource),
            needs_explicit_rule: input.authority.needs_explicit_rule(),
        }
    }

    /// Apply the gates to a decision (§4.1 step 9) for `request`. Needs
    /// the zone check's pass, so a request cannot be routed without it; the
    /// facts about the authority (human-only, sensitive, needs a named rule)
    /// are computed here, not taken from the caller. A clearance in the
    /// result is bound to `request` and the evaluated authority. A decision
    /// evaluated for another authority or resource clears nothing.
    #[must_use]
    pub fn route(
        &self,
        request: RequestId,
        input: &PolicyInput<'_>,
        decision: &PolicyDecision,
        zone: &ZonePassed,
    ) -> RoutedRequest {
        let sealed = &decision.sealed;
        let same = sealed.authority == *input.authority && sealed.resource == input.resource;
        let (proposed, strength) = if same {
            (
                sealed.action,
                RuleStrength {
                    pinned: sealed.pinned,
                    explicit: sealed.explicit,
                },
            )
        } else if sealed.action == PolicyAction::Deny {
            (PolicyAction::Deny, RuleStrength::NONE)
        } else {
            (PolicyAction::Surface, RuleStrength::NONE)
        };
        let gated = gate(proposed, strength, self.gate_facts(input, zone));
        let notes = gated
            .downgrades
            .iter()
            .map(|d| match d {
                Downgrade::Zone => zone
                    .human_note()
                    .unwrap_or("restricted zone: always a human")
                    .to_owned(),
                Downgrade::HumanOnly => "always decided by a human".to_owned(),
                Downgrade::WebConnector => {
                    "for a web UI connector: always decided by a human".to_owned()
                }
                Downgrade::Sensitive => "sensitive capability — routed to human review".to_owned(),
                Downgrade::NotNamed => format!(
                    "no rule names {} — routed to human review",
                    repr(&input.authority.capability())
                ),
            })
            .collect();
        RoutedRequest {
            route: route(gated.action, request, input.authority, sealed.source),
            downgrades: gated.downgrades,
            notes,
        }
    }

    /// [`Policy::evaluate`] then [`Policy::route`]: the broker's one call.
    #[must_use]
    pub fn evaluate_and_route(
        &self,
        request: RequestId,
        input: &PolicyInput<'_>,
        saved: &[SavedRule],
        zone: &ZonePassed,
        now: OffsetDateTime,
    ) -> (PolicyDecision, RoutedRequest) {
        let decision = self.evaluate(input, saved, now);
        let routed = self.route(request, input, &decision, zone);
        (decision, routed)
    }
}
