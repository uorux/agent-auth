//! The gates between a policy decision and what actually happens to a
//! request (core/service.py `create_request`, step 9 in the spec).
//!
//! The policy engine proposes an action; the gates may only ever *downgrade*
//! `approve`/`llm` to `surface` (a human decides). An auto-approval in the
//! broker requires an [`AutoClearance`] (and an LLM review an
//! [`LlmClearance`]), which only this crate constructs, from
//! [`crate::Policy::route`] / [`crate::Policy::evaluate_and_route`]: those
//! need the zone check's pass and compute every gate fact about the
//! authority themselves. A clearance names the request and the authority it
//! was computed for, so it cannot be spent on another request (the store
//! checks both). Nothing outside this crate can make one:
//!
//! ```compile_fail
//! use agent_auth_core::{AutoClearance, DecisionSource, RequestId, Authority};
//! fn forge(request: RequestId) -> AutoClearance {
//!     AutoClearance { request, authority: Authority::Models, source: DecisionSource::Policy }
//! }
//! ```
//!
//! Invariants (numbered as in rust/spec/core-lifecycle-policy.md §5.4), all
//! checked exhaustively in the tests below and by the Kani harnesses in
//! `crate::proofs`:
//! - INV-4  gates only downgrade: the result is the proposal or `surface`,
//!   and `deny` stays `deny`, `surface` stays `surface`.
//! - INV-5  human-only authorities (a host shell) never auto-clear.
//! - INV-6  a web-UI agent, or a request on one's behalf, never auto-clears.
//! - INV-7  a sensitive authority auto-clears only via a saved rule pinned
//!   to (covering) its exact authority; when only the resource makes it
//!   sensitive (a sensitive namespace, a pool's sensitive item), only via
//!   such a rule naming exactly that resource (not a glob reaching it).
//! - INV-8  an explicit-only authority auto-clears only via a rule naming it.
//! - INV-9  a restricted zone requiring a human never auto-clears.

use crate::authority::Authority;
use crate::ids::RequestId;
use crate::lifecycle::DecisionSource;

/// What a policy layer proposes for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Deny,
    Approve,
    /// Route to the LLM reviewer (which may approve).
    Llm,
    /// A human decides.
    Surface,
}

impl PolicyAction {
    pub const ALL: [PolicyAction; 4] = [
        PolicyAction::Deny,
        PolicyAction::Approve,
        PolicyAction::Llm,
        PolicyAction::Surface,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyAction::Deny => "deny",
            PolicyAction::Approve => "approve",
            PolicyAction::Llm => "llm",
            PolicyAction::Surface => "surface",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// Would this clear the request without a human?
    #[must_use]
    pub const fn is_auto(self) -> bool {
        matches!(self, PolicyAction::Approve | PolicyAction::Llm)
    }
}

/// How strongly the matched rule names the request's privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleStrength {
    /// A saved rule pinned to an authority covering this one. The only thing
    /// that lets a sensitive authority through without a human.
    pub pinned: bool,
    /// The rule names this privilege: pinned, or a policy-file rule whose
    /// `match.capability` is literally the request's capability.
    pub explicit: bool,
    /// A pinned saved rule whose resource pattern is exactly the request's
    /// resource (the Python's `rule_resource == request.resource`): the
    /// only pinned rule that clears a sensitivity coming from the resource.
    pub names_resource: bool,
}

impl RuleStrength {
    pub(crate) const NONE: RuleStrength = RuleStrength {
        pinned: false,
        explicit: false,
        names_resource: false,
    };

    /// Does the rule clear a sensitive request (the Python's
    /// `pinned_here`)? Pinned, and naming the very resource when the
    /// resource is what makes it sensitive.
    #[must_use]
    pub const fn clears_sensitive(self, facts: GateFacts) -> bool {
        self.pinned && (self.names_resource || !facts.sensitive_by_resource)
    }
}

/// Facts about the request the gates look at, all computed by
/// [`crate::Policy::gate_facts`] from the request (the authority's own
/// predicates) and the zone check; none comes from the requesting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateFacts {
    /// A restricted zone owns the resource and wants a human.
    pub zone_requires_human: bool,
    /// `Authority::human_only` (a host shell).
    pub human_only: bool,
    /// The agent, or the agent it acts for, is a web-UI connector.
    pub web_connector: bool,
    /// `Authority::is_sensitive` for this resource.
    pub sensitive: bool,
    /// `Authority::sensitive_by_resource`: sensitive only because of the
    /// resource (where), not the authority (what).
    pub sensitive_by_resource: bool,
    /// `Authority::needs_explicit_rule`.
    pub needs_explicit_rule: bool,
}

/// Why a gate downgraded the proposal. Rendered into the request's risk
/// notes (the human and the LLM reviewer see them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Downgrade {
    Zone,
    HumanOnly,
    WebConnector,
    Sensitive,
    NotNamed,
}

/// Proof that a request passed every gate with `approve`: what the broker's
/// auto-approve path needs (the store's `Approval::auto`). Made only by
/// [`crate::Policy::route`]; not `Clone`.
#[derive(Debug, PartialEq, Eq)]
pub struct AutoClearance {
    request: RequestId,
    authority: Authority,
    source: DecisionSource,
}

impl AutoClearance {
    /// The request it was computed for.
    #[must_use]
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// The authority it was computed for.
    #[must_use]
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// `rule` (a saved rule matched) or `policy` (the file or the default).
    #[must_use]
    pub fn source(&self) -> DecisionSource {
        self.source
    }
}

/// Proof that a request passed every gate with `llm`: what entering LLM
/// review and an LLM approval need. Made only by [`crate::Policy::route`];
/// not `Clone`, and a different type from [`AutoClearance`] so one cannot
/// stand in for the other.
#[derive(Debug, PartialEq, Eq)]
pub struct LlmClearance {
    request: RequestId,
    authority: Authority,
}

impl LlmClearance {
    #[must_use]
    pub fn request(&self) -> RequestId {
        self.request
    }

    #[must_use]
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Deny,
    Surface,
    Approve(AutoClearance),
    Llm(LlmClearance),
}

impl Route {
    #[must_use]
    pub fn action(&self) -> PolicyAction {
        match self {
            Route::Deny => PolicyAction::Deny,
            Route::Surface => PolicyAction::Surface,
            Route::Approve(_) => PolicyAction::Approve,
            Route::Llm(_) => PolicyAction::Llm,
        }
    }
}

/// The outcome of the gates: the action, and every gate that downgraded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Gated {
    pub(crate) action: PolicyAction,
    pub(crate) downgrades: Vec<Downgrade>,
}

/// Apply the gates to a policy proposal, in the Python's order. Each gate
/// fires only while the action is still automatic; the zone, human-only and
/// web gates also strip the rule's strength, so a later gate cannot be
/// satisfied by a rule that an earlier gate already overruled.
#[must_use]
pub(crate) fn gate(proposed: PolicyAction, strength: RuleStrength, facts: GateFacts) -> Gated {
    let mut action = proposed;
    let mut strength = strength;
    let mut downgrades = Vec::new();

    let mut gate = |fires: bool,
                    why: Downgrade,
                    strip: bool,
                    action: &mut PolicyAction,
                    strength: &mut RuleStrength| {
        if action.is_auto() && fires {
            *action = PolicyAction::Surface;
            downgrades.push(why);
            if strip {
                *strength = RuleStrength::NONE;
            }
        }
    };

    gate(
        facts.zone_requires_human,
        Downgrade::Zone,
        true,
        &mut action,
        &mut strength,
    );
    gate(
        facts.human_only,
        Downgrade::HumanOnly,
        true,
        &mut action,
        &mut strength,
    );
    gate(
        facts.web_connector,
        Downgrade::WebConnector,
        true,
        &mut action,
        &mut strength,
    );
    let sensitive_blocks = facts.sensitive && !strength.clears_sensitive(facts);
    gate(
        sensitive_blocks,
        Downgrade::Sensitive,
        false,
        &mut action,
        &mut strength,
    );
    let unnamed_blocks = facts.needs_explicit_rule && !strength.explicit;
    gate(
        unnamed_blocks,
        Downgrade::NotNamed,
        false,
        &mut action,
        &mut strength,
    );
    Gated { action, downgrades }
}

/// The route for a gated action, with its clearance bound to the request
/// and authority.
#[must_use]
pub(crate) fn route(
    action: PolicyAction,
    request: RequestId,
    authority: &Authority,
    source: DecisionSource,
) -> Route {
    match action {
        PolicyAction::Deny => Route::Deny,
        PolicyAction::Surface => Route::Surface,
        PolicyAction::Approve => Route::Approve(AutoClearance {
            request,
            authority: authority.clone(),
            source,
        }),
        PolicyAction::Llm => Route::Llm(LlmClearance {
            request,
            authority: authority.clone(),
        }),
    }
}

/// The predicate the invariants promise: may this combination auto-clear?
/// Written independently of `route`, as the specification it must meet.
#[must_use]
pub fn may_auto_clear(strength: RuleStrength, facts: GateFacts) -> bool {
    !facts.zone_requires_human
        && !facts.human_only
        && !facts.web_connector
        && (!facts.sensitive
            || (strength.pinned && (strength.names_resource || !facts.sensitive_by_resource)))
        && (!facts.needs_explicit_rule || strength.explicit)
}

#[cfg(test)]
pub(crate) fn all_inputs() -> impl Iterator<Item = (PolicyAction, RuleStrength, GateFacts)> {
    (0u32..(1 << 9)).flat_map(|bits| {
        let b = |i: u32| bits & (1 << i) != 0;
        let strength = RuleStrength {
            pinned: b(0),
            explicit: b(1),
            names_resource: b(7),
        };
        let facts = GateFacts {
            zone_requires_human: b(2),
            human_only: b(3),
            web_connector: b(4),
            sensitive: b(5),
            sensitive_by_resource: b(8),
            needs_explicit_rule: b(6),
        };
        PolicyAction::ALL
            .into_iter()
            .map(move |a| (a, strength, facts))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_FACTS: GateFacts = GateFacts {
        zone_requires_human: false,
        human_only: false,
        web_connector: false,
        sensitive: false,
        sensitive_by_resource: false,
        needs_explicit_rule: false,
    };

    /// Exhaustive over all 2048 inputs: this is a complete proof for the
    /// finite domain, not a sample.
    #[test]
    fn invariants_hold_for_every_input() {
        let mut count = 0;
        for (proposed, strength, facts) in all_inputs() {
            count += 1;
            let result = gate(proposed, strength, facts).action;
            // INV-4: only the proposal itself or surface; deny/surface fixed.
            assert!(result == proposed || result == PolicyAction::Surface);
            if proposed == PolicyAction::Deny {
                assert_eq!(result, PolicyAction::Deny);
            }
            if proposed == PolicyAction::Surface {
                assert_eq!(result, PolicyAction::Surface);
            }
            // INV-5/6/7/8/9 in one: auto-clears exactly when allowed.
            if proposed.is_auto() {
                assert_eq!(
                    result.is_auto(),
                    may_auto_clear(strength, facts),
                    "{proposed:?} {strength:?} {facts:?}"
                );
            } else {
                assert!(!result.is_auto());
            }
        }
        assert_eq!(count, 2048);
    }

    #[test]
    fn downgrades_are_reported_once_in_order() {
        let facts = GateFacts {
            human_only: true,
            sensitive: true,
            needs_explicit_rule: true,
            ..NO_FACTS
        };
        let routed = gate(
            PolicyAction::Approve,
            RuleStrength {
                pinned: true,
                explicit: true,
                names_resource: false,
            },
            facts,
        );
        assert_eq!(routed.action, PolicyAction::Surface);
        // Once surfaced, later gates do not fire (Python checks `action in
        // (APPROVE, LLM)` before each).
        assert_eq!(routed.downgrades, vec![Downgrade::HumanOnly]);
    }

    #[test]
    fn pinned_rule_clears_sensitive() {
        let facts = GateFacts {
            sensitive: true,
            ..NO_FACTS
        };
        let routed = gate(
            PolicyAction::Approve,
            RuleStrength {
                pinned: true,
                explicit: true,
                names_resource: false,
            },
            facts,
        );
        assert_eq!(routed.action, PolicyAction::Approve);
        let routed = gate(
            PolicyAction::Approve,
            RuleStrength {
                pinned: false,
                explicit: true,
                names_resource: false,
            },
            facts,
        );
        assert_eq!(routed.action, PolicyAction::Surface);
    }

    #[test]
    fn a_resource_driven_sensitivity_needs_the_rule_to_name_the_resource() {
        let facts = GateFacts {
            sensitive: true,
            sensitive_by_resource: true,
            ..NO_FACTS
        };
        let widened = RuleStrength {
            pinned: true,
            explicit: true,
            names_resource: false,
        };
        let named = RuleStrength {
            names_resource: true,
            ..widened
        };
        assert_eq!(
            gate(PolicyAction::Approve, widened, facts).action,
            PolicyAction::Surface
        );
        assert_eq!(
            gate(PolicyAction::Approve, named, facts).action,
            PolicyAction::Approve
        );
        // Sensitive because of what is asked: any pinned rule covering it.
        let what = GateFacts {
            sensitive_by_resource: false,
            ..facts
        };
        assert_eq!(
            gate(PolicyAction::Approve, widened, what).action,
            PolicyAction::Approve
        );
    }
}
