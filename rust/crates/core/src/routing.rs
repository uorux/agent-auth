//! The gates between a policy decision and what actually happens to a
//! request (core/service.py `create_request`, step 9 in the spec).
//!
//! The policy engine proposes an action; the gates may only ever *downgrade*
//! `approve`/`llm` to `surface` (a human decides). An auto-approval in the
//! broker requires an [`AutoClearance`], which only [`route`] constructs, so
//! nothing can approve a request without having passed every gate.
//!
//! Invariants (numbered as in rust/spec/core-lifecycle-policy.md §5.4), all
//! checked exhaustively in the tests below and by the Kani harnesses in
//! `crate::proofs`:
//! - INV-4  gates only downgrade: the result is the proposal or `surface`,
//!   and `deny` stays `deny`, `surface` stays `surface`.
//! - INV-5  human-only authorities (a host shell) never auto-clear.
//! - INV-6  a web-UI agent, or a request on one's behalf, never auto-clears.
//! - INV-7  a sensitive authority auto-clears only via a saved rule pinned
//!   to (covering) its exact authority.
//! - INV-8  an explicit-only authority auto-clears only via a rule naming it.
//! - INV-9  a restricted zone requiring a human never auto-clears.

/// What a policy layer proposes for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuleStrength {
    /// A saved rule pinned to an authority covering this one. The only thing
    /// that lets a sensitive authority through without a human.
    pub pinned: bool,
    /// The rule names this privilege: pinned, or a policy-file rule whose
    /// `match.capability` is literally the request's capability.
    pub explicit: bool,
}

/// Facts about the request the gates look at. Every field is computed by
/// the broker before routing; none comes from the requesting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateFacts {
    /// A restricted zone owns the resource and wants a human.
    pub zone_requires_human: bool,
    /// `Authority::human_only` (a host shell).
    pub human_only: bool,
    /// The agent, or the agent it acts for, is a web-UI connector.
    pub web_connector: bool,
    /// `Authority::is_sensitive` for this resource.
    pub sensitive: bool,
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

/// Proof that a request passed every gate with an auto action. Only
/// [`route`] makes one; the broker's auto-approve and LLM-approve paths take
/// it by value.
#[derive(Debug, PartialEq, Eq)]
pub struct AutoClearance {
    _private: (),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Deny,
    Surface,
    Approve(AutoClearance),
    Llm(AutoClearance),
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

/// The outcome of the gates: the route, the first gate that downgraded (if
/// any) and every gate that would have.
#[derive(Debug, PartialEq, Eq)]
pub struct Routed {
    pub route: Route,
    pub downgrades: Vec<Downgrade>,
}

/// Apply the gates to a policy proposal, in the Python's order. Each gate
/// fires only while the action is still automatic; the zone, human-only and
/// web gates also strip the rule's strength, so a later gate cannot be
/// satisfied by a rule that an earlier gate already overruled.
#[must_use]
pub fn route(proposed: PolicyAction, strength: RuleStrength, facts: GateFacts) -> Routed {
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
                *strength = RuleStrength::default();
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
    let sensitive_blocks = facts.sensitive && !strength.pinned;
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

    let route = match action {
        PolicyAction::Deny => Route::Deny,
        PolicyAction::Surface => Route::Surface,
        PolicyAction::Approve => Route::Approve(AutoClearance { _private: () }),
        PolicyAction::Llm => Route::Llm(AutoClearance { _private: () }),
    };
    Routed { route, downgrades }
}

/// The predicate the invariants promise: may this combination auto-clear?
/// Written independently of `route`, as the specification it must meet.
#[must_use]
pub fn may_auto_clear(strength: RuleStrength, facts: GateFacts) -> bool {
    !facts.zone_requires_human
        && !facts.human_only
        && !facts.web_connector
        && (!facts.sensitive || strength.pinned)
        && (!facts.needs_explicit_rule || strength.explicit)
}

#[cfg(test)]
pub(crate) fn all_inputs() -> impl Iterator<Item = (PolicyAction, RuleStrength, GateFacts)> {
    (0u32..(1 << 7)).flat_map(|bits| {
        let b = |i: u32| bits & (1 << i) != 0;
        let strength = RuleStrength {
            pinned: b(0),
            explicit: b(1),
        };
        let facts = GateFacts {
            zone_requires_human: b(2),
            human_only: b(3),
            web_connector: b(4),
            sensitive: b(5),
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

    /// Exhaustive over all 512 inputs: this is a complete proof for the
    /// finite domain, not a sample.
    #[test]
    fn invariants_hold_for_every_input() {
        let mut count = 0;
        for (proposed, strength, facts) in all_inputs() {
            count += 1;
            let result = route(proposed, strength, facts).route.action();
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
        assert_eq!(count, 512);
    }

    #[test]
    fn downgrades_are_reported_once_in_order() {
        let facts = GateFacts {
            human_only: true,
            sensitive: true,
            needs_explicit_rule: true,
            ..GateFacts::default()
        };
        let routed = route(
            PolicyAction::Approve,
            RuleStrength {
                pinned: true,
                explicit: true,
            },
            facts,
        );
        assert_eq!(routed.route, Route::Surface);
        // Once surfaced, later gates do not fire (Python checks `action in
        // (APPROVE, LLM)` before each).
        assert_eq!(routed.downgrades, vec![Downgrade::HumanOnly]);
    }

    #[test]
    fn pinned_rule_clears_sensitive() {
        let facts = GateFacts {
            sensitive: true,
            ..GateFacts::default()
        };
        let routed = route(
            PolicyAction::Approve,
            RuleStrength {
                pinned: true,
                explicit: true,
            },
            facts,
        );
        assert!(matches!(routed.route, Route::Approve(_)));
        let routed = route(
            PolicyAction::Approve,
            RuleStrength {
                pinned: false,
                explicit: true,
            },
            facts,
        );
        assert_eq!(routed.route, Route::Surface);
    }
}
