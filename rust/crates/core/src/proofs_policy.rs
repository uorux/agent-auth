//! Kani harnesses for the policy layer (`cargo kani -p agent-auth-core`).
//! Each proves a property over its whole (bounded) input space.

use crate::durations::DurationSecs;
use crate::policy::{cap_duration, default_action, delegator_axis};
use crate::routing::{GateFacts, PolicyAction, RuleStrength, gate};

fn any_action() -> PolicyAction {
    match kani::any::<u8>() % 4 {
        0 => PolicyAction::Deny,
        1 => PolicyAction::Approve,
        2 => PolicyAction::Llm,
        _ => PolicyAction::Surface,
    }
}

fn any_duration() -> DurationSecs {
    let secs: u32 = kani::any();
    match DurationSecs::from_secs(i64::from(secs)) {
        Ok(d) => d,
        Err(_) => {
            kani::assume(false);
            DurationSecs::MAX
        }
    }
}

/// INV-10, the delegation axis: a rule naming a delegator matches only a
/// delegated request whose delegator fits; a rule naming none never grants
/// a delegated request, and still denies/surfaces it.
#[kani::proof]
fn delegator_axis_truth_table() {
    let names: bool = kani::any();
    let fits: bool = kani::any();
    let delegated: bool = kani::any();
    let grants: bool = kani::any();
    let m = delegator_axis(names, fits, delegated, grants);
    if names {
        assert!(m == (delegated && fits));
    } else if delegated {
        assert!(m == !grants);
    } else {
        assert!(m);
    }
    // Never a grant for a delegated request by a rule without a delegator.
    if delegated && grants && !names {
        assert!(!m);
    }
    // Never a match of a delegator rule for a request without one.
    if names && !delegated {
        assert!(!m);
    }
}

/// B-7: the default never clears a delegated request; otherwise it is the
/// configured action.
#[kani::proof]
fn default_never_clears_delegated() {
    let configured = any_action();
    let delegated: bool = kani::any();
    let got = default_action(configured, delegated);
    if delegated {
        assert!(!got.is_auto());
        if !configured.is_auto() {
            assert!(got == configured);
        }
    } else {
        assert!(got == configured);
    }
}

/// INV-19: an automatic approval's duration is at most the request, the
/// default maximum and the rule's cap, and is one of them.
#[kani::proof]
fn cap_duration_is_the_minimum() {
    let requested = any_duration();
    let default_max = any_duration();
    let has_rule: bool = kani::any();
    let rule_max = if has_rule { Some(any_duration()) } else { None };
    let got = cap_duration(requested, default_max, rule_max);
    assert!(got <= requested);
    assert!(got <= default_max);
    if let Some(m) = rule_max {
        assert!(got <= m);
        assert!(got == requested || got == default_max || got == m);
    } else {
        assert!(got == requested || got == default_max);
    }
}

/// INV-4..9 through the policy's wiring: whatever the decision, a request
/// with a zone note, a human-only or web connector authority never clears,
/// and the gates only ever downgrade to surface.
#[kani::proof]
fn routed_decisions_only_downgrade() {
    let proposed = any_action();
    let strength = RuleStrength {
        pinned: kani::any(),
        explicit: kani::any(),
        names_resource: kani::any(),
    };
    let facts = GateFacts {
        zone_requires_human: kani::any(),
        human_only: kani::any(),
        web_connector: kani::any(),
        sensitive: kani::any(),
        sensitive_by_resource: kani::any(),
        needs_explicit_rule: kani::any(),
    };
    let routed = gate(proposed, strength, facts);
    let result = routed.action;
    assert!(result == proposed || result == PolicyAction::Surface);
    assert!(routed.downgrades.len() <= 1);
    if result.is_auto() {
        assert!(!facts.zone_requires_human && !facts.human_only && !facts.web_connector);
        assert!(!facts.sensitive || strength.pinned);
        assert!(!facts.sensitive || !facts.sensitive_by_resource || strength.names_resource);
        assert!(!facts.needs_explicit_rule || strength.explicit);
    }
}
