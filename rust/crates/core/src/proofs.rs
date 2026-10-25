//! Kani model-checking harnesses (`cargo kani -p agent-auth-core`).
//!
//! Kani explores every value of the symbolic inputs, so each harness is a
//! proof over its whole input space (bounded where noted), not a test.

use crate::lifecycle::RequestStatus;
use crate::routing::{GateFacts, PolicyAction, RuleStrength, gate, may_auto_clear};

fn any_action() -> PolicyAction {
    match kani::any::<u8>() % 4 {
        0 => PolicyAction::Deny,
        1 => PolicyAction::Approve,
        2 => PolicyAction::Llm,
        _ => PolicyAction::Surface,
    }
}

fn any_status() -> RequestStatus {
    let i: usize = kani::any();
    kani::assume(i < RequestStatus::ALL.len());
    RequestStatus::ALL[i]
}

/// INV-4..INV-9: the gates only downgrade, and an automatic action survives
/// exactly when the specification allows it.
#[kani::proof]
fn gates_only_downgrade_and_match_spec() {
    let proposed = any_action();
    let strength = RuleStrength {
        pinned: kani::any(),
        explicit: kani::any(),
    };
    let facts = GateFacts {
        zone_requires_human: kani::any(),
        human_only: kani::any(),
        web_connector: kani::any(),
        sensitive: kani::any(),
        needs_explicit_rule: kani::any(),
    };
    let result = gate(proposed, strength, facts).action;
    assert!(result == proposed || result == PolicyAction::Surface);
    if !proposed.is_auto() {
        assert!(result == proposed);
    } else {
        assert!(result.is_auto() == may_auto_clear(strength, facts));
    }
    if facts.human_only || facts.web_connector || facts.zone_requires_human {
        assert!(!result.is_auto());
    }
    if facts.sensitive && !strength.pinned {
        assert!(!result.is_auto());
    }
}

/// INV-15: terminal statuses have no way out, and the graph only reaches
/// GRANTED through APPROVED then PROVISIONING.
///
/// `can_transition` searches a successor list (at most 4 long), so CBMC's
/// loop unwinding needs a bound: 4 iterations plus one to show the loop
/// ends (Kani's unwinding assertions fail the proof if 5 is too small).
#[kani::proof]
#[kani::unwind(5)]
fn status_machine_properties() {
    let from = any_status();
    let to = any_status();
    if from.is_terminal() {
        assert!(!from.can_transition(to));
    }
    if to == RequestStatus::Granted && from.can_transition(to) {
        assert!(from == RequestStatus::Provisioning);
    }
    if to == RequestStatus::Provisioning && from.can_transition(to) {
        assert!(from == RequestStatus::Approved);
    }
    // No transition goes back to PENDING, and nothing loops to itself.
    assert!(!(to == RequestStatus::Pending && from.can_transition(to)));
    assert!(!from.can_transition(from));
}
