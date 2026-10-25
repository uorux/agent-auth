//! Kani harnesses for sandboxd's holds (`scripts/kani.sh --harness sandbox`):
//! held means held on every path (sandboxd spec INV-17, B-2).

use crate::sandbox::{AgentHoldEvent, Hold, UnitAction, transition};

fn any_hold() -> Hold {
    Hold {
        locked: kani::any(),
        contained: kani::any(),
    }
}

fn any_event() -> AgentHoldEvent {
    match kani::any::<u8>() % 3 {
        0 => AgentHoldEvent::Lockdown,
        1 => AgentHoldEvent::Unlock,
        _ => AgentHoldEvent::Contained(kani::any()),
    }
}

/// A contained agent is never thawed by lifting another hold (the
/// lockdown), and nothing is thawed while the VM is locked down: an agent
/// is released only when nothing holds it any more.
#[kani::proof]
fn sandbox_contained_agent_never_thawed() {
    let before = any_hold();
    let event = any_event();
    let (after, action) = transition(before, event);
    if action == UnitAction::Release {
        assert!(!after.locked && !after.contained);
        assert!(before.held());
    }
    if after.contained || after.locked {
        assert!(action != UnitAction::Release);
    }
    if action == UnitAction::Freeze {
        assert!(after.held() && !before.held());
    }
}

/// Over any sequence of events, a daemon that freezes on `Freeze` and
/// thaws on `Release` keeps every unit frozen exactly while its agent is
/// held, starting from any consistent state.
#[kani::proof]
#[kani::unwind(9)]
fn sandbox_frozen_tracks_held() {
    let mut hold = any_hold();
    let mut frozen = hold.held();
    for _ in 0..8 {
        let (after, action) = transition(hold, any_event());
        match action {
            UnitAction::Freeze => frozen = true,
            UnitAction::Release => frozen = false,
            UnitAction::Keep => {}
        }
        hold = after;
        assert!(frozen == hold.held());
    }
}
