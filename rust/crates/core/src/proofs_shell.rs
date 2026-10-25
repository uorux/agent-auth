//! Kani harnesses for shell modes (`scripts/kani.sh --harness shell`).

use crate::authority::ShellMode;
use crate::shell_mode::{GuardOutcome, ShellRefusal, after_guard, scope_rule};

fn any_mode() -> ShellMode {
    match kani::any::<u8>() % 4 {
        0 => ShellMode::Watched,
        1 => ShellMode::General,
        2 => ShellMode::Guarded,
        _ => ShellMode::Umbrella,
    }
}

fn any_outcome() -> GuardOutcome {
    match kani::any::<u8>() % 4 {
        0 => GuardOutcome::NotAsked,
        1 => GuardOutcome::Allow,
        2 => GuardOutcome::Refuse {
            alarming: kani::any(),
        },
        _ => GuardOutcome::Unavailable,
    }
}

/// A command is sent (both steps pass) only if: an umbrella's runs in a
/// scope and no other shell's does; a guarded or umbrella command had the
/// guard's explicit allow (never a refusal, an unavailable guard or no
/// guard at all); and a watched or general command is always watched
/// after it starts, a guarded one never again.
#[kani::proof]
fn shell_command_sent_only_as_its_mode_allows() {
    let mode = any_mode();
    let scoped: bool = kani::any();
    let guard = any_outcome();
    let sent = scope_rule(mode, scoped).and_then(|()| after_guard(mode, guard));
    if let Ok(watched) = sent {
        assert!(scoped == (mode == ShellMode::Umbrella));
        if matches!(mode, ShellMode::Guarded | ShellMode::Umbrella) {
            assert!(guard == GuardOutcome::Allow);
            assert!(!watched);
        } else {
            assert!(watched);
        }
    }
    // An alarming refusal is reported as alarming.
    if mode.guarded() && scope_rule(mode, scoped).is_ok() {
        if let GuardOutcome::Refuse { alarming } = guard {
            assert!(sent == Err(ShellRefusal::Guard { alarming }));
        }
    }
}
