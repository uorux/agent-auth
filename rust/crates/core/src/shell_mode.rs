//! Whether a shell command may be sent, by the shell's mode (the broker's
//! `hostexec::shells` asks these, in this order; Kani: `proofs_shell`).
//!
//! 1. [`scope_rule`]: an umbrella's command runs only in a scope; any other
//!    shell has no scopes.
//! 2. [`after_guard`]: a guarded or umbrella command runs only on the
//!    guard's explicit allow (a refusal, or a guard that could not be
//!    asked, refuses it); watched and general commands are not guarded and
//!    are watched after they start instead.

use crate::authority::ShellMode;

/// What the guard said about a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Not asked: the shell is not guarded.
    NotAsked,
    Allow,
    Refuse {
        alarming: bool,
    },
    /// The model could not be asked.
    Unavailable,
}

/// Why a command was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellRefusal {
    /// An umbrella's command named no scope.
    NeedsScope,
    /// A scope was named in a shell that has none.
    NoScopes,
    /// The guard refused it.
    Guard { alarming: bool },
    /// The guard could not be asked (fail closed).
    GuardUnavailable,
    /// A guarded shell's command reached the end without the guard.
    GuardNotAsked,
}

/// Step 1: does the command's scope (or its absence) fit the mode?
pub fn scope_rule(mode: ShellMode, scoped: bool) -> Result<(), ShellRefusal> {
    match (mode, scoped) {
        (ShellMode::Umbrella, false) => Err(ShellRefusal::NeedsScope),
        (ShellMode::Umbrella, true) => Ok(()),
        (_, true) => Err(ShellRefusal::NoScopes),
        (_, false) => Ok(()),
    }
}

/// Step 2: may it be sent, given what the guard said? `Ok(true)`: send it
/// and have the watcher look at it after it starts; `Ok(false)`: send it,
/// no watcher (the guard rated it already).
pub fn after_guard(mode: ShellMode, guard: GuardOutcome) -> Result<bool, ShellRefusal> {
    if !mode.guarded() {
        // An answer from a guard nobody should have asked changes nothing:
        // the operator still sees the command, and the watcher still looks.
        return Ok(true);
    }
    match guard {
        GuardOutcome::Allow => Ok(false),
        GuardOutcome::Refuse { alarming } => Err(ShellRefusal::Guard { alarming }),
        GuardOutcome::Unavailable => Err(ShellRefusal::GuardUnavailable),
        GuardOutcome::NotAsked => Err(ShellRefusal::GuardNotAsked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_combination() {
        let outcomes = [
            GuardOutcome::NotAsked,
            GuardOutcome::Allow,
            GuardOutcome::Refuse { alarming: false },
            GuardOutcome::Refuse { alarming: true },
            GuardOutcome::Unavailable,
        ];
        for mode in ShellMode::ALL {
            for scoped in [false, true] {
                let scope_ok = scope_rule(mode, scoped).is_ok();
                assert_eq!(
                    scope_ok,
                    (mode == ShellMode::Umbrella) == scoped,
                    "{mode} {scoped}"
                );
            }
            for g in outcomes {
                let sent = after_guard(mode, g);
                if mode.guarded() {
                    assert_eq!(sent.is_ok(), g == GuardOutcome::Allow, "{mode} {g:?}");
                    assert_ne!(sent, Ok(true), "a guarded command is not watched again");
                } else {
                    assert_eq!(sent, Ok(true), "{mode} {g:?}");
                }
            }
        }
    }
}
