//! Agent VMs (sandboxd spec): the names both sides agree on, the mint
//! resource rule the broker checks, and the hold state machine sandboxd
//! runs (VM-wide lockdown plus per-agent containment) with the freeze and
//! thaw decisions it makes.
//!
//! Held means held on every path: an agent is thawed (and its queued work
//! delivered) only when it was held before an event and is held by
//! nothing after it. Lifting the lockdown never thaws a contained agent,
//! and lifting a containment during a lockdown thaws nothing (the Python's
//! B-2). Model-checked in `proofs_sandbox.rs`.

use std::collections::BTreeSet;

/// The broker's runtime for the VM's orchestrator agent.
pub const ORCHESTRATOR_RUNTIME: &str = "orchestrator";

/// `orchestrator-<host>-sandbox`.
#[must_use]
pub fn orchestrator_name(host: &str) -> String {
    format!("orchestrator-{host}-sandbox")
}

/// `<runtime>-<project>-<host>-sandbox`.
#[must_use]
pub fn agent_name(runtime: &str, project: &str, host: &str) -> String {
    format!("{runtime}-{project}-{host}-sandbox")
}

pub use crate::names::SandboxProject as ProjectName;

/// A project's unix user (and group): `p-<project>`.
#[must_use]
pub fn project_user(project: &ProjectName) -> String {
    format!("p-{project}")
}

/// What a valid mint resource names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintName {
    /// The resource, normalized (trimmed, lower case).
    pub name: String,
    pub runtime: String,
    pub project: ProjectName,
}

/// Read `<runtime>-<project>-<host>-sandbox` (trimmed, lower-cased): the
/// first configured runtime the name starts with, and a valid project.
/// The texts are the validator's (sandboxd spec §2.5, steps 5-6).
pub fn parse_mint_name(
    resource: &str,
    runtimes: &[String],
    host: &str,
) -> Result<MintName, String> {
    let name = resource.trim().to_lowercase();
    let suffix = format!("-{host}-sandbox");
    let runtime = runtimes
        .iter()
        .find(|r| name.starts_with(&format!("{r}-")) && name.ends_with(&suffix));
    let Some(runtime) = runtime else {
        return Err(format!(
            "resource must be '<runtime>-<project>{suffix}' with runtime one of {}",
            runtimes.join(", ")
        ));
    };
    let start = runtime.len().saturating_add(1);
    let end = name.len().saturating_sub(suffix.len());
    let project = name.get(start..end).unwrap_or("");
    let Ok(project) = ProjectName::parse(project) else {
        return Err(format!(
            "invalid project name {} (lowercase letters, digits and '-', ≤30)",
            crate::pyfmt::repr(project)
        ));
    };
    Ok(MintName {
        name,
        runtime: runtime.clone(),
        project,
    })
}

// ------------------------------------------------------------------ holds

/// One agent's holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hold {
    /// The VM-wide lockdown.
    pub locked: bool,
    /// This agent's containment.
    pub contained: bool,
}

impl Hold {
    /// Held by anything.
    #[must_use]
    pub const fn held(self) -> bool {
        self.locked || self.contained
    }
}

/// An event as one agent sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHoldEvent {
    Lockdown,
    Unlock,
    /// The broker's held set was replaced: whether this agent is in it.
    Contained(bool),
}

/// What to do with an agent's processes after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitAction {
    /// It became held: freeze its units (they are kept, not killed).
    Freeze,
    /// It was held and nothing holds it now: thaw its units and deliver
    /// what queued up meanwhile.
    Release,
    /// Nothing changes for it.
    Keep,
}

/// One agent's hold after an event, and what to do about its processes.
#[must_use]
pub const fn transition(before: Hold, event: AgentHoldEvent) -> (Hold, UnitAction) {
    let after = match event {
        AgentHoldEvent::Lockdown => Hold {
            locked: true,
            contained: before.contained,
        },
        AgentHoldEvent::Unlock => Hold {
            locked: false,
            contained: before.contained,
        },
        AgentHoldEvent::Contained(c) => Hold {
            locked: before.locked,
            contained: c,
        },
    };
    let action = match (before.held(), after.held()) {
        (false, true) => UnitAction::Freeze,
        (true, false) => UnitAction::Release,
        _ => UnitAction::Keep,
    };
    (after, action)
}

/// A VM-wide event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldEvent {
    Lockdown,
    Unlock,
    /// The broker's complete held set for this VM (`agents.contained`).
    Contained(BTreeSet<String>),
}

/// The VM's holds: whether it is locked down, and which agents are
/// contained.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Holds {
    locked: bool,
    contained: BTreeSet<String>,
}

/// An event applied: the holds before and after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub before: Holds,
    pub after: Holds,
    event: HoldEvent,
}

impl Applied {
    /// What to do with `agent`'s processes.
    #[must_use]
    pub fn action(&self, agent: &str) -> UnitAction {
        let event = match &self.event {
            HoldEvent::Lockdown => AgentHoldEvent::Lockdown,
            HoldEvent::Unlock => AgentHoldEvent::Unlock,
            HoldEvent::Contained(set) => AgentHoldEvent::Contained(set.contains(agent)),
        };
        transition(self.before.hold(agent), event).1
    }

    /// Did anything change?
    #[must_use]
    pub fn changed(&self) -> bool {
        self.before != self.after
    }
}

impl Holds {
    #[must_use]
    pub fn new(locked: bool, contained: BTreeSet<String>) -> Holds {
        Holds { locked, contained }
    }

    #[must_use]
    pub fn locked(&self) -> bool {
        self.locked
    }

    #[must_use]
    pub fn contained_set(&self) -> &BTreeSet<String> {
        &self.contained
    }

    #[must_use]
    pub fn is_contained(&self, agent: &str) -> bool {
        self.contained.contains(agent)
    }

    /// One agent's holds.
    #[must_use]
    pub fn hold(&self, agent: &str) -> Hold {
        Hold {
            locked: self.locked,
            contained: self.is_contained(agent),
        }
    }

    /// Held by anything.
    #[must_use]
    pub fn held(&self, agent: &str) -> bool {
        self.hold(agent).held()
    }

    /// Why `agent` is held, as sandboxd says it: `locked down`, or `<agent>
    /// is contained`.
    #[must_use]
    pub fn refusal(&self, agent: &str) -> Option<String> {
        if self.locked {
            Some("locked down".to_owned())
        } else if self.is_contained(agent) {
            Some(format!("{agent} is contained"))
        } else {
            None
        }
    }

    /// Apply an event (every agent's hold moves by [`transition`]).
    #[must_use]
    pub fn apply(&self, event: HoldEvent) -> Applied {
        let after = match &event {
            HoldEvent::Lockdown => Holds {
                locked: true,
                contained: self.contained.clone(),
            },
            HoldEvent::Unlock => Holds {
                locked: false,
                contained: self.contained.clone(),
            },
            HoldEvent::Contained(set) => Holds {
                locked: self.locked,
                contained: set.clone(),
            },
        };
        Applied {
            before: self.clone(),
            after,
            event,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn project_names() {
        for ok in ["a", "a1", "larder", "a-b", "0", &"a".repeat(30)] {
            assert!(ProjectName::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "A",
            "a_b",
            "a.b",
            &"a".repeat(31),
            "é",
            "a b",
        ] {
            assert!(ProjectName::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            project_user(&ProjectName::parse("larder").unwrap()),
            "p-larder"
        );
    }

    #[test]
    fn mint_names() {
        let rt = vec!["claude".to_owned(), "codex".to_owned()];
        let m = parse_mint_name(" Claude-Larder-excelsior-sandbox ", &rt, "excelsior").unwrap();
        assert_eq!(
            (m.name.as_str(), m.runtime.as_str(), m.project.as_str()),
            ("claude-larder-excelsior-sandbox", "claude", "larder")
        );
        let e = parse_mint_name("claude-larder-galaxy-sandbox", &rt, "excelsior").unwrap_err();
        assert_eq!(
            e,
            "resource must be '<runtime>-<project>-excelsior-sandbox' with runtime one of claude, codex"
        );
        assert!(
            parse_mint_name("gemini-larder-excelsior-sandbox", &rt, "excelsior")
                .unwrap_err()
                .starts_with("resource must be")
        );
        for bad in [
            "claude-Bad_Name-excelsior-sandbox",
            "claude--excelsior-sandbox",
            &format!("claude-{}-excelsior-sandbox", "a".repeat(31)),
        ] {
            let e = parse_mint_name(bad, &rt, "excelsior").unwrap_err();
            assert!(e.starts_with("invalid project"), "{bad}: {e}");
        }
        // The suffix and the runtime prefix may not overlap (an empty project).
        assert!(
            parse_mint_name("claude-excelsior-sandbox", &rt, "excelsior")
                .unwrap_err()
                .starts_with("invalid project name ''")
        );
    }

    #[test]
    fn lifting_one_hold_never_thaws_another() {
        let h = Holds::new(false, set(&["a"]));
        let locked = h.apply(HoldEvent::Lockdown);
        assert_eq!(locked.action("a"), UnitAction::Keep);
        assert_eq!(locked.action("b"), UnitAction::Freeze);
        let unlocked = locked.after.apply(HoldEvent::Unlock);
        assert_eq!(unlocked.action("a"), UnitAction::Keep);
        assert_eq!(unlocked.action("b"), UnitAction::Release);
        // Release during a lockdown: still held.
        let released = locked.after.apply(HoldEvent::Contained(set(&[])));
        assert_eq!(released.action("a"), UnitAction::Keep);
        assert!(released.after.held("a"));
        let free = released.after.apply(HoldEvent::Unlock);
        assert_eq!(free.action("a"), UnitAction::Release);
        assert_eq!(h.refusal("a").unwrap(), "a is contained");
        assert_eq!(locked.after.refusal("a").unwrap(), "locked down");
        assert!(h.refusal("b").is_none());
    }
}
