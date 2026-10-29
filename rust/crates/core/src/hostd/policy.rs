//! A host's own policy: which tiers exist and how far they trust the
//! broker, deny and auto patterns, templates, the environment allowlist and
//! timeouts. hostd loads it from its config file (written by the NixOS or
//! nix-darwin module); the broker has no say in any of it.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::Tier;
use crate::hostexec::Template;

/// One tier's settings (`tiers.{user,root}` in the config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierPolicy {
    pub enable: bool,
    /// The longest one arming may last.
    pub max_arm_secs: u32,
    /// While armed: honour "approve all" windows.
    pub accept_approve_all: bool,
    /// While armed: honour approvals no human made (a saved rule, the LLM
    /// reviewer, a policy rule).
    pub accept_machine_approvals: bool,
    pub shell_enable: bool,
    pub shell_max_duration_secs: u32,
}

impl Default for TierPolicy {
    fn default() -> Self {
        TierPolicy {
            enable: false,
            max_arm_secs: 3600,
            accept_approve_all: false,
            accept_machine_approvals: false,
            shell_enable: false,
            shell_max_duration_secs: 1800,
        }
    }
}

/// Everything admission consults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicy {
    /// This host's daemon name.
    pub name: String,
    pub user: TierPolicy,
    pub root: TierPolicy,
    /// argv patterns: user-tier `run` jobs that need no approval at all.
    pub auto_commands: Vec<Vec<String>>,
    /// argv patterns never run, whatever the approval (the program also
    /// matches by its basename).
    pub deny_commands: Vec<Vec<String>>,
    /// This host's templates: what a `tpl` job runs comes from here, never
    /// from the broker.
    pub templates: BTreeMap<String, Template>,
    pub env_allow: BTreeSet<String>,
    /// For a job whose spec has no timeout.
    pub default_timeout_secs: u32,
    pub max_timeout_secs: u32,
    /// Does Allow at this host's desk approve a command of the tier on this
    /// host (`desktop.approve.{user,root}`)? Root also needs polkit.
    pub desk_approve_user: bool,
    pub desk_approve_root: bool,
}

impl HostPolicy {
    /// A policy with nothing enabled: runs nothing (a host without a
    /// config file).
    #[must_use]
    pub fn connect_only(name: &str) -> HostPolicy {
        HostPolicy {
            name: name.to_owned(),
            user: TierPolicy::default(),
            root: TierPolicy::default(),
            auto_commands: Vec::new(),
            deny_commands: Vec::new(),
            templates: BTreeMap::new(),
            env_allow: ["LANG", "LC_ALL", "TZ", "TERM"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            default_timeout_secs: 600,
            max_timeout_secs: 3600,
            desk_approve_user: false,
            desk_approve_root: false,
        }
    }

    #[must_use]
    pub fn tier(&self, tier: Tier) -> &TierPolicy {
        match tier {
            Tier::User => &self.user,
            Tier::Root => &self.root,
        }
    }

    #[must_use]
    pub fn desk_approves(&self, tier: Tier) -> bool {
        match tier {
            Tier::User => self.desk_approve_user,
            Tier::Root => self.desk_approve_root,
        }
    }

    /// Whether this hostd does anything that needs root (a tier).
    #[must_use]
    pub fn any_tier_enabled(&self) -> bool {
        self.user.enable || self.root.enable
    }
}
