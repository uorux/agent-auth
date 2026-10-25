//! The policy file: its schema, loading (with overlays), and evaluation.
//! Spec core-lifecycle-policy §5.
//!
//! A [`Policy`] only exists validated: [`Policy::load`] parses the YAML,
//! merges the overlays, refuses unknown keys everywhere (bug B-1), and runs
//! the cross-field checks. Evaluation ([`Policy::evaluate`]) and routing
//! ([`Policy::route`]) are pure functions of their inputs.

pub mod agents;
mod eval;
pub mod schema;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::authority::SensitivityConfig;
use crate::durations::DurationSecs;
use crate::names::AttrValue;

pub use agents::{
    AgentKind, AgentMatch, AgentPattern, AgentRef, Delegation, PatternError, Placement, Project,
    WEB_RUNTIME, check_resource, delegator_axis, delegator_matches, describe, glob_literal,
    resources_for,
};
pub use eval::{
    Matched, PolicyDecision, PolicyInput, RoutedRequest, SavedRule, SavedRuleAction, cap_duration,
    default_action, sort_saved_rules,
};
pub use schema::{
    AgentsConfig, AuditConfig, Constraints, ContainmentConfig, Defaults, DesktopConfig,
    GithubConfig, GoogleAccount, GoogleConfig, HomelabConfig, HostexecConfig, KubernetesConfig,
    LlmConfig, MAX_POOL_PER_AGENT, MCP_TOOL_NAMES, Match, McpConfig, McpServer, ModelsConfig,
    NotifyConfig, PlatformsConfig, PolicyRule, PoolConfig, PoolItem, REMOTE_MCP_REDIRECT_URIS,
    REMOTE_MCP_TOOLS, RemoteMcpConfig, RestrictedZone, UiConfig, WikiConfig, config_name_ok,
    email_address_ok, redirect_uri_ok,
};

/// A policy that does not load. The text says where (`rules[3]: ...`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PolicyError(pub String);

/// The largest policy file (or overlay) accepted, in bytes.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;

/// The validated policy. Built only by [`Policy::load`] / [`Policy::from_value`]
/// (or `Default`, which is the all-defaults policy), so every value of this
/// type passed every check.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Policy {
    defaults: Defaults,
    llm: LlmConfig,
    platforms: PlatformsConfig,
    desktop: DesktopConfig,
    wiki: WikiConfig,
    ui: UiConfig,
    notify: NotifyConfig,
    containment: ContainmentConfig,
    restricted: BTreeMap<String, RestrictedZone>,
    audit: AuditConfig,
    remote_mcp: RemoteMcpConfig,
    projects: BTreeMap<AttrValue, Project>,
    rules: Vec<PolicyRule>,
}

const SECTIONS: [&str; 13] = [
    "defaults",
    "llm",
    "platforms",
    "desktop",
    "wiki",
    "ui",
    "notify",
    "containment",
    "restricted",
    "audit",
    "remote_mcp",
    "projects",
    "rules",
];

const PLATFORM_SECTIONS: [&str; 9] = [
    "github",
    "homelab",
    "kubernetes",
    "agents",
    "hostexec",
    "mcp",
    "models",
    "google",
    "pools",
];

/// Parse one YAML document into a generic value, with limits so a hostile
/// file (alias bombs, deep nesting, huge scalars) cannot exhaust memory.
/// Duplicate keys are an error. An empty document is an empty mapping.
pub fn parse_yaml(text: &str) -> Result<Value, PolicyError> {
    if text.len() > MAX_POLICY_BYTES {
        return Err(PolicyError(format!(
            "the policy is larger than {MAX_POLICY_BYTES} bytes"
        )));
    }
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_events = 200_000;
    budget.max_aliases = 1_000;
    budget.max_anchors = 1_000;
    budget.max_depth = 32;
    budget.max_documents = 1;
    budget.max_nodes = 100_000;
    budget.max_total_scalar_bytes = MAX_POLICY_BYTES;
    budget.max_merge_keys = 1_000;
    budget.max_recorded_anchor_events = 100_000;
    budget.max_recorded_anchor_bytes = MAX_POLICY_BYTES;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.alias_limits.max_total_replayed_events = 100_000;
    options.alias_limits.max_alias_expansions_per_anchor = 1_000;
    options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    options.reject_unsupported_tags = true;
    options.with_snippet = false;
    let value: Value = serde_saphyr::from_str_with_options(text, options)
        .map_err(|e| PolicyError(format!("not valid YAML: {e}")))?;
    Ok(if value.is_null() {
        Value::Object(Map::new())
    } else {
        value
    })
}

/// `_overlay(base, extra)`: mappings merge key by key, recursively; lists
/// put the overlay's items first (its rules are matched before the base
/// file's); anything else is replaced by the overlay.
#[must_use]
pub fn overlay(base: Value, extra: Value) -> Value {
    match (base, extra) {
        (Value::Object(mut base), Value::Object(extra)) => {
            for (key, value) in extra {
                let merged = match base.remove(&key) {
                    Some(old) => overlay(old, value),
                    None => value,
                };
                base.insert(key, merged);
            }
            Value::Object(base)
        }
        (Value::Array(base), Value::Array(mut extra)) => {
            extra.extend(base);
            Value::Array(extra)
        }
        (_, extra) => extra,
    }
}

fn parse_section<T: DeserializeOwned>(where_: &str, value: Value) -> Result<T, PolicyError> {
    serde_json::from_value(value).map_err(|e| PolicyError(format!("{where_}: {e}")))
}

fn take_object(where_: &str, value: Value) -> Result<Map<String, Value>, PolicyError> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(PolicyError(format!("{where_}: a mapping"))),
    }
}

fn refuse_unknown(
    where_: &str,
    map: &Map<String, Value>,
    known: &[&str],
) -> Result<(), PolicyError> {
    match map.keys().find(|k| !known.contains(&k.as_str())) {
        None => Ok(()),
        Some(key) => Err(PolicyError(format!(
            "{where_}unknown field `{key}`, expected one of {}",
            known
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

impl Policy {
    /// The base policy file's text with each overlay merged over it, in
    /// order. Each overlay is `(label, text)`; the label (its path) prefixes
    /// its parse errors. The caller reads the files: a missing base file or
    /// overlay is the caller's error ("policy overlay {path} is missing";
    /// unlike the Python, a missing base file should be one too, B-12).
    pub fn load(base: &str, overlays: &[(&str, &str)]) -> Result<Policy, PolicyError> {
        let mut data = parse_yaml(base)?;
        for (label, text) in overlays {
            let extra = parse_yaml(text).map_err(|e| PolicyError(format!("{label}: {e}")))?;
            data = overlay(data, extra);
        }
        Policy::from_value(data)
    }

    /// One YAML document, no overlays.
    pub fn from_yaml(text: &str) -> Result<Policy, PolicyError> {
        Policy::load(text, &[])
    }

    /// Validate an already-parsed (and merged) policy document.
    pub fn from_value(value: Value) -> Result<Policy, PolicyError> {
        let mut map = match value {
            Value::Null => Map::new(),
            Value::Object(map) => map,
            _ => {
                return Err(PolicyError(
                    "the policy is a mapping at the top level".to_owned(),
                ));
            }
        };
        refuse_unknown("", &map, &SECTIONS)?;
        let mut policy = Policy::default();
        if let Some(v) = map.remove("defaults") {
            policy.defaults = parse_section("defaults", v)?;
        }
        if let Some(v) = map.remove("llm") {
            policy.llm = parse_section("llm", v)?;
        }
        if let Some(v) = map.remove("platforms") {
            policy.platforms = parse_platforms(v)?;
        }
        if let Some(v) = map.remove("desktop") {
            policy.desktop = parse_section("desktop", v)?;
        }
        if let Some(v) = map.remove("wiki") {
            policy.wiki = parse_section("wiki", v)?;
        }
        if let Some(v) = map.remove("ui") {
            policy.ui = parse_section("ui", v)?;
        }
        if let Some(v) = map.remove("notify") {
            policy.notify = parse_section("notify", v)?;
        }
        if let Some(v) = map.remove("containment") {
            policy.containment = parse_section("containment", v)?;
        }
        if let Some(v) = map.remove("restricted") {
            for (name, zone) in take_object("restricted", v)? {
                let where_ = format!("restricted.{name}");
                let mut zone: RestrictedZone = parse_section(&where_, zone)?;
                zone.normalize();
                zone.validate()
                    .map_err(|e| PolicyError(format!("{where_}: {e}")))?;
                policy.restricted.insert(name, zone);
            }
        }
        if let Some(v) = map.remove("audit") {
            policy.audit = parse_section("audit", v)?;
        }
        if let Some(v) = map.remove("remote_mcp") {
            policy.remote_mcp = parse_section("remote_mcp", v)?;
        }
        if let Some(v) = map.remove("projects") {
            for (name, project) in take_object("projects", v)? {
                let key =
                    AttrValue::parse(&name).map_err(|e| PolicyError(format!("projects: {e}")))?;
                let project: Project = parse_section(&format!("projects.{name}"), project)?;
                policy.projects.insert(key, project);
            }
        }
        if let Some(v) = map.remove("rules") {
            let Value::Array(rules) = v else {
                return Err(PolicyError("rules: a list".to_owned()));
            };
            for (i, rule) in rules.into_iter().enumerate() {
                policy
                    .rules
                    .push(parse_section(&format!("rules[{i}]"), rule)?);
            }
        }
        policy.wiki.validate().map_err(PolicyError)?;
        policy.ui.validate().map_err(PolicyError)?;
        policy.normalize_case();
        policy.check_references()?;
        Ok(policy)
    }

    /// GitHub names are case-insensitive and the broker compares them
    /// lowercased: the wiki's repo, the projects' repos and the resources of
    /// rules for GitHub are lowercased (a `JRT/App` would never match), and
    /// the wiki's repo is always on the GitHub denylist (it is written only
    /// by the broker, by path rules: a GitHub grant on it would write past
    /// them), whether or not the operator listed it.
    fn normalize_case(&mut self) {
        self.wiki.repo = self.wiki.repo.to_lowercase();
        for project in self.projects.values_mut() {
            for repo in &mut project.repos {
                *repo = repo.to_lowercase();
            }
        }
        for rule in &mut self.rules {
            if rule.matches.platform == Some(crate::platform::Platform::Github) {
                rule.matches.resource = rule.matches.resource.to_lowercase();
            }
        }
        let wiki = &self.wiki.repo;
        let deny = &mut self.platforms.github.repo_denylist;
        if !wiki.is_empty() && !deny.iter().any(|g| g.as_str() == wiki) {
            deny.push(crate::glob::Glob::new(&crate::glob::escape(wiki)));
        }
    }

    /// `_references`: projects named by agent matches must be declared, the
    /// remote MCP settings must be complete, and rule resources may only
    /// use the known placeholders.
    fn check_references(&self) -> Result<(), PolicyError> {
        let mut patterns: Vec<(String, &AgentPattern)> = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            patterns.push((format!("rules[{i}]"), &r.matches.agent));
        }
        for (i, r) in self.rules.iter().enumerate() {
            if let Some(d) = &r.matches.delegator {
                patterns.push((format!("rules[{i}] delegator"), d));
            }
        }
        let lists: [(&str, &Vec<AgentPattern>); 4] = [
            ("desktop.agents", &self.desktop.agents),
            ("wiki.editors", &self.wiki.editors),
            ("containment.agents", &self.containment.agents),
            ("audit.readers", &self.audit.readers),
        ];
        for (name, list) in lists {
            for (i, p) in list.iter().enumerate() {
                patterns.push((format!("{name}[{i}]"), p));
            }
        }
        for (name, pool) in &self.platforms.pools {
            for (i, p) in pool.agents.iter().enumerate() {
                patterns.push((format!("platforms.pools.{name}.agents[{i}]"), p));
            }
            for (item, spec) in &pool.items {
                for (i, p) in spec.agents.iter().enumerate() {
                    patterns.push((
                        format!("platforms.pools.{name}.items.{item}.agents[{i}]"),
                        p,
                    ));
                }
            }
        }
        for (zone_name, zone) in &self.restricted {
            for (i, p) in zone.members.iter().enumerate() {
                patterns.push((format!("restricted.{zone_name}.members[{i}]"), p));
            }
        }
        for (where_, pattern) in patterns {
            for project in pattern.projects() {
                if !self.projects.contains_key(project) {
                    return Err(PolicyError(format!(
                        "{where_}: project {} is not listed under `projects`",
                        crate::pyfmt::repr(project.as_str())
                    )));
                }
            }
        }
        if self.remote_mcp.enabled {
            if self.ui.issuer.is_empty()
                || self.ui.client_id.is_empty()
                || self.remote_mcp.base_url.is_empty()
            {
                return Err(PolicyError(
                    "remote_mcp needs base_url, and ui.issuer and ui.client_id to sign in with"
                        .to_owned(),
                ));
            }
            let mut unknown: Vec<&str> = self
                .remote_mcp
                .tools
                .iter()
                .map(String::as_str)
                .filter(|t| !MCP_TOOL_NAMES.contains(t))
                .collect();
            unknown.sort_unstable();
            unknown.dedup();
            if !unknown.is_empty() {
                return Err(PolicyError(format!(
                    "remote_mcp.tools: no such tools: {}",
                    unknown.join(", ")
                )));
            }
            if let Some(bad) = self
                .remote_mcp
                .redirect_uris
                .iter()
                .find(|u| !schema::redirect_uri_ok(u))
            {
                return Err(PolicyError(format!(
                    "remote_mcp.redirect_uris: {} is not an https URL without a fragment",
                    crate::pyfmt::repr(bad)
                )));
            }
        }
        for (i, rule) in self.rules.iter().enumerate() {
            check_resource(&rule.matches.resource)
                .map_err(|e| PolicyError(format!("rules[{i}]: {e}")))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn defaults(&self) -> &Defaults {
        &self.defaults
    }

    #[must_use]
    pub fn llm(&self) -> &LlmConfig {
        &self.llm
    }

    #[must_use]
    pub fn platforms(&self) -> &PlatformsConfig {
        &self.platforms
    }

    #[must_use]
    pub fn desktop(&self) -> &DesktopConfig {
        &self.desktop
    }

    #[must_use]
    pub fn wiki(&self) -> &WikiConfig {
        &self.wiki
    }

    #[must_use]
    pub fn ui(&self) -> &UiConfig {
        &self.ui
    }

    #[must_use]
    pub fn notify(&self) -> &NotifyConfig {
        &self.notify
    }

    #[must_use]
    pub fn containment(&self) -> &ContainmentConfig {
        &self.containment
    }

    /// Restricted zones, by name.
    #[must_use]
    pub fn restricted(&self) -> &BTreeMap<String, RestrictedZone> {
        &self.restricted
    }

    #[must_use]
    pub fn audit(&self) -> &AuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn remote_mcp(&self) -> &RemoteMcpConfig {
        &self.remote_mcp
    }

    #[must_use]
    pub fn projects(&self) -> &BTreeMap<AttrValue, Project> {
        &self.projects
    }

    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// The parts of the configuration `Authority::is_sensitive` reads.
    #[must_use]
    pub fn sensitivity(&self) -> SensitivityConfig {
        let k8s = &self.platforms.kubernetes;
        SensitivityConfig {
            github_sensitive_permissions: self
                .platforms
                .github
                .sensitive_permissions
                .iter()
                .cloned()
                .collect(),
            kubernetes_sensitive_roles: k8s.sensitive_roles.iter().cloned().collect(),
            kubernetes_sensitive_namespaces: k8s.sensitive_namespaces.clone(),
            kubernetes_cluster_grant_namespace: k8s.cluster_grant_namespace.clone(),
            pool_sensitive_items: self
                .platforms
                .pools
                .iter()
                .map(|(name, pool)| {
                    let sensitive = pool
                        .items
                        .iter()
                        .filter(|(_, item)| item.sensitive)
                        .map(|(n, _)| n.clone())
                        .collect();
                    (name.clone(), sensitive)
                })
                .collect(),
        }
    }

    /// `cap_duration(requested, max)`: no longer than requested, the
    /// default maximum, and the rule's cap if it has one.
    #[must_use]
    pub fn cap_duration(
        &self,
        requested: DurationSecs,
        rule_max: Option<DurationSecs>,
    ) -> DurationSecs {
        cap_duration(requested, self.defaults.max_duration, rule_max)
    }
}

fn parse_platforms(value: Value) -> Result<PlatformsConfig, PolicyError> {
    let mut map = take_object("platforms", value)?;
    refuse_unknown("platforms: ", &map, &PLATFORM_SECTIONS)?;
    let mut out = PlatformsConfig::default();
    if let Some(v) = map.remove("github") {
        out.github = parse_section("platforms.github", v)?;
        out.github.normalize();
    }
    if let Some(v) = map.remove("homelab") {
        out.homelab = parse_section("platforms.homelab", v)?;
        out.homelab
            .validate()
            .map_err(|e| PolicyError(format!("platforms.homelab.{e}")))?;
    }
    if let Some(v) = map.remove("kubernetes") {
        out.kubernetes = parse_section("platforms.kubernetes", v)?;
        out.kubernetes
            .normalize()
            .map_err(|e| PolicyError(format!("platforms.kubernetes.{e}")))?;
    }
    if let Some(v) = map.remove("agents") {
        out.agents = parse_section("platforms.agents", v)?;
    }
    if let Some(v) = map.remove("hostexec") {
        out.hostexec = parse_section("platforms.hostexec", v)?;
    }
    if let Some(v) = map.remove("mcp") {
        out.mcp = parse_section("platforms.mcp", v)?;
        out.mcp.validate().map_err(PolicyError)?;
    }
    if let Some(v) = map.remove("models") {
        out.models = parse_section("platforms.models", v)?;
        out.models.validate().map_err(PolicyError)?;
    }
    if let Some(v) = map.remove("google") {
        out.google = parse_section("platforms.google", v)?;
        out.google
            .normalize()
            .map_err(|e| PolicyError(format!("platforms.google: {e}")))?;
    }
    if let Some(v) = map.remove("pools") {
        for (name, pool) in take_object("platforms.pools", v)? {
            let pool: PoolConfig = parse_section(&format!("platforms.pools.{name}"), pool)?;
            pool.validate(&name)
                .map_err(|e| PolicyError(format!("platforms.pools: {e}")))?;
            out.pools.insert(name, pool);
        }
    }
    Ok(out)
}
