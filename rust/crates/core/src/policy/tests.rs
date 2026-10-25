//! Policy loading and evaluation: the Python's tests (tests/test_policy.py,
//! test_agent_attributes.py, the policy parts of test_zones.py,
//! test_delegation.py, test_lifecycle.py, test_models.py) over the pure
//! functions, and property tests for the invariants of spec §5.4.
#![allow(clippy::arithmetic_side_effects)] // test arithmetic on small known values

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::*;
use crate::authority::{Authority, rule_covers};
use crate::glob::Glob;
use crate::ids::{RequestId, RuleId};
use crate::lifecycle::DecisionSource;
use crate::platform::Platform;
use crate::routing::{PolicyAction, Route};
use crate::zones::ZonePassed;

/// tests/conftest.py TEST_POLICY
const TEST_POLICY: &str = r#"
defaults: {action: surface, max_duration: 24h}
llm: {model: test/judge, retry_budget: 2, timeout_secs: 5}
platforms:
  github:
    repo_allowlist: ["jrt/*"]
    repo_denylist: [jrt/nixos-dots]
    permission_ceiling: {contents: write, secrets: write, issues: read}
    create_owners: [jrt]
  homelab: {allowed_groups: [svc-gitea, svc-sonarr, svc-k8s-gitops]}
  kubernetes:
    namespace_allowlist: ["apps-*", personal-site]
    role_allowlist: [view, logs-reader, edit]
    cluster_role_allowlist: [view, edit]
    cluster_grant_namespace: agent-auth
    role_descriptions: {view: read-only in the namespace}
rules:
  - match: {agent: "denied-*"}
    action: deny
    reason: agent is on the naughty list
  - match: {platform: homelab, resource: svc-sonarr}
    action: approve
    constraints: {max_duration: 1h}
  - match: {platform: github}
    action: llm
    constraints: {max_duration: 8h}
  - match: {platform: a2a, agent: "auto-*"}
    action: approve
    constraints: {max_duration: 2h}
  - match: {platform: a2a, agent: "claude-*"}
    action: approve
    constraints: {max_duration: 12h}
  - match: {platform: homelab, resource: svc-gitea, agent: "hermes-*", delegator: "claude-*"}
    action: approve
    constraints: {max_duration: 1h}
  - match: {platform: kubernetes, capability: view}
    action: approve
    constraints: {max_duration: 8h}
  - match: {platform: kubernetes, capability: edit}
    action: surface
"#;

fn test_policy() -> Policy {
    Policy::from_yaml(TEST_POLICY).unwrap()
}

fn now() -> OffsetDateTime {
    time::macros::datetime!(2026-10-25 12:00 UTC)
}

fn auth(platform: Platform, capability: &str, scope: Value) -> Authority {
    let scope = scope.as_object().cloned().unwrap_or_default();
    Authority::from_wire(platform, capability, &scope).unwrap()
}

fn a2a() -> Authority {
    auth(Platform::A2a, "talk", json!({}))
}

fn decide(
    policy: &Policy,
    agent: AgentRef<'_>,
    authority: &Authority,
    resource: &str,
) -> PolicyDecision {
    decide_with(policy, agent, Delegation::None, authority, resource, &[])
}

fn decide_with(
    policy: &Policy,
    agent: AgentRef<'_>,
    delegation: Delegation<'_>,
    authority: &Authority,
    resource: &str,
    saved: &[SavedRule],
) -> PolicyDecision {
    let input = PolicyInput {
        agent,
        delegation,
        resource,
        authority,
    };
    policy.evaluate(&input, saved, now())
}

fn routed(
    policy: &Policy,
    agent: AgentRef<'_>,
    delegation: Delegation<'_>,
    authority: &Authority,
    resource: &str,
    saved: &[SavedRule],
) -> (PolicyDecision, RoutedRequest) {
    let input = PolicyInput {
        agent,
        delegation,
        resource,
        authority,
    };
    policy.evaluate_and_route(
        RequestId::new(),
        &input,
        saved,
        &ZonePassed::for_tests(None),
        now(),
    )
}

fn saved(action: SavedRuleAction, agent: &str, platform: Platform) -> SavedRule {
    SavedRule {
        id: RuleId::new(),
        action,
        agent_pattern: Glob::new(agent),
        delegator_pattern: None,
        platform,
        resource_pattern: Glob::any(),
        authority: None,
        max_duration: None,
        enabled: true,
        notes: String::new(),
        expires_at: None,
        created_at: now(),
    }
}

fn secs(s: &str) -> DurationSecs {
    DurationSecs::parse(s).unwrap()
}

// ------------------------------------------------------- test_policy.py

#[test]
fn yaml_rule_matching() {
    let p = test_policy();
    let d = decide(&p, AgentRef::named("auto-deployer"), &a2a(), "other-agent");
    assert_eq!(d.action, PolicyAction::Approve);
    assert_eq!(d.max_duration, secs("2h"));
    let d = decide(&p, AgentRef::named("denied-agent"), &a2a(), "other-agent");
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.reason, "agent is on the naughty list");
    let gh = auth(Platform::Github, "repo", json!({}));
    let d = decide(&p, AgentRef::named("auto-deployer"), &gh, "jrt/x");
    assert_eq!(d.action, PolicyAction::Llm);
    assert_eq!(d.llm_model, "test/judge");
    assert_eq!(d.retry_budget, 2);
    assert_eq!(d.reason, "matched policy rule");
    assert_eq!(d.matched, Matched::PolicyRule(2));
}

#[test]
fn default_action_surface() {
    let d = decide(
        &test_policy(),
        AgentRef::named("plain-agent"),
        &a2a(),
        "other-agent",
    );
    assert_eq!(d.action, PolicyAction::Surface);
    assert_eq!(d.source(), DecisionSource::Policy);
    assert_eq!(d.reason, "no matching rule; policy default");
    assert_eq!(d.matched, Matched::Default);
    assert_eq!(d.max_duration, secs("24h"));
}

#[test]
fn db_rule_beats_yaml() {
    let mut rule = saved(
        SavedRuleAction::AutoApprove,
        "denied-but-trusted",
        Platform::A2a,
    );
    rule.max_duration = Some(secs("600"));
    let d = decide_with(
        &test_policy(),
        AgentRef::named("denied-but-trusted"),
        Delegation::None,
        &a2a(),
        "x",
        std::slice::from_ref(&rule),
    );
    assert_eq!(d.action, PolicyAction::Approve);
    assert_eq!(d.source(), DecisionSource::Rule);
    assert_eq!(d.rule_id(), Some(rule.id));
    assert_eq!(d.max_duration.get(), 600);
    assert_eq!(d.reason, "matched saved rule");
    assert!(!d.pinned && !d.explicit && !d.window);
}

#[test]
fn disabled_db_rule_ignored() {
    let mut rule = saved(SavedRuleAction::AutoDeny, "*", Platform::A2a);
    rule.enabled = false;
    let d = decide_with(
        &test_policy(),
        AgentRef::named("plain-agent-2"),
        Delegation::None,
        &a2a(),
        "x",
        &[rule],
    );
    assert_eq!(d.action, PolicyAction::Surface);
}

#[test]
fn expired_and_other_platform_rules_are_ignored() {
    let mut expired = saved(SavedRuleAction::AutoDeny, "*", Platform::A2a);
    expired.expires_at = Some(now());
    let other = saved(SavedRuleAction::AutoDeny, "*", Platform::Github);
    let d = decide_with(
        &test_policy(),
        AgentRef::named("plain"),
        Delegation::None,
        &a2a(),
        "x",
        &[expired.clone(), other],
    );
    assert_eq!(d.action, PolicyAction::Surface);
    expired.expires_at = Some(now() + time::Duration::seconds(1));
    expired.notes = "window".to_owned();
    let d = decide_with(
        &test_policy(),
        AgentRef::named("plain"),
        Delegation::None,
        &a2a(),
        "x",
        &[expired],
    );
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.reason, "matched saved rule (window)");
}

/// tests/test_lifecycle.py::test_rule_decisions_notify_channel: the newest
/// saved rule wins.
#[test]
fn newest_saved_rule_wins() {
    let mut older = saved(SavedRuleAction::AutoApprove, "*", Platform::A2a);
    older.created_at = now() - time::Duration::hours(1);
    let newer = saved(SavedRuleAction::AutoDeny, "*", Platform::A2a);
    let mut rules = vec![older.clone(), newer.clone()];
    sort_saved_rules(&mut rules);
    assert_eq!(rules[0].id, newer.id);
    let d = decide_with(
        &test_policy(),
        AgentRef::named("x"),
        Delegation::None,
        &a2a(),
        "y",
        &rules,
    );
    assert_eq!(d.rule_id(), Some(newer.id));
    // Same instant: the id decides, so the order is total.
    let mut tie = older.clone();
    tie.created_at = newer.created_at;
    let mut a = vec![tie.clone(), newer.clone()];
    let mut b = vec![newer.clone(), tie.clone()];
    sort_saved_rules(&mut a);
    sort_saved_rules(&mut b);
    assert_eq!(a, b);
}

#[test]
fn scope_pinned_rule_does_not_widen() {
    let p = test_policy();
    let contents = auth(
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
    );
    let secrets = auth(
        Platform::Github,
        "repo",
        json!({"permissions": {"secrets": "write"}}),
    );
    let mut rule = saved(SavedRuleAction::AutoApprove, "sde-widen", Platform::Github);
    rule.resource_pattern = Glob::new("jrt/cactus");
    rule.authority = Some(contents.clone());
    let rules = [rule];
    let agent = AgentRef::named("sde-widen");
    let d = decide_with(&p, agent, Delegation::None, &contents, "jrt/cactus", &rules);
    assert_eq!(
        (d.action, d.source()),
        (PolicyAction::Approve, DecisionSource::Rule)
    );
    assert!(d.pinned && d.explicit);
    let d = decide_with(&p, agent, Delegation::None, &secrets, "jrt/cactus", &rules);
    // Falls through the pinned rule to the YAML github → llm rule.
    assert_eq!(d.action, PolicyAction::Llm);
}

#[test]
fn is_sensitive() {
    let cfg = test_policy().sensitivity();
    let secrets = auth(
        Platform::Github,
        "repo",
        json!({"permissions": {"secrets": "write"}}),
    );
    assert!(secrets.is_sensitive(&cfg, "jrt/x"));
    let contents = auth(
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
    );
    assert!(!contents.is_sensitive(&cfg, "jrt/x"));
    let edit = auth(Platform::Kubernetes, "edit", json!({}));
    assert!(edit.is_sensitive(&cfg, "media"));
    // cluster_grant_namespace is always sensitive.
    let view = auth(Platform::Kubernetes, "view", json!({}));
    assert!(view.is_sensitive(&cfg, "agent-auth"));
    assert!(!view.is_sensitive(&cfg, "apps-x"));
}

#[test]
fn null_authority_rule_cannot_clear_sensitive_role() {
    let p = test_policy();
    let rule = saved(
        SavedRuleAction::AutoApprove,
        "k8s-broad",
        Platform::Kubernetes,
    );
    let agent = AgentRef::named("k8s-broad");
    for role in ["view", "edit"] {
        let a = auth(Platform::Kubernetes, role, json!({}));
        let (d, r) = routed(
            &p,
            agent,
            Delegation::None,
            &a,
            "apps-x",
            std::slice::from_ref(&rule),
        );
        assert!(!d.pinned);
        assert_eq!(d.action, PolicyAction::Approve);
        if role == "edit" {
            assert_eq!(r.route, Route::Surface);
            assert_eq!(
                r.notes,
                vec!["sensitive capability — routed to human review"]
            );
        } else {
            assert!(matches!(r.route, Route::Approve(_)));
            assert!(r.notes.is_empty());
        }
    }
}

#[test]
fn duration_capping() {
    let p = test_policy();
    assert_eq!(
        p.cap_duration(secs("3600"), Some(secs("7200"))),
        secs("3600")
    );
    assert_eq!(
        p.cap_duration(secs("36000"), Some(secs("7200"))),
        secs("7200")
    );
    assert_eq!(p.cap_duration(secs("48h"), None), secs("24h"));
}

// ------------------------------------------- test_agent_attributes.py

fn rules_policy(rules: Value, extra: Value) -> Policy {
    let mut doc = extra.as_object().cloned().unwrap_or_default();
    doc.insert("rules".to_owned(), rules);
    Policy::from_value(Value::Object(doc)).unwrap()
}

#[test]
fn a_rule_matches_fields_not_the_name() {
    let p = rules_policy(
        json!([{"match": {"agent": {"placement": "sandbox", "runtime": ["claude", "codex"]}, "platform": "a2a"}, "action": "approve"}]),
        json!({}),
    );
    let imposter = AgentRef::named("claude-thing-excelsior-sandbox");
    let real = AgentRef {
        runtime: Some("codex"),
        placement: Placement::Sandbox,
        host: Some("excelsior"),
        ..AgentRef::named("whatever")
    };
    let other = AgentRef {
        runtime: Some("hermes"),
        placement: Placement::Sandbox,
        ..AgentRef::named("hermes-x")
    };
    assert_eq!(
        decide(&p, real, &a2a(), "peer").action,
        PolicyAction::Approve
    );
    assert_eq!(
        decide(&p, imposter, &a2a(), "peer").action,
        PolicyAction::Surface
    );
    assert_eq!(
        decide(&p, other, &a2a(), "peer").action,
        PolicyAction::Surface
    );
}

#[test]
fn a_rule_about_the_agents_own_project() {
    let p = rules_policy(
        json!([
            {"match": {"agent": {"runtime": "claude"}, "platform": "github", "resource": "{agent.repos}"}, "action": "approve"},
            {"match": {"platform": "kubernetes", "capability": "view", "resource": "{agent.project}"}, "action": "approve"}
        ]),
        json!({"projects": {"agent-auth": {"repos": ["uorux/agent-auth", "uorux/homelab"]}, "larder": {}}}),
    );
    let claude = |project| AgentRef {
        runtime: Some("claude"),
        project,
        ..AgentRef::named("a")
    };
    let mine = claude(Some("agent-auth"));
    let theirs = claude(Some("larder"));
    let none = claude(None);
    let stray = claude(Some("flux-system"));
    let gh = auth(Platform::Github, "repo", json!({}));
    let g = |agent, repo| decide(&p, agent, &gh, repo).action;
    assert_eq!(g(mine, "uorux/agent-auth"), PolicyAction::Approve);
    assert_eq!(g(mine, "uorux/homelab"), PolicyAction::Approve);
    assert_eq!(g(mine, "uorux/larder"), PolicyAction::Surface);
    assert_eq!(g(theirs, "uorux/agent-auth"), PolicyAction::Surface);
    assert_eq!(g(none, "uorux/agent-auth"), PolicyAction::Surface);
    let view = auth(Platform::Kubernetes, "view", json!({}));
    for (agent, ns, want) in [
        (mine, "agent-auth", PolicyAction::Approve),
        (mine, "larder", PolicyAction::Surface),
        (none, "", PolicyAction::Surface),
        (none, "None", PolicyAction::Surface),
        (stray, "flux-system", PolicyAction::Surface),
    ] {
        assert_eq!(decide(&p, agent, &view, ns).action, want, "{ns}");
    }
}

#[test]
fn a_mistake_in_the_policy_fails_at_load() {
    let cases: [(Value, &str); 8] = [
        (
            json!({"rules": [{"match": {"agent": {"project": "nope"}}, "action": "deny"}]}),
            "not listed under `projects`",
        ),
        (
            json!({"rules": [{"match": {"agent": {"runtme": "claude"}}, "action": "deny"}]}),
            "runtme",
        ),
        (
            json!({"rules": [{"match": {"agent": {"placement": "vm"}}, "action": "deny"}]}),
            "placement",
        ),
        (
            json!({"rules": [{"match": {"agent": {"runtime": []}}, "action": "deny"}]}),
            "empty list",
        ),
        (
            json!({"rules": [{"match": {"resource": "x/{agent.projct}"}, "action": "deny"}]}),
            "unknown placeholder",
        ),
        (
            json!({"rules": [{"match": {"resource": "x/{project}"}, "action": "deny"}]}),
            "not an {agent",
        ),
        (
            json!({"desktop": {"agents": [{"project": "nope"}]}}),
            "desktop.agents[0]",
        ),
        (json!({"projects": {"Bad Name": {}}}), "lowercase"),
    ];
    for (doc, why) in cases {
        let err = Policy::from_value(doc.clone()).unwrap_err().0;
        assert!(err.contains(why), "{doc}: {err}");
    }
    assert_eq!(
        Policy::from_value(
            json!({"rules": [{"match": {"agent": {"project": "nope"}}, "action": "deny"}]})
        )
        .unwrap_err()
        .0,
        "rules[0]: project 'nope' is not listed under `projects`"
    );
}

/// Bug B-1: every section refuses keys it doesn't know.
#[test]
fn typos_are_errors_everywhere() {
    let cases: [(Value, &str); 12] = [
        (
            json!({"rules": [{"match": {"agnet": "x"}, "action": "approve"}]}),
            "agnet",
        ),
        (
            json!({"rules": [{"match": {"platfrom": "github"}, "action": "approve"}]}),
            "platfrom",
        ),
        (
            json!({"rules": [{"action": "approve", "max_duration": "24h"}]}),
            "max_duration",
        ),
        (
            json!({"rules": [{"action": "approve", "constraints": {"max_durration": "1h"}}]}),
            "max_durration",
        ),
        (json!({"rules": [{"action": "aprove"}]}), "aprove"),
        (json!({"rules": [{"match": {}}]}), "action"),
        (json!({"defualts": {}}), "defualts"),
        (json!({"defaults": {"acton": "deny"}}), "acton"),
        (json!({"platforms": {"gihtub": {}}}), "gihtub"),
        (
            json!({"platforms": {"kubernetes": {"namespace_alowlist": []}}}),
            "namespace_alowlist",
        ),
        (json!({"llm": {"modle": "x"}}), "modle"),
        (
            json!({"restricted": {"z": {"members": ["*"], "k8s": []}}}),
            "k8s",
        ),
    ];
    for (doc, why) in cases {
        let err = Policy::from_value(doc.clone()).unwrap_err().0;
        assert!(err.contains(why), "{doc}: {err}");
    }
}

#[test]
fn field_validators() {
    let cases: [(Value, &str); 14] = [
        (
            json!({"wiki": {"repo": "nope"}}),
            "wiki.repo 'nope': owner/name",
        ),
        (
            json!({"ui": {"enabled": true, "issuer": "https://id"}}),
            "ui.base_url: an https URL is required when the panel is enabled",
        ),
        (
            json!({"platforms": {"mcp": {"servers": {"git": {"url": "https://x"}}}}}),
            "platforms.mcp.issuer (the broker's https URL) is required when servers are listed",
        ),
        (
            json!({"platforms": {"mcp": {"issuer": "https://b", "servers": {"Git": {"url": "https://x"}}}}}),
            "mcp server name 'Git': lowercase letters, digits and dashes",
        ),
        (
            json!({"platforms": {"models": {"name": "Lite"}}}),
            "platforms.models.name: lowercase letters, digits and dashes",
        ),
        (
            json!({"platforms": {"models": {"url": "ftp://x"}}}),
            "platforms.models: 'ftp://x' is not an http(s) URL",
        ),
        (
            json!({"remote_mcp": {"enabled": true}}),
            "remote_mcp needs base_url, and ui.issuer and ui.client_id to sign in with",
        ),
        (
            json!({"remote_mcp": {"enabled": true, "base_url": "https://b", "tools": ["whoami", "zz", "aa"]}, "ui": {"issuer": "https://id"}}),
            "remote_mcp.tools: no such tools: aa, zz",
        ),
        (
            json!({"remote_mcp": {"enabled": true, "base_url": "https://b", "redirect_uris": ["http://claude.ai/cb"]}, "ui": {"issuer": "https://id"}}),
            "remote_mcp.redirect_uris: 'http://claude.ai/cb' is not an https URL without a fragment",
        ),
        (
            json!({"remote_mcp": {"enabled": true, "base_url": "https://b", "redirect_uris": ["https://claude.ai/cb#x"]}, "ui": {"issuer": "https://id"}}),
            "remote_mcp.redirect_uris: 'https://claude.ai/cb#x' is not an https URL without a fragment",
        ),
        (
            json!({"restricted": {"z": {"members": []}}}),
            "restricted.z: members: at least one agent pattern",
        ),
        (
            json!({"defaults": {"max_duration": "0m"}}),
            "duration must be positive",
        ),
        (
            json!({"platforms": {"hostexec": {"templates": {"t": {"tier": "user", "argv": []}}}}}),
            "at least one argument",
        ),
        (
            json!({"platforms": {"homelab": {"managed_email_domain": ""}}}),
            "platforms.homelab.managed_email_domain",
        ),
    ];
    for (doc, why) in cases {
        let err = Policy::from_value(doc.clone()).unwrap_err().0;
        assert!(err.contains(why), "{doc}: {err}");
    }
    let ok = Policy::from_value(json!({
        "remote_mcp": {"enabled": true, "base_url": "https://b"}, "ui": {"issuer": "https://id"},
        "platforms": {"mcp": {"issuer": "https://b", "servers": {"git": {"url": "https://x"}}},
                      "models": {"url": "http://10.0.0.1:4000", "max_budget": 5.5}},
        "wiki": {"repo": "uorux/wiki"}
    }));
    assert!(ok.is_ok(), "{ok:?}");
}

#[test]
fn name_globs_still_work() {
    let p = rules_policy(
        json!([{"match": {"agent": "deploy-*", "platform": "a2a"}, "action": "approve"}]),
        json!({}),
    );
    assert_eq!(
        decide(&p, AgentRef::named("deploy-bot"), &a2a(), "peer").action,
        PolicyAction::Approve
    );
    assert_eq!(
        decide(&p, AgentRef::named("other-bot"), &a2a(), "peer").action,
        PolicyAction::Surface
    );
}

#[test]
fn a_delegator_is_matched_by_its_fields_too() {
    let p = rules_policy(
        json!([{"match": {"agent": {"runtime": "hermes"}, "platform": "kubernetes", "capability": "view",
                          "delegator": {"runtime": "claude", "placement": "sandbox"}}, "action": "approve"}]),
        json!({}),
    );
    let hermes = AgentRef {
        runtime: Some("hermes"),
        ..AgentRef::named("h")
    };
    let vm_claude = AgentRef {
        runtime: Some("claude"),
        placement: Placement::Sandbox,
        ..AgentRef::named("c1")
    };
    let host_claude = AgentRef {
        runtime: Some("claude"),
        ..AgentRef::named("c2")
    };
    let view = auth(Platform::Kubernetes, "view", json!({}));
    let asked_by = |d| decide_with(&p, hermes, d, &view, "media", &[]).action;
    assert_eq!(
        asked_by(Delegation::Agent(vm_claude)),
        PolicyAction::Approve
    );
    assert_eq!(
        asked_by(Delegation::Agent(host_claude)),
        PolicyAction::Surface
    );
    assert_eq!(asked_by(Delegation::None), PolicyAction::Surface);
    assert_eq!(asked_by(Delegation::Gone), PolicyAction::Surface);
}

// ---------------------------------------------------- test_delegation.py

/// test_delegation_rule_semantics, and the delegated-pair rule of conftest.
#[test]
fn delegation_rule_semantics() {
    let p = test_policy();
    let homelab = auth(Platform::Homelab, "group", json!({}));
    let hermes = AgentRef::named("hermes-1");
    let claude = AgentRef::named("claude-1");
    let codex = AgentRef::named("codex-1");
    // The pair rule approves only for a claude-* delegator.
    let d = decide_with(
        &p,
        hermes,
        Delegation::Agent(claude),
        &homelab,
        "svc-gitea",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Approve);
    let d = decide_with(
        &p,
        hermes,
        Delegation::Agent(codex),
        &homelab,
        "svc-gitea",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Surface);
    // ...and never without delegation.
    assert_eq!(
        decide(&p, hermes, &homelab, "svc-gitea").action,
        PolicyAction::Surface
    );
    // A rule without a delegator does not approve a delegated request...
    let d = decide_with(
        &p,
        hermes,
        Delegation::Agent(claude),
        &homelab,
        "svc-sonarr",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Surface);
    assert_eq!(
        decide(&p, hermes, &homelab, "svc-sonarr").action,
        PolicyAction::Approve
    );
    // ...but its deny still applies.
    let denied = AgentRef::named("denied-x");
    let d = decide_with(
        &p,
        denied,
        Delegation::Agent(claude),
        &homelab,
        "svc-sonarr",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Deny);
    // Saved rules: the same axis.
    let mut pair = saved(SavedRuleAction::AutoApprove, "hermes-1", Platform::Homelab);
    pair.delegator_pattern = Some(Glob::new("claude-1"));
    let rules = [pair.clone()];
    assert_eq!(
        decide_with(&p, hermes, Delegation::Agent(claude), &homelab, "x", &rules).rule_id(),
        Some(pair.id)
    );
    assert_eq!(
        decide_with(&p, hermes, Delegation::None, &homelab, "x", &rules).action,
        PolicyAction::Surface
    );
    assert_eq!(
        decide_with(&p, hermes, Delegation::Gone, &homelab, "x", &rules).action,
        PolicyAction::Surface
    );
    let plain = [saved(
        SavedRuleAction::AutoApprove,
        "hermes-1",
        Platform::Homelab,
    )];
    assert_eq!(
        decide_with(&p, hermes, Delegation::Agent(claude), &homelab, "x", &plain).action,
        PolicyAction::Surface
    );
    let deny = [saved(
        SavedRuleAction::AutoDeny,
        "hermes-1",
        Platform::Homelab,
    )];
    assert_eq!(
        decide_with(&p, hermes, Delegation::Agent(claude), &homelab, "x", &deny).action,
        PolicyAction::Deny
    );
}

/// Bug B-7: with an approving default, a delegated request still reaches
/// a human.
#[test]
fn the_default_never_clears_a_delegated_request() {
    let p = Policy::from_yaml("defaults: {action: approve}").unwrap();
    let homelab = auth(Platform::Homelab, "group", json!({}));
    let agent = AgentRef::named("a");
    assert_eq!(
        decide(&p, agent, &homelab, "g").action,
        PolicyAction::Approve
    );
    let d = decide_with(
        &p,
        agent,
        Delegation::Agent(AgentRef::named("b")),
        &homelab,
        "g",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Surface);
    let d = decide_with(&p, agent, Delegation::Gone, &homelab, "g", &[]);
    assert_eq!(d.action, PolicyAction::Surface);
    let p = Policy::from_yaml("defaults: {action: deny}").unwrap();
    let d = decide_with(
        &p,
        agent,
        Delegation::Agent(AgentRef::named("b")),
        &homelab,
        "g",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Deny);
}

// ------------------------------------------------ gates (test_lifecycle)

/// test_sensitive_scope_forced_to_human
#[test]
fn sensitive_scope_forced_to_human() {
    let secrets = auth(
        Platform::Github,
        "repo",
        json!({"permissions": {"secrets": "write"}}),
    );
    let (d, r) = routed(
        &test_policy(),
        AgentRef::named("sde"),
        Delegation::None,
        &secrets,
        "jrt/x",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Llm);
    assert_eq!(r.route, Route::Surface);
    assert!(r.notes[0].contains("sensitive"));
}

/// test_models.py::test_what_is_refused_and_what_a_rule_covers: a
/// catch-all approve rule doesn't hand out model keys.
#[test]
fn catch_all_rules_do_not_clear_explicit_only_privileges() {
    let p = rules_policy(
        json!([{"match": {"agent": "a"}, "action": "approve"}]),
        json!({}),
    );
    let models = auth(Platform::Models, "use", json!({}));
    let (d, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &models,
        "litellm",
        &[],
    );
    assert_eq!(d.action, PolicyAction::Approve);
    assert_eq!(r.route, Route::Surface);
    assert_eq!(
        r.notes,
        vec!["no rule names 'use' — routed to human review"]
    );
    // A rule naming it for the platform clears it.
    let p = rules_policy(
        json!([{"match": {"platform": "models", "capability": "use"}, "action": "approve"}]),
        json!({}),
    );
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &models,
        "litellm",
        &[],
    );
    assert!(matches!(r.route, Route::Approve(_)));
    // B-16: without a platform, `capability: use` names nothing.
    let p = rules_policy(
        json!([{"match": {"capability": "use"}, "action": "approve"}]),
        json!({}),
    );
    let (d, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &models,
        "litellm",
        &[],
    );
    assert!(!d.explicit);
    assert_eq!(r.route, Route::Surface);
    // A github create is only cleared by a rule naming "create".
    let create = auth(Platform::Github, "create", json!({}));
    let p = rules_policy(
        json!([{"match": {"platform": "github"}, "action": "approve"}]),
        json!({}),
    );
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &create,
        "jrt/new",
        &[],
    );
    assert_eq!(r.route, Route::Surface);
    let p = rules_policy(
        json!([{"match": {"platform": "github", "capability": "create"}, "action": "approve"}]),
        json!({}),
    );
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &create,
        "jrt/new",
        &[],
    );
    assert!(matches!(r.route, Route::Approve(_)));
    // Public is sensitive on top: only a pinned saved rule.
    let public = auth(Platform::Github, "create", json!({"visibility": "public"}));
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &public,
        "jrt/new",
        &[],
    );
    assert_eq!(r.route, Route::Surface);
    let mut pinned = saved(SavedRuleAction::AutoApprove, "a", Platform::Github);
    pinned.authority = Some(public.clone());
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &public,
        "jrt/new",
        &[pinned],
    );
    assert!(matches!(r.route, Route::Approve(_)));
}

/// A glob that happens to match the capability doesn't name it: `tpl.*`
/// is not explicit for `tpl.x`, nor `tpl.?` for... `tpl.?`.
#[test]
fn only_a_literal_capability_is_explicit() {
    let tpl = auth(
        Platform::Hostexec,
        "tpl.x",
        json!({"tier": "user", "params": {}}),
    );
    for (pattern, explicit) in [
        ("tpl.*", false),
        ("tpl.?", false),
        ("tpl.[x]", false),
        ("tpl.x", true),
    ] {
        let p = rules_policy(
            json!([{"match": {"platform": "hostexec", "capability": pattern}, "action": "approve"}]),
            json!({}),
        );
        let (d, r) = routed(
            &p,
            AgentRef::named("a"),
            Delegation::None,
            &tpl,
            "excelsior",
            &[],
        );
        assert_eq!(d.action, PolicyAction::Approve, "{pattern}");
        assert_eq!(d.explicit, explicit, "{pattern}");
        assert_eq!(matches!(r.route, Route::Approve(_)), explicit, "{pattern}");
    }
}

#[test]
fn shells_and_web_connectors_always_reach_a_human() {
    let p = rules_policy(
        json!([{"match": {"platform": "hostexec", "capability": "shell"}, "action": "approve"}]),
        json!({}),
    );
    let shell = auth(Platform::Hostexec, "shell", json!({"tier": "user"}));
    let mut pinned = saved(SavedRuleAction::AutoApprove, "*", Platform::Hostexec);
    pinned.authority = Some(shell.clone());
    let (d, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &shell,
        "excelsior",
        &[pinned],
    );
    assert!(d.pinned);
    assert_eq!(r.route, Route::Surface);
    assert_eq!(r.notes, vec!["always decided by a human"]);

    let a2a_rule = rules_policy(
        json!([{"match": {"platform": "a2a"}, "action": "approve"}]),
        json!({}),
    );
    let web = AgentRef {
        runtime: Some("web"),
        ..AgentRef::named("web-claude")
    };
    let (_, r) = routed(&a2a_rule, web, Delegation::None, &a2a(), "peer", &[]);
    assert_eq!(r.route, Route::Surface);
    assert_eq!(
        r.notes,
        vec!["for a web UI connector: always decided by a human"]
    );
    let homelab = auth(Platform::Homelab, "group", json!({}));
    let mut pair = saved(SavedRuleAction::AutoApprove, "*", Platform::Homelab);
    pair.delegator_pattern = Some(Glob::any());
    let (d, r) = routed(
        &a2a_rule,
        AgentRef::named("h"),
        Delegation::Agent(web),
        &homelab,
        "g",
        &[pair],
    );
    assert_eq!(d.action, PolicyAction::Approve);
    assert_eq!(r.route, Route::Surface);
}

#[test]
fn a_window_covers_run_and_tpl_of_its_tier() {
    let p = Policy::default();
    let window = auth(Platform::Hostexec, "run", json!({"tier": "user"}));
    let Authority::Hostexec(_) = &window else {
        panic!()
    };
    let mut rule = saved(SavedRuleAction::AutoApprove, "a", Platform::Hostexec);
    rule.authority = Some(Authority::Hostexec(
        crate::authority::HostexecAuthority::Window {
            tier: crate::authority::Tier::User,
        },
    ));
    let run = auth(
        Platform::Hostexec,
        "run",
        json!({"tier": "user", "argv": ["ls"]}),
    );
    let (d, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &run,
        "excelsior",
        std::slice::from_ref(&rule),
    );
    assert!(d.window && d.pinned);
    assert!(matches!(r.route, Route::Approve(_)));
    let root = auth(
        Platform::Hostexec,
        "run",
        json!({"tier": "root", "argv": ["ls"]}),
    );
    let d = decide_with(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &root,
        "excelsior",
        std::slice::from_ref(&rule),
    );
    assert_eq!(d.matched, Matched::Default);
    let shell = auth(Platform::Hostexec, "shell", json!({"tier": "user"}));
    let d = decide_with(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &shell,
        "excelsior",
        &[rule],
    );
    assert_eq!(d.matched, Matched::Default);
}

#[test]
fn a_zone_note_sends_it_to_a_human() {
    let p = rules_policy(
        json!([{"match": {"platform": "agents", "capability": "mint"}, "action": "approve"}]),
        json!({}),
    );
    let mint = auth(Platform::Agents, "mint", json!({"runtime": "codex"}));
    let input = PolicyInput {
        agent: AgentRef::named("o"),
        delegation: Delegation::None,
        resource: "codex-soc-galaxy-sandbox",
        authority: &mint,
    };
    let note = "mints an agent inside restricted zone soc: always a human";
    let (_, r) = p.evaluate_and_route(
        RequestId::new(),
        &input,
        &[],
        &ZonePassed::for_tests(Some(note)),
        now(),
    );
    assert_eq!(r.route, Route::Surface);
    assert_eq!(r.notes, vec![note]);
    let (_, r) = p.evaluate_and_route(
        RequestId::new(),
        &input,
        &[],
        &ZonePassed::for_tests(None),
        now(),
    );
    assert!(matches!(r.route, Route::Approve(_)));
}

/// A clearance names the request and authority it was computed for; a
/// decision cannot be widened by editing its fields, nor routed for
/// another authority.
#[test]
fn clearances_are_bound_and_decisions_sealed() {
    let p = rules_policy(
        json!([{"match": {"platform": "agents", "capability": "mint"}, "action": "approve"}]),
        json!({}),
    );
    let mint = auth(Platform::Agents, "mint", json!({"runtime": "codex"}));
    let input = PolicyInput {
        agent: AgentRef::named("o"),
        delegation: Delegation::None,
        resource: "codex-x-galaxy-sandbox",
        authority: &mint,
    };
    let id = RequestId::new();
    let zone = ZonePassed::for_tests(None);
    let (mut decision, r) = p.evaluate_and_route(id, &input, &[], &zone, now());
    let Route::Approve(c) = r.route else {
        panic!("{:?}", r.route)
    };
    assert_eq!(c.request(), id);
    assert_eq!(c.authority(), &mint);
    assert_eq!(c.source(), DecisionSource::Policy);

    // A sensitive authority: editing `pinned` on the decision does not
    // make it clear.
    let p = rules_policy(
        json!([{"match": {"platform": "sandbox", "capability": "project.write"}, "action": "approve"}]),
        json!({}),
    );
    let write = auth(Platform::Sandbox, "project.write", json!({}));
    let input = PolicyInput {
        agent: AgentRef::named("o"),
        delegation: Delegation::None,
        resource: "other",
        authority: &write,
    };
    let (mut d, r) = p.evaluate_and_route(id, &input, &[], &zone, now());
    assert_eq!(r.route, Route::Surface);
    d.pinned = true;
    d.explicit = true;
    assert_eq!(p.route(id, &input, &d, &zone).route, Route::Surface);

    // A decision evaluated for one authority clears nothing for another.
    decision.action = PolicyAction::Approve;
    assert_eq!(p.route(id, &input, &decision, &zone).route, Route::Surface);
}

// ------------------------------------------------- loading and overlays

/// test_zones.py::test_an_overlay_merges_over_the_policy_and_must_exist
#[test]
fn an_overlay_merges_over_the_policy() {
    let base = "projects: {ops: {}}\nrules:\n  - {match: {platform: a2a}, action: approve}\n";
    let private = "projects: {soc: {}}\n\
                   rules:\n  - {match: {agent: {project: soc}, platform: a2a}, action: deny}\n\
                   restricted:\n  soc: {members: [{project: soc}], kubernetes: [soc]}\n\
                   audit: {readers: [{project: soc}]}\n";
    let p = Policy::load(base, &[("private.yaml", private)]).unwrap();
    let projects: Vec<&str> = p.projects().keys().map(|k| k.as_str()).collect();
    assert_eq!(projects, vec!["ops", "soc"]);
    let actions: Vec<PolicyAction> = p.rules().iter().map(|r| r.action).collect();
    assert_eq!(actions, vec![PolicyAction::Deny, PolicyAction::Approve]);
    assert_eq!(p.restricted()["soc"].kubernetes, vec![Glob::new("soc")]);
    // A zone naming a project that isn't listed is an error, as in a rule.
    let bad = "restricted:\n  soc: {members: [{project: nope}]}\n";
    let err = Policy::load(base, &[("private.yaml", bad)]).unwrap_err().0;
    assert!(err.contains("nope"), "{err}");
    assert!(err.starts_with("restricted.soc.members[0]"), "{err}");
    // A parse error names the overlay.
    let err = Policy::load(base, &[("private.yaml", "a: [")])
        .unwrap_err()
        .0;
    assert!(err.starts_with("private.yaml: "), "{err}");
}

#[test]
fn overlay_semantics() {
    let merged = overlay(
        json!({"a": {"x": 1, "y": [1, 2]}, "b": 1, "c": [1]}),
        json!({"a": {"y": [3], "z": 2}, "b": {"n": 1}, "c": "s"}),
    );
    assert_eq!(
        merged,
        json!({"a": {"x": 1, "y": [3, 1, 2], "z": 2}, "b": {"n": 1}, "c": "s"})
    );
    assert_eq!(overlay(json!({"a": 1}), json!({})), json!({"a": 1}));
    assert_eq!(overlay(json!({"a": 1}), Value::Null), Value::Null);
}

#[test]
fn yaml_forms() {
    // Empty or comment-only documents are the defaults.
    assert_eq!(Policy::from_yaml("").unwrap(), Policy::default());
    assert_eq!(Policy::from_yaml("# nothing\n").unwrap(), Policy::default());
    assert_eq!(Policy::from_yaml("~").unwrap(), Policy::default());
    // Durations as ints or strings.
    let p = Policy::from_yaml("defaults: {max_duration: 3600}").unwrap();
    assert_eq!(p.defaults().max_duration.get(), 3600);
    let p = Policy::from_yaml("defaults: {max_duration: \"90\"}").unwrap();
    assert_eq!(p.defaults().max_duration.get(), 90);
    assert!(Policy::from_yaml("defaults: {max_duration: true}").is_err());
    // A duplicate key is an error, not a silent override.
    assert!(Policy::from_yaml("defaults: {action: deny}\ndefaults: {action: approve}\n").is_err());
    // The top level is a mapping.
    assert!(Policy::from_yaml("- a\n- b\n").is_err());
    // Anchors and aliases work within the limits.
    let p = Policy::from_yaml("rules:\n  - &r {match: {platform: a2a}, action: approve}\n  - *r\n")
        .unwrap();
    assert_eq!(p.rules().len(), 2);
}

#[test]
fn alias_bombs_are_refused() {
    let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
    for i in 1..12 {
        let prev = i - 1;
        doc.push_str(&format!(
            "a{i}: &a{i} [*a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}]\n"
        ));
    }
    let started = std::time::Instant::now();
    assert!(parse_yaml(&doc).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // Deep nesting too.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(parse_yaml(&deep).is_err());
    assert!(parse_yaml(&"x".repeat(MAX_POLICY_BYTES + 1)).is_err());
}

#[test]
fn the_example_policy_loads() {
    let text = include_str!("../../../../../policy.example.yaml");
    let p = Policy::from_yaml(text).unwrap();
    assert!(p.rules().len() > 10);
    assert_eq!(
        p.platforms().kubernetes.cluster_grant_namespace,
        "agent-auth"
    );
    assert!(
        p.sensitivity()
            .kubernetes_sensitive_roles
            .contains("pod-exec")
    );
}

#[test]
fn defaults_are_the_pythons() {
    let p = Policy::default();
    assert_eq!(p.defaults().action, PolicyAction::Surface);
    assert_eq!(p.defaults().max_duration.get(), 86_400);
    assert_eq!(p.llm().model, "anthropic/claude-sonnet-4.5");
    assert_eq!(p.llm().retry_budget, 2);
    assert_eq!(p.platforms().kubernetes.role_allowlist, vec!["view"]);
    assert_eq!(p.platforms().agents.runtimes, vec!["claude", "codex"]);
    assert_eq!(p.platforms().agents.lease.get(), 30 * 86_400);
    assert_eq!(p.platforms().hostexec.window_max.get(), 8 * 3600);
    assert_eq!(p.desktop().timeout.get(), 90);
    assert_eq!(p.remote_mcp().tools.len(), 23);
    assert_eq!(p.remote_mcp().refresh_ttl.get(), 30 * 86_400);
    assert_eq!(p.wiki().max_page_bytes, 65_536);
    assert!(p.platforms().homelab.managed_accounts);
}

// ------------------------------------------------- invariants (§5.4)

const AGENT_NAMES: [&str; 5] = ["auto-x", "claude-a", "hermes-b", "web-c", "denied-d"];
const RUNTIMES: [Option<&str>; 4] = [None, Some("claude"), Some("web"), Some("hermes")];
const PROJECTS: [Option<&str>; 3] = [None, Some("p1"), Some("p2")];
const RESOURCES: [&str; 6] = ["x", "apps-1", "kube-system", "jrt/x", "p1", "agent-auth"];

fn sample_authorities() -> Vec<Authority> {
    vec![
        auth(
            Platform::Github,
            "repo",
            json!({"permissions": {"contents": "write"}}),
        ),
        auth(
            Platform::Github,
            "repo",
            json!({"permissions": {"secrets": "write"}}),
        ),
        auth(Platform::Github, "create", json!({})),
        auth(Platform::Github, "create", json!({"visibility": "public"})),
        auth(Platform::Kubernetes, "view", json!({})),
        auth(Platform::Kubernetes, "edit", json!({})),
        auth(Platform::Kubernetes, "view", json!({"cluster": true})),
        a2a(),
        auth(Platform::Homelab, "group", json!({})),
        auth(Platform::Mcp, "use", json!({})),
        auth(Platform::Mcp, "use", json!({"tools": ["a"]})),
        auth(Platform::Models, "use", json!({})),
        auth(
            Platform::Hostexec,
            "run",
            json!({"tier": "user", "argv": ["ls"]}),
        ),
        auth(
            Platform::Hostexec,
            "run",
            json!({"tier": "root", "argv": ["ls"]}),
        ),
        auth(
            Platform::Hostexec,
            "tpl.restart",
            json!({"tier": "user", "params": {}}),
        ),
        auth(Platform::Hostexec, "shell", json!({"tier": "user"})),
        auth(Platform::Agents, "mint", json!({"runtime": "claude"})),
        auth(Platform::Sandbox, "project.read", json!({})),
        auth(Platform::Sandbox, "project.write", json!({})),
        auth(Platform::Google, "calendar.read", json!({})),
    ]
}

fn arb_action() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("deny"), Just("approve"), Just("llm"), Just("surface")]
}

fn arb_agent_pattern() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("*")),
        Just(json!("claude-*")),
        Just(json!("auto-x")),
        Just(json!({"runtime": "claude"})),
        Just(json!({"project": ["p1", "p2"]})),
        Just(json!({"placement": "sandbox"})),
        Just(json!({"kind": ["service"]})),
    ]
}

fn arb_yaml_rule() -> impl Strategy<Value = Value> {
    let platform = prop_oneof![
        Just(None),
        proptest::sample::select(Platform::ALL.to_vec()).prop_map(Some)
    ];
    let capability = proptest::sample::select(vec![
        "*",
        "view",
        "edit",
        "repo",
        "use",
        "run",
        "create",
        "talk",
        "shell",
        "mint",
        "group",
        "project.write",
    ]);
    let resource = proptest::sample::select(vec![
        "*",
        "{agent.project}",
        "apps-*",
        "x",
        "{agent.repos}",
        "kube-*",
    ]);
    (
        arb_agent_pattern(),
        platform,
        capability,
        resource,
        proptest::option::of(arb_agent_pattern()),
        arb_action(),
        proptest::option::of(1u32..200_000),
    )
        .prop_map(
            |(agent, platform, capability, resource, delegator, action, max)| {
                let mut m = Map::new();
                m.insert("agent".into(), agent);
                if let Some(p) = platform {
                    m.insert("platform".into(), json!(p.as_str()));
                }
                m.insert("capability".into(), json!(capability));
                m.insert("resource".into(), json!(resource));
                if let Some(d) = delegator {
                    m.insert("delegator".into(), d);
                }
                let mut rule = json!({"match": m, "action": action});
                if let Some(max) = max {
                    rule["constraints"] = json!({"max_duration": max});
                }
                rule
            },
        )
}

fn arb_policy() -> impl Strategy<Value = Policy> {
    (
        proptest::collection::vec(arb_yaml_rule(), 0..6),
        arb_action(),
        1u32..200_000,
    )
        .prop_map(|(rules, default, max)| {
            Policy::from_value(json!({
                "defaults": {"action": default, "max_duration": max},
                "projects": {"p1": {"repos": ["jrt/x"]}, "p2": {}},
                "rules": rules,
            }))
            .unwrap()
        })
}

#[derive(Debug, Clone)]
struct AgentSpec {
    name: &'static str,
    runtime: Option<&'static str>,
    project: Option<&'static str>,
    placement: Placement,
    kind: AgentKind,
}

impl AgentSpec {
    fn as_ref(&self) -> AgentRef<'static> {
        AgentRef {
            name: self.name,
            runtime: self.runtime,
            project: self.project,
            host: Some("h"),
            placement: self.placement,
            kind: self.kind,
        }
    }
}

fn arb_agent() -> impl Strategy<Value = AgentSpec> {
    (
        proptest::sample::select(AGENT_NAMES.to_vec()),
        proptest::sample::select(RUNTIMES.to_vec()),
        proptest::sample::select(PROJECTS.to_vec()),
        proptest::sample::select(Placement::ALL.to_vec()),
        proptest::sample::select(vec![AgentKind::Service, AgentKind::Ephemeral]),
    )
        .prop_map(|(name, runtime, project, placement, kind)| AgentSpec {
            name,
            runtime,
            project,
            placement,
            kind,
        })
}

#[derive(Debug, Clone)]
enum DelegationSpec {
    None,
    Gone,
    Agent(AgentSpec),
}

fn arb_delegation() -> impl Strategy<Value = DelegationSpec> {
    prop_oneof![
        Just(DelegationSpec::None),
        Just(DelegationSpec::Gone),
        arb_agent().prop_map(DelegationSpec::Agent),
    ]
}

fn arb_saved_rules() -> impl Strategy<Value = Vec<SavedRule>> {
    let one = (
        any::<bool>(),
        proptest::sample::select(vec!["*", "claude-*", "auto-x", "hermes-b"]),
        proptest::option::of(proptest::sample::select(vec!["*", "claude-*", "web-c"])),
        0usize..20,
        proptest::option::of(0usize..21),
        proptest::sample::select(vec!["*", "x", "apps-*"]),
        proptest::option::of(-2i64..3),
        any::<bool>(),
        proptest::option::of(1u32..200_000),
    )
        .prop_map(
            |(
                approve,
                agent,
                delegator,
                platform_of,
                authority,
                resource,
                expires,
                enabled,
                max,
            )| {
                let samples = sample_authorities();
                let platform = samples[platform_of].platform();
                let authority = authority.map(|i| {
                    if i == 20 {
                        Authority::Hostexec(crate::authority::HostexecAuthority::Window {
                            tier: crate::authority::Tier::User,
                        })
                    } else {
                        samples[i % samples.len()].clone()
                    }
                });
                SavedRule {
                    id: RuleId::new(),
                    action: if approve {
                        SavedRuleAction::AutoApprove
                    } else {
                        SavedRuleAction::AutoDeny
                    },
                    agent_pattern: Glob::new(agent),
                    delegator_pattern: delegator.map(Glob::new),
                    platform,
                    resource_pattern: Glob::new(resource),
                    authority,
                    max_duration: max.map(|m| DurationSecs::from_secs(i64::from(m)).unwrap()),
                    enabled,
                    notes: String::new(),
                    expires_at: expires.map(|h| now() + time::Duration::hours(h)),
                    created_at: now(),
                }
            },
        );
    proptest::collection::vec(one, 0..5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// INV-4..INV-10, INV-13, INV-19 over random policies, saved rules,
    /// agents, delegations, requests and zone outcomes.
    #[test]
    fn invariants_hold(
        policy in arb_policy(),
        saved in arb_saved_rules(),
        agent in arb_agent(),
        delegation in arb_delegation(),
        which in 0usize..20,
        resource in proptest::sample::select(RESOURCES.to_vec()),
        zone_human in any::<bool>(),
        requested in 1u32..400_000,
    ) {
        let authorities = sample_authorities();
        let authority = &authorities[which];
        let delegation_ref = match &delegation {
            DelegationSpec::None => Delegation::None,
            DelegationSpec::Gone => Delegation::Gone,
            DelegationSpec::Agent(a) => Delegation::Agent(a.as_ref()),
        };
        let input = PolicyInput { agent: agent.as_ref(), delegation: delegation_ref, resource, authority };
        let zone = ZonePassed::for_tests(zone_human.then_some("zone"));
        let (decision, routed) = policy.evaluate_and_route(RequestId::new(), &input, &saved, &zone, now());
        let result = routed.route.action();
        let proposed = decision.action;

        // INV-4: gates only downgrade, and deny is decided by policy alone.
        prop_assert!(result == proposed || result == PolicyAction::Surface);
        prop_assert_eq!(result == PolicyAction::Deny, proposed == PolicyAction::Deny);
        if proposed == PolicyAction::Surface {
            prop_assert_eq!(result, PolicyAction::Surface);
        }
        prop_assert_eq!(routed.notes.len(), routed.downgrades.len());

        // The matched layer, and the saved rule if one.
        let matched_saved = match decision.matched {
            Matched::SavedRule(id) => saved.iter().find(|r| r.id == id),
            _ => None,
        };
        let matched_yaml = match decision.matched {
            Matched::PolicyRule(i) => policy.rules().get(i),
            _ => None,
        };
        prop_assert_eq!(matches!(decision.matched, Matched::SavedRule(_)), matched_saved.is_some());
        prop_assert_eq!(matches!(decision.matched, Matched::PolicyRule(_)), matched_yaml.is_some());

        // INV-13: a pinned saved rule covers the request; null never pins.
        if let Some(rule) = matched_saved {
            prop_assert!(rule.enabled && rule.platform == authority.platform());
            prop_assert!(rule_covers(rule.authority.as_ref(), authority));
            prop_assert_eq!(decision.pinned, rule.authority.is_some());
            prop_assert!(rule.expires_at.is_none_or(|e| e > now()));
        } else {
            prop_assert!(!decision.pinned);
        }

        if result.is_auto() {
            // INV-5: human-only authorities.
            prop_assert!(!authority.human_only());
            // INV-6: web connectors, and requests on their behalf.
            prop_assert!(!input.agent.is_web() && !input.delegation.is_web());
            // INV-9: a zone that wants a human.
            prop_assert!(!zone_human);
            // INV-7: sensitive only through a covering pinned saved rule.
            if authority.is_sensitive(&policy.sensitivity(), resource) {
                let rule = matched_saved.and_then(|r| r.authority.as_ref());
                prop_assert!(rule.is_some_and(|a| rule_covers(Some(a), authority)));
            }
            // INV-8: explicit-only privileges through a rule naming them.
            if authority.needs_explicit_rule() {
                let by_saved = matched_saved.is_some_and(|r| r.authority.is_some());
                let by_yaml = matched_yaml.is_some_and(|r| {
                    r.matches.platform == Some(authority.platform())
                        && r.matches.capability.is_literal()
                        && r.matches.capability.as_str() == authority.capability()
                });
                prop_assert!(by_saved || by_yaml);
            }
        }

        // INV-10: the delegation axis (the default included, B-7).
        if proposed.is_auto() {
            match (&delegation, decision.matched) {
                (DelegationSpec::None, _) => {
                    prop_assert!(matched_saved.is_none_or(|r| r.delegator_pattern.is_none()));
                    prop_assert!(matched_yaml.is_none_or(|r| r.matches.delegator.is_none()));
                }
                (_, Matched::Default) => prop_assert!(false, "the default cleared a delegated request"),
                (DelegationSpec::Gone, _) => prop_assert!(false, "a gone delegator matched"),
                (DelegationSpec::Agent(d), _) => {
                    if let Some(r) = matched_saved {
                        prop_assert!(r.delegator_pattern.as_ref().is_some_and(|g| g.matches(d.name)));
                    }
                    if let Some(r) = matched_yaml {
                        prop_assert!(r.matches.delegator.as_ref().is_some_and(|p| p.matches(&d.as_ref())));
                    }
                }
            }
        }
        if matches!(delegation, DelegationSpec::None) {
            prop_assert!(matched_saved.is_none_or(|r| r.delegator_pattern.is_none()));
            prop_assert!(matched_yaml.is_none_or(|r| r.matches.delegator.is_none()));
        }

        // INV-19: the approved duration is capped by everything.
        let requested = DurationSecs::from_secs(i64::from(requested)).unwrap_or(DurationSecs::MAX);
        let capped = policy.cap_duration(requested, Some(decision.max_duration));
        prop_assert!(capped <= requested);
        prop_assert!(capped <= policy.defaults().max_duration);
        prop_assert!(capped <= decision.max_duration);
        if let Some(cap) = matched_saved.and_then(|r| r.max_duration) {
            prop_assert!(capped <= cap);
        }
        if let Some(cap) = matched_yaml.and_then(|r| r.constraints.max_duration) {
            prop_assert!(capped <= cap);
        }
    }

    /// First match: removing every rule before the matched one, or adding
    /// a non-matching rule, doesn't change the decision; the matched rule
    /// alone decides the same.
    #[test]
    fn first_match_wins(
        policy in arb_policy(),
        agent in arb_agent(),
        which in 0usize..20,
        resource in proptest::sample::select(RESOURCES.to_vec()),
    ) {
        let authorities = sample_authorities();
        let input = PolicyInput { agent: agent.as_ref(), delegation: Delegation::None, resource, authority: &authorities[which] };
        let d = policy.evaluate(&input, &[], now());
        if let Matched::PolicyRule(i) = d.matched {
            // Each earlier rule alone does not match.
            for j in 0..i {
                let alone = Policy::from_value(json!({
                    "defaults": {"action": "surface", "max_duration": policy.defaults().max_duration.get()},
                    "projects": {"p1": {"repos": ["jrt/x"]}, "p2": {}},
                    "rules": [rule_value(&policy.rules()[j])],
                })).unwrap();
                prop_assert_eq!(alone.evaluate(&input, &[], now()).matched, Matched::Default);
            }
        }
    }
}

fn rule_value(rule: &PolicyRule) -> Value {
    let m = &rule.matches;
    let mut out = Map::new();
    out.insert("agent".into(), m.agent.to_value());
    if let Some(p) = m.platform {
        out.insert("platform".into(), json!(p.as_str()));
    }
    out.insert("capability".into(), json!(m.capability.as_str()));
    out.insert("resource".into(), json!(m.resource));
    if let Some(d) = &m.delegator {
        out.insert("delegator".into(), d.to_value());
    }
    json!({"match": out, "action": rule.action.as_str()})
}

/// Case-folded resources are matched by lowercased globs (provisioners
/// review: a denylist with a capital failed open).
#[test]
fn resource_globs_are_lowercased_at_load() {
    let p = Policy::from_value(json!({
        "platforms": {
            "github": {"repo_denylist": ["JRT/Secrets"], "repo_allowlist": ["Acme/*"]},
            "kubernetes": {"namespace_allowlist": ["Apps-*"], "sensitive_namespaces": ["Kube-*"], "grant_namespace": "AA-Grants"},
        },
        "restricted": {"soc": {"members": ["soc-*"], "kubernetes": ["SOC-*"], "github": ["Acme/SOC-*"]}},
    }))
    .unwrap();
    let gh = &p.platforms().github;
    assert!(gh.repo_denylist[0].matches("jrt/secrets"));
    assert!(gh.repo_allowlist[0].matches("acme/x"));
    let k = &p.platforms().kubernetes;
    assert!(k.namespace_allowlist[0].matches("apps-x"));
    assert!(k.namespace_is_sensitive("kube-system"));
    assert_eq!(k.grant_namespace, "aa-grants");
    let zone = &p.restricted()["soc"];
    assert!(zone.kubernetes[0].matches("soc-x"));
    assert!(zone.github[0].matches("acme/soc-1"));
    assert_eq!(
        KubernetesConfig::default().grant_namespace,
        "agent-auth-grants"
    );
    let bad =
        Policy::from_value(json!({"platforms": {"kubernetes": {"grant_namespace": "not a ns"}}}));
    assert!(bad.unwrap_err().0.contains("grant_namespace"));
}

#[test]
fn mcp_audiences_are_unique() {
    let err = Policy::from_value(
        json!({"platforms": {"mcp": {"issuer": "https://b", "servers": {
            "a": {"url": "https://x/mcp"},
            "b": {"url": "https://y/mcp", "audience": "https://x/mcp"},
        }}}}),
    )
    .unwrap_err();
    assert_eq!(
        err.0,
        "platforms.mcp.servers: a and b have the same audience 'https://x/mcp'"
    );
}

// ------------------------------------------ test_review_2026_10.py (core)

/// A saved rule pinned to a role with a widened resource (what Discord's
/// Edit "approve:capability" saves) clears an ordinary namespace, never a
/// sensitive one; a human's rule for exactly that namespace does.
#[test]
fn a_widened_saved_rule_does_not_clear_a_sensitive_namespace() {
    let p = Policy::from_value(json!({
        "platforms": {"kubernetes": {
            "namespace_allowlist": ["apps-*"],
            "role_allowlist": ["logs-reader"],
            "sensitive_namespaces": ["kube-system", "apps-system"],
        }}
    }))
    .unwrap();
    let role = auth(Platform::Kubernetes, "logs-reader", json!({}));
    let mut widened = saved(
        SavedRuleAction::AutoApprove,
        "ops-agent",
        Platform::Kubernetes,
    );
    widened.authority = Some(role.clone());
    let agent = AgentRef::named("ops-agent");
    let (_, r) = routed(
        &p,
        agent,
        Delegation::None,
        &role,
        "apps-a",
        &[widened.clone()],
    );
    assert_eq!(r.route.action(), PolicyAction::Approve);
    let (d, r) = routed(
        &p,
        agent,
        Delegation::None,
        &role,
        "apps-system",
        &[widened.clone()],
    );
    assert!(d.pinned && !d.names_resource);
    assert_eq!(r.route.action(), PolicyAction::Surface);
    assert_eq!(
        r.notes,
        vec!["sensitive capability — routed to human review".to_owned()]
    );
    let mut named = widened.clone();
    named.id = RuleId::new();
    named.resource_pattern = Glob::new("apps-system");
    let (d, r) = routed(
        &p,
        agent,
        Delegation::None,
        &role,
        "apps-system",
        &[named, widened],
    );
    assert!(d.names_resource);
    assert_eq!(r.route.action(), PolicyAction::Approve);
}

/// A pool's sensitive item is the resource's doing: a pinned rule for any
/// pool does not lease it, one naming the pool does.
#[test]
fn a_pinned_rule_for_a_sensitive_item_must_name_the_pool() {
    let p = Policy::from_value(json!({
        "platforms": {"pools": {"minecraft": {"items": {
            "alt-1": {"properties": {"edition": "java"}},
            "main": {"sensitive": true},
        }}}}
    }))
    .unwrap();
    let main = auth(Platform::Pool, "lease", json!({"item": "main"}));
    let mut rule = saved(SavedRuleAction::AutoApprove, "bot-a", Platform::Pool);
    rule.authority = Some(main.clone());
    let bot = AgentRef::named("bot-a");
    let (_, r) = routed(
        &p,
        bot,
        Delegation::None,
        &main,
        "minecraft",
        &[rule.clone()],
    );
    assert_eq!(r.route.action(), PolicyAction::Surface);
    rule.resource_pattern = Glob::new("minecraft");
    let (_, r) = routed(&p, bot, Delegation::None, &main, "minecraft", &[rule]);
    assert_eq!(r.route.action(), PolicyAction::Approve);
}

/// Pools, google and mail-like platforms need a rule naming them; a policy
/// rule for the platform and capability does.
#[test]
fn pool_and_google_need_a_named_rule() {
    let p = Policy::from_value(json!({
        "platforms": {"pools": {"shared": {"items": {"box": {}}}}},
        "rules": [
            {"match": {"agent": "*"}, "action": "approve"},
        ],
    }))
    .unwrap();
    let any = auth(Platform::Pool, "lease", json!({}));
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &any,
        "shared",
        &[],
    );
    assert_eq!(r.route.action(), PolicyAction::Surface);
    let named = Policy::from_value(json!({
        "rules": [{"match": {"platform": "pool", "capability": "lease"}, "action": "approve"}],
    }))
    .unwrap();
    let (_, r) = routed(
        &named,
        AgentRef::named("a"),
        Delegation::None,
        &any,
        "shared",
        &[],
    );
    assert_eq!(r.route.action(), PolicyAction::Approve);
    let cal = auth(Platform::Google, "calendar.read", json!({}));
    let (_, r) = routed(
        &p,
        AgentRef::named("a"),
        Delegation::None,
        &cal,
        "main",
        &[],
    );
    assert_eq!(r.route.action(), PolicyAction::Surface);
    let write = auth(Platform::Google, "calendar.write", json!({}));
    let google = Policy::from_value(json!({
        "rules": [{"match": {"platform": "google", "capability": "calendar.write"}, "action": "approve"}],
    }))
    .unwrap();
    let (_, r) = routed(
        &google,
        AgentRef::named("a"),
        Delegation::None,
        &write,
        "main",
        &[],
    );
    assert_eq!(r.route.action(), PolicyAction::Surface, "sensitive");
}

#[test]
fn a_rule_names_a_capability_only_with_its_platform() {
    let p = Policy::from_value(json!({
        "rules": [{"match": {"capability": "use"}, "action": "approve"}],
    }))
    .unwrap();
    let d = decide(
        &p,
        AgentRef::named("any-agent"),
        &auth(Platform::Mcp, "use", json!({})),
        "x",
    );
    assert!(!d.explicit);
}

#[test]
fn the_wiki_repo_is_never_brokered() {
    let p = Policy::from_value(json!({"wiki": {"repo": "jrt/Agent-Wiki"}})).unwrap();
    assert_eq!(p.wiki().repo, "jrt/agent-wiki");
    let deny: Vec<&str> = p
        .platforms()
        .github
        .repo_denylist
        .iter()
        .map(Glob::as_str)
        .collect();
    assert_eq!(deny, vec!["jrt/agent-wiki"]);
    // Listed already (in any case): not twice.
    let p = Policy::from_value(json!({
        "wiki": {"repo": "jrt/wiki"},
        "platforms": {"github": {"repo_denylist": ["JRT/Wiki"]}},
    }))
    .unwrap();
    assert_eq!(p.platforms().github.repo_denylist.len(), 1);
}

#[test]
fn github_rule_resources_and_project_repos_are_lowercased() {
    let p = Policy::from_value(json!({
        "projects": {"app": {"repos": ["JRT/App"]}},
        "rules": [
            {"match": {"platform": "github", "resource": "JRT/Docs"}, "action": "approve"},
            {"match": {"agent": {"project": "app"}, "resource": "{agent.repos}"}, "action": "llm"},
            {"match": {"resource": "Other/*"}, "action": "deny"},
        ],
    }))
    .unwrap();
    assert_eq!(p.rules()[0].matches.resource, "jrt/docs");
    assert_eq!(p.projects().values().next().unwrap().repos, vec!["jrt/app"]);
    let repo = auth(Platform::Github, "repo", json!({}));
    let d = decide(&p, AgentRef::named("a"), &repo, "jrt/docs");
    assert_eq!(d.action, PolicyAction::Approve);
    let in_app = AgentRef {
        project: Some("app"),
        ..AgentRef::named("b")
    };
    let d = decide(&p, in_app, &repo, "jrt/app");
    assert_eq!(d.action, PolicyAction::Llm);
    // A rule with no platform is matched lowercased for GitHub requests.
    let d = decide(&p, AgentRef::named("a"), &repo, "other/x");
    assert_eq!(d.action, PolicyAction::Deny);
}

#[test]
fn google_accounts_and_pools_load() {
    let p = Policy::from_value(json!({"platforms": {
        "google": {"accounts": {"main": {
            "address": "Me@Example.com", "client_secret_file": "/c", "refresh_token_file": "/r",
        }}},
        "pools": {"minecraft": {
            "capacity": 2,
            "agents": ["bot-*"],
            "items": {"alt-1": {"properties": {"edition": "java", "tags": ["a"], "n": 1}}},
        }},
    }}))
    .unwrap();
    assert_eq!(
        p.platforms().google.accounts["main"].address,
        "me@example.com"
    );
    assert_eq!(p.platforms().pools["minecraft"].capacity, 2);
    let bad = |v: Value, text: &str| {
        let e = Policy::from_value(json!({"platforms": v})).unwrap_err();
        assert!(e.0.contains(text), "{e}");
    };
    bad(
        json!({"google": {"accounts": {"x": {"address": "a@b.example"}}}}),
        "either client_secret_file",
    );
    bad(
        json!({"google": {"accounts": {"x": {"address": "nope", "service_account_file": "/s"}}}}),
        "is not an email address",
    );
    bad(
        json!({"google": {"accounts": {"X": {"address": "a@b.c", "service_account_file": "/s"}}}}),
        "google account name 'X'",
    );
    bad(
        json!({"pools": {"p": {"capacity": 0}}}),
        "capacity: from 1 to 100",
    );
    bad(
        json!({"pools": {"p": {"max_per_agent": 0}}}),
        "max_per_agent",
    );
    bad(json!({"pools": {"Bad": {}}}), "pool name 'Bad'");
    bad(
        json!({"pools": {"p": {"items": {"-x": {}}}}}),
        "pool item '-x'",
    );
    bad(
        json!({"pools": {"p": {"items": {"x": {"properties": {"a": {"b": 1}}}}}}}),
        "a property is",
    );
    bad(
        json!({"pools": {"p": {"agents": [{"project": "nope"}]}}}),
        "is not listed",
    );
}

#[test]
fn the_orchestrator_runtime_is_not_mintable() {
    let e = Policy::from_yaml("platforms:\n  agents: {runtimes: [claude, orchestrator]}\n")
        .unwrap_err();
    assert!(e.0.contains("'orchestrator'"), "{e}");
}

#[test]
fn mint_runtimes_have_no_hyphen() {
    let e = Policy::from_yaml("platforms:\n  agents: {runtimes: [claude-x]}\n").unwrap_err();
    assert!(e.0.contains("no '-'"), "{e}");
}
