//! The bot against a fake Discord (a local axum server standing in for
//! the REST API) and, where it reads or writes rows, a real database.
//! Rendering is checked as pure functions against the spec's strings.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::durations::DurationSecs;
use agent_auth_core::{
    AgentId, Authority, DecisionSource, GrantId, GrantStatus, JobId, Platform, RequestId,
    RequestStatus, RuleId,
};
use agent_auth_crypto::Secret;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::hostexec::{JobRow, JobStatus};
use agent_auth_store::lockdown::ContainmentEntry;
use agent_auth_store::requests::{DiscordRefs, RequestRow};
use agent_auth_store::rules::{RuleAction, RuleRow};
use agent_auth_store::{Store, agents, requests, rules as rule_store};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::macros::datetime;
use twilight_model::application::interaction::Interaction;
use twilight_model::channel::message::Component;

use super::embeds::*;
use super::model::{COLOR_APPROVED, COLOR_ENDED, Input};
use super::notifier::{contained_message, shell_command_text};
use super::ops::{Contained, ContainmentOps, HumanDecision, OpError, RequestOps};
use super::rules::{Page, paginate, render, rule_detail_embed, rules_embed, rules_view};
use super::views::*;
use super::{Discord, DiscordConfig, Services, interactions};
use crate::auth::{DiscordOwner, HumanDecider};
use crate::notify::Notify;

pub(super) const OWNER: u64 = 42;
const T0: OffsetDateTime = datetime!(2026-10-25 12:00 UTC);

// ------------------------------------------------------------- fixtures

pub(super) fn agent(name: &str) -> AgentRow {
    AgentRow {
        id: AgentId::new(),
        name: name.to_owned(),
        description: String::new(),
        key_id: "k".to_owned(),
        api_key_hash: "h".to_owned(),
        webhook_url: None,
        webhook_secret: None,
        lldap_username: None,
        lldap_password_encrypted: None,
        disabled: false,
        kind: AgentKind::Service,
        last_seen_at: None,
        last_listen_at: None,
        parent_agent_id: None,
        sandbox_id: None,
        runtime: Some("claude".to_owned()),
        project: Some("agent-auth".to_owned()),
        host: Some("excelsior".to_owned()),
        placement: Placement::Sandbox,
        lease_expires_at: None,
        created_at: T0,
    }
}

fn authority(platform: Platform, cap: &str, scope: &Value) -> Authority {
    let Value::Object(m) = scope else {
        panic!("scope")
    };
    Authority::from_wire(platform, cap, m).expect("authority")
}

fn request(platform: Platform, cap: &str, scope: Value, resource: &str) -> RequestRow {
    RequestRow {
        id: RequestId::new(),
        agent_id: AgentId::new(),
        session_id: None,
        delegation: None,
        platform,
        resource: resource.to_owned(),
        requested_capability: cap.to_owned(),
        authority: Some(authority(platform, cap, &scope)),
        requested_scope: scope,
        justification: "I need to push the fix".to_owned(),
        requested_duration_secs: 3600,
        risk_notes: vec!["first request for this repo".to_owned()],
        status: RequestStatus::AwaitingHuman,
        attempt: 1,
        decision_source: None,
        decided_by: None,
        decision_reason: None,
        approved_duration_secs: None,
        approved_edit: None,
        decided_at: None,
        discord: DiscordRefs::default(),
        created_at: T0,
        updated_at: T0,
    }
}

fn github() -> RequestRow {
    request(
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        "uorux/agent-auth",
    )
}

fn grant(status: GrantStatus) -> GrantView {
    GrantView {
        status,
        expires_at: datetime!(2026-10-25 13:00 UTC),
        revoked_at: Some(datetime!(2026-10-25 12:30 UTC)),
        revoke_reason: Some("revoked by jrt".to_owned()),
    }
}

fn rule(action: RuleAction, enabled: bool) -> RuleRow {
    RuleRow {
        id: RuleId::new(),
        action,
        agent_pattern: "codex-*".to_owned(),
        delegator_pattern: Some("orchestrator".to_owned()),
        platform: Platform::Github,
        resource_pattern: "uorux/*".to_owned(),
        authority: Some(authority(
            Platform::Github,
            "repo",
            &json!({"permissions": {"contents": "write"}}),
        )),
        max_duration_secs: Some(7200),
        enabled,
        created_by: "jrt".to_owned(),
        notes: "their own repos".to_owned(),
        expires_at: None,
        created_at: T0,
    }
}

fn job(status: JobStatus, exit: Option<i32>, output: &str) -> JobRow {
    JobRow {
        id: JobId::new(),
        grant_id: None,
        request_id: RequestId::new(),
        agent_id: AgentId::new(),
        host: "excelsior".to_owned(),
        tier: agent_auth_core::Tier::User,
        shell_id: None,
        spec: json!({"argv": ["ls", "-la"], "cwd": "/tmp", "env": {"B": "2", "A": "1"}}),
        status,
        via: None,
        exit_code: exit,
        error: None,
        output: Some(output.to_owned()),
        output_bytes: None,
        output_sha256: None,
        truncated: false,
        duration_ms: Some(1234),
        finished_at: None,
        created_at: T0,
        updated_at: T0,
    }
}

fn field<'a>(e: &'a twilight_model::channel::message::Embed, name: &str) -> &'a str {
    &e.fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .value
}

fn buttons(components: &[Component]) -> Vec<(String, Option<String>, bool)> {
    let mut out = Vec::new();
    for c in components {
        if let Component::ActionRow(r) = c {
            for b in &r.components {
                if let Component::Button(b) = b {
                    out.push((
                        b.label.clone().unwrap_or_default(),
                        b.custom_id.clone(),
                        b.disabled,
                    ));
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------ rendering

#[test]
fn custom_ids_round_trip() {
    let rid = RequestId::new();
    for id in [
        CustomId::Approve(rid),
        CustomId::Deny(rid),
        CustomId::Edit(rid),
        CustomId::Totp(rid),
        CustomId::EndShell(rid),
        CustomId::DecisionModal {
            approve: true,
            request: rid,
        },
        CustomId::DecisionModal {
            approve: false,
            request: rid,
        },
        CustomId::EditModal(rid),
        CustomId::TotpModal(rid),
        CustomId::RulesSelect { page: 2 },
        CustomId::RulesPage { target: -1 },
        CustomId::RulesToggle {
            page: 0,
            rule: RuleId::new(),
        },
        CustomId::RulesDelete {
            page: 0,
            rule: RuleId::new(),
        },
    ] {
        let text = id.render();
        assert!(text.len() <= 100, "{text}");
        assert_eq!(CustomId::parse(&text), Some(id));
    }
    assert_eq!(format!("aa:approve:{rid}"), CustomId::Approve(rid).render());
    assert_eq!(CustomId::parse("aa:approve:not-a-uuid"), None);
    assert_eq!(CustomId::parse(&format!("aa:approve:{rid}:x")), None);
    assert_eq!(
        CustomId::parse(&format!("aa:approve:{}", rid.to_string().to_uppercase())),
        None
    );
    assert_eq!(CustomId::parse(&format!("xx:approve:{rid}")), None);
}

#[test]
fn request_card() {
    let mut r = github();
    r.attempt = 2;
    let e = request_embed(&r, &agent("alice"), None, None);
    assert_eq!(e.title.as_deref(), Some("🐙 Access request: github/repo"));
    assert_eq!(e.description.as_deref(), Some("I need to push the fix"));
    assert_eq!(
        field(&e, "Agent"),
        "alice\nclaude · agent\\-auth · excelsior · VM"
    );
    assert_eq!(field(&e, "Resource"), "uorux/agent\\-auth");
    assert_eq!(field(&e, "Requested duration"), "1h");
    assert_eq!(
        field(&e, "Scope"),
        "```json\n{\n  \"permissions\": {\n    \"contents\": \"write\"\n  }\n}\n```"
    );
    assert_eq!(
        field(&e, "⚠️ Risk context"),
        "• first request for this repo"
    );
    assert_eq!(field(&e, "LLM attempt"), "2");
    assert!(e.footer.as_ref().unwrap().text.ends_with(&r.id.to_string()));
    assert_eq!(e.color, Some(0xF1C40F));

    r.status = RequestStatus::Granted;
    r.decided_by = Some("jrt".to_owned());
    r.approved_duration_secs = Some(7200);
    let g = grant(GrantStatus::Active);
    let e = apply_outcome(e, &r, Some(&g));
    assert_eq!(e.color, Some(COLOR_APPROVED));
    let expires = g.expires_at.unix_timestamp();
    assert_eq!(
        field(&e, "Outcome"),
        format!("✅ Approved by jrt for **2h** — expires <t:{expires}:R>")
    );
    let e = apply_grant_ended(e, &g);
    assert_eq!(e.color, Some(COLOR_ENDED));
    assert!(field(&e, "Revoked").ends_with(" — revoked by jrt"));

    let mut d = github();
    d.status = RequestStatus::Denied;
    d.decision_reason = Some("**no**".to_owned());
    let e = apply_outcome(request_embed(&d, &agent("a"), None, None), &d, None);
    assert_eq!(
        field(&e, "Outcome"),
        "⛔ Denied by policy\n> \\*\\*no\\*\\*"
    );
}

#[test]
fn a_card_cannot_be_spoofed() {
    let mut r = request(
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        "x` **Resource: fine**",
    );
    r.justification =
        "**✅ Approved by policy**\n[docs](https://evil.example) @everyone <@1>".to_owned();
    let e = request_embed(&r, &agent("alice"), None, None);
    let d = e.description.clone().unwrap();
    assert!(!d.contains("**") && !d.contains("[docs]") && !d.contains("@everyone"));
    assert!(d.contains("\\<@\u{200b}1\\>"), "{d}");
    assert_eq!(field(&e, "Resource"), "x\\` \\*\\*Resource\\: fine\\*\\*");

    // A scope value cannot close the fence.
    let mut m = Map::new();
    m.insert("topic".to_owned(), json!("```\n**pwned**\n```"));
    let (_, value) = scope_field(&m);
    assert_eq!(value.matches("```").count(), 2);

    // Delegation: the topic stays in its code span.
    let mut thread_owner = agent("orchestrator");
    thread_owner.name = "orch_1".to_owned();
    let topic = "`x` **y**";
    let thread = agent_auth_store::a2a::ThreadRow {
        id: agent_auth_core::ThreadId::new(),
        initiator_agent_id: thread_owner.id,
        initiator_session_id: None,
        responder_agent_id: AgentId::new(),
        responder_session_id: None,
        topic: Some(topic.to_owned()),
        grant_id: None,
        state: agent_auth_store::a2a::ThreadState::Open,
        accepted_at: None,
        closed_at: None,
        close_reason: None,
        closed_by: None,
        close_note: None,
        last_activity_at: T0,
        last_seq: 0,
        created_at: T0,
    };
    let e = request_embed(&r, &agent("alice"), Some(&thread_owner), Some(&thread));
    assert_eq!(
        field(&e, "🤝 On behalf of"),
        "**orch\\_1** (thread topic `ˋxˋ **y**`)"
    );
}

#[test]
fn long_scope_says_it_was_cut() {
    let mut m = Map::new();
    m.insert("permissions".to_owned(), json!("x".repeat(2000)));
    let (name, value) = scope_field(&m);
    assert!(name.starts_with("⚠️ Scope (too long to show"));
    assert!(value.chars().count() <= 1024);
}

#[test]
fn rule_applied_lines() {
    let a = agent("alice");
    let mut r = github();
    r.status = RequestStatus::Granted;
    r.decision_source = Some(DecisionSource::Policy);
    r.decision_reason = Some("the agent's own project's repo".to_owned());
    r.approved_duration_secs = Some(3600);
    let e = rule_applied_embed(&r, &a, None, None);
    let d = e.description.unwrap();
    assert!(
        d.contains("Policy auto-approved: **alice** → github/repo on `uorux/agent-auth`"),
        "{d}"
    );
    assert!(d.contains("by: the agent's own project's repo"));
    assert_eq!(e.color, Some(COLOR_APPROVED));

    r.decision_source = Some(DecisionSource::Llm);
    r.decision_reason = Some("narrow and **justified**".to_owned());
    let d = rule_applied_embed(&r, &a, None, None).description.unwrap();
    assert!(d.contains("LLM reviewer auto-approved"));
    assert!(d.contains("because: narrow and \\*\\*justified\\*\\*"));

    r.decision_source = Some(DecisionSource::Rule);
    let d = rule_applied_embed(&r, &a, None, None).description.unwrap();
    assert!(d.contains("since-deleted rule — manage with /rules"));
    let saved = rule(RuleAction::AutoApprove, true);
    let g = grant(GrantStatus::Active);
    let d = rule_applied_embed(&r, &a, Some(&saved), Some(&g))
        .description
        .unwrap();
    let prefix = &saved.id.to_string()[..8];
    assert!(d.contains(&format!(
        "by rule `{prefix}` (their own repos) — manage with /rules"
    )));
    assert!(d.contains(" for **1h** — expires <t:"));

    r.status = RequestStatus::Denied;
    let e = rule_applied_embed(&r, &a, Some(&saved), None);
    assert!(e.description.unwrap().contains("Rule auto-denied"));
}

#[test]
fn edit_modal_fields_and_limits() {
    let r = github();
    let m = edit_modal(&r).expect("fits");
    assert_eq!(m.title, "Edit & approve");
    assert_eq!(m.custom_id, format!("aa:editmodal:{}", r.id));
    assert_eq!(m.inputs.len(), 5);
    assert_eq!(m.inputs[0].value.as_deref(), Some("1h"));
    assert_eq!(m.inputs[1].value.as_deref(), Some("uorux/agent-auth"));
    assert_eq!(
        m.inputs[2].value.as_deref(),
        Some("{\"permissions\": {\"contents\": \"write\"}}")
    );
    let limits = |m: &super::model::Modal| {
        assert!(m.title.chars().count() <= 45);
        for i in &m.inputs {
            assert!(i.label.chars().count() <= 45, "{}", i.label);
            assert!(
                i.placeholder
                    .as_ref()
                    .is_none_or(|p| p.chars().count() <= 100)
            );
            let max = usize::from(i.max_length.unwrap_or(4000));
            assert!(i.value.as_ref().is_none_or(|v| v.chars().count() <= max));
        }
    };
    limits(&m);
    limits(&decision_modal(r.id, true));
    limits(&decision_modal(r.id, false));
    assert_eq!(decision_modal(r.id, false).inputs.len(), 1);

    // Bug-A2: too long to edit whole: no Edit modal at all.
    let long = request(
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        &"x".repeat(5000),
    );
    assert!(edit_modal(&long).is_none());

    let shell = request(
        Platform::Hostexec,
        "shell",
        json!({"tier": "root"}),
        "excelsior",
    );
    let t = totp_modal(&shell);
    assert_eq!(t.inputs.len(), 3);
    limits(&t);
    let run = request(
        Platform::Hostexec,
        "run",
        json!({"tier": "user", "argv": ["ls"]}),
        "a-host-with-a-really-long-name-indeed",
    );
    let t = totp_modal(&run);
    assert_eq!(t.inputs.len(), 2);
    limits(&t);
    assert_eq!(t.inputs[0].min_length, Some(6));
}

fn form(pairs: &[(&str, &str)]) -> Submitted {
    Submitted(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

#[test]
fn reading_modals() {
    let d = read_decision(true, &form(&[("reason", " fine "), ("duration", "4h")])).unwrap();
    assert!(d.approve);
    assert_eq!(d.reason, "fine");
    assert_eq!(d.duration_secs.map(DurationSecs::get), Some(14_400));
    assert_eq!(
        read_decision(true, &form(&[("duration", "4x")]))
            .unwrap_err()
            .0,
        "Invalid duration: invalid duration '4x': use e.g. '30m', '8h', '2d', or seconds"
    );
    // A deny ignores any duration.
    assert!(read_decision(false, &form(&[("duration", "4x")])).is_ok());

    let base = [
        ("duration", "2h"),
        ("resource", " uorux/x "),
        ("scope", ""),
        ("rule", ""),
        ("notes", "n"),
    ];
    let d = read_edit(&form(&base)).unwrap();
    assert!(d.approve && d.rule_action.is_none());
    assert_eq!(d.resource_override.as_deref(), Some("uorux/x"));
    assert_eq!(d.scope_override, None);

    let mut f = base;
    f[3] = ("rule", " DENY:platform ");
    let d = read_edit(&form(&f)).unwrap();
    assert!(!d.approve, "a deny rule also denies this request");
    assert_eq!(d.rule_action, Some(RuleAction::AutoDeny));
    assert_eq!(d.rule_resource_pattern.as_deref(), Some("*"));
    assert!(d.rule_any_authority);
    f[3] = ("rule", "approve:capability");
    let d = read_edit(&form(&f)).unwrap();
    assert_eq!(
        (d.rule_resource_pattern.as_deref(), d.rule_any_authority),
        (Some("*"), false)
    );
    f[3] = ("rule", "approve");
    assert_eq!(read_edit(&form(&f)).unwrap().rule_resource_pattern, None);
    for bad in ["approve:", "allow", "approve:exact:x", "deny:repo"] {
        f[3] = ("rule", bad);
        assert_eq!(
            read_edit(&form(&f)).unwrap_err().0,
            "Invalid rule: use approve|deny[:exact|:capability|:platform]"
        );
    }
    f[3] = ("rule", "");
    f[2] = ("scope", "[1]");
    assert_eq!(
        read_edit(&form(&f)).unwrap_err().0,
        "Invalid scope JSON: scope must be a JSON object"
    );
    f[2] = ("scope", "{nope");
    assert!(
        read_edit(&form(&f))
            .unwrap_err()
            .0
            .starts_with("Invalid scope JSON: ")
    );
    f[2] = ("scope", "{\"permissions\": {}}");
    assert!(read_edit(&form(&f)).unwrap().scope_override.is_some());

    let d = read_totp(&form(&[("code", " 123456 "), ("reason", "")])).unwrap();
    assert_eq!(d.totp.as_deref(), Some("123456"));
    assert!(d.approve);
}

#[test]
fn decided_texts() {
    let rid: RequestId = "12345678-aaaa-4bbb-8ccc-000000000000".parse().unwrap();
    let mut row = github();
    row.approved_duration_secs = Some(14_400);
    let approve = HumanDecision {
        approve: true,
        ..HumanDecision::default()
    };
    assert_eq!(
        decided_text(rid, &approve, &row),
        "Approved `12345678` for 4h."
    );
    let deny = HumanDecision {
        rule_action: Some(RuleAction::AutoDeny),
        ..HumanDecision::default()
    };
    assert_eq!(
        decided_text(rid, &deny, &row),
        "Denied `12345678` (rule saved — manage with /rules)."
    );
}

#[test]
fn views() {
    let r = github();
    let labels: Vec<_> = buttons(&pending_view(r.id))
        .into_iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(labels, ["Approve", "Deny", "Edit"]);
    assert!(
        buttons(&disabled_view())
            .iter()
            .all(|b| b.2 && b.1.is_none())
    );
    let shell = request(
        Platform::Hostexec,
        "shell",
        json!({"tier": "root"}),
        "excelsior",
    );
    let labels: Vec<_> = buttons(&hostexec_pending_view(&shell))
        .into_iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(labels, ["Approve with TOTP", "Deny"]);
    let run = request(
        Platform::Hostexec,
        "run",
        json!({"tier": "user", "argv": ["ls"]}),
        "excelsior",
    );
    let all = buttons(&hostexec_pending_view(&run));
    assert_eq!(
        all.iter().map(|b| b.0.as_str()).collect::<Vec<_>>(),
        [
            "Approve",
            "Approve all…",
            "Approve with TOTP",
            "Deny",
            "Edit"
        ]
    );
    assert!(
        all.iter()
            .all(|b| b.1.as_ref().is_some_and(|c| c.len() <= 100))
    );
    assert_eq!(
        buttons(&shell_view(r.id)),
        [(
            "End shell".to_owned(),
            Some(format!("aa:hxend:{}", r.id)),
            false
        )]
    );
}

#[test]
fn hostexec_cards() {
    let a = agent("alice");
    let run = request(
        Platform::Hostexec,
        "run",
        json!({"tier": "user", "argv": ["echo", "```", "**x**"]}),
        "excelsior",
    );
    let host = json!({"online": true, "tiers": {"user": {"enabled": true, "armed_until": 1_761_400_000.5}}});
    let e = hostexec_embed(&run, &a, None, None, Some(&host));
    assert_eq!(e.title.as_deref(), Some("🖥️ Run on excelsior as your user"));
    let cmd = field(&e, "Command");
    assert_eq!(cmd.matches("```").count(), 2, "{cmd}");
    assert_eq!(
        field(&e, "Host"),
        "🔓 user tier armed until <t:1761400000:t> — Approve works"
    );
    let root = request(
        Platform::Hostexec,
        "run",
        json!({"tier": "root", "argv": ["ls"]}),
        "excelsior",
    );
    let e = hostexec_embed(&root, &a, None, None, None);
    assert_eq!(e.title.as_deref(), Some("🖥️ Run on excelsior as ROOT"));
    assert_eq!(field(&e, "Host"), "⚫ offline");
    let shell = request(
        Platform::Hostexec,
        "shell",
        json!({"tier": "root"}),
        "excelsior",
    );
    let e = hostexec_embed(&shell, &a, None, None, Some(&host));
    assert_eq!(e.title.as_deref(), Some("🚨 ROOT SHELL on excelsior"));
    assert_eq!(field(&e, "For"), "1h");
    assert_eq!(
        field(&e, "Host"),
        "⛔ the root tier is not enabled on this host"
    );
    assert_eq!(
        host_line(
            Some(&json!({"online": true, "tiers": {"user": {"enabled": true}}})),
            "user",
            false
        ),
        "🔒 user tier not armed — Approve needs `/arm`; Approve with TOTP works now"
    );
}

#[test]
fn job_results() {
    let j = job(JobStatus::Done, Some(0), "hello\nworld");
    let f = result_field(&j);
    assert!(f.starts_with("✅ exit 0 in 1.2s"), "{f}");
    assert!(f.chars().count() <= 1024);
    assert!(output_file(&j).is_none());
    let big = job(JobStatus::Done, Some(1), &"line\n".repeat(400));
    assert!(result_field(&big).chars().count() <= 1024);
    assert!(output_file(&big).is_some_and(|f| f.name.starts_with("output-")));
    let mut refused = job(JobStatus::Refused, None, "");
    refused.error = Some("not armed".to_owned());
    assert_eq!(result_field(&refused), "⛔ refused by excelsior: not armed");
    assert!(output_file(&refused).is_none());

    assert_eq!(
        shell_command_text(&j),
        "$ ls -la\n# cwd: /tmp\n# env: A=1\n# env: B=2"
    );
}

fn page_of(n: usize, page: i64) -> Page {
    let all: Vec<RuleRow> = (0..n)
        .map(|i| {
            rule(
                if i % 2 == 0 {
                    RuleAction::AutoApprove
                } else {
                    RuleAction::AutoDeny
                },
                i != 1,
            )
        })
        .collect();
    paginate(all, page)
}

#[test]
fn rules_browser() {
    let p = page_of(3, 0);
    let e = rules_embed(&p);
    let d = e.description.unwrap();
    assert!(d.contains(&p.rules[0].id.to_string()[..8]));
    assert!(d.contains("contents:write"));
    assert!(d.contains("*(disabled)*"));
    assert!(e.footer.is_none());
    assert!(
        rules_embed(&page_of(0, 0))
            .description
            .unwrap()
            .starts_with("No rules")
    );

    let detail = rule_detail_embed(&p.rules[0]);
    for name in ["Agent", "Resource", "Max duration", "🤝 Delegator"] {
        field(&detail, name);
    }
    assert_eq!(field(&detail, "Max duration"), "2h");
    assert_eq!(detail.color, Some(COLOR_APPROVED));
    assert_eq!(rule_detail_embed(&p.rules[1]).color, Some(COLOR_ENDED));

    // 25 options, labels and descriptions within 100.
    let full = page_of(25, 0);
    let rows = rules_view(&full, None);
    assert_eq!(rows.len(), 1, "no selection: the select only");
    let Component::ActionRow(r) = &rows[0] else {
        panic!()
    };
    let Component::SelectMenu(s) = &r.components[0] else {
        panic!()
    };
    let options = s.options.as_ref().unwrap();
    assert_eq!(options.len(), 25);
    assert!(options.iter().all(|o| {
        o.label.chars().count() <= 100
            && o.description
                .as_ref()
                .is_some_and(|d| d.chars().count() <= 100)
    }));
    let selected = &full.rules[1];
    let labels: Vec<_> = buttons(&rules_view(&full, Some(selected)))
        .into_iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(labels, ["Enable", "Delete"]);
    let labels: Vec<_> = buttons(&rules_view(&full, Some(&full.rules[0])))
        .into_iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(labels, ["Disable", "Delete"]);

    // Pagination.
    let first = page_of(55, 0);
    let nav = buttons(&rules_view(&first, None));
    assert_eq!(nav[0].0, "◀ Prev");
    assert!(nav[0].2 && !nav[1].2);
    let last = page_of(55, 99);
    assert_eq!(last.page, 2);
    let nav = buttons(&rules_view(&last, None));
    assert!(!nav[0].2 && nav[1].2);
    let middle = page_of(55, 1);
    assert_eq!(
        rules_embed(&middle).footer.unwrap().text,
        "Page 2/3 · 55 rules, newest first"
    );
    let msg = render(&middle, Some(middle.rules[0].id));
    assert_eq!(msg.embeds.unwrap().len(), 2);
}

#[test]
fn owner_check() {
    assert!(DiscordOwner::check(0, 0, "x".to_owned()).is_none());
    assert!(DiscordOwner::check(OWNER, 7, "x".to_owned()).is_none());
    let o = DiscordOwner::check(OWNER, OWNER, "jrt".to_owned()).unwrap();
    assert_eq!(HumanDecider::from(&o).label(), "jrt");
}

#[test]
fn configuration() {
    let vars = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    };
    assert!(DiscordConfig::from_vars(vars(&[])).unwrap().is_none());
    let c = DiscordConfig::from_vars(vars(&[
        ("DISCORD_TOKEN", "t"),
        ("DISCORD_CHANNEL_ID", "5"),
        ("DISCORD_OWNER_ID", "42"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        (c.activity_channel(), c.loud_channel(), c.owner()),
        (5, 5, Some(42))
    );
    assert_eq!(
        (c.api_base.as_str(), c.gateway_url.as_str()),
        (super::rest::DISCORD_API, super::gateway::DISCORD_GATEWAY)
    );
    let c = DiscordConfig::from_vars(vars(&[
        ("DISCORD_TOKEN", "t"),
        ("DISCORD_API_URL", "http://127.0.0.1:9/api"),
        ("DISCORD_GATEWAY_URL", " ws://127.0.0.1:9 "),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        (c.api_base.as_str(), c.gateway_url.as_str()),
        ("http://127.0.0.1:9/api", "ws://127.0.0.1:9")
    );
    let secret = DiscordConfig::from_vars(vars(&[("DISCORD_TOKEN", "sekrit-token")]))
        .unwrap()
        .unwrap();
    assert!(!format!("{secret:?}").contains("sekrit"));
    let c = DiscordConfig::from_vars(vars(&[
        ("DISCORD_TOKEN", "t"),
        ("DISCORD_CHANNEL_ID", "5"),
        ("DISCORD_ACTIVITY_CHANNEL_ID", "6"),
        ("DISCORD_LOUD_CHANNEL_ID", "7"),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        (c.activity_channel(), c.loud_channel(), c.owner()),
        (6, 7, None)
    );
    assert!(
        DiscordConfig::from_vars(vars(&[("DISCORD_TOKEN", "t"), ("DISCORD_OWNER_ID", "me")]))
            .is_err()
    );
}

#[test]
fn containment_ping() {
    let event = json!({
        "id": "ab12cd34",
        "by": "codex_1",
        "reason": "**exfiltration** @everyone",
        "agents": ["a_1", "b"],
        "grants_revoked": 3,
        "threads_closed": 1,
        "daemons": {"vm-1": "frozen"},
        "evidence": "[link](https://x)",
    });
    let m = contained_message(&event, Some(OWNER));
    let text = m.content.unwrap();
    assert!(text.starts_with("<@42> 🛑 **Containment `ab12cd34`** by codex\\_1\n> \\*\\*exfiltration\\*\\* @\u{200b}everyone\n"));
    assert!(text.contains("Agents (2): a\\_1, b\n"));
    assert!(text.contains("Grants revoked: 3 · conversations closed: 1\n"));
    assert!(text.contains("Hosts/VMs: vm\\-1 frozen\n"));
    assert!(text.contains("Evidence:\n> \\[link\\]\\(https\\://x\\)\n"));
    assert!(
        text.ends_with(
            "Lift: `agent-auth admin contain-lift ab12cd34` (or /unlock for a lockdown)"
        )
    );
    let mentions = serde_json::to_value(m.allowed_mentions.unwrap()).unwrap();
    assert_eq!(mentions, json!({"parse": [], "users": ["42"]}));
    let none = contained_message(&json!({"id": "x"}), None)
        .content
        .unwrap();
    assert!(none.contains("Agents (0): none right now (new ones matching are held too)"));
}

#[test]
fn release_text() {
    let entry = |id: &str, source| ContainmentEntry {
        id: id.to_owned(),
        r#match: json!({}),
        reason: String::new(),
        evidence: String::new(),
        by: "jrt".to_owned(),
        source,
        at: T0,
    };
    use agent_auth_store::lockdown::ContainmentSource as S;
    assert_eq!(
        interactions::released_text(&[]),
        "Lifted: nothing was contained."
    );
    assert_eq!(
        interactions::released_text(&[entry("a", S::Operator), entry("b", S::Lockdown)]),
        "Lifted: `a`, `b`. A lockdown's hosts stay locked until /unlock with their codes."
    );
}

#[test]
fn modal_inputs_are_labels() {
    let v = serde_json::to_value(Input::new("code", "Code").component()).unwrap();
    assert_eq!(v["type"], 18);
    assert_eq!(v["label"], "Code");
    assert_eq!(v["component"]["type"], 4);
    assert_eq!(v["component"]["custom_id"], "code");
    assert!(v["component"].get("label").is_none());
}

proptest::proptest! {
    /// Parsers of what Discord (or anyone posing as a click) sends never
    /// panic, and only our exact custom ids parse.
    #[test]
    fn parsers_take_anything(s in "\\PC{0,120}|aa:[a-z]{0,10}:[-+0-9a-f:]{0,80}") {
        if let Some(id) = CustomId::parse(&s) {
            proptest::prop_assert_eq!(id.render(), s.clone());
        }
        let _ = super::gateway::parse_frame(&s);
    }
}

// ----------------------------------------------------- the fake Discord

#[derive(Debug, Clone)]
pub(super) struct Call {
    pub(super) method: Method,
    pub(super) path: String,
    pub(super) body: Value,
    pub(super) raw: String,
}

#[derive(Clone, Default)]
pub(super) struct Fake {
    pub(super) calls: Arc<Mutex<Vec<Call>>>,
    pub(super) rate_limit_once: Arc<AtomicBool>,
    /// Embeds a GET of a message returns.
    pub(super) embeds: Arc<Mutex<Value>>,
}

impl Fake {
    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

async fn fake_handler(State(f): State<Fake>, method: Method, uri: Uri, body: Bytes) -> Response {
    let raw = String::from_utf8_lossy(&body).into_owned();
    let path = uri.path().trim_start_matches("/api").to_owned();
    f.calls.lock().unwrap().push(Call {
        method: method.clone(),
        path: path.clone(),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        raw,
    });
    if f.rate_limit_once.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({"retry_after": 0.01, "global": false, "message": "slow down"})),
        )
            .into_response();
    }
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let body = match (method, parts.as_slice()) {
        (Method::GET, ["channels", c, "messages", m]) => {
            json!({"id": m, "channel_id": c, "embeds": f.embeds.lock().unwrap().clone()})
        }
        (Method::GET, ["channels", c]) => json!({"id": c, "guild_id": "77"}),
        (Method::POST, ["channels", _, "messages", _, "threads"]) => json!({"id": "555"}),
        (Method::POST, ["channels", c, "messages"]) => json!({"id": "900", "channel_id": c}),
        (Method::POST, ["interactions", ..]) => return StatusCode::NO_CONTENT.into_response(),
        _ => json!({"id": "901", "channel_id": "5"}),
    };
    axum::Json(body).into_response()
}

pub(super) async fn fake() -> (Fake, String) {
    let f = Fake::default();
    *f.embeds.lock().unwrap() = json!([]);
    let app = Router::new().fallback(fake_handler).with_state(f.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (f, format!("http://{addr}/api"))
}

pub(super) fn config(base: &str, owner: u64) -> DiscordConfig {
    DiscordConfig {
        token: Secret::new("test-token".to_owned()),
        channel_id: 5,
        owner_id: owner,
        loud_channel_id: 0,
        activity_channel_id: 6,
        api_base: base.to_owned(),
        gateway_url: "wss://127.0.0.1:1".to_owned(),
    }
}

pub(super) fn lazy_store() -> Store {
    Store::from_pool(
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap(),
    )
}

#[derive(Default)]
struct FakeOps {
    decisions: Mutex<Vec<(String, RequestId, HumanDecision)>>,
    refuse: Option<String>,
    contained: Mutex<Vec<(String, Value, String, bool)>>,
}

impl RequestOps for FakeOps {
    fn decide<'a>(
        &'a self,
        who: &'a HumanDecider,
        request: RequestId,
        decision: HumanDecision,
        approval: Option<agent_auth_core::HumanApproval>,
    ) -> BoxFuture<'a, Result<RequestRow, OpError>> {
        Box::pin(async move {
            assert_eq!(approval.is_some(), decision.approve);
            if let Some(a) = &approval {
                assert_eq!((a.request(), a.decided_by()), (request, who.label()));
            }
            self.decisions.lock().unwrap().push((
                who.label().to_owned(),
                request,
                decision.clone(),
            ));
            if let Some(e) = &self.refuse {
                return Err(OpError(e.clone()));
            }
            let mut row = github();
            row.id = request;
            row.approved_duration_secs = decision.duration_secs.map(DurationSecs::get);
            Ok(row)
        })
    }

    fn revoke_grant<'a>(
        &'a self,
        _: &'a HumanDecider,
        _: GrantId,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), OpError>> {
        Box::pin(async { Ok(()) })
    }
}

impl ContainmentOps for FakeOps {
    fn contain<'a>(
        &'a self,
        who: &'a HumanDecider,
        m: Value,
        reason: &'a str,
        allow_all: bool,
    ) -> BoxFuture<'a, Result<Contained, OpError>> {
        Box::pin(async move {
            self.contained.lock().unwrap().push((
                who.label().to_owned(),
                m,
                reason.to_owned(),
                allow_all,
            ));
            Ok(Contained {
                id: "abcd1234".to_owned(),
                agents: 2,
                grants_revoked: 3,
            })
        })
    }

    fn lift<'a>(
        &'a self,
        _: &'a HumanDecider,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ContainmentEntry>, OpError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn bot_with(base: &str, owner: u64, store: Store, ops: &Arc<FakeOps>) -> Discord {
    let d = Discord::new(config(base, owner), store).unwrap();
    let requests: Arc<dyn RequestOps> = ops.clone();
    let containment: Arc<dyn ContainmentOps> = ops.clone();
    d.attach(Services {
        requests: Some(requests),
        containment: Some(containment),
        hosts: None,
        app: None,
        mail: None,
    });
    d
}

pub(super) fn interaction(kind: u8, user: u64, data: Value) -> Interaction {
    serde_json::from_value(json!({
        "id": "10",
        "application_id": "20",
        "type": kind,
        "token": "itok",
        "channel_id": "5",
        "data": data,
        "user": {"id": user.to_string(), "username": "jrt", "discriminator": "0", "avatar": null},
        "entitlements": [],
        "authorizing_integration_owners": {},
        "version": 1,
        "locale": "en-US",
    }))
    .expect("interaction")
}

pub(super) fn button_click(user: u64, custom_id: &str) -> Interaction {
    interaction(
        3,
        user,
        json!({"custom_id": custom_id, "component_type": 2}),
    )
}

pub(super) fn modal_submit(user: u64, custom_id: &str, fields: &[(&str, &str)]) -> Interaction {
    let components: Vec<Value> = fields
        .iter()
        .enumerate()
        .map(|(i, (k, v))| json!({"type": 18, "id": i, "component": {"type": 4, "id": i + 10, "custom_id": k, "value": v}}))
        .collect();
    interaction(
        5,
        user,
        json!({"custom_id": custom_id, "components": components}),
    )
}

pub(super) fn command(user: u64, name: &str, options: Value) -> Interaction {
    interaction(
        2,
        user,
        json!({"id": "30", "name": name, "type": 1, "options": options}),
    )
}

pub(super) const CALLBACK: &str = "/interactions/10/itok/callback";
pub(super) const FOLLOWUP: &str = "/webhooks/20/itok";

pub(super) fn ephemeral_reply(c: &Call) -> &str {
    assert_eq!(c.path, CALLBACK);
    assert_eq!(c.body["type"], 4);
    assert_eq!(c.body["data"]["flags"], 64);
    c.body["data"]["content"].as_str().unwrap()
}

#[tokio::test]
async fn only_the_owner_acts() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps::default());
    let rid = RequestId::new();
    for owner in [OWNER, 0] {
        let bot = bot_with(&base, owner, lazy_store(), &ops);
        bot.handle(button_click(7, &format!("aa:approve:{rid}")))
            .await;
        // A modal submission is checked again (INV-A2).
        bot.handle(modal_submit(
            7,
            &format!("aa:decision:approve:{rid}"),
            &[("reason", "")],
        ))
        .await;
        bot.handle(command(7, "contain", json!([{"name": "reason", "type": 3, "value": "x"}, {"name": "everyone", "type": 5, "value": true}]))).await;
    }
    let calls = f.calls();
    assert_eq!(calls.len(), 6);
    for c in &calls {
        assert_eq!(ephemeral_reply(c), interactions::NOT_OWNER);
    }
    assert!(ops.decisions.lock().unwrap().is_empty());
    assert!(ops.contained.lock().unwrap().is_empty());
    // The token never reaches the fake in a body, and the Authorization
    // header is the bot's.
    assert!(calls.iter().all(|c| !c.raw.contains("test-token")));
}

#[tokio::test]
async fn approve_opens_the_decision_modal() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    let rid = RequestId::new();
    bot.handle(button_click(OWNER, &format!("aa:approve:{rid}")))
        .await;
    bot.handle(button_click(OWNER, &format!("aa:deny:{rid}")))
        .await;
    let calls = f.calls();
    assert_eq!(calls[0].body["type"], 9);
    let data = &calls[0].body["data"];
    assert_eq!(data["custom_id"], format!("aa:decision:approve:{rid}"));
    assert_eq!(data["title"], "Approve request");
    assert_eq!(data["components"].as_array().unwrap().len(), 2);
    assert_eq!(
        data["components"][1]["label"],
        "Duration (blank = requested, capped)"
    );
    assert_eq!(
        calls[1].body["data"]["custom_id"],
        format!("aa:decision:deny:{rid}")
    );
    assert_eq!(
        calls[1].body["data"]["components"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_decision_goes_through_the_service() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    let rid: RequestId = "12345678-aaaa-4bbb-8ccc-000000000000".parse().unwrap();
    bot.handle(modal_submit(
        OWNER,
        &format!("aa:decision:approve:{rid}"),
        &[("reason", " looks fine "), ("duration", "4h")],
    ))
    .await;
    bot.handle(modal_submit(
        OWNER,
        &format!("aa:decision:approve:{rid}"),
        &[("duration", "soon")],
    ))
    .await;
    bot.handle(modal_submit(
        OWNER,
        &format!("aa:hxtotpm:{rid}"),
        &[("code", "654321"), ("reason", "")],
    ))
    .await;
    let calls = f.calls();
    let paths: Vec<_> = calls.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        [CALLBACK, FOLLOWUP, CALLBACK, FOLLOWUP, CALLBACK, FOLLOWUP]
    );
    assert_eq!(calls[0].body, json!({"type": 5, "data": {"flags": 64}}));
    assert_eq!(calls[1].body["content"], "Approved `12345678` for 4h.");
    assert_eq!(calls[1].body["flags"], 64);
    assert_eq!(
        calls[3].body["content"],
        "Invalid duration: invalid duration 'soon': use e.g. '30m', '8h', '2d', or seconds"
    );
    let decisions = ops.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "the bad duration never reached the service"
    );
    let (who, id, d) = &decisions[0];
    assert_eq!((who.as_str(), *id), ("jrt", rid));
    assert!(d.approve);
    assert_eq!(d.reason, "looks fine");
    assert_eq!(d.duration_secs.map(DurationSecs::get), Some(14_400));
    assert_eq!(decisions[1].2.totp.as_deref(), Some("654321"));
}

#[tokio::test]
async fn a_refused_decision_says_why() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps {
        refuse: Some("request already resolved (status denied)".to_owned()),
        ..FakeOps::default()
    });
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    let rid = RequestId::new();
    bot.handle(modal_submit(
        OWNER,
        &format!("aa:decision:deny:{rid}"),
        &[("reason", "no")],
    ))
    .await;
    let calls = f.calls();
    assert_eq!(
        calls[1].body["content"],
        "Could not apply decision: request already resolved (status denied)"
    );
    assert!(!ops.decisions.lock().unwrap()[0].2.approve);
}

#[tokio::test]
async fn contain_command() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    bot.handle(command(
        OWNER,
        "contain",
        json!([{"name": "reason", "type": 3, "value": "why"}]),
    ))
    .await;
    bot.handle(command(
        OWNER,
        "contain",
        json!([
            {"name": "reason", "type": 3, "value": "leaking"},
            {"name": "project", "type": 3, "value": "food"},
        ]),
    ))
    .await;
    let unset = Discord::new(config(&base, OWNER), lazy_store()).unwrap();
    unset
        .handle(command(
            OWNER,
            "contain",
            json!([{"name": "reason", "type": 3, "value": "x"}]),
        ))
        .await;
    let calls = f.calls();
    assert_eq!(
        ephemeral_reply(&calls[0]),
        "Say which agents (name, project, host, runtime), or everyone:True."
    );
    assert_eq!(calls[1].body["type"], 5);
    assert_eq!(
        calls[2].body["content"],
        "Contained `abcd1234`: 2 agent(s), 3 grant(s) revoked."
    );
    assert_eq!(ephemeral_reply(&calls[3]), interactions::NO_CONTAINMENT);
    let contained = ops.contained.lock().unwrap();
    assert_eq!(
        contained[0],
        (
            "jrt".to_owned(),
            json!({"project": "food"}),
            "leaking".to_owned(),
            false
        )
    );
}

#[tokio::test]
async fn notifications_ping_only_the_owner() {
    let (f, base) = fake().await;
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    let n = bot.notifier();
    let a = agent("alice");
    n.attention(&a, "look **here** @everyone", "low", &["desk-1".to_owned()])
        .await;
    n.attention(&a, "now", "high", &[]).await;
    let mut r = github();
    r.status = RequestStatus::Granted;
    r.decision_source = Some(DecisionSource::Policy);
    n.rule_applied(&r, &a, None, None).await;
    let calls = f.calls();
    assert_eq!(calls[0].path, "/channels/5/messages");
    assert_eq!(
        calls[0].body["content"],
        "🔔 **alice** wants your attention (shown on desk\\-1):\n> look \\*\\*here\\*\\* @\u{200b}everyone"
    );
    assert_eq!(calls[0].body["allowed_mentions"], json!({"parse": []}));
    assert_eq!(
        calls[1].body["content"],
        "<@42> 🔔 **alice** wants your attention:\n> now"
    );
    assert_eq!(
        calls[1].body["allowed_mentions"],
        json!({"parse": [], "users": ["42"]})
    );
    // The activity channel.
    assert_eq!(calls[2].path, "/channels/6/messages");
    assert!(
        calls[2].body["embeds"][0]["description"]
            .as_str()
            .unwrap()
            .contains("Policy auto-approved")
    );
}

#[tokio::test]
async fn rate_limits_are_waited_out() {
    let (f, base) = fake().await;
    f.rate_limit_once.store(true, Ordering::SeqCst);
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, lazy_store(), &ops);
    bot.notifier()
        .attention(&agent("a"), "x", "low", &["d".to_owned()])
        .await;
    let calls = f.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].raw, calls[1].raw);
}

#[tokio::test]
async fn a_dead_discord_never_fails_the_caller() {
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with("http://127.0.0.1:1/api", OWNER, lazy_store(), &ops);
    let n = bot.notifier();
    n.attention(&agent("a"), "x", "low", &[]).await;
    n.contained(&json!({"id": "x"})).await;
    let mut j = job(JobStatus::Running, None, "");
    j.shell_id = Some(RequestId::new());
    // A shell command that cannot be shown does not run.
    assert!(!n.shell_command(&github(), &j).await);
}

// ------------------------------------------------- with a real database

async fn insert_request(
    store: &Store,
    platform: Platform,
    cap: &str,
    scope: Value,
    resource: &str,
) -> (AgentRow, RequestRow) {
    let tx = store.begin().await.unwrap();
    let a = agents::insert(
        &tx,
        &agents::NewAgent {
            id: AgentId::new(),
            name: "alice",
            description: "",
            key_id: "aaaaaaaaaaaa",
            api_key_hash: "0000000000000000000000000000000000000000000000000000000000000000",
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: None,
            project: None,
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: T0,
        },
    )
    .await
    .unwrap();
    let auth = authority(platform, cap, &scope);
    let r = requests::insert(
        &tx,
        &requests::NewRequest {
            id: RequestId::new(),
            agent_id: a.id,
            session_id: None,
            delegation: None,
            platform,
            resource,
            requested_capability: cap,
            requested_scope: &scope,
            authority: Some(&auth),
            justification: "because",
            requested_duration_secs: 3600,
            risk_notes: &[],
            now: T0,
        },
    )
    .await
    .unwrap()
    .into_row();
    tx.commit().await.unwrap();
    (a, r)
}

async fn refs(store: &Store, id: RequestId) -> DiscordRefs {
    let tx = store.begin().await.unwrap();
    let r = requests::get(&tx, id).await.unwrap().unwrap().into_row();
    tx.commit().await.unwrap();
    r.discord
}

#[sqlx::test(migrations = "../store/migrations")]
async fn surfacing_a_request(pool: sqlx::PgPool) {
    let (f, base) = fake().await;
    let store = Store::from_pool(pool);
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, store.clone(), &ops);
    let (a, r) = insert_request(
        &store,
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        "uorux/x",
    )
    .await;
    bot.notifier().surface(&r, &a).await;
    let calls = f.calls();
    assert_eq!(calls.len(), 1);
    let body = &calls[0].body;
    assert_eq!(calls[0].path, "/channels/5/messages");
    assert_eq!(body["content"], "<@42> access request from **alice**");
    assert_eq!(
        body["allowed_mentions"],
        json!({"parse": [], "users": ["42"]})
    );
    assert_eq!(body["embeds"][0]["title"], "🐙 Access request: github/repo");
    assert_eq!(
        body["components"][0]["components"][0]["custom_id"],
        format!("aa:approve:{}", r.id)
    );
    assert_eq!(
        refs(&store, r.id).await,
        DiscordRefs {
            channel_id: Some(5),
            message_id: Some(900),
            thread_id: None
        }
    );

    // The outcome edits the card (its embed read back) and greys the buttons.
    *f.embeds.lock().unwrap() = body["embeds"].clone();
    let mut decided = r.clone();
    decided.status = RequestStatus::Denied;
    decided.decided_by = Some("jrt".to_owned());
    bot.notifier().update_outcome(&decided, None).await;
    let calls = f.calls();
    assert_eq!(calls[1].method, Method::GET);
    assert_eq!(calls[2].method, Method::PATCH);
    assert_eq!(calls[2].path, "/channels/5/messages/900");
    let fields = calls[2].body["embeds"][0]["fields"].as_array().unwrap();
    assert_eq!(fields.last().unwrap()["value"], "⛔ Denied by jrt");
    assert_eq!(
        calls[2].body["components"][0]["components"][0]["disabled"],
        true
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn edit_button_reads_the_request(pool: sqlx::PgPool) {
    let (f, base) = fake().await;
    let store = Store::from_pool(pool);
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, store.clone(), &ops);
    let (_, r) = insert_request(
        &store,
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        "uorux/x",
    )
    .await;
    bot.handle(button_click(OWNER, &format!("aa:edit:{}", r.id)))
        .await;
    bot.handle(button_click(
        OWNER,
        &format!("aa:edit:{}", RequestId::new()),
    ))
    .await;
    let calls = f.calls();
    assert_eq!(calls[0].body["type"], 9);
    assert_eq!(calls[0].body["data"]["title"], "Edit & approve");
    assert_eq!(
        calls[0].body["data"]["components"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        calls[0].body["data"]["components"][1]["component"]["value"],
        "uorux/x"
    );
    assert_eq!(ephemeral_reply(&calls[1]), interactions::GONE);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn rules_browser_round_trip(pool: sqlx::PgPool) {
    let (f, base) = fake().await;
    let store = Store::from_pool(pool);
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, store.clone(), &ops);
    let tx = store.begin().await.unwrap();
    let saved = rule_store::insert(
        &tx,
        &rule_store::NewRule {
            id: RuleId::new(),
            action: RuleAction::AutoApprove,
            agent_pattern: "alice",
            delegator_pattern: None,
            platform: Platform::Homelab,
            resource_pattern: "media",
            authority: None,
            max_duration_secs: None,
            created_by: "jrt",
            notes: "",
            expires_at: None,
            now: T0,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    bot.handle(command(OWNER, "rules", json!([]))).await;
    bot.handle(interaction(
        3,
        OWNER,
        json!({"custom_id": "aa:rules:sel:0", "component_type": 3, "values": [saved.id.to_string()]}),
    ))
    .await;
    bot.handle(button_click(
        OWNER,
        &format!("aa:rules:toggle:0:{}", saved.id),
    ))
    .await;
    bot.handle(button_click(OWNER, &format!("aa:rules:del:0:{}", saved.id)))
        .await;
    let calls = f.calls();
    assert_eq!(calls[0].body["type"], 4);
    assert_eq!(calls[0].body["data"]["flags"], 64);
    assert_eq!(
        calls[0].body["data"]["embeds"][0]["title"],
        "🧾 Decision rules"
    );
    assert_eq!(calls[1].body["type"], 7);
    assert_eq!(calls[1].body["data"]["embeds"].as_array().unwrap().len(), 2);
    let toggled = &calls[2].body["data"];
    assert!(
        toggled["embeds"][0]["description"]
            .as_str()
            .unwrap()
            .contains("*(disabled)*")
    );
    assert_eq!(
        calls[3].body["data"]["embeds"][0]["description"],
        "No rules yet. Create one from a request's **Edit** dialogue."
    );
    let tx = store.begin().await.unwrap();
    assert!(rule_store::get(&tx, saved.id).await.unwrap().is_none());
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../store/migrations")]
async fn shell_commands_are_shown_before_they_run(pool: sqlx::PgPool) {
    let (f, base) = fake().await;
    let store = Store::from_pool(pool);
    let ops = Arc::new(FakeOps::default());
    let bot = bot_with(&base, OWNER, store.clone(), &ops);
    let (a, r) = insert_request(
        &store,
        Platform::Hostexec,
        "shell",
        json!({"tier": "user"}),
        "excelsior",
    )
    .await;
    let mut j = job(JobStatus::Starting, None, "");
    j.shell_id = Some(r.id);
    // No approval message: cannot be shown, so it must not run.
    assert!(!bot.notifier().shell_command(&r, &j).await);
    bot.notifier().surface(&r, &a).await;
    assert!(bot.notifier().shell_command(&r, &j).await);
    assert!(bot.notifier().shell_command(&r, &j).await);
    let calls = f.calls();
    let paths: Vec<_> = calls
        .iter()
        .map(|c| (c.method.as_str().to_owned(), c.path.clone()))
        .collect();
    assert_eq!(
        paths,
        [
            ("POST".to_owned(), "/channels/5/messages".to_owned()),
            (
                "POST".to_owned(),
                "/channels/5/messages/900/threads".to_owned()
            ),
            ("POST".to_owned(), "/channels/555/messages".to_owned()),
            ("POST".to_owned(), "/channels/555/messages".to_owned()),
        ]
    );
    assert_eq!(
        calls[0].body["content"],
        "<@42> 🚨 **SHELL request** (user on excelsior) from **alice**"
    );
    let buttons: Vec<_> = calls[0].body["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["label"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(buttons, ["Approve with TOTP", "Deny"]);
    assert_eq!(calls[1].body["name"], "shell · user on excelsior");
    assert_eq!(
        calls[2].body["content"],
        "```\n$ ls -la\n# cwd: /tmp\n# env: A=1\n# env: B=2\n```"
    );
    assert_eq!(refs(&store, r.id).await.thread_id, Some(555));
}
