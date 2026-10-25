//! The hostexec side of the bot: rendering as pure functions, and the
//! commands and buttons against a fake Discord, a broker with the daemon
//! part and a real hostd (`daemons::testkit`).
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use agent_auth_core::durations::DurationSecs;
use agent_auth_core::{AgentId, JobId, Platform, RequestId, RequestStatus, RuleId, Tier};
use agent_auth_store::daemons::DaemonRole;
use agent_auth_store::hostexec::{JobRow, JobStatus};
use agent_auth_store::lockdown::{ContainmentEntry, ContainmentSource};
use agent_auth_wire::admin::{LockdownResult, LockdownScope, UnlockResult};
use agent_auth_wire::common::TierName;
use agent_auth_wire::daemon::host::{DesktopStatus, HostStatus, TierStatus};
use axum::http::Method;
use serde_json::{Map, Value, json};
use time::macros::datetime;
use twilight_model::channel::message::Embed;

use super::embeds::hostexec_embed;
use super::hostexec::*;
use super::interactions;
use super::notifier::shell_command_text;
use super::tests::{
    CALLBACK, FOLLOWUP, OWNER, button_click, command, config, ephemeral_reply, fake, interaction,
    lazy_store, modal_submit,
};
use super::views::{CustomId, Submitted, read_window, window_modal};
use super::{Discord, Services};
use crate::daemons::testkit::{Broker, HOST, Host, caller};

fn field<'a>(e: &'a Embed, name: &str) -> &'a str {
    &e.fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .value
}

fn line(name: &str, role: DaemonRole, online: bool, status: HostStatus) -> DaemonLine {
    DaemonLine {
        name: name.to_owned(),
        role,
        online,
        version: Some("0.1.0".to_owned()),
        last_seen_at: Some(datetime!(2026-10-25 12:00 UTC)),
        fingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz".to_owned(),
        status,
    }
}

#[test]
fn hosts_list() {
    let mut tiers = BTreeMap::new();
    tiers.insert(
        TierName::User,
        TierStatus {
            enabled: true,
            armed_until: Some(1_761_400_000.7),
            ..TierStatus::default()
        },
    );
    tiers.insert(
        TierName::Root,
        TierStatus {
            enabled: true,
            ..TierStatus::default()
        },
    );
    let status = HostStatus {
        role: Some("host".to_owned()),
        tiers,
        jobs: 2,
        lockdown: true,
        desktop: Some(DesktopStatus {
            present: true,
            ..DesktopStatus::default()
        }),
        ..HostStatus::default()
    };
    let e = hosts_embed(&[
        line("excelsior", DaemonRole::Host, true, status),
        line("vm-1", DaemonRole::Sandbox, false, HostStatus::default()),
    ]);
    assert_eq!(e.title.as_deref(), Some("Hosts"));
    let d = e.description.unwrap();
    let ts = datetime!(2026-10-25 12:00 UTC).unix_timestamp();
    assert_eq!(
        d,
        format!(
            "🟢 online **excelsior** (host) · v0.1.0 · last seen <t:{ts}:R> · `SHA256:abcdefghijkl`\n\
             \u{3000}⛔ locked down · user 🔓 until <t:1761400000:t> · root 🔒 · 2 job(s) · 🧑‍💻 at the desk\n\
             ⚫ offline **vm\\-1** (sandbox) · v0.1.0 · last seen <t:{ts}:R> · `SHA256:abcdefghijkl`"
        )
    );
    assert_eq!(e.footer.unwrap().text, "1/2 online");
    let empty = hosts_embed(&[]);
    assert_eq!(
        empty.description.as_deref(),
        Some("No paired daemons. Pair one with `agent-auth admin daemon-pair`.")
    );
    assert_eq!(empty.footer.unwrap().text, "0/0 online");
}

#[test]
fn lockdown_and_unlock_texts() {
    let mut daemons = BTreeMap::new();
    daemons.insert(
        "host:excelsior".to_owned(),
        "locked · vm **frozen**".to_owned(),
    );
    let out = LockdownResult {
        scope: LockdownScope::Host,
        host: Some("excelsior".to_owned()),
        daemons,
        grants_revoked: 3,
        requests_denied: 1,
        threads_closed: 2,
    };
    let e = lockdown_embed(LockdownScope::Host, Some("excelsior"), &out);
    assert_eq!(e.title.as_deref(), Some("⛔ LOCKDOWN (host excelsior)"));
    let d = e.description.unwrap();
    assert!(d.starts_with(
        "3 grant(s) revoked, 2 thread(s) closed.\n• `host:excelsior`: locked · vm \\*\\*frozen\\*\\*\n\n`/unlock` lifts"
    ));
    let none = lockdown_embed(
        LockdownScope::Sandboxes,
        None,
        &LockdownResult {
            scope: LockdownScope::Sandboxes,
            host: None,
            daemons: BTreeMap::new(),
            grants_revoked: 0,
            requests_denied: 0,
            threads_closed: 0,
        },
    );
    assert_eq!(none.title.as_deref(), Some("⛔ LOCKDOWN (sandboxes)"));
    assert!(none.description.unwrap().contains("• no daemons paired"));

    let mut unlocked = UnlockResult {
        host: None,
        daemons: BTreeMap::new(),
        broker_locked: Vec::new(),
    };
    assert_eq!(
        unlocked_text(None, false, &unlocked),
        "Unlocked: the broker only. Hosts stay locked until they get their own code."
    );
    unlocked
        .daemons
        .insert("host:excelsior".to_owned(), "unlocked".to_owned());
    unlocked.broker_locked = vec!["excelsior".to_owned()];
    assert_eq!(
        unlocked_text(Some("excelsior"), true, &unlocked),
        "Unlocked: `host:excelsior`. The broker is still locked (`/unlock` without a host lifts that)."
    );

    let mut out = Map::new();
    out.insert("armed_until".to_owned(), json!(1_761_400_000.9));
    assert_eq!(
        armed_text("excelsior", Tier::Root, &out),
        "🔓 **excelsior** root tier armed until <t:1761400000:t>."
    );
}

fn hostexec_request(cap: &str, scope: Value) -> agent_auth_store::requests::RequestRow {
    let Value::Object(m) = &scope else { panic!() };
    let authority = agent_auth_core::Authority::from_wire(Platform::Hostexec, cap, m).unwrap();
    agent_auth_store::requests::RequestRow {
        id: RequestId::new(),
        agent_id: AgentId::new(),
        session_id: None,
        delegation: None,
        platform: Platform::Hostexec,
        resource: "excelsior".to_owned(),
        requested_capability: cap.to_owned(),
        requested_scope: scope,
        authority: Some(authority),
        justification: "deploy".to_owned(),
        requested_duration_secs: 3600,
        risk_notes: Vec::new(),
        status: RequestStatus::AwaitingHuman,
        attempt: 1,
        decision_source: None,
        decided_by: None,
        decision_reason: None,
        approved_duration_secs: None,
        approved_edit: None,
        decided_at: None,
        discord: Default::default(),
        created_at: datetime!(2026-10-25 12:00 UTC),
        updated_at: datetime!(2026-10-25 12:00 UTC),
    }
}

#[test]
fn hostexec_card_is_display_safe() {
    let long_arg = format!("{}TAIL", "x".repeat(2000));
    let r = hostexec_request(
        "run",
        json!({
            "tier": "user",
            "argv": ["sh", "-c", "echo ok\rrm -rf ~", long_arg],
            "cwd": "/srv/a\u{202e}b",
            "env": {"LANG": "C\u{200b}\nX=1"},
            "stdin": "line one\nfake\u{202e}line\r\n",
        }),
    );
    let mut agent = super::tests::agent("alice");
    agent.project = None;
    let e = hostexec_embed(&r, &agent, None, None, None);
    let cmd = field(&e, "Command");
    // Head and tail of a long command, the \r shown, the fence intact.
    assert!(cmd.starts_with("```\nsh -c $'echo ok\\rrm -rf ~'"), "{cmd}");
    assert!(cmd.contains("\n…\n") && cmd.ends_with("TAIL\n```"), "{cmd}");
    assert_eq!(cmd.matches("```").count(), 2);
    assert_eq!(field(&e, "cwd"), "```\n/srv/a\\u202eb\n```");
    assert_eq!(field(&e, "env"), "```\nLANG=$'C\\u200b\\nX=1'\n```");
    assert_eq!(
        field(&e, "stdin (20 chars)"),
        "```\nline one\nfake\\u202eline\\r\n\n```"
    );
}

#[test]
fn shell_mirror_is_whole_and_display_safe() {
    let job = JobRow {
        id: JobId::new(),
        grant_id: None,
        request_id: RequestId::new(),
        agent_id: AgentId::new(),
        host: HOST.to_owned(),
        tier: Tier::User,
        shell_id: Some(RequestId::new()),
        spec: json!({"argv": ["bash"], "env": {"B": "two words", "A": "1"}, "stdin": "echo hi\u{202e}\nrm x\n"}),
        status: JobStatus::Starting,
        via: None,
        exit_code: None,
        error: None,
        output: None,
        output_bytes: None,
        output_sha256: None,
        truncated: false,
        duration_ms: None,
        finished_at: None,
        created_at: datetime!(2026-10-25 12:00 UTC),
        updated_at: datetime!(2026-10-25 12:00 UTC),
    };
    assert_eq!(
        shell_command_text(&job),
        "$ bash\n# env: A=1\n# env: B='two words'\n# stdin (14 chars):\necho hi\\u202e\nrm x\n"
    );
}

#[test]
fn window_modal_and_limit() {
    let r = hostexec_request("run", json!({"tier": "user", "argv": ["ls"]}));
    let m = window_modal(&r, "30m");
    assert_eq!(m.title, "Approve all for a while");
    assert_eq!(m.custom_id, format!("aa:hxallm:{}", r.id));
    assert_eq!(m.inputs.len(), 1);
    assert_eq!(m.inputs[0].label, "user commands on excelsior, for");
    assert_eq!(m.inputs[0].value.as_deref(), Some("30m"));
    let max = DurationSecs::parse("8h").unwrap();
    let form = |d: &str| Submitted(vec![("duration".to_owned(), d.to_owned())]);
    assert_eq!(read_window(&form("2h"), max).unwrap().get(), 7200);
    assert_eq!(
        read_window(&form("9h"), max).unwrap_err().0,
        "A window lasts at most 8h."
    );
    assert!(
        read_window(&form("soon"), max)
            .unwrap_err()
            .0
            .starts_with("Invalid duration: ")
    );
    assert_eq!(
        window_text(
            DurationSecs::parse("1h").unwrap(),
            "claude_1",
            "user",
            "excelsior",
            "12345678-aaaa-4bbb-8ccc-000000000000"
                .parse::<RuleId>()
                .unwrap(),
            2
        ),
        "Window open for 1h: **claude\\_1** may run user commands on **excelsior** without asking \
         (rule `12345678`, /rules to end it early). Approved now: 2."
    );
}

#[test]
fn kill_vm_ids() {
    let host = "a".repeat(63);
    for id in [
        CustomId::KillVms {
            scope: LockdownScope::Host,
            host: Some(host),
        },
        CustomId::KillVms {
            scope: LockdownScope::Sandboxes,
            host: None,
        },
        CustomId::ApproveAll(RequestId::new()),
        CustomId::WindowModal(RequestId::new()),
    ] {
        let text = id.render();
        assert!(text.len() <= 100, "{text}");
        assert_eq!(CustomId::parse(&text), Some(id));
    }
    assert_eq!(CustomId::parse("aa:hxkill:host:Not_A_Host"), None);
    assert_eq!(CustomId::parse("aa:hxkill:everything:"), None);
}

#[test]
fn release_needs_an_entry_or_all() {
    let entry = ContainmentEntry {
        id: "ab12cd34".to_owned(),
        r#match: json!({"project": "food"}),
        reason: "leak".to_owned(),
        evidence: String::new(),
        by: "jrt".to_owned(),
        source: ContainmentSource::Operator,
        at: datetime!(2026-10-25 12:00 UTC),
    };
    let how =
        "Say which: `/release entry:<id>` lifts one, `/release all:True` lifts every containment.";
    assert_eq!(
        interactions::release_help(&[]),
        format!("Nothing is contained. {how}")
    );
    let text = interactions::release_help(&[entry]);
    assert!(text.starts_with(&format!("{how}\n• `ab12cd34` ")), "{text}");
}

#[test]
fn command_definitions() {
    let defs = super::commands::definitions();
    let names: Vec<&str> = defs
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "rules",
            "contain",
            "contained",
            "release",
            "hosts",
            "arm",
            "disarm",
            "lockdown",
            "unlock",
            "review",
            "dnd"
        ]
    );
    for c in defs.as_array().unwrap() {
        assert!(c["description"].as_str().unwrap().chars().count() <= 100);
        for o in c["options"].as_array().into_iter().flatten() {
            assert!(o["description"].as_str().unwrap().chars().count() <= 100);
        }
    }
    let release = &defs[3]["options"];
    assert_eq!(
        release[1],
        json!({"type": 5, "name": "all", "description": "lift every containment"})
    );
}

// ------------------------------------------- against a broker and a hostd

fn bot(base: &str, b: Option<&Broker>) -> Discord {
    let store = b.map_or_else(lazy_store, |b| b.st.store.clone());
    let d = Discord::new(config(base, OWNER), store).unwrap();
    d.attach(Services {
        app: b.map(|b| b.st.clone()),
        ..Services::default()
    });
    d
}

fn opt(name: &str, value: Value) -> Value {
    let kind = if value.is_boolean() { 5 } else { 3 };
    json!({"name": name, "type": kind, "value": value})
}

async fn followups(f: &super::tests::Fake, from: usize) -> Vec<Value> {
    f.calls()
        .into_iter()
        .skip(from)
        .filter(|c| c.path == FOLLOWUP)
        .map(|c| c.body)
        .collect()
}

#[tokio::test]
async fn without_the_daemon_channel() {
    let (f, base) = fake().await;
    let d = bot(&base, None);
    d.handle(command(
        OWNER,
        "arm",
        json!([
            opt("host", json!("h")),
            opt("tier", json!("user")),
            opt("code", json!("1"))
        ]),
    ))
    .await;
    d.handle(command(OWNER, "dnd", json!([]))).await;
    d.handle(command(7, "lockdown", json!([]))).await;
    d.handle(modal_submit(
        7,
        &format!("aa:hxallm:{}", RequestId::new()),
        &[("duration", "1h")],
    ))
    .await;
    d.handle(command(OWNER, "hosts", json!([]))).await;
    let calls = f.calls();
    assert_eq!(ephemeral_reply(&calls[0]), NO_DAEMONS);
    assert_eq!(ephemeral_reply(&calls[1]), NO_DESKTOP);
    assert_eq!(ephemeral_reply(&calls[2]), interactions::NOT_OWNER);
    assert_eq!(ephemeral_reply(&calls[3]), interactions::NOT_OWNER);
    assert_eq!(
        calls[4].body["data"]["embeds"][0]["description"],
        "No paired daemons. Pair one with `agent-auth admin daemon-pair`."
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn hostexec_commands_end_to_end(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let (f, base) = fake().await;
    let d = bot(&base, Some(&b));

    // /hosts and host autocomplete.
    d.handle(command(OWNER, "hosts", json!([]))).await;
    let calls = f.calls();
    let hosts = calls[0].body["data"]["embeds"][0]["description"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        hosts.starts_with("🟢 online **excelsior** (host)"),
        "{hosts}"
    );
    assert_eq!(calls[0].body["data"]["flags"], 64);
    d.handle(interaction(
        4,
        OWNER,
        json!({"id": "30", "name": "arm", "type": 1,
               "options": [{"name": "host", "type": 3, "value": "exc", "focused": true}]}),
    ))
    .await;
    assert_eq!(
        f.calls()[1].body,
        json!({"type": 8, "data": {"choices": [{"name": "excelsior", "value": "excelsior"}]}})
    );

    // /arm: a wrong code, then the right one.
    let arm = |code: String| {
        command(
            OWNER,
            "arm",
            json!([
                opt("host", json!(HOST)),
                opt("tier", json!("user")),
                opt("code", json!(code)),
                opt("duration", json!("30m"))
            ]),
        )
    };
    d.handle(arm("000000".to_owned())).await;
    d.handle(arm(host.code("user-arm", 0))).await;
    let ups = followups(&f, 0).await;
    assert!(
        ups[0]["content"]
            .as_str()
            .unwrap()
            .starts_with("Not armed — excelsior: "),
        "{}",
        ups[0]
    );
    assert!(
        ups[1]["content"]
            .as_str()
            .unwrap()
            .starts_with("🔓 **excelsior** user tier armed until <t:"),
        "{}",
        ups[1]
    );

    // Approve all…: the modal, the cap, then a window that approves.
    let a = b.agent("claude-1").await;
    let body = serde_json::from_value(json!({
        "platform": "hostexec", "capability": "run", "resource": HOST,
        "scope": {"tier": "user", "argv": ["true"]}, "justification": "a specific task",
        "requested_duration": "1h",
    }))
    .unwrap();
    let r = crate::service::create(&b.st, &caller(&a), body)
        .await
        .unwrap();
    assert_eq!(r.status, RequestStatus::AwaitingHuman);
    let before = f.calls().len();
    d.handle(button_click(OWNER, &format!("aa:hxall:{}", r.id)))
        .await;
    let modal = &f.calls()[before].body;
    assert_eq!(modal["type"], 9);
    assert_eq!(modal["data"]["custom_id"], format!("aa:hxallm:{}", r.id));
    assert_eq!(modal["data"]["components"][0]["component"]["value"], "30m");
    d.handle(modal_submit(
        OWNER,
        &format!("aa:hxallm:{}", r.id),
        &[("duration", "9h")],
    ))
    .await;
    d.handle(modal_submit(
        OWNER,
        &format!("aa:hxallm:{}", r.id),
        &[("duration", "1h")],
    ))
    .await;
    let ups = followups(&f, before).await;
    assert_eq!(ups[0]["content"], "A window lasts at most 8h.");
    let opened = ups[1]["content"].as_str().unwrap();
    assert!(
        opened.starts_with("Window open for 1h: **claude\\-1** may run user commands on **excelsior** without asking (rule `"),
        "{opened}"
    );
    assert!(opened.ends_with("Approved now: 1."), "{opened}");

    // /disarm.
    let before = f.calls().len();
    d.handle(command(
        OWNER,
        "disarm",
        json!([opt("host", json!(HOST)), opt("tier", json!("user"))]),
    ))
    .await;
    assert_eq!(
        followups(&f, before).await[0]["content"],
        "🔒 **excelsior** user disarmed."
    );

    // /lockdown: answered in the channel, with Kill VMs.
    let before = f.calls().len();
    d.handle(command(
        OWNER,
        "lockdown",
        json!([opt("scope", json!("host")), opt("host", json!(HOST))]),
    ))
    .await;
    let calls: Vec<_> = f.calls().into_iter().skip(before).collect();
    assert_eq!(calls[0].path, CALLBACK);
    assert_eq!(calls[0].body, json!({"type": 5}));
    assert_eq!(
        calls[1].body["embeds"][0]["title"],
        "⛔ LOCKDOWN (host excelsior)"
    );
    assert!(calls[1].body.get("flags").is_none());
    let kill = &calls[1].body["components"][0]["components"][0];
    assert_eq!(kill["label"], "Kill VMs");
    assert_eq!(kill["custom_id"], "aa:hxkill:host:excelsior");

    // Kill VMs: the same lockdown, the button greyed out after.
    let before = f.calls().len();
    d.handle(button_click(OWNER, "aa:hxkill:host:excelsior"))
        .await;
    let calls: Vec<_> = f.calls().into_iter().skip(before).collect();
    assert_eq!(calls[0].body, json!({"type": 6}));
    assert!(
        calls[1].body["content"]
            .as_str()
            .unwrap()
            .starts_with("Agent VMs stopped.")
    );
    assert_eq!(calls[2].method, Method::PATCH);
    assert_eq!(calls[2].path, "/webhooks/20/itok/messages/@original");
    assert_eq!(
        calls[2].body["components"][0]["components"][0]["disabled"],
        true
    );

    // /unlock (the broker's side only), /dnd.
    let before = f.calls().len();
    d.handle(command(OWNER, "unlock", json!([]))).await;
    let ups = followups(&f, before).await;
    assert!(
        ups[0]["content"]
            .as_str()
            .unwrap()
            .starts_with("Unlocked: "),
        "{}",
        ups[0]
    );
    assert!(
        ups[0]["content"]
            .as_str()
            .unwrap()
            .contains("Hosts stay locked until they get their own code.")
    );
    let before = f.calls().len();
    d.handle(command(OWNER, "dnd", json!([opt("duration", json!("2h"))])))
        .await;
    d.handle(command(OWNER, "dnd", json!([]))).await;
    d.handle(command(
        OWNER,
        "dnd",
        json!([opt("duration", json!("never"))]),
    ))
    .await;
    let calls: Vec<_> = f.calls().into_iter().skip(before).collect();
    assert_eq!(ephemeral_reply(&calls[0]), "Desktop prompts off for 2h.");
    assert_eq!(ephemeral_reply(&calls[1]), "Desktop prompts back on.");
    assert!(ephemeral_reply(&calls[2]).starts_with("Invalid duration: "));
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn release_takes_all_explicitly(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (f, base) = fake().await;
    let d = Discord::new(config(&base, OWNER), b.st.store.clone()).unwrap();
    let ops = std::sync::Arc::new(crate::service::SpineOps::new(b.st.clone()));
    d.attach(Services {
        containment: Some(ops),
        app: Some(b.st.clone()),
        ..Services::default()
    });
    d.handle(command(
        OWNER,
        "contain",
        json!([opt("reason", json!("leak")), opt("project", json!("food"))]),
    ))
    .await;
    d.handle(command(OWNER, "release", json!([]))).await;
    d.handle(command(OWNER, "release", json!([opt("all", json!(true))])))
        .await;
    let calls = f.calls();
    let help = ephemeral_reply(&calls[2]);
    assert!(
        help.starts_with("Say which: `/release entry:<id>` lifts one"),
        "{help}"
    );
    assert!(
        help.contains("project=food") || help.contains("food"),
        "{help}"
    );
    let lifted = calls[4].body["content"].as_str().unwrap();
    assert!(lifted.starts_with("Lifted: `"), "{lifted}");
}
