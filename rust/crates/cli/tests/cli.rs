//! `agent-auth` against a fake broker: argument parsing for every command,
//! and what is printed.

// Test code: helpers outside #[test] functions may unwrap and index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_auth_cli::args::{A2aCommand, AdminCommand, Command, SessionCommand};
use agent_auth_cli::{Cli, Io, run};
use agent_auth_client::Config;
use agent_auth_client::testing::{FakeBroker, Reply, shapes};
use clap::Parser;
use serde_json::{Value, json};

struct Ran {
    code: u8,
    out: String,
    err: String,
    prompts: Vec<String>,
}

async fn agent_auth(url: &str, args: &[&str]) -> Ran {
    agent_auth_with(url, args, true, &[]).await
}

async fn agent_auth_with(url: &str, args: &[&str], stdout_tty: bool, env: &[(&str, &str)]) -> Ran {
    let mut argv = vec!["agent-auth"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut prompts = Vec::new();
    let mut prompt = |text: &str| {
        prompts.push(text.to_owned());
        Ok("123456\n".to_owned())
    };
    let vars: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let lookup = move |name: &str| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let mut io = Io {
        out: &mut out,
        err: &mut err,
        color: false,
        stdout_tty,
        prompt: &mut prompt,
        config: Config {
            base_url: Some(url.to_owned()),
            api_key: Some("aa_abcdef_secret".into()),
            admin_token: Some("admin-token".into()),
            session_id: None,
        },
        env: &lookup,
    };
    let code = run(cli, &mut io).await;
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        prompts,
    }
}

fn parse(args: &[&str]) -> Command {
    let mut argv = vec!["agent-auth"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv)
        .unwrap_or_else(|e| panic!("{args:?}: {e}"))
        .command
}

fn refused(args: &[&str]) {
    let mut argv = vec!["agent-auth"];
    argv.extend_from_slice(args);
    assert!(
        Cli::try_parse_from(argv).is_err(),
        "{args:?} should not parse"
    );
}

#[test]
fn every_agent_command_parses() {
    assert!(matches!(parse(&["me"]), Command::Me));
    assert!(matches!(parse(&["catalog"]), Command::Catalog));
    match parse(&[
        "request",
        "github",
        "repo",
        "o/r",
        "--why",
        "fix",
        "-d",
        "8h",
        "-s",
        r#"{"a":1}"#,
        "--on-behalf-of-thread",
        "t1",
        "-w",
    ]) {
        Command::Request {
            platform,
            capability,
            resource,
            justification,
            duration,
            scope,
            on_behalf_of_thread,
            wait,
        } => {
            assert_eq!(
                (platform.as_str(), capability.as_str(), resource.as_str()),
                ("github", "repo", "o/r")
            );
            assert_eq!(
                (justification.as_str(), duration.as_str(), scope.as_str()),
                ("fix", "8h", r#"{"a":1}"#)
            );
            assert_eq!(on_behalf_of_thread.as_deref(), Some("t1"));
            assert!(wait);
        }
        other => panic!("{other:?}"),
    }
    match parse(&["request", "a2a", "talk", "hermes", "-j", "why"]) {
        Command::Request {
            duration,
            scope,
            wait,
            on_behalf_of_thread,
            ..
        } => {
            assert_eq!(
                (duration.as_str(), scope.as_str(), wait),
                ("1h", "{}", false)
            );
            assert_eq!(on_behalf_of_thread, None);
        }
        other => panic!("{other:?}"),
    }
    refused(&["request", "github", "repo", "o/r"]); // --why is required
    assert!(
        matches!(parse(&["status", "r1"]), Command::Status { request_id } if request_id == "r1")
    );
    assert!(
        matches!(parse(&["wait", "r1"]), Command::Wait { timeout, .. } if (timeout - 60.0).abs() < 1e-9)
    );
    assert!(
        matches!(parse(&["wait", "r1", "--timeout", "2.5"]), Command::Wait { timeout, .. } if (timeout - 2.5).abs() < 1e-9)
    );
    assert!(
        matches!(parse(&["retry", "r1", "-j", "better"]), Command::Retry { justification, .. } if justification == "better")
    );
    refused(&["retry", "r1"]);
    assert!(matches!(
        parse(&["escalate", "r1"]),
        Command::Escalate { .. }
    ));
    assert!(matches!(parse(&["grants"]), Command::Grants { status } if status == "active"));
    assert!(
        matches!(parse(&["grants", "--status", "all"]), Command::Grants { status } if status == "all")
    );
    assert!(matches!(parse(&["cred", "g1"]), Command::Cred { grant_id } if grant_id == "g1"));
    assert!(matches!(
        parse(&["session", "create"]),
        Command::Session(SessionCommand::Create { label: None })
    ));
    assert!(
        matches!(parse(&["session", "create", "-l", "x"]), Command::Session(SessionCommand::Create { label: Some(l) }) if l == "x")
    );
    assert!(matches!(
        parse(&["session", "close"]),
        Command::Session(SessionCommand::Close)
    ));
    refused(&[]);
    refused(&["session"]);
    refused(&["nope"]);
}

#[test]
fn every_a2a_command_parses() {
    let a2a = |args: &[&str]| match parse(args) {
        Command::A2a(c) => c,
        other => panic!("{other:?}"),
    };
    assert!(
        matches!(a2a(&["a2a", "check", "hermes"]), A2aCommand::Check { direction, topic: None, .. } if direction == "out")
    );
    assert!(
        matches!(a2a(&["a2a", "check", "hermes", "--direction", "in", "--topic", "deploy/x"]),
                     A2aCommand::Check { direction, topic: Some(t), .. } if direction == "in" && t == "deploy/x")
    );
    assert!(matches!(
        a2a(&["a2a", "open", "hermes", "-p", "{}"]),
        A2aCommand::Open { topic: None, .. }
    ));
    refused(&["a2a", "open", "hermes"]);
    assert!(matches!(
        a2a(&["a2a", "send", "t1", "--payload", "{}"]),
        A2aCommand::Send { .. }
    ));
    assert!(
        matches!(a2a(&["a2a", "poll", "t1"]), A2aCommand::Poll { after_seq: 0, wait, .. } if wait == 0.0)
    );
    assert!(
        matches!(a2a(&["a2a", "poll", "t1", "--after-seq", "4", "--wait", "30"]),
                     A2aCommand::Poll { after_seq: 4, wait, .. } if (wait - 30.0).abs() < 1e-9)
    );
    assert!(matches!(
        a2a(&["a2a", "threads", "--state", "open", "--role", "initiator"]),
        A2aCommand::Threads {
            state: Some(_),
            role: Some(_)
        }
    ));
    assert!(matches!(
        a2a(&["a2a", "show", "t1"]),
        A2aCommand::Show { .. }
    ));
    assert!(matches!(
        a2a(&["a2a", "accept", "t1"]),
        A2aCommand::Accept { .. }
    ));
    assert!(matches!(
        a2a(&["a2a", "reject", "t1", "-r", "busy"]),
        A2aCommand::Reject {
            reason: Some(_),
            ..
        }
    ));
    assert!(matches!(
        a2a(&["a2a", "close", "t1"]),
        A2aCommand::Close { reason: None, .. }
    ));
    assert!(matches!(
        a2a(&["a2a", "events", "--wait", "60", "--after", "c"]),
        A2aCommand::Events { after: Some(_), .. }
    ));
    match a2a(&["a2a", "serve", "--on-open-url", "http://127.0.0.1:9/start"]) {
        A2aCommand::Serve(s) => {
            assert_eq!(s.hmac_env, "AGENT_AUTH_WEBHOOK_SECRET");
            assert_eq!(s.sig_header, "X-Agent-Auth-Signature");
            assert!((s.wait - 60.0).abs() < 1e-9 && (s.redeliver_interval - 60.0).abs() < 1e-9);
            assert!((s.failure_backoff - 5.0).abs() < 1e-9 && (s.poll_interval - 5.0).abs() < 1e-9);
            assert!(!s.insecure_no_sign && !s.include_activity && s.state.is_none());
        }
        other => panic!("{other:?}"),
    }
    match a2a(&[
        "a2a",
        "serve",
        "--on-open-url",
        "u",
        "--include-activity",
        "--no-include-activity",
        "--insecure-no-sign",
        "--sig-header",
        "X-Hub-Signature-256",
        "--state",
        "/tmp/s.json",
        "--hmac-env",
        "SECRET",
        "--wait",
        "30",
        "--redeliver-interval",
        "10",
        "--failure-backoff",
        "1",
        "--poll-interval",
        "2",
    ]) {
        A2aCommand::Serve(s) => {
            assert!(!s.include_activity || s.no_include_activity);
            assert!(s.insecure_no_sign);
            assert_eq!(
                s.state.as_deref(),
                Some(std::path::Path::new("/tmp/s.json"))
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(a2a(&["a2a", "serve", "--on-open-url", "u", "--include-activity"]),
                     A2aCommand::Serve(s) if s.include_activity)
    );
    refused(&["a2a", "serve"]);
}

#[test]
fn every_admin_command_parses() {
    let admin = |args: &[&str]| match parse(args) {
        Command::Admin(c) => c,
        other => panic!("{other:?}"),
    };
    assert!(matches!(admin(&["admin", "gen-key"]), AdminCommand::GenKey));
    match admin(&[
        "admin",
        "agent-create",
        "hermes",
        "--description",
        "d",
        "--kind",
        "ephemeral",
        "--webhook-url",
        "https://h/x",
        "--lldap-username",
        "svc",
        "--runtime",
        "hermes",
        "--project",
        "homelab",
        "--host",
        "excelsior",
    ]) {
        AdminCommand::AgentCreate {
            kind,
            webhook_url: Some(_),
            lldap_username: Some(_),
            runtime: Some(_),
            project: Some(_),
            host: Some(_),
            ..
        } => {
            assert_eq!(kind, "ephemeral");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(admin(&["admin", "agent-create", "x"]), AdminCommand::AgentCreate { kind, description, .. } if kind == "service" && description.is_empty())
    );
    assert!(
        matches!(admin(&["admin", "agent-set", "x", "--runtime", ""]), AdminCommand::AgentSet { runtime: Some(r), .. } if r.is_empty())
    );
    assert!(matches!(
        admin(&["admin", "agent-rename", "x", "y"]),
        AdminCommand::AgentRename { .. }
    ));
    assert!(matches!(
        admin(&["admin", "rotate-lldap-password", "a"]),
        AdminCommand::RotateLldapPassword { .. }
    ));
    assert!(matches!(
        admin(&["admin", "rotate-webhook-secret", "a"]),
        AdminCommand::RotateWebhookSecret { .. }
    ));
    assert!(matches!(
        admin(&["admin", "set-webhook", "a"]),
        AdminCommand::SetWebhook { url: None, .. }
    ));
    assert!(matches!(
        admin(&["admin", "set-webhook", "a", "--url", "https://x"]),
        AdminCommand::SetWebhook { url: Some(_), .. }
    ));
    assert!(matches!(
        admin(&["admin", "set-kind", "a", "ephemeral"]),
        AdminCommand::SetKind { .. }
    ));
    assert!(matches!(admin(&["admin", "agents"]), AdminCommand::Agents));
    assert!(matches!(
        admin(&["admin", "agent-disable", "a"]),
        AdminCommand::AgentDisable { .. }
    ));
    assert!(matches!(
        admin(&["admin", "rotate-key", "a"]),
        AdminCommand::RotateKey { .. }
    ));
    assert!(matches!(admin(&["admin", "rules"]), AdminCommand::Rules));
    assert!(matches!(
        admin(&["admin", "rule-delete", "r"]),
        AdminCommand::RuleDelete { .. }
    ));
    assert!(matches!(
        admin(&["admin", "requests"]),
        AdminCommand::Requests { limit: 100 }
    ));
    assert!(matches!(
        admin(&["admin", "requests", "--limit", "5"]),
        AdminCommand::Requests { limit: 5 }
    ));
    assert!(matches!(
        admin(&["admin", "decide", "r", "--approve"]),
        AdminCommand::Decide {
            approve: true,
            totp: false,
            ..
        }
    ));
    assert!(matches!(
        admin(&[
            "admin", "decide", "r", "--deny", "--reason", "no", "-d", "2h", "--totp"
        ]),
        AdminCommand::Decide {
            approve: false,
            deny: true,
            duration: Some(_),
            totp: true,
            ..
        }
    ));
    refused(&["admin", "decide", "r"]);
    refused(&["admin", "decide", "r", "--approve", "--deny"]);
    assert!(
        matches!(admin(&["admin", "revoke", "g"]), AdminCommand::Revoke { reason, .. } if reason == "revoked by admin")
    );
    assert!(matches!(
        admin(&["admin", "gen-signing-key"]),
        AdminCommand::GenSigningKey {
            out: None,
            to_stdout: false
        }
    ));
    assert!(matches!(
        admin(&["admin", "gen-signing-key", "--out", "f", "--stdout"]),
        AdminCommand::GenSigningKey {
            out: Some(_),
            to_stdout: true
        }
    ));
    assert!(
        matches!(admin(&["admin", "daemon-pair", "excelsior"]), AdminCommand::DaemonPair { role, .. } if role == "host")
    );
    assert!(
        matches!(admin(&["admin", "daemon-pair", "vm", "--role", "sandbox"]), AdminCommand::DaemonPair { role, .. } if role == "sandbox")
    );
    assert!(matches!(
        admin(&["admin", "daemons"]),
        AdminCommand::Daemons
    ));
    assert!(matches!(
        admin(&["admin", "daemon-unpair", "d"]),
        AdminCommand::DaemonUnpair { .. }
    ));
    assert!(matches!(
        admin(&["admin", "broker-key"]),
        AdminCommand::BrokerKey
    ));
    assert!(matches!(admin(&["admin", "hosts"]), AdminCommand::Hosts));
    assert!(
        matches!(admin(&["admin", "arm", "h"]), AdminCommand::Arm { tier, duration, .. } if tier == "user" && duration == "1h")
    );
    assert!(matches!(
        admin(&["admin", "arm", "h", "--tier", "root", "-d", "30m"]),
        AdminCommand::Arm { .. }
    ));
    refused(&["admin", "arm", "h", "--totp", "123456"]); // codes are never arguments
    assert!(matches!(
        admin(&["admin", "disarm", "h"]),
        AdminCommand::Disarm { tier: None, .. }
    ));
    assert!(
        matches!(admin(&["admin", "lockdown"]), AdminCommand::Lockdown { scope, host: None, kill_vm: false } if scope == "sandboxes")
    );
    assert!(matches!(
        admin(&["admin", "lockdown", "--scope", "all", "--kill-vm"]),
        AdminCommand::Lockdown { kill_vm: true, .. }
    ));
    assert!(matches!(
        admin(&["admin", "unlock"]),
        AdminCommand::Unlock { host: None }
    ));
    assert!(matches!(
        admin(&["admin", "unlock", "--host", "h"]),
        AdminCommand::Unlock { host: Some(_) }
    ));
    assert!(matches!(
        admin(&[
            "admin", "contain", "--reason", "r", "--name", "claude-*", "--all"
        ]),
        AdminCommand::Contain {
            everyone: true,
            name: Some(_),
            ..
        }
    ));
    refused(&["admin", "contain", "--name", "x"]); // --reason is required
    assert!(matches!(
        admin(&["admin", "contain-list"]),
        AdminCommand::ContainList
    ));
    assert!(matches!(
        admin(&["admin", "contain-lift"]),
        AdminCommand::ContainLift { entry: None }
    ));
    assert!(matches!(
        admin(&["admin", "contain-lift", "0a1b2c3d"]),
        AdminCommand::ContainLift { entry: Some(_) }
    ));
    assert!(matches!(
        admin(&["admin", "connectors"]),
        AdminCommand::Connectors
    ));
    assert!(matches!(
        admin(&["admin", "connector-revoke", "c"]),
        AdminCommand::ConnectorRevoke { .. }
    ));
}

#[tokio::test]
async fn success_is_python_json_on_stdout() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("GET", "/v1/me", 200, shapes::me("ephemeral"));
    let r = agent_auth(&fake.url, &["me"]).await;
    assert_eq!(r.code, 0);
    assert_eq!(r.err, "");
    let expected = format!(
        "{{\n  \"id\": \"{}\",\n  \"name\": \"claude-x-host\",\n  \"description\": \"\",\n  \"kind\": \"ephemeral\",\n  \
         \"webhook_url\": null,\n  \"lldap_username\": null,\n  \"runtime\": \"claude\",\n  \"project\": null,\n  \
         \"host\": \"excelsior\",\n  \"placement\": \"host\"\n}}\n",
        shapes::AGENT_ID
    );
    assert_eq!(r.out, expected);
}

#[tokio::test]
async fn failures_go_to_stderr_with_exit_1() {
    let fake = FakeBroker::start().await.unwrap();
    fake.on("GET", "/v1/requests/*", |_| {
        Reply::detail(404, "unknown request")
    });
    let r = agent_auth(&fake.url, &["status", "r1"]).await;
    assert_eq!(
        (r.code, r.out.as_str(), r.err.as_str()),
        (1, "", "[404] unknown request\n")
    );

    let gone = {
        let f = FakeBroker::start().await.unwrap();
        f.url.clone()
    };
    tokio::task::yield_now().await;
    let r = agent_auth(&gone, &["me"]).await;
    assert_eq!(r.code, 1);
    assert!(
        r.err.starts_with("could not reach the broker: "),
        "{}",
        r.err
    );
}

#[tokio::test]
async fn request_with_wait_waits_and_bad_scope_is_a_usage_error() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("POST", "/v1/requests", 200, shapes::request("pending"));
    fake.json(
        "GET",
        "/v1/requests/*/wait",
        200,
        shapes::request("granted"),
    );
    let r = agent_auth(
        &fake.url,
        &[
            "request",
            "github",
            "repo",
            "o/r",
            "-j",
            "fix",
            "-s",
            r#"{"permissions": {"contents": "write"}}"#,
            "-w",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.err);
    let out: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(out["status"], "granted");
    let body = fake.calls("POST", "/v1/requests")[0].json();
    assert_eq!(body["scope"], json!({"permissions": {"contents": "write"}}));
    assert_eq!(
        fake.calls("GET", "/v1/requests/*/wait")[0].param("timeout"),
        Some("60.0")
    );

    let r = agent_auth(
        &fake.url,
        &[
            "request", "github", "repo", "o/r", "-j", "fix", "-s", "{nope",
        ],
    )
    .await;
    assert_eq!(r.code, 2);
    assert!(r.err.contains("--scope: not JSON"), "{}", r.err);
    let r = agent_auth(&fake.url, &["a2a", "open", "hermes", "-p", "[1]"]).await;
    assert_eq!(r.code, 2);
    assert!(r.err.contains("--payload: a JSON object"), "{}", r.err);
    assert_eq!(fake.calls("POST", "/v1/requests").len(), 1);
}

#[tokio::test]
async fn session_create_prints_the_export_line_on_stderr() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "POST",
        "/v1/sessions",
        200,
        shapes::session(shapes::SESSION_ID),
    );
    let r = agent_auth(&fake.url, &["session", "create", "-l", "task"]).await;
    assert_eq!(r.code, 0);
    assert_eq!(
        r.err,
        format!("export AGENT_AUTH_SESSION={}\n", shapes::SESSION_ID)
    );
    assert_eq!(
        serde_json::from_str::<Value>(&r.out).unwrap()["session_id"],
        shapes::SESSION_ID
    );
    assert_eq!(
        fake.calls("POST", "/v1/sessions")[0].json(),
        json!({"label": "task"})
    );
    agent_auth(&fake.url, &["session", "create"]).await;
    assert_eq!(
        fake.calls("POST", "/v1/sessions")[1].json(),
        json!({"label": agent_auth_client::default_session_label()})
    );
}

#[tokio::test]
async fn admin_create_warns_and_drops_nulls() {
    let fake = FakeBroker::start().await.unwrap();
    let mut created = shapes::agent("hermes");
    created["api_key"] = json!("aa_0123456789ab_secret");
    fake.json("POST", "/admin/agents", 200, created);
    let r = agent_auth(&fake.url, &["admin", "agent-create", "hermes"]).await;
    assert_eq!(r.code, 0);
    assert!(
        r.err
            .starts_with("warning: hermes is 'service' with no --webhook-url"),
        "{}",
        r.err
    );
    // Null fields dropped, the rest in AgentOut's order.
    assert_eq!(
        r.out,
        format!(
            "{{\n  \"id\": \"{}\",\n  \"name\": \"hermes\",\n  \"description\": \"\",\n  \"kind\": \"service\",\n  \
             \"lldap_managed\": false,\n  \"disabled\": false,\n  \"placement\": \"host\",\n  \
             \"api_key\": \"aa_0123456789ab_secret\"\n}}\n",
            shapes::AGENT_ID
        )
    );
    let seen = &fake.calls("POST", "/admin/agents")[0];
    assert_eq!(seen.header("authorization"), Some("Bearer admin-token"));
    assert_eq!(seen.json()["kind"], "service");
    let r = agent_auth(
        &fake.url,
        &["admin", "agent-create", "cli", "--kind", "ephemeral"],
    )
    .await;
    assert_eq!(r.err, "");
}

#[tokio::test]
async fn bad_parameters_are_usage_errors() {
    let fake = FakeBroker::start().await.unwrap();
    let r = agent_auth(&fake.url, &["admin", "agent-set", "hermes"]).await;
    assert_eq!(r.code, 2);
    assert!(
        r.err
            .contains("nothing to set: pass --runtime, --project or --host"),
        "{}",
        r.err
    );
    let r = agent_auth(&fake.url, &["admin", "set-kind", "hermes", "operator"]).await;
    assert_eq!(r.code, 2);
    assert!(
        r.err.contains("kind must be 'service' or 'ephemeral'"),
        "{}",
        r.err
    );
    let r = agent_auth(&fake.url, &["admin", "contain", "--reason", "r"]).await;
    assert_eq!(r.code, 2);
    assert!(
        r.err
            .contains("say which agents (--name/--project/--host/--runtime) or --all"),
        "{}",
        r.err
    );
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn codes_are_prompted_for_hidden() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "POST",
        "/admin/requests/*/decide",
        200,
        shapes::request("granted"),
    );
    fake.json(
        "POST",
        "/admin/hosts/*/arm",
        200,
        json!({"armed_until": 1.5e9}),
    );
    fake.json(
        "POST",
        "/admin/unlock",
        200,
        json!({"host": null, "daemons": {}, "broker_locked": []}),
    );

    let r = agent_auth(&fake.url, &["admin", "decide", "r1", "--approve", "--totp"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(r.prompts, ["TOTP code: "]);
    assert_eq!(
        fake.calls("POST", "/admin/requests/*/decide")[0].json(),
        json!({"approve": true, "reason": "", "duration": null, "resource_override": null,
               "scope_override": null, "totp": "123456"})
    );
    // Denying asks for nothing.
    let r = agent_auth(&fake.url, &["admin", "decide", "r1", "--deny", "--totp"]).await;
    assert!(r.prompts.is_empty());
    assert_eq!(
        fake.calls("POST", "/admin/requests/*/decide")[1].json()["totp"],
        Value::Null
    );

    let r = agent_auth(&fake.url, &["admin", "arm", "excelsior", "--tier", "root"]).await;
    assert_eq!(r.prompts, ["excelsior root-arm code: "]);
    assert_eq!(
        fake.calls("POST", "/admin/hosts/*/arm")[0].json(),
        json!({"tier": "root", "duration": "1h", "totp": "123456"})
    );
    assert_eq!(r.out, "{\n  \"armed_until\": 1500000000.0\n}\n");

    let r = agent_auth(&fake.url, &["admin", "unlock"]).await;
    assert!(r.prompts.is_empty());
    let r = agent_auth(&fake.url, &["admin", "unlock", "--host", "excelsior"]).await;
    assert_eq!(r.prompts, ["excelsior root-arm code: "]);
    assert_eq!(
        fake.calls("POST", "/admin/unlock")[1].json(),
        json!({"host": "excelsior", "totp": "123456"})
    );
}

#[tokio::test]
async fn admin_bodies() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("POST", "/admin/lockdown", 200, json!({"scope": "host", "host": "excelsior", "daemons": {}, "grants_revoked": 0, "threads_closed": 0}));
    fake.json(
        "POST",
        "/admin/containment/lift",
        200,
        json!({"lifted": []}),
    );
    fake.json("POST", "/admin/containment", 200, json!({
        "id": "0a1b2c3d", "match": {"name": "claude-*"}, "reason": "r", "evidence": "", "by": "admin token",
        "source": "operator", "at": shapes::T, "agents": [], "grants_revoked": 0, "requests_denied": 0,
        "threads_closed": 0, "daemons": {}}));
    fake.json(
        "POST",
        "/admin/grants/*/revoke",
        200,
        json!({"ok": true, "grant_id": shapes::GRANT_ID, "status": "revoked"}),
    );

    agent_auth(&fake.url, &["admin", "lockdown", "--host", "excelsior"]).await;
    assert_eq!(
        fake.calls("POST", "/admin/lockdown")[0].json(),
        json!({"scope": "host", "host": "excelsior", "kill_vm": false})
    );
    agent_auth(&fake.url, &["admin", "contain-lift"]).await;
    assert_eq!(
        fake.calls("POST", "/admin/containment/lift")[0].json(),
        json!({"all": true})
    );
    let r = agent_auth(
        &fake.url,
        &[
            "admin", "contain", "--reason", "r", "--name", "claude-*", "--host", "",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        fake.calls("POST", "/admin/containment")[0].json(),
        json!({"match": {"name": "claude-*"}, "reason": "r", "evidence": ""})
    );
    agent_auth(&fake.url, &["admin", "revoke", shapes::GRANT_ID]).await;
    assert_eq!(
        fake.calls("POST", "/admin/grants/*/revoke")[0].param("reason"),
        Some("revoked by admin")
    );
}

#[tokio::test]
async fn daemon_pair_prints_text() {
    let fake = FakeBroker::start().await.unwrap();
    let key = agent_auth_crypto::daemon::SigningKey::generate()
        .unwrap()
        .public_key();
    fake.json(
        "POST",
        "/admin/daemons/pairing-codes",
        200,
        json!({
        "role": "host", "name": "excelsior", "code": "ABCD-EFGH", "expires_at": shapes::T,
        "broker_public_key": key.to_text()}),
    );
    let r = agent_auth(&fake.url, &["admin", "daemon-pair", "excelsior"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(
        r.out,
        format!(
            "pairing code for host:excelsior: ABCD-EFGH\nexpires: {}\nbroker key fingerprint (the daemon prints it too): {}\n\
             on the host: `sudo agent-auth-hostd pair`, then enter the code at the prompt (not as an argument — it would land in shell history)\n",
            shapes::T,
            key.fingerprint()
        )
    );
}

static N: AtomicUsize = AtomicUsize::new(0);

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agent-auth-cli-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn gen_signing_key_keeps_the_seed_off_pipes_and_never_overwrites() {
    let fake = FakeBroker::start().await.unwrap();
    let r = agent_auth_with(&fake.url, &["admin", "gen-signing-key"], false, &[]).await;
    assert_eq!(r.code, 2);
    assert_eq!(r.out, "");
    assert!(
        r.err
            .starts_with("refusing to print the private signing key")
    );

    let r = agent_auth_with(
        &fake.url,
        &["admin", "gen-signing-key", "--stdout"],
        false,
        &[],
    )
    .await;
    assert_eq!(r.code, 0);
    let lines: Vec<&str> = r.out.lines().collect();
    assert!(lines[0].starts_with("BROKER_SIGNING_KEY="));
    let seed = lines[0].trim_start_matches("BROKER_SIGNING_KEY=");
    let key = agent_auth_crypto::daemon::SigningKey::from_text(seed).unwrap();
    assert_eq!(
        lines[1],
        format!(
            "# public key (pin in daemons): {}",
            key.public_key().to_text()
        )
    );
    assert_eq!(
        lines[2],
        format!("# fingerprint: {}", key.public_key().fingerprint())
    );

    let dir = scratch();
    let path = dir.join("signing.env");
    let p = path.to_str().unwrap();
    let r = agent_auth_with(
        &fake.url,
        &["admin", "gen-signing-key", "--out", p],
        false,
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        !r.out.contains("BROKER_SIGNING_KEY="),
        "the seed is only in the file"
    );
    assert_eq!(
        r.out.lines().next(),
        Some(format!("# wrote BROKER_SIGNING_KEY to {p}").as_str())
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("BROKER_SIGNING_KEY=") && text.ends_with('\n'));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Never overwritten.
    let r = agent_auth_with(
        &fake.url,
        &["admin", "gen-signing-key", "--out", p],
        false,
        &[],
    )
    .await;
    assert_eq!(r.code, 1);
    assert_eq!(r.err, format!("cannot create {p}: File exists\n"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    // Never through a link (even a dangling one).
    let link = dir.join("link.env");
    symlink(dir.join("elsewhere"), &link).unwrap();
    let r = agent_auth_with(
        &fake.url,
        &["admin", "gen-signing-key", "--out", link.to_str().unwrap()],
        false,
        &[],
    )
    .await;
    assert_eq!(r.code, 1);
    assert!(!dir.join("elsewhere").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn gen_key_prints_an_encryption_key() {
    let r = agent_auth("http://127.0.0.1:9", &["admin", "gen-key"]).await;
    assert_eq!(r.code, 0);
    let key = r.out.trim_end();
    assert_eq!(key.len(), 44);
    assert!(agent_auth_crypto::secretbox::SecretBox::from_base64(key).is_ok());
}

#[tokio::test]
async fn a2a_serve_needs_its_secret() {
    let r = agent_auth_with(
        "http://127.0.0.1:9",
        &["a2a", "serve", "--on-open-url", "http://127.0.0.1:9/x"],
        true,
        &[],
    )
    .await;
    assert_eq!(r.code, 1);
    assert_eq!(
        r.err,
        "AGENT_AUTH_WEBHOOK_SECRET is not set. Set it to the shared webhook secret, or pass --insecure-no-sign for loopback testing.\n"
    );
    let r = agent_auth_with(
        "http://127.0.0.1:9",
        &["a2a", "serve", "--on-open-url", "u", "--hmac-env", "MINE"],
        true,
        &[("AGENT_AUTH_WEBHOOK_SECRET", "s")],
    )
    .await;
    assert!(r.err.starts_with("MINE is not set."), "{}", r.err);
}

#[tokio::test]
async fn admin_calls_need_the_admin_token() {
    let fake = FakeBroker::start().await.unwrap();
    let cli = Cli::try_parse_from(["agent-auth", "admin", "agents"]).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut prompt = |_: &str| Ok(String::new());
    let env = |_: &str| None;
    let mut io = Io {
        out: &mut out,
        err: &mut err,
        color: true,
        stdout_tty: true,
        prompt: &mut prompt,
        config: Config {
            base_url: Some(fake.url.clone()),
            ..Config::default()
        },
        env: &env,
    };
    assert_eq!(run(cli, &mut io).await, 1);
    // Red on a terminal.
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "\u{1b}[31m[0] AGENT_AUTH_ADMIN_TOKEN not set\u{1b}[0m\n"
    );
    assert!(fake.seen().is_empty());
}
