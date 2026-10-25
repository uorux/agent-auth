//! Agents, requests, decisions, grants and credentials.

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::harness::Who;
use crate::world::World;

/// Scenario 1: the admin creates an agent; its key works and `me` shows it.
#[sqlx::test(migrations = false)]
async fn admin_creates_an_agent(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let b = &w.broker;
    let agent = b
        .create_agent("auto-sde", &["--kind", "ephemeral", "--runtime", "claude"])
        .await;
    assert!(agent.key.starts_with("aa_"), "{}", agent.key);

    let me = b.cli(agent.who(), &["me"]).await.ok();
    assert_eq!(me["id"], json!(agent.id));
    assert_eq!(me["name"], "auto-sde");
    assert_eq!(me["kind"], "ephemeral");
    assert_eq!(me["runtime"], "claude");

    let listed = b.cli(Who::Admin, &["admin", "agents"]).await.ok();
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["name"] == "auto-sde"),
        "{listed}"
    );

    // A wrong key, and no key at all, are refused.
    let bad = b
        .cli(Who::Agent("aa_000000000000_nope"), &["me"])
        .await
        .refused();
    assert!(bad.starts_with("[401]"), "{bad}");
    let none = b.cli(Who::Nobody, &["me"]).await.refused();
    assert!(none.contains("AGENT_AUTH_API_KEY not set"), "{none}");
    // Agents are not admins.
    let not_admin = b
        .cli(Who::Agent(&agent.key), &["admin", "agents"])
        .await
        .refused();
    assert!(
        not_admin.contains("AGENT_AUTH_ADMIN_TOKEN not set"),
        "{not_admin}"
    );
}

/// A GitHub scope: read the contents.
const READ: &str = r#"{"permissions": {"contents": "read"}}"#;

/// `agent-auth request ...`, parsed.
async fn request(
    w: &World,
    agent: &crate::harness::Agent,
    target: [&str; 3],
    why: &str,
    extra: &[&str],
) -> serde_json::Value {
    let mut args = vec!["request", target[0], target[1], target[2], "--why", why];
    args.extend_from_slice(extra);
    w.broker.cli(agent.who(), &args).await.ok()
}

/// Scenario 2: policy auto-approves, the grant is live, the credential is
/// issued — for a2a (nothing upstream) and GitHub (the fake mints).
#[sqlx::test(migrations = false)]
async fn policy_approves_and_credentials_issue(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let b = &w.broker;
    let a = b.create_agent("auto-a", &[]).await;
    b.create_agent("peer-b", &[]).await;

    let r = request(
        &w,
        &a,
        ["a2a", "talk", "peer-b"],
        "coordinate a deploy",
        &["-d", "2h", "--wait"],
    )
    .await;
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["decision_source"], "policy");
    let a2a_grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(a.who(), &["cred", &a2a_grant]).await.ok();
    assert_eq!(cred["kind"], "a2a_grant", "{cred}");
    assert_eq!(cred["value"], serde_json::Value::Null);

    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/auto-app"],
        "push the release branch",
        &["-s", r#"{"permissions": {"contents": "write"}}"#, "--wait"],
    )
    .await;
    assert_eq!(r["status"], "granted", "{r}");
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    // Provisioning minted a token to prove the installation covers the
    // repo, and revoked it at once.
    let revoked = w.github.calls_to("DELETE", "/installation/token");
    assert_eq!(revoked.len(), 1);
    assert!(
        revoked[0].authorization.ends_with("ghs_e2e_1"),
        "{revoked:?}"
    );
    let cred = b.cli(a.who(), &["cred", &grant]).await.ok();
    assert_eq!(cred["kind"], "github_installation_token", "{cred}");
    assert_eq!(cred["value"], "ghs_e2e_2");
    // Fetched again: the cached token.
    let again = b.cli(a.who(), &["cred", &grant]).await.ok();
    assert_eq!(again["value"], "ghs_e2e_2");
    let minted = w.github.calls_to("POST", "/access_tokens");
    assert_eq!(minted.len(), 2);
    for m in &minted {
        assert_eq!(
            m.body,
            json!({"repositories": ["auto-app"], "permissions": {"contents": "write"}})
        );
        assert!(m.authorization.starts_with("Bearer ey"), "an App JWT");
    }

    let grants = b.cli(a.who(), &["grants"]).await.ok();
    assert_eq!(grants.as_array().unwrap().len(), 2, "{grants}");
}

/// Scenario 3: a human decides (with an edit, and a denial); the LLM
/// reviewer approves, denies (the agent retries), and answers nonsense
/// (a human decides).
#[sqlx::test(migrations = false)]
async fn humans_and_the_llm_decide(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let b = &w.broker;
    let a = b.create_agent("sde-a", &[]).await;

    // Human, approving a narrower scope than asked.
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/site"],
        "fix the landing page",
        &[
            "-s",
            r#"{"permissions": {"contents": "write", "pull_requests": "write"}}"#,
        ],
    )
    .await;
    assert_eq!(r["status"], "awaiting_human", "{r}");
    let id = r["id"].as_str().unwrap().to_owned();
    let listed = b.cli(Who::Admin, &["admin", "requests"]).await.ok();
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == json!(id)),
        "{listed}"
    );
    let (status, decided) = b
        .admin(
            reqwest::Method::POST,
            &format!("/admin/requests/{id}/decide"),
            Some(
                json!({"approve": true, "reason": "read is enough", "duration": "2h",
                        "scope_override": {"permissions": {"contents": "read"}}}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{decided}");
    let r = b.cli(a.who(), &["wait", &id, "--timeout", "10"]).await.ok();
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["decision_source"], "human");
    assert_eq!(r["approved_duration_secs"], 7200);
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(a.who(), &["cred", &grant]).await.ok();
    assert!(
        cred["value"].as_str().unwrap().starts_with("ghs_e2e_"),
        "{cred}"
    );
    let minted = w.github.calls_to("POST", "/access_tokens");
    assert_eq!(
        minted.last().unwrap().body["permissions"],
        json!({"contents": "read"}),
        "the edited scope is what was minted"
    );

    // Human, denying (through the CLI).
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/infra"],
        "tidy the repo",
        &["-s", READ],
    )
    .await;
    assert_eq!(r["status"], "awaiting_human", "{r}");
    let id = r["id"].as_str().unwrap().to_owned();
    let d = b
        .cli(
            Who::Admin,
            &[
                "admin",
                "decide",
                &id,
                "--deny",
                "--reason",
                "not this week",
            ],
        )
        .await
        .ok();
    assert_eq!(d["status"], "denied", "{d}");
    let r = b.cli(a.who(), &["status", &id]).await.ok();
    assert_eq!(r["status"], "denied");
    assert_eq!(r["decision_reason"], "not this week");

    // The LLM approves.
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/llm-docs"],
        "[llm:approve] update the docs for release 1.2",
        &["-s", READ, "--wait"],
    )
    .await;
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["decision_source"], "llm");
    let asked = w.openrouter.calls();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].authorization, "Bearer sk-or-e2e");
    assert_eq!(asked[0].body["model"], "e2e/reviewer");

    // The LLM denies; the agent retries with a better reason.
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/llm-ci"],
        "[llm:deny] ci",
        &["-s", READ, "--wait"],
    )
    .await;
    assert_eq!(r["status"], "llm_denied", "{r}");
    assert_eq!(r["decision_reason"], "too vague: say which task");
    let id = r["id"].as_str().unwrap().to_owned();
    let r = b
        .cli(
            a.who(),
            &[
                "retry",
                &id,
                "--why",
                "[llm:approve] fix the flaky CI job in ci.yml",
            ],
        )
        .await
        .ok();
    assert_eq!(r["attempt"], 2, "{r}");
    let r = b.cli(a.who(), &["wait", &id, "--timeout", "20"]).await.ok();
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(w.openrouter.calls().len(), 3);
    // The reviewer saw the first verdict.
    let prompt = w.openrouter.calls()[2].body["messages"][1]["content"].clone();
    assert!(
        prompt
            .as_str()
            .unwrap()
            .contains("Attempt 1: verdict=deny; reasoning (quoted model output): \"too vague"),
        "{prompt}"
    );

    // Denied again: the agent escalates to a human instead.
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/llm-ops"],
        "[llm:deny] ops",
        &["-s", READ, "--wait"],
    )
    .await;
    assert_eq!(r["status"], "llm_denied", "{r}");
    let id = r["id"].as_str().unwrap().to_owned();
    let r = b.cli(a.who(), &["escalate", &id]).await.ok();
    assert_eq!(r["status"], "awaiting_human", "{r}");

    // The LLM answers nonsense: a human decides.
    // (`wait` holds an awaiting_human request until its timeout.)
    let r = request(
        &w,
        &a,
        ["github", "repo", "acme/llm-x"],
        "[llm:garbage] x",
        &["-s", READ],
    )
    .await;
    let id = r["id"].as_str().unwrap().to_owned();
    let r = b.cli(a.who(), &["wait", &id, "--timeout", "2"]).await.ok();
    assert_eq!(r["status"], "awaiting_human", "{r}");
    assert_eq!(r["decision_source"], serde_json::Value::Null, "{r}");
}
