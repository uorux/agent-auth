//! Scenario 5: two agents talk in a thread, and the responder gets access
//! on behalf of it.

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::world::World;

#[sqlx::test(migrations = false)]
async fn a_thread_with_long_poll_and_delegation(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let b = &w.broker;
    let sde = b.create_agent("auto-sde", &[]).await;
    let ops = b.create_agent("ops-agent", &[]).await;

    // No grant: no thread.
    let refused = b
        .cli(
            sde.who(),
            &["a2a", "open", "ops-agent", "-p", r#"{"task": "x"}"#],
        )
        .await
        .refused();
    assert!(refused.starts_with("[403]"), "{refused}");

    let r = b
        .cli(
            sde.who(),
            &[
                "request",
                "a2a",
                "talk",
                "ops-agent",
                "--why",
                "deploy help",
                "-s",
                r#"{"topic": "deploy/*"}"#,
                "--wait",
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "granted", "{r}");
    let check = b
        .cli(
            ops.who(),
            &[
                "a2a",
                "check",
                "auto-sde",
                "--direction",
                "in",
                "--topic",
                "deploy/web",
            ],
        )
        .await
        .ok();
    assert_eq!(check["allowed"], true, "{check}");

    // A service agent is reachable once it polls its events.
    let events = b.cli(ops.who(), &["a2a", "events"]).await.ok();
    assert_eq!(events["pending_opens"], json!([]), "{events}");
    let opened = b
        .cli(
            sde.who(),
            &[
                "a2a",
                "open",
                "ops-agent",
                "-p",
                r#"{"task": "deploy cactus"}"#,
                "--topic",
                "deploy/web",
            ],
        )
        .await
        .ok();
    let tid = opened["thread_id"].as_str().unwrap().to_owned();
    assert_eq!(opened["state"], "pending_open", "{opened}");

    let events = b.cli(ops.who(), &["a2a", "events"]).await.ok();
    let pending = events["pending_opens"].as_array().unwrap();
    assert!(
        pending.iter().any(|p| p["thread_id"] == json!(tid)),
        "{events}"
    );
    let read = b.cli(ops.who(), &["a2a", "poll", &tid]).await.ok();
    assert_eq!(
        read["messages"][0]["payload"],
        json!({"task": "deploy cactus"}),
        "{read}"
    );

    // The initiator long-polls; the reply wakes it.
    let poll = ["a2a", "poll", &tid, "--after-seq", "1", "--wait", "30"];
    let waiting = b.cli(sde.who(), &poll);
    let reply = async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        b.cli(
            ops.who(),
            &[
                "a2a",
                "send",
                &tid,
                "-p",
                r#"{"ok": true, "note": "on it"}"#,
            ],
        )
        .await
        .ok()
    };
    let started = std::time::Instant::now();
    let (got, sent) = tokio::join!(waiting, reply);
    let got = got.ok();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(15),
        "woken, not timed out"
    );
    assert_eq!(sent["seq"], 2, "{sent}");
    assert_eq!(
        got["messages"][0]["payload"],
        json!({"ok": true, "note": "on it"}),
        "{got}"
    );
    assert_eq!(
        got["thread"]["state"], "open",
        "the reply accepted the thread: {got}"
    );

    // The responder asks for access on behalf of the thread.
    let r = b
        .cli(
            ops.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/delegated-cactus",
                "--why",
                "deploy cactus for auto-sde",
                "-s",
                r#"{"permissions": {"contents": "read"}}"#,
                "--on-behalf-of-thread",
                &tid,
                "--wait",
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["delegator"], "auto-sde", "{r}");
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(ops.who(), &["cred", &grant]).await.ok();
    assert!(
        cred["value"].as_str().unwrap().starts_with("ghs_e2e_"),
        "{cred}"
    );
    // Not for a thread it is not the responder of.
    let r = b
        .cli(
            sde.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/delegated-cactus",
                "--why",
                "x",
                "-s",
                r#"{"permissions": {"contents": "read"}}"#,
                "--on-behalf-of-thread",
                &tid,
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "denied", "{r}");
    assert!(
        r["decision_reason"]
            .as_str()
            .unwrap()
            .contains("only the responder may act"),
        "{r}"
    );

    b.cli(
        ops.who(),
        &[
            "a2a",
            "send",
            &tid,
            "-p",
            r#"{"type": "result", "status": "done", "summary": "deployed"}"#,
        ],
    )
    .await
    .ok();
    let closed = b
        .cli(ops.who(), &["a2a", "close", &tid, "--reason", "done"])
        .await
        .ok();
    assert_eq!(closed["state"], "closed", "{closed}");
    assert_eq!(closed["close_note"], "done", "{closed}");
    let last = b
        .cli(sde.who(), &["a2a", "poll", &tid, "--after-seq", "2"])
        .await
        .ok();
    assert_eq!(last["thread"]["state"], "closed", "{last}");
    assert_eq!(last["messages"][0]["payload"]["type"], "result", "{last}");

    // The thread is closed: the delegated credential stops.
    let refused = b.cli(ops.who(), &["cred", &grant]).await.refused();
    assert!(
        refused.starts_with("[403]") || refused.starts_with("[409]"),
        "{refused}"
    );
}
