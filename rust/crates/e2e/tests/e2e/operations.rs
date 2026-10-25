//! The operator's side: containment, expiry, one broker per database,
//! shutdown.

use std::time::Duration;

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::harness::{Broker, TempDir, Who, eventually};
use crate::world::World;

const WRITE: &str = r#"{"permissions": {"contents": "write"}}"#;

/// Scenario 4: a contained agent's pending requests are denied, its
/// grants revoked (upstream too), its credentials refused; released, it
/// asks again.
#[sqlx::test(migrations = false)]
async fn containment_holds_and_releases(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let b = &w.broker;
    let bad = b.create_agent("auto-rogue", &[]).await;
    let good = b.create_agent("auto-good", &[]).await;

    let mut grants = Vec::new();
    for agent in [&bad, &good] {
        let r = b
            .cli(
                agent.who(),
                &[
                    "request",
                    "github",
                    "repo",
                    "acme/auto-app",
                    "--why",
                    "work",
                    "-s",
                    WRITE,
                    "--wait",
                ],
            )
            .await
            .ok();
        assert_eq!(r["status"], "granted", "{r}");
        let g = r["grant_id"].as_str().unwrap().to_owned();
        b.cli(agent.who(), &["cred", &g]).await.ok();
        grants.push(g);
    }
    let pending = b
        .cli(
            bad.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/other",
                "--why",
                "more",
                "-s",
                WRITE,
            ],
        )
        .await
        .ok();
    assert_eq!(pending["status"], "awaiting_human", "{pending}");
    let pending = pending["id"].as_str().unwrap().to_owned();
    let tokens_before = w.github.calls_to("DELETE", "/installation/token").len();

    let held = b
        .cli(
            Who::Admin,
            &[
                "admin",
                "contain",
                "--name",
                "auto-rogue",
                "--reason",
                "acting oddly",
            ],
        )
        .await
        .ok();
    assert_eq!(held["agents"], json!(["auto-rogue"]), "{held}");
    assert_eq!(held["grants_revoked"], 1, "{held}");
    assert_eq!(held["requests_denied"], 1, "{held}");
    let listed = b.cli(Who::Admin, &["admin", "contain-list"]).await.ok();
    assert!(listed.to_string().contains("acting oddly"), "{listed}");

    let r = b.cli(bad.who(), &["status", &pending]).await.ok();
    assert_eq!(r["status"], "denied", "{r}");
    let all = b.cli(bad.who(), &["grants", "--status", "all"]).await.ok();
    let g = all
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == json!(grants[0]))
        .unwrap();
    assert_eq!(g["status"], "revoked", "{all}");
    let refused = b.cli(bad.who(), &["cred", &grants[0]]).await.refused();
    assert!(refused.starts_with("[4"), "{refused}");
    let r = b
        .cli(
            bad.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/auto-app",
                "--why",
                "again",
                "-s",
                WRITE,
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "denied", "{r}");
    let reason = format!("contained ({}): acting oddly", held["id"].as_str().unwrap());
    assert_eq!(r["decision_reason"], json!(reason));
    // Its cached token was revoked upstream; the other agent's was not.
    eventually(
        Duration::from_secs(30),
        "the held agent's token revoked upstream",
        || async { w.github.calls_to("DELETE", "/installation/token").len() > tokens_before },
    )
    .await;
    let other = b.cli(good.who(), &["cred", &grants[1]]).await.ok();
    assert!(other["value"].as_str().is_some(), "{other}");

    // Released: it asks again and gets access again.
    b.cli(
        Who::Admin,
        &["admin", "contain-lift", held["id"].as_str().unwrap()],
    )
    .await
    .ok();
    let listed = b.cli(Who::Admin, &["admin", "contain-list"]).await.ok();
    assert!(!listed.to_string().contains("acting oddly"), "{listed}");
    let r = b
        .cli(
            bad.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/auto-app",
                "--why",
                "again",
                "-s",
                WRITE,
                "--wait",
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "granted", "{r}");
}

/// Scenario 7: a short grant expires; its credential is refused at once,
/// and the scheduler revokes the token upstream (here on the boot tick of
/// a restarted broker, which also proves a restart).
#[sqlx::test(migrations = false)]
async fn a_short_grant_expires(_: PgPoolOptions, opts: PgConnectOptions) {
    let mut w = World::start(&opts).await;
    let a = w.broker.create_agent("auto-brief", &[]).await;
    let r = w
        .broker
        .cli(
            a.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/auto-brief",
                "--why",
                "one push",
                "-d",
                "3s",
                "-s",
                WRITE,
                "--wait",
            ],
        )
        .await
        .ok();
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["approved_duration_secs"], 3);
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = w.broker.cli(a.who(), &["cred", &grant]).await.ok();
    let token = cred["value"].as_str().unwrap().to_owned();

    // Refused once it expired (3 s after the approval).
    eventually(Duration::from_secs(30), "the grant expires", || {
        let (w, a, grant) = (&w, &a, &grant);
        async move { w.broker.cli(a.who(), &["cred", grant]).await.code != 0 }
    })
    .await;
    let refused = w.broker.cli(a.who(), &["cred", &grant]).await.refused();
    assert!(refused.contains("not active"), "{refused}");
    let revoked = |w: &World| {
        w.github
            .calls_to("DELETE", "/installation/token")
            .iter()
            .any(|c| c.authorization.ends_with(&token))
    };
    w.broker.restart().await;
    eventually(
        Duration::from_secs(30),
        "the expired grant's token revoked upstream",
        || {
            let done = revoked(&w);
            async move { done }
        },
    )
    .await;
    let all = w
        .broker
        .cli(a.who(), &["grants", "--status", "all"])
        .await
        .ok();
    let g = all
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == json!(grant))
        .unwrap();
    assert_eq!(g["status"], "expired", "{all}");
}

/// Scenario 8: a second broker on the same database refuses to start.
#[sqlx::test(migrations = false)]
async fn one_broker_per_database(_: PgPoolOptions, opts: PgConnectOptions) {
    let w = World::start(&opts).await;
    let mut second = Broker::spawn(
        w.broker.setup.clone(),
        w.broker.encryption_key.clone(),
        TempDir::new(),
    );
    let status = second
        .exited(Duration::from_secs(30))
        .await
        .expect("it exits");
    assert!(!status.success());
    assert!(
        second
            .log()
            .contains("another agent-auth broker is running on this database"),
        "{}",
        second.log()
    );
    // The first one is unaffected.
    let a = w.broker.create_agent("auto-still", &[]).await;
    w.broker.cli(a.who(), &["me"]).await.ok();
}

/// Scenario 9: SIGTERM stops the broker cleanly, also with an agent in a
/// long-poll; the lock is released, so the next broker starts.
#[sqlx::test(migrations = false)]
async fn sigterm_shuts_down_gracefully(_: PgPoolOptions, opts: PgConnectOptions) {
    let mut w = World::start(&opts).await;
    let a = w.broker.create_agent("auto-poller", &[]).await;
    let pending = w
        .broker
        .cli(
            a.who(),
            &[
                "request",
                "github",
                "repo",
                "acme/human",
                "--why",
                "x",
                "-s",
                WRITE,
            ],
        )
        .await
        .ok();
    let id = pending["id"].as_str().unwrap().to_owned();
    // An agent waiting for a decision (up to 60 s) while the broker stops.
    let wait = ["wait", &id, "--timeout", "60"];
    let waiting = w.broker.cli(a.who(), &wait);
    let stop = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        w.broker.sigterm();
    };
    let started = std::time::Instant::now();
    let (out, ()) = tokio::join!(waiting, stop);
    // The waiter is cut off after the drain (the broker's DRAIN, 10 s).
    assert_eq!(out.code, 1, "{out:?}");
    assert!(out.stderr.contains("could not reach the broker"), "{out:?}");
    let status = w.broker.exited(Duration::from_secs(20)).await;
    assert!(
        status.is_some_and(|s| s.success()),
        "stopped cleanly within 20 s ({status:?}):\n{}",
        w.broker.log()
    );
    assert!(
        w.broker.log().contains("shutting down"),
        "{}",
        w.broker.log()
    );
    assert!(started.elapsed() < Duration::from_secs(25));
    // The lock went with it: a new broker starts on the database.
    let again =
        Broker::start_with_key(w.broker.setup.clone(), w.broker.encryption_key.clone()).await;
    let r = again.cli(a.who(), &["status", &id]).await.ok();
    assert_eq!(r["status"], "awaiting_human", "{r}");
}
