//! Platform `pool` and `release_grant`: a scarce item is one agent's at a
//! time; giving it back early hands it to the next.

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::harness::{Mcp, TempDir, Who};
use crate::world::World;

fn policy(secrets: &TempDir) -> String {
    let secret = secrets.path().join("alt-1");
    std::fs::write(
        &secret,
        "{\"email\": \"alt-1@example.org\", \"password\": \"pw\"}\n",
    )
    .unwrap();
    format!(
        r#"
defaults: {{action: surface, max_duration: 24h}}
platforms:
  pools:
    minecraft:
      description: Minecraft accounts
      agents: ["bot-*"]
      items:
        alt-1:
          properties: {{edition: java, username: AltOne}}
          secret_file: {}
        main:
          properties: {{edition: java, username: TheMain}}
          sensitive: true
rules:
  - match: {{platform: pool, capability: lease, resource: minecraft}}
    action: approve
    constraints: {{max_duration: 8h}}
"#,
        secret.display()
    )
}

#[sqlx::test(migrations = false)]
async fn a_pool_item_is_one_agents_until_released(_: PgPoolOptions, opts: PgConnectOptions) {
    let secrets = TempDir::new();
    let w = World::start_with(&opts, &policy(&secrets)).await;
    let b = &w.broker;
    let a = b.create_agent("bot-a", &[]).await;
    let c = b.create_agent("bot-c", &["--kind", "ephemeral"]).await;
    let lease = |who| async move {
        b.cli(
            who,
            &[
                "request",
                "pool",
                "lease",
                "minecraft",
                "--why",
                "play on the build server",
            ],
        )
        .await
        .ok()
    };

    // The catalog shows the pool, its items and that alt-1 is free.
    let catalog = b.cli(a.who(), &["catalog"]).await.ok();
    let entry = catalog["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["platform"] == "pool")
        .unwrap()
        .clone();
    // The typical disposition is a probe for any resource; the rule names
    // the pool, so the probe errs toward a human (as the Python's).
    assert_eq!(
        entry["capabilities"],
        json!(["lease (human review)"]),
        "{entry}"
    );
    assert_eq!(entry["pools"][0]["items"][0]["name"], "alt-1");
    assert_eq!(entry["pools"][0]["items"][0]["free"], true);

    let r = lease(a.who()).await;
    assert_eq!(r["status"], "granted", "{r}");
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(a.who(), &["cred", &grant]).await.ok();
    assert_eq!(cred["kind"], "pool_item");
    assert_eq!(
        cred["value"],
        "{\"email\": \"alt-1@example.org\", \"password\": \"pw\"}"
    );
    assert_eq!(cred["username"], "AltOne");
    assert_eq!(
        cred["properties"],
        json!({"item": "alt-1", "edition": "java", "username": "AltOne"})
    );

    // The only item "any" may pick is taken: the next agent's grant fails.
    let r = lease(c.who()).await;
    assert_eq!(r["status"], "provision_failed", "{r}");
    let why = r["decision_reason"].as_str().unwrap();
    assert!(
        why.contains("every matching item of pool minecraft is in use; the first frees at"),
        "{why}"
    );

    // Given back early, it is the next agent's.
    let out = b.cli(a.who(), &["release", &grant]).await.ok();
    assert_eq!(out, json!({"released": true}));
    let again = b.cli(a.who(), &["release", &grant]).await.ok();
    assert_eq!(again, json!({"released": false, "status": "revoked"}));
    let refused = b.cli(a.who(), &["cred", &grant]).await.refused();
    assert!(refused.starts_with("[403]"), "{refused}");
    // Nobody else releases a grant that is not theirs.
    let r = lease(c.who()).await;
    assert_eq!(r["status"], "granted", "{r}");
    let theirs = r["grant_id"].as_str().unwrap().to_owned();
    let not_mine = b.cli(a.who(), &["release", &theirs]).await.refused();
    assert!(not_mine.starts_with("[404]"), "{not_mine}");

    // The MCP tool gives it back too.
    let runtime = TempDir::new();
    let mut mcp = Mcp::start(b, &c.key, runtime.path()).await;
    let out = mcp
        .call_ok("release_grant", json!({"grant_id": theirs}))
        .await;
    assert_eq!(out, json!({"released": true}));
    let grants = b
        .cli(Who::Agent(&c.key), &["grants", "--status", "all"])
        .await
        .ok();
    assert!(
        grants
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["id"] == theirs.as_str() && g["status"] == "revoked"),
        "{grants}"
    );
}
