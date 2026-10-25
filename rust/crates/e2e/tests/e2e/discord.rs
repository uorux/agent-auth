//! The operator on Discord: the bot configured from `./.env` as in the
//! README's quick start, a card for a request that needs a human, and the
//! owner's approval (with a shorter duration) through the gateway.

use std::time::Duration;

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::fakes;
use crate::harness::{Broker, TempDir, eventually};
use crate::world::{POLICY, World};

const OWNER: u64 = 42;

#[sqlx::test(migrations = false)]
async fn the_owner_approves_on_discord(_: PgPoolOptions, opts: PgConnectOptions) {
    let github = fakes::github().await;
    let openrouter = fakes::openrouter().await;
    let discord = fakes::discord().await;
    let files = TempDir::new();
    let setup = World::setup(&opts, POLICY, &github, &openrouter, &files)
        .dotenv("DISCORD_TOKEN", "e2e-discord-token")
        .dotenv("DISCORD_CHANNEL_ID", "5")
        .dotenv("DISCORD_OWNER_ID", &OWNER.to_string())
        .dotenv("DISCORD_API_URL", &format!("{}/api/v10", discord.rest.url))
        .dotenv("DISCORD_GATEWAY_URL", &discord.gateway_url);
    let b = Broker::start(setup).await;

    // The bot logged in with the token from ./.env and synced its commands.
    eventually(Duration::from_secs(10), "the bot identifies", || {
        let identified = discord
            .received
            .lock()
            .unwrap()
            .iter()
            .any(|f| f["op"] == 2 && f["d"]["token"] == "e2e-discord-token");
        async move { identified }
    })
    .await;
    eventually(Duration::from_secs(10), "slash commands synced", || {
        let synced = !discord.rest.calls_to("PUT", "/guilds/77/commands").is_empty();
        async move { synced }
    })
    .await;
    assert!(
        discord.rest.calls().iter().all(|c| c.authorization == "Bot e2e-discord-token"),
        "{:?}",
        discord.rest.calls()
    );

    let agent = b.create_agent("sde-d", &[]).await;
    let r = b
        .cli(
            agent.who(),
            &["request", "github", "repo", "acme/site", "--why", "fix the footer",
              "-s", r#"{"permissions": {"contents": "write"}}"#],
        )
        .await
        .ok();
    assert_eq!(r["status"], "awaiting_human", "{r}");
    let rid = r["id"].as_str().unwrap().to_owned();

    eventually(Duration::from_secs(10), "the card is posted", || {
        let posted = !discord.rest.calls_to("POST", "/channels/5/messages").is_empty();
        async move { posted }
    })
    .await;
    let card = discord.rest.calls_to("POST", "/channels/5/messages").remove(0).body;
    // (Names are markdown-escaped; Discord shows `sde-d`.)
    assert_eq!(card["content"], r"<@42> access request from **sde\-d**", "{card}");
    assert_eq!(
        card["components"][0]["components"][0]["custom_id"],
        json!(format!("aa:approve:{rid}")),
        "{card}"
    );

    // Someone else's click changes nothing.
    let stranger = discord.click(7, &format!("aa:approve:{rid}"));
    eventually(Duration::from_secs(10), "the stranger is answered", || {
        let answered = !discord.callbacks(&stranger).is_empty();
        async move { answered }
    })
    .await;
    assert_eq!(discord.callbacks(&stranger)[0]["data"]["flags"], 64);
    let r = b.cli(agent.who(), &["status", &rid]).await.ok();
    assert_eq!(r["status"], "awaiting_human", "{r}");

    // The owner's click opens the decision modal; submitting it decides.
    let click = discord.click(OWNER, &format!("aa:approve:{rid}"));
    eventually(Duration::from_secs(10), "the modal opens", || {
        let opened = !discord.callbacks(&click).is_empty();
        async move { opened }
    })
    .await;
    let modal = discord.callbacks(&click).remove(0);
    assert_eq!(modal["type"], 9, "{modal}");
    assert_eq!(modal["data"]["custom_id"], json!(format!("aa:decision:approve:{rid}")));
    discord.submit(
        OWNER,
        &format!("aa:decision:approve:{rid}"),
        &[("reason", "ok for today"), ("duration", "2h")],
    );
    let r = b.cli(agent.who(), &["wait", &rid, "--timeout", "10"]).await.ok();
    assert_eq!(r["status"], "granted", "{r}");
    assert_eq!(r["decision_source"], "human");
    assert_eq!(r["decision_reason"], "ok for today");
    assert_eq!(r["approved_duration_secs"], 7200);
    let grant = r["grant_id"].as_str().unwrap().to_owned();
    let cred = b.cli(agent.who(), &["cred", &grant]).await.ok();
    assert!(cred["value"].as_str().unwrap().starts_with("ghs_e2e_"), "{cred}");

    // The card shows the outcome.
    eventually(Duration::from_secs(10), "the card is updated", || {
        let edited = !discord.rest.calls_to("PATCH", "/channels/5/messages/900").is_empty();
        async move { edited }
    })
    .await;
}
