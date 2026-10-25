//! Platform `pool` through the request service against Postgres
//! (upstream tests/test_pool.py), plus concurrency for its caps.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use agent_auth_core::authority::Authority;
use agent_auth_core::policy::Policy;
use agent_auth_core::{GrantStatus, Platform, RequestStatus, RuleId};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::{self, NewRule, RuleAction};
use agent_auth_wire::agent::RequestCreate;
use serde_json::{Value, json};

use super::pool::PoolProvisioner;
use super::{AnyProvisioner, Provisioner, Registry};
use crate::auth::{AgentCaller, AgentCredentialKind};
use crate::service::tests::{make_agent, state_with};
use crate::service::{self};
use crate::state::AppState;

/// A directory of secret files for one test.
fn secrets_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agent-auth-pool-{}-{}",
        std::process::id(),
        agent_auth_core::GrantId::new()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["alt-1", "alt-2", "main"] {
        std::fs::write(
            dir.join(name),
            format!("{{\"email\": \"{name}@example.org\", \"password\": \"pw-{name}\"}}\n"),
        )
        .unwrap();
    }
    dir
}

fn pool_policy(dir: &std::path::Path, rules: bool) -> String {
    let secret = |n: &str| dir.join(n).display().to_string();
    let rules = if rules {
        "rules:\n  - {match: {platform: pool, capability: lease}, action: approve}\n"
    } else {
        ""
    };
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
          properties: {{edition: java, tags: [optifine, survival], username: AltOne}}
          secret_file: {}
        alt-2:
          properties: {{edition: bedrock, tags: [creative], username: AltTwo}}
          secret_file: {}
        main:
          properties: {{edition: java, username: TheMain}}
          secret_file: {}
          sensitive: true
    shared:
      capacity: 2
      max_per_agent: 2
      items: {{box: {{}}, box2: {{}}}}
{rules}"#,
        secret("alt-1"),
        secret("alt-2"),
        secret("main"),
    )
}

fn pool_state(pool: sqlx::PgPool, rules: bool) -> AppState {
    let dir = secrets_dir();
    let text = pool_policy(&dir, rules);
    let mut st = state_with(pool, &text);
    let policy = Policy::from_yaml(&text).unwrap();
    let mut reg = Registry::default();
    reg.register(AnyProvisioner::Pool(PoolProvisioner::new(
        &policy.platforms().pools,
    )));
    st.registry = Arc::new(reg);
    st
}

fn caller(a: &AgentRow) -> AgentCaller {
    AgentCaller::new(a.clone(), None, AgentCredentialKind::ApiKey)
}

async fn lease(st: &AppState, agent: &AgentRow, scope: Value, pool: &str) -> RequestRow {
    let body: RequestCreate = serde_json::from_value(json!({
        "platform": "pool", "capability": "lease", "resource": pool, "scope": scope,
        "justification": "play on the test server for the build task",
        "requested_duration": "2h",
    }))
    .unwrap();
    service::create(st, &caller(agent), body).await.unwrap()
}

async fn mc(st: &AppState, agent: &AgentRow, scope: Value) -> RequestRow {
    lease(st, agent, scope, "minecraft").await
}

async fn grant_of(st: &AppState, r: &RequestRow) -> GrantRow {
    let tx = st.store.begin().await.unwrap();
    grants::by_request(&tx, r.id).await.unwrap().unwrap()
}

fn item(g: &GrantRow) -> String {
    g.provisioner_state["item"].as_str().unwrap().to_owned()
}

fn reason(r: &RequestRow) -> String {
    r.decision_reason.clone().unwrap_or_default()
}

async fn credential(
    st: &AppState,
    g: &GrantRow,
) -> Result<super::Credential, super::ProvisionError> {
    let tx = st.store.begin().await.unwrap();
    let issuable = grants::issuable(&tx, g.agent_id, g.id, st.now())
        .await
        .unwrap()
        .map_err(|e| super::ProvisionError::failed(e.detail()))?;
    st.registry
        .get(Platform::Pool)
        .unwrap()
        .credential(&tx, &issuable, st.now())
        .await
}

async fn release(st: &AppState, g: &GrantRow) {
    service::revoke_grant(st, g.id, "released by the agent", "test")
        .await
        .unwrap();
}

async fn bot(st: &AppState, name: &str) -> AgentRow {
    make_agent(st, name, |_| {}).await
}

async fn lease_rows(st: &AppState, pool: &str) -> Vec<agent_auth_store::pool::LeaseRow> {
    let tx = st.store.begin().await.unwrap();
    agent_auth_store::pool::leases(&tx, pool).await.unwrap()
}

#[sqlx::test(migrations = "../store/migrations")]
async fn any_lease_gets_an_item_and_its_secret(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let r = mc(&st, &a, json!({})).await;
    assert_eq!(r.status, RequestStatus::Granted, "{}", reason(&r));
    let g = grant_of(&st, &r).await;
    assert_eq!(g.resource, "minecraft"); // the pool stays the resource
    let it = item(&g);
    assert!(["alt-1", "alt-2"].contains(&it.as_str()));
    let cred = credential(&st, &g).await.unwrap();
    assert_eq!(cred.kind, "pool_item");
    assert_eq!(
        cred.value.unwrap().expose(),
        &format!("{{\"email\": \"{it}@example.org\", \"password\": \"pw-{it}\"}}")
    );
    assert!(["AltOne", "AltTwo"].contains(&cred.username.as_deref().unwrap()));
    assert!(cred.note.unwrap().contains("release_grant"));
    let props = cred.properties.unwrap();
    assert_eq!(props["item"], json!(it));
    assert!(props.contains_key("edition"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn items_are_exclusive_and_sensitive_never_picked(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let (a, b, c) = (
        bot(&st, "bot-a").await,
        bot(&st, "bot-b").await,
        bot(&st, "bot-c").await,
    );
    let first = grant_of(&st, &mc(&st, &a, json!({})).await).await;
    let second = grant_of(&st, &mc(&st, &b, json!({})).await).await;
    let mut both = vec![item(&first), item(&second)];
    both.sort();
    assert_eq!(both, vec!["alt-1", "alt-2"]);
    let third = mc(&st, &c, json!({})).await;
    assert_eq!(third.status, RequestStatus::ProvisionFailed);
    let why = reason(&third);
    assert!(
        why.contains("in use") && why.contains("first frees"),
        "{why}"
    );
    // Releasing frees it for the next one.
    release(&st, &first).await;
    let again = mc(&st, &c, json!({})).await;
    assert_eq!(again.status, RequestStatus::Granted);
    assert_eq!(item(&grant_of(&st, &again).await), item(&first));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn previous_returns_the_same_item(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let first = grant_of(
        &st,
        &mc(&st, &a, json!({"match": {"edition": "bedrock"}})).await,
    )
    .await;
    assert_eq!(item(&first), "alt-2");
    release(&st, &first).await;
    let back = mc(&st, &a, json!({"previous": true})).await;
    assert_eq!(back.status, RequestStatus::Granted, "{}", reason(&back));
    let back = grant_of(&st, &back).await;
    assert_eq!(item(&back), "alt-2");
    // "any" also prefers the one held last.
    release(&st, &back).await;
    let any = grant_of(&st, &mc(&st, &a, json!({})).await).await;
    assert_eq!(item(&any), "alt-2");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn previous_without_history_is_denied(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let r = mc(&st, &a, json!({"previous": true})).await;
    assert_eq!(r.status, RequestStatus::Denied);
    let why = reason(&r);
    assert!(why.contains("not held") && why.contains("any"), "{why}");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn match_by_property_and_list_membership(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let r = mc(&st, &a, json!({"match": {"tags": "optifine"}})).await;
    assert_eq!(item(&grant_of(&st, &r).await), "alt-1");
    let b = bot(&st, "bot-b").await;
    let r = mc(
        &st,
        &b,
        json!({"match": {"tags": ["optifine", "survival"], "edition": "java"}}),
    )
    .await;
    // alt-1 is taken, main is sensitive: nothing for "any".
    assert_eq!(r.status, RequestStatus::ProvisionFailed);
    let c = bot(&st, "bot-c").await;
    let none = mc(&st, &c, json!({"match": {"edition": "pocket"}})).await;
    assert_eq!(none.status, RequestStatus::Denied);
    assert!(reason(&none).contains("no item"), "{}", reason(&none));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn sensitive_item_by_name_surfaces(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let only_main = mc(&st, &a, json!({"match": {"username": "TheMain"}})).await;
    assert_eq!(only_main.status, RequestStatus::Denied); // "any" never picks it
    let named = mc(&st, &a, json!({"item": "main"})).await;
    assert_eq!(named.status, RequestStatus::AwaitingHuman); // despite the rule
    assert!(
        named
            .risk_notes
            .iter()
            .any(|n| n.contains("a sensitive item")),
        "{:?}",
        named.risk_notes
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn max_per_agent_and_capacity(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    mc(&st, &a, json!({})).await;
    let second = mc(&st, &a, json!({})).await;
    assert_eq!(second.status, RequestStatus::ProvisionFailed);
    assert!(reason(&second).contains("at most 1"), "{}", reason(&second));
    assert!(
        second
            .risk_notes
            .iter()
            .any(|n| n.contains("this fails unless one is released first")),
        "{:?}",
        second.risk_notes
    );
    // shared: two holders per item, two items per agent.
    let mut holders = Vec::new();
    for name in ["x-1", "x-2"] {
        let agent = bot(&st, name).await;
        let r = lease(&st, &agent, json!({"item": "box"}), "shared").await;
        assert_eq!(r.status, RequestStatus::Granted, "{}", reason(&r));
        holders.push(grant_of(&st, &r).await);
    }
    let mut slots: Vec<i64> = holders
        .iter()
        .map(|g| g.provisioner_state["slot"].as_i64().unwrap())
        .collect();
    slots.sort_unstable();
    assert_eq!(slots, vec![0, 1]);
    let third = bot(&st, "x-3").await;
    let full = lease(&st, &third, json!({"item": "box"}), "shared").await;
    assert_eq!(full.status, RequestStatus::ProvisionFailed);
    assert_eq!(
        lease_rows(&st, "shared")
            .await
            .iter()
            .filter(|l| l.item == "box")
            .count(),
        2
    );
    // One agent holds two items of "shared", never two slots of one.
    let x1 = &holders[0];
    let again = lease(&st, &bot(&st, "x-9").await, json!({}), "shared").await;
    assert_eq!(again.status, RequestStatus::Granted);
    let owner = {
        let tx = st.store.begin().await.unwrap();
        agent_auth_store::agents::get(&tx, x1.agent_id)
            .await
            .unwrap()
            .unwrap()
    };
    let same = lease(&st, &owner, json!({"item": "box"}), "shared").await;
    assert_eq!(same.status, RequestStatus::ProvisionFailed);
    assert!(
        reason(&same).contains("you already hold box of pool shared"),
        "{}",
        reason(&same)
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn agent_not_admitted(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let other = bot(&st, "someone-else").await;
    let r = mc(&st, &other, json!({})).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(reason(&r).contains("not open"), "{}", reason(&r));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn unknown_pool_and_bad_scope(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let r = lease(&st, &a, json!({}), "nope").await;
    assert!(reason(&r).contains("no pool"), "{}", reason(&r));
    let bad = mc(&st, &a, json!({"item": "alt-1", "previous": true})).await;
    assert_eq!(bad.status, RequestStatus::Denied);
    let bad = mc(&st, &a, json!({"colour": "red"})).await;
    assert_eq!(bad.status, RequestStatus::Denied);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn revoke_deletes_the_lease(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let g = grant_of(&st, &mc(&st, &a, json!({})).await).await;
    release(&st, &g).await;
    assert!(lease_rows(&st, "minecraft").await.is_empty());
    let tx = st.store.begin().await.unwrap();
    let ended = grants::get(&tx, g.id).await.unwrap().unwrap();
    drop(tx);
    assert_eq!(ended.status, GrantStatus::Revoked);
    assert!(credential(&st, &g).await.is_err());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn saved_rule_does_not_lease_a_named_item(pool: sqlx::PgPool) {
    let st = pool_state(pool, false);
    let a = bot(&st, "bot-a").await;
    let java = Authority::from_wire(
        Platform::Pool,
        "lease",
        json!({"match": {"edition": "java"}}).as_object().unwrap(),
    )
    .unwrap();
    let tx = st.store.begin().await.unwrap();
    rules::insert(
        &tx,
        &NewRule {
            id: RuleId::new(),
            action: RuleAction::AutoApprove,
            agent_pattern: "bot-a",
            delegator_pattern: None,
            platform: Platform::Pool,
            resource_pattern: "minecraft",
            authority: Some(&java),
            max_duration_secs: None,
            created_by: "jrt",
            notes: "",
            expires_at: None,
            now: st.now(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let ok = mc(
        &st,
        &a,
        json!({"match": {"edition": "java", "tags": "optifine"}}),
    )
    .await;
    assert_eq!(ok.status, RequestStatus::Granted, "{}", reason(&ok));
    let named = mc(&st, &a, json!({"item": "alt-1"})).await;
    assert_eq!(named.status, RequestStatus::AwaitingHuman);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn pool_status_lists_what_the_agent_may_hold(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let g = grant_of(&st, &mc(&st, &a, json!({})).await).await;
    let stranger = bot(&st, "stranger").await;
    let Some(AnyProvisioner::Pool(p)) = st.registry.get(Platform::Pool) else {
        panic!("pool provisioner")
    };
    let tx = st.store.begin().await.unwrap();
    let status = p.status(&tx, &a).await.unwrap();
    let hidden = p.status(&tx, &stranger).await.unwrap();
    let mc = status.iter().find(|p| p.name == "minecraft").unwrap();
    let held = mc.items.iter().find(|i| i.name == item(&g)).unwrap();
    assert!(held.yours && !held.free && held.frees_at.is_some());
    assert_eq!(held.in_use, 1);
    assert_eq!(mc.you_held_last.as_deref(), Some(item(&g).as_str()));
    let names: Vec<&str> = hidden.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["shared"]);
}

/// Many agents asking for one item at once: never more holders than the
/// capacity, and nothing deadlocks.
#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_leases_never_exceed_capacity(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let mut agents = Vec::new();
    for i in 0..12 {
        agents.push(bot(&st, &format!("c-{i}")).await);
    }
    let mut tasks = Vec::new();
    for a in agents {
        let st = st.clone();
        tasks.push(tokio::spawn(async move {
            lease(&st, &a, json!({"item": "box"}), "shared").await
        }));
    }
    let mut granted = 0;
    for t in tasks {
        let r = t.await.unwrap();
        match r.status {
            RequestStatus::Granted => granted += 1,
            RequestStatus::ProvisionFailed => {
                assert!(reason(&r).contains("in use"), "{}", reason(&r));
            }
            other => panic!("{other:?}: {}", reason(&r)),
        }
    }
    assert_eq!(granted, 2);
    let leases = lease_rows(&st, "shared").await;
    assert_eq!(leases.len(), 2);
    let mut slots: Vec<u32> = leases.iter().map(|l| l.slot).collect();
    slots.sort_unstable();
    assert_eq!(slots, vec![0, 1]);
}

/// One agent asking for many items of a pool at once: never more than
/// `max_per_agent`, never two slots of one item.
#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_leases_never_exceed_max_per_agent(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "greedy").await;
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (st, a) = (st.clone(), a.clone());
        tasks.push(tokio::spawn(async move {
            lease(&st, &a, json!({}), "shared").await
        }));
    }
    let mut granted = 0;
    for t in tasks {
        if t.await.unwrap().status == RequestStatus::Granted {
            granted += 1;
        }
    }
    assert_eq!(granted, 2);
    let leases = lease_rows(&st, "shared").await;
    let per_item: BTreeMap<&str, usize> = leases.iter().fold(BTreeMap::new(), |mut m, l| {
        *m.entry(l.item.as_str()).or_default() += 1;
        m
    });
    assert_eq!(per_item.len(), 2, "{per_item:?}");
    assert!(per_item.values().all(|n| *n == 1));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_catalog_lists_the_pools_an_agent_may_lease_from(pool: sqlx::PgPool) {
    let st = pool_state(pool, true);
    let a = bot(&st, "bot-a").await;
    let out = crate::http::catalog::catalog(&st, &a).await.unwrap();
    let entry = out["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["platform"] == "pool")
        .unwrap()
        .clone();
    assert_eq!(entry["capabilities"], json!(["lease (auto-approve)"]));
    assert_eq!(entry["resource_hint"], "<pool>");
    let names: Vec<&str> = entry["pools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["minecraft", "shared"]);
    let alt = &entry["pools"][0]["items"][0];
    assert_eq!(alt["name"], "alt-1");
    assert_eq!(alt["properties"]["tags"], json!(["optifine", "survival"]));
    assert_eq!(alt["free"], true);
    assert_eq!(alt["frees_at"], Value::Null);
    // An agent no pool admits sees no pool entry.
    let b = make_agent(&st, "nobody", |_| {}).await;
    let mut st2 = st.clone();
    let text = pool_policy(&secrets_dir(), true).replace(
        "items: {box: {}, box2: {}}",
        "agents: [\"bot-*\"]\n      items: {box: {}}",
    );
    let policy = Policy::from_yaml(&text).unwrap();
    let mut reg = Registry::default();
    reg.register(AnyProvisioner::Pool(PoolProvisioner::new(
        &policy.platforms().pools,
    )));
    st2.registry = Arc::new(reg);
    let out = crate::http::catalog::catalog(&st2, &b).await.unwrap();
    assert!(
        !out["platforms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["platform"] == "pool"),
        "{out}"
    );
}
