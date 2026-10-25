//! Pool leases: the unique constraints are the guard (a refused insert
//! does not break the transaction), and the insert trigger.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use agent_auth_core::Authority;
use agent_auth_core::containment::AgentKind;
use agent_auth_core::pool::{PoolChoice, PropMatch};
use agent_auth_store::Store;
use agent_auth_store::grants::GrantRow;
use agent_auth_store::pool::{self, NewLease};
use common::*;
use sqlx::PgPool;

fn any() -> Authority {
    Authority::Pool(PoolChoice::Any(PropMatch::new()))
}

async fn pool_grant(store: &Store, agent: &str, active: bool) -> GrantRow {
    let a = common::agent(store, agent, AgentKind::Service).await;
    let r = awaiting_on(store, a.id, &any(), "minecraft", None).await;
    if active {
        active_grant(store, r).await
    } else {
        provisioning_grant(store, r).await
    }
}

fn lease<'a>(g: &GrantRow, item: &'a str, slot: u32, agent_slot: u32) -> NewLease<'a> {
    NewLease {
        pool: "minecraft",
        item,
        slot,
        agent_slot,
        grant_id: g.id,
        agent_id: g.agent_id,
        now: now(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn a_taken_slot_is_refused_without_breaking_the_transaction(pool: PgPool) {
    let store = Store::from_pool(pool);
    let first = pool_grant(&store, "bot-a", false).await;
    let second = pool_grant(&store, "bot-b", false).await;
    let tx = store.begin().await.unwrap();
    assert!(
        pool::take(&tx, &lease(&first, "alt-1", 0, 0))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let tx = store.begin().await.unwrap();
    // The same slot of the same item: refused, and the transaction lives on.
    assert!(
        !pool::take(&tx, &lease(&second, "alt-1", 0, 0))
            .await
            .unwrap()
    );
    assert!(
        pool::take(&tx, &lease(&second, "alt-2", 0, 0))
            .await
            .unwrap()
    );
    // One lease per grant.
    assert!(
        !pool::take(&tx, &lease(&second, "alt-3", 0, 1))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let tx = store.begin().await.unwrap();
    let leases = pool::leases(&tx, "minecraft").await.unwrap();
    assert_eq!(leases.len(), 2);
    assert_eq!(pool::release(&tx, first.id).await.unwrap(), 1);
    assert_eq!(pool::leases(&tx, "minecraft").await.unwrap().len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn one_agent_slot_per_lease(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = common::agent(&store, "bot-a", AgentKind::Service).await;
    let r1 = awaiting_on(&store, a.id, &any(), "minecraft", None).await;
    let r2 = awaiting_on(&store, a.id, &any(), "minecraft", None).await;
    let g1 = provisioning_grant(&store, r1).await;
    let g2 = provisioning_grant(&store, r2).await;
    let tx = store.begin().await.unwrap();
    assert!(pool::take(&tx, &lease(&g1, "alt-1", 0, 0)).await.unwrap());
    // Agent slot 0 of the pool is held: max_per_agent cannot be passed.
    assert!(!pool::take(&tx, &lease(&g2, "alt-2", 0, 0)).await.unwrap());
    assert!(pool::take(&tx, &lease(&g2, "alt-2", 0, 1)).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_lease_needs_a_pool_grant_being_provisioned(pool: PgPool) {
    let store = Store::from_pool(pool);
    let active = pool_grant(&store, "bot-a", true).await;
    let tx = store.begin().await.unwrap();
    let e = pool::take(&tx, &lease(&active, "alt-1", 0, 0))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("a pool lease needs"), "{e}");
    drop(tx);
    let other = common::agent(&store, "bot-b", AgentKind::Service).await;
    let r = awaiting(&store, other.id, &homelab()).await;
    let g = provisioning_grant(&store, r).await;
    let tx = store.begin().await.unwrap();
    assert!(pool::take(&tx, &lease(&g, "alt-1", 0, 0)).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn ended_grants_free_their_slots_and_last_held(pool: PgPool) {
    let store = Store::from_pool(pool);
    let g = pool_grant(&store, "bot-a", false).await;
    let tx = store.begin().await.unwrap();
    assert!(pool::take(&tx, &lease(&g, "alt-1", 0, 0)).await.unwrap());
    tx.commit().await.unwrap();
    // A grant ended without its revoke (out of band): its lease is cleared.
    let tx = store.begin().await.unwrap();
    let pg = agent_auth_store::grants::load_provisioning(&tx, g.id)
        .await
        .unwrap()
        .unwrap();
    let _ = agent_auth_store::grants::fail_provisioning(&tx, pg, "x", None)
        .await
        .unwrap();
    assert_eq!(pool::clear_ended(&tx, "minecraft").await.unwrap(), 1);
    assert!(pool::leases(&tx, "minecraft").await.unwrap().is_empty());
    assert_eq!(
        pool::last_held(&tx, g.agent_id, "minecraft", None)
            .await
            .unwrap(),
        None
    );
}
