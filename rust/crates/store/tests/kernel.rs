//! Containment checks, grant creation and credential issuance.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::Duration as StdDuration;

use agent_auth_core::containment::AgentKind;
use agent_auth_core::lifecycle::state;
use agent_auth_core::{GrantId, GrantStatus, MessageId, ThreadId};
use agent_auth_store::a2a::{self, NewThread};
use agent_auth_store::grants::{self, BeginRefused, GrantEnd, NotIssuable};
use agent_auth_store::lockdown::{self, ContainmentSource, Held, NewEntry};
use agent_auth_store::requests::{self, AnyRequest};
use agent_auth_store::{Delegation, Store, StoreError};
use common::*;
use serde_json::json;
use sqlx::PgPool;

async fn contain(store: &Store, id: &str, m: serde_json::Value) {
    let tx = store.begin().await.unwrap();
    lockdown::record(
        &tx,
        &NewEntry {
            id,
            r#match: &m,
            reason: "testing",
            evidence: "",
            by: "jrt",
            source: ContainmentSource::Operator,
            at: now(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn containment_holds_by_attributes_and_spares_the_operator(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "claude-a", AgentKind::Service).await;
    contain(&store, "0000000a", json!({"project": "agent-auth"})).await;
    let tx = store.begin().await.unwrap();
    match lockdown::check(&tx, a.id, now()).await.unwrap() {
        Err(Held::Contained(e)) => {
            assert_eq!(e.id, "0000000a");
            assert_eq!(e.held_text(), "contained (0000000a): testing");
        }
        other => panic!("{other:?}"),
    }
    let op = agents_operator(&tx).await;
    assert!(lockdown::check(&tx, op, now()).await.unwrap().is_ok());
}

async fn agents_operator(tx: &agent_auth_store::Tx<'_>) -> agent_auth_core::AgentId {
    agent_auth_store::agents::ensure_operator(
        tx,
        agent_auth_core::AgentId::new(),
        "op0000000000",
        now(),
    )
    .await
    .unwrap()
    .unwrap()
    .id
}

#[sqlx::test(migrations = "./migrations")]
async fn an_entry_that_does_not_parse_holds_everyone(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "anyone", AgentKind::Ephemeral).await;
    // record() refuses it...
    let tx = store.begin().await.unwrap();
    let refused = lockdown::record(
        &tx,
        &NewEntry {
            id: "0000000b",
            r#match: &json!({"agnet": "x"}),
            reason: "",
            evidence: "",
            by: "jrt",
            source: ContainmentSource::Operator,
            at: now(),
        },
    )
    .await
    .unwrap();
    assert!(refused.is_err());
    drop(tx);
    // ...but if one is in the table anyway, it holds every agent (fail closed).
    sqlx::query(
        "INSERT INTO containment_entries (id, match, reason, created_by, source, at)
         VALUES ('0000000c', '{\"agnet\": \"x\"}', '', 'db', '', now())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let tx = store.begin().await.unwrap();
    let held = lockdown::check(&tx, a.id, now())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(held.text(), "contained (0000000c): by the operator");
    let op = agents_operator(&tx).await;
    assert!(lockdown::check(&tx, op, now()).await.unwrap().is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn disabled_and_lapsed_agents_are_held(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "off", AgentKind::Service).await;
    let tx = store.begin().await.unwrap();
    agent_auth_store::agents::set_disabled(&tx, a.id, true)
        .await
        .unwrap();
    assert!(matches!(
        lockdown::check(&tx, a.id, now()).await.unwrap(),
        Err(Held::Disabled)
    ));
    assert!(matches!(
        lockdown::check(&tx, agent_auth_core::AgentId::new(), now())
            .await
            .unwrap(),
        Err(Held::Unknown)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn recording_containment_waits_for_in_flight_checks(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "inflight", AgentKind::Service).await;
    let tx1 = store.begin().await.unwrap();
    let nh = lockdown::check(&tx1, a.id, now()).await.unwrap().unwrap();
    let s2 = store.clone();
    let recorder = tokio::spawn(async move { contain(&s2, "0000000d", json!({})).await });
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    assert!(
        !recorder.is_finished(),
        "record must wait for the check's transaction"
    );
    drop(nh);
    tx1.commit().await.unwrap();
    recorder.await.unwrap();
    let tx = store.begin().await.unwrap();
    assert!(lockdown::check(&tx, a.id, now()).await.unwrap().is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_proof_from_another_transaction_or_agent_is_refused(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "proof-a", AgentKind::Service).await;
    let b = agent(&store, "proof-b", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;

    let other = store.begin().await.unwrap();
    let foreign = lockdown::check(&other, a.id, now()).await.unwrap().unwrap();

    let tx = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, id).await.unwrap() else {
        panic!()
    };
    let r = requests::transition::<_, state::Approved>(&tx, r, approval(60), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::Provisioning>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let err = grants::begin(&tx, &r, &foreign, GrantId::new(), now())
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof));
    let wrong_agent = lockdown::check(&tx, b.id, now()).await.unwrap().unwrap();
    let err = grants::begin(&tx, &r, &wrong_agent, GrantId::new(), now())
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof));
    let right = lockdown::check(&tx, a.id, now()).await.unwrap().unwrap();
    let g = grants::begin(&tx, &r, &right, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(g.status, GrantStatus::Provisioning);
    assert_eq!(g.resource, "svc-gitea");
    // One grant per request.
    let err = grants::begin(&tx, &r, &right, GrantId::new(), now())
        .await
        .unwrap_err();
    assert!(err.is_unique_violation(), "{err:?}");
}

#[sqlx::test(migrations = "./migrations")]
async fn grant_status_changes_are_compare_and_swap(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "cas", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;
    let g = provisioning_grant(&store, id).await;

    // The reaper fails it; a late activation then loses (core B-9).
    let tx = store.begin().await.unwrap();
    grants::fail_provisioning(&tx, g.id, "interrupted", Some(now()))
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, a.id, now()).await.unwrap().unwrap();
    assert!(
        grants::activate(&tx, g.id, &nh, &json!({}))
            .await
            .unwrap()
            .is_err()
    );
    drop(nh);
    tx.commit().await.unwrap();

    // A revoke racing an expiry ends the grant once.
    let id2 = awaiting(&store, a.id, &homelab()).await;
    let g2 = active_grant(&store, id2).await;
    let mut tasks = Vec::new();
    for i in 0..6 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let how = if i % 2 == 0 {
                GrantEnd::Expired
            } else {
                GrantEnd::Revoked {
                    reason: "revoked by admin".into(),
                }
            };
            let out = grants::end(&tx, g2.id, how, now()).await.unwrap();
            tx.commit().await.unwrap();
            out.is_ok()
        }));
    }
    let mut won = 0;
    for t in tasks {
        if t.await.unwrap() {
            won += 1;
        }
    }
    assert_eq!(won, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn issuable_refuses_each_way_it_should(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "issuer", AgentKind::Service).await;
    let other = agent(&store, "stranger", AgentKind::Service).await;

    // Provisioning: not active.
    let id = awaiting(&store, a.id, &homelab()).await;
    let g = provisioning_grant(&store, id).await;
    let tx = store.begin().await.unwrap();
    let e = grants::issuable(&tx, a.id, g.id, now())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(e.detail(), "grant is not active");
    drop(tx);

    // Active: issuable to its owner only.
    let id = awaiting(&store, a.id, &homelab()).await;
    let g = active_grant(&store, id).await;
    let tx = store.begin().await.unwrap();
    let ok = grants::issuable(&tx, a.id, g.id, now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ok.grant().id, g.id);
    drop(ok);
    let e = grants::issuable(&tx, other.id, g.id, now())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.is_not_found());
    assert_eq!(e.detail(), "unknown grant");
    let e = grants::issuable(&tx, a.id, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, NotIssuable::UnknownGrant));
    drop(tx);

    // Expired by the clock even though still ACTIVE.
    let tx = store.begin().await.unwrap();
    let later = now() + hours(2);
    let e = grants::issuable(&tx, a.id, g.id, later)
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, NotIssuable::NotActive { .. }));
    drop(tx);

    // Contained.
    contain(&store, "0000000e", json!({"name": "issuer"})).await;
    let tx = store.begin().await.unwrap();
    let e = grants::issuable(&tx, a.id, g.id, now())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        e.detail(),
        "contained (0000000e): credentials are not issued"
    );
    // Ownership is checked before containment.
    let e = grants::issuable(&tx, a.id, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.is_not_found());
}

/// Two agents, an a2a grant from `initiator` to `responder`, and an open
/// thread on it.
async fn open_thread(
    store: &Store,
) -> (
    agent_auth_store::agents::AgentRow,
    agent_auth_store::agents::AgentRow,
    ThreadId,
    GrantId,
) {
    let initiator = agent(store, "asker", AgentKind::Service).await;
    let responder = agent(store, "doer", AgentKind::Service).await;
    let rid = awaiting_on(store, initiator.id, &a2a(), "doer", None).await;
    let backing = active_grant(store, rid).await;
    let tx = store.begin().await.unwrap();
    let clear = lockdown::check_pair(&tx, initiator.id, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    let thread = ThreadId::new();
    a2a::open(
        &tx,
        &clear,
        &NewThread {
            id: thread,
            initiator: initiator.id,
            initiator_session: None,
            responder: responder.id,
            topic: Some("deploy"),
            grant_id: Some(backing.id),
            message_id: MessageId::new(),
            payload: r#"{"type": "message", "text": "hi"}"#,
            now: now(),
        },
    )
    .await
    .unwrap();
    a2a::accept(&tx, &clear, thread, None, now())
        .await
        .unwrap()
        .unwrap();
    drop(clear);
    tx.commit().await.unwrap();
    (initiator, responder, thread, backing.id)
}

#[sqlx::test(migrations = "./migrations")]
async fn delegated_grants_live_and_die_with_their_thread(pool: PgPool) {
    let store = Store::from_pool(pool);
    let (initiator, responder, thread, backing) = open_thread(&store).await;
    let delegation = Some(Delegation {
        thread_id: thread,
        delegator_agent_id: initiator.id,
    });

    // The delegated grant is clamped to the backing grant's expiry (1 h).
    let rid = awaiting_on(&store, responder.id, &homelab(), "svc-gitea", delegation).await;
    let tx = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, rid).await.unwrap() else {
        panic!()
    };
    let r = requests::transition::<_, state::Approved>(&tx, r, approval(30 * 86400), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::Provisioning>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    let g = grants::begin(&tx, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap();
    let b = grants::get(&tx, backing).await.unwrap().unwrap();
    assert_eq!(g.expires_at, b.expires_at);
    let g = grants::activate(&tx, g.id, &nh, &json!({}))
        .await
        .unwrap()
        .unwrap();
    drop(nh);
    tx.commit().await.unwrap();

    let tx = store.begin().await.unwrap();
    assert!(
        grants::issuable(&tx, responder.id, g.id, now())
            .await
            .unwrap()
            .is_ok()
    );
    drop(tx);

    // The thread closes: no credential, and no new delegated grant.
    let tx = store.begin().await.unwrap();
    a2a::close(
        &tx,
        thread,
        a2a::CloseReason::Closed,
        Some(initiator.id),
        None,
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    let tx = store.begin().await.unwrap();
    let e = grants::issuable(&tx, responder.id, g.id, now())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        e.detail(),
        "delegation thread is closed; credential no longer issuable"
    );
    assert_eq!(
        grants::delegated_on_closed_threads(&tx).await.unwrap(),
        vec![(g.id, Some("closed".to_owned()))]
    );
    drop(tx);

    let rid = awaiting_on(&store, responder.id, &homelab(), "svc-gitea", delegation).await;
    let tx = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, rid).await.unwrap() else {
        panic!()
    };
    let r = requests::transition::<_, state::Approved>(&tx, r, approval(60), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::Provisioning>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    let refused = grants::begin(&tx, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(refused, BeginRefused::DelegationClosed);
}
