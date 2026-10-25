//! The request state machine against the database: compare-and-swap,
//! what each transition writes, and the database's own guards.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use agent_auth_core::containment::AgentKind;
use agent_auth_core::lifecycle::state;
use agent_auth_core::{DecisionSource, RequestId, RequestStatus};
use agent_auth_store::requests::{
    self, AnyRequest, Denial, Escalation, LlmDenial, LlmRound, NewRequest, ProvisionFailure,
};
use agent_auth_store::{Store, StoreError};
use common::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn exactly_one_racing_transition_wins(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "racer", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;

    let mut tasks = Vec::new();
    for i in 0..8u32 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, id).await.unwrap() else {
                return None; // someone already committed
            };
            // Hold the snapshot for a moment so the racers overlap.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let won = if i % 2 == 0 {
                requests::transition::<_, state::Approved>(&tx, r, approval(60), now())
                    .await
                    .unwrap()
                    .map(|_| RequestStatus::Approved)
            } else {
                requests::transition::<_, state::Denied>(
                    &tx,
                    r,
                    Denial {
                        source: DecisionSource::Human,
                        decided_by: Some("jrt".into()),
                        reason: "no".into(),
                    },
                    now(),
                )
                .await
                .unwrap()
                .map(|_| RequestStatus::Denied)
            };
            tx.commit().await.unwrap();
            won.ok()
        }));
    }
    let mut winners = Vec::new();
    for t in tasks {
        if let Some(s) = t.await.unwrap() {
            winners.push(s);
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    let tx = store.begin().await.unwrap();
    let r = requests::get(&tx, id).await.unwrap().unwrap();
    assert_eq!(r.status(), winners[0]);
}

#[sqlx::test(migrations = "./migrations")]
async fn lost_when_moved_by_another_transaction(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "slow", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;

    let tx1 = store.begin().await.unwrap();
    let tx2 = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r1)) = requests::get(&tx1, id).await.unwrap() else {
        panic!()
    };
    let Some(AnyRequest::AwaitingHuman(r2)) = requests::get(&tx2, id).await.unwrap() else {
        panic!()
    };
    requests::transition::<_, state::Approved>(&tx1, r1, approval(60), now())
        .await
        .unwrap()
        .unwrap();
    // tx2's UPDATE waits for tx1's row lock, then re-checks the status.
    let second = tokio::spawn(async move {
        let out = requests::transition::<_, state::Approved>(&tx2, r2, approval(60), now())
            .await
            .unwrap();
        tx2.rollback().await.unwrap();
        out.map(|_| ())
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tx1.commit().await.unwrap();
    let lost = second.await.unwrap().unwrap_err();
    assert_eq!(lost.id, id);
}

#[sqlx::test(migrations = "./migrations")]
async fn transitions_write_what_their_state_requires(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "writer", AgentKind::Service).await;
    let tx = store.begin().await.unwrap();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id: RequestId::new(),
            agent_id: a.id,
            session_id: None,
            delegation: None,
            platform: homelab().platform(),
            resource: "svc-gitea",
            requested_capability: "member",
            requested_scope: &json!({}),
            authority: Some(&homelab()),
            justification: "first",
            requested_duration_secs: 3600,
            risk_notes: &["validator note".to_owned()],
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(r.row().attempt, 0);
    let r = requests::transition::<_, state::LlmEvaluating>(&tx, r, LlmRound::default(), now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.row().attempt, 1);
    let r = requests::transition::<_, state::LlmDenied>(
        &tx,
        r,
        LlmDenial {
            model: "test/judge".into(),
            reasoning: "too broad".into(),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.row().decision_source, Some(DecisionSource::Llm));
    assert_eq!(r.row().decided_by.as_deref(), Some("test/judge"));
    let r = requests::transition::<_, state::LlmEvaluating>(
        &tx,
        r,
        LlmRound {
            justification: Some("second".into()),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.row().attempt, 2);
    assert_eq!(r.row().justification, "second");
    let r = requests::transition::<_, state::AwaitingHuman>(
        &tx,
        r,
        Escalation {
            note: Some("LLM evaluation failed; escalating to human review".into()),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        r.row().risk_notes,
        vec![
            "validator note".to_owned(),
            "LLM evaluation failed; escalating to human review".to_owned()
        ]
    );
    let r = requests::transition::<_, state::Approved>(&tx, r, approval(1800), now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.row().approved_duration_secs, Some(1800));
    assert_eq!(r.row().decision_source, Some(DecisionSource::Human));
    assert!(r.row().decided_at.is_some());
    let r = requests::transition::<_, state::Provisioning>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::ProvisionFailed>(
        &tx,
        r,
        ProvisionFailure {
            why: "contained (abcd0123): x".into(),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        r.row().decision_reason.as_deref(),
        Some("ok | provisioning failed: contained (abcd0123): x")
    );
    requests::append_note(&tx, r.id(), "late note")
        .await
        .unwrap();
    let row = requests::get(&tx, r.id())
        .await
        .unwrap()
        .unwrap()
        .into_row();
    assert_eq!(row.risk_notes.last().map(String::as_str), Some("late note"));
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn the_database_refuses_edges_the_machine_does_not_have(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "guarded", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;
    // Straight to GRANTED, bypassing the kernel: the trigger refuses.
    let err = sqlx::query("UPDATE access_requests SET status = 'granted' WHERE id = $1")
        .bind(uuid::Uuid::from(id))
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(StoreError::from(err).is_check_violation());
    // APPROVED without who/when/how long: the CHECK refuses.
    let err = sqlx::query("UPDATE access_requests SET status = 'approved' WHERE id = $1")
        .bind(uuid::Uuid::from(id))
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(StoreError::from(err).is_check_violation());
    // A row inserted in any status but PENDING.
    let err = sqlx::query(
        "INSERT INTO access_requests (id, agent_id, platform, resource, requested_capability,
             requested_scope, authority, justification, requested_duration_secs, status,
             decision_source, decided_at)
         VALUES (gen_random_uuid(), $1, 'homelab', 'x', 'member', '{}', '{}', 'j', 60, 'denied',
                 'policy', now())",
    )
    .bind(uuid::Uuid::from(a.id))
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(StoreError::from(err).is_check_violation());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_corrupt_row_is_an_error_not_a_default(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "corrupt", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;
    // An authority this version would not have written.
    sqlx::query("UPDATE access_requests SET authority = '{\"role\": \"admin\"}' WHERE id = $1")
        .bind(uuid::Uuid::from(id))
        .execute(&pool)
        .await
        .unwrap();
    let tx = store.begin().await.unwrap();
    let err = requests::get(&tx, id).await.unwrap_err();
    assert!(matches!(err, StoreError::Corrupt { .. }), "{err:?}");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_request_refused_before_parsing_has_no_authority(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "unparsed", AgentKind::Service).await;
    let tx = store.begin().await.unwrap();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id: RequestId::new(),
            agent_id: a.id,
            session_id: None,
            delegation: None,
            platform: homelab().platform(),
            resource: "svc-gitea",
            requested_capability: "nonsense",
            requested_scope: &json!({"x": 1}),
            authority: None,
            justification: "j",
            requested_duration_secs: 60,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap();
    // It can be denied...
    let d = requests::transition::<_, state::Denied>(
        &tx,
        r,
        Denial {
            source: DecisionSource::Policy,
            decided_by: None,
            reason: "validator: unknown capability".into(),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(d.row().authority.is_none());
    assert_eq!(d.row().requested_scope, json!({"x": 1}));
    tx.commit().await.unwrap();

    // ...but never routed anywhere else.
    let tx = store.begin().await.unwrap();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id: RequestId::new(),
            agent_id: a.id,
            session_id: None,
            delegation: None,
            platform: homelab().platform(),
            resource: "svc-gitea",
            requested_capability: "nonsense",
            requested_scope: &json!({}),
            authority: None,
            justification: "j",
            requested_duration_secs: 60,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap();
    let err = requests::transition::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now())
        .await
        .unwrap_err();
    assert!(err.is_check_violation(), "{err:?}");
}
