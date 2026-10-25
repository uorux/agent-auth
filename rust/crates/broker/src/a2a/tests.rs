//! In-crate tests that need the activity clock (a2a B3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::lifecycle::state;
use agent_auth_core::policy::Policy;
use agent_auth_core::{AgentId, Authority, GrantId, HumanApproval, RequestId, ThreadId};
use agent_auth_store::a2a::{self as store_a2a, CloseReason};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::requests::{self, AnyRequest, Approval, Escalation, NewRequest, Request};
use agent_auth_store::{Store, grants, lockdown};
use serde_json::{Map, json};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::service::{self, Actor, CloseKind};
use crate::auth::{AgentCaller, AgentCredentialKind, AuthConfig};
use crate::state::AppState;

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

async fn agent(store: &Store, name: &str) -> AgentRow {
    let tx = store.begin().await.unwrap();
    let id = AgentId::new();
    let row = agents::insert(
        &tx,
        &agents::NewAgent {
            id,
            name,
            description: "",
            key_id: &id.to_string()[..12],
            api_key_hash: &"0".repeat(64),
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: None,
            project: None,
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    agents::mark_listening(&tx, id, now(), now()).await.unwrap();
    tx.commit().await.unwrap();
    agents::get(&store.begin().await.unwrap(), id)
        .await
        .unwrap()
        .unwrap_or(row)
}

async fn grant(store: &Store, agent: &AgentRow, to: &str) {
    let authority = Authority::A2a { topic: None };
    let tx = store.begin().await.unwrap();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id: RequestId::new(),
            agent_id: agent.id,
            session_id: None,
            delegation: None,
            platform: authority.platform(),
            resource: to,
            requested_capability: "talk",
            requested_scope: &json!({}),
            authority: Some(&authority),
            justification: "x",
            requested_duration_secs: 3600,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap();
    let r = requests::transition::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now())
        .await
        .unwrap()
        .unwrap();
    let id = r.id();
    let approval = Approval::human(HumanApproval::attest(id, "jrt"), "ok", 3600);
    let r = requests::transition::<_, state::Approved>(&tx, r, approval, now())
        .await
        .unwrap()
        .unwrap();
    let r: Request<state::Provisioning> = requests::transition(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, agent.id, now())
        .await
        .unwrap()
        .unwrap();
    let g = grants::begin(&tx, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap();
    let g = grants::activate(&tx, g, &nh, &json!({}))
        .await
        .unwrap()
        .unwrap();
    drop(nh);
    let Some(AnyRequest::Provisioning(r)) = requests::get(&tx, g.request_id).await.unwrap() else {
        panic!()
    };
    requests::transition::<_, state::Granted>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
}

/// a2a B3: a write that commits after a later-stamped one is not skipped
/// by the cursor, and nothing is returned twice.
#[sqlx::test(migrations = "../store/migrations")]
async fn the_events_cursor_never_skips_a_late_commit(pool: PgPool) {
    let state = AppState::new(
        Store::from_pool(pool),
        Policy::default(),
        AuthConfig::default(),
    );
    let s = agent(&state.store, "auto-s").await;
    let r = agent(&state.store, "svc-r").await;
    grant(&state.store, &s, "svc-r").await;
    let sc = AgentCaller::new(s.clone(), None, AgentCredentialKind::ApiKey);
    let rc = AgentCaller::new(r.clone(), None, AgentCredentialKind::ApiKey);
    let actor = Actor::agent_caller(&sc);
    let a = service::open(&state, &actor, "svc-r", None, &Map::new())
        .await
        .unwrap()
        .thread_id;
    let b = service::open(&state, &actor, "svc-r", None, &Map::new())
        .await
        .unwrap()
        .thread_id;

    let first = service::events_snapshot(&state, &sc, None).await.unwrap();
    assert_eq!(first.activity.len(), 2);
    let c0 = first.cursor.unwrap();

    // A slow writer stamps first and commits last.
    let slow = state.store.begin().await.unwrap();
    let stamp = state.a2a.clock.stamp();
    store_a2a::close(&slow, a, CloseReason::Closed, Some(s.id), None, stamp.at)
        .await
        .unwrap()
        .unwrap();
    // A fast writer stamps later and commits at once.
    service::close(&state, &actor, b, CloseKind::Close, None)
        .await
        .unwrap();

    // The Python returned b here and moved the cursor past a's stamp.
    let held = service::events_snapshot(&state, &sc, Some(c0))
        .await
        .unwrap();
    assert!(
        held.activity.is_empty(),
        "held back until the slow writer ends"
    );
    assert_eq!(held.cursor, Some(c0));

    slow.commit().await.unwrap();
    drop(stamp);
    let both = service::events_snapshot(&state, &sc, Some(c0))
        .await
        .unwrap();
    let ids: Vec<ThreadId> = both.activity.iter().map(|t| t.thread_id).collect();
    assert_eq!(ids, [a, b]);
    let c1 = both.cursor.unwrap();
    assert_eq!(c1, both.activity[1].last_activity_at);
    let after = service::events_snapshot(&state, &sc, Some(c1))
        .await
        .unwrap();
    assert!(after.activity.is_empty(), "nothing twice");
    // The responder's view of the same.
    let rv = service::events_snapshot(&state, &rc, Some(c0))
        .await
        .unwrap();
    assert_eq!(rv.activity.len(), 2);
}
