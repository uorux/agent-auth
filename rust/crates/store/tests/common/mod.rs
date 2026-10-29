//! Fixtures shared by the database tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::lifecycle::state;
use agent_auth_core::policy::{AgentRef, Delegation as PolicyDelegation, PolicyInput};
use agent_auth_core::zones::{self, ZoneFacts};
use agent_auth_core::{AgentId, Authority, GrantId, Platform, RequestId};
use agent_auth_core::{AutoClearance, HumanApproval, LlmClearance, Policy, Route};
use agent_auth_store::agents::{self, AgentRow, NewAgent};
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::requests::{self, AnyRequest, Approval, Escalation, NewRequest, Request};
use agent_auth_store::{Delegation, Store, lockdown};
use serde_json::json;
use time::{Duration, OffsetDateTime};

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub async fn agent(store: &Store, name: &str, kind: AgentKind) -> AgentRow {
    let tx = store.begin().await.unwrap();
    let id = AgentId::new();
    let key_id = &id.to_string()[..12];
    let row = agents::insert(
        &tx,
        &NewAgent {
            id,
            name,
            description: "",
            key_id,
            api_key_hash: &"0".repeat(64),
            kind,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: Some("claude"),
            project: Some("agent-auth"),
            host: Some("excelsior"),
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    row
}

/// A committed request in AWAITING_HUMAN.
pub async fn awaiting(store: &Store, agent: AgentId, authority: &Authority) -> RequestId {
    awaiting_on(store, agent, authority, "svc-gitea", None).await
}

pub async fn awaiting_on(
    store: &Store,
    agent: AgentId,
    authority: &Authority,
    resource: &str,
    delegation: Option<Delegation>,
) -> RequestId {
    let tx = store.begin().await.unwrap();
    let id = RequestId::new();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id,
            agent_id: agent,
            session_id: None,
            delegation,
            platform: authority.platform(),
            resource,
            requested_capability: "member",
            requested_scope: &json!({}),
            authority: Some(authority),
            justification: "testing",
            requested_duration_secs: 3600,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap();
    requests::transition::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now())
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    id
}

/// A human's approval of `request` (tests stand in for the human surface).
pub fn approval(request: RequestId, secs: u32) -> Approval {
    Approval::human(HumanApproval::attest(request, "jrt"), "ok", secs)
}

/// Route `request` under a policy whose default is `action`, for an agent
/// named `agent`.
pub fn routed(request: RequestId, authority: &Authority, resource: &str, action: &str) -> Route {
    let policy = Policy::from_yaml(&format!("defaults:\n  action: {action}\n")).unwrap();
    let agent = AgentRef::named("tester");
    let zone = zones::check(&policy, &agent, authority, resource, &ZoneFacts::Nothing).unwrap();
    let input = PolicyInput {
        agent,
        delegation: PolicyDelegation::None,
        resource,
        authority,
    };
    policy
        .evaluate_and_route(request, &input, &[], &zone, now())
        .1
        .route
}

/// The clearance an `approve` default gives `request`.
pub fn auto_clearance(request: RequestId, authority: &Authority, resource: &str) -> AutoClearance {
    match routed(request, authority, resource, "approve") {
        Route::Approve(c) => c,
        other => panic!("{other:?}"),
    }
}

/// The clearance an `llm` default gives `request`.
pub fn llm_clearance(request: RequestId, authority: &Authority, resource: &str) -> LlmClearance {
    match routed(request, authority, resource, "llm") {
        Route::Llm(c) => c,
        other => panic!("{other:?}"),
    }
}

/// Approve and begin provisioning an AWAITING_HUMAN request; returns the
/// PROVISIONING grant (committed).
pub async fn provisioning_grant(store: &Store, request: RequestId) -> GrantRow {
    let tx = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, request).await.unwrap() else {
        panic!("not awaiting");
    };
    let r = requests::transition::<_, state::Approved>(&tx, r, approval(request, 3600), now())
        .await
        .unwrap()
        .unwrap();
    let r: Request<state::Provisioning> = requests::transition(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, r.agent_id(), now())
        .await
        .unwrap()
        .unwrap();
    let g = grants::begin(&tx, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap()
        .grant()
        .clone();
    drop(nh);
    tx.commit().await.unwrap();
    g
}

/// A committed ACTIVE grant of an AWAITING_HUMAN request.
pub async fn active_grant(store: &Store, request: RequestId) -> GrantRow {
    let g = provisioning_grant(store, request).await;
    let tx = store.begin().await.unwrap();
    let nh = lockdown::check(&tx, g.agent_id, now())
        .await
        .unwrap()
        .unwrap();
    let pg = grants::load_provisioning(&tx, g.id).await.unwrap().unwrap();
    let g = grants::activate(&tx, pg, &nh, &json!({}))
        .await
        .unwrap()
        .unwrap();
    drop(nh);
    let Some(AnyRequest::Provisioning(r)) = requests::get(&tx, g.request_id).await.unwrap() else {
        panic!("not provisioning");
    };
    requests::transition::<_, state::Granted>(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    g
}

pub fn homelab() -> Authority {
    Authority::Homelab
}

pub fn a2a() -> Authority {
    Authority::A2a { topic: None }
}

pub fn hours(n: i64) -> Duration {
    Duration::hours(n)
}

pub fn platform_of(a: &Authority) -> Platform {
    a.platform()
}

/// Wait until some transaction of this test's database is blocked on a
/// lock (row, table or advisory): what a test of "B waits for A" waits for
/// before checking B is still waiting and releasing A. A sleep there only
/// guessed that B got as far as the lock; under load B might not have, and
/// the test passed without testing the wait (30 s at most).
pub async fn until_waiting_on_a_lock(store: &Store) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        if waiting > 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "nothing waited on a lock in 30 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
