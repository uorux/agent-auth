//! Proofs for approvals and provisioning, the lock order, and the guards
//! added after the security review.
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
use agent_auth_core::{
    DecisionSource, GrantId, HumanApproval, JobId, MessageId, RequestId, ThreadId, Tier,
};
use agent_auth_store::a2a::{self, NewThread};
use agent_auth_store::hostexec::{self, JobStatus, NewJob};
use agent_auth_store::requests::{self, AnyRequest, Approval, ApprovedEdit, LlmRound};
use agent_auth_store::{Delegation, Store, StoreError, grants, lockdown, sandboxes};
use common::*;
use serde_json::json;
use sqlx::PgPool;

async fn pending(
    store: &Store,
    tx: &agent_auth_store::Tx<'_>,
) -> requests::Request<state::Pending> {
    let a = agent(
        store,
        &format!("p-{}", &RequestId::new().to_string()[..8]),
        AgentKind::Service,
    )
    .await;
    requests::insert(
        tx,
        &requests::NewRequest {
            id: RequestId::new(),
            agent_id: a.id,
            session_id: None,
            delegation: None,
            platform: homelab().platform(),
            resource: "svc-gitea",
            requested_capability: "member",
            requested_scope: &json!({}),
            authority: Some(&homelab()),
            justification: "j",
            requested_duration_secs: 60,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn an_approval_is_spent_only_on_its_own_request(pool: PgPool) {
    let store = Store::from_pool(pool);
    let tx = store.begin().await.unwrap();

    // A clearance for another request.
    let r = pending(&store, &tx).await;
    let other = auto_clearance(RequestId::new(), &homelab(), "svc-gitea");
    let err = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::auto(other, "policy", "ok", 60),
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof), "{err:?}");

    // A clearance for this request but another authority.
    let r = pending(&store, &tx).await;
    let wrong = auto_clearance(r.id(), &a2a(), "peer");
    let err = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::auto(wrong, "policy", "ok", 60),
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof), "{err:?}");

    // A human's approval of another request, and one from a state a human
    // does not decide from (PENDING).
    let r = pending(&store, &tx).await;
    let id = r.id();
    let err = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::human(HumanApproval::attest(RequestId::new(), "jrt"), "ok", 60),
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof), "{err:?}");
    let r = pending(&store, &tx).await;
    let err = requests::transition::<_, state::Approved>(&tx, r, approval(id, 60), now())
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof), "{err:?}");

    // LLM review needs the LLM clearance of this request.
    let r = pending(&store, &tx).await;
    let err = requests::transition::<_, state::LlmEvaluating>(
        &tx,
        r,
        LlmRound {
            clearance: llm_clearance(RequestId::new(), &homelab(), "svc-gitea"),
            justification: None,
        },
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::WrongProof), "{err:?}");

    // The real thing: an auto approval records its clearance's source.
    let r = pending(&store, &tx).await;
    let c = auto_clearance(r.id(), &homelab(), "svc-gitea");
    let r = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::auto(c, "policy", "no matching rule; policy default", 60),
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.row().decision_source, Some(DecisionSource::Policy));

    // An LLM approval, from LLM review only.
    let r = pending(&store, &tx).await;
    let rid = r.id();
    let r = requests::transition::<_, state::LlmEvaluating>(
        &tx,
        r,
        LlmRound {
            clearance: llm_clearance(rid, &homelab(), "svc-gitea"),
            justification: None,
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    let r = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::llm(
            llm_clearance(rid, &homelab(), "svc-gitea"),
            "test/judge",
            "fine",
            60,
        ),
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.row().decision_source, Some(DecisionSource::Llm));
    assert_eq!(r.row().decided_by.as_deref(), Some("test/judge"));
}

#[sqlx::test(migrations = "./migrations")]
async fn guards_on_requests_grants_and_jobs(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "guarded", AgentKind::Service).await;
    let id = awaiting(&store, a.id, &homelab()).await;

    // What was asked is immutable.
    let err =
        sqlx::query("UPDATE access_requests SET authority = '{}', resource = 'x' WHERE id = $1")
            .bind(uuid::Uuid::from(id))
            .execute(&pool)
            .await
            .unwrap_err();
    assert!(StoreError::from(err).is_check_violation());

    // No grant row for a request that is not PROVISIONING.
    let err = sqlx::query(
        "INSERT INTO grants (id, request_id, agent_id, platform, resource, authority, granted_at,
             expires_at, status)
         VALUES (gen_random_uuid(), $1, $2, 'homelab', 'svc-gitea', '{}', now(),
                 now() + interval '1 hour', 'provisioning')",
    )
    .bind(uuid::Uuid::from(id))
    .bind(uuid::Uuid::from(a.id))
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(StoreError::from(err).is_check_violation());

    // set_approved_edit on a request moved on since its handle was loaded.
    let tx = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx, id).await.unwrap() else {
        panic!()
    };
    requests::transition::<_, state::Approved>(&tx, r, approval(id, 60), now())
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    let tx2 = store.begin().await.unwrap();
    let Some(AnyRequest::Approved(mut stale)) = requests::get(&tx2, id).await.unwrap() else {
        panic!()
    };
    let tx3 = store.begin().await.unwrap();
    let Some(AnyRequest::Approved(r)) = requests::get(&tx3, id).await.unwrap() else {
        panic!()
    };
    requests::transition::<_, state::Provisioning>(&tx3, r, (), now())
        .await
        .unwrap()
        .unwrap();
    tx3.commit().await.unwrap();
    let lost = requests::set_approved_edit(
        &tx2,
        &mut stale,
        ApprovedEdit {
            resource: "svc-sonarr".into(),
            authority: homelab(),
        },
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(lost.id, id);
    drop(tx2);

    // A job's status and `via` move only for its own host, and `via`
    // never changes on a finished job.
    let tx = store.begin().await.unwrap();
    let job = JobId::new();
    hostexec::insert(
        &tx,
        &NewJob {
            id: job,
            grant_id: None,
            request_id: id,
            agent_id: a.id,
            host: "excelsior",
            tier: Tier::User,
            shell_id: None,
            spec: &json!({}),
            now: now(),
        },
    )
    .await
    .unwrap();
    assert!(
        !hostexec::set_status(&tx, job, "recusant", JobStatus::Running, None, Some("totp"))
            .await
            .unwrap()
    );
    assert!(
        hostexec::set_status(
            &tx,
            job,
            "excelsior",
            JobStatus::Refused,
            Some("no"),
            Some("auto")
        )
        .await
        .unwrap()
    );
    assert!(
        !hostexec::set_status(
            &tx,
            job,
            "excelsior",
            JobStatus::Running,
            None,
            Some("totp")
        )
        .await
        .unwrap()
    );
    let j = hostexec::get(&tx, job).await.unwrap().unwrap();
    assert_eq!(j.status, JobStatus::Refused);
    assert_eq!(j.via.as_deref(), Some("auto"));
}

/// The confirmed deadlock: a provisioning that has locked the backing
/// grant (and thread) racing a disable of the delegator, which locks the
/// delegator and then its grants. With the lock order (the disable takes
/// the containment lock exclusively first) the disable waits instead.
#[sqlx::test(migrations = "./migrations")]
async fn disabling_a_delegator_waits_for_a_provisioning_instead_of_deadlocking(pool: PgPool) {
    let store = Store::from_pool(pool);
    let initiator = agent(&store, "delegator", AgentKind::Service).await;
    let responder = agent(&store, "worker", AgentKind::Service).await;
    let rid = awaiting_on(&store, initiator.id, &a2a(), "worker", None).await;
    let backing = active_grant(&store, rid).await;
    let thread = ThreadId::new();
    let tx = store.begin().await.unwrap();
    let clear = lockdown::check_pair(&tx, initiator.id, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    a2a::open(
        &tx,
        &clear,
        &NewThread {
            id: thread,
            initiator: initiator.id,
            initiator_session: None,
            responder: responder.id,
            topic: None,
            grant_id: Some(backing.id),
            message_id: MessageId::new(),
            payload: "{}",
            now: now(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    a2a::accept(&tx, &clear, thread, None, now())
        .await
        .unwrap()
        .unwrap();
    drop(clear);
    tx.commit().await.unwrap();
    let delegation = Some(Delegation {
        thread_id: thread,
        delegator_agent_id: initiator.id,
    });
    let id = awaiting_on(&store, responder.id, &homelab(), "svc-gitea", delegation).await;

    let tx1 = store.begin().await.unwrap();
    let Some(AnyRequest::AwaitingHuman(r)) = requests::get(&tx1, id).await.unwrap() else {
        panic!()
    };
    let r = requests::transition::<_, state::Approved>(&tx1, r, approval(id, 60), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::Provisioning>(&tx1, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx1, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    // What the old `begin` locked first: the thread and the backing grant.
    a2a::get_for_update(&tx1, thread).await.unwrap().unwrap();
    grants::get_for_update(&tx1, backing.id)
        .await
        .unwrap()
        .unwrap();

    let s2 = store.clone();
    let delegator = initiator.id;
    let disabler = tokio::spawn(async move {
        let tx2 = s2.begin().await.unwrap();
        let names = sandboxes::disable_tree(
            &tx2,
            delegator,
            now(),
            agent_auth_store::agents::DisableReason::Operator,
        )
        .await?;
        tx2.commit().await?;
        Ok::<_, StoreError>(names)
    });
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    assert!(
        !disabler.is_finished(),
        "the disable waits for the containment lock"
    );

    // The old order would now wait on the delegator held by the disable,
    // which waits on the backing grant held here: a deadlock.
    let pg = grants::begin(&tx1, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap();
    grants::activate(&tx1, pg, &nh, &json!({}))
        .await
        .unwrap()
        .unwrap();
    drop(nh);
    tx1.commit().await.unwrap();
    assert_eq!(
        disabler.await.unwrap().unwrap(),
        vec!["delegator".to_owned()]
    );
}
