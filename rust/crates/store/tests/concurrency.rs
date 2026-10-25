//! One-time tokens, pairing attempts and a2a sequence numbers under
//! concurrency; cascades and constraints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::{AgentId, DaemonId, MessageId, SessionId, ThreadId};
use agent_auth_store::a2a::{self, NewMessage, NewThread};
use agent_auth_store::agents::{self, NewAgent};
use agent_auth_store::daemons::{self, DaemonRole};
use agent_auth_store::oauth::{self, Consumed, NewClient, NewToken, TokenKind};
use agent_auth_store::{Store, StoreError, lockdown, sandboxes, sessions};
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn a_code_is_consumed_once_and_a_replay_burns_the_family(pool: PgPool) {
    let store = Store::from_pool(pool);
    let web = agent(&store, "web-claude", AgentKind::Ephemeral).await;
    let family = Uuid::new_v4();
    let tx = store.begin().await.unwrap();
    oauth::insert_client(
        &tx,
        &NewClient {
            id: "mcpc_test",
            name: "Claude",
            redirect_uris: &["https://claude.ai/cb".to_owned()],
            secret_hash: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    for (kind, hash) in [(TokenKind::Code, "a"), (TokenKind::Access, "b")] {
        oauth::insert_token(
            &tx,
            &NewToken {
                id: Uuid::new_v4(),
                kind,
                token_hash: &hash.repeat(64),
                client_id: "mcpc_test",
                agent_id: web.id,
                family,
                expires_at: now() + hours(1),
                code_challenge: (kind == TokenKind::Code).then_some(&"c".repeat(43)),
                redirect_uri: (kind == TokenKind::Code).then_some("https://claude.ai/cb"),
                authorized_by: "jrt",
                now: now(),
            },
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let out = oauth::consume(&tx, &"a".repeat(64), TokenKind::Code, "mcpc_test", now())
                .await
                .unwrap();
            tx.commit().await.unwrap();
            out
        }));
    }
    let mut fresh = 0;
    let mut replayed = 0;
    for t in tasks {
        match t.await.unwrap() {
            Consumed::Fresh(_) => fresh += 1,
            Consumed::Replayed { .. } => replayed += 1,
            Consumed::Unknown => {}
        }
    }
    assert_eq!(fresh, 1);
    assert!(replayed >= 1);
    // The replay revoked the family: the access token is dead.
    let tx = store.begin().await.unwrap();
    assert!(
        oauth::agent_for_access(&tx, &"b".repeat(64), now())
            .await
            .unwrap()
            .is_none()
    );
    // An access token is never "consumed".
    assert!(matches!(
        oauth::consume(&tx, &"b".repeat(64), TokenKind::Access, "mcpc_test", now())
            .await
            .unwrap(),
        Consumed::Unknown
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn pairing_attempts_are_spent_atomically(pool: PgPool) {
    let store = Store::from_pool(pool);
    let tx = store.begin().await.unwrap();
    let code = Uuid::new_v4();
    daemons::issue_code(
        &tx,
        code,
        DaemonRole::Host,
        "excelsior",
        &"0".repeat(64),
        now() + hours(1),
        now(),
    )
    .await
    .unwrap();
    // A second code burns the first: only the newest is live.
    let newer = Uuid::new_v4();
    daemons::issue_code(
        &tx,
        newer,
        DaemonRole::Host,
        "excelsior",
        &"1".repeat(64),
        now() + hours(1),
        now(),
    )
    .await
    .unwrap();
    let live = daemons::live_code(&tx, DaemonRole::Host, "excelsior", now(), 5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.id, newer);
    tx.commit().await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..30 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let spent = daemons::spend_attempt(&tx, newer, 5).await.unwrap();
            tx.commit().await.unwrap();
            spent
        }));
    }
    let mut evaluated = 0;
    for t in tasks {
        if t.await.unwrap() {
            evaluated += 1;
        }
    }
    assert_eq!(evaluated, 5);
    let tx = store.begin().await.unwrap();
    assert!(
        daemons::live_code(&tx, DaemonRole::Host, "excelsior", now(), 5)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !daemons::claim_code(&tx, code, now()).await.unwrap(),
        "burnt code"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_messages_get_contiguous_seqs(pool: PgPool) {
    let store = Store::from_pool(pool);
    let initiator = agent(&store, "asker", AgentKind::Service).await;
    let responder = agent(&store, "doer", AgentKind::Service).await;
    let rid = awaiting_on(&store, initiator.id, &a2a(), "doer", None).await;
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
            payload: r#"{"b": 1, "a": 2}"#,
            now: now(),
        },
    )
    .await
    .unwrap();
    // The initiator cannot add to a pending thread.
    assert!(
        a2a::append(
            &tx,
            &clear,
            &NewMessage {
                thread_id: thread,
                id: MessageId::new(),
                sender: initiator.id,
                sender_session: None,
                payload: "{}",
                now: now(),
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    drop(clear);
    tx.commit().await.unwrap();

    // Two racing accepts: one wins.
    let mut accepts = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let (i, r) = (initiator.id, responder.id);
        accepts.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let clear = lockdown::check_pair(&tx, i, r, now())
                .await
                .unwrap()
                .unwrap();
            let out = a2a::accept(&tx, &clear, thread, None, now()).await.unwrap();
            drop(clear);
            tx.commit().await.unwrap();
            out.is_some()
        }));
    }
    let mut won = 0;
    for t in accepts {
        if t.await.unwrap() {
            won += 1;
        }
    }
    assert_eq!(won, 1);

    let mut tasks = Vec::new();
    for n in 0..20u32 {
        let store = store.clone();
        let (i, r) = (initiator.id, responder.id);
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let clear = lockdown::check_pair(&tx, i, r, now())
                .await
                .unwrap()
                .unwrap();
            let sender = if n % 2 == 0 { i } else { r };
            let m = a2a::append(
                &tx,
                &clear,
                &NewMessage {
                    thread_id: thread,
                    id: MessageId::new(),
                    sender,
                    sender_session: None,
                    payload: &format!(r#"{{"n": {n}}}"#),
                    now: now(),
                },
            )
            .await
            .unwrap()
            .unwrap();
            drop(clear);
            tx.commit().await.unwrap();
            m.seq
        }));
    }
    let mut seqs = Vec::new();
    for t in tasks {
        seqs.push(t.await.unwrap());
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (2..=21).collect::<Vec<u32>>());
    let tx = store.begin().await.unwrap();
    let t = a2a::get(&tx, thread).await.unwrap().unwrap();
    assert_eq!(t.last_seq, 21);
    let msgs = a2a::messages_after(&tx, thread, 0).await.unwrap();
    assert_eq!(msgs.len(), 21);
    // The payload comes back exactly as sent (key order included).
    assert_eq!(msgs[0].message.payload, r#"{"b": 1, "a": 2}"#);
    assert_eq!(msgs[0].sender_name, "asker");

    // Closed is terminal: no message, no reopening.
    a2a::close(
        &tx,
        thread,
        a2a::CloseReason::Closed,
        Some(responder.id),
        Some("done"),
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    let clear = lockdown::check_pair(&tx, initiator.id, responder.id, now())
        .await
        .unwrap()
        .unwrap();
    assert!(
        a2a::append(
            &tx,
            &clear,
            &NewMessage {
                thread_id: thread,
                id: MessageId::new(),
                sender: initiator.id,
                sender_session: None,
                payload: "{}",
                now: now(),
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        a2a::close(&tx, thread, a2a::CloseReason::Closed, None, None, now())
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn constraints_tie_rows_to_the_right_agent(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let a = agent(&store, "alice", AgentKind::Service).await;
    let b = agent(&store, "bob", AgentKind::Ephemeral).await;
    let tx = store.begin().await.unwrap();
    let sb = sessions::insert(&tx, SessionId::new(), b.id, "cli-0a1b", now())
        .await
        .unwrap();
    // Session names are unique per agent.
    let err = sessions::insert(&tx, SessionId::new(), b.id, "cli-0a1b", now())
        .await
        .unwrap_err();
    assert!(err.is_unique_violation());
    tx.rollback().await.unwrap();

    let tx = store.begin().await.unwrap();
    let sb = sessions::insert(&tx, sb.id, b.id, "cli-0a1b", now())
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // A thread whose initiator session belongs to another agent.
    let rid = awaiting_on(&store, a.id, &a2a(), "bob", None).await;
    let g = active_grant(&store, rid).await;
    let err = sqlx::query(
        "INSERT INTO a2a_threads (id, initiator_agent_id, initiator_session_id, responder_agent_id,
             grant_id, state, last_activity_at, last_seq)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, 'pending_open', now(), 1)",
    )
    .bind(Uuid::from(a.id))
    .bind(Uuid::from(sb.id))
    .bind(Uuid::from(b.id))
    .bind(Uuid::from(g.id))
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(StoreError::from(err).is_foreign_key_violation());
    // A thread backed by the responder's grant instead of the initiator's.
    let err = sqlx::query(
        "INSERT INTO a2a_threads (id, initiator_agent_id, responder_agent_id, grant_id, state,
             last_activity_at, last_seq)
         VALUES (gen_random_uuid(), $1, $2, $3, 'pending_open', now(), 1)",
    )
    .bind(Uuid::from(b.id))
    .bind(Uuid::from(a.id))
    .bind(Uuid::from(g.id))
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(StoreError::from(err).is_foreign_key_violation());

    let tx = store.begin().await.unwrap();
    // Webhooks are for service agents only.
    let err = agents::set_webhook(&tx, b.id, Some("https://x"), Some("s"))
        .await
        .unwrap_err();
    assert!(err.is_check_violation());
    drop(tx);
    // One operator row, however many first uses race.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let tx = store.begin().await.unwrap();
            let key = AgentId::new().to_string();
            let op = agents::ensure_operator(&tx, AgentId::new(), &key[..12], now())
                .await
                .unwrap();
            tx.commit().await.unwrap();
            op.unwrap().id
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    ids.dedup();
    assert_eq!(ids.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn unpairing_cascades_and_disabling_walks_the_tree(pool: PgPool) {
    let store = Store::from_pool(pool);
    let tx = store.begin().await.unwrap();
    let vm = daemons::upsert_paired(
        &tx,
        DaemonId::new(),
        DaemonRole::Sandbox,
        "vm1",
        "pk",
        now(),
    )
    .await
    .unwrap();
    // Re-pairing keeps the id.
    let again = daemons::upsert_paired(
        &tx,
        DaemonId::new(),
        DaemonRole::Sandbox,
        "vm1",
        "pk2",
        now(),
    )
    .await
    .unwrap();
    assert_eq!(again.id, vm.id);
    let mut parent = None;
    let mut ids = Vec::new();
    for name in [
        "orchestrator-vm1-sandbox",
        "claude-p-vm1-sandbox",
        "codex-q-vm1-sandbox",
    ] {
        let id = AgentId::new();
        agents::insert(
            &tx,
            &NewAgent {
                id,
                name,
                description: "",
                key_id: &id.to_string()[..12],
                api_key_hash: &"0".repeat(64),
                kind: AgentKind::Service,
                webhook_url: None,
                webhook_secret: None,
                lldap_username: None,
                parent_agent_id: parent,
                sandbox_id: Some(vm.id),
                runtime: Some("claude"),
                project: None,
                host: Some("vm1"),
                placement: Placement::Sandbox,
                lease_expires_at: None,
                last_seen_at: None,
                now: now(),
            },
        )
        .await
        .unwrap();
        sandboxes::queue(
            &tx,
            Uuid::new_v4(),
            id,
            vm.id,
            &id.to_string()[..12],
            "ct",
            now(),
        )
        .await
        .unwrap();
        parent = Some(id);
        ids.push(id);
    }
    // An ack for another key deletes nothing (sandboxd B-6).
    assert!(!sandboxes::ack(&tx, ids[0], vm.id, "stale").await.unwrap());
    assert!(
        sandboxes::ack(&tx, ids[0], vm.id, &ids[0].to_string()[..12])
            .await
            .unwrap()
    );
    // Disabling the middle agent takes its child with it, not its parent.
    let names = sandboxes::disable_tree(&tx, ids[1], now()).await.unwrap();
    assert_eq!(names, vec!["claude-p-vm1-sandbox", "codex-q-vm1-sandbox"]);
    assert!(!agents::get(&tx, ids[0]).await.unwrap().unwrap().disabled);
    assert!(sandboxes::pending_for(&tx, vm.id).await.unwrap().is_empty());
    sandboxes::queue(&tx, Uuid::new_v4(), ids[0], vm.id, "k", "ct", now())
        .await
        .unwrap();
    // Unpairing: deliveries cascade, agents lose their sandbox.
    daemons::unpair(&tx, vm.id, now()).await.unwrap().unwrap();
    assert!(sandboxes::pending_for(&tx, vm.id).await.unwrap().is_empty());
    assert_eq!(
        agents::get(&tx, ids[0]).await.unwrap().unwrap().sandbox_id,
        None
    );
    let _ = json!({});
}
