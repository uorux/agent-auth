//! Agent VMs, broker side (ported from `tests/test_sandboxes.py`, with the
//! fixes of sandboxd spec §7): the orchestrator bootstrap, key delivery to
//! the sandbox daemon only, minting with lineage and leases, cascade
//! disable, cross-project grants carried out by the daemon, and what a
//! sandbox is told about lockdowns and containment. Each test names the
//! invariant (INV-n) or bug (B-n) it pins.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::{AgentId, GrantStatus, RequestId, RequestStatus};
use agent_auth_store::agents::{self, AgentRow, DisableReason, NewAgent};
use agent_auth_store::lockdown::ContainmentSource;
use agent_auth_store::{daemons, flags, grants, requests, sandboxes as store};
use agent_auth_wire::admin::LockdownScope;
use agent_auth_wire::agent::RequestCreate;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::testkit::{ADMIN_TOKEN, Broker, FakeSandbox, HOST, POLICY, Seen, eventually};
use crate::auth::{AgentCaller, AgentCredentialKind};
use crate::provisioners::AnyProvisioner;

const ORCH: &str = "orchestrator-excelsior-sandbox";
const CHILD: &str = "claude-larder-excelsior-sandbox";

fn caller(a: &AgentRow) -> AgentCaller {
    AgentCaller::new(a.clone(), None, AgentCredentialKind::ApiKey)
}

fn mint_body(name: &str) -> RequestCreate {
    serde_json::from_value(json!({
        "platform": "agents", "capability": "mint", "resource": name, "scope": {},
        "justification": "set up the larder project", "requested_duration": "10m",
    }))
    .unwrap()
}

fn access_body(target: &str, capability: &str) -> RequestCreate {
    serde_json::from_value(json!({
        "platform": "sandbox", "capability": capability, "resource": target, "scope": {},
        "justification": "read the shared schema", "requested_duration": "1h",
    }))
    .unwrap()
}

async fn request(b: &Broker, id: RequestId) -> requests::RequestRow {
    let tx = b.st.store.begin().await.unwrap();
    requests::get(&tx, id).await.unwrap().unwrap().into_row()
}

/// Create a request as `agent` and wait until the broker is done with it.
async fn ask(b: &Broker, agent: &AgentRow, body: RequestCreate) -> requests::RequestRow {
    let r = crate::service::create(&b.st, &caller(agent), body)
        .await
        .unwrap();
    for _ in 0..500 {
        let r = request(b, r.id).await;
        if !matches!(
            r.status,
            RequestStatus::Pending
                | RequestStatus::LlmEvaluating
                | RequestStatus::Approved
                | RequestStatus::Provisioning
        ) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("request {} did not settle", r.id);
}

async fn grant_of(b: &Broker, id: RequestId) -> grants::GrantRow {
    let tx = b.st.store.begin().await.unwrap();
    grants::by_request(&tx, id).await.unwrap().unwrap()
}

/// A paired, connected sandbox whose orchestrator key arrived.
async fn vm(b: &Broker) -> (FakeSandbox, AgentRow, String) {
    let sb = FakeSandbox::start(b, HOST).await;
    let key = sb.wait_key(ORCH).await;
    (sb, b.agent(ORCH).await, key)
}

/// The VM with a minted `claude` agent on project larder.
async fn vm_with_child(b: &Broker) -> (FakeSandbox, AgentRow, AgentRow, String) {
    let (sb, orch, _) = vm(b).await;
    let r = ask(b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Granted, "{:?}", r.decision_reason);
    let key = sb.wait_key(CHILD).await;
    (sb, orch, b.agent(CHILD).await, key)
}

async fn me_status(b: &Broker, key: &str) -> u16 {
    b.get_as(key, "/v1/me").await.0
}

async fn pending(b: &Broker) -> Vec<store::PendingKey> {
    let tx = b.st.store.begin().await.unwrap();
    let d = daemons::by_name(&tx, daemons::DaemonRole::Sandbox, HOST)
        .await
        .unwrap()
        .unwrap();
    store::pending_for(&tx, d.id).await.unwrap()
}

async fn plain_agent(
    b: &Broker,
    name: &str,
    f: impl FnOnce(&mut NewAgent<'_>),
) -> (AgentRow, String) {
    let key = agent_auth_crypto::api_key::generate().unwrap();
    let tx = b.st.store.begin().await.unwrap();
    let mut n = NewAgent {
        id: AgentId::new(),
        name,
        description: "",
        key_id: key.key_id.as_str(),
        api_key_hash: key.hash.as_str(),
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
        last_seen_at: Some(OffsetDateTime::now_utc()),
        now: OffsetDateTime::now_utc(),
    };
    f(&mut n);
    let row = agents::insert(&tx, &n).await.unwrap();
    tx.commit().await.unwrap();
    (row, key.full_key.expose().clone())
}

async fn platforms_of(b: &Broker, key: &str) -> Vec<String> {
    let (status, cat) = b.get_as(key, "/v1/catalog").await;
    assert_eq!(status, 200, "{cat}");
    cat["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["platform"].as_str().map(str::to_owned))
        .collect()
}

// ------------------------------------------------- orchestrator and keys

/// INV-1, INV-2, INV-3: pairing bootstraps the orchestrator; its key goes
/// to the sandbox alone and authenticates; acked, the broker holds no copy.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv1_inv3_pairing_bootstraps_the_orchestrator_and_delivers_its_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, key) = vm(&b).await;
    assert_eq!(orch.runtime.as_deref(), Some("orchestrator"));
    assert_eq!(orch.kind, AgentKind::Service);
    assert!(!orch.disabled);
    assert_eq!(
        (orch.host.as_deref(), orch.placement),
        (Some(HOST), Placement::Sandbox)
    );
    let (status, me) = b.get_as(&key, "/v1/me").await;
    assert_eq!(status, 200);
    assert_eq!(me["name"], json!(ORCH));
    let msg = &sb.of_type("key")[0];
    // The message names its key (B-6) and the agent's VM fields.
    assert_eq!(msg["key_id"], json!(orch.key_id));
    assert_eq!(msg["runtime"], json!("orchestrator"));
    assert!(eventually(|| async { pending(&b).await.is_empty() }).await);
    // The admin listing never carries it.
    let (_, listing) = b.get_as(ADMIN_TOKEN, "/admin/agents").await;
    assert!(!listing.to_string().contains(&key));
}

/// INV-2: while it waits, the key is stored encrypted (never in the clear).
#[sqlx::test(migrations = "../store/migrations")]
async fn inv2_a_pending_key_is_stored_encrypted(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let sb = FakeSandbox::start_with(
        &b,
        HOST,
        Seen {
            no_ack: true,
            ..Seen::default()
        },
    )
    .await;
    let key = sb.wait_key(ORCH).await;
    let rows = pending(&b).await;
    assert_eq!(rows.len(), 1);
    let secret = key.rsplit('_').next().unwrap();
    assert!(!rows[0].key_encrypted.contains(secret));
    assert!(!format!("{:?}", rows[0]).contains(secret));
}

/// INV-2: without ENCRYPTION_KEY nothing is bootstrapped (no plaintext
/// fallback).
#[sqlx::test(migrations = "../store/migrations")]
async fn inv2_without_an_encryption_key_nothing_is_bootstrapped(pool: sqlx::PgPool) {
    let b = Broker::start_with(pool, POLICY, false).await;
    let sb = FakeSandbox::start(&b, HOST).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(b.maybe_agent(ORCH).await.is_none());
    assert!(sb.of_type("key").is_empty());
}

/// INV-10: re-pairing rotates the orchestrator's key; the old one is dead.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv10_repairing_rotates_the_orchestrator_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (mut sb, _, old) = vm(&b).await;
    sb.stop().await;
    let again = FakeSandbox::start(&b, HOST).await;
    let new = again.wait_key(ORCH).await;
    assert_ne!(new, old);
    assert_eq!(me_status(&b, &old).await, 401);
    assert_eq!(me_status(&b, &new).await, 200);
}

/// INV-10: a sandbox never takes over a same-named agent of another
/// runtime.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv10_no_takeover_of_a_same_named_agent(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (squatter, key) = plain_agent(&b, ORCH, |n| n.runtime = Some("claude")).await;
    let sb = FakeSandbox::start(&b, HOST).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(sb.of_type("key").is_empty());
    let now = b.agent(ORCH).await;
    assert_eq!(now.sandbox_id, None);
    assert_eq!(now.key_id, squatter.key_id);
    assert_eq!(me_status(&b, &key).await, 200);
}

/// INV-4: `key.rotate` issues a new key only for the sandbox's own enabled
/// agents, to it alone; the old key dies at once.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv4_a_sandbox_rotates_only_its_own_enabled_agents_keys(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, old) = vm(&b).await;
    let (_, outsider_key) = plain_agent(&b, "hand-registered", |_| {}).await;
    sb.send(json!({"type": "key.rotate", "name": "hand-registered"}))
        .await;
    sb.send(json!({"type": "key.rotate", "name": ORCH})).await;
    super::testkit::wait_until(|| sb.key(ORCH).is_some_and(|k| k != old)).await;
    let new = sb.key(ORCH).unwrap();
    assert_eq!(me_status(&b, &old).await, 401);
    assert_eq!(me_status(&b, &new).await, 200);
    assert!(sb.key("hand-registered").is_none());
    assert_eq!(me_status(&b, &outsider_key).await, 200);
    // A disabled agent gets no new key either.
    let tx = b.st.store.begin().await.unwrap();
    agents::set_disabled(&tx, orch.id, true).await.unwrap();
    tx.commit().await.unwrap();
    sb.forget_key(ORCH);
    sb.send(json!({"type": "key.rotate", "name": ORCH})).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(sb.key(ORCH).is_none());
}

/// INV-3, B-6: an ack for a key since replaced deletes nothing; neither
/// does an ack from another daemon; the right ack deletes the delivery.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv3_b6_an_ack_for_a_superseded_key_keeps_the_new_one(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let sb = FakeSandbox::start_with(
        &b,
        HOST,
        Seen {
            no_ack: true,
            ..Seen::default()
        },
    )
    .await;
    sb.wait_key(ORCH).await;
    let first = sb.of_type("key")[0].clone();
    sb.send(json!({"type": "key.rotate", "name": ORCH})).await;
    // Unacked, the first key is pushed again on heartbeats: wait for the
    // new one.
    let newer = || sb.seen.lock().unwrap().keys[ORCH]["key_id"] != first["key_id"];
    super::testkit::wait_until(newer).await;
    let second = sb.seen.lock().unwrap().keys[ORCH].clone();
    // The late ack of the first key.
    sb.send(json!({"type": "key.ack", "agent_id": first["agent_id"], "key_id": first["key_id"]}))
        .await;
    // An ack (of the right key) from another VM.
    let other = FakeSandbox::start(&b, "galaxy").await;
    other
        .send(
            json!({"type": "key.ack", "agent_id": second["agent_id"], "key_id": second["key_id"]}),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rows = pending(&b).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(json!(rows[0].key_id), second["key_id"]);
    sb.send(json!({"type": "key.ack", "agent_id": second["agent_id"], "key_id": second["key_id"]}))
        .await;
    assert!(eventually(|| async { pending(&b).await.is_empty() }).await);
}

// --------------------------------------------------------------- minting

/// INV-1, INV-5: a mint creates the child with its lineage, its VM's
/// host and placement, and a lease; the credential names it but never
/// carries the key, which only the sandbox gets.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv1_inv5_a_mint_creates_a_child_whose_key_only_the_sandbox_gets(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, orch_key) = vm(&b).await;
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Granted, "{:?}", r.decision_reason);
    let child = b.agent(CHILD).await;
    assert_eq!(
        (child.parent_agent_id, child.sandbox_id),
        (Some(orch.id), orch.sandbox_id)
    );
    assert_eq!(
        (
            child.runtime.as_deref(),
            child.project.as_deref(),
            child.kind
        ),
        (Some("claude"), Some("larder"), AgentKind::Service)
    );
    assert_eq!(
        (child.host.as_deref(), child.placement),
        (Some(HOST), Placement::Sandbox)
    );
    let left = child.lease_expires_at.unwrap() - OffsetDateTime::now_utc();
    assert!(left > time::Duration::days(29), "{left}");
    let key = sb.wait_key(CHILD).await;
    let msg = sb.seen.lock().unwrap().keys[CHILD].clone();
    assert_eq!(msg["project"], json!("larder"));
    assert_eq!(msg["key_id"], json!(child.key_id));
    assert_eq!(me_status(&b, &key).await, 200);
    // The orchestrator's credential: the name, not the key.
    let g = grant_of(&b, r.id).await;
    let (status, cred) = b
        .get_as(&orch_key, &format!("/v1/grants/{}/credential", g.id))
        .await;
    assert_eq!(status, 200, "{cred}");
    assert_eq!(cred["kind"], json!("agent_identity"));
    assert_eq!(cred["value"], json!(CHILD));
    assert!(
        cred["note"]
            .as_str()
            .unwrap()
            .starts_with("minted; lease until ")
    );
    let secret = key.rsplit('_').next().unwrap();
    assert!(!cred.to_string().contains(secret));
    assert!(!g.provisioner_state.to_string().contains(secret));
    assert_eq!(g.provisioner_state["created"], json!(true));
}

/// B-1: minting a live agent again renews its lease and sends no new key.
#[sqlx::test(migrations = "../store/migrations")]
async fn b1_minting_a_live_agent_again_renews_without_a_new_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, child, key) = vm_with_child(&b).await;
    let tx = b.st.store.begin().await.unwrap();
    agents::set_lease(
        &tx,
        child.id,
        Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Granted);
    let now = b.agent(CHILD).await;
    assert!(!now.disabled);
    assert!(now.lease_expires_at.unwrap() - OffsetDateTime::now_utc() > time::Duration::days(29));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let keys = sb
        .of_type("key")
        .into_iter()
        .filter(|m| m["name"] == json!(CHILD))
        .count();
    assert_eq!(keys, 1);
    assert_eq!(me_status(&b, &key).await, 200);
    assert_eq!(
        grant_of(&b, r.id).await.provisioner_state["outcome"],
        json!("renewed")
    );
}

/// B-1, B-8: an agent whose lease ran out comes back on a new mint with a
/// NEW key (which restarts its dispatcher in the VM); the old key stays
/// dead.
#[sqlx::test(migrations = "../store/migrations")]
async fn b1_b8_a_lapsed_agent_is_reenabled_with_a_new_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, child, old) = vm_with_child(&b).await;
    let tx = b.st.store.begin().await.unwrap();
    agents::set_lease(
        &tx,
        child.id,
        Some(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(crate::scheduler::sweep_leases(&b.st).await, 1);
    let lapsed = b.agent(CHILD).await;
    assert!(lapsed.disabled);
    assert_eq!(lapsed.disabled_reason, Some(DisableReason::Lease));
    assert_eq!(me_status(&b, &old).await, 401);
    sb.forget_key(CHILD);
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Granted, "{:?}", r.decision_reason);
    let new = sb.wait_key(CHILD).await;
    assert_ne!(new, old);
    assert_eq!(me_status(&b, &new).await, 200);
    assert_eq!(me_status(&b, &old).await, 401);
    let back = b.agent(CHILD).await;
    assert!(!back.disabled && back.disabled_reason.is_none());
    assert_eq!(
        grant_of(&b, r.id).await.provisioner_state["outcome"],
        json!("re-enabled")
    );
}

/// B-1: a re-mint never undoes the operator's disable, even after the
/// lease also ran out.
#[sqlx::test(migrations = "../store/migrations")]
async fn b1_an_operator_disabled_agent_is_not_reenabled_by_a_mint(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, child, key) = vm_with_child(&b).await;
    let (status, out) = b
        .post_as(
            ADMIN_TOKEN,
            &format!("/admin/agents/{}/disable", child.id),
            json!({}),
        )
        .await;
    assert_eq!(status, 200, "{out}");
    // Its lease runs out too: the operator's reason stays.
    let tx = b.st.store.begin().await.unwrap();
    store::disable_tree(
        &tx,
        child.id,
        OffsetDateTime::now_utc(),
        DisableReason::Lease,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        b.agent(CHILD).await.disabled_reason,
        Some(DisableReason::Operator)
    );
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(
        r.decision_reason
            .as_deref()
            .unwrap()
            .contains(&super::agents::operator_disabled(CHILD)),
        "{:?}",
        r.decision_reason
    );
    let still = b.agent(CHILD).await;
    assert!(still.disabled);
    assert_eq!(me_status(&b, &key).await, 401);
}

/// INV-5: the mint resource must name this VM's host, a configured
/// runtime and a valid project.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv5_mint_validation(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, _) = vm(&b).await;
    let long = format!("claude-{}-excelsior-sandbox", "a".repeat(31));
    for (name, why) in [
        ("claude-larder-galaxy-sandbox", "resource must be"),
        ("gemini-larder-excelsior-sandbox", "resource must be"),
        ("claude-Bad_Name-excelsior-sandbox", "invalid project"),
        ("claude--excelsior-sandbox", "invalid project"),
        (long.as_str(), "invalid project"),
    ] {
        let r = ask(&b, &orch, mint_body(name)).await;
        assert_eq!(r.status, RequestStatus::Denied, "{name}");
        assert!(
            r.decision_reason.as_deref().unwrap().contains(why),
            "{name}: {:?}",
            r.decision_reason
        );
    }
    // The scope may only repeat the name's runtime.
    let body: RequestCreate = serde_json::from_value(json!({
        "platform": "agents", "capability": "mint", "resource": CHILD,
        "scope": {"runtime": "codex"}, "justification": "x y z", "requested_duration": "10m",
    }))
    .unwrap();
    let r = ask(&b, &orch, body).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(
        r.decision_reason
            .as_deref()
            .unwrap()
            .contains("scope may only repeat the name's runtime")
    );
}

/// INV-5: an agent outside any VM cannot mint, whatever its rules say.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv5_only_agents_in_a_vm_can_mint(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let _vm = vm(&b).await;
    let (outsider, _) = plain_agent(&b, "catchall-hermes", |_| {}).await;
    let r = ask(&b, &outsider, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(r.decision_reason.unwrap().contains("agent VM"));
}

/// B-14: a project's agent cannot mint (another project's agent would
/// cross the project boundary without a `sandbox` grant).
#[sqlx::test(migrations = "../store/migrations")]
async fn b14_only_the_orchestrator_can_mint(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, _orch, child, _) = vm_with_child(&b).await;
    let r = ask(&b, &child, mint_body("claude-site-excelsior-sandbox")).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(
        r.decision_reason
            .unwrap()
            .contains(super::agents::NOT_ORCHESTRATOR)
    );
    assert!(
        b.maybe_agent("claude-site-excelsior-sandbox")
            .await
            .is_none()
    );
}

/// INV-7: a catch-all approve rule does not clear a mint (it needs a rule
/// naming `mint`).
#[sqlx::test(migrations = "../store/migrations")]
async fn inv7_a_catchall_rule_does_not_clear_a_mint(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, _) = vm(&b).await;
    let tx = b.st.store.begin().await.unwrap();
    agents::rename(&tx, orch.id, "catchall-orch").await.unwrap();
    tx.commit().await.unwrap();
    let orch = b.agent("catchall-orch").await;
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::AwaitingHuman);
}

/// INV-8: nothing is minted while the broker is locked down for the VM.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv8_no_mint_while_locked_down(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, _) = vm(&b).await;
    let tx = b.st.store.begin().await.unwrap();
    flags::set(
        &tx,
        flags::LOCKDOWN,
        &json!({"hosts": [HOST]}),
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let r = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(r.decision_reason.unwrap().contains(super::agents::LOCKED));
}

// ------------------------------------------------- disabling and leases

/// INV-9: disabling cascades to minted agents, drops their pending keys,
/// ends their grants on the next expiry pass, and their keys get 401.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv9_disable_cascades_to_minted_agents_and_ends_their_grants(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, orch, _child, child_key) = vm_with_child(&b).await;
    let orch_key = sb.key(ORCH).unwrap();
    let mint = {
        let tx = b.st.store.begin().await.unwrap();
        grants::of_agent(&tx, orch.id, None).await.unwrap()
    };
    let (status, out) = b
        .post_as(
            ADMIN_TOKEN,
            &format!("/admin/agents/{}/disable", orch.id),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(out["disabled"], json!([CHILD, ORCH]));
    let g = &mint[0];
    let tx = b.st.store.begin().await.unwrap();
    let now = grants::get(&tx, g.id).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert!(now.expires_at <= OffsetDateTime::now_utc());
    crate::service::expire_due_grants(&b.st).await;
    let tx = b.st.store.begin().await.unwrap();
    let ended = grants::get(&tx, g.id).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ended.status, GrantStatus::Expired);
    assert_eq!(me_status(&b, &orch_key).await, 401);
    assert_eq!(me_status(&b, &child_key).await, 401);
    assert!(pending(&b).await.is_empty());
    // The admin listing shows it disabled, with its VM runtime.
    let (_, listing) = b.get_as(ADMIN_TOKEN, "/admin/agents").await;
    let row = listing
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == json!(ORCH))
        .unwrap()
        .clone();
    assert_eq!(row["disabled"], json!(true));
    assert_eq!(row["runtime"], json!("orchestrator"));
}

/// INV-9: the lease sweep disables only the expired child, not its parent.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv9_the_lease_sweep_disables_only_the_expired(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, child, _) = vm_with_child(&b).await;
    let tx = b.st.store.begin().await.unwrap();
    agents::set_lease(
        &tx,
        child.id,
        Some(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(crate::scheduler::sweep_leases(&b.st).await, 1);
    assert!(b.agent(CHILD).await.disabled);
    assert!(!b.agent(&orch.name).await.disabled);
}

/// INV-6: the broker's fields of a VM agent are not the admin's to edit,
/// and its key is its sandbox's (rotate-key is refused: B-10).
#[sqlx::test(migrations = "../store/migrations")]
async fn inv6_vm_agents_refuse_attribute_rename_and_rotate_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, _orch, child, key) = vm_with_child(&b).await;
    let client = b.http();
    let attrs = client
        .patch(format!("{}/admin/agents/{}/attributes", b.url(), child.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"project": "other"}))
        .send()
        .await
        .unwrap();
    assert_eq!(attrs.status().as_u16(), 409);
    let (status, _) = b
        .post_as(
            ADMIN_TOKEN,
            &format!("/admin/agents/{}/rename", child.id),
            json!({"name": "x"}),
        )
        .await;
    assert_eq!(status, 409);
    let (status, out) = b
        .post_as(
            ADMIN_TOKEN,
            &format!("/admin/agents/{}/rotate-key", child.id),
            json!({}),
        )
        .await;
    assert_eq!(status, 409);
    assert!(
        out["detail"]
            .as_str()
            .unwrap()
            .contains("its key is its sandbox's")
    );
    assert_eq!(me_status(&b, &key).await, 200);
}

/// B-10: unpairing an agent VM disables its agents (and what they
/// minted); their keys stop working.
#[sqlx::test(migrations = "../store/migrations")]
async fn b10_unpairing_disables_the_vms_agents(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _orch, _child, child_key) = vm_with_child(&b).await;
    let orch_key = sb.key(ORCH).unwrap();
    let id = b.agent(ORCH).await.sandbox_id.unwrap();
    let resp = b
        .http()
        .delete(format!("{}/admin/daemons/{id}", b.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    for name in [ORCH, CHILD] {
        let a = b.agent(name).await;
        assert!(a.disabled, "{name}");
        assert_eq!(a.disabled_reason, Some(DisableReason::Unpaired));
        assert_eq!(a.sandbox_id, None);
    }
    assert_eq!(me_status(&b, &orch_key).await, 401);
    assert_eq!(me_status(&b, &child_key).await, 401);
    // Re-pairing adopts the orchestrator again, with a new key.
    let again = FakeSandbox::start(&b, "excelsior").await;
    let new = again.wait_key(ORCH).await;
    assert_eq!(me_status(&b, &new).await, 200);
    // Its minted child stays out: it no longer belongs to any VM.
    assert!(b.agent(CHILD).await.disabled);
}

// ------------------------------------------- what a sandbox is told

/// B-3: on connect a sandbox is told the lock state — `unlock` when the
/// broker is not locked (a missed unlock is resent) — then its held
/// agents, then its keys.
#[sqlx::test(migrations = "../store/migrations")]
async fn b3_on_connect_a_sandbox_gets_unlock_then_held_then_keys(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _, _) = vm(&b).await;
    let types = sb.types();
    let pos = |t: &str| types.iter().position(|x| x == t).unwrap();
    assert!(pos("unlock") < pos("agents.contained"), "{types:?}");
    assert!(pos("agents.contained") < pos("key"), "{types:?}");
    assert!(!types.contains(&"lockdown".to_owned()));
    assert_eq!(sb.of_type("agents.contained")[0]["agents"], json!([]));
}

/// B-3: a sandbox that connects while the broker is locked for it gets
/// `lockdown` (and its agents held by the lockdown's entry).
#[sqlx::test(migrations = "../store/migrations")]
async fn b3_on_connect_while_locked_a_sandbox_gets_lockdown(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (mut sb, _, _) = vm(&b).await;
    let hx = b.part.hostexec.clone().unwrap();
    crate::hostexec::lockdown::lockdown(&b.st, &hx, LockdownScope::Sandboxes, None, false, "jrt")
        .await
        .unwrap();
    sb.stop().await;
    let again = FakeSandbox::start(&b, HOST).await;
    assert!(eventually(|| async { !again.of_type("agents.contained").is_empty() }).await);
    let types = again.types();
    assert_eq!(
        types.first().map(String::as_str),
        Some("lockdown"),
        "{types:?}"
    );
    assert!(!types.contains(&"unlock".to_owned()));
    assert_eq!(
        again.of_type("agents.contained")[0]["agents"],
        json!([ORCH])
    );
}

/// Lockdown and unlock tell sandboxes their held lists; an unlock of one
/// host while the broker is still locked globally sends no `unlock`.
#[sqlx::test(migrations = "../store/migrations")]
async fn lockdown_and_unlock_tell_sandboxes_their_held_agents(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _, _) = vm(&b).await;
    let hx = b.part.hostexec.clone().unwrap();
    let before = sb.of_type("agents.contained").len();
    crate::hostexec::lockdown::lockdown(&b.st, &hx, LockdownScope::All, None, false, "jrt")
        .await
        .unwrap();
    assert!(!sb.of_type("lockdown").is_empty());
    let held = sb.of_type("agents.contained");
    assert!(held.len() > before);
    assert_eq!(held.last().unwrap()["agents"], json!([ORCH]));
    let unlocks = sb.of_type("unlock").len();
    // Unlocking this host alone leaves `*`: the VM stays locked.
    crate::hostexec::lockdown::unlock(&b.st, &hx, Some(HOST), None, "jrt")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sb.of_type("unlock").len(), unlocks);
    let out = crate::hostexec::lockdown::unlock(&b.st, &hx, None, None, "jrt")
        .await
        .unwrap();
    assert!(out.broker_locked.is_empty());
    assert!(eventually(|| async { sb.of_type("unlock").len() > unlocks }).await);
    assert_eq!(
        sb.of_type("agents.contained").last().unwrap()["agents"],
        json!([])
    );
}

/// Containment and its lifting tell the VM its complete held list.
#[sqlx::test(migrations = "../store/migrations")]
async fn containment_tells_the_vm_its_held_agents(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _, _) = vm(&b).await;
    let out = crate::containment::contain(
        &b.st,
        json!({"name": ORCH}),
        "test",
        "",
        "jrt",
        ContainmentSource::Operator,
    )
    .await
    .unwrap();
    let held = |want: Value| {
        let sb = &sb;
        async move {
            eventually(|| async {
                sb.of_type("agents.contained")
                    .last()
                    .map(|m| m["agents"].clone())
                    == Some(want.clone())
            })
            .await
        }
    };
    assert!(held(json!([ORCH])).await);
    let _ = out;
    crate::containment::lift_entries(&b.st, None, "jrt")
        .await
        .unwrap();
    assert!(held(json!([])).await);
}

// ----------------------------------------------- cross-project access

/// INV-22 (broker half): a project.read grant is applied by the daemon
/// with (project, target, access) and removed with project.revoke.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv22_project_read_is_applied_and_removed_by_the_sandbox(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _orch, child, child_key) = vm_with_child(&b).await;
    let r = ask(&b, &child, access_body("site", "project.read")).await;
    assert_eq!(r.status, RequestStatus::Granted, "{:?}", r.decision_reason);
    let call = sb.of_type("project.grant").pop().unwrap();
    let g = grant_of(&b, r.id).await;
    assert_eq!(call["grant_id"], json!(g.id.to_string()));
    assert_eq!(
        (&call["project"], &call["target"], &call["access"]),
        (&json!("larder"), &json!("site"), &json!("project.read"))
    );
    let (_, cred) = b
        .get_as(&child_key, &format!("/v1/grants/{}/credential", g.id))
        .await;
    assert_eq!(cred["kind"], json!("project_access"));
    assert!(
        cred["note"]
            .as_str()
            .unwrap()
            .contains("/var/lib/sandbox/projects/site")
    );
    crate::service::revoke_grant(&b.st, g.id, "test", "jrt")
        .await
        .unwrap();
    let revoke = sb.of_type("project.revoke").pop().unwrap();
    assert_eq!(revoke["grant_id"], json!(g.id.to_string()));
    assert_eq!(revoke["target"], json!("site"));
}

/// INV-7: project.write always goes to a human; one's own project is
/// refused.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv7_project_write_needs_a_human_and_own_project_is_refused(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_sb, orch, child, _) = vm_with_child(&b).await;
    let w = ask(&b, &child, access_body("site", "project.write")).await;
    assert_eq!(w.status, RequestStatus::AwaitingHuman);
    let own = ask(&b, &child, access_body("larder", "project.read")).await;
    assert_eq!(own.status, RequestStatus::Denied);
    assert!(own.decision_reason.unwrap().contains("own project"));
    // The orchestrator has no project: it cannot ask.
    let o = ask(&b, &orch, access_body("site", "project.read")).await;
    assert_eq!(o.status, RequestStatus::Denied);
    assert!(
        o.decision_reason
            .unwrap()
            .contains("only a project's agent")
    );
}

/// A daemon's refusal fails provisioning with its error.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_sandbox_refusal_fails_provisioning(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _orch, child, _) = vm_with_child(&b).await;
    sb.seen.lock().unwrap().refuse = Some("no project 'nope'".into());
    let r = ask(&b, &child, access_body("nope", "project.read")).await;
    assert_eq!(r.status, RequestStatus::ProvisionFailed);
    assert!(r.decision_reason.unwrap().contains("no project 'nope'"));
}

/// B-7 (broker half): a grant the daemon did not answer in time may still
/// be applied there, so it is taken back with a project.revoke.
#[sqlx::test(migrations = "../store/migrations")]
async fn b7_a_timed_out_project_grant_is_taken_back(pool: sqlx::PgPool) {
    let b = Broker::start_full(pool, POLICY, true, |ps| {
        for p in ps.iter_mut() {
            if let AnyProvisioner::Sandbox(s) = p {
                s.call_timeout = Duration::from_millis(300);
            }
        }
    })
    .await;
    let (sb, _orch, child, _) = vm_with_child(&b).await;
    sb.seen.lock().unwrap().delay = Some(Duration::from_millis(800));
    let r = ask(&b, &child, access_body("site", "project.read")).await;
    assert_eq!(r.status, RequestStatus::ProvisionFailed);
    assert!(r.decision_reason.unwrap().contains("did not answer"));
    let grant_id = sb.of_type("project.grant").pop().unwrap()["grant_id"].clone();
    assert!(
        eventually(|| async {
            sb.of_type("project.revoke")
                .iter()
                .any(|m| m["grant_id"] == grant_id)
        })
        .await
    );
}

/// B-14 and the catalog: `agents` only for the VM's orchestrator,
/// `sandbox` only for a project's agent, neither for an outsider.
#[sqlx::test(migrations = "../store/migrations")]
async fn the_catalog_shows_vm_platforms_only_to_vm_agents(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (sb, _orch, _child, child_key) = vm_with_child(&b).await;
    let orch_key = sb.key(ORCH).unwrap();
    let (_, outsider_key) = plain_agent(&b, "outsider", |_| {}).await;
    let p = platforms_of(&b, &orch_key).await;
    assert!(
        p.contains(&"agents".to_owned()) && !p.contains(&"sandbox".to_owned()),
        "{p:?}"
    );
    let p = platforms_of(&b, &child_key).await;
    assert!(
        p.contains(&"sandbox".to_owned()) && !p.contains(&"agents".to_owned()),
        "{p:?}"
    );
    let p = platforms_of(&b, &outsider_key).await;
    assert!(
        !p.contains(&"sandbox".to_owned()) && !p.contains(&"agents".to_owned()),
        "{p:?}"
    );
    let (_, cat) = b.get_as(&orch_key, "/v1/catalog").await;
    let agents = cat["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["platform"] == json!("agents"))
        .unwrap()
        .clone();
    assert_eq!(agents["capability_hint"], json!("mint"));
    assert_eq!(agents["capabilities"], json!(["claude", "codex"]));
    assert!(b.registry_has(agent_auth_core::Platform::Sandbox));
}

/// The reason precedence of the disable cascade (store): an operator's
/// disable is never downgraded by a later lease expiry, and re-enabling
/// clears the reason.
#[sqlx::test(migrations = "../store/migrations")]
async fn disable_reasons_keep_the_operators(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (a, _) = plain_agent(&b, "x", |_| {}).await;
    let tx = b.st.store.begin().await.unwrap();
    store::disable_tree(&tx, a.id, OffsetDateTime::now_utc(), DisableReason::Lease)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        b.agent("x").await.disabled_reason,
        Some(DisableReason::Lease)
    );
    let tx = b.st.store.begin().await.unwrap();
    store::disable_tree(
        &tx,
        a.id,
        OffsetDateTime::now_utc(),
        DisableReason::Operator,
    )
    .await
    .unwrap();
    store::disable_tree(&tx, a.id, OffsetDateTime::now_utc(), DisableReason::Lease)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        b.agent("x").await.disabled_reason,
        Some(DisableReason::Operator)
    );
    let tx = b.st.store.begin().await.unwrap();
    agents::set_disabled(&tx, a.id, false).await.unwrap();
    tx.commit().await.unwrap();
    let back = b.agent("x").await;
    assert!(!back.disabled && back.disabled_reason.is_none());
    // The database refuses a reason on an enabled agent.
    let tx = b.st.store.begin().await.unwrap();
    assert!(
        !agents::reenable_after_lease(
            &tx,
            a.id,
            "0123456789ab",
            &"0".repeat(64),
            OffsetDateTime::now_utc()
        )
        .await
        .unwrap()
    );
}

#[test]
fn the_key_box_error_text() {
    assert_eq!(
        super::QueueError::NoKeyBox.to_string(),
        "ENCRYPTION_KEY is required to hand keys to a sandbox"
    );
    let _ = Value::Null;
}

/// INV-7: a mint into a restricted zone always goes to a human, whatever
/// rule would approve it.
#[sqlx::test(migrations = "../store/migrations")]
async fn inv7_a_mint_into_a_restricted_zone_goes_to_a_human(pool: sqlx::PgPool) {
    let policy = format!(
        "{POLICY}projects: {{soc: {{}}}}\nrestricted:\n  soc: {{members: [{{project: soc}}]}}\n"
    );
    let b = Broker::start_with(pool, &policy, true).await;
    let (_sb, orch, _) = vm(&b).await;
    let r = ask(&b, &orch, mint_body("claude-soc-excelsior-sandbox")).await;
    assert_eq!(
        r.status,
        RequestStatus::AwaitingHuman,
        "{:?}",
        r.decision_reason
    );
    let free = ask(&b, &orch, mint_body(CHILD)).await;
    assert_eq!(free.status, RequestStatus::Granted);
}
