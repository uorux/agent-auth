//! Desk prompts with a real hostd and a stand-in desktop helper (ported
//! from `tests/test_desktop.py`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use agent_auth_core::RequestStatus;
use agent_auth_hostd::presence::PresenceEvent;
use agent_auth_store::requests;
use agent_auth_wire::agent::RequestCreate;
use serde_json::{Value, json};
use tokio::sync::mpsc::Receiver;

use crate::daemons::testkit::{Broker, HOST, Host, caller, wait_until};

/// A host whose user is at the desk: the helper attached, unlocked.
async fn at_desk(b: &Broker) -> (Host, Receiver<String>) {
    let host = Host::start(b).await;
    let rx = host.hostd.helper_attached(1, 4242).await;
    host.hostd.presence_event(PresenceEvent::Unlocked);
    host.hostd.presence_changed().await;
    let desktop = b.part.desktop.clone().unwrap();
    for _ in 0..200 {
        if desktop.present_hosts().await == vec![HOST.to_owned()] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(desktop.present_hosts().await, vec![HOST.to_owned()]);
    (host, rx)
}

async fn next_prompt(rx: &mut Receiver<String>) -> Value {
    loop {
        let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a prompt")
            .unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        if v["type"] == json!("prompt") {
            return v;
        }
    }
}

fn homelab() -> RequestCreate {
    serde_json::from_value(json!({
        "platform": "homelab", "capability": "group", "resource": "svc-gitea",
        "justification": "deploy the thing", "requested_duration": "1h"}))
    .unwrap()
}

async fn status(b: &Broker, id: agent_auth_core::RequestId) -> requests::RequestRow {
    let tx = b.st.store.begin().await.unwrap();
    requests::get(&tx, id).await.unwrap().unwrap().into_row()
}

async fn settled(b: &Broker, id: agent_auth_core::RequestId) -> requests::RequestRow {
    for _ in 0..750 {
        let r = status(b, id).await;
        if !matches!(
            r.status,
            RequestStatus::AwaitingHuman | RequestStatus::Provisioning
        ) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("not decided");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_request_is_asked_at_the_desk_and_the_answer_decides(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (host, mut rx) = at_desk(&b).await;
    let a = b.agent("desk-1").await;
    let r = crate::service::create(&b.st, &caller(&a), homelab())
        .await
        .unwrap();
    assert_eq!(r.status, RequestStatus::AwaitingHuman);
    let prompt = next_prompt(&mut rx).await;
    assert_eq!(prompt["who"], json!("desk-1"));
    assert!(
        prompt["what"]
            .as_str()
            .unwrap()
            .starts_with("homelab / group on svc-gitea")
    );
    assert!(
        prompt["detail"]
            .as_str()
            .unwrap()
            .contains("The agent says (unverified): deploy the thing")
    );
    host.hostd
        .answered(prompt["id"].as_str().unwrap(), "allow", 1)
        .await;
    let r = settled(&b, r.id).await;
    assert_eq!(r.status, RequestStatus::Granted);
    assert_eq!(r.decided_by.as_deref(), Some("desktop:excelsior"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_deny_at_the_desk_denies_and_pauses_that_agent(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (host, mut rx) = at_desk(&b).await;
    let a = b.agent("desk-1").await;
    let r = crate::service::create(&b.st, &caller(&a), homelab())
        .await
        .unwrap();
    let prompt = next_prompt(&mut rx).await;
    host.hostd
        .answered(prompt["id"].as_str().unwrap(), "deny", 1)
        .await;
    let r = settled(&b, r.id).await;
    assert_eq!(r.status, RequestStatus::Denied);
    assert!(
        r.decision_reason
            .unwrap_or_default()
            .contains("denied at the desk")
    );
    let again = crate::service::create(&b.st, &caller(&a), homelab())
        .await
        .unwrap();
    let desktop = b.part.desktop.clone().unwrap();
    assert_eq!(
        desktop.refusal(&again, &a),
        Some("this agent's desktop prompts are paused")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn who_is_never_asked_and_answers_for_unknown_prompts_count_for_nothing(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (host, _rx) = at_desk(&b).await;
    let desktop = b.part.desktop.clone().unwrap();
    // An agent not listed.
    let other = b.agent("claude-1").await;
    let r = crate::service::create(&b.st, &caller(&other), homelab())
        .await
        .unwrap();
    assert_eq!(
        desktop.refusal(&r, &other),
        Some("agent not listed under desktop.agents")
    );
    // A shell, ever.
    let a = b.agent("desk-1").await;
    let shell: RequestCreate = serde_json::from_value(json!({
        "platform": "hostexec", "capability": "shell", "resource": HOST,
        "scope": {"tier": "user"}, "justification": "x", "requested_duration": "1h"}))
    .unwrap();
    let r = crate::service::create(&b.st, &caller(&a), shell)
        .await
        .unwrap();
    assert_eq!(desktop.refusal(&r, &a), Some("never asked on a desktop"));
    // An answer for a prompt nobody sent decides nothing.
    let pending = crate::service::create(&b.st, &caller(&other), homelab())
        .await
        .unwrap();
    host.hostd
        .answered("11111111-2222-4333-8444-555555555555", "allow", 1)
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        status(&b, pending.id).await.status,
        RequestStatus::AwaitingHuman
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn rates_keep_an_agent_from_flooding_the_desk(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_host, _rx) = at_desk(&b).await;
    let desktop = b.part.desktop.clone().unwrap();
    let a = b.agent("desk-1").await;
    let r = crate::service::create(&b.st, &caller(&a), homelab())
        .await
        .unwrap();
    // Two in the burst window were already taken (the request was
    // surfaced once on creation, reserving a slot): one more fits.
    assert_eq!(desktop.refusal(&r, &a), None);
    assert_eq!(
        desktop.refusal(&r, &a),
        Some("desktop rate-limited (agent)")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn allow_at_its_own_desk_approves_exactly_that_command(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (host, mut rx) = at_desk(&b).await;
    let a = b.agent("desk-1").await;
    let run: RequestCreate = serde_json::from_value(json!({
        "platform": "hostexec", "capability": "run", "resource": HOST,
        "scope": {"tier": "user", "argv": ["echo", "from the desk"]},
        "justification": "x", "requested_duration": "1h"}))
    .unwrap();
    let r = crate::service::create(&b.st, &caller(&a), run)
        .await
        .unwrap();
    let prompt = next_prompt(&mut rx).await;
    // hostd says what it would run.
    assert_eq!(
        prompt["what"],
        json!("run on excelsior as jrt: echo 'from the desk'")
    );
    host.hostd
        .answered(prompt["id"].as_str().unwrap(), "allow", 1)
        .await;
    let r = settled(&b, r.id).await;
    assert_eq!(r.status, RequestStatus::Granted, "{:?}", r.decision_reason);
    let mut job = None;
    for _ in 0..750 {
        let tx = b.st.store.begin().await.unwrap();
        let j = agent_auth_store::hostexec::get(&tx, agent_auth_core::JobId::for_request(r.id))
            .await
            .unwrap();
        drop(tx);
        if j.as_ref().is_some_and(|j| {
            j.status != agent_auth_store::hostexec::JobStatus::Starting
                && j.status != agent_auth_store::hostexec::JobStatus::Running
        }) {
            job = j;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let job = job.unwrap_or_else(|| panic!("the job did not end: {:?}", b.recorded()));
    assert_eq!(
        job.status,
        agent_auth_store::hostexec::JobStatus::Done,
        "{:?}",
        job.error
    );
    assert_eq!(job.via.as_deref(), Some("desk"));
    assert_eq!(job.output.as_deref(), Some("from the desk\n"));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_can_ask_for_attention_on_the_desks(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let (_host, mut rx) = at_desk(&b).await;
    let desktop = b.part.desktop.clone().unwrap();
    let a = b.agent("desk-1").await;
    let shown = desktop.notify(&a, "<b>look</b>", "high").await;
    assert_eq!(shown, vec![HOST.to_owned()]);
    let line: Value = loop {
        let v: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        if v["type"] == json!("notify") {
            break v;
        }
    };
    assert_eq!(line["title"], json!("agent-auth: desk-1"));
    assert_eq!(line["urgency"], json!("critical"));
    // Do-not-disturb: nothing on the desks.
    desktop.set_dnd(3600).await;
    assert!(desktop.notify(&a, "again", "normal").await.is_empty());
    wait_until(|| true).await;
}
