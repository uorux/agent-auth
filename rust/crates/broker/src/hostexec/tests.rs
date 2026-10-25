//! Commands on hosts end to end: the broker (request service, gate,
//! provisioner, results) and a real hostd over the loopback channel,
//! jobs run by hostd's direct executor (ported from
//! `tests/test_hostexec.py`; hostd's own decisions are tested in the hostd
//! crate).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use agent_auth_core::{JobId, RequestId, RequestStatus};
use agent_auth_store::hostexec::{self as store, JobStatus, NewJob};
use agent_auth_store::requests;
use agent_auth_wire::admin::LockdownScope;
use agent_auth_wire::agent::RequestCreate;
use agent_auth_wire::hostexec::ShellExecBody;
use serde_json::{Value, json};

use super::*;
use crate::daemons::testkit::{Broker, HOST, Host, caller, jrt, wait_until};
use crate::service::HumanDecision;

fn body(capability: &str, scope: Value) -> RequestCreate {
    serde_json::from_value(json!({
        "platform": "hostexec", "capability": capability, "resource": HOST,
        "scope": scope, "justification": "a specific task that needs it",
        "requested_duration": "1h",
    }))
    .unwrap()
}

async fn request(b: &Broker, id: RequestId) -> agent_auth_store::requests::RequestRow {
    let tx = b.st.store.begin().await.unwrap();
    requests::get(&tx, id).await.unwrap().unwrap().into_row()
}

async fn job(b: &Broker, id: JobId) -> agent_auth_store::hostexec::JobRow {
    for _ in 0..1500 {
        let tx = b.st.store.begin().await.unwrap();
        let j = store::get(&tx, id).await.unwrap();
        if let Some(j) = j.filter(|j| !matches!(j.status, JobStatus::Starting | JobStatus::Running))
        {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("job {id} did not end");
}

fn totp(code: String) -> HumanDecision {
    HumanDecision {
        approve: true,
        totp: Some(code),
        ..HumanDecision::default()
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn approve_needs_an_armed_tier_and_totp_works_disarmed(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let a = b.agent("claude-1").await;
    let r = crate::service::create(&b.st, &caller(&a), body("run", json!({"tier": "user", "argv": ["sh", "-c", "cat; echo err >&2; exit 3"], "stdin": "in\n"})))
        .await
        .unwrap();
    assert_eq!(r.status, RequestStatus::AwaitingHuman);
    // Approve without a code on a disarmed host: refused, still pending.
    let err = crate::service::decide(
        &b.st,
        r.id,
        &jrt(),
        HumanDecision {
            approve: true,
            ..HumanDecision::default()
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("excelsior: not_armed"), "{err}");
    assert_eq!(request(&b, r.id).await.status, RequestStatus::AwaitingHuman);
    // A wrong code is refused by the host, the request stays pending.
    let err = crate::service::decide(&b.st, r.id, &jrt(), totp("000000".into()))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "excelsior: wrong code");
    // With the user-direct code: runs, disarmed.
    let decided = crate::service::decide(&b.st, r.id, &jrt(), totp(host.code("user-direct", 0)))
        .await
        .unwrap();
    assert_eq!(decided.status, RequestStatus::Granted);
    let j = job(&b, JobId::for_request(r.id)).await;
    assert_eq!(j.status, JobStatus::Done);
    assert_eq!(j.via.as_deref(), Some("totp"));
    assert_eq!(j.exit_code, Some(3));
    assert_eq!(j.output.as_deref(), Some("in\nerr\n"));
    assert!(b.wait_recorded("job_finished").await);
    // The job API: the agent's own job, its output once done.
    let got = b
        .hostexec()
        .get_job(a.id, j.id, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    let out = job_out(&got, true);
    assert_eq!(out.output.as_deref(), Some("in\nerr\n"));
    let other = b.agent("claude-2").await;
    assert!(
        b.hostexec()
            .get_job(other.id, j.id, Duration::ZERO)
            .await
            .unwrap()
            .is_none()
    );
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_user_code_does_not_approve_a_root_command(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let a = b.agent("claude-1").await;
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        body("run", json!({"tier": "root", "argv": ["id"]})),
    )
    .await
    .unwrap();
    // The gate relays the code to the root-direct secret: a user code fails.
    let err = crate::service::decide(&b.st, r.id, &jrt(), totp(host.code("user-direct", 0)))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "excelsior: wrong code");
    assert_eq!(request(&b, r.id).await.status, RequestStatus::AwaitingHuman);
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_hosts_policy_refuses_before_a_code_is_spent(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let a = b.agent("claude-1").await;
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        body(
            "run",
            json!({"tier": "user", "argv": ["rm", "-rf", "/tmp/x"]}),
        ),
    )
    .await
    .unwrap();
    let code = host.code("user-direct", 0);
    let err = crate::service::decide(&b.st, r.id, &jrt(), totp(code.clone()))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "excelsior: that command is denied by this host's policy"
    );
    // The code was not spent: it still approves another request.
    let ok = crate::service::create(
        &b.st,
        &caller(&a),
        body("run", json!({"tier": "user", "argv": ["true"]})),
    )
    .await
    .unwrap();
    crate::service::decide(&b.st, ok.id, &jrt(), totp(code))
        .await
        .unwrap();
    // Validation fails fast at creation: unknown host, bad tier, unknown key.
    let bad = |scope: Value, resource: &str| {
        serde_json::from_value::<RequestCreate>(json!({
            "platform": "hostexec", "capability": "run", "resource": resource, "scope": scope,
            "justification": "x", "requested_duration": "1h"}))
        .unwrap()
    };
    for (scope, resource) in [
        (json!({"tier": "user", "argv": ["ls"]}), "nowhere"),
        (json!({"tier": "wheel", "argv": ["ls"]}), HOST),
        (json!({"tier": "user", "argv": []}), HOST),
    ] {
        let r = crate::service::create(&b.st, &caller(&a), bad(scope, resource))
            .await
            .unwrap();
        assert_eq!(r.status, RequestStatus::Denied, "{:?}", r.decision_reason);
    }
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn armed_approvals_and_templates_expanded_by_the_host(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let armed = b
        .hostexec()
        .arm(
            HOST,
            agent_auth_core::Tier::User,
            &agent_auth_wire::duration::HostDuration::parse("8h").unwrap(),
            &host.code("user-arm", 0),
        )
        .await
        .unwrap();
    assert!(armed["armed_until"].as_f64().unwrap() > 0.0);
    let a = b.agent("claude-1").await;
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        body(
            "tpl.greet",
            json!({"tier": "user", "params": {"name": "world"}}),
        ),
    )
    .await
    .unwrap();
    crate::service::decide(
        &b.st,
        r.id,
        &jrt(),
        HumanDecision {
            approve: true,
            ..HumanDecision::default()
        },
    )
    .await
    .unwrap();
    let j = job(&b, JobId::for_request(r.id)).await;
    assert_eq!(j.via.as_deref(), Some("armed+human"));
    assert_eq!(j.output.as_deref(), Some("hello world\n"));
    // Disarmed: refused again.
    b.hostexec().disarm(HOST, None).await.unwrap();
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        body("run", json!({"tier": "user", "argv": ["true"]})),
    )
    .await
    .unwrap();
    assert!(
        crate::service::decide(
            &b.st,
            r.id,
            &jrt(),
            HumanDecision {
                approve: true,
                ..HumanDecision::default()
            }
        )
        .await
        .is_err()
    );
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_shell_takes_a_code_and_shows_every_command_first(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let a = b.agent("claude-1").await;
    let r = crate::service::create(&b.st, &caller(&a), body("shell", json!({"tier": "user"})))
        .await
        .unwrap();
    assert_eq!(r.status, RequestStatus::AwaitingHuman);
    // Never without a code.
    let err = crate::service::decide(
        &b.st,
        r.id,
        &jrt(),
        HumanDecision {
            approve: true,
            ..HumanDecision::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "a shell is approved with a TOTP code only (Approve with TOTP)"
    );
    let d = HumanDecision {
        duration_secs: Some(600),
        ..totp(host.code("user-shell", 0))
    };
    crate::service::decide(&b.st, r.id, &jrt(), d)
        .await
        .unwrap();
    let tx = b.st.store.begin().await.unwrap();
    let grant = agent_auth_store::grants::by_request(&tx, r.id)
        .await
        .unwrap()
        .unwrap();
    drop(tx);
    let exec = |argv: &[&str]| -> ShellExecBody {
        serde_json::from_value(json!({"argv": argv, "wait": 5})).unwrap()
    };
    let job = b
        .hostexec()
        .shell_exec(a.id, grant.id, &exec(&["echo", "in a shell"]))
        .await
        .unwrap();
    let job = super::tests::job(&b, job.id).await;
    assert_eq!(job.output.as_deref(), Some("in a shell\n"));
    assert!(
        b.recorded()
            .iter()
            .any(|l| l == &format!("shell_command {}", job.id))
    );
    // The deny list applies inside a shell.
    let err = b
        .hostexec()
        .shell_exec(a.id, grant.id, &exec(&["rm", "x"]))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        ShellExecError::Refused("that command is denied by this host's policy".into())
    );
    // Another agent can't use it.
    let other = b.agent("claude-2").await;
    assert_eq!(
        b.hostexec()
            .shell_exec(other.id, grant.id, &exec(&["ls"]))
            .await
            .unwrap_err(),
        ShellExecError::NotFound
    );
    // Ending the grant closes the shell on the host.
    crate::service::revoke_grant(&b.st, grant.id, "done", "jrt")
        .await
        .unwrap();
    let err = b
        .hostexec()
        .shell_exec(a.id, grant.id, &exec(&["ls"]))
        .await
        .unwrap_err();
    assert_eq!(err, ShellExecError::Refused("that shell has ended".into()));
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn lockdown_stops_the_host_and_only_its_code_unlocks_it(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    let hx = b.hostexec();
    let out = lockdown::lockdown(&b.st, &hx, LockdownScope::All, None, false, "jrt")
        .await
        .unwrap();
    assert_eq!(out.daemons["host:excelsior"], "locked");
    assert!(host.hostd.lock_state().is_locked());
    // New requests for the host are refused at validation.
    let a = b.agent("claude-1").await;
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        body("run", json!({"tier": "user", "argv": ["true"]})),
    )
    .await
    .unwrap();
    assert_eq!(r.status, RequestStatus::Denied);
    // The broker's unlock alone leaves the host locked.
    let un = lockdown::unlock(&b.st, &hx, None, None, "jrt")
        .await
        .unwrap();
    assert!(un.broker_locked.is_empty());
    assert!(host.hostd.lock_state().is_locked());
    // A wrong root-unlock code is refused; the right one unlocks the host.
    let err = lockdown::unlock(&b.st, &hx, Some(HOST), Some("000000"), "jrt")
        .await
        .unwrap_err();
    assert_eq!(err.0, "wrong code");
    // A root-arm code doesn't unlock (a code typed to unlock can't arm).
    let err = lockdown::unlock(
        &b.st,
        &hx,
        Some(HOST),
        Some(&host.code("root-arm", 0)),
        "jrt",
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, "wrong code");
    lockdown::unlock(
        &b.st,
        &hx,
        Some(HOST),
        Some(&host.code("root-unlock", 0)),
        "jrt",
    )
    .await
    .unwrap();
    assert!(!host.hostd.lock_state().is_locked());
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_locked_broker_tells_a_host_that_connects(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let hx = b.hostexec();
    lockdown::lockdown(&b.st, &hx, LockdownScope::Host, Some(HOST), false, "jrt")
        .await
        .unwrap();
    let host = Host::start(&b).await;
    wait_until(|| host.hostd.lock_state().is_locked()).await;
    drop(host);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn jobs_without_a_result_become_lost(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let hx = b.hostexec();
    let a = b.agent("claude-1").await;
    // A request row for the job to hang off.
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        serde_json::from_value(json!({
        "platform": "homelab", "capability": "group", "resource": "svc-gitea",
        "justification": "x", "requested_duration": "1h"}))
        .unwrap(),
    )
    .await
    .unwrap();
    let old = time::OffsetDateTime::now_utc() - time::Duration::hours(3);
    let spec = json!({"kind": "run", "host": HOST, "tier": "user", "argv": ["sleep", "1"], "cwd": null,
                      "env": {}, "timeout": 600, "stdin": null});
    let tx = b.st.store.begin().await.unwrap();
    let id = JobId::new();
    store::insert(
        &tx,
        &NewJob {
            id,
            grant_id: None,
            request_id: r.id,
            agent_id: a.id,
            host: HOST,
            tier: agent_auth_core::Tier::User,
            shell_id: None,
            spec: &spec,
            now: old,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scheduler_tick(&hx, time::OffsetDateTime::now_utc())
            .await
            .unwrap(),
        1
    );
    let tx = b.st.store.begin().await.unwrap();
    let j = store::get(&tx, id).await.unwrap().unwrap();
    assert_eq!(j.status, JobStatus::Lost);
    assert_eq!(
        job_out(&j, true).status,
        agent_auth_wire::hostexec::JobStatus::Lost
    );
}

#[test]
fn tails_and_sanitized_status() {
    let text: String = (0..40).map(|i| format!("line {i}\n")).collect();
    let t = tail(Some(&text));
    assert!(t.starts_with("line 10"));
    assert!(t.ends_with("line 39"));
    let s = sanitize_status(Some(&json!({
        "tiers": {"user": {"enabled": true, "armed_until": 1e300}},
        "templates": ["ok", "Not OK", "../x"],
        "desktop": {"enabled": true, "present": true, "away_reason": "a\u{1b}[2Jb"},
        "version": "1.0 evil"
    })));
    assert_eq!(
        s.tiers[&agent_auth_wire::common::TierName::User].armed_until,
        None
    );
    assert_eq!(s.templates, vec!["ok".to_owned()]);
    assert_eq!(
        s.desktop.unwrap().away_reason.as_deref(),
        Some("a\\x1b[2Jb")
    );
    assert_eq!(s.version, None);
    assert_eq!(
        sanitize_status(Some(&json!({"tiers": {"admin": {}}})))
            .tiers
            .len(),
        0
    );
}
