//! hostd's handlers end to end, without a broker: messages as the broker
//! sends them (envelope bodies), real TOTP secrets and state files, and
//! jobs run by the direct executor as this test's own user (ported from
//! `tests/test_hostexec.py`; the broker-side halves are in the broker).
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agent_auth_core::Tier;
use agent_auth_core::hostd::LocalId;
use agent_auth_core::hostd::totp::SecretName;
use agent_auth_crypto::digest::digest;
use agent_auth_crypto::totp::TotpSecret;
use agent_auth_daemon::localsock::{LocalApi as _, Peer};
use serde_json::{Map, Value, json};

use super::*;
use crate::ctl::Ctl;
use crate::executor::direct::DirectExecutor;
use crate::fsutil::testdir::TestDir;

const HOST: &str = "excelsior";
const KEY: &str = "ed25519:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const USER_UID: u32 = 4242;

fn find(program: &str) -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let p = std::path::Path::new(dir).join(program);
        if p.is_file() {
            return p.to_string_lossy().into_owned();
        }
    }
    program.to_owned()
}

struct T {
    _dir: TestDir,
    hostd: Arc<Hostd<DirectExecutor>>,
    secrets: BTreeMap<&'static str, TotpSecret>,
}

fn config(dir: &TestDir, extra: impl FnOnce(&mut Value)) -> HostConfig {
    let mut raw = json!({
        "broker_url": "https://broker.example",
        "broker_public_key": KEY,
        "name": HOST,
        "state_dir": dir.path().join("state").to_string_lossy(),
        "runtime_dir": dir.path().join("run").to_string_lossy(),
        "user": "jrt",
        "tiers": {
            "user": {"enable": true, "max_arm": "1h", "accept_approve_all": true,
                     "shell": {"enable": true, "max_duration": "10m"}},
            "root": {"enable": true, "max_arm": "30m",
                     "shell": {"enable": true, "max_duration": "5m"}}
        },
        "auto_commands": [["true"]],
        "deny_commands": [["rm", "**"]],
        "templates": {"greet": {"tier": "user", "argv": ["echo", "hello", "{name}"],
                                "params": {"name": "[a-z]+"}}},
        "env_allow": ["LANG", "GREETING"],
        "vm_unit": "microvm@agents.service",
        "desktop": {"enable": true, "approve": {"user": true, "root": true}},
    });
    extra(&mut raw);
    HostConfig::from_json(&raw, false).unwrap()
}

impl T {
    fn new() -> T {
        T::with(|_| {})
    }

    fn with(extra: impl FnOnce(&mut Value)) -> T {
        let dir = TestDir::new("hostd");
        let cfg = config(&dir, extra);
        T::start(dir, cfg)
    }

    fn start(dir: TestDir, cfg: HostConfig) -> T {
        let exec = DirectExecutor::new(&std::env::var("PATH").unwrap_or_default(), &find("kill"));
        let hostd = Hostd::new(cfg, exec);
        hostd.pin_user_uid(Some(USER_UID));
        let mut secrets = BTreeMap::new();
        for name in SecretName::every() {
            secrets.insert(name.as_str(), hostd.totp().enroll(name, false).unwrap());
        }
        T {
            _dir: dir,
            hostd,
            secrets,
        }
    }

    /// The code for `name` now, without moving the clock.
    fn code_peek(&self, name: &str) -> String {
        let step = self.hostd.totp_now() / 30;
        self.secrets[name].code_at(step).expose().clone()
    }

    /// The code for `name` now; the clock moves on one step after each,
    /// so tests can use as many as they like.
    fn code(&self, name: &str) -> String {
        let step = self.hostd.totp_now() / 30;
        let code = self.secrets[name].code_at(step).expose().clone();
        self.hostd.totp_skew.fetch_add(30, Ordering::Relaxed);
        code
    }

    async fn call(&self, msg: Value) -> Result<Map<String, Value>, String> {
        let Value::Object(mut body) = msg else {
            panic!()
        };
        body.insert("call_id".into(), json!("0123456789abcdef0123456789abcdef"));
        let reply = self.hostd.handle(body).await.expect("a reply");
        if reply["ok"] == json!(true) {
            Ok(reply["data"].as_object().cloned().unwrap_or_default())
        } else {
            Err(reply["error"].as_str().unwrap_or("").to_owned())
        }
    }

    async fn done(&self, job: &str) -> Map<String, Value> {
        let id = LocalId::parse(job).unwrap();
        for _ in 0..1500 {
            if let Some(d) = self.hostd.spool.done(&id) {
                let mut r = d.result;
                r.insert("output".into(), json!(String::from_utf8_lossy(&d.output)));
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job {job} did not finish");
    }

    async fn ctl(&self, uid: u32, method: &str, params: Value) -> Result<Value, String> {
        let Value::Object(p) = params else { panic!() };
        Ctl(Arc::clone(&self.hostd))
            .call(
                method,
                p,
                None,
                Peer {
                    uid,
                    gid: 0,
                    pid: Some(1),
                },
            )
            .await
            .map_err(|e| e.0)
    }
}

/// Killed while running, or before it started (a kill that lands first
/// keeps it from starting at all).
fn stopped(error: &Value) -> bool {
    matches!(
        error.as_str(),
        Some("killed" | "killed before it started" | "locked down before it started")
    )
}

fn job_id(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn run_spec(tier: &str, argv: &[&str]) -> Value {
    json!({"kind": "run", "host": HOST, "tier": tier, "argv": argv, "cwd": null,
           "env": {}, "timeout": 600, "stdin": null})
}

fn evidence(source: Option<&str>, window: bool) -> Value {
    json!({"request_id": job_id(999), "decided_by": "jacob", "source": source, "window": window})
}

fn start(id: &str, spec: &Value, source: Option<&str>) -> Value {
    json!({"type": "job.start", "job_id": id, "spec": spec, "evidence": evidence(source, false)})
}

fn authorize(id: &str, tier: &str, spec: &Value, code: &str) -> Value {
    json!({"type": "hostexec.authorize", "job_id": id, "tier": tier,
           "digest": digest(spec).unwrap(), "totp": code})
}

#[tokio::test]
async fn approve_counts_only_while_the_tier_is_armed() {
    let t = T::new();
    let spec = run_spec("user", &["echo", "hi"]);
    let err = t
        .call(start(&job_id(1), &spec, Some("human")))
        .await
        .unwrap_err();
    assert!(
        err.starts_with("not_armed: the user tier of excelsior"),
        "{err}"
    );
    // A wrong arm code arms nothing.
    let err = t
        .call(json!({"type": "arm", "tier": "user", "duration": "1h", "totp": "000000"}))
        .await
        .unwrap_err();
    assert_eq!(err, "wrong code");
    // Arming is capped at max_arm (1h).
    let armed = t
        .call(json!({"type": "arm", "tier": "user", "duration": "8h", "totp": t.code("user-arm")}))
        .await
        .unwrap();
    let until = armed["armed_until"].as_f64().unwrap();
    assert!((until - now_f64() - 3600.0).abs() < 5.0);
    let started = t
        .call(start(&job_id(2), &spec, Some("human")))
        .await
        .unwrap();
    assert_eq!(started["via"], json!("armed+human"));
    assert_eq!(t.done(&job_id(2)).await["output"], json!("hi\n"));
    // The same id never runs twice.
    assert_eq!(
        t.call(start(&job_id(2), &spec, Some("human")))
            .await
            .unwrap_err(),
        "that job already ran here"
    );
    t.call(json!({"type": "disarm", "tier": null}))
        .await
        .unwrap();
    assert!(
        t.call(start(&job_id(3), &spec, Some("human")))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn approve_with_totp_works_disarmed_and_binds_digest_and_tier() {
    let t = T::new();
    let mut spec = run_spec("user", &["sh", "-c", "cat; echo err >&2; exit 3"]);
    spec["stdin"] = json!("from stdin\n");
    let id = job_id(10);
    // Precheck with a code coming: the host would take it.
    let pre = t
        .call(json!({"type": "hostexec.precheck", "spec": spec, "source": "human", "totp": true, "job_id": id}))
        .await
        .unwrap();
    assert_eq!(pre["via"], json!("totp"));
    t.call(authorize(&id, "user", &spec, &t.code("user-direct")))
        .await
        .unwrap();
    let started = t.call(start(&id, &spec, Some("human"))).await.unwrap();
    assert_eq!(started["via"], json!("totp"));
    let done = t.done(&id).await;
    assert_eq!(done["exit_code"], json!(3));
    assert_eq!(done["output"], json!("from stdin\nerr\n"));
    assert_eq!(done["truncated"], json!(false));
    assert_eq!(done["sha256"], json!(sha256_hex(b"from stdin\nerr\n")));

    // A code is bound to the request it was typed for: another spec under
    // the same id is refused (and the approval is spent).
    let other = run_spec("user", &["echo", "other"]);
    let id = job_id(11);
    t.call(authorize(&id, "user", &spec, &t.code("user-direct")))
        .await
        .unwrap();
    assert!(t.call(start(&id, &other, None)).await.is_err());

    // A user-direct code relayed with a root job's digest admits nothing.
    let root = run_spec("root", &["echo", "root"]);
    let id = job_id(12);
    let err = t
        .call(authorize(&id, "root", &root, &t.code("user-direct")))
        .await
        .unwrap_err();
    assert_eq!(err, "wrong code");
    // Even when the broker names the user tier for it.
    t.call(authorize(&id, "user", &root, &t.code("user-direct")))
        .await
        .unwrap();
    assert!(
        t.call(start(&id, &root, None))
            .await
            .unwrap_err()
            .starts_with("no approval evidence")
    );
    // A code is single use.
    let code = t.code("user-direct");
    t.call(authorize(&job_id(13), "user", &spec, &code))
        .await
        .unwrap();
    assert!(
        t.call(authorize(&job_id(14), "user", &spec, &code))
            .await
            .unwrap_err()
            .contains("already used")
    );
}

#[tokio::test]
async fn the_hosts_policy_refuses_whatever_the_approval() {
    let t = T::new();
    let denied = run_spec("user", &["rm", "-rf", "/tmp/x"]);
    // Refused at precheck, before a code is spent on it.
    let err = t
        .call(json!({"type": "hostexec.precheck", "spec": denied, "source": "human", "totp": true}))
        .await
        .unwrap_err();
    assert_eq!(err, "that command is denied by this host's policy");
    let mut env = run_spec("user", &["env"]);
    env["env"] = json!({"AWS_SECRET": "x"});
    assert_eq!(
        t.call(start(&job_id(20), &env, Some("human")))
            .await
            .unwrap_err(),
        "environment variables not allowed on this host: AWS_SECRET"
    );
    let mut other = run_spec("user", &["ls"]);
    other["host"] = json!("enterprise");
    assert!(
        t.call(start(&job_id(21), &other, None))
            .await
            .unwrap_err()
            .contains("'enterprise'")
    );
    // Auto patterns run unarmed (user tier, run only).
    assert_eq!(
        t.call(start(&job_id(22), &run_spec("user", &["true"]), None))
            .await
            .unwrap()["via"],
        json!("auto")
    );
    assert!(
        t.call(start(&job_id(23), &run_spec("root", &["true"]), None))
            .await
            .is_err()
    );
    // A malformed message is answered, not dropped.
    let err = t
        .call(json!({"type": "job.start", "job_id": "nope"}))
        .await
        .unwrap_err();
    assert!(err.starts_with("malformed job.start"), "{err}");
}

#[tokio::test]
async fn templates_are_expanded_by_the_host() {
    let t = T::new();
    t.call(json!({"type": "arm", "tier": "user", "duration": 600, "totp": t.code("user-arm")}))
        .await
        .unwrap();
    let spec = json!({"kind": "tpl", "host": HOST, "tier": "user", "template": "greet",
                      "params": {"name": "world"}, "cwd": null, "env": {}, "timeout": 600, "stdin": null});
    t.call(start(&job_id(30), &spec, Some("human")))
        .await
        .unwrap();
    assert_eq!(t.done(&job_id(30)).await["output"], json!("hello world\n"));
    let mut root = spec.clone();
    root["tier"] = json!("root");
    assert_eq!(
        t.call(start(&job_id(31), &root, Some("human")))
            .await
            .unwrap_err(),
        "template 'greet' is a user-tier template"
    );
}

#[tokio::test]
async fn output_keeps_its_end_and_a_killed_job_says_so() {
    let t = T::new();
    t.call(json!({"type": "arm", "tier": "user", "duration": 600, "totp": t.code("user-arm")}))
        .await
        .unwrap();
    let big = run_spec("user", &["sh", "-c", "head -c 1100000 /dev/zero; echo END"]);
    t.call(start(&job_id(40), &big, Some("human")))
        .await
        .unwrap();
    let done = t.done(&job_id(40)).await;
    assert_eq!(done["bytes"], json!(1024 * 1024));
    assert_eq!(done["truncated"], json!(true));
    assert!(done["output"].as_str().unwrap().ends_with("END\n"));

    let slow = run_spec("user", &["sleep", "30"]);
    t.call(start(&job_id(41), &slow, Some("human")))
        .await
        .unwrap();
    let killed = t
        .call(json!({"type": "job.kill", "job_id": job_id(41)}))
        .await
        .unwrap();
    assert_eq!(killed["killed"], json!(true));
    let done = t.done(&job_id(41)).await;
    assert!(stopped(&done["error"]), "{}", done["error"]);
    assert_eq!(
        t.call(json!({"type": "job.kill", "job_id": job_id(41)}))
            .await
            .unwrap()["killed"],
        json!(false)
    );
    // Acked: the spool goes.
    t.call(json!({"type": "job.ack", "job_id": job_id(41)}))
        .await
        .unwrap();
    assert!(!t.hostd.spool.exists(&LocalId::parse(&job_id(41)).unwrap()));
}

#[tokio::test]
async fn a_job_timeout_kills_its_whole_group() {
    let t = T::new();
    t.call(json!({"type": "arm", "tier": "user", "duration": 600, "totp": t.code("user-arm")}))
        .await
        .unwrap();
    let mut spec = run_spec("user", &["sh", "-c", "sleep 60 & sleep 60"]);
    spec["timeout"] = json!(1);
    t.call(start(&job_id(45), &spec, Some("human")))
        .await
        .unwrap();
    let done = t.done(&job_id(45)).await;
    assert_eq!(done["exit_code"], json!(143));
    assert!(done["duration_secs"].as_f64().unwrap() < 10.0);
}

#[tokio::test]
async fn shells_take_a_totp_code_and_stay_bounded() {
    let t = T::new();
    let shell = job_id(50);
    let spec = json!({"kind": "shell", "host": HOST, "tier": "user", "duration": 300});
    let pre = t
        .call(
            json!({"type": "hostexec.precheck", "kind": "shell", "tier": "user", "duration": 300}),
        )
        .await
        .unwrap();
    assert_eq!(pre["needs"], json!("totp"));
    assert!(
        t.call(
            json!({"type": "hostexec.precheck", "kind": "shell", "tier": "user", "duration": 601})
        )
        .await
        .unwrap_err()
        .contains("lasts at most 600s")
    );
    // Arming does not open a shell.
    t.call(json!({"type": "arm", "tier": "user", "duration": 600, "totp": t.code("user-arm")}))
        .await
        .unwrap();
    let open = json!({"type": "shell.open", "shell_id": shell, "spec": spec});
    assert_eq!(
        t.call(open.clone()).await.unwrap_err(),
        "a shell is opened with a TOTP code only"
    );
    // A direct code (typed to approve a command) doesn't open a shell
    // once the tier has a shell secret (security review 2026-10, finding 4).
    t.call(authorize(&shell, "user", &spec, &t.code("user-direct")))
        .await
        .unwrap();
    assert_eq!(
        t.call(open.clone()).await.unwrap_err(),
        "a user shell is opened with a user-shell code"
    );
    // Nor is a direct code relayed as a shell code checked as one.
    let mut as_shell = authorize(&shell, "user", &spec, &t.code_peek("user-direct"));
    as_shell["shell"] = json!(true);
    assert_eq!(t.call(as_shell).await.unwrap_err(), "wrong code");
    let mut a = authorize(&shell, "user", &spec, &t.code("user-shell"));
    a["shell"] = json!(true);
    t.call(a).await.unwrap();
    let opened = t.call(open).await.unwrap();
    assert!(opened["expires_at"].as_f64().unwrap() > now_f64() + 290.0);
    let exec = |id: u32, argv: &[&str], tier: &str| json!({"type": "shell.exec", "shell_id": shell, "job_id": job_id(id), "spec": run_spec(tier, argv)});
    t.call(exec(51, &["echo", "in a shell"], "user"))
        .await
        .unwrap();
    assert_eq!(t.done(&job_id(51)).await["output"], json!("in a shell\n"));
    assert_eq!(
        t.call(exec(52, &["ls"], "root")).await.unwrap_err(),
        "that is a user shell"
    );
    assert!(t.call(exec(53, &["rm", "x"], "user")).await.is_err());
    // Ending the shell kills what runs in it.
    t.call(exec(54, &["sleep", "30"], "user")).await.unwrap();
    let closed = t
        .call(json!({"type": "shell.close", "shell_id": shell}))
        .await
        .unwrap();
    assert_eq!(closed["closed"], json!(true));
    assert!(stopped(&t.done(&job_id(54)).await["error"]));
    assert!(
        t.call(exec(55, &["ls"], "user"))
            .await
            .unwrap_err()
            .starts_with("no such shell")
    );
}

#[tokio::test]
async fn lockdown_stops_everything_and_only_the_root_unlock_code_unlocks() {
    let t = T::new();
    t.call(json!({"type": "arm", "tier": "user", "duration": 600, "totp": t.code("user-arm")}))
        .await
        .unwrap();
    t.call(start(
        &job_id(60),
        &run_spec("user", &["sleep", "30"]),
        Some("human"),
    ))
    .await
    .unwrap();
    let locked = t
        .call(json!({"type": "lockdown", "kill_vm": false}))
        .await
        .unwrap();
    assert_eq!(locked["vm"], json!("freeze: ok"));
    assert!(stopped(&t.done(&job_id(60)).await["error"]));
    assert_eq!(
        t.call(start(&job_id(61), &run_spec("user", &["true"]), None))
            .await
            .unwrap_err(),
        "excelsior is locked down"
    );
    // Arming is refused while locked, and the arm code is not spent on it
    // (daemons bug 8).
    let code = t.code_peek("user-arm");
    assert_eq!(
        t.call(json!({"type": "arm", "tier": "user", "duration": 60, "totp": code.clone()}))
            .await
            .unwrap_err(),
        "excelsior is locked down"
    );
    // A wrong code doesn't unlock; neither does a user-arm code, nor the
    // root-arm code (a code typed to unlock can't arm, and the reverse;
    // security review 2026-10, finding 4).
    assert_eq!(
        t.call(json!({"type": "unlock", "totp": "000000"}))
            .await
            .unwrap_err(),
        "wrong code"
    );
    for other in ["user-arm", "root-arm"] {
        let err = t
            .call(json!({"type": "unlock", "totp": t.code_peek(other)}))
            .await
            .unwrap_err();
        assert_eq!(err, "wrong code");
    }
    let unlocked = t
        .call(json!({"type": "unlock", "totp": t.code_peek("root-unlock")}))
        .await
        .unwrap();
    assert_eq!(unlocked["locked"], json!(false));
    assert_eq!(unlocked["vm"], json!("thaw: ok"));
    // Unlocked is not armed.
    assert!(
        t.call(start(
            &job_id(62),
            &run_spec("user", &["ls"]),
            Some("human")
        ))
        .await
        .is_err()
    );
    // The arm code refused while locked still works.
    t.call(json!({"type": "arm", "tier": "user", "duration": 60, "totp": code}))
        .await
        .unwrap();
    let units = t.hostd.executor().recorded.lock().unwrap().units.clone();
    assert_eq!(
        units,
        vec![
            ("freeze".to_owned(), "microvm@agents.service".to_owned()),
            ("thaw".to_owned(), "microvm@agents.service".to_owned())
        ]
    );
}

#[tokio::test]
async fn lockdown_survives_a_restart_and_jobs_running_at_a_crash_are_lost_and_killable() {
    let t = T::new();
    t.call(json!({"type": "lockdown", "kill_vm": true}))
        .await
        .unwrap();
    // A job that was running when hostd died, and its unit still running.
    let lost = LocalId::parse(&job_id(70)).unwrap();
    t.hostd
        .spool
        .write_running(&lost, Tier::Root, now_f64())
        .unwrap();
    let cfg = t.hostd.config.clone();
    let T { _dir, .. } = t;
    let exec = DirectExecutor::new("/bin", "kill");
    exec.recorded.lock().unwrap().leftover = vec![lost.clone()];
    let hostd = Hostd::new(cfg, exec);
    hostd.recover().await;
    assert!(hostd.lock_state().is_locked());
    let done = hostd.spool.done(&lost).unwrap();
    assert_eq!(
        done.result["error"],
        json!("hostd restarted while the job was running; its outcome is unknown")
    );
    assert_eq!(done.result["lost"], json!(true));
    assert_eq!(hostd.orphans(), vec![lost.clone()]);
    // Locked at startup: its unit was stopped before anything else
    // (security review 2026-10, finding 2).
    assert_eq!(
        hostd.executor().recorded.lock().unwrap().killed,
        vec![lost.to_string()]
    );
    // A unit hostd knows nothing of: lockdown sweeps every job unit too.
    let stray = LocalId::parse(&job_id(71)).unwrap();
    hostd.executor().recorded.lock().unwrap().leftover = vec![lost.clone(), stray.clone()];
    hostd.lockdown("test", false).await.unwrap();
    assert!(hostd.orphans().is_empty());
    let killed = hostd.executor().recorded.lock().unwrap().killed.clone();
    assert!(killed.contains(&stray.to_string()), "{killed:?}");
    drop(_dir);
}

#[tokio::test]
async fn hostctl_rules() {
    let t = T::new();
    // Neither root nor the configured user.
    assert_eq!(
        t.ctl(999, "status", json!({})).await.unwrap_err(),
        "not for this user"
    );
    assert!(t.ctl(USER_UID, "status", json!({})).await.is_ok());
    // The user arms the user tier only, without a code.
    assert!(
        t.ctl(USER_UID, "arm", json!({"duration": "10m"}))
            .await
            .is_ok()
    );
    assert_eq!(
        t.ctl(USER_UID, "arm", json!({"tier": "root"}))
            .await
            .unwrap_err(),
        "arm needs root"
    );
    // Root arming is capped at max_arm (30m).
    let out = t
        .ctl(0, "arm", json!({"tier": "root", "duration": "8h"}))
        .await
        .unwrap();
    assert!((out["armed_until"].as_f64().unwrap() - now_f64() - 1800.0).abs() < 5.0);
    // The user may lock, never unlock.
    t.ctl(USER_UID, "lockdown", json!({})).await.unwrap();
    assert_eq!(
        t.ctl(USER_UID, "unlock", json!({})).await.unwrap_err(),
        "unlock needs root"
    );
    t.ctl(0, "unlock", json!({})).await.unwrap();
    assert!(!t.hostd.lock_state().is_locked());
    assert!(
        t.ctl(USER_UID, "presence", json!({"state": "sleepy"}))
            .await
            .is_err()
    );
    assert_eq!(
        t.ctl(0, "nope", json!({})).await.unwrap_err(),
        "unknown method 'nope'"
    );
    // TOTP locks: wrong codes lock, only root clears.
    for _ in 0..5 {
        let _ = t
            .call(json!({"type": "arm", "tier": "user", "duration": 60, "totp": "000000"}))
            .await;
    }
    let err = t
        .call(json!({"type": "arm", "tier": "user", "duration": 60, "totp": t.code("user-arm")}))
        .await
        .unwrap_err();
    assert!(err.contains("locked"), "{err}");
    let status = t.ctl(0, "status", json!({})).await.unwrap();
    assert_eq!(status["tiers"]["user"]["totp_locked"], json!(true));
    assert_eq!(
        t.ctl(USER_UID, "totp-unlock", json!({"name": "user-arm"}))
            .await
            .unwrap_err(),
        "totp-unlock needs root"
    );
    t.ctl(0, "totp-unlock", json!({"name": "user-arm"}))
        .await
        .unwrap();
    t.call(json!({"type": "arm", "tier": "user", "duration": 60, "totp": t.code("user-arm")}))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_host_without_tiers_runs_nothing() {
    let t = T::with(|raw| {
        raw["tiers"] = json!({});
        raw["auto_commands"] = json!([["true"]]);
    });
    let err = t
        .call(start(&job_id(80), &run_spec("user", &["true"]), None))
        .await
        .unwrap_err();
    assert_eq!(err, "the user tier is not enabled on excelsior");
    let status = t.hostd.status();
    assert_eq!(status["tiers"]["user"]["enabled"], json!(false));
    assert_eq!(status["role"], json!("host"));
}

#[tokio::test]
async fn allow_at_its_own_desk_approves_exactly_that_command() {
    let t = T::new();
    let mut rx = t.hostd.helper_attached(7, 1234, Some(4321)).await;
    for state in ["unlocked", "active"] {
        t.ctl(USER_UID, "presence", json!({"state": state}))
            .await
            .unwrap();
    }
    let mut spec = run_spec("root", &["sh", "-c", "echo a\necho b"]);
    spec["stdin"] = json!("secret-ish\n");
    let prompt_id = "11111111-2222-4333-8444-555555555555";
    let shown = t
        .call(
            json!({"type": "prompt", "prompt_id": prompt_id, "request_id": job_id(90),
                     "who": "agent-1", "what": "broker text", "detail": "why", "timeout": 30,
                     "job": {"job_id": job_id(90), "spec": spec}}),
        )
        .await
        .unwrap();
    assert_eq!(shown["approves"], json!(true));
    let line: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    // What it shows is what would run: the newline visible, stdin shown.
    assert_eq!(
        line["what"],
        json!("run on excelsior as ROOT: sh -c $'echo a\\necho b'")
    );
    assert!(
        line["detail"]
            .as_str()
            .unwrap()
            .contains("stdin (11 chars): $'secret-ish\\n'")
    );
    // The helper answers by hostd's nonce, not the broker's prompt id.
    let nonce = line["id"].as_str().unwrap().to_owned();
    assert_ne!(nonce, prompt_id);
    t.hostd.answered(prompt_id, "allow", 7).await;
    assert!(t.call(start(&job_id(90), &spec, None)).await.is_err());
    // No password: no approval, the answer becomes "discord".
    t.hostd.executor().recorded.lock().unwrap().password_ok = false;
    t.hostd.answered(&nonce, "allow", 7).await;
    assert!(t.call(start(&job_id(90), &spec, None)).await.is_err());
    // With the password: exactly that job, that digest.
    t.hostd.executor().recorded.lock().unwrap().password_ok = true;
    let p2 = "11111111-2222-4333-8444-555555555556";
    t.call(
        json!({"type": "prompt", "prompt_id": p2, "request_id": job_id(91),
                  "who": "agent-1", "what": "", "detail": "", "timeout": 30,
                  "job": {"job_id": job_id(91), "spec": spec}}),
    )
    .await
    .unwrap();
    let line: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    let nonce = line["id"].as_str().unwrap().to_owned();
    // An answer from another connection is not this host's approval.
    t.hostd.answered(&nonce, "allow", 8).await;
    assert!(t.call(start(&job_id(91), &spec, None)).await.is_err());
    let p3 = "11111111-2222-4333-8444-555555555557";
    t.call(
        json!({"type": "prompt", "prompt_id": p3, "request_id": job_id(92),
                  "who": "agent-1", "what": "", "detail": "", "timeout": 30,
                  "job": {"job_id": job_id(92), "spec": spec}}),
    )
    .await
    .unwrap();
    let line: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    let nonce = line["id"].as_str().unwrap().to_owned();
    t.hostd.answered(&nonce, "allow", 7).await;
    let started = t.call(start(&job_id(92), &spec, None)).await.unwrap();
    assert_eq!(started["via"], json!("desk"));
    assert_eq!(t.done(&job_id(92)).await["output"], json!("a\nb\n"));
    let polkit = t.hostd.executor().recorded.lock().unwrap().polkit.clone();
    assert_eq!(polkit.len(), 2);
    // The process as it was when it connected.
    assert_eq!(
        polkit[1].0,
        crate::executor::Process {
            pid: 1234,
            start_time: Some(4321)
        }
    );
}

#[tokio::test]
async fn nobody_at_the_desk_means_no_prompt() {
    let t = T::new();
    let prompt = json!({"type": "prompt", "prompt_id": "11111111-2222-4333-8444-555555555555",
                        "request_id": job_id(95), "who": "a", "what": "b", "detail": "c", "timeout": 30});
    assert_eq!(
        t.call(prompt.clone()).await.unwrap_err(),
        "nobody is at this desktop"
    );
    let _rx = t.hostd.helper_attached(1, 1, None).await;
    // Lock state unknown: away.
    assert_eq!(
        t.call(prompt.clone()).await.unwrap_err(),
        "nobody is at this desktop"
    );
    t.ctl(USER_UID, "presence", json!({"state": "unlocked"}))
        .await
        .unwrap();
    assert_eq!(
        t.call(prompt.clone()).await.unwrap()["approves"],
        json!(false)
    );
    t.ctl(USER_UID, "dnd", json!({"duration": "1h"}))
        .await
        .unwrap();
    // (A prompt id that was shown is spent: a fresh one.)
    let mut again = prompt;
    again["prompt_id"] = json!("11111111-2222-4333-8444-555555555565");
    assert_eq!(
        t.call(again).await.unwrap_err(),
        "nobody is at this desktop"
    );
}

#[tokio::test]
async fn a_desk_is_shown_everything_or_not_asked_and_prompt_ids_are_single() {
    let t = T::new();
    let _rx = t.hostd.helper_attached(7, 1234, None).await;
    t.ctl(USER_UID, "presence", json!({"state": "unlocked"}))
        .await
        .unwrap();
    let prompt = |id: &str, spec: &Value| {
        json!({"type": "prompt", "prompt_id": id, "request_id": job_id(96), "who": "a",
               "what": "", "detail": "", "timeout": 30,
               "job": {"job_id": job_id(96), "spec": spec}})
    };
    let p1 = "11111111-2222-4333-8444-555555555551";
    t.call(prompt(p1, &run_spec("user", &["true"])))
        .await
        .unwrap();
    // The same id again (a swapped job behind an open dialog): refused.
    assert_eq!(
        t.call(prompt(p1, &run_spec("user", &["rm", "-r", "x"])))
            .await
            .unwrap_err(),
        "that prompt is already up"
    );
    // A command too long to show whole is not asked at the desk.
    let long = "x".repeat(700);
    assert_eq!(
        t.call(prompt(
            "11111111-2222-4333-8444-555555555552",
            &run_spec("user", &["echo", &long])
        ))
        .await
        .unwrap_err(),
        "too long to show in full at a desk"
    );
}

/// Security review 2026-10, finding 1: with `desktop.approve.root` off and
/// root armed, a root command is not asked at the desk at all, and a desk
/// click relayed by the broker (`decided_by` `desktop:...`) admits nothing
/// on the armed tier.
#[tokio::test]
async fn a_desk_click_never_approves_on_an_armed_tier() {
    let t = T::with(|raw| raw["desktop"]["approve"] = json!({"user": true}));
    let mut rx = t.hostd.helper_attached(7, 1234, None).await;
    t.ctl(USER_UID, "presence", json!({"state": "unlocked"}))
        .await
        .unwrap();
    t.call(json!({"type": "arm", "tier": "root", "duration": 600, "totp": t.code("root-arm")}))
        .await
        .unwrap();
    let spec = run_spec("root", &["id"]);
    let err = t
        .call(
            json!({"type": "prompt", "prompt_id": "11111111-2222-4333-8444-555555555560",
                     "request_id": job_id(100), "who": "a", "what": "", "detail": "", "timeout": 30,
                     "job": {"job_id": job_id(100), "spec": spec}}),
        )
        .await
        .unwrap_err();
    assert_eq!(err, "this desk doesn't approve root commands");
    assert!(rx.try_recv().is_err(), "nothing was shown");
    // The broker relays a desk click anyway: refused on the armed tier.
    let mut msg = start(&job_id(100), &spec, Some("human"));
    msg["evidence"]["decided_by"] = json!("desktop:excelsior");
    let err = t.call(msg).await.unwrap_err();
    assert!(err.starts_with("a desk answer approves only"), "{err}");
    // A human's approval on Discord still counts while armed.
    t.call(start(&job_id(101), &spec, Some("human")))
        .await
        .unwrap();
}

/// Security review 2026-10, finding 1d: an answer counts only from the
/// helper connection the prompt was shown on, even if another connection
/// of the user's has replaced it since.
#[tokio::test]
async fn only_the_connection_shown_a_prompt_answers_it() {
    let t = T::new();
    let mut rx = t.hostd.helper_attached(7, 1234, None).await;
    t.ctl(USER_UID, "presence", json!({"state": "unlocked"}))
        .await
        .unwrap();
    let spec = run_spec("user", &["id"]);
    t.call(
        json!({"type": "prompt", "prompt_id": "11111111-2222-4333-8444-555555555561",
                  "request_id": job_id(102), "who": "a", "what": "", "detail": "", "timeout": 30,
                  "job": {"job_id": job_id(102), "spec": spec}}),
    )
    .await
    .unwrap();
    let line: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    let nonce = line["id"].as_str().unwrap().to_owned();
    // Another connection of the user's takes the helper's place and
    // answers the prompt it didn't show.
    let _rx2 = t.hostd.helper_attached(8, 999, None).await;
    t.hostd.answered(&nonce, "allow", 8).await;
    assert!(t.call(start(&job_id(102), &spec, None)).await.is_err());
}

/// Security review 2026-10, findings 1e and 6: a process inside a job's
/// unit is refused on ctl.sock (it can't arm its own tier or unlock) and
/// as the desktop helper.
#[tokio::test]
async fn a_job_can_be_neither_hostctl_nor_the_desk() {
    let t = T::new();
    let procs = TestDir::new("proc");
    let job_pid = 4100;
    let desk_pid = 4101;
    for (pid, cgroup) in [
        (job_pid, "0::/system.slice/aa-job-0123abcd-0000.service\n"),
        (desk_pid, "0::/user.slice/user-4242.slice/session-2.scope\n"),
    ] {
        std::fs::create_dir_all(procs.path().join(pid.to_string())).unwrap();
        std::fs::write(procs.path().join(format!("{pid}/cgroup")), cgroup).unwrap();
    }
    t.hostd.set_proc_root(procs.path().to_path_buf());
    let ctl = Ctl(Arc::clone(&t.hostd));
    let peer = |uid: u32, pid: i32| Peer {
        uid,
        gid: 0,
        pid: Some(pid),
    };
    for uid in [USER_UID, 0] {
        assert_eq!(
            ctl.admit(peer(uid, job_pid)).await.unwrap_err().0,
            "not from inside a job"
        );
        assert!(ctl.admit(peer(uid, desk_pid)).await.is_ok());
    }
    // Unknown process: refused (fail closed).
    assert!(ctl.admit(peer(0, 4199)).await.is_err());
    assert!(ctl.admit(peer(999, desk_pid)).await.is_err());
    // As the helper: over the real socket, from this process placed in a job.
    let me = std::process::id();
    let my_uid = {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        Peer::of(&tokio::net::UnixStream::from_std(a).unwrap())
            .unwrap()
            .uid
    };
    let dir = TestDir::new("usersock");
    let procs2 = TestDir::new("proc2");
    std::fs::create_dir_all(procs2.path().join(me.to_string())).unwrap();
    std::fs::write(
        procs2.path().join(format!("{me}/cgroup")),
        "0::/system.slice/aa-job-1.service\n",
    )
    .unwrap();
    let cfg = config(&dir, |_| {});
    let hostd = Hostd::new(
        cfg,
        DirectExecutor::new(&std::env::var("PATH").unwrap_or_default(), &find("kill")),
    );
    hostd.pin_user_uid(Some(my_uid));
    hostd.set_proc_root(procs2.path().to_path_buf());
    let path = dir.path().join("user.sock");
    let listener = agent_auth_daemon::localsock::bind(&path, 0o600).unwrap();
    let server = tokio::spawn(crate::desk::serve(listener, Arc::clone(&hostd)));
    let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let _ = s
        .write_all(b"{\"type\":\"presence\",\"locked\":false,\"fresh\":true}\n")
        .await;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "closed at once");
    assert_eq!(hostd.status()["desktop"]["present"], json!(false));
    server.abort();
}

/// Security review 2026-10, finding 5: an arming racing a lockdown never
/// leaves the host locked and armed (the lockdown lands as the arming
/// starts).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arming_never_survives_a_concurrent_lockdown() {
    let t = T::new();
    let hostd = Arc::clone(&t.hostd);
    *t.hostd.arm_hook.lock().unwrap() = Some(Box::new(move || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(hostd.lockdown("test", false))
                .unwrap();
        });
    }));
    let armed = t.hostd.arm_local(Tier::User, 600, LocalCaller::Root, 0);
    assert!(t.hostd.lock_state().is_locked());
    assert_eq!(armed.unwrap_err(), "excelsior is locked down");
    assert!(t.hostd.status()["tiers"]["user"]["armed_until"].is_null());
}
