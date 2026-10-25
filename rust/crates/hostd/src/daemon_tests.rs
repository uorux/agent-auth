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
const KEY: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
        for name in SecretName::ALL {
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
        for _ in 0..500 {
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
    assert_eq!(done["error"], json!("killed"));
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
    t.call(authorize(&shell, "user", &spec, &t.code("user-direct")))
        .await
        .unwrap();
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
    assert_eq!(t.done(&job_id(54)).await["error"], json!("killed"));
    assert!(
        t.call(exec(55, &["ls"], "user"))
            .await
            .unwrap_err()
            .starts_with("no such shell")
    );
}

#[tokio::test]
async fn lockdown_stops_everything_and_only_the_root_arm_code_unlocks() {
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
    assert_eq!(t.done(&job_id(60)).await["error"], json!("killed"));
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
    // A wrong root-arm code doesn't unlock; a user-arm code is not a root code.
    assert_eq!(
        t.call(json!({"type": "unlock", "totp": "000000"}))
            .await
            .unwrap_err(),
        "wrong code"
    );
    let err = t
        .call(json!({"type": "unlock", "totp": t.code_peek("user-arm")}))
        .await
        .unwrap_err();
    assert_eq!(err, "wrong code");
    let unlocked = t
        .call(json!({"type": "unlock", "totp": t.code_peek("root-arm")}))
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
    // The orphan can't start again under its id, and lockdown kills it.
    hostd.lockdown("test", false).await.unwrap();
    assert!(hostd.orphans().is_empty());
    assert_eq!(
        hostd.executor().recorded.lock().unwrap().killed,
        vec![lost.to_string()]
    );
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
    let mut rx = t.hostd.helper_attached(7, 1234).await;
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
    // No password: no approval, the answer becomes "discord".
    t.hostd.executor().recorded.lock().unwrap().password_ok = false;
    t.hostd.answered(prompt_id, "allow", 7).await;
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
    // An answer from another (replaced) connection is not this host's approval.
    t.hostd.answered(p2, "allow", 8).await;
    assert!(t.call(start(&job_id(91), &spec, None)).await.is_err());
    let p3 = "11111111-2222-4333-8444-555555555557";
    t.call(
        json!({"type": "prompt", "prompt_id": p3, "request_id": job_id(92),
                  "who": "agent-1", "what": "", "detail": "", "timeout": 30,
                  "job": {"job_id": job_id(92), "spec": spec}}),
    )
    .await
    .unwrap();
    t.hostd.answered(p3, "allow", 7).await;
    let started = t.call(start(&job_id(92), &spec, None)).await.unwrap();
    assert_eq!(started["via"], json!("desk"));
    assert_eq!(t.done(&job_id(92)).await["output"], json!("a\nb\n"));
    let polkit = t.hostd.executor().recorded.lock().unwrap().polkit.clone();
    assert_eq!(polkit.len(), 2);
    assert_eq!(polkit[1].0, 1234);
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
    let _rx = t.hostd.helper_attached(1, 1).await;
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
    assert_eq!(
        t.call(prompt).await.unwrap_err(),
        "nobody is at this desktop"
    );
}
