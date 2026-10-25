//! Channel messages: every type, as the Python sends it (inside a verified
//! envelope body), parses; extras and out-of-bounds values are refused;
//! unknown types are told apart.

use serde_json::{Map, Value, json};

use crate::daemon::channel::{ChannelMessage, Incoming, parse};
use crate::daemon::handshake::{BrokerHandshake, DaemonHandshake};
use crate::daemon::host::{BrokerToHost, HostToBroker, Precheck};
use crate::daemon::sandbox::{BrokerToSandbox, SandboxToBroker};

const JOB: &str = "6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const REQ: &str = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9";
const CALL: &str = "4c0ffee0c0ffee0c0ffee0c0ffee0c0f";
const PROMPT: &str = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d";
const AGENT: &str = "11111111-2222-4333-8444-555555555555";
const GRANT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

/// `payload` as an envelope body: the six envelope keys added, as sealing
/// does.
fn sealed(payload: &Value) -> Map<String, Value> {
    let mut body = payload.as_object().unwrap().clone();
    body.insert("id".into(), json!("00000000000040008000000000000000"));
    body.insert("iss".into(), json!("broker"));
    body.insert("aud".into(), json!("host:excelsior"));
    body.insert("seq".into(), json!(7));
    body.insert("iat".into(), json!(1_767_225_600.5));
    body.insert("exp".into(), json!(1_767_225_660.5));
    body
}

/// Parses as a message, and serializing it gives a body that parses to the
/// same message.
#[track_caller]
fn known<T: ChannelMessage + PartialEq + std::fmt::Debug>(payload: Value) -> T {
    let message = match parse::<T>(sealed(&payload)) {
        Incoming::Message(m) => m,
        other => panic!("{payload}: {other:?}"),
    };
    let again = serde_json::to_value(&message).unwrap();
    match parse::<T>(again.as_object().unwrap().clone()) {
        Incoming::Message(back) => assert_eq!(back, message),
        other => panic!("re-parse of {again}: {other:?}"),
    }
    message
}

#[track_caller]
fn malformed<T: ChannelMessage + std::fmt::Debug>(payload: Value) -> String {
    match parse::<T>(sealed(&payload)) {
        Incoming::Malformed { error, .. } => error,
        other => panic!("{payload}: {other:?}"),
    }
}

fn job_spec() -> Value {
    json!({"kind": "run", "host": "excelsior", "tier": "user", "argv": ["uptime"],
           "cwd": null, "env": {}, "timeout": 600, "stdin": null})
}

fn shell_spec() -> Value {
    json!({"kind": "shell", "host": "excelsior", "tier": "root", "duration": 900})
}

#[test]
fn broker_to_host_every_type() {
    let samples = [
        json!({"type": "hostexec.precheck", "job_id": REQ, "spec": job_spec(), "source": "human",
               "totp": true, "call_id": CALL}),
        json!({"type": "hostexec.precheck", "spec": job_spec(), "source": "rule", "window": true,
               "call_id": CALL}),
        json!({"type": "hostexec.precheck", "kind": "shell", "tier": "root", "duration": 900,
               "call_id": CALL}),
        json!({"type": "hostexec.authorize", "job_id": REQ, "tier": "user",
               "digest": "ab".repeat(32), "totp": "123456", "call_id": CALL}),
        json!({"type": "job.start", "job_id": REQ, "spec": job_spec(),
               "evidence": {"request_id": REQ, "decided_by": "window:abc", "source": "rule",
                            "window": true}, "call_id": CALL}),
        json!({"type": "job.start", "job_id": REQ, "spec": job_spec(),
               "evidence": {"request_id": REQ, "decided_by": null, "source": null, "window": false},
               "call_id": CALL}),
        json!({"type": "job.kill", "job_id": JOB, "call_id": CALL}),
        json!({"type": "job.ack", "job_id": JOB}),
        json!({"type": "shell.open", "shell_id": REQ, "spec": shell_spec(), "call_id": CALL}),
        json!({"type": "shell.exec", "shell_id": REQ, "job_id": JOB, "spec": job_spec(),
               "call_id": CALL}),
        json!({"type": "shell.close", "shell_id": REQ, "call_id": CALL}),
        json!({"type": "shell.close", "shell_id": REQ}),
        json!({"type": "arm", "tier": "root", "duration": "30m", "totp": "123456", "call_id": CALL}),
        json!({"type": "arm", "tier": "user", "duration": 3600, "totp": "123456", "call_id": CALL}),
        json!({"type": "disarm", "tier": null, "call_id": CALL}),
        json!({"type": "disarm", "tier": "root", "call_id": CALL}),
        json!({"type": "lockdown", "kill_vm": false}),
        json!({"type": "lockdown", "kill_vm": true, "call_id": CALL}),
        json!({"type": "unlock", "totp": "123456", "call_id": CALL}),
        json!({"type": "dnd", "duration": 3600}),
        json!({"type": "dnd", "duration": null}),
        json!({"type": "prompt", "prompt_id": PROMPT, "request_id": REQ, "who": "claude-x",
               "what": "run uptime", "detail": "because", "timeout": 90, "call_id": CALL}),
        json!({"type": "prompt", "prompt_id": PROMPT, "request_id": REQ, "who": "claude-x",
               "what": "run uptime", "detail": "", "timeout": 90,
               "job": {"job_id": REQ, "spec": job_spec()}, "call_id": CALL}),
        json!({"type": "prompt.cancel", "prompt_id": PROMPT}),
        json!({"type": "notify", "title": "agent-auth: claude-x", "text": "hello",
               "urgency": "critical", "call_id": CALL}),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for sample in samples {
        let m: BrokerToHost = known(sample.clone());
        seen.insert(sample["type"].as_str().unwrap().to_owned());
        assert_eq!(
            m.call_id().map(|c| c.as_str().to_owned()),
            sample
                .get("call_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        );
    }
    let all: std::collections::BTreeSet<String> = BrokerToHost::TYPES
        .iter()
        .map(|t| (*t).to_owned())
        .collect();
    assert_eq!(seen, all, "a sample per type");
}

#[test]
fn precheck_forms_are_distinguished() {
    let shell: BrokerToHost = known(json!({"type": "hostexec.precheck", "kind": "shell",
                                           "tier": "user", "duration": 60}));
    assert!(matches!(shell, BrokerToHost::Precheck(Precheck::Shell(_))));
    let job: BrokerToHost = known(json!({"type": "hostexec.precheck", "spec": job_spec(),
                                         "source": "human", "totp": false}));
    assert!(matches!(job, BrokerToHost::Precheck(Precheck::Job(_))));
    // Neither form: a kind other than shell, or both forms' fields.
    malformed::<BrokerToHost>(
        json!({"type": "hostexec.precheck", "kind": "run", "tier": "user",
                                     "duration": 60}),
    );
    malformed::<BrokerToHost>(
        json!({"type": "hostexec.precheck", "kind": "shell", "tier": "user",
                                     "duration": 60, "spec": {}}),
    );
}

#[test]
fn host_to_broker_every_type() {
    let samples = [
        json!({"type": "heartbeat", "status": {"version": "0.1", "role": "host",
               "started_at": 1_767_225_600.25,
               "tiers": {"user": {"enabled": true, "armed_until": null, "shell": false, "totp": true}},
               "jobs": 0, "shells": 0, "lockdown": false, "vm": null, "templates": ["restart"],
               "desktop": {"enabled": false, "present": false, "away_reason": "desktop prompts off",
                           "dnd_until": null}}}),
        json!({"type": "heartbeat", "status": {"error": "status unavailable", "version": "0.1"}}),
        json!({"type": "reply", "call_id": CALL, "ok": true, "data": {"via": "totp"}}),
        json!({"type": "reply", "call_id": CALL, "ok": false,
               "error": "not_armed: the root tier of excelsior is not armed"}),
        // The chunk index arrives as `chunk`; a Python hostd's `seq` was
        // replaced by the envelope's and is stripped with it.
        json!({"type": "job.output", "job_id": JOB, "chunk": 0, "data": "aGVsbG8K"}),
        json!({"type": "job.output", "job_id": JOB, "data": "aGVsbG8K"}),
        json!({"type": "job.done", "job_id": JOB, "exit_code": 0, "error": null,
               "duration_secs": 0.012, "bytes": 6, "sha256": "cd".repeat(32), "truncated": false}),
        json!({"type": "job.done", "job_id": JOB, "exit_code": null,
               "error": "hostd restarted while the job was running; its outcome is unknown",
               "duration_secs": null, "bytes": 0, "sha256": "e3".repeat(32), "truncated": false}),
        json!({"type": "presence", "enabled": true, "present": false, "away_reason": "locked",
               "dnd_until": 1_767_229_200.0}),
        json!({"type": "prompt.answer", "prompt_id": PROMPT, "answer": "allow", "authorized": true}),
    ];
    for sample in samples {
        let _: HostToBroker = known(sample);
    }
}

#[test]
fn sandbox_every_type() {
    let to_sandbox = [
        json!({"type": "key", "agent_id": AGENT, "name": "orchestrator-galaxy-sandbox",
               "runtime": "orchestrator", "project": null, "api_key": "aa_0123456789ab_secret"}),
        json!({"type": "project.grant", "grant_id": GRANT, "project": "a", "target": "b",
               "access": "project.read", "call_id": CALL}),
        json!({"type": "project.revoke", "grant_id": GRANT, "project": "a", "target": "b",
               "call_id": CALL}),
        json!({"type": "lockdown", "kill_vm": false, "call_id": CALL}),
        json!({"type": "unlock"}),
        json!({"type": "agents.contained", "agents": ["claude-a-galaxy-sandbox"]}),
        json!({"type": "agents.contained", "agents": [], "call_id": CALL}),
    ];
    for sample in to_sandbox {
        let m: BrokerToSandbox = known(sample);
        // The key never prints.
        assert!(!format!("{m:?}").contains("aa_0123456789ab_secret"));
    }
    let from_sandbox = [
        json!({"type": "heartbeat", "status": {"version": "0.1", "role": "sandbox", "host": "galaxy",
               "agents": 2, "projects": 1, "conversations": {"running": 1}, "lockdown": false,
               "processes": 1}}),
        json!({"type": "reply", "call_id": CALL, "ok": true}),
        json!({"type": "reply", "call_id": null, "ok": false, "error": "no such project"}),
        json!({"type": "key.ack", "agent_id": AGENT}),
        json!({"type": "key.rotate", "name": "claude-a-galaxy-sandbox"}),
    ];
    for sample in from_sandbox {
        let _: SandboxToBroker = known(sample);
    }
    assert!(
        malformed::<BrokerToSandbox>(json!({"type": "project.grant", "grant_id": GRANT,
            "project": "a", "target": "b", "access": "project.admin"}))
        .contains("unknown variant")
    );
}

#[test]
fn unknown_types_and_extras() {
    match parse::<BrokerToHost>(sealed(&json!({"type": "teleport", "where": "moon"}))) {
        Incoming::UnknownType(t) => assert_eq!(t, "teleport"),
        other => panic!("{other:?}"),
    }
    // A sandbox message is not a host's.
    assert!(matches!(
        parse::<BrokerToHost>(sealed(&json!({"type": "key.ack", "agent_id": AGENT}))),
        Incoming::UnknownType(_)
    ));
    assert!(matches!(
        parse::<HostToBroker>(sealed(&json!({"no_type": 1}))),
        Incoming::Malformed { .. }
    ));
    assert!(matches!(
        parse::<HostToBroker>(sealed(&json!({"type": 5}))),
        Incoming::Malformed { .. }
    ));
    // Extra fields in a known type are refused.
    let e = malformed::<BrokerToHost>(json!({"type": "job.ack", "job_id": JOB, "extra": 1}));
    assert!(e.contains("unknown field"), "{e}");
    let e = malformed::<HostToBroker>(json!({"type": "prompt.answer", "prompt_id": PROMPT,
                                             "answer": "allow", "authorized": true, "x": 0}));
    assert!(e.contains("unknown field"), "{e}");
    // Ids are UUIDs. (Core's id types still deserialize other UUID spellings,
    // e.g. upper case, and re-serialize them canonically; see the report.)
    malformed::<BrokerToHost>(json!({"type": "job.kill", "job_id": "../../etc/passwd"}));
    malformed::<HostToBroker>(
        json!({"type": "prompt.answer", "prompt_id": PROMPT.to_uppercase(),
                                     "answer": "deny", "authorized": false}),
    );
    malformed::<HostToBroker>(json!({"type": "reply", "call_id": "x", "ok": true}));
    // Bounds.
    malformed::<HostToBroker>(json!({"type": "job.output", "job_id": JOB, "chunk": 0,
                                     "data": "A".repeat(131_073)}));
    malformed::<HostToBroker>(json!({"type": "job.done", "job_id": JOB, "exit_code": 0,
        "error": null, "duration_secs": 1.0, "bytes": 0, "sha256": "short", "truncated": false}));
    malformed::<BrokerToHost>(
        json!({"type": "notify", "title": "t", "text": "x".repeat(5000),
                                     "urgency": "normal"}),
    );
    malformed::<BrokerToHost>(json!({"type": "notify", "title": "t", "text": "x",
                                     "urgency": "apocalyptic"}));
    malformed::<BrokerToHost>(json!({"type": "arm", "tier": "root", "duration": true,
                                     "totp": "1"}));
    malformed::<BrokerToHost>(
        json!({"type": "hostexec.authorize", "job_id": REQ, "tier": "user",
                                     "digest": "AB".repeat(32), "totp": "1"}),
    );
    let huge_spec = json!({"kind": "run", "argv": ["x".repeat(600_000)]});
    malformed::<BrokerToHost>(
        json!({"type": "job.start", "job_id": REQ, "spec": huge_spec,
        "evidence": {"request_id": REQ, "decided_by": null, "source": null, "window": false}}),
    );
    let names: Vec<String> = (0..10_001).map(|i| format!("a{i}")).collect();
    malformed::<BrokerToSandbox>(json!({"type": "agents.contained", "agents": names}));
}

#[test]
fn envelope_keys_never_reach_a_message() {
    // A message type that would collide with an envelope key cannot be
    // expressed: they are stripped before parsing.
    let m: HostToBroker = known(json!({"type": "job.output", "job_id": JOB, "data": ""}));
    let v = serde_json::to_value(&m).unwrap();
    for key in crate::daemon::channel::ENVELOPE_KEYS {
        assert!(v.get(key).is_none(), "{key}");
    }
}

#[test]
fn handshake_frames() {
    let challenge: BrokerHandshake =
        serde_json::from_value(json!({"type": "challenge", "nonce": "n"})).unwrap();
    assert!(matches!(challenge, BrokerHandshake::Challenge(_)));
    let nonce43 = "A".repeat(43);
    let sig86 = "B".repeat(86);
    let hello = json!({"type": "hello", "role": "host", "name": "excelsior", "nonce": nonce43,
                       "params": "{\"version\": \"0.1\"}", "sig": sig86});
    let parsed: DaemonHandshake = serde_json::from_value(hello.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), hello);
    let welcome = json!({"type": "welcome", "params": "{\"heartbeat_secs\": 30}", "sig": sig86});
    let parsed: BrokerHandshake = serde_json::from_value(welcome.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), welcome);
    // Bad hellos (4400).
    for bad in [
        json!({"type": "hello", "role": "toaster", "name": "x", "nonce": "n", "params": "{}", "sig": "s"}),
        json!({"type": "hello", "role": "host", "name": "X!", "nonce": "n", "params": "{}", "sig": "s"}),
        json!({"type": "hello", "role": "host", "name": "x", "nonce": 5, "params": "{}", "sig": "s"}),
        json!({"type": "hello", "role": "host", "name": "x", "nonce": "n", "params": {}, "sig": "s"}),
        json!({"type": "hello", "role": "host", "name": "x", "nonce": "n", "params": "{}"}),
        json!({"type": "hello", "role": "host", "name": "x", "nonce": "a+b/", "params": "{}", "sig": "s"}),
        json!({"type": "hello", "role": "host", "name": "x", "nonce": "n", "params": "{}", "sig": "s", "x": 1}),
        json!({"type": "welcome", "params": "{}", "sig": "s"}),
    ] {
        assert!(
            serde_json::from_value::<DaemonHandshake>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}
