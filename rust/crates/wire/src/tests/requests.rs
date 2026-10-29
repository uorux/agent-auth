//! Request bodies: what the Python tests and the clients send is accepted,
//! unknown fields are refused, and every limit holds.

use serde_json::{Value, json};

use super::{accepted, refused, with_extra};
use crate::a2a::{SessionCreate, ThreadCloseBody, ThreadMessageBody, ThreadOpenBody};
use crate::admin::{
    AgentAttributesBody, AgentCreate, AgentRenameBody, ArmBody, DecideBody, LockdownBody,
    LockdownScope, PairingCodeCreate, Patch, SetKindBody, SetWebhookBody, UnlockBody,
};
use crate::agent::{AttentionBody, RequestCreate, RetryBody};
use crate::chat::{ChatClose, ChatOpen, ChatSend};
use crate::common::{DaemonRole, SettableKind, TierName};
use crate::containment::{ContainBody, LiftBody};
use crate::daemon::pairing::PairBody;
use crate::duration::HostDuration;
use crate::error::{BodyError, parse_body};
use crate::hostexec::ShellExecBody;
use crate::wiki::{PageDelete, PageWrite};
use agent_auth_core::Platform;

/// Every request body type with a valid sample: each refuses an unknown key.
#[test]
fn every_request_body_refuses_unknown_fields() {
    macro_rules! check {
        ($($ty:ty => $sample:expr),* $(,)?) => {$(
            let sample: Value = $sample;
            let _: $ty = accepted(sample.clone());
            let msg = refused::<$ty>(with_extra(sample));
            assert!(msg.contains("unknown field `bogus`"), "{}: {msg}", stringify!($ty));
        )*};
    }
    check! {
        AttentionBody => json!({"text": "please look at the deploy", "urgency": "high"}),
        RequestCreate => json!({"platform": "a2a", "capability": "talk", "resource": "bob",
                                "justification": "ask bob for the logs", "requested_duration": "1h"}),
        RetryBody => json!({"justification": "a better reason"}),
        SessionCreate => json!({"label": "conv-1"}),
        ThreadOpenBody => json!({"to": "auto-r", "payload": {"hi": 1}}),
        ThreadMessageBody => json!({"payload": {"ok": true}}),
        ThreadCloseBody => json!({"reason": "busy, try later"}),
        PageWrite => json!({"path": "projects/x/a.md", "content": "# A\n", "summary": "add a"}),
        PageDelete => json!({"path": "projects/x/a.md", "summary": "gone", "base_sha": "abc"}),
        ContainBody => json!({"match": {"name": "claude-x-*"}, "reason": "leaked a token"}),
        ShellExecBody => json!({"argv": ["ls", "-la"], "cwd": "/tmp", "wait": 30}),
        AgentCreate => json!({"name": "new-agent", "description": "created via api"}),
        AgentAttributesBody => json!({"runtime": "claude"}),
        AgentRenameBody => json!({"name": "renamed"}),
        SetKindBody => json!({"kind": "ephemeral"}),
        SetWebhookBody => json!({"webhook_url": "https://hooks.internal/agent"}),
        DecideBody => json!({"approve": true, "reason": "via api", "duration": "10m"}),
        PairingCodeCreate => json!({"role": "host", "name": "excelsior"}),
        ArmBody => json!({"tier": "root", "duration": "30m", "totp": "123456"}),
        LockdownBody => json!({"scope": "host", "host": "excelsior", "kill_vm": true}),
        UnlockBody => json!({"host": "excelsior", "totp": "123456"}),
        ChatOpen => json!({"to": "agent-a", "topic": "deploy", "text": "how is it going?"}),
        ChatSend => json!({"text": "thanks"}),
        ChatClose => json!({}),
        PairBody => json!({"role": "host", "name": "excelsior",
                           "public_key": "ed25519:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                           "selector": "0123456789abcdef0123456789abcdef",
                           "proof": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}),
    }
    // LiftBody is an enum over two shapes; both refuse extras.
    let _: LiftBody = accepted(json!({"id": "0a1b2c3d"}));
    assert!(refused::<LiftBody>(json!({"id": "0a1b2c3d", "bogus": 1})).contains("bogus"));
}

#[test]
fn request_create() {
    let full = json!({
        "platform": "kubernetes", "capability": "view", "resource": "apps",
        "scope": {"cluster": false}, "justification": "read pod logs",
        "requested_duration": 600, "on_behalf_of_thread": null,
    });
    let r: RequestCreate = accepted(full);
    assert_eq!(r.platform, Platform::Kubernetes);
    assert_eq!(r.requested_duration.get(), 600);
    assert_eq!(r.scope.get("cluster"), Some(&json!(false)));

    let base = || {
        json!({"platform": "a2a", "capability": "talk", "resource": "bob",
               "justification": "j", "requested_duration": "8h"})
    };
    let with = |k: &str, v: Value| {
        let mut b = base();
        b[k] = v;
        b
    };
    // test_invalid_duration_rejected
    assert_eq!(
        refused::<RequestCreate>(with("requested_duration", json!("sometime"))),
        "invalid duration 'sometime': use e.g. '30m', '8h', '2d', or seconds"
    );
    // §8.4: bool and float refused, upper bound.
    assert!(
        refused::<RequestCreate>(with("requested_duration", json!(true))).contains("whole number")
    );
    assert!(
        refused::<RequestCreate>(with("requested_duration", json!(1.0))).contains("whole number")
    );
    assert!(
        refused::<RequestCreate>(with("requested_duration", json!("3551w"))).contains("at most")
    );
    // test_field_size_caps: a 5000-character justification.
    assert!(
        refused::<RequestCreate>(with("justification", json!("j".repeat(5000))))
            .contains("at most 4000 characters")
    );
    assert!(refused::<RequestCreate>(with("justification", json!(""))).contains("at least 1"));
    assert!(refused::<RequestCreate>(with("capability", json!("c".repeat(129)))).contains("128"));
    assert!(refused::<RequestCreate>(with("resource", json!("r".repeat(513)))).contains("512"));
    assert!(refused::<RequestCreate>(with("platform", json!("ftp"))).contains("unknown variant"));
    assert!(
        refused::<RequestCreate>(with("on_behalf_of_thread", json!("t".repeat(37))))
            .contains("at most 36")
    );
    // §8.8: the scope is capped.
    let huge = json!({"argv": ["x".repeat(600_000)]});
    assert_eq!(
        refused::<RequestCreate>(with("scope", huge)),
        "scope exceeds 524288 bytes"
    );
    assert!(refused::<RequestCreate>(with("scope", json!([]))).contains("invalid type"));
    // Missing fields.
    let mut missing = base();
    missing.as_object_mut().unwrap().remove("justification");
    assert!(refused::<RequestCreate>(missing).contains("missing field `justification`"));
}

#[test]
fn invalid_json_is_told_apart() {
    assert!(matches!(
        parse_body::<RetryBody>(b"{not json"),
        Err(BodyError::Json(_))
    ));
    assert!(matches!(
        parse_body::<RetryBody>(b"{}"),
        Err(BodyError::Invalid(_))
    ));
}

#[test]
fn thread_bodies() {
    let t: ThreadOpenBody =
        accepted(json!({"to": "auto-r", "topic": null, "payload": {"task": "deploy cactus"}}));
    assert!(t.topic.is_none());
    let t: ThreadOpenBody = accepted(json!({"to": "x"}));
    assert!(t.payload.as_map().is_empty());
    assert_eq!(
        refused::<ThreadOpenBody>(json!({"to": "x", "topic": "line\nbreak"})),
        "topic must not contain control characters or newlines"
    );
    assert!(refused::<ThreadOpenBody>(json!({"to": ""})).contains("at least 1"));
    assert!(refused::<ThreadOpenBody>(json!({"to": "x", "payload": [1]})).contains("invalid type"));
    assert!(
        refused::<ThreadOpenBody>(json!({"to": "x", "topic": "t".repeat(257)})).contains("256")
    );
    // The client sends {"reason": null}; reject and close take {}.
    let _: ThreadCloseBody = accepted(json!({"reason": null}));
    let _: ThreadCloseBody = accepted(json!({}));
    assert!(refused::<ThreadCloseBody>(json!({"reason": "r".repeat(2001)})).contains("2000"));
    // Payload keys survive verbatim, `_sa*` included.
    let m: ThreadMessageBody = accepted(json!({"payload": {"_sandbox": 1, "_sample": [2]}}));
    assert!(m.payload.as_map().contains_key("_sandbox"));
}

#[test]
fn session_labels() {
    let _: SessionCreate = accepted(json!({"label": "a.b_c-1"}));
    assert!(refused::<SessionCreate>(json!({"label": "a b"})).contains("pattern"));
    assert!(refused::<SessionCreate>(json!({"label": "x".repeat(65)})).contains("64"));
}

#[test]
fn attention() {
    let a: AttentionBody = accepted(json!({"text": "hi"}));
    assert_eq!(a.urgency.as_str(), "normal");
    assert!(refused::<AttentionBody>(json!({"text": "x".repeat(2001)})).contains("2000"));
    assert!(refused::<AttentionBody>(json!({"text": ""})).contains("at least 1"));
}

#[test]
fn admin_agents() {
    let a: AgentCreate = accepted(json!({
        "name": "cat-hooked", "webhook_url": "https://example.test/hook", "kind": "service",
        "runtime": "claude", "project": "agent-auth", "host": "excelsior",
        "lldap_username": null,
    }));
    assert_eq!(a.kind, SettableKind::Service);
    // test_webhook_url_validated
    assert_eq!(
        refused::<AgentCreate>(json!({"name": "wh-bad", "webhook_url": "ftp://x/h"})),
        "webhook_url must be an http(s) URL with a host"
    );
    assert!(refused::<AgentCreate>(json!({"name": "bad name"})).contains("pattern"));
    assert!(
        refused::<AgentCreate>(json!({"name": "x", "kind": "operator"}))
            .contains("unknown variant")
    );
    assert!(refused::<AgentCreate>(json!({"name": "x", "runtime": "Claude"})).contains("pattern"));
    assert!(refused::<AgentCreate>(json!({"name": "x", "runtime": "r".repeat(17)})).contains("16"));
    // test_set_kind_rejects_garbage
    assert!(refused::<SetKindBody>(json!({"kind": "garbage"})).contains("unknown variant"));
    // test_set_webhook_on_existing_agent: {} clears.
    let w: SetWebhookBody = accepted(json!({}));
    assert!(w.webhook_url.is_none());
    assert!(refused::<SetWebhookBody>(json!({"webhook_url": "ftp://x"})).contains("http(s)"));
}

#[test]
fn attribute_patches_are_tri_state() {
    let p: AgentAttributesBody = accepted(json!({"runtime": "codex", "project": null, "host": ""}));
    assert!(matches!(p.runtime, Patch::Set(Some(ref r)) if r.as_str() == "codex"));
    assert!(matches!(p.project, Patch::Set(None)));
    assert!(matches!(p.host, Patch::Set(Some(ref h)) if h.is_empty()));
    let p: AgentAttributesBody = accepted(json!({}));
    assert!(p.runtime.is_keep() && p.project.is_keep() && p.host.is_keep());
    assert!(refused::<AgentAttributesBody>(json!({"host": "-x"})).contains("pattern"));
    // Serialization leaves out what is kept.
    let p: AgentAttributesBody = accepted(json!({"project": null}));
    assert_eq!(serde_json::to_value(&p).unwrap(), json!({"project": null}));
}

#[test]
fn decide() {
    let d: DecideBody = accepted(json!({"approve": false}));
    assert!(d.duration.is_none() && d.reason.is_empty());
    let d: DecideBody = accepted(json!({"approve": true, "duration": "10m", "totp": "123456",
                                         "scope_override": {"tier": "user"}, "resource_override": "h"}));
    assert_eq!(d.duration.unwrap().get(), 600);
    // The route's string detail is the duration's own message.
    assert_eq!(
        refused::<DecideBody>(json!({"approve": true, "duration": "x"})),
        "invalid duration 'x': use e.g. '30m', '8h', '2d', or seconds"
    );
    assert!(refused::<DecideBody>(json!({"approve": "yes"})).contains("invalid type"));
    assert!(
        refused::<DecideBody>(json!({"approve": true, "duration": false})).contains("whole number")
    );
    // The TOTP code never prints.
    let d: DecideBody = accepted(json!({"approve": true, "totp": "654321"}));
    assert!(!format!("{d:?}").contains("654321"));
}

#[test]
fn hosts_and_daemons() {
    let p: PairingCodeCreate = accepted(json!({"role": "sandbox", "name": "galaxy"}));
    assert_eq!(p.identity().unwrap().0, DaemonRole::Sandbox);
    let bad_role: PairingCodeCreate = accepted(json!({"role": "toaster", "name": "x"}));
    assert_eq!(
        bad_role.identity().unwrap_err().message(),
        "role must be one of host, sandbox"
    );
    let bad_name: PairingCodeCreate = accepted(json!({"role": "host", "name": "Bad_Name"}));
    assert_eq!(
        bad_name.identity().unwrap_err().message(),
        "name must be a lowercase hostname label ([a-z0-9-], ≤63)"
    );

    let arm: ArmBody = accepted(json!({"totp": "123456"}));
    assert_eq!(arm.tier, TierName::User);
    assert_eq!(serde_json::to_value(&arm.duration).unwrap(), json!("1h"));
    let arm: ArmBody = accepted(json!({"tier": "root", "duration": 3600, "totp": "1"}));
    assert_eq!(arm.duration, HostDuration::from_secs(3600).unwrap());
    assert!(refused::<ArmBody>(json!({"tier": "user"})).contains("missing field `totp`"));

    let l: LockdownBody = accepted(json!({}));
    assert_eq!(l.scope, LockdownScope::Sandboxes);
    assert!(refused::<LockdownBody>(json!({"scope": "everything"})).contains("unknown variant"));
    let _: UnlockBody = accepted(json!({"host": null, "totp": null}));

    let pair = |selector: &str, proof: &str| {
        json!({"role": "host", "name": "excelsior", "public_key": "ed25519:x",
               "selector": selector, "proof": proof})
    };
    let hex32 = "0123456789abcdef0123456789abcdef";
    let hex64 = "0123456789abcdef".repeat(4);
    let _: PairBody = accepted(pair(hex32, &hex64));
    assert!(refused::<PairBody>(pair("0123", &hex64)).contains("pattern"));
    assert!(refused::<PairBody>(pair(&hex32.to_uppercase(), &hex64)).contains("pattern"));
    assert!(refused::<PairBody>(pair(hex32, "zz")).contains("pattern"));
}

#[test]
fn containment_bodies() {
    let c: ContainBody = accepted(json!({"match": {}, "reason": "r"}));
    assert!(c.matches.is_empty() && c.evidence.is_empty());
    assert!(refused::<ContainBody>(json!({"match": {}, "reason": ""})).contains("at least 1"));
    assert!(
        refused::<ContainBody>(json!({"match": {}, "reason": "r".repeat(501)})).contains("500")
    );
    assert!(
        refused::<ContainBody>(json!({"match": {}, "reason": "r", "evidence": "e".repeat(4001)}))
            .contains("4000")
    );
    assert!(
        refused::<ContainBody>(json!({"match": "everyone", "reason": "r"}))
            .contains("invalid type")
    );
    // §8.15: lifting everything is explicit.
    assert!(refused::<LiftBody>(json!({})).contains("say which containment"));
    let _: LiftBody = accepted(json!({"all": true}));
}

#[test]
fn wiki_bodies() {
    let w: PageWrite = accepted(
        json!({"path": "projects/x/a.md", "content": "", "summary": "s",
                                        "base_sha": null}),
    );
    assert!(w.base_sha.is_none());
    assert!(
        refused::<PageWrite>(json!({"path": "p".repeat(301), "content": "", "summary": "s"}))
            .contains("300")
    );
    assert!(
        refused::<PageWrite>(json!({"path": "a.md", "content": "", "summary": ""}))
            .contains("at least 1")
    );
    assert!(
        refused::<PageDelete>(json!({"path": "a.md", "summary": "s", "base_sha": "f".repeat(65)}))
            .contains("64")
    );
}

#[test]
fn shell_exec() {
    // What the Python client sends.
    let s: ShellExecBody = accepted(json!({"argv": ["uptime"], "cwd": null, "stdin": null,
                                           "timeout": null, "wait": 60}));
    assert!(s.env.is_empty());
    let s: ShellExecBody = accepted(json!({"argv": ["x"]}));
    assert!((s.wait - 60.0).abs() < f64::EPSILON);
    assert!(refused::<ShellExecBody>(json!({"argv": []})).contains("at least 1"));
    assert!(refused::<ShellExecBody>(json!({"argv": "ls"})).contains("invalid type"));
    assert!(
        refused::<ShellExecBody>(json!({"argv": ["x"], "timeout": -1})).contains("invalid value")
    );
    let many: Vec<String> = vec!["a".to_owned(); 1025];
    assert!(refused::<ShellExecBody>(json!({"argv": many})).contains("at most 1024"));
    assert!(
        refused::<ShellExecBody>(json!({"argv": ["x"], "env": {"A": 1}})).contains("invalid type")
    );
}

#[test]
fn chat_bodies() {
    assert!(refused::<ChatOpen>(json!({"to": "a", "text": ""})).contains("at least 1"));
    assert!(refused::<ChatOpen>(json!({"to": "a", "text": "x".repeat(20001)})).contains("20000"));
    assert!(refused::<ChatSend>(json!({})).contains("missing field"));
}
