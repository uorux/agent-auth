//! Admission, arming, shells and TOTP counting, as hostd decides them
//! (ported from `tests/test_hostexec.py` where the logic is hostd's own).
#![allow(clippy::arithmetic_side_effects)] // test arithmetic on small known values

use std::collections::BTreeMap;

use proptest::prelude::*;
use serde_json::{Value, json};

use super::totp::{
    self, AcceptedCode, FAILURE_WINDOW_SECS, HARD_LOCK_FAILURES, MAX_FAILURES, Purpose, SecretName,
    TotpRefusal, TotpState,
};
use super::*;
use crate::hostexec::{ParamPattern, Template};

const HOST: &str = "excelsior";
const NOW: UnixMillis = UnixMillis(1_700_000_000_000);

fn policy() -> HostPolicy {
    let mut p = HostPolicy::connect_only(HOST);
    p.user.enable = true;
    p.root.enable = true;
    p.user.accept_approve_all = true;
    p.user.shell_enable = true;
    p.root.shell_enable = true;
    p.root.shell_max_duration_secs = 600;
    p.auto_commands = vec![vec!["uptime".into()]];
    p.deny_commands = vec![vec!["rm".into(), "**".into()]];
    let params: BTreeMap<String, ParamPattern> =
        [("name".to_owned(), ParamPattern::new("[a-z]+").unwrap())].into();
    p.templates.insert(
        "greet".into(),
        Template::new(
            Tier::User,
            vec!["echo".into(), "hello".into(), "{name}".into()],
            params,
            String::new(),
        )
        .unwrap(),
    );
    p
}

fn run(tier: &str, argv: &[&str]) -> Value {
    json!({"kind": "run", "host": HOST, "tier": tier, "argv": argv, "cwd": null,
           "env": {}, "timeout": 600, "stdin": null})
}

fn digest(n: u8) -> SpecDigest {
    SpecDigest::parse(&format!("{n:02x}").repeat(32)).unwrap()
}

fn id(n: u8) -> LocalId {
    LocalId::parse(&format!("0000000{n:x}-aaaa")).unwrap()
}

fn direct(tier: Tier) -> AcceptedCode {
    AcceptedCode::for_tests(SecretName::new(tier, Purpose::Direct), 1)
}

fn arm_code(tier: Tier) -> AcceptedCode {
    AcceptedCode::for_tests(SecretName::new(tier, Purpose::Arm), 1)
}

struct Host {
    policy: HostPolicy,
    auths: Authorizations,
    arm: ArmState,
    lock: LockState,
}

impl Host {
    fn new() -> Host {
        Host {
            policy: policy(),
            auths: Authorizations::default(),
            arm: ArmState::default(),
            lock: LockState::Unlocked,
        }
    }

    fn start(
        &mut self,
        job: &LocalId,
        raw: &Value,
        d: &SpecDigest,
        source: Option<Source>,
        window: bool,
    ) -> Result<Via, Refused> {
        let n = normalize(&self.policy, raw, false)?;
        admit(
            HostView {
                policy: &self.policy,
                arm: &self.arm,
                lock: self.lock,
                now: NOW,
            },
            job.clone(),
            n,
            d,
            Evidence { source, window },
            &mut self.auths,
        )
        .map(|a| a.via())
    }

    fn totp(&mut self, job: &LocalId, tier: Tier, d: &SpecDigest) {
        let approval = TotpApproval::new(direct(tier), d.clone()).unwrap();
        self.auths.record_totp(job.clone(), approval, NOW);
    }

    /// A `{tier}-shell` code for `d`.
    fn shell_code(&mut self, job: &LocalId, tier: Tier, d: &SpecDigest) {
        let code = AcceptedCode::for_tests(SecretName::new(tier, Purpose::Shell), 1);
        let approval = TotpApproval::new(code, d.clone()).unwrap();
        self.auths.record_totp(job.clone(), approval, NOW);
    }
}

#[test]
fn approve_counts_only_while_the_tier_is_armed() {
    let mut h = Host::new();
    let raw = run("user", &["ls"]);
    let err = h
        .start(&id(1), &raw, &digest(1), Some(Source::Human), false)
        .unwrap_err();
    assert!(
        err.0.starts_with("not_armed: the user tier of excelsior"),
        "{err}"
    );
    let until = h
        .arm
        .arm(
            &h.policy,
            Tier::User,
            999_999,
            ArmProof::Totp(arm_code(Tier::User)),
            h.lock,
            NOW,
        )
        .unwrap();
    // Capped at max_arm (3600 s).
    assert_eq!(until, NOW.plus_secs(3600));
    assert_eq!(
        h.start(&id(1), &raw, &digest(1), Some(Source::Human), false),
        Ok(Via::ArmedHuman)
    );
    // Machine approvals need accept_machine_approvals.
    let err = h
        .start(&id(2), &raw, &digest(1), Some(Source::Llm), false)
        .unwrap_err();
    assert!(
        err.0
            .contains("only accepts a human's approval for the user tier (this one came from llm)")
    );
    h.policy.user.accept_machine_approvals = true;
    assert_eq!(
        h.start(&id(2), &raw, &digest(1), Some(Source::Rule), false),
        Ok(Via::ArmedRule)
    );
    assert_eq!(
        h.start(&id(3), &raw, &digest(1), Some(Source::Human), true),
        Ok(Via::ArmedWindow)
    );
    h.arm.disarm(None);
    assert!(
        h.start(&id(4), &raw, &digest(1), Some(Source::Human), false)
            .is_err()
    );
    assert_eq!(
        h.start(&id(4), &raw, &digest(1), None, false)
            .unwrap_err()
            .0,
        "no approval evidence"
    );
}

#[test]
fn a_wrong_tier_code_arms_nothing_and_users_arm_only_the_user_tier() {
    let mut h = Host::new();
    let p = h.policy.clone();
    assert!(
        h.arm
            .arm(
                &p,
                Tier::Root,
                60,
                ArmProof::Totp(arm_code(Tier::User)),
                h.lock,
                NOW
            )
            .is_err()
    );
    assert!(
        h.arm
            .arm(
                &p,
                Tier::User,
                60,
                ArmProof::Totp(direct(Tier::User)),
                h.lock,
                NOW
            )
            .is_err()
    );
    assert_eq!(
        h.arm
            .arm(
                &p,
                Tier::Root,
                60,
                ArmProof::Local(LocalCaller::User),
                h.lock,
                NOW
            )
            .unwrap_err()
            .0,
        "arm needs root"
    );
    assert!(!h.arm.armed(Tier::Root, NOW));
    assert!(
        h.arm
            .arm(
                &p,
                Tier::Root,
                60,
                ArmProof::Local(LocalCaller::Root),
                h.lock,
                NOW
            )
            .is_ok()
    );
    // Locked: no arming, checked before a code would be spent.
    assert_eq!(
        ArmState::check_can_arm(&p, Tier::User, LockState::Locked)
            .unwrap_err()
            .0,
        "excelsior is locked down"
    );
    assert!(ArmState::check_unlock(&ArmProof::Totp(arm_code(Tier::User))).is_err());
    assert!(ArmState::check_unlock(&ArmProof::Totp(direct(Tier::Root))).is_err());
    assert!(ArmState::check_unlock(&ArmProof::Local(LocalCaller::User)).is_err());
    // A root-arm code no longer unlocks (review 2026-10, finding 4).
    assert!(ArmState::check_unlock(&ArmProof::Totp(arm_code(Tier::Root))).is_err());
    assert!(ArmState::check_unlock(&ArmProof::Local(LocalCaller::Root)).is_ok());
}

#[test]
fn a_totp_code_is_for_one_job_its_digest_and_its_tier() {
    let mut h = Host::new();
    let raw = run("user", &["ls"]);
    h.totp(&id(1), Tier::User, &digest(1));
    // Disarmed, with the code: runs.
    assert_eq!(
        h.start(&id(1), &raw, &digest(1), None, false),
        Ok(Via::Totp)
    );
    // Single use.
    assert!(h.start(&id(1), &raw, &digest(1), None, false).is_err());
    // Bound to its digest: a different spec under the same id is refused,
    // and the approval is spent anyway.
    h.totp(&id(2), Tier::User, &digest(1));
    assert!(h.start(&id(2), &raw, &digest(2), None, false).is_err());
    assert!(h.start(&id(2), &raw, &digest(1), None, false).is_err());
    // A user code relayed with a root job's digest admits nothing.
    let root = run("root", &["ls"]);
    h.totp(&id(3), Tier::User, &digest(3));
    assert!(h.start(&id(3), &root, &digest(3), None, false).is_err());
    h.totp(&id(4), Tier::Root, &digest(4));
    assert_eq!(
        h.start(&id(4), &root, &digest(4), None, false),
        Ok(Via::Totp)
    );
    // An arm code is not a direct approval.
    assert!(TotpApproval::new(arm_code(Tier::User), digest(1)).is_err());
}

#[test]
fn approvals_expire_and_lockdown_refuses_everything() {
    let mut h = Host::new();
    let raw = run("user", &["ls"]);
    h.totp(&id(1), Tier::User, &digest(1));
    let n = normalize(&h.policy, &raw, false).unwrap();
    let late = NOW.plus_secs(301);
    assert!(
        admit(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: late
            },
            id(1),
            n,
            &digest(1),
            Evidence::default(),
            &mut h.auths,
        )
        .is_err()
    );
    h.totp(&id(2), Tier::User, &digest(1));
    h.lock = LockState::Locked;
    assert_eq!(
        h.start(&id(2), &raw, &digest(1), None, false)
            .unwrap_err()
            .0,
        "excelsior is locked down"
    );
    // Even auto commands.
    assert!(
        h.start(&id(3), &run("user", &["uptime"]), &digest(1), None, false)
            .is_err()
    );
}

#[test]
fn auto_patterns_run_unarmed_for_user_run_jobs_only() {
    let mut h = Host::new();
    assert_eq!(
        h.start(&id(1), &run("user", &["uptime"]), &digest(1), None, false),
        Ok(Via::Auto)
    );
    // Never root, and the program must match exactly (no basename).
    assert!(
        h.start(&id(2), &run("root", &["uptime"]), &digest(1), None, false)
            .is_err()
    );
    assert!(
        h.start(
            &id(3),
            &run("user", &["/bin/uptime"]),
            &digest(1),
            None,
            false
        )
        .is_err()
    );
}

#[test]
fn the_hosts_policy_refuses_whatever_the_approval() {
    let mut h = Host::new();
    let p = h.policy.clone();
    let refuse = |raw: &Value| normalize(&p, raw, false).unwrap_err().0;
    assert_eq!(
        refuse(&run("user", &["/run/current-system/sw/bin/rm", "-rf", "/"])),
        "that command is denied by this host's policy"
    );
    let mut env = run("user", &["ls"]);
    env["env"] = json!({"SECRET": "x", "AWS": "y"});
    assert_eq!(
        refuse(&env),
        "environment variables not allowed on this host: AWS, SECRET"
    );
    let mut other = run("user", &["ls"]);
    other["host"] = json!("enterprise");
    assert_eq!(
        refuse(&other),
        "that job is for 'enterprise', this is excelsior"
    );
    let mut long = run("user", &["ls"]);
    long["timeout"] = json!(7200);
    assert_eq!(refuse(&long), "timeout exceeds this host's maximum (3600s)");
    assert_eq!(
        refuse(&json!({"kind": "shell", "host": HOST})),
        "not a runnable job"
    );
    assert_eq!(refuse(&json!("x")), "malformed job");
    // Even with a TOTP code for it: precheck refuses before the code is spent.
    let denied = run("user", &["rm", "x"]);
    assert!(
        precheck_job(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: NOW
            },
            &denied,
            &digest(1),
            true,
            None,
            Evidence {
                source: None,
                window: false
            },
            &h.auths,
        )
        .is_err()
    );
    h.policy.root.enable = false;
    assert_eq!(
        normalize(&h.policy, &run("root", &["ls"]), false)
            .unwrap_err()
            .0,
        "the root tier is not enabled on excelsior"
    );
}

#[test]
fn templates_are_expanded_by_the_host() {
    let p = policy();
    let tpl = |tier: &str, name: &str, params: Value| {
        json!({"kind": "tpl", "host": HOST, "tier": tier, "template": name, "params": params,
               "cwd": null, "env": {}, "timeout": 600, "stdin": null})
    };
    let n = normalize(&p, &tpl("user", "greet", json!({"name": "jacob"})), false).unwrap();
    assert_eq!(n.argv(), ["echo", "hello", "jacob"]);
    assert!(!n.is_run());
    assert!(normalize(&p, &tpl("user", "greet", json!({"name": "a b"})), false).is_err());
    assert_eq!(
        normalize(&p, &tpl("root", "greet", json!({"name": "x"})), false)
            .unwrap_err()
            .0,
        "template 'greet' is a user-tier template"
    );
    assert_eq!(
        normalize(&p, &tpl("user", "nope", json!({})), false)
            .unwrap_err()
            .0,
        "no template 'nope' on excelsior"
    );
    assert_eq!(
        normalize(&p, &tpl("user", "greet", json!({"name": "x"})), true)
            .unwrap_err()
            .0,
        "templates don't run inside a shell"
    );
}

#[test]
fn precheck_consumes_nothing() {
    let mut h = Host::new();
    let raw = run("user", &["ls"]);
    h.totp(&id(1), Tier::User, &digest(1));
    let pre = |h: &Host, job: Option<&str>| {
        precheck_job(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: NOW,
            },
            &raw,
            &digest(1),
            false,
            job,
            Evidence {
                source: Some(Source::Human),
                window: false,
            },
            &h.auths,
        )
    };
    assert_eq!(pre(&h, Some(id(1).as_str())), Ok(Via::Totp));
    assert_eq!(pre(&h, Some(id(1).as_str())), Ok(Via::Totp));
    assert!(pre(&h, None).unwrap_err().0.starts_with("not_armed"));
    assert_eq!(
        h.start(&id(1), &raw, &digest(1), None, false),
        Ok(Via::Totp)
    );
    assert_eq!(
        precheck_job(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: NOW
            },
            &raw,
            &digest(1),
            true,
            None,
            Evidence {
                source: None,
                window: false
            },
            &h.auths,
        ),
        Ok(Via::Totp)
    );
}

#[test]
fn shells_open_with_a_totp_code_only_and_stay_bounded() {
    let mut h = Host::new();
    let raw = json!({"kind": "shell", "host": HOST, "tier": "root", "duration": 300});
    let spec = parse_shell_request(&h.policy, &raw).unwrap();
    // Arming does not open a shell.
    h.arm
        .arm(
            &h.policy,
            Tier::Root,
            600,
            ArmProof::Local(LocalCaller::Root),
            h.lock,
            NOW,
        )
        .unwrap();
    assert_eq!(
        open_shell(
            &h.policy,
            id(1),
            &spec,
            &digest(1),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .unwrap_err()
        .0,
        "a shell is opened with a TOTP code only"
    );
    // A desk approval doesn't either.
    let n = normalize(&h.policy, &run("root", &["ls"]), false).unwrap();
    let mut desk_policy = h.policy.clone();
    desk_policy.desk_approve_root = true;
    let prompt = desk_prompt(
        HostView {
            policy: &desk_policy,
            arm: &h.arm,
            lock: h.lock,
            now: NOW,
        },
        id(1),
        digest(1),
        &n,
        "m".into(),
    )
    .unwrap();
    let (job, approval) = desk_approval(
        prompt,
        true,
        h.lock,
        Some(PolkitConfirmed::after_successful_pkcheck()),
    )
    .unwrap();
    h.auths.record_desk(job, approval, NOW);
    assert!(
        open_shell(
            &h.policy,
            id(1),
            &spec,
            &digest(1),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .is_err()
    );
    // A root-shell code for the shell's digest does.
    h.shell_code(&id(1), Tier::Root, &digest(1));
    let shell = open_shell(
        &h.policy,
        id(1),
        &spec,
        &digest(1),
        &mut h.auths,
        h.lock,
        NOW,
        true,
    )
    .unwrap();
    assert_eq!(shell.expires_at(), NOW.plus_secs(300));
    // Commands: same tier only, never a template, and only while it lasts.
    let ok = admit_shell_command(
        &h.policy,
        Some(&shell),
        id(2),
        &run("root", &["ls"]),
        h.lock,
        NOW,
    )
    .unwrap();
    assert_eq!(ok.via(), Via::Shell);
    assert_eq!(ok.shell(), Some(&id(1)));
    assert_eq!(
        admit_shell_command(
            &h.policy,
            Some(&shell),
            id(3),
            &run("user", &["ls"]),
            h.lock,
            NOW
        )
        .unwrap_err()
        .0,
        "that is a root shell"
    );
    assert!(
        admit_shell_command(
            &h.policy,
            Some(&shell),
            id(3),
            &run("root", &["rm", "-rf"]),
            h.lock,
            NOW
        )
        .is_err()
    );
    let later = NOW.plus_secs(300);
    assert!(
        admit_shell_command(
            &h.policy,
            Some(&shell),
            id(3),
            &run("root", &["ls"]),
            h.lock,
            later
        )
        .unwrap_err()
        .0
        .starts_with("no such shell")
    );
    assert!(
        admit_shell_command(
            &h.policy,
            Some(&shell),
            id(3),
            &run("root", &["ls"]),
            LockState::Locked,
            NOW
        )
        .is_err()
    );
    // Duration bounded by the host, at precheck and at open.
    let long = json!({"kind": "shell", "host": HOST, "tier": "root", "duration": 601});
    let long_spec = parse_shell_request(&h.policy, &long).unwrap();
    h.shell_code(&id(4), Tier::Root, &digest(4));
    assert_eq!(
        open_shell(
            &h.policy,
            id(4),
            &long_spec,
            &digest(4),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .unwrap_err()
        .0,
        "a root shell on excelsior lasts at most 600s"
    );
    assert!(
        precheck_shell(
            &h.policy,
            Some(&json!("root")),
            Some(&json!(601)),
            h.lock,
            true
        )
        .is_err()
    );
    assert!(
        precheck_shell(
            &h.policy,
            Some(&json!("root")),
            Some(&json!(600)),
            h.lock,
            true
        )
        .is_ok()
    );
    h.policy.root.shell_enable = false;
    assert_eq!(
        precheck_shell(&h.policy, Some(&json!("root")), None, h.lock, true)
            .unwrap_err()
            .0,
        "root shells are not enabled on excelsior"
    );
}

/// Security review 2026-10, finding 4: a code is bound to what it was
/// typed for. A direct code never opens a root shell; with a `{tier}-shell`
/// secret enrolled a direct code opens no shell of that tier; a shell code
/// never admits a job; only a root-unlock code unlocks.
#[test]
fn codes_are_bound_to_what_they_were_typed_for() {
    let mut h = Host::new();
    h.policy.user.shell_enable = true;
    let root = parse_shell_request(
        &h.policy,
        &json!({"kind": "shell", "host": HOST, "tier": "root", "duration": 300}),
    )
    .unwrap();
    let user = parse_shell_request(
        &h.policy,
        &json!({"kind": "shell", "host": HOST, "tier": "user", "duration": 300}),
    )
    .unwrap();
    // No root-shell secret: refused before a code is spent, and a direct
    // code doesn't open one.
    assert!(
        precheck_shell(&h.policy, Some(&json!("root")), None, h.lock, false)
            .unwrap_err()
            .0
            .contains("root-shell")
    );
    h.totp(&id(1), Tier::Root, &digest(1));
    assert!(
        open_shell(
            &h.policy,
            id(1),
            &root,
            &digest(1),
            &mut h.auths,
            h.lock,
            NOW,
            false
        )
        .is_err()
    );
    // Enrolled: still not with a direct code.
    h.totp(&id(1), Tier::Root, &digest(1));
    assert_eq!(
        open_shell(
            &h.policy,
            id(1),
            &root,
            &digest(1),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .unwrap_err()
        .0,
        "a root shell is opened with a root-shell code"
    );
    // A user shell: a direct code while no user-shell secret is enrolled,
    // only a user-shell code once one is.
    h.totp(&id(2), Tier::User, &digest(2));
    assert!(
        open_shell(
            &h.policy,
            id(2),
            &user,
            &digest(2),
            &mut h.auths,
            h.lock,
            NOW,
            false
        )
        .is_ok()
    );
    h.totp(&id(3), Tier::User, &digest(3));
    assert!(
        open_shell(
            &h.policy,
            id(3),
            &user,
            &digest(3),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .is_err()
    );
    h.shell_code(&id(3), Tier::User, &digest(3));
    assert!(
        open_shell(
            &h.policy,
            id(3),
            &user,
            &digest(3),
            &mut h.auths,
            h.lock,
            NOW,
            true
        )
        .is_ok()
    );
    // A shell code admits no job, armed or not.
    h.shell_code(&id(4), Tier::User, &digest(4));
    assert!(
        h.start(&id(4), &run("user", &["whoami"]), &digest(4), None, false)
            .is_err()
    );
    // Unlocking takes the root-unlock code; a root-arm code doesn't, and
    // an unlock code doesn't arm.
    let unlock = AcceptedCode::for_tests(SecretName::new(Tier::Root, Purpose::Unlock), 1);
    assert!(ArmState::check_unlock(&ArmProof::Totp(arm_code(Tier::Root))).is_err());
    assert!(ArmState::check_unlock(&ArmProof::Totp(unlock)).is_ok());
    let unlock = AcceptedCode::for_tests(SecretName::new(Tier::Root, Purpose::Unlock), 2);
    assert!(
        h.arm
            .arm(
                &h.policy,
                Tier::Root,
                60,
                ArmProof::Totp(unlock),
                h.lock,
                NOW
            )
            .is_err()
    );
    // The broker can't arm longer than this host's max_arm.
    let until = h
        .arm
        .arm(
            &h.policy,
            Tier::Root,
            999_999,
            ArmProof::Totp(arm_code(Tier::Root)),
            h.lock,
            NOW,
        )
        .unwrap();
    assert_eq!(until, NOW.plus_secs(u64::from(h.policy.root.max_arm_secs)));
}

#[test]
fn the_desk_approves_only_when_allowed_and_root_needs_polkit() {
    let mut h = Host::new();
    let n = normalize(&h.policy, &run("root", &["ls"]), false).unwrap();
    // approve.root off and not armed: refused.
    assert!(
        desk_prompt(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: NOW
            },
            id(1),
            digest(1),
            &n,
            "m".into(),
        )
        .unwrap_err()
        .0
        .contains("this desk doesn't approve root commands")
    );
    // Armed: still refused. A desk Allow is never a click relayed on an
    // armed tier (security review 2026-10, finding 1).
    h.arm
        .arm(
            &h.policy,
            Tier::Root,
            60,
            ArmProof::Local(LocalCaller::Root),
            h.lock,
            NOW,
        )
        .unwrap();
    assert_eq!(
        desk_prompt(
            HostView {
                policy: &h.policy,
                arm: &h.arm,
                lock: h.lock,
                now: NOW
            },
            id(1),
            digest(1),
            &n,
            "m".into(),
        )
        .unwrap_err()
        .0,
        "this desk doesn't approve root commands"
    );
    h.policy.desk_approve_root = true;
    let prompt = desk_prompt(
        HostView {
            policy: &h.policy,
            arm: &h.arm,
            lock: h.lock,
            now: NOW,
        },
        id(1),
        digest(1),
        &n,
        "m".into(),
    )
    .unwrap();
    // No password: no approval.
    let prompt = desk_approval(prompt, true, h.lock, None).unwrap_err();
    // Answer from a replaced helper connection: no approval.
    let prompt = desk_approval(
        prompt,
        false,
        h.lock,
        Some(PolkitConfirmed::after_successful_pkcheck()),
    )
    .unwrap_err();
    let (job, approval) = desk_approval(
        prompt,
        true,
        h.lock,
        Some(PolkitConfirmed::after_successful_pkcheck()),
    )
    .unwrap();
    h.auths.record_desk(job, approval, NOW);
    h.arm.disarm(None);
    assert_eq!(
        h.start(&id(1), &run("root", &["ls"]), &digest(1), None, false),
        Ok(Via::Desk)
    );
}

// --------------------------------------------------------------- TOTP

fn attempt(state: &mut TotpState, now: u64, matched: Option<u64>) -> Result<u64, TotpRefusal> {
    let name = SecretName::new(Tier::User, Purpose::Direct);
    totp::begin(state, name, now)?
        .conclude(state, matched)
        .map(|c| c.step())
}

#[test]
fn totp_codes_are_single_use_and_wrong_ones_lock_the_secret() {
    let mut s = TotpState::default();
    let now = 1_700_000_000u64;
    let step = now / 30;
    assert_eq!(attempt(&mut s, now, Some(step)), Ok(step));
    assert_eq!(
        attempt(&mut s, now, Some(step)),
        Err(TotpRefusal::AlreadyUsed)
    );
    assert_eq!(
        attempt(&mut s, now, Some(step - 1)),
        Err(TotpRefusal::AlreadyUsed)
    );
    assert_eq!(attempt(&mut s, now, Some(step + 1)), Ok(step + 1));
    // Outside the window is a wrong code whatever the caller claims.
    assert_eq!(
        attempt(&mut s, now, Some(step + 5)),
        Err(TotpRefusal::WrongCode)
    );
    let later = now + 600;
    for _ in 1..MAX_FAILURES {
        assert_eq!(attempt(&mut s, later, None), Err(TotpRefusal::WrongCode));
    }
    // Locked: even the right code is refused until the lock runs out.
    let good = later / 30;
    let err = attempt(&mut s, later, Some(good)).unwrap_err();
    assert!(err.to_string().contains("locked for 300s"), "{err}");
    assert_eq!(
        attempt(&mut s, later + 400, Some((later + 400) / 30)),
        Ok((later + 400) / 30)
    );
}

#[test]
fn lockouts_escalate_and_hard_lock_needs_root() {
    let mut s = TotpState::default();
    let mut now = 1_700_000_000u64;
    let mut expected_lock = 300u64;
    let mut wrong = 0usize;
    for _ in 0..3 {
        for _ in 0..MAX_FAILURES {
            assert_eq!(attempt(&mut s, now, None), Err(TotpRefusal::WrongCode));
            wrong += 1;
        }
        assert_eq!(s.locked_until, Some(now + expected_lock));
        now += expected_lock;
        expected_lock *= 2;
    }
    // A right code in between resets the escalation but not the count.
    let step = now / 30;
    assert_eq!(attempt(&mut s, now, Some(step)), Ok(step));
    assert_eq!(s.lockouts, 0);
    while wrong < HARD_LOCK_FAILURES {
        if let Some(until) = s.locked_until.filter(|u| *u > now) {
            now = until;
        }
        assert_eq!(attempt(&mut s, now, None), Err(TotpRefusal::WrongCode));
        wrong += 1;
    }
    assert!(s.hard_locked);
    let far = now + 10 * 86400;
    assert!(matches!(
        attempt(&mut s, far, Some(far / 30)),
        Err(TotpRefusal::HardLocked { .. })
    ));
    s.clear_lock();
    // Clearing keeps the last used step.
    assert_eq!(
        attempt(&mut s, now, Some(step)),
        Err(TotpRefusal::AlreadyUsed)
    );
    assert_eq!(attempt(&mut s, far, Some(far / 30)), Ok(far / 30));
}

#[test]
fn totp_state_reads_the_python_format() {
    let s = TotpState::from_json(&json!({"last_step": -1, "failures": 2, "locked_until": 1.5e9}))
        .unwrap();
    assert_eq!(s.last_step, None);
    assert_eq!(s.failures, 2);
    assert_eq!(s.locked_until, Some(1_500_000_000));
    let s2 = TotpState::from_json(&s.to_json()).unwrap();
    assert_eq!(s, s2);
    assert!(TotpState::from_json(&json!([])).is_none());
    assert!(TotpState::from_json(&json!({"last_step": "x"})).is_none());
    assert_eq!(
        SecretName::parse("root-arm"),
        Some(SecretName::new(Tier::Root, Purpose::Arm))
    );
    assert_eq!(SecretName::parse("root"), None);
}

#[test]
fn ids_and_digests_are_strict() {
    assert!(LocalId::parse("../../etc").is_err());
    assert!(LocalId::parse("abcdef0").is_err());
    assert!(LocalId::parse(&"a".repeat(65)).is_err());
    assert!(LocalId::parse("01234567-89ab-cdef-0123-456789abcdef").is_ok());
    assert!(SpecDigest::parse(&"A".repeat(64)).is_err());
    assert_eq!(UnixMillis(1500).as_secs_f64(), 1.5);
    assert_eq!(UnixMillis::from_secs_f64(1.5), UnixMillis(1500));
    assert_eq!(UnixMillis::from_secs_f64(f64::NAN), UnixMillis(0));
}

// ------------------------------------------------------------ properties

fn any_tier() -> impl Strategy<Value = Tier> {
    prop_oneof![Just(Tier::User), Just(Tier::Root)]
}

fn any_source() -> impl Strategy<Value = Option<Source>> {
    prop_oneof![
        Just(None),
        Just(Some(Source::Human)),
        Just(Some(Source::Rule)),
        Just(Some(Source::Llm)),
        Just(Some(Source::Policy)),
        Just(Some(Source::Desk))
    ]
}

proptest! {
    /// A TOTP approval for tier T and digest D admits only a job of tier T
    /// whose digest is D, whatever else holds (disarmed, no evidence).
    #[test]
    fn a_totp_approval_admits_only_its_tier_and_digest(
        code_tier in any_tier(), job_tier in any_tier(),
        code_digest in 0u8..3, job_digest in 0u8..3,
        source in any_source(), window in any::<bool>(),
    ) {
        let mut h = Host::new();
        h.totp(&id(1), code_tier, &digest(code_digest));
        let raw = run(job_tier.as_str(), &["ls"]);
        let result = h.start(&id(1), &raw, &digest(job_digest), source, window);
        if result == Ok(Via::Totp) {
            prop_assert_eq!(code_tier, job_tier);
            prop_assert_eq!(code_digest, job_digest);
        }
        if code_tier == job_tier && code_digest == job_digest {
            prop_assert_eq!(result, Ok(Via::Totp));
        } else {
            // Disarmed and no auto pattern: nothing else admits it.
            prop_assert!(result.is_err());
        }
        // Spent either way.
        prop_assert!(h.auths.is_empty());
    }

    /// A root job is only ever admitted on a root-direct code, a desk
    /// approval, or the root tier armed.
    #[test]
    fn root_jobs_always_had_a_human(
        armed in any::<bool>(), totp_tier in proptest::option::of(any_tier()),
        source in any_source(), window in any::<bool>(),
        approve_all in any::<bool>(), machine in any::<bool>(),
        argv in prop_oneof![Just("uptime"), Just("ls")],
    ) {
        let mut h = Host::new();
        h.policy.root.accept_approve_all = approve_all;
        h.policy.root.accept_machine_approvals = machine;
        h.policy.auto_commands.push(vec!["ls".into()]);
        if armed {
            h.arm.arm(&h.policy, Tier::Root, 60, ArmProof::Totp(arm_code(Tier::Root)), h.lock, NOW).unwrap();
        }
        if let Some(t) = totp_tier {
            h.totp(&id(1), t, &digest(1));
        }
        let raw = run("root", &[argv]);
        match h.start(&id(1), &raw, &digest(1), source, window) {
            Ok(Via::Totp) => prop_assert_eq!(totp_tier, Some(Tier::Root)),
            Ok(v) => prop_assert!(v.is_armed() && armed, "{v:?}"),
            Err(_) => {}
        }
    }

    /// Security review 2026-10, finding 1: a desk answer is admission only
    /// as the host's own recorded desk approval, which exists only when the
    /// desk approves the tier; a desk click relayed on an armed tier admits
    /// nothing.
    #[test]
    fn a_desk_click_is_never_armed_evidence(
        tier in any_tier(), armed in any::<bool>(), approves in any::<bool>(),
        window in any::<bool>(), approve_all in any::<bool>(), machine in any::<bool>(),
    ) {
        let mut h = Host::new();
        for t in [&mut h.policy.user, &mut h.policy.root] {
            t.accept_approve_all = approve_all;
            t.accept_machine_approvals = machine;
        }
        h.policy.desk_approve_root = approves;
        h.policy.desk_approve_user = approves;
        if armed {
            h.arm.arm(&h.policy, tier, 60, ArmProof::Local(LocalCaller::Root), h.lock, NOW).unwrap();
        }
        let raw = run(tier.as_str(), &["whoami"]);
        let n = normalize(&h.policy, &raw, false).unwrap();
        let prompt = desk_prompt(
            HostView { policy: &h.policy, arm: &h.arm, lock: h.lock, now: NOW },
            id(1), digest(1), &n, "m".into(),
        );
        prop_assert_eq!(prompt.is_ok(), approves);
        // The broker's relay of the click: never admits.
        prop_assert!(h.start(&id(1), &raw, &digest(1), Some(Source::Desk), window).is_err());
        prop_assert_eq!(
            Source::from_evidence(Some("human"), Some("desktop:excelsior")),
            Some(Source::Desk)
        );
    }

    /// Wrong codes are counted; within any window at most
    /// HARD_LOCK_FAILURES of them are evaluated, and replays never pass.
    #[test]
    fn totp_sequences(ops in proptest::collection::vec((0u64..4000, prop_oneof![Just(None), (0u64..3).prop_map(Some)]), 1..80)) {
        let mut s = TotpState::default();
        let mut now = 1_700_000_000u64;
        let mut wrong_times: Vec<u64> = Vec::new();
        let mut accepted: Vec<u64> = Vec::new();
        for (dt, m) in ops {
            now += dt;
            let step = (now / 30).saturating_sub(1);
            let matched = m.map(|k| step + k);
            match attempt(&mut s, now, matched) {
                Err(TotpRefusal::WrongCode) => wrong_times.push(now),
                Ok(st) => {
                    prop_assert!(accepted.last().is_none_or(|l| st > *l));
                    accepted.push(st);
                }
                Err(_) => {}
            }
            let in_window = wrong_times.iter().filter(|t| **t + FAILURE_WINDOW_SECS > now).count();
            prop_assert!(in_window <= HARD_LOCK_FAILURES);
        }
    }
}

#[test]
fn auto_patterns_do_not_cross_paths_and_deny_sees_through_them() {
    let p: Vec<String> = vec!["cat".into(), "/var/log/*".into()];
    assert!(auto_matches(&p, &["cat", "/var/log/syslog"]));
    assert!(!auto_matches(
        &p,
        &["cat", "/var/log/../../home/jrt/.ssh/id_ed25519"]
    ));
    assert!(!auto_matches(&p, &["cat", "/var/log/a/b"]));
    assert!(auto_matches(
        &["ls".to_owned(), "*".to_owned()],
        &["ls", "a/b"]
    ));
    assert!(!auto_matches(
        &["ls".to_owned(), "**".to_owned()],
        &["ls", "x/../../etc"]
    ));
    let deny: Vec<String> = vec!["/bin/rm".into(), "**".into()];
    assert!(deny_matches(&deny, &["/usr/../bin/rm", "-rf"]));
    assert!(deny_matches(
        &["rm".to_owned(), "**".to_owned()],
        &["/x/y/rm"]
    ));
    assert!(!deny_matches(&deny, &["/bin/ls"]));
    // Through admission: the `..` argv is not auto.
    let mut h = Host::new();
    h.policy.auto_commands = vec![vec!["cat".into(), "/var/log/*".into()]];
    assert_eq!(
        h.start(
            &id(1),
            &run("user", &["cat", "/var/log/syslog"]),
            &digest(1),
            None,
            false
        ),
        Ok(Via::Auto)
    );
    assert!(
        h.start(
            &id(2),
            &run("user", &["cat", "/var/log/../../etc/shadow"]),
            &digest(1),
            None,
            false
        )
        .is_err()
    );
}

#[test]
fn templates_pin_cwd_env_and_stdin() {
    let mut p = policy();
    let t: crate::hostexec::Template = serde_json::from_value(json!({
        "tier": "user", "argv": ["make", "deploy"], "cwd": "/srv/app/../app",
        "env": {"LANG": "C"}, "stdin": "yes\n"
    }))
    .unwrap();
    assert_eq!(t.cwd.as_deref(), Some("/srv/app"));
    p.templates.insert("deploy".into(), t);
    let tpl = |extra: Value| {
        let mut v = json!({"kind": "tpl", "host": HOST, "tier": "user", "template": "deploy",
               "params": {}, "cwd": null, "env": {}, "timeout": 600, "stdin": null});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let n = normalize(&p, &tpl(json!({})), false).unwrap();
    assert_eq!(n.cwd(), Some("/srv/app"));
    assert_eq!(n.env().get("LANG").map(String::as_str), Some("C"));
    assert_eq!(n.stdin(), Some("yes\n"));
    for (extra, why) in [
        (json!({"cwd": "/tmp"}), "template 'deploy' takes no cwd"),
        (
            json!({"env": {"LANG": "x"}}),
            "template 'deploy' takes no environment",
        ),
        (
            json!({"stdin": "rm -rf ~\n"}),
            "template 'deploy' takes no stdin",
        ),
    ] {
        assert_eq!(normalize(&p, &tpl(extra), false).unwrap_err().0, why);
    }
    assert!(
        serde_json::from_value::<crate::hostexec::Template>(
            json!({"tier": "user", "argv": ["x"], "cwd": "rel"})
        )
        .is_err()
    );
}
