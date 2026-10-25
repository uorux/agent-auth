//! Kani harnesses for hostd's decisions (`scripts/kani.sh --harness hostd`).

use crate::authority::Tier;
use crate::hostd::totp::{self, Purpose, SecretName, TotpRefusal, TotpState};
use crate::hostd::{AdmissionFacts, ApprovalVia, AuthzFacts, Source, Via, decide};

fn any_tier() -> Tier {
    if kani::any() { Tier::User } else { Tier::Root }
}

fn any_source() -> Option<Source> {
    match kani::any::<u8>() % 5 {
        0 => None,
        1 => Some(Source::Human),
        2 => Some(Source::Rule),
        3 => Some(Source::Llm),
        _ => Some(Source::Policy),
    }
}

fn any_facts() -> AdmissionFacts {
    let authorization = if kani::any() {
        Some(AuthzFacts {
            via: if kani::any() {
                ApprovalVia::Totp
            } else {
                ApprovalVia::Desk
            },
            tier: any_tier(),
            digest_matches: kani::any(),
            unexpired: kani::any(),
        })
    } else {
        None
    };
    AdmissionFacts {
        locked: kani::any(),
        tier: any_tier(),
        kind_run: kani::any(),
        authorization,
        auto_match: kani::any(),
        source: any_source(),
        window: kani::any(),
        armed: kani::any(),
        accept_approve_all: kani::any(),
        accept_machine_approvals: kani::any(),
    }
}

/// INV-17: a TOTP (or desk) admission is for an unexpired approval of this
/// job's own tier and digest.
#[kani::proof]
fn hostd_totp_binds_tier_and_digest() {
    let f = any_facts();
    if let Ok(via) = decide(&f) {
        if via == Via::Totp || via == Via::Desk {
            let a = f.authorization.unwrap();
            assert!(a.tier == f.tier && a.digest_matches && a.unexpired);
            assert!(
                (via == Via::Totp && a.via == ApprovalVia::Totp)
                    || (via == Via::Desk && a.via == ApprovalVia::Desk)
            );
        }
    }
}

/// INV-20/21/22: nothing is admitted while locked; a root job is admitted
/// only on the host's own approval or while root is armed (never `auto`);
/// `auto` is user-tier `run` only; armed reasons need the tier armed and
/// the tier's own acceptance flags.
#[kani::proof]
fn hostd_root_jobs_need_a_human() {
    let f = any_facts();
    let Ok(via) = decide(&f) else { return };
    assert!(!f.locked);
    if f.tier == Tier::Root {
        assert!(matches!(via, Via::Totp | Via::Desk) || (via.is_armed() && f.armed));
    }
    if via == Via::Auto {
        assert!(f.tier == Tier::User && f.kind_run && f.auto_match);
    }
    if via.is_armed() {
        assert!(f.armed);
    }
    if via == Via::ArmedWindow {
        assert!(f.window && f.accept_approve_all);
    }
    if matches!(via, Via::ArmedRule | Via::ArmedLlm | Via::ArmedPolicy) {
        assert!(f.accept_machine_approvals && !f.window);
    }
    assert!(via != Via::Shell);
}

/// INV-12/13: a replayed or earlier step is refused without changing the
/// state; an accepted step is later than the last; a locked secret accepts
/// nothing.
#[kani::proof]
fn hostd_totp_replay_and_lock() {
    let now: u64 = kani::any();
    kani::assume(now < u64::MAX / 2);
    let mut state = TotpState {
        last_step: if kani::any() { Some(kani::any()) } else { None },
        failures: 0,
        lockouts: kani::any(),
        locked_until: if kani::any() { Some(kani::any()) } else { None },
        recent_failures: Vec::new(),
        hard_locked: kani::any(),
    };
    let before = state.clone();
    let name = SecretName::new(Tier::Root, Purpose::Direct);
    let matched: u64 = kani::any();
    // A code that matched: its step is in the attempt's window (the
    // wrong-code path, which counts failures in a list, is covered by the
    // property tests).
    let current = now / totp::STEP_SECS;
    kani::assume(matched.saturating_add(1) >= current && matched <= current.saturating_add(1));
    match totp::begin(&state, name, now) {
        Err(_) => {
            assert!(before.hard_locked || before.locked_until.is_some_and(|u| u > now));
        }
        Ok(attempt) => {
            assert!(!before.hard_locked);
            match attempt.conclude(&mut state, Some(matched)) {
                Ok(code) => {
                    assert!(before.last_step.is_none_or(|l| code.step() > l));
                    assert!(state.last_step == Some(code.step()));
                    assert!(code.name() == name);
                }
                Err(TotpRefusal::AlreadyUsed) => {
                    assert!(before.last_step.is_some_and(|l| matched <= l));
                    assert!(state == before);
                }
                Err(_) => {}
            }
        }
    }
}
