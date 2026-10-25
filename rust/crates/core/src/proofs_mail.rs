//! Kani: a mail rule pinned to an authority covers only requests that ask
//! for no more (`MailAuthority::covers`, the Python's `_mail_covers`).
//!
//! `covers` compares through `covers_by`, generic over the compared values;
//! the harness runs `covers_by` itself over every action, any prefix and
//! topic (symbolic bytes), any set of correspondents over four parties (a
//! bitmask: the subset test is `covers`' `BTreeSet::is_subset`), any date,
//! and any operation, and checks that whatever the covered request allows,
//! the rule allows too. (The string and set handling around it is checked
//! exhaustively by the unit tests, `covers_is_monotone_exhaustively`.)

use crate::mail::{Covering, MailAction, covers_by};

fn any_action() -> MailAction {
    match kani::any::<u8>() % 4 {
        0 => MailAction::Read,
        1 => MailAction::Send,
        2 => MailAction::ReadSend,
        _ => MailAction::Create,
    }
}

/// An authority: its compared parts, with its correspondents as a set of
/// four parties.
struct Auth {
    action: MailAction,
    prefix: Option<u8>,
    topic: Option<u8>,
    correspondents: u8,
    since: Option<u16>,
}

fn any_auth() -> Auth {
    let correspondents: u8 = kani::any();
    kani::assume(correspondents < 16);
    let action = any_action();
    Auth {
        action,
        prefix: if action == MailAction::Create {
            kani::any()
        } else {
            None
        },
        topic: kani::any(),
        correspondents,
        since: kani::any(),
    }
}

fn view(a: &Auth) -> Covering<'_, u8, u16> {
    Covering {
        action: a.action,
        prefix: a.prefix.as_ref(),
        topic: a.topic.as_ref(),
        correspondents: a.correspondents != 0,
        since: a.since,
    }
}

fn covers(rule: &Auth, request: &Auth) -> bool {
    let subset = request.correspondents != 0 && request.correspondents & !rule.correspondents == 0;
    covers_by(&view(rule), &view(request), subset)
}

/// The meaning of an authority: does it allow sending (or reading), or
/// creating with `prefix`, mail about `topic` with `party`, dated `day`?
fn permits(
    g: &Auth,
    send: bool,
    create: Option<Option<u8>>,
    topic: u8,
    party: u8,
    day: u16,
) -> bool {
    let action_ok = match (create, g.action) {
        (Some(prefix), MailAction::Create) => prefix == g.prefix,
        (Some(_), _) | (None, MailAction::Create) => false,
        (None, action) => {
            if send {
                action.sends()
            } else {
                action.reads()
            }
        }
    };
    action_ok
        && g.topic.is_none_or(|t| t == topic)
        && (g.correspondents == 0 || g.correspondents & (1 << party) != 0)
        && g.since.is_none_or(|s| day >= s)
}

#[kani::proof]
fn mail_covers_is_monotone() {
    let rule = any_auth();
    let request = any_auth();
    kani::assume(covers(&rule, &request));
    let party: u8 = kani::any();
    kani::assume(party < 4);
    let create: Option<Option<u8>> = kani::any();
    let (send, topic, day) = (kani::any(), kani::any(), kani::any());
    if permits(&request, send, create, topic, party, day) {
        assert!(permits(&rule, send, create, topic, party, day));
    }
}

/// Coverage never crosses between create and the other actions, a create
/// rule covers only its own prefix, and every authority covers itself.
#[kani::proof]
fn mail_create_is_its_own_privilege() {
    let rule = any_auth();
    let request = any_auth();
    if covers(&rule, &request) {
        assert!((rule.action == MailAction::Create) == (request.action == MailAction::Create));
        if rule.action == MailAction::Create {
            assert!(rule.prefix == request.prefix);
        }
    }
    assert!(covers(&rule, &rule));
}
