#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use serde_json::{Value, json};

use super::*;
use crate::authority::{Authority, SensitivityConfig, rule_covers};
use crate::platform::Platform;

fn wire(cap: &str, scope: Value) -> Result<MailAuthority, AuthorityError> {
    let Value::Object(map) = scope else {
        panic!("scope must be an object")
    };
    MailAuthority::from_wire(cap, &map)
}

fn a(cap: &str, scope: Value) -> MailAuthority {
    wire(cap, scope).unwrap()
}

fn error(cap: &str, scope: Value) -> String {
    wire(cap, scope).unwrap_err().0
}

#[test]
fn validation_texts() {
    assert_eq!(
        error("write", json!({})),
        "mail capability is one of read, send, read+send, create"
    );
    assert_eq!(
        error("read", json!({"colour": "red"})),
        "unknown mail scope key(s) ['colour']; a mail scope has ['correspondents', 'since', 'topic']"
    );
    assert_eq!(
        error("read", json!({"prefix": "x"})),
        "unknown mail scope key(s) ['prefix']; a mail scope has ['correspondents', 'since', 'topic']"
    );
    assert_eq!(
        error("create", json!({"z": 1, "a": 2})),
        "unknown mail scope key(s) ['a', 'z']; a mail scope has ['correspondents', 'prefix', 'since', 'topic']"
    );
    for bad in [json!(""), json!("   "), json!(3), json!("x".repeat(1001))] {
        assert_eq!(
            error("read", json!({ "topic": bad })),
            "topic is a sentence of at most 1000 characters"
        );
    }
    for bad in [json!([]), json!("*@x.com"), json!(vec!["*@x.com"; 33])] {
        assert_eq!(
            error("read", json!({ "correspondents": bad })),
            "correspondents is a list of 1 to 32 address globs"
        );
    }
    assert_eq!(
        error(
            "read",
            json!({"correspondents": ["*@x.com", "nobody", "A B@c"]})
        ),
        "not an address or address glob (like *@example.com): ['a b@c', 'nobody']"
    );
    for bad in ["2026-13-01", "20260101", "2026-W01-1", "x"] {
        assert_eq!(
            error("read", json!({ "since": bad })),
            "since is a date, YYYY-MM-DD"
        );
    }
    for bad in ["", "-x", "a".repeat(41).as_str(), "a b"] {
        assert_eq!(
            error("create", json!({ "prefix": bad })),
            "prefix: 1-40 lowercase letters, digits, . _ - (starting with a letter or digit)"
        );
    }
}

#[test]
fn normalization() {
    let m = a(
        "read",
        json!({"topic": "  my  ticket\nto Perth ", "correspondents": ["*@QANTAS.example", " *@qantas.example"],
               "since": "2026-01-01"}),
    );
    assert_eq!(m.topic.as_deref(), Some("my ticket to Perth"));
    assert_eq!(
        m.correspondents.iter().collect::<Vec<_>>(),
        vec!["*@qantas.example"]
    );
    assert_eq!(m.since.map(format_date).as_deref(), Some("2026-01-01"));
    let c = a("create", json!({"prefix": "SignUp"}));
    assert_eq!(c.prefix.as_deref(), Some("signup"));
    // Nulls are absent.
    assert_eq!(
        a(
            "read",
            json!({"topic": null, "correspondents": null, "since": null})
        ),
        a("read", json!({}))
    );
}

#[test]
fn stored_and_wire_forms() {
    let samples = [
        a("read", json!({})),
        a("send", json!({"topic": "t"})),
        a(
            "read+send",
            json!({"correspondents": ["*@a.example", "b@c.example"], "since": "2026-05-01"}),
        ),
        a("create", json!({})),
        a("create", json!({"prefix": "p1", "topic": "x"})),
    ];
    for m in samples {
        let auth = Authority::Mail(m.clone());
        let stored = auth.to_json();
        assert_eq!(
            Authority::from_json(Platform::Mail, &stored).as_ref(),
            Ok(&auth),
            "{stored}"
        );
        let back = Authority::from_wire(Platform::Mail, &auth.capability(), &auth.scope());
        assert_eq!(back, Ok(auth.clone()));
    }
    assert_eq!(
        Authority::Mail(a("read", json!({}))).to_json(),
        json!({"action": "read", "topic": null, "correspondents": [], "since": null})
    );
    assert_eq!(
        Authority::Mail(a("create", json!({}))).to_json(),
        json!({"action": "create", "topic": null, "correspondents": [], "since": null, "prefix": null})
    );
    // Not canonical: a prefix on a read, an unknown key.
    for row in [
        json!({"action": "read", "topic": null, "correspondents": [], "since": null, "prefix": null}),
        json!({"action": "read", "topic": null, "correspondents": [], "since": null, "x": 1}),
        json!({"action": "read", "topic": null, "correspondents": ["b", "a"], "since": null}),
        json!({"action": "nope", "topic": null, "correspondents": [], "since": null}),
    ] {
        assert!(Authority::from_json(Platform::Mail, &row).is_err(), "{row}");
    }
}

#[test]
fn labels() {
    let l = |cap: &str, scope: Value| Authority::Mail(a(cap, scope)).label();
    assert_eq!(l("read", json!({})), "read");
    assert_eq!(
        l(
            "read+send",
            json!({"correspondents": ["b@x.example", "*@a.example"], "topic": "t"})
        ),
        "read+send:with *@a.example,b@x.example:topic"
    );
}

/// `test_mail_rule_coverage`.
#[test]
fn rule_coverage() {
    let rule = a(
        "read+send",
        json!({"correspondents": ["*@qantas.example", "x@y.example"]}),
    );
    assert!(rule.covers(&a("read", json!({"correspondents": ["*@qantas.example"]}))));
    assert!(!rule.covers(&a("read", json!({}))));
    assert!(!rule.covers(&a(
        "create",
        json!({"correspondents": ["*@qantas.example"]})
    )));
    let topical = a("read", json!({"topic": "Perth"}));
    assert!(topical.covers(&a("read", json!({"topic": "Perth", "since": "2026-01-01"}))));
    assert!(!topical.covers(&a("read", json!({"topic": "anything"}))));
    let dated = a("read", json!({"since": "2026-05-01"}));
    assert!(dated.covers(&a("read", json!({"since": "2026-06-01"}))));
    assert!(!dated.covers(&a("read", json!({"since": "2026-01-01"}))));
    assert!(!dated.covers(&a("read", json!({}))));
    // Actions.
    assert!(!a("read", json!({})).covers(&a("send", json!({}))));
    assert!(!a("send", json!({})).covers(&a("read+send", json!({}))));
    assert!(a("read+send", json!({})).covers(&a("send", json!({}))));
    // Create: only a create rule with the same prefix.
    assert!(a("create", json!({"prefix": "p"})).covers(&a("create", json!({"prefix": "p"}))));
    assert!(!a("create", json!({"prefix": "p"})).covers(&a("create", json!({}))));
    assert!(!a("create", json!({})).covers(&a("create", json!({"prefix": "p"}))));
    assert!(!a("create", json!({})).covers(&a("read", json!({}))));
    // Through the authority.
    let r = Authority::Mail(rule);
    assert!(rule_covers(
        Some(&r),
        &Authority::Mail(a("send", json!({"correspondents": ["x@y.example"]})))
    ));
    assert!(!rule_covers(Some(&r), &Authority::Models));
}

// ------------------------------------------------- monotonicity, exhaustive

/// One thing done under a grant: an operation, on mail about `topic`, with
/// `party`, dated `day`. `create` operations need a create grant with the
/// same prefix.
#[derive(Debug, Clone)]
pub(super) struct Op {
    pub send: bool,
    pub create: Option<Option<String>>,
    pub topic: String,
    pub party: String,
    pub day: Date,
}

/// The meaning of an authority: does it allow `op`? Topics are compared
/// as the judge would (the grant's topic, if any, must be the mail's);
/// correspondents by membership (a literal party matching the glob
/// itself), dates by order.
pub(super) fn permits(g: &MailAuthority, op: &Op) -> bool {
    let action_ok = match (&op.create, g.action) {
        (Some(prefix), MailAction::Create) => *prefix == g.prefix,
        (Some(_), _) | (None, MailAction::Create) => false,
        (None, action) => {
            if op.send {
                action.sends()
            } else {
                action.reads()
            }
        }
    };
    action_ok
        && g.topic.as_ref().is_none_or(|t| *t == op.topic)
        && (g.correspondents.is_empty() || g.correspondents.contains(&op.party))
        && g.since.is_none_or(|s| op.day >= s)
}

fn days() -> [Date; 3] {
    [
        parse_date("2026-01-01").unwrap(),
        parse_date("2026-05-01").unwrap(),
        parse_date("2026-09-01").unwrap(),
    ]
}

fn small_authorities() -> Vec<MailAuthority> {
    let topics = [None, Some("t1"), Some("t2")];
    let parties = ["x@a.example", "*@b.example"];
    let mut out = Vec::new();
    for action in MailAction::ALL {
        let prefixes: Vec<Option<&str>> = if action == MailAction::Create {
            vec![None, Some("p"), Some("q")]
        } else {
            vec![None]
        };
        for prefix in &prefixes {
            for topic in topics {
                for mask in 0..4u8 {
                    for since in [None, Some(days()[0]), Some(days()[1]), Some(days()[2])] {
                        out.push(MailAuthority {
                            action,
                            topic: topic.map(str::to_owned),
                            correspondents: parties
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| mask & (1 << i) != 0)
                                .map(|(_, p)| (*p).to_owned())
                                .collect(),
                            since,
                            prefix: prefix.map(str::to_owned),
                        });
                    }
                }
            }
        }
    }
    out
}

fn small_ops() -> Vec<Op> {
    let mut out = Vec::new();
    for create in [None, Some(None), Some(Some("p".to_owned()))] {
        for send in [false, true] {
            for topic in ["t1", "t2"] {
                for party in ["x@a.example", "*@b.example", "z@c.example"] {
                    for day in days() {
                        out.push(Op {
                            send,
                            create: create.clone(),
                            topic: topic.to_owned(),
                            party: party.to_owned(),
                            day,
                        });
                    }
                }
            }
        }
    }
    out
}

/// A covered request asks for no more: whatever it allows, the rule allows
/// (every rule × request × operation of a small domain that has every
/// case: each action, prefix, topic, correspondent set and date).
#[test]
fn covers_is_monotone_exhaustively() {
    let auths = small_authorities();
    let ops = small_ops();
    let mut covered = 0usize;
    for rule in &auths {
        for req in &auths {
            if !rule.covers(req) {
                continue;
            }
            covered += 1;
            for op in &ops {
                if permits(req, op) {
                    assert!(permits(rule, op), "{rule:?} covers {req:?} but not {op:?}");
                }
            }
        }
    }
    assert!(covered > 1000, "{covered}");
}

#[test]
fn covers_is_reflexive_and_transitive() {
    let auths = small_authorities();
    for x in &auths {
        assert!(x.covers(x));
    }
    // Transitivity on a sample (the full cube is large).
    for (i, x) in auths.iter().enumerate().step_by(7) {
        for y in auths.iter().skip(i % 5).step_by(5) {
            if !x.covers(y) {
                continue;
            }
            for z in auths.iter().step_by(3) {
                if y.covers(z) {
                    assert!(x.covers(z));
                }
            }
        }
    }
}

// ------------------------------------------------------------ addresses

#[test]
fn address_checks() {
    for ok in ["a@b.example", "a.b+c@x-y.example.com", "x@1.2"] {
        assert!(is_address(ok), "{ok}");
    }
    for bad in [
        "a@b",
        "a@-b.example",
        "a@b-.example",
        "A@b.example",
        "@b.example",
        "a@b..example",
        "a b@c.example",
        "a@b.example\n",
    ] {
        assert!(!is_address(bad), "{bad}");
    }
    for ok in ["*@x.com", "bookings@*.airline.com", "[ab]*@x?.com"] {
        assert!(is_glob(ok), "{ok}");
    }
    for bad in ["*", "*@", "@x.com", "a@b@c", "A@x.com", "a@x.com "] {
        assert!(!is_glob(bad), "{bad}");
    }
    assert!(is_prefix("signup2") && is_prefix("a.b_c-d") && !is_prefix("_a"));
}

/// `test_server_terms`.
#[test]
fn server_terms() {
    assert_eq!(
        server_term("*@qantas.example").as_deref(),
        Some("qantas.example")
    );
    assert_eq!(
        server_term("bookings@qantas.example").as_deref(),
        Some("bookings@qantas.example")
    );
    assert_eq!(
        server_term("*@*.qantas.example").as_deref(),
        Some("qantas.example")
    );
    assert_eq!(server_term("*@*"), None);
    assert_eq!(server_term("*"), None);
    assert_eq!(server_term("x@localhost"), None);
}

#[test]
fn sensitivity() {
    let mut cfg = SensitivityConfig::default();
    cfg.mail_mailboxes.insert("me@mail.example".to_owned());
    let auth = |cap: &str, scope: Value| Authority::Mail(a(cap, scope));
    let corr = json!({"correspondents": ["*@q.example"]});
    // A mailbox itself, whatever the scope; by resource only when the
    // authority is not sensitive by itself.
    assert!(auth("read", corr.clone()).is_sensitive(&cfg, "ME@mail.example"));
    assert!(auth("read", corr.clone()).sensitive_by_resource(&cfg, "me@mail.example"));
    assert!(!auth("read", corr.clone()).is_sensitive(&cfg, "x@me.example"));
    // Reading an alias with nothing narrowing it is not sensitive.
    assert!(!auth("read", json!({})).is_sensitive(&cfg, "x@me.example"));
    // Sending with neither a topic nor correspondents is, by what.
    for cap in ["send", "read+send", "create"] {
        assert!(auth(cap, json!({})).is_sensitive(&cfg, "x@me.example"));
        assert!(!auth(cap, json!({})).sensitive_by_resource(&cfg, "me@mail.example"));
        assert!(!auth(cap, json!({"topic": "t"})).is_sensitive(&cfg, "x@me.example"));
        assert!(!auth(cap, corr.clone()).is_sensitive(&cfg, "x@me.example"));
    }
    assert!(auth("read", json!({})).needs_explicit_rule());
}

proptest! {
    /// Parsing never panics and what parses round-trips.
    #[test]
    fn from_wire_total(cap in "(read|send|read\\+send|create|x)",
                       topic in proptest::option::of(".{0,40}"),
                       corr in proptest::collection::vec("[a-z*?.@\\[\\] A-Z-]{0,12}", 0..4),
                       since in proptest::option::of("[0-9-]{0,12}"),
                       prefix in proptest::option::of("[a-zA-Z0-9._ -]{0,6}")) {
        let mut scope = serde_json::Map::new();
        if let Some(t) = topic { scope.insert("topic".into(), json!(t)); }
        if !corr.is_empty() { scope.insert("correspondents".into(), json!(corr)); }
        if let Some(s) = since { scope.insert("since".into(), json!(s)); }
        if let Some(p) = prefix { scope.insert("prefix".into(), json!(p)); }
        if let Ok(m) = MailAuthority::from_wire(&cap, &scope) {
            let auth = Authority::Mail(m);
            prop_assert_eq!(Authority::from_json(Platform::Mail, &auth.to_json()), Ok(auth.clone()));
            prop_assert_eq!(Authority::from_wire(Platform::Mail, &auth.capability(), &auth.scope()), Ok(auth));
        }
    }

    #[test]
    fn address_predicates_total(s in "\\PC{0,40}") {
        let _ = is_address(&s);
        let _ = is_glob(&s);
        let _ = server_term(&s);
        if is_address(&s) {
            prop_assert!(is_glob(&s));
        }
    }
}
