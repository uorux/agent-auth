//! Containment matching (rust/spec/core-lifecycle-policy.md §8.5): which
//! agents a containment entry holds.
//!
//! An entry's `match` names agents the way a policy rule does (Python's
//! `AgentMatch`): a glob on the name plus exact-value lists for `runtime`,
//! `project`, `host`, `placement` and `kind`. Every field given must hold;
//! an agent without a field is not matched by an entry that asks for it.
//!
//! Invariants (tested exhaustively/property-tested below):
//! - INV-C-1 the operator row is never held, whatever the entry says;
//! - INV-C-2 fail closed: an entry whose `match` does not parse holds every
//!   other agent, and so does an empty (or falsy, as Python's `or {}`) one;
//! - INV-C-3 a parsed entry holds exactly the agents its fields describe.

use serde_json::{Map, Value};

use crate::glob::Glob;

/// One definition of an agent's kind and placement for the whole crate
/// (policy patterns, zones and containment read the same values).
pub use crate::policy::agents::{AgentKind, Placement};

/// The agent attributes an entry can name.
#[derive(Debug, Clone, Copy)]
pub struct AgentFacts<'a> {
    pub name: &'a str,
    pub kind: AgentKind,
    pub runtime: Option<&'a str>,
    pub project: Option<&'a str>,
    pub host: Option<&'a str>,
    pub placement: Placement,
}

/// Why an entry's `match` does not parse (the entry then holds everyone).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MatchError(pub String);

/// A parsed `AgentMatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMatch {
    pub name: Glob,
    pub runtime: Option<Vec<String>>,
    pub project: Option<Vec<String>>,
    pub host: Option<Vec<String>>,
    pub placement: Option<Vec<Placement>>,
    /// Only `service`/`ephemeral` can be named (the operator is never held).
    pub kind: Option<Vec<AgentKind>>,
}

const FIELDS: [&str; 6] = ["name", "runtime", "project", "host", "placement", "kind"];

/// `[a-z0-9][a-z0-9._-]{0,63}`: a runtime, project or host value.
fn valid_attr(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && s.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// A string or a list of strings; `null` is "not given".
fn one_or_many(field: &str, value: &Value) -> Result<Option<Vec<String>>, MatchError> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(vec![s.clone()])),
        Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| MatchError(format!("{field}: a string or a list of strings")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(MatchError(format!(
            "{field}: a string or a list of strings"
        ))),
    }
}

fn attr_list(field: &str, value: &Value) -> Result<Option<Vec<String>>, MatchError> {
    let list = one_or_many(field, value)?;
    if let Some(items) = &list {
        if items.is_empty() {
            return Err(MatchError(format!(
                "{field}: an empty list matches no agent; leave the field out for any"
            )));
        }
        if let Some(bad) = items.iter().find(|i| !valid_attr(i)) {
            return Err(MatchError(format!(
                "{field}: {bad:?}: lowercase letters, digits, dots, dashes and underscores"
            )));
        }
    }
    Ok(list)
}

fn enum_list<T>(
    field: &str,
    value: &Value,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<Vec<T>>, MatchError> {
    one_or_many(field, value)?
        .map(|items| {
            items
                .iter()
                .map(|i| {
                    parse(i).ok_or_else(|| MatchError(format!("{field}: {i:?} is not allowed")))
                })
                .collect()
        })
        .transpose()
}

/// Python truthiness of a JSON value (`entry.get("match") or {}`).
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n
            .as_f64()
            .is_some_and(|f| matches!(f.classify(), std::num::FpCategory::Zero)),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

impl AgentMatch {
    /// `{}`: every (non-operator) agent.
    #[must_use]
    pub fn everyone() -> AgentMatch {
        AgentMatch {
            name: Glob::any(),
            runtime: None,
            project: None,
            host: None,
            placement: None,
            kind: None,
        }
    }

    /// Parse a stored or submitted `match` object. Unknown keys and wrong
    /// types are errors (pydantic `extra="forbid"`).
    pub fn parse(value: &Value) -> Result<AgentMatch, MatchError> {
        let Value::Object(map) = value else {
            return Err(MatchError("a match is an object".to_owned()));
        };
        Self::parse_map(map)
    }

    fn parse_map(map: &Map<String, Value>) -> Result<AgentMatch, MatchError> {
        if let Some(extra) = map.keys().find(|k| !FIELDS.contains(&k.as_str())) {
            return Err(MatchError(format!(
                "{extra}: extra inputs are not permitted"
            )));
        }
        let null = Value::Null;
        let get = |k: &str| map.get(k).unwrap_or(&null);
        let name = match map.get("name") {
            None => Glob::any(),
            Some(Value::String(s)) => Glob::new(s),
            Some(_) => return Err(MatchError("name: a string".to_owned())),
        };
        Ok(AgentMatch {
            name,
            runtime: attr_list("runtime", get("runtime"))?,
            project: attr_list("project", get("project"))?,
            host: attr_list("host", get("host"))?,
            placement: enum_list("placement", get("placement"), Placement::parse)?,
            kind: enum_list("kind", get("kind"), |s| match s {
                "service" => Some(AgentKind::Service),
                "ephemeral" => Some(AgentKind::Ephemeral),
                _ => None,
            })?,
        })
    }

    /// Does this match describe the agent? (Not containment itself: see
    /// [`holds`], which also exempts the operator.)
    #[must_use]
    pub fn matches(&self, agent: &AgentFacts<'_>) -> bool {
        fn has(wanted: Option<&Vec<String>>, value: Option<&str>) -> bool {
            match wanted {
                None => true,
                Some(list) => value.is_some_and(|v| list.iter().any(|w| w == v)),
            }
        }
        has(self.runtime.as_ref(), agent.runtime)
            && has(self.project.as_ref(), agent.project)
            && has(self.host.as_ref(), agent.host)
            && self
                .placement
                .as_ref()
                .is_none_or(|l| l.contains(&agent.placement))
            && self.kind.as_ref().is_none_or(|l| l.contains(&agent.kind))
            && self.name.matches(agent.name)
    }

    /// The pattern as a person would write it: `{project: a|b, host: x}`.
    #[must_use]
    pub fn pattern_text(&self) -> String {
        let mut parts = Vec::new();
        if self.name.as_str() != "*" {
            parts.push(format!("name: {}", self.name.as_str()));
        }
        for (field, list) in [
            ("runtime", &self.runtime),
            ("project", &self.project),
            ("host", &self.host),
        ] {
            if let Some(l) = list {
                parts.push(format!("{field}: {}", l.join("|")));
            }
        }
        if let Some(l) = &self.placement {
            let v: Vec<&str> = l.iter().map(|p| p.as_str()).collect();
            parts.push(format!("placement: {}", v.join("|")));
        }
        if let Some(l) = &self.kind {
            let v: Vec<&str> = l.iter().map(|k| k.as_str()).collect();
            parts.push(format!("kind: {}", v.join("|")));
        }
        format!("{{{}}}", parts.join(", "))
    }
}

/// Does a containment entry whose `match` is `entry_match` hold this agent?
///
/// The operator is never held (INV-C-1). A falsy `match` is `{}` (every
/// agent), and one that does not parse holds every agent: fail closed
/// (INV-C-2).
#[must_use]
pub fn holds(entry_match: &Value, agent: &AgentFacts<'_>) -> bool {
    if agent.kind == AgentKind::Operator {
        return false;
    }
    if is_falsy(entry_match) {
        return true;
    }
    match AgentMatch::parse(entry_match) {
        Ok(m) => m.matches(agent),
        Err(_) => true,
    }
}

/// The first entry (in list order) that holds the agent.
pub fn first_holding<'e, E>(
    entries: &'e [E],
    match_of: impl Fn(&E) -> &Value,
    agent: &AgentFacts<'_>,
) -> Option<&'e E> {
    entries.iter().find(|e| holds(match_of(e), agent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn agent(kind: AgentKind) -> AgentFacts<'static> {
        AgentFacts {
            name: "claude-agent-auth",
            kind,
            runtime: Some("claude"),
            project: Some("agent-auth"),
            host: Some("excelsior"),
            placement: Placement::Sandbox,
        }
    }

    #[test]
    fn operator_is_never_held() {
        for m in [
            json!({}),
            json!(null),
            json!({"bogus": 1}),
            json!({"name": "*"}),
            json!(7),
        ] {
            assert!(!holds(&m, &agent(AgentKind::Operator)), "{m}");
        }
    }

    #[test]
    fn empty_and_falsy_hold_everyone() {
        for m in [
            json!({}),
            json!(null),
            json!([]),
            json!(""),
            json!(false),
            json!(0),
        ] {
            assert!(holds(&m, &agent(AgentKind::Service)), "{m}");
            assert!(holds(&m, &agent(AgentKind::Ephemeral)), "{m}");
        }
    }

    #[test]
    fn unparsable_holds_everyone() {
        for m in [
            json!({"agnet": "x"}),
            json!({"name": 3}),
            json!({"project": []}),
            json!({"project": "Bad Name"}),
            json!({"placement": "moon"}),
            json!({"kind": "operator"}),
            json!({"runtime": [1]}),
            json!("text"),
            json!([1]),
            json!(true),
        ] {
            assert!(holds(&m, &agent(AgentKind::Service)), "{m}");
        }
    }

    #[test]
    fn fields_must_all_hold() {
        let a = agent(AgentKind::Service);
        assert!(holds(&json!({"project": "agent-auth"}), &a));
        assert!(holds(
            &json!({"project": ["x", "agent-auth"], "host": "excelsior"}),
            &a
        ));
        assert!(!holds(&json!({"project": "x"}), &a));
        assert!(!holds(
            &json!({"project": "agent-auth", "host": "recusant"}),
            &a
        ));
        assert!(holds(
            &json!({"placement": "sandbox", "kind": ["service"]}),
            &a
        ));
        assert!(!holds(&json!({"placement": []}), &a));
        assert!(!holds(&json!({"kind": "ephemeral"}), &a));
        assert!(holds(&json!({"name": "claude-*"}), &a));
        assert!(!holds(&json!({"name": "hermes-*"}), &a));
        assert!(holds(&json!({"project": null}), &a));
        let bare = AgentFacts { project: None, ..a };
        assert!(!holds(&json!({"project": "agent-auth"}), &bare));
    }

    #[test]
    fn pattern_text_reads_back() {
        let m = AgentMatch::parse(
            &json!({"placement": "sandbox", "runtime": ["claude", "codex"], "name": "hermes-*"}),
        )
        .unwrap();
        assert_eq!(
            m.pattern_text(),
            "{name: hermes-*, runtime: claude|codex, placement: sandbox}"
        );
        assert_eq!(AgentMatch::everyone().pattern_text(), "{}");
    }

    #[test]
    fn first_holding_is_list_order() {
        let entries = [
            json!({"project": "x"}),
            json!({"host": "excelsior"}),
            json!({}),
        ];
        let a = agent(AgentKind::Service);
        assert_eq!(first_holding(&entries, |e| e, &a), entries.get(1));
    }

    fn any_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| json!(n)),
            "[a-z*?!\\[\\] ._-]{0,8}".prop_map(Value::String),
        ];
        leaf.prop_recursive(3, 24, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                prop::collection::btree_map(
                    prop_oneof![
                        Just("name".to_owned()),
                        Just("runtime".to_owned()),
                        Just("project".to_owned()),
                        Just("host".to_owned()),
                        Just("placement".to_owned()),
                        Just("kind".to_owned()),
                        "[a-z]{1,6}",
                    ],
                    inner,
                    0..4
                )
                .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// INV-C-1, INV-C-2, INV-C-3 over arbitrary JSON.
        #[test]
        fn containment_properties(m in any_json(), kind_ix in 0usize..3, placement_ix in 0usize..2) {
            let kind = AgentKind::ALL[kind_ix];
            let a = AgentFacts { kind, placement: Placement::ALL[placement_ix], ..agent(kind) };
            let held = holds(&m, &a);
            if kind == AgentKind::Operator {
                prop_assert!(!held);
            } else {
                match AgentMatch::parse(&m) {
                    Err(_) => prop_assert!(held),
                    Ok(parsed) => prop_assert_eq!(held, is_falsy(&m) || parsed.matches(&a)),
                }
            }
        }
    }
}
