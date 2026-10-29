//! What an agent is, as recorded fields (runtime, project, host, placement,
//! kind), and the patterns policy uses to pick agents (`policy/agents.py`).
//! The broker sets the fields; an agent cannot change its own.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::glob::Glob;
use crate::names::{AGENT_NAME_ALPHABET, AttrValue};
use crate::pyfmt::{escape_unprintable, repr};

/// Where an agent runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placement {
    Host,
    /// In an agent VM.
    Sandbox,
}

impl Placement {
    pub const ALL: [Placement; 2] = [Placement::Host, Placement::Sandbox];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Placement::Host => "host",
            Placement::Sandbox => "sandbox",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// What kind of agent. `Operator` is the admin panel's own row: never held,
/// never matched by a `kind:` field (only service/ephemeral can be named).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentKind {
    Service,
    Ephemeral,
    Operator,
}

impl AgentKind {
    pub const ALL: [AgentKind; 3] = [
        AgentKind::Service,
        AgentKind::Ephemeral,
        AgentKind::Operator,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AgentKind::Service => "service",
            AgentKind::Ephemeral => "ephemeral",
            AgentKind::Operator => "operator",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// The kinds a pattern may name.
const MATCHABLE_KINDS: [AgentKind; 2] = [AgentKind::Service, AgentKind::Ephemeral];

/// The runtime of web-UI connectors (remote MCP): always a human's call.
pub const WEB_RUNTIME: &str = "web";

/// An agent as policy sees it. Borrowed so the broker can build one from a
/// row without copying; `runtime`/`project`/`host` are `None` when unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRef<'a> {
    pub name: &'a str,
    pub runtime: Option<&'a str>,
    pub project: Option<&'a str>,
    pub host: Option<&'a str>,
    pub placement: Placement,
    pub kind: AgentKind,
}

impl<'a> AgentRef<'a> {
    /// An agent with only a name (host placement, service kind, no fields).
    #[must_use]
    pub const fn named(name: &'a str) -> Self {
        AgentRef {
            name,
            runtime: None,
            project: None,
            host: None,
            placement: Placement::Host,
            kind: AgentKind::Service,
        }
    }

    #[must_use]
    pub fn is_web(&self) -> bool {
        self.runtime == Some(WEB_RUNTIME)
    }

    #[must_use]
    pub fn is_operator(&self) -> bool {
        self.kind == AgentKind::Operator
    }
}

/// `describe(agent)`: the fields as one line for a person,
/// "claude · agent-auth · excelsior · VM".
#[must_use]
pub fn describe(agent: &AgentRef<'_>) -> String {
    let vm = (agent.placement == Placement::Sandbox).then_some("VM");
    [agent.runtime, agent.project, agent.host, vm]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A pattern that did not parse. The text is shown to the operator (policy
/// load) or the caller (containment, 422).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PatternError(pub String);

/// Which agents something is about, by fields (`AgentMatch`). Every field
/// given must hold; a field takes one value or a list, compared exactly.
/// `name` is the one glob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMatch {
    name: Glob,
    runtime: Option<Vec<AttrValue>>,
    project: Option<Vec<AttrValue>>,
    host: Option<Vec<AttrValue>>,
    placement: Option<Vec<Placement>>,
    kind: Option<Vec<AgentKind>>,
}

const MATCH_FIELDS: [&str; 6] = ["name", "runtime", "project", "host", "placement", "kind"];

impl Default for AgentMatch {
    /// Matches every agent (`{}`).
    fn default() -> Self {
        AgentMatch {
            name: Glob::any(),
            runtime: None,
            project: None,
            host: None,
            placement: None,
            kind: None,
        }
    }
}

impl AgentMatch {
    /// Parse the mapping form, as written in the policy or a containment
    /// body. Unknown keys are refused.
    pub fn from_value(value: &Value) -> Result<AgentMatch, PatternError> {
        let Value::Object(map) = value else {
            return Err(PatternError(
                "an agent match is a mapping of name, runtime, project, host, placement, kind"
                    .to_owned(),
            ));
        };
        let mut out = AgentMatch::default();
        for (key, v) in map {
            match key.as_str() {
                "name" => match v {
                    Value::String(s) => out.name = Glob::new(s),
                    _ => return Err(PatternError("name: a glob (a string)".to_owned())),
                },
                "runtime" => out.runtime = attr_values("runtime", v)?,
                "project" => out.project = attr_values("project", v)?,
                "host" => out.host = attr_values("host", v)?,
                "placement" => {
                    out.placement = enum_values("placement", v, Placement::parse, "host, sandbox")?;
                }
                "kind" => {
                    out.kind = enum_values(
                        "kind",
                        v,
                        |s| MATCHABLE_KINDS.into_iter().find(|k| k.as_str() == s),
                        "service, ephemeral",
                    )?;
                }
                other => {
                    return Err(PatternError(format!(
                        "unknown field `{other}` (an agent match takes {})",
                        MATCH_FIELDS.join(", ")
                    )));
                }
            }
        }
        Ok(out)
    }

    /// The canonical mapping: the fields that are set (`name` only when it
    /// is not `*`), lists as lists.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        if self.name.as_str() != "*" {
            map.insert(
                "name".to_owned(),
                Value::String(self.name.as_str().to_owned()),
            );
        }
        for (key, values) in self.listed() {
            map.insert(
                key.to_owned(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
        Value::Object(map)
    }

    fn listed(&self) -> Vec<(&'static str, Vec<String>)> {
        let attr = |v: &Option<Vec<AttrValue>>| {
            v.as_ref()
                .map(|v| v.iter().map(|a| a.as_str().to_owned()).collect::<Vec<_>>())
        };
        let mut out = Vec::new();
        if let Some(v) = attr(&self.runtime) {
            out.push(("runtime", v));
        }
        if let Some(v) = attr(&self.project) {
            out.push(("project", v));
        }
        if let Some(v) = attr(&self.host) {
            out.push(("host", v));
        }
        if let Some(v) = &self.placement {
            out.push((
                "placement",
                v.iter().map(|p| p.as_str().to_owned()).collect(),
            ));
        }
        if let Some(v) = &self.kind {
            out.push(("kind", v.iter().map(|k| k.as_str().to_owned()).collect()));
        }
        out
    }

    #[must_use]
    pub fn name(&self) -> &Glob {
        &self.name
    }

    /// The projects this match names (checked against `projects:` at load).
    #[must_use]
    pub fn projects(&self) -> &[AttrValue] {
        self.project.as_deref().unwrap_or(&[])
    }

    /// `AgentMatch.matches`: every field given holds (an agent without the
    /// field never matches a field that asks for it), and the name glob.
    #[must_use]
    pub fn matches(&self, agent: &AgentRef<'_>) -> bool {
        fn has(wanted: Option<&Vec<AttrValue>>, actual: Option<&str>) -> bool {
            match wanted {
                None => true,
                Some(list) => actual.is_some_and(|a| list.iter().any(|w| w.as_str() == a)),
            }
        }
        has(self.runtime.as_ref(), agent.runtime)
            && has(self.project.as_ref(), agent.project)
            && has(self.host.as_ref(), agent.host)
            && self
                .placement
                .as_ref()
                .is_none_or(|p| p.contains(&agent.placement))
            && self.kind.as_ref().is_none_or(|k| k.contains(&agent.kind))
            && self.name.matches(agent.name)
    }

    /// Could this match hold every agent there may be? True when the name
    /// glob matches every possible agent name and no field narrows it (a
    /// runtime/project/host field always leaves out the agents without one;
    /// `placement` and `kind` narrow unless they list every value).
    ///
    /// This is the containment `allow_all` check (bug B-2: the Python only
    /// refused a literally empty `{}`, so `{"name": "*"}` or
    /// `{"placement": ["host", "sandbox"]}` passed). It is exact for the
    /// pattern alone; a pattern that happens to cover every agent that
    /// exists today (say, each project listed) is not "everyone".
    #[must_use]
    pub fn matches_everyone(&self) -> bool {
        name_glob_matches_everyone(&self.name)
            && self.runtime.is_none()
            && self.project.is_none()
            && self.host.is_none()
            && self
                .placement
                .as_ref()
                .is_none_or(|p| Placement::ALL.iter().all(|x| p.contains(x)))
            && self
                .kind
                .as_ref()
                .is_none_or(|k| MATCHABLE_KINDS.iter().all(|x| k.contains(x)))
    }

    /// `pattern_text` of the mapping form: `{placement: sandbox}`,
    /// `{runtime: claude|codex}`.
    #[must_use]
    pub fn text(&self) -> String {
        let mut parts = Vec::new();
        if self.name.as_str() != "*" {
            parts.push(format!("name: {}", escape_unprintable(self.name.as_str())));
        }
        for (key, values) in self.listed() {
            parts.push(format!("{key}: {}", values.join("|")));
        }
        format!("{{{}}}", parts.join(", "))
    }
}

fn name_glob_matches_everyone(glob: &Glob) -> bool {
    let alphabet: Vec<char> = AGENT_NAME_ALPHABET.chars().collect();
    glob.matches_every_nonempty_over(&alphabet)
}

/// One string or a list of strings (`_one_or_many`); null = absent.
fn one_or_many<'v>(field: &str, v: &'v Value) -> Result<Option<Vec<&'v str>>, PatternError> {
    let bad = || PatternError(format!("{field}: a string or a list of strings"));
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(vec![s.as_str()])),
        Value::Array(items) => items
            .iter()
            .map(|i| i.as_str().ok_or_else(bad))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(bad()),
    }
}

fn attr_values(field: &str, v: &Value) -> Result<Option<Vec<AttrValue>>, PatternError> {
    let Some(items) = one_or_many(field, v)? else {
        return Ok(None);
    };
    let values = items
        .into_iter()
        .map(|s| AttrValue::parse(s).map_err(|e| PatternError(format!("{field}: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(PatternError(format!(
            "{field}: an empty list matches no agent; leave the field out for any"
        )));
    }
    Ok(Some(values))
}

fn enum_values<T>(
    field: &str,
    v: &Value,
    parse: impl Fn(&str) -> Option<T>,
    allowed: &str,
) -> Result<Option<Vec<T>>, PatternError> {
    let Some(items) = one_or_many(field, v)? else {
        return Ok(None);
    };
    // An empty list is accepted, as in the Python, and matches nothing.
    items
        .into_iter()
        .map(|s| {
            parse(s).ok_or_else(|| {
                PatternError(format!("{field}: {} is not one of {allowed}", repr(s)))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// `AgentPattern = str | AgentMatch`: a string is a glob on the name (the
/// older form); a mapping is fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPattern {
    Name(Glob),
    Fields(AgentMatch),
}

impl Default for AgentPattern {
    fn default() -> Self {
        AgentPattern::Name(Glob::any())
    }
}

impl AgentPattern {
    pub fn from_value(value: &Value) -> Result<AgentPattern, PatternError> {
        match value {
            Value::String(s) => Ok(AgentPattern::Name(Glob::new(s))),
            Value::Object(_) => AgentMatch::from_value(value).map(AgentPattern::Fields),
            _ => Err(PatternError(
                "an agent pattern is a name glob or a mapping of fields".to_owned(),
            )),
        }
    }

    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            AgentPattern::Name(g) => Value::String(g.as_str().to_owned()),
            AgentPattern::Fields(m) => m.to_value(),
        }
    }

    /// `agent_matches(pattern, agent)`.
    #[must_use]
    pub fn matches(&self, agent: &AgentRef<'_>) -> bool {
        match self {
            AgentPattern::Name(g) => g.matches(agent.name),
            AgentPattern::Fields(m) => m.matches(agent),
        }
    }

    /// See [`AgentMatch::matches_everyone`].
    #[must_use]
    pub fn matches_everyone(&self) -> bool {
        match self {
            AgentPattern::Name(g) => name_glob_matches_everyone(g),
            AgentPattern::Fields(m) => m.matches_everyone(),
        }
    }

    #[must_use]
    pub fn projects(&self) -> &[AttrValue] {
        match self {
            AgentPattern::Name(_) => &[],
            AgentPattern::Fields(m) => m.projects(),
        }
    }

    /// `pattern_text`: a pattern as a person would write it.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            AgentPattern::Name(g) => escape_unprintable(g.as_str()),
            AgentPattern::Fields(m) => m.text(),
        }
    }
}

impl fmt::Display for AgentPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for AgentPattern {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for AgentPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;
        AgentPattern::from_value(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for AgentMatch {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for AgentMatch {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;
        AgentMatch::from_value(&value).map_err(serde::de::Error::custom)
    }
}

/// The requester's delegator, for a request made on another agent's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delegation<'a> {
    /// Not delegated.
    None,
    /// On behalf of this agent.
    Agent(AgentRef<'a>),
    /// Delegated, but the delegator's row is gone. Matches no rule that
    /// names a delegator (the Python's stand-in named "?" matched `*`, bug
    /// B-18), and still keeps rules without one from granting.
    Gone,
}

impl Delegation<'_> {
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        !matches!(self, Delegation::None)
    }

    #[must_use]
    pub fn is_web(&self) -> bool {
        matches!(self, Delegation::Agent(a) if a.is_web())
    }
}

/// The delegation axis of rule matching (`_delegator_matches`) reduced to
/// what it depends on, so it can be checked exhaustively:
/// - `pattern`: `None` if the rule names no delegator, else whether the
///   delegator matches it (`None` too when there is no live delegator to
///   match);
/// - a rule naming a delegator matches only a delegated request whose
///   delegator fits;
/// - a rule naming none matches a non-delegated request, and a delegated
///   one only if it does not grant access (deny/surface still apply).
#[must_use]
pub fn delegator_axis(
    rule_names_delegator: bool,
    delegator_fits: bool,
    delegated: bool,
    grants_access: bool,
) -> bool {
    if rule_names_delegator {
        delegated && delegator_fits
    } else {
        !delegated || !grants_access
    }
}

/// `_delegator_matches(pattern, delegator, grants_access)`.
#[must_use]
pub fn delegator_matches(
    pattern: Option<&AgentPattern>,
    delegation: &Delegation<'_>,
    grants_access: bool,
) -> bool {
    let fits = match (pattern, delegation) {
        (Some(p), Delegation::Agent(d)) => p.matches(d),
        _ => false,
    };
    delegator_axis(
        pattern.is_some(),
        fits,
        delegation.is_delegated(),
        grants_access,
    )
}

/// A project as `projects:` declares it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Project {
    pub description: String,
    /// GitHub repos ("owner/repo") this project's agents work in: what
    /// `{agent.repos}` stands for in a rule's resource.
    pub repos: Vec<String>,
}

/// The placeholders a rule's resource may use.
pub const PLACEHOLDERS: [&str; 4] = ["runtime", "project", "host", "repos"];

/// Every `{agent.<lowercase letters>}` in `resource`, left to right, as
/// (byte range, name). The Python's `\{agent\.([a-z]+)\}`.
fn placeholders(resource: &str) -> Vec<(usize, usize, &str)> {
    const OPEN: &str = "{agent.";
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rest) = resource.get(i..) {
        let Some(found) = rest.find(OPEN) else {
            break;
        };
        let start = i.saturating_add(found);
        let name_start = start.saturating_add(OPEN.len());
        let name_len = resource
            .get(name_start..)
            .map_or(0, |s| s.bytes().take_while(u8::is_ascii_lowercase).count());
        let name_end = name_start.saturating_add(name_len);
        if name_len > 0 && resource.get(name_end..name_end.saturating_add(1)) == Some("}") {
            let end = name_end.saturating_add(1);
            out.push((start, end, resource.get(name_start..name_end).unwrap_or("")));
            i = end;
        } else {
            i = start.saturating_add(1);
        }
    }
    out
}

/// `check_resource`: refuse a rule whose resource names a placeholder that
/// doesn't exist, or holds a brace that is not a placeholder.
pub fn check_resource(resource: &str) -> Result<(), PatternError> {
    let found = placeholders(resource);
    for (_, _, name) in &found {
        if !PLACEHOLDERS.contains(name) {
            let there_are: Vec<String> = PLACEHOLDERS
                .iter()
                .map(|p| format!("{{agent.{p}}}"))
                .collect();
            return Err(PatternError(format!(
                "resource {}: unknown placeholder {{agent.{name}}} (there are: {})",
                repr(resource),
                there_are.join(", ")
            )));
        }
    }
    let mut stripped = String::with_capacity(resource.len());
    let mut last = 0usize;
    for (start, end, _) in &found {
        stripped.push_str(resource.get(last..*start).unwrap_or(""));
        last = *end;
    }
    stripped.push_str(resource.get(last..).unwrap_or(""));
    if stripped.contains('{') {
        return Err(PatternError(format!(
            "resource {}: a brace that is not an {{agent.…}} placeholder",
            repr(resource)
        )));
    }
    Ok(())
}

/// A value as itself inside a glob: `*`, `?` and `[` become `[*]`, `[?]`,
/// `[[]`.
#[must_use]
pub fn glob_literal(value: &str) -> String {
    crate::glob::escape(value)
}

/// `resources_for`: the rule's resource globs with the agent's own fields
/// filled in. A placeholder the agent has no value for leaves nothing to
/// match; `{agent.project}` and `{agent.repos}` need the agent's project to
/// be declared in `projects:`; `{agent.repos}` gives one candidate per repo.
#[must_use]
pub fn resources_for(
    resource: &str,
    agent: &AgentRef<'_>,
    projects: &BTreeMap<AttrValue, Project>,
) -> Vec<String> {
    let names: BTreeSet<&str> = placeholders(resource)
        .into_iter()
        .map(|(_, _, n)| n)
        .collect();
    let mut out = vec![resource.to_owned()];
    let declared = agent
        .project
        .filter(|p| !p.is_empty())
        .and_then(|p| projects.get(p));
    for name in names {
        let values: Vec<&str> = match name {
            "repos" => {
                declared.map_or_else(Vec::new, |p| p.repos.iter().map(String::as_str).collect())
            }
            "project" => agent
                .project
                .filter(|p| !p.is_empty() && declared.is_some())
                .into_iter()
                .collect(),
            "runtime" => agent
                .runtime
                .filter(|v| !v.is_empty())
                .into_iter()
                .collect(),
            "host" => agent.host.filter(|v| !v.is_empty()).into_iter().collect(),
            // Refused at load; an unknown placeholder never matches.
            _ => Vec::new(),
        };
        let needle = format!("{{agent.{name}}}");
        out = out
            .iter()
            .flat_map(|r| values.iter().map(|v| r.replace(&needle, &glob_literal(v))))
            .collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn m(v: Value) -> Result<AgentMatch, String> {
        AgentMatch::from_value(&v).map_err(|e| e.0)
    }

    #[test]
    fn parses_one_or_many() {
        let a = m(json!({"runtime": "claude", "placement": "sandbox"})).unwrap();
        assert_eq!(a.text(), "{runtime: claude, placement: sandbox}");
        let a = m(json!({"runtime": ["claude", "codex"], "name": "x-*"})).unwrap();
        assert_eq!(a.text(), "{name: x-*, runtime: claude|codex}");
        assert_eq!(
            a.to_value(),
            json!({"name": "x-*", "runtime": ["claude", "codex"]})
        );
        assert_eq!(m(json!({})).unwrap().text(), "{}");
        assert_eq!(m(json!({"runtime": null})).unwrap(), AgentMatch::default());
    }

    #[test]
    fn mistakes_are_errors() {
        assert!(
            m(json!({"runtme": "claude"}))
                .unwrap_err()
                .contains("runtme")
        );
        assert!(
            m(json!({"placement": "vm"}))
                .unwrap_err()
                .contains("placement")
        );
        assert!(
            m(json!({"runtime": []}))
                .unwrap_err()
                .contains("empty list")
        );
        assert!(
            m(json!({"project": "Bad"}))
                .unwrap_err()
                .contains("lowercase")
        );
        assert!(m(json!({"kind": "operator"})).is_err());
        assert!(m(json!({"name": 3})).is_err());
        assert!(m(json!({"host": [1]})).is_err());
        // placement/kind: [] are accepted and match nothing.
        let none = m(json!({"placement": []})).unwrap();
        assert!(!none.matches(&AgentRef::named("x")));
    }

    #[test]
    fn matching() {
        let vm = AgentRef {
            name: "whatever",
            runtime: Some("codex"),
            project: None,
            host: Some("excelsior"),
            placement: Placement::Sandbox,
            kind: AgentKind::Service,
        };
        let p = m(json!({"placement": "sandbox", "runtime": ["claude", "codex"]})).unwrap();
        assert!(p.matches(&vm));
        assert!(!p.matches(&AgentRef::named("claude-thing-excelsior-sandbox")));
        assert!(!m(json!({"project": "x"})).unwrap().matches(&vm));
        let op = AgentRef {
            kind: AgentKind::Operator,
            ..AgentRef::named("operator")
        };
        assert!(
            !m(json!({"kind": ["service", "ephemeral"]}))
                .unwrap()
                .matches(&op)
        );
        assert!(AgentPattern::Name(Glob::new("what*")).matches(&vm));
    }

    #[test]
    fn matches_everyone_is_semantic() {
        let every = |v: Value| AgentPattern::from_value(&v).unwrap().matches_everyone();
        assert!(every(json!({})));
        assert!(every(json!({"name": "*"})));
        assert!(every(json!({"name": "?*"})));
        assert!(every(json!({"name": "*?**"})));
        assert!(every(json!({"name": "[!/]*"})));
        assert!(every(json!({"placement": ["host", "sandbox"]})));
        assert!(every(json!({"kind": ["ephemeral", "service"]})));
        assert!(every(json!("*")));
        assert!(!every(json!({"name": "??*"})));
        assert!(!every(json!({"name": "a*"})));
        assert!(!every(json!({"name": "[a-z]*"})));
        assert!(!every(json!({"placement": "host"})));
        assert!(!every(json!({"kind": "service"})));
        assert!(!every(json!({"runtime": "claude"})));
        assert!(!every(json!({"name": "?"})));
    }

    proptest::proptest! {
        /// The containment check must not be bypassable: a pattern that
        /// holds every agent is always reported as such. For a pattern
        /// reported otherwise, an agent it misses is found among names of
        /// one or two characters (enough: see `matches_every_nonempty_over`)
        /// with no runtime/project/host, of each placement and kind.
        #[test]
        fn matches_everyone_is_never_too_lenient(
            name in "[a*?\\[\\]!Z.-]{0,6}",
            placement in proptest::option::of(proptest::sample::subsequence(vec!["host", "sandbox"], 0..=2)),
            kind in proptest::option::of(proptest::sample::subsequence(vec!["service", "ephemeral"], 0..=2)),
            runtime in proptest::option::of(proptest::sample::select(vec!["claude", "web"])),
        ) {
            let mut v = serde_json::Map::new();
            v.insert("name".into(), json!(name));
            if let Some(p) = placement { v.insert("placement".into(), json!(p)); }
            if let Some(k) = kind { v.insert("kind".into(), json!(k)); }
            if let Some(r) = runtime { v.insert("runtime".into(), json!(r)); }
            let m = AgentMatch::from_value(&Value::Object(v)).unwrap();
            let alphabet: Vec<char> = AGENT_NAME_ALPHABET.chars().collect();
            let mut names: Vec<String> = alphabet.iter().map(|c| c.to_string()).collect();
            for a in &alphabet {
                for b in &alphabet {
                    names.push(format!("{a}{b}"));
                }
            }
            let mut missed = false;
            'outer: for n in &names {
                for placement in Placement::ALL {
                    for kind in MATCHABLE_KINDS {
                        let agent = AgentRef { placement, kind, ..AgentRef::named(n) };
                        if !m.matches(&agent) {
                            missed = true;
                            break 'outer;
                        }
                    }
                }
            }
            proptest::prop_assert_eq!(m.matches_everyone(), !missed);
        }
    }

    #[test]
    fn pattern_text_is_display_safe() {
        let p = AgentPattern::from_value(&json!({"name": "a\n\u{202e}*"})).unwrap();
        assert_eq!(p.text(), "{name: a\\n\\u202e*}");
        let p = AgentPattern::from_value(&json!("x\ry")).unwrap();
        assert_eq!(p.text(), "x\\ry");
    }

    /// tests/test_agent_attributes.py::test_a_pattern_reads_back_the_way_it_was_written
    #[test]
    fn pattern_text() {
        let patterns: Vec<AgentPattern> = [
            json!({"placement": "sandbox"}),
            json!({"runtime": ["claude", "codex"]}),
            json!("hermes-*"),
        ]
        .iter()
        .map(|v| AgentPattern::from_value(v).unwrap())
        .collect();
        let text: Vec<String> = patterns.iter().map(AgentPattern::text).collect();
        assert_eq!(
            text.join(", "),
            "{placement: sandbox}, {runtime: claude|codex}, hermes-*"
        );
    }

    #[test]
    fn delegator_axis_truth_table() {
        for names in [false, true] {
            for fits in [false, true] {
                for delegated in [false, true] {
                    for grants in [false, true] {
                        let got = delegator_axis(names, fits, delegated, grants);
                        let python = if names {
                            delegated && fits
                        } else if !delegated {
                            true
                        } else {
                            !grants
                        };
                        assert_eq!(got, python);
                    }
                }
            }
        }
        let p = AgentPattern::Name(Glob::any());
        assert!(!delegator_matches(Some(&p), &Delegation::Gone, false));
        assert!(!delegator_matches(None, &Delegation::Gone, true));
        assert!(delegator_matches(None, &Delegation::Gone, false));
    }

    #[test]
    fn resources() {
        assert!(check_resource("x/{agent.repos}").is_ok());
        assert!(check_resource("plain/*").is_ok());
        assert!(check_resource("a}b").is_ok());
        assert_eq!(
            check_resource("x/{agent.projct}").unwrap_err().0,
            "resource 'x/{agent.projct}': unknown placeholder {agent.projct} (there are: \
             {agent.runtime}, {agent.project}, {agent.host}, {agent.repos})"
        );
        assert_eq!(
            check_resource("x/{project}").unwrap_err().0,
            "resource 'x/{project}': a brace that is not an {agent.…} placeholder"
        );
        assert!(check_resource("{agent.Project}").is_err());
        assert!(check_resource("{agent.}").is_err());
        assert!(check_resource("{{agent.host}").is_err());
    }

    /// tests/test_agent_attributes.py::test_a_field_value_is_literal_inside_the_glob
    #[test]
    fn field_value_is_literal_inside_the_glob() {
        let a = AgentRef {
            name: "n",
            runtime: Some("claude"),
            project: Some("p"),
            host: Some("a*b"),
            placement: Placement::Host,
            kind: AgentKind::Service,
        };
        let none = BTreeMap::new();
        assert_eq!(
            resources_for("org/{agent.host}-*", &a, &none),
            vec!["org/a[*]b-*"]
        );
        assert_eq!(resources_for("plain/*", &a, &none), vec!["plain/*"]);
        assert_eq!(glob_literal("a?b[c]*"), "a[?]b[[]c][*]");
    }

    #[test]
    fn repos_and_projects() {
        let mut projects = BTreeMap::new();
        projects.insert(
            AttrValue::parse("agent-auth").unwrap(),
            Project {
                description: String::new(),
                repos: vec!["uorux/agent-auth".into(), "uorux/homelab".into()],
            },
        );
        let a = AgentRef {
            project: Some("agent-auth"),
            host: Some("galaxy"),
            ..AgentRef::named("a")
        };
        let mut got = resources_for("{agent.repos}#{agent.host}", &a, &projects);
        got.sort();
        assert_eq!(got, vec!["uorux/agent-auth#galaxy", "uorux/homelab#galaxy"]);
        assert_eq!(
            resources_for("{agent.project}", &a, &projects),
            vec!["agent-auth"]
        );
        let stray = AgentRef {
            project: Some("flux-system"),
            ..AgentRef::named("d")
        };
        assert!(resources_for("{agent.project}", &stray, &projects).is_empty());
        assert!(resources_for("{agent.repos}", &AgentRef::named("c"), &projects).is_empty());
    }

    #[test]
    fn describes() {
        let a = AgentRef {
            runtime: Some("claude"),
            project: Some("agent-auth"),
            host: Some("excelsior"),
            placement: Placement::Sandbox,
            ..AgentRef::named("x")
        };
        assert_eq!(describe(&a), "claude · agent-auth · excelsior · VM");
        assert_eq!(describe(&AgentRef::named("deploy-bot")), "");
    }
}
