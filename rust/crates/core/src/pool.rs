//! Platform `pool`: what a lease asks for and how a pool item's
//! properties are matched (`provisioners/pool.py` `_matches`), as pure
//! functions. The broker's provisioner chooses and holds the item.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::{Number, Value};

use crate::pyfmt::repr;

/// At most this many keys in a `match`, and items in a list value.
pub const MAX_MATCH_KEYS: usize = 32;
/// The longest property name and string value.
pub const MAX_PROP_CHARS: usize = 256;

/// A property of a pool item, or a value a `match` asks for: a string, a
/// number, a boolean, or a list of strings (the Python's
/// `str | int | float | bool | list[str]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PropValue {
    Str(String),
    Num(Number),
    Bool(bool),
    List(Vec<String>),
}

impl PropValue {
    /// From JSON: a scalar, or a list of strings (bounded). None for
    /// anything else.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<PropValue> {
        match value {
            Value::String(s) if s.chars().count() <= MAX_PROP_CHARS => {
                Some(PropValue::Str(s.clone()))
            }
            Value::Number(n) => Some(PropValue::Num(n.clone())),
            Value::Bool(b) => Some(PropValue::Bool(*b)),
            Value::Array(items) if items.len() <= MAX_MATCH_KEYS => items
                .iter()
                .map(|v| match v {
                    Value::String(s) if s.chars().count() <= MAX_PROP_CHARS => Some(s.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<String>>>()
                .map(PropValue::List),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            PropValue::Str(s) => Value::String(s.clone()),
            PropValue::Num(n) => Value::Number(n.clone()),
            PropValue::Bool(b) => Value::Bool(*b),
            PropValue::List(items) => {
                Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
            }
        }
    }

    /// Python's `str(value)`: `True`, `1`, `1.5`, `['a', 'b']`.
    #[must_use]
    pub fn py_str(&self) -> String {
        match self {
            PropValue::Str(s) => s.clone(),
            PropValue::Num(n) => py_number(n),
            PropValue::Bool(true) => "True".to_owned(),
            PropValue::Bool(false) => "False".to_owned(),
            PropValue::List(items) => {
                let mut out = String::from("[");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&repr(item));
                }
                out.push(']');
                out
            }
        }
    }
}

fn py_number(n: &Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 => {
            let mut s = String::new();
            let _ = write!(s, "{f:.1}");
            s
        }
        Some(f) => f.to_string(),
        None => n.to_string(),
    }
}

impl<'de> Deserialize<'de> for PropValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;
        PropValue::from_json(&value).ok_or_else(|| {
            serde::de::Error::custom(
                "a property is a string, a number, a boolean or a list of strings",
            )
        })
    }
}

/// A `match`: property name to the value wanted.
pub type PropMatch = BTreeMap<String, PropValue>;

/// Which item of the pool a lease asks for (exactly one of the three).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PoolChoice {
    /// Any free item whose properties match (empty: any).
    Any(PropMatch),
    /// The item this agent held last.
    Previous,
    /// That item, by name.
    Item(String),
}

/// `_matches`: every key holds. A list asked for is a subset of a list
/// property; a scalar asked of a list property is one of its values;
/// scalars are equal (or print the same, as `str()`).
#[must_use]
pub fn matches(properties: &BTreeMap<String, PropValue>, wanted: &PropMatch) -> bool {
    wanted.iter().all(|(key, want)| {
        let Some(have) = properties.get(key) else {
            return false;
        };
        match (want, have) {
            (PropValue::List(want), PropValue::List(have)) => {
                want.iter().all(|w| have.iter().any(|h| h == w))
            }
            (PropValue::List(_), _) => false,
            (want, PropValue::List(have)) => {
                let w = want.py_str();
                have.contains(&w)
            }
            (want, have) => want == have || want.py_str() == have.py_str(),
        }
    })
}

/// A saved rule's `match` covers a request's: every key the rule names
/// is asked for with the same value (the request may ask for more).
#[must_use]
pub fn match_covers(rule: &PropMatch, wanted: &PropMatch) -> bool {
    rule.iter().all(|(k, v)| wanted.get(k) == Some(v))
}

/// `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`: an item's name.
#[must_use]
pub fn item_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn props(v: Value) -> BTreeMap<String, PropValue> {
        let Value::Object(map) = v else {
            panic!("an object")
        };
        map.iter()
            .map(|(k, v)| (k.clone(), PropValue::from_json(v).expect("a property")))
            .collect()
    }

    #[test]
    fn matching_follows_the_python() {
        let item = props(
            json!({"edition": "java", "tags": ["optifine", "survival"], "slots": 4, "ok": true}),
        );
        assert!(matches(&item, &props(json!({}))));
        assert!(matches(&item, &props(json!({"edition": "java"}))));
        assert!(!matches(&item, &props(json!({"edition": "bedrock"}))));
        assert!(matches(&item, &props(json!({"tags": "optifine"}))));
        assert!(matches(
            &item,
            &props(json!({"tags": ["optifine", "survival"]}))
        ));
        assert!(!matches(&item, &props(json!({"tags": ["creative"]}))));
        assert!(!matches(&item, &props(json!({"edition": ["java"]}))));
        assert!(matches(&item, &props(json!({"slots": 4}))));
        assert!(matches(&item, &props(json!({"slots": "4"}))));
        assert!(matches(&item, &props(json!({"ok": true}))));
        assert!(matches(&item, &props(json!({"ok": "True"}))));
        assert!(!matches(&item, &props(json!({"colour": "red"}))));
    }

    #[test]
    fn python_str() {
        assert_eq!(PropValue::Num(Number::from(3)).py_str(), "3");
        assert_eq!(
            PropValue::from_json(&json!(1.0)).map(|v| v.py_str()),
            Some("1.0".to_owned())
        );
        assert_eq!(
            PropValue::List(vec!["a".into(), "b'c".into()]).py_str(),
            "['a', \"b'c\"]"
        );
        assert!(PropValue::from_json(&json!({"a": 1})).is_none());
        assert!(PropValue::from_json(&json!([1])).is_none());
    }

    #[test]
    fn item_names() {
        assert!(item_name_ok("alt-1"));
        assert!(item_name_ok("A.b_c"));
        assert!(!item_name_ok("-x"));
        assert!(!item_name_ok(""));
        assert!(!item_name_ok("a b"));
        assert!(!item_name_ok(&"a".repeat(129)));
    }
}
