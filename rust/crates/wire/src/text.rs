//! Validating string and list newtypes: a value of one of these types is
//! within its limits, because deserializing (or `new`) is the only way to
//! make one. Lengths count characters (Unicode scalar values), as Python's
//! `len()` and pydantic's `max_length` do. Messages follow pydantic's
//! wording, or the Python's own `ValueError` text where it had one.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ValidationError;

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Is `s` between `min` and `max` characters long? Cheap for the common
/// cases: no counting when the byte length already decides.
fn check_length(s: &str, min: usize, max: usize) -> Result<(), ValidationError> {
    let bytes = s.len();
    let too_long = bytes > max && (bytes > max.saturating_mul(4) || s.chars().count() > max);
    if too_long {
        return Err(ValidationError::new(format!(
            "String should have at most {}",
            plural(max, "character", "characters")
        )));
    }
    let too_short =
        min > 0 && (bytes < min || (bytes < min.saturating_mul(4) && s.chars().count() < min));
    if too_short {
        return Err(ValidationError::new(format!(
            "String should have at least {}",
            plural(min, "character", "characters")
        )));
    }
    Ok(())
}

macro_rules! string_newtype_impls {
    ($name:ident $(<$(const $p:ident: $t:ty),*>)?) => {
        impl$(<$(const $p: $t),*>)? $name$(<$($p),*>)? {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl$(<$(const $p: $t),*>)? Deref for $name$(<$($p),*>)? {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl$(<$(const $p: $t),*>)? AsRef<str> for $name$(<$($p),*>)? {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl$(<$(const $p: $t),*>)? fmt::Display for $name$(<$($p),*>)? {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl$(<$(const $p: $t),*>)? fmt::Debug for $name$(<$($p),*>)? {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }

        impl$(<$(const $p: $t),*>)? From<$name$(<$($p),*>)?> for String {
            fn from(v: $name$(<$($p),*>)?) -> String {
                v.0
            }
        }

        impl$(<$(const $p: $t),*>)? TryFrom<String> for $name$(<$($p),*>)? {
            type Error = ValidationError;
            fn try_from(s: String) -> Result<Self, ValidationError> {
                Self::new(s)
            }
        }

        impl$(<$(const $p: $t),*>)? TryFrom<&str> for $name$(<$($p),*>)? {
            type Error = ValidationError;
            fn try_from(s: &str) -> Result<Self, ValidationError> {
                Self::new(s.to_owned())
            }
        }

        impl$(<$(const $p: $t),*>)? PartialEq<str> for $name$(<$($p),*>)? {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl$(<$(const $p: $t),*>)? PartialEq<&str> for $name$(<$($p),*>)? {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl$(<$(const $p: $t),*>)? Serialize for $name$(<$($p),*>)? {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de $($(, const $p: $t)*)?> Deserialize<'de> for $name$(<$($p),*>)? {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(de::Error::custom)
            }
        }
    };
}

/// A string of `MIN..=MAX` characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Text<const MIN: usize, const MAX: usize>(String);

impl<const MIN: usize, const MAX: usize> Text<MIN, MAX> {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        check_length(&s, MIN, MAX)?;
        Ok(Text(s))
    }
}

string_newtype_impls!(Text<const MIN: usize, const MAX: usize>);

/// Defines a string newtype checked by `$check: fn(&str) -> Result<(), String>`.
macro_rules! checked_string {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
                let s = s.into();
                let check: fn(&str) -> Result<(), ValidationError> = $check;
                check(&s)?;
                Ok($name(s))
            }
        }

        string_newtype_impls!($name);
    };
}

fn name_chars(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

checked_string!(
    /// `POST /v1/sessions` `label`: 1..64 of `[a-zA-Z0-9._-]`.
    SessionLabel,
    |s| {
        check_length(s, 1, 64)?;
        if !name_chars(s) {
            return Err(ValidationError::new(
                "String should match pattern '^[a-zA-Z0-9._-]+$'",
            ));
        }
        Ok(())
    }
);

checked_string!(
    /// An agent's name as an admin gives it (create, rename): 1..128 of
    /// `[a-zA-Z0-9._-]`.
    AgentNameInput,
    |s| {
        check_length(s, 1, 128)?;
        if !name_chars(s) {
            return Err(ValidationError::new(
                "String should match pattern '^[a-zA-Z0-9._-]+$'",
            ));
        }
        Ok(())
    }
);

checked_string!(
    /// `webhook_url`: at most 512 characters, `http` or `https` with a host
    /// (Python's `urlparse(v).scheme in (http, https) and netloc`).
    WebhookUrl,
    |s| {
        check_length(s, 0, 512)?;
        if webhook_url_ok(s) {
            Ok(())
        } else {
            Err(ValidationError::new(
                "webhook_url must be an http(s) URL with a host",
            ))
        }
    }
);

/// `urlparse`: the scheme is everything before the first `:` when that is a
/// valid scheme (compared lowercased); the netloc is what follows `//` up to
/// the next `/`, `?` or `#`.
fn webhook_url_ok(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let Some(after) = rest.strip_prefix("//") else {
        return false;
    };
    let netloc = after.split(['/', '?', '#']).next().unwrap_or("");
    !netloc.is_empty()
}

checked_string!(
    /// An a2a topic: at most 256 characters, none of them a control
    /// character (it is rendered into reviewer-facing context as one line).
    Topic,
    |s| {
        check_length(s, 0, 256)?;
        if s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}') {
            return Err(ValidationError::new(
                "topic must not contain control characters or newlines",
            ));
        }
        Ok(())
    }
);

checked_string!(
    /// A daemon's name (and so a host's): a lowercase hostname label,
    /// `[a-z0-9][a-z0-9-]{0,62}`.
    DaemonName,
    |s| {
        let mut bytes = s.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if first_ok && rest_ok && s.len() <= 63 {
            Ok(())
        } else {
            Err(ValidationError::new(
                "name must be a lowercase hostname label ([a-z0-9-], ≤63)",
            ))
        }
    }
);

/// An agent attribute (`runtime`, `project`, `host`): at most `MAX`
/// characters of `[a-z0-9][a-z0-9._-]*`; with `EMPTY` also `""` (which
/// clears the attribute in a PATCH).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attribute<const MAX: usize, const EMPTY: bool>(String);

impl<const MAX: usize, const EMPTY: bool> Attribute<MAX, EMPTY> {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s: String = s.into();
        check_length(&s, 0, MAX)?;
        if s.is_empty() && EMPTY {
            return Ok(Attribute(s));
        }
        let mut bytes = s.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok = bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
        if first_ok && rest_ok {
            Ok(Attribute(s))
        } else if EMPTY {
            Err(ValidationError::new(
                "String should match pattern '^([a-z0-9][a-z0-9._-]*)?$'",
            ))
        } else {
            Err(ValidationError::new(
                "String should match pattern '^[a-z0-9][a-z0-9._-]*$'",
            ))
        }
    }
}

string_newtype_impls!(Attribute<const MAX: usize, const EMPTY: bool>);

/// `runtime` (at most 16 characters).
pub type Runtime = Attribute<16, false>;
/// `project` or `host` (at most 64 characters).
pub type ProjectOrHost = Attribute<64, false>;

/// Exactly `N` lowercase hex digits (pairing selector and proofs, digests).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowerHex<const N: usize>(String);

impl<const N: usize> LowerHex<N> {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s: String = s.into();
        if s.len() == N
            && s.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            Ok(LowerHex(s))
        } else {
            Err(ValidationError::new(format!(
                "String should match pattern '^[0-9a-f]{{{N}}}$'"
            )))
        }
    }
}

string_newtype_impls!(LowerHex<const N: usize>);

/// URL-safe base64 text of at most `MAX` characters (nonces, signatures),
/// with or without `=` padding. Decoding is the crypto crate's.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base64Url<const MAX: usize>(String);

impl<const MAX: usize> Base64Url<MAX> {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s: String = s.into();
        let body = s.trim_end_matches('=');
        let padding = s.len().saturating_sub(body.len());
        let ok = !body.is_empty()
            && s.len() <= MAX
            && padding <= 2
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if ok {
            Ok(Base64Url(s))
        } else {
            Err(ValidationError::new(format!(
                "expected URL-safe base64 of at most {MAX} characters"
            )))
        }
    }
}

string_newtype_impls!(Base64Url<const MAX: usize>);

/// A list of `MIN..=MAX` items. Deserializing stops at the first item past
/// `MAX`, so an oversized list is never held in full.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedVec<T, const MIN: usize, const MAX: usize>(Vec<T>);

impl<T, const MIN: usize, const MAX: usize> BoundedVec<T, MIN, MAX> {
    pub fn new(items: Vec<T>) -> Result<Self, ValidationError> {
        if items.len() > MAX {
            return Err(ValidationError::new(format!(
                "List should have at most {}",
                plural(MAX, "item", "items")
            )));
        }
        if items.len() < MIN {
            return Err(ValidationError::new(format!(
                "List should have at least {}",
                plural(MIN, "item", "items")
            )));
        }
        Ok(BoundedVec(items))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> Default for BoundedVec<T, MIN, MAX> {
    /// Empty; only meaningful (and only used as a serde default) when
    /// `MIN == 0`.
    fn default() -> Self {
        BoundedVec(Vec::new())
    }
}

impl<T, const MIN: usize, const MAX: usize> Deref for BoundedVec<T, MIN, MAX> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> From<BoundedVec<T, MIN, MAX>> for Vec<T> {
    fn from(v: BoundedVec<T, MIN, MAX>) -> Vec<T> {
        v.0
    }
}

impl<T: Serialize, const MIN: usize, const MAX: usize> Serialize for BoundedVec<T, MIN, MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Deserialize<'de>, const MIN: usize, const MAX: usize> Deserialize<'de>
    for BoundedVec<T, MIN, MAX>
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const MIN: usize, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MIN: usize, const MAX: usize> Visitor<'de> for V<T, MIN, MAX> {
            type Value = BoundedVec<T, MIN, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a list of {MIN} to {MAX} items")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX).min(64));
                while let Some(item) = seq.next_element()? {
                    if items.len() >= MAX {
                        return Err(de::Error::custom(format!(
                            "List should have at most {}",
                            plural(MAX, "item", "items")
                        )));
                    }
                    items.push(item);
                }
                BoundedVec::new(items).map_err(de::Error::custom)
            }
        }
        d.deserialize_seq(V::<T, MIN, MAX>(PhantomData))
    }
}

/// A string-keyed object of at most `MAX` entries (sorted by key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedMap<K: Ord, V, const MAX: usize>(BTreeMap<K, V>);

impl<K: Ord, V, const MAX: usize> BoundedMap<K, V, MAX> {
    pub fn new(map: BTreeMap<K, V>) -> Result<Self, ValidationError> {
        if map.len() > MAX {
            Err(ValidationError::new(format!(
                "Dictionary should have at most {}",
                plural(MAX, "item", "items")
            )))
        } else {
            Ok(BoundedMap(map))
        }
    }

    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<K, V> {
        &self.0
    }

    #[must_use]
    pub fn into_map(self) -> BTreeMap<K, V> {
        self.0
    }
}

impl<K: Ord, V, const MAX: usize> Default for BoundedMap<K, V, MAX> {
    fn default() -> Self {
        BoundedMap(BTreeMap::new())
    }
}

impl<K: Ord, V, const MAX: usize> Deref for BoundedMap<K, V, MAX> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<K: Ord + Serialize, V: Serialize, const MAX: usize> Serialize for BoundedMap<K, V, MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, K, V, const MAX: usize> Deserialize<'de> for BoundedMap<K, V, MAX>
where
    K: Ord + Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis<K, V, const MAX: usize>(PhantomData<(K, V)>);
        impl<'de, K: Ord + Deserialize<'de>, V: Deserialize<'de>, const MAX: usize> Visitor<'de>
            for Vis<K, V, MAX>
        {
            type Value = BoundedMap<K, V, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an object of at most {MAX} entries")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((k, v)) = access.next_entry()? {
                    map.insert(k, v);
                    if map.len() > MAX {
                        return Err(de::Error::custom(format!(
                            "Dictionary should have at most {}",
                            plural(MAX, "item", "items")
                        )));
                    }
                }
                Ok(BoundedMap(map))
            }
        }
        d.deserialize_map(Vis::<K, V, MAX>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn de<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, String> {
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    #[test]
    fn text_counts_characters() {
        assert!(Text::<1, 3>::new("日本語").is_ok());
        assert_eq!(
            Text::<1, 3>::new("日本語x").unwrap_err().message(),
            "String should have at most 3 characters"
        );
        assert_eq!(
            Text::<1, 3>::new("").unwrap_err().message(),
            "String should have at least 1 character"
        );
        assert!(de::<Text<1, 3>>(json!(5)).is_err());
    }

    #[test]
    fn webhook_urls() {
        for ok in [
            "https://x.example/hook",
            "http://10.0.0.1:8080",
            "HTTPS://x",
            "http://:80",
        ] {
            assert!(WebhookUrl::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ftp://x",
            "https://",
            "https:x",
            "x",
            "",
            "https:///path",
            "javascript://%0a",
        ] {
            assert_eq!(
                WebhookUrl::new(bad).unwrap_err().message(),
                "webhook_url must be an http(s) URL with a host",
                "{bad}"
            );
        }
        let long = format!("https://x/{}", "a".repeat(600));
        assert!(WebhookUrl::new(long).is_err());
    }

    #[test]
    fn topics_are_one_line() {
        assert!(Topic::new("deploy/cactus").is_ok());
        for bad in ["a\nb", "a\rb", "\x00", "tab\t", "del\x7f"] {
            assert_eq!(
                Topic::new(bad).unwrap_err().message(),
                "topic must not contain control characters or newlines"
            );
        }
        assert!(Topic::new("x".repeat(257)).is_err());
        assert!(Topic::new("é".repeat(256)).is_ok());
    }

    #[test]
    fn labels_and_names() {
        assert!(SessionLabel::new("conv-1.a_b").is_ok());
        assert!(SessionLabel::new("has space").is_err());
        assert!(SessionLabel::new("x".repeat(65)).is_err());
        assert!(AgentNameInput::new("x".repeat(128)).is_ok());
        assert!(AgentNameInput::new("x".repeat(129)).is_err());
        assert!(DaemonName::new("excelsior").is_ok());
        assert!(DaemonName::new("a-1").is_ok());
        for bad in ["", "-a", "A", "a_b", "a\n", &"a".repeat(64)] {
            assert!(DaemonName::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn attributes() {
        assert!(Runtime::new("claude").is_ok());
        assert!(Runtime::new("").is_err());
        assert!(Attribute::<16, true>::new("").is_ok());
        assert!(Runtime::new("Claude").is_err());
        assert!(Runtime::new(".x").is_err());
        assert!(Runtime::new("x".repeat(17)).is_err());
        assert!(ProjectOrHost::new("agent-auth.v2_x").is_ok());
    }

    #[test]
    fn hex_and_base64() {
        assert!(LowerHex::<4>::new("0a9f").is_ok());
        assert!(LowerHex::<4>::new("0A9F").is_err());
        assert!(LowerHex::<4>::new("0a9").is_err());
        assert!(Base64Url::<8>::new("ab-_Z9").is_ok());
        assert!(Base64Url::<8>::new("ab+/").is_err());
        assert!(Base64Url::<8>::new("abcd==").is_ok());
        assert!(Base64Url::<8>::new("===").is_err());
        assert!(Base64Url::<4>::new("abcde").is_err());
    }

    #[test]
    fn bounded_lists_and_maps() {
        assert!(de::<BoundedVec<u8, 1, 2>>(json!([1, 2])).is_ok());
        assert!(
            de::<BoundedVec<u8, 1, 2>>(json!([1, 2, 3]))
                .unwrap_err()
                .contains("at most 2 items")
        );
        assert!(
            de::<BoundedVec<u8, 1, 2>>(json!([]))
                .unwrap_err()
                .contains("at least 1 item")
        );
        assert!(de::<BoundedMap<String, u8, 1>>(json!({"a": 1})).is_ok());
        assert!(de::<BoundedMap<String, u8, 1>>(json!({"a": 1, "b": 2})).is_err());
    }
}
