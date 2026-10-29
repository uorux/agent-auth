//! Validated names. Each is a newtype whose only constructor checks it, so a
//! value of the type is always well-formed (parse, don't validate). The
//! rules and the error texts are the Python's.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pyfmt::repr;

/// A name that did not validate. The text is what the Python said.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NameError(pub String);

/// `[first][rest]{0,max_rest}`, ASCII only (every pattern here is).
fn shaped(s: &str, first: fn(char) -> bool, rest: fn(char) -> bool, max_rest: usize) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if first(c) => {}
        _ => return false,
    }
    let mut n = 0usize;
    for c in chars {
        if !rest(c) {
            return false;
        }
        n = n.saturating_add(1);
        if n > max_rest {
            return false;
        }
    }
    true
}

fn lower_digit(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn lower_digit_dash(c: char) -> bool {
    lower_digit(c) || c == '-'
}

fn lower_digit_dot_dash_underscore(c: char) -> bool {
    lower_digit(c) || matches!(c, '.' | '_' | '-')
}

fn agent_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

macro_rules! name_type {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validate `s`.
            pub fn parse(s: &str) -> Result<Self, NameError> {
                let check: fn(&str) -> Result<(), NameError> = $check;
                check(s)?;
                Ok(Self(s.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = NameError;
            fn from_str(s: &str) -> Result<Self, NameError> {
                Self::parse(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// The characters an agent name is made of (`AgentName`).
pub const AGENT_NAME_ALPHABET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
pub const AGENT_NAME_MAX: usize = 128;

name_type!(
    /// An agent's name: `^[a-zA-Z0-9._-]+$`, 1 to 128 characters
    /// (`AgentCreate.name`). Rules match it with globs; it is a label for
    /// people, the fields (runtime, project, host) are what policy is about.
    AgentName,
    |s| {
        if shaped(s, agent_name_char, agent_name_char, AGENT_NAME_MAX.saturating_sub(1)) {
            Ok(())
        } else {
            Err(NameError(
                "name: letters, digits, '.', '_' and '-', 1 to 128 characters".to_owned(),
            ))
        }
    }
);

/// The longest a runtime may be (the agents.runtime column).
pub const RUNTIME_MAX: usize = 16;

name_type!(
    /// An agent attribute value — a runtime, project or host as policy sees
    /// it: `[a-z0-9][a-z0-9._-]{0,63}` (`policy/agents.py` `ATTR_RE`).
    AttrValue,
    |s| {
        if shaped(s, lower_digit, lower_digit_dot_dash_underscore, 63) {
            Ok(())
        } else {
            Err(NameError(format!(
                "{}: lowercase letters, digits, dots, dashes and underscores",
                repr(s)
            )))
        }
    }
);

name_type!(
    /// A paired daemon's name (a host or an agent VM): a lowercase hostname
    /// label, `[a-z0-9][a-z0-9-]{0,62}` (`core/daemons.py` `NAME_RE`).
    DaemonName,
    |s| {
        if shaped(s, lower_digit, lower_digit_dash, 62) {
            Ok(())
        } else {
            Err(NameError(
                "name must be a lowercase hostname label ([a-z0-9-], ≤63)".to_owned(),
            ))
        }
    }
);

/// A host running hostd is a daemon like any other.
pub type HostName = DaemonName;

name_type!(
    /// A hostexec template's name: `[a-z0-9][a-z0-9._-]{0,62}`
    /// (`daemon_common/hostexec.py` `NAME_RE`).
    TemplateName,
    |s| {
        if shaped(s, lower_digit, lower_digit_dot_dash_underscore, 62) {
            Ok(())
        } else {
            Err(NameError("invalid template name".to_owned()))
        }
    }
);

name_type!(
    /// A project inside an agent VM (it becomes the unix user `p-<project>`):
    /// `[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?` (`sandboxd` `PROJECT_RE`).
    SandboxProject,
    |s| {
        let ok = shaped(s, lower_digit, lower_digit_dash, 29) && !s.ends_with('-');
        if ok {
            Ok(())
        } else {
            Err(NameError(
                "project names: lowercase letters, digits and '-', at most 30".to_owned(),
            ))
        }
    }
);

name_type!(
    /// An MCP server's name in the policy (`[a-z0-9][a-z0-9-]{0,62}`).
    McpServerName,
    |s| {
        if shaped(s, lower_digit, lower_digit_dash, 62) {
            Ok(())
        } else {
            Err(NameError(format!(
                "mcp server name {}: lowercase letters, digits and dashes",
                repr(s)
            )))
        }
    }
);

name_type!(
    /// The label of a web-UI connector; its agent is `web-<label>`
    /// (`core/oauth.py` `NAME_RE`, `^[a-z0-9][a-z0-9-]{0,40}$`).
    WebConnectorLabel,
    |s| {
        if shaped(s, lower_digit, lower_digit_dash, 40) {
            Ok(())
        } else {
            Err(NameError("name: lowercase letters, digits and '-'".to_owned()))
        }
    }
);

impl WebConnectorLabel {
    /// The connector's agent name.
    #[must_use]
    pub fn agent_name(&self) -> AgentName {
        // "web-" + [a-z0-9-]{1,41} is always a valid agent name.
        AgentName(format!("web-{}", self.0))
    }
}

name_type!(
    /// An environment variable name for a host job: `[A-Za-z_][A-Za-z0-9_]{0,63}`.
    EnvKey,
    |s| {
        let first = |c: char| c.is_ascii_alphabetic() || c == '_';
        let rest = |c: char| c.is_ascii_alphanumeric() || c == '_';
        if shaped(s, first, rest, 63) {
            Ok(())
        } else {
            Err(NameError(format!(
                "invalid environment variable name {}",
                repr(s)
            )))
        }
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn agent_names() {
        assert!(AgentName::parse("claude-agent-auth-galaxy").is_ok());
        assert!(AgentName::parse("A.b_c-1").is_ok());
        assert!(AgentName::parse("").is_err());
        assert!(AgentName::parse("not a name").is_err());
        assert!(AgentName::parse("x\n").is_err());
        assert!(AgentName::parse(&"a".repeat(128)).is_ok());
        assert!(AgentName::parse(&"a".repeat(129)).is_err());
        assert_eq!(AGENT_NAME_ALPHABET.chars().count(), 65);
    }

    #[test]
    fn attr_values() {
        assert!(AttrValue::parse("agent-auth").is_ok());
        assert!(AttrValue::parse("a.b_c").is_ok());
        assert_eq!(
            AttrValue::parse("Bad Name").unwrap_err().0,
            "'Bad Name': lowercase letters, digits, dots, dashes and underscores"
        );
        assert!(AttrValue::parse("-x").is_err());
        assert!(AttrValue::parse(&"a".repeat(64)).is_ok());
        assert!(AttrValue::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn daemon_names_reject_a_trailing_newline() {
        assert!(DaemonName::parse("excelsior").is_ok());
        assert!(DaemonName::parse("excelsior\n").is_err());
        assert!(DaemonName::parse("Excelsior").is_err());
        assert!(DaemonName::parse("a.b").is_err());
        assert!(DaemonName::parse(&"a".repeat(63)).is_ok());
        assert!(DaemonName::parse(&"a".repeat(64)).is_err());
    }

    #[test]
    fn sandbox_projects() {
        assert!(SandboxProject::parse("a").is_ok());
        assert!(SandboxProject::parse("ab-c").is_ok());
        assert!(SandboxProject::parse("ab-").is_err());
        assert!(SandboxProject::parse(&"a".repeat(30)).is_ok());
        assert!(SandboxProject::parse(&"a".repeat(31)).is_err());
    }

    #[test]
    fn web_labels() {
        let label = WebConnectorLabel::parse("claude-ai").unwrap();
        assert_eq!(label.agent_name().as_str(), "web-claude-ai");
        assert!(WebConnectorLabel::parse(&"a".repeat(41)).is_ok());
        assert!(WebConnectorLabel::parse(&"a".repeat(42)).is_err());
    }

    #[test]
    fn env_keys() {
        assert!(EnvKey::parse("_A1").is_ok());
        assert_eq!(
            EnvKey::parse("1A").unwrap_err().0,
            "invalid environment variable name '1A'"
        );
    }

    proptest! {
        #[test]
        fn attr_value_agrees_with_regex(s in "[a-z0-9._A-Z -]{0,70}") {
            let first_ok = s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            let rest_ok = s.chars().skip(1).all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".-_".contains(c));
            let len_ok = s.chars().count() <= 64;
            prop_assert_eq!(AttrValue::parse(&s).is_ok(), first_ok && rest_ok && len_ok);
        }

        #[test]
        fn agent_name_agrees_with_regex(s in "[a-zA-Z0-9._ /-]{0,130}") {
            let ok = !s.is_empty() && s.len() <= 128 && s.chars().all(|c| AGENT_NAME_ALPHABET.contains(c));
            prop_assert_eq!(AgentName::parse(&s).is_ok(), ok);
        }
    }
}
