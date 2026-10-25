//! Fields that only ever hold one value (`"ok": true`, `"kind": "shell"`):
//! unit types that serialize as that value and refuse any other.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The JSON value `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct True;

impl Serialize for True {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for True {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(True)
        } else {
            Err(de::Error::custom("expected true"))
        }
    }
}

/// Defines a unit type for one string value.
macro_rules! literal_str {
    ($(#[$meta:meta])* $name:ident = $text:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl $name {
            pub const TEXT: &'static str = $text;
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str($text)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_str($crate::literal::Expect($text)).map(|()| $name)
            }
        }
    };
}
pub(crate) use literal_str;

/// Visitor accepting exactly one string.
#[doc(hidden)]
#[derive(Debug)]
pub struct Expect(pub &'static str);

impl Visitor<'_> for Expect {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        if v == self.0 {
            Ok(())
        } else {
            Err(E::invalid_value(de::Unexpected::Str(v), &self))
        }
    }
}

literal_str!(
    /// `"kind": "shell"` (a shell's precheck and spec).
    ShellKind = "shell"
);
literal_str!(
    /// OAuth `token_type`.
    Bearer = "Bearer"
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_one_value() {
        assert_eq!(serde_json::to_value(True).unwrap(), json!(true));
        assert!(serde_json::from_value::<True>(json!(true)).is_ok());
        assert!(serde_json::from_value::<True>(json!(false)).is_err());
        assert!(serde_json::from_value::<True>(json!(1)).is_err());
        assert_eq!(serde_json::to_value(ShellKind).unwrap(), json!("shell"));
        assert!(serde_json::from_value::<ShellKind>(json!("shell")).is_ok());
        assert!(serde_json::from_value::<ShellKind>(json!("run")).is_err());
    }
}
