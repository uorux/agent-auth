//! Durations as agents and the operator write them: a number of seconds, or
//! `"30m"`, `"8h"`, `"2d"`, `"1w"` (Python `schemas.parse_duration`).
//!
//! Fixed here (http-api §8.4, see DEVIATIONS.md): JSON `true` and floats are
//! refused (Python took `true` as 1 s and `1.0` as 1); a zero with a unit
//! (`"0m"`) is refused like a plain zero; and there is an upper bound,
//! [`MAX_DURATION_SECS`] (Python had none and failed the INSERT with a 500).

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ValidationError;
use crate::pyrepr::repr;
use crate::text::Text;

/// The longest duration accepted anywhere: the int4 range the store keeps
/// seconds in (about 68 years; policy caps grants far below this).
pub const MAX_DURATION_SECS: u32 = 2_147_483_647;

const NOT_A_DURATION: &str = "duration must be a string or a whole number of seconds";

fn positive() -> ValidationError {
    ValidationError::new("duration must be positive")
}

fn too_long() -> ValidationError {
    ValidationError::new(format!(
        "duration must be at most {MAX_DURATION_SECS} seconds"
    ))
}

/// A positive number of seconds, at most [`MAX_DURATION_SECS`]. On the wire
/// it is read from a number or a duration string and written as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurationSecs(u32);

impl DurationSecs {
    pub fn from_secs(secs: u64) -> Result<Self, ValidationError> {
        if secs == 0 {
            return Err(positive());
        }
        match u32::try_from(secs) {
            Ok(s) if s <= MAX_DURATION_SECS => Ok(DurationSecs(s)),
            _ => Err(too_long()),
        }
    }

    /// `"30m"`, `" 8H "`, `"600"`: stripped and lowercased, then all digits
    /// (seconds) or digits and one unit of `s m h d w`.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        let value = text.trim().to_lowercase();
        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if all_digits(&value) {
            return value
                .parse::<u64>()
                .map_err(|_| too_long())
                .and_then(Self::from_secs);
        }
        let unit = value.chars().last().and_then(|u| match u {
            's' => Some(1u64),
            'm' => Some(60),
            'h' => Some(3600),
            'd' => Some(86_400),
            'w' => Some(604_800),
            _ => None,
        });
        let number = value.get(..value.len().saturating_sub(1)).unwrap_or("");
        match unit {
            Some(unit) if all_digits(number) => {
                let n = number.parse::<u64>().map_err(|_| too_long())?;
                n.checked_mul(unit)
                    .ok_or_else(too_long)
                    .and_then(Self::from_secs)
            }
            _ => Err(ValidationError::new(format!(
                "invalid duration {}: use e.g. '30m', '8h', '2d', or seconds",
                repr(&value)
            ))),
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for DurationSecs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(self.0))
    }
}

impl Serialize for DurationSecs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for DurationSecs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = DurationSecs;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as \"30m\" or a number of seconds")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<DurationSecs, E> {
                DurationSecs::from_secs(v).map_err(E::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<DurationSecs, E> {
                match u64::try_from(v) {
                    Ok(v) => self.visit_u64(v),
                    Err(_) => Err(E::custom(positive())),
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<DurationSecs, E> {
                DurationSecs::parse(v).map_err(E::custom)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<DurationSecs, E> {
                Err(E::custom(NOT_A_DURATION))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<DurationSecs, E> {
                Err(E::custom(NOT_A_DURATION))
            }
        }
        d.deserialize_any(V)
    }
}

/// `600` → `"10m"`: the largest unit that divides evenly (Python
/// `format_duration`).
#[must_use]
pub fn format_duration(secs: u32) -> String {
    for (unit, div) in [("w", 604_800u32), ("d", 86_400), ("h", 3600), ("m", 60)] {
        if secs >= div && secs.checked_rem(div) == Some(0) {
            return format!("{}{unit}", secs.checked_div(div).unwrap_or(0));
        }
    }
    format!("{secs}s")
}

/// A duration passed through to a host (`arm`, `dnd`), which parses it with
/// its own rules (hostd's `duration_secs` also takes a bare `"30"`). Only
/// its type and size are checked here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostDuration {
    Seconds(u64),
    Text(Text<1, 32>),
}

impl Serialize for HostDuration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            HostDuration::Seconds(n) => s.serialize_u64(*n),
            HostDuration::Text(t) => t.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for HostDuration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = HostDuration;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as \"30m\" or a number of seconds")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<HostDuration, E> {
                Ok(HostDuration::Seconds(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<HostDuration, E> {
                u64::try_from(v)
                    .map(HostDuration::Seconds)
                    .map_err(|_| E::custom(positive()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<HostDuration, E> {
                Text::new(v).map(HostDuration::Text).map_err(E::custom)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<HostDuration, E> {
                Err(E::custom(NOT_A_DURATION))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<HostDuration, E> {
                Err(E::custom(NOT_A_DURATION))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn de(v: serde_json::Value) -> Result<u32, String> {
        serde_json::from_value::<DurationSecs>(v)
            .map(DurationSecs::get)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn python_cases() {
        assert_eq!(de(json!("30m")), Ok(1800));
        assert_eq!(de(json!(" 8H ")), Ok(28_800));
        assert_eq!(de(json!("2d")), Ok(172_800));
        assert_eq!(de(json!("1w")), Ok(604_800));
        assert_eq!(de(json!("45s")), Ok(45));
        assert_eq!(de(json!("600")), Ok(600));
        assert_eq!(de(json!(600)), Ok(600));
        assert_eq!(de(json!(0)).unwrap_err(), "duration must be positive");
        assert_eq!(de(json!(-5)).unwrap_err(), "duration must be positive");
        assert_eq!(de(json!("0")).unwrap_err(), "duration must be positive");
        assert_eq!(
            de(json!("sometime")).unwrap_err(),
            "invalid duration 'sometime': use e.g. '30m', '8h', '2d', or seconds"
        );
        assert_eq!(
            de(json!("")).unwrap_err(),
            "invalid duration '': use e.g. '30m', '8h', '2d', or seconds"
        );
        assert_eq!(
            de(json!(" X ")).unwrap_err(),
            "invalid duration 'x': use e.g. '30m', '8h', '2d', or seconds"
        );
        assert!(de(json!("1.5h")).is_err());
        assert!(de(json!("-1h")).is_err());
        assert!(de(json!("h")).is_err());
    }

    #[test]
    fn fixed_python_bugs() {
        let not = "duration must be a string or a whole number of seconds";
        assert_eq!(de(json!(true)).unwrap_err(), not);
        assert_eq!(de(json!(1.0)).unwrap_err(), not);
        assert_eq!(de(json!("0m")).unwrap_err(), "duration must be positive");
        let max = "duration must be at most 2147483647 seconds";
        assert_eq!(de(json!("3551w")).unwrap_err(), max);
        assert_eq!(de(json!(2_147_483_648u64)).unwrap_err(), max);
        assert_eq!(de(json!("99999999999999999999999")).unwrap_err(), max);
        assert_eq!(de(json!("99999999999999999w")).unwrap_err(), max);
        assert_eq!(de(json!(2_147_483_647u64)), Ok(2_147_483_647));
        assert!(de(json!(null)).unwrap_err().contains("expected a duration"));
    }

    #[test]
    fn formats_like_python() {
        assert_eq!(format_duration(600), "10m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(90), "90s");
        assert_eq!(format_duration(1_209_600), "2w");
        assert_eq!(format_duration(86_400), "1d");
        assert_eq!(format_duration(0), "0s");
        assert_eq!(
            serde_json::to_value(DurationSecs::parse("1h").unwrap()).unwrap(),
            json!(3600)
        );
    }

    #[test]
    fn host_durations_pass_through() {
        let d: HostDuration = serde_json::from_value(json!("30m")).unwrap();
        assert_eq!(serde_json::to_value(&d).unwrap(), json!("30m"));
        let d: HostDuration = serde_json::from_value(json!(90)).unwrap();
        assert_eq!(d, HostDuration::Seconds(90));
        assert!(serde_json::from_value::<HostDuration>(json!(true)).is_err());
        assert!(serde_json::from_value::<HostDuration>(json!(1.5)).is_err());
        assert!(serde_json::from_value::<HostDuration>(json!("x".repeat(33))).is_err());
    }
}
