//! Durations as agents and the operator write them: a number of seconds, or
//! `"30m"`, `"8h"`, `"2d"`, `"1w"` (Python `schemas.parse_duration`).
//!
//! One type for the whole system: [`DurationSecs`] is
//! `agent_auth_core::durations::DurationSecs`, so the wire accepts exactly
//! what the policy does (http-api §8.4, see DEVIATIONS.md): JSON `true` and
//! floats are refused (Python took `true` as 1 s and `1.0` as 1); a zero
//! with a unit (`"0m"`) is refused like a plain zero; and nothing over 365
//! days is accepted (Python had no bound and failed the INSERT with a 500).

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use agent_auth_core::durations::{
    DurationError, DurationSecs, MAX_DURATION_SECS, MAX_HOST_DURATION_SECS, NOT_A_DURATION,
    format_duration,
};
use agent_auth_core::durations::{host_duration_from_int, host_duration_secs};

use crate::text::Text;

/// A duration passed through to a host (`arm`, `dnd`), which parses it with
/// its own rules (hostd's `duration_secs` also takes a bare `"30"`). It is
/// checked here with those same rules and bounded by
/// [`MAX_HOST_DURATION_SECS`] (365 days), so nothing the broker relays can
/// overflow the host's clock arithmetic; the text form is kept as written.
///
/// Only the constructors make one, so a value is always within the bound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostDuration(HostRepr);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum HostRepr {
    Seconds(u64),
    Text(Text<1, 32>),
}

impl HostDuration {
    /// One second.
    pub const MIN: HostDuration = HostDuration(HostRepr::Seconds(1));

    /// A number of seconds: positive, at most [`MAX_HOST_DURATION_SECS`].
    pub fn from_secs(secs: u64) -> Result<HostDuration, DurationError> {
        let secs = i64::try_from(secs).unwrap_or(i64::MAX);
        host_duration_from_int(secs).map(|s| HostDuration(HostRepr::Seconds(s)))
    }

    /// Text by the host's rules (`"30"`, `"30m"`, `"8h"`), kept as written.
    pub fn parse(text: &str) -> Result<HostDuration, DurationError> {
        let kept = Text::new(text).map_err(|e| DurationError(e.to_string()))?;
        host_duration_secs(text)?;
        Ok(HostDuration(HostRepr::Text(kept)))
    }

    /// The number of seconds, by the host's rules.
    #[must_use]
    pub fn secs(&self) -> u64 {
        match &self.0 {
            HostRepr::Seconds(n) => *n,
            HostRepr::Text(t) => host_duration_secs(t.as_str()).unwrap_or(0),
        }
    }
}

impl Serialize for HostDuration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            HostRepr::Seconds(n) => s.serialize_u64(*n),
            HostRepr::Text(t) => t.serialize(s),
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
                HostDuration::from_secs(v).map_err(E::custom)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<HostDuration, E> {
                host_duration_from_int(v)
                    .map(|s| HostDuration(HostRepr::Seconds(s)))
                    .map_err(E::custom)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<HostDuration, E> {
                HostDuration::parse(v).map_err(E::custom)
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
        let max = "duration must be at most 365 days";
        assert_eq!(de(json!("100w")).unwrap_err(), max);
        assert_eq!(de(json!("366d")).unwrap_err(), max);
        assert_eq!(de(json!(31_536_001u64)).unwrap_err(), max);
        assert_eq!(de(json!(2_147_483_648u64)).unwrap_err(), max);
        assert_eq!(de(json!("99999999999999999999999")).unwrap_err(), max);
        assert_eq!(de(json!("99999999999999999w")).unwrap_err(), max);
        assert_eq!(de(json!(31_536_000u64)), Ok(31_536_000));
        assert_eq!(de(json!("52w")), Ok(52 * 604_800));
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
    fn host_durations_pass_through_bounded() {
        let d: HostDuration = serde_json::from_value(json!("30m")).unwrap();
        assert_eq!(serde_json::to_value(&d).unwrap(), json!("30m"));
        assert_eq!(d.secs(), 1800);
        let d: HostDuration = serde_json::from_value(json!("30")).unwrap();
        assert_eq!(d.secs(), 30);
        let d: HostDuration = serde_json::from_value(json!(90)).unwrap();
        assert_eq!(d, HostDuration::from_secs(90).unwrap());
        assert_eq!(d.secs(), 90);
        assert!(HostDuration::from_secs(MAX_HOST_DURATION_SECS + 1).is_err());
        assert!(HostDuration::from_secs(0).is_err());
        assert!(HostDuration::parse("1y").is_err());
        for bad in [
            json!(true),
            json!(1.5),
            json!("x".repeat(33)),
            json!("soon"),
            json!(0),
            json!(-1),
            json!("0m"),
            json!("366d"),
            json!(31_536_001u64),
            json!(u64::MAX),
            json!("99999999999999999999w"),
        ] {
            assert!(
                serde_json::from_value::<HostDuration>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        let max: HostDuration = serde_json::from_value(json!("365d")).unwrap();
        assert_eq!(max.secs(), MAX_HOST_DURATION_SECS);
    }
}
