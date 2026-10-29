//! Durations as written in requests and the policy file: `"90s"`, `"30m"`,
//! `"24h"`, `"30d"`, `"2w"`, or a number of seconds (an integer, or a string
//! of digits). Spec core-lifecycle-policy §9.4 (`schemas.parse_duration`).
//!
//! Deliberately stricter than the Python (bug B-14): zero is refused on
//! every path (`"0m"` used to parse to 0), and nothing longer than
//! [`MAX_DURATION_SECS`] (365 days) is accepted (it overflowed the 32-bit
//! columns). Only ASCII digits count as digits.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pyfmt::repr;

/// 365 days: the longest anything is granted for (a human's approval is
/// capped at the same).
pub const MAX_DURATION_SECS: u32 = 365 * 86_400;

/// A positive number of seconds, at most [`MAX_DURATION_SECS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurationSecs(u32);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DurationError(pub String);

impl DurationSecs {
    /// The longest duration there is.
    pub const MAX: DurationSecs = DurationSecs(MAX_DURATION_SECS);

    /// From a number of seconds (`parse_duration(int)`).
    pub fn from_secs(secs: i64) -> Result<Self, DurationError> {
        if secs <= 0 {
            return Err(DurationError("duration must be positive".to_owned()));
        }
        match u32::try_from(secs) {
            Ok(s) if s <= MAX_DURATION_SECS => Ok(DurationSecs(s)),
            _ => Err(too_long()),
        }
    }

    /// From text (`parse_duration(str)`): stripped and lowercased, then
    /// all digits (seconds) or `<digits><s|m|h|d|w>`.
    pub fn parse(text: &str) -> Result<Self, DurationError> {
        let value = text.trim().to_lowercase();
        let invalid = || {
            DurationError(format!(
                "invalid duration {}: use e.g. '30m', '8h', '2d', or seconds",
                repr(&value)
            ))
        };
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
            return Self::from_secs(parse_digits(&value).ok_or_else(too_long)?);
        }
        let Some(unit) = value.chars().last() else {
            return Err(invalid());
        };
        let multiplier: i64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(invalid()),
        };
        let digits = value.get(..value.len().saturating_sub(1)).unwrap_or("");
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let n = parse_digits(digits).ok_or_else(too_long)?;
        Self::from_secs(n.checked_mul(multiplier).ok_or_else(too_long)?)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn as_i64(self) -> i64 {
        i64::from(self.0)
    }

    #[must_use]
    pub fn as_duration(self) -> time::Duration {
        time::Duration::seconds(self.as_i64())
    }
}

/// A JSON boolean or float where a duration belongs (the Python took
/// `true` as 1 s and `1.0` as 1).
pub const NOT_A_DURATION: &str = "duration must be a string or a whole number of seconds";

fn too_long() -> DurationError {
    DurationError("duration must be at most 365 days".to_owned())
}

/// ASCII digits to a number; None past 18 significant digits (far beyond
/// any accepted duration).
fn parse_digits(digits: &str) -> Option<i64> {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.len() > 18 {
        return None;
    }
    if trimmed.is_empty() {
        return Some(0);
    }
    trimmed.parse().ok()
}

/// `format_duration`: the largest of w, d, h, m that divides it exactly,
/// else seconds.
#[must_use]
pub fn format_duration(secs: u64) -> String {
    for (unit, div) in [("w", 604_800u64), ("d", 86_400), ("h", 3600), ("m", 60)] {
        if secs >= div && secs.checked_rem(div) == Some(0) {
            return format!("{}{unit}", secs.checked_div(div).unwrap_or(0));
        }
    }
    format!("{secs}s")
}

impl fmt::Display for DurationSecs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(u64::from(self.0)))
    }
}

/// Serialized as seconds.
impl Serialize for DurationSecs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

/// An integer of seconds or a duration string; booleans and floats are
/// refused.
impl<'de> Deserialize<'de> for DurationSecs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = DurationSecs;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as \"30m\", \"8h\", \"2d\", or a number of seconds")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<DurationSecs, E> {
                DurationSecs::from_secs(v).map_err(E::custom)
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<DurationSecs, E> {
                let v = i64::try_from(v).map_err(|_| E::custom(too_long()))?;
                DurationSecs::from_secs(v).map_err(E::custom)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<DurationSecs, E> {
                DurationSecs::parse(v).map_err(E::custom)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<DurationSecs, E> {
                Err(E::custom(NOT_A_DURATION))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<DurationSecs, E> {
                Err(E::custom(NOT_A_DURATION))
            }
        }
        d.deserialize_any(V)
    }
}

/// The longest duration a host accepts or is sent (arming, do-not-disturb,
/// its own config): 365 days, like every other duration. Far above any
/// sane arm (hostd caps those per tier, default 1 h), and small enough that
/// `now + d` can never overflow on the host.
pub const MAX_HOST_DURATION_SECS: u64 = 365 * 86_400;

fn host_too_long() -> DurationError {
    DurationError("duration must be at most 365 days".to_owned())
}

/// hostd's own config durations (`hostd/config.py` `duration_secs`, spec
/// daemons-hostd §6.6): an integer > 0, or `<digits>[smhdw]` (no unit =
/// seconds) with a positive number; at most [`MAX_HOST_DURATION_SECS`]
/// (the Python had no bound).
pub fn host_duration_secs(text: &str) -> Result<u64, DurationError> {
    let value = text.trim().to_lowercase();
    let invalid = || {
        DurationError(format!(
            "invalid duration {}: use e.g. 30m, 8h, or seconds",
            repr(text)
        ))
    };
    let (digits, multiplier) = match value.chars().last() {
        Some('s') => (value.get(..value.len().saturating_sub(1)), 1u64),
        Some('m') => (value.get(..value.len().saturating_sub(1)), 60),
        Some('h') => (value.get(..value.len().saturating_sub(1)), 3600),
        Some('d') => (value.get(..value.len().saturating_sub(1)), 86_400),
        Some('w') => (value.get(..value.len().saturating_sub(1)), 604_800),
        _ => (Some(value.as_str()), 1),
    };
    let digits = digits.unwrap_or("");
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let Some(n) = parse_digits(digits) else {
        return Err(host_too_long());
    };
    if n <= 0 {
        return Err(invalid());
    }
    u64::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|&s| s <= MAX_HOST_DURATION_SECS)
        .ok_or_else(host_too_long)
}

/// hostd's integer form: positive and at most [`MAX_HOST_DURATION_SECS`].
pub fn host_duration_from_int(secs: i64) -> Result<u64, DurationError> {
    let secs = u64::try_from(secs)
        .ok()
        .filter(|&s| s > 0)
        .ok_or_else(|| DurationError("duration must be positive".to_owned()))?;
    if secs > MAX_HOST_DURATION_SECS {
        return Err(host_too_long());
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn p(s: &str) -> Result<u32, String> {
        DurationSecs::parse(s)
            .map(DurationSecs::get)
            .map_err(|e| e.0)
    }

    /// tests/test_policy.py::test_parse_duration
    #[test]
    fn parse_duration() {
        assert_eq!(p("30m"), Ok(1800));
        assert_eq!(p("8h"), Ok(8 * 3600));
        assert_eq!(p("2d"), Ok(2 * 86400));
        assert_eq!(DurationSecs::from_secs(90).map(DurationSecs::get), Ok(90));
        assert_eq!(p("90"), Ok(90));
        assert_eq!(
            p("soon"),
            Err("invalid duration 'soon': use e.g. '30m', '8h', '2d', or seconds".into())
        );
        assert_eq!(
            DurationSecs::from_secs(-5).map_err(|e| e.0),
            Err("duration must be positive".into())
        );
    }

    #[test]
    fn edges() {
        assert_eq!(p(" 90S "), Ok(90));
        assert_eq!(p("1W"), Ok(604_800));
        assert_eq!(p("0"), Err("duration must be positive".into()));
        assert_eq!(p("0m"), Err("duration must be positive".into()));
        assert_eq!(p("000"), Err("duration must be positive".into()));
        assert_eq!(p("0090"), Ok(90));
        assert_eq!(p("365d"), Ok(MAX_DURATION_SECS));
        assert_eq!(p("366d"), Err("duration must be at most 365 days".into()));
        assert_eq!(
            p("100000d"),
            Err("duration must be at most 365 days".into())
        );
        assert_eq!(
            p("99999999999999999999999999w"),
            Err("duration must be at most 365 days".into())
        );
        assert!(p("").is_err());
        assert!(p("m").is_err());
        assert!(p("1.5h").is_err());
        assert!(p("-5").is_err());
        assert!(p("+5").is_err());
        assert!(p("5 m").is_err());
        assert!(p("1h30m").is_err());
        assert!(p("٣").is_err(), "non-ASCII digits");
        assert_eq!(
            p(" Soon\n"),
            Err("invalid duration 'soon': use e.g. '30m', '8h', '2d', or seconds".into())
        );
    }

    #[test]
    fn serde_forms() {
        let d: DurationSecs = serde_json::from_str("3600").unwrap();
        assert_eq!(d.get(), 3600);
        let d: DurationSecs = serde_json::from_str("\"24h\"").unwrap();
        assert_eq!(d.get(), 86400);
        for bad in ["true", "1.5", "1.0"] {
            let err = serde_json::from_str::<DurationSecs>(bad)
                .unwrap_err()
                .to_string();
            assert!(err.starts_with(NOT_A_DURATION), "{err}");
        }
        let err = serde_json::from_str::<DurationSecs>("null")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected a duration"), "{err}");
        assert!(serde_json::from_str::<DurationSecs>("0").is_err());
        assert!(serde_json::from_str::<DurationSecs>("-1").is_err());
        assert!(serde_json::from_str::<DurationSecs>("18446744073709551615").is_err());
    }

    #[test]
    fn formats() {
        assert_eq!(format_duration(1800), "30m");
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(604_800 * 2), "2w");
        assert_eq!(format_duration(90), "90s");
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(3600 * 25), "25h");
    }

    #[test]
    fn host_durations() {
        assert_eq!(host_duration_secs("30"), Ok(30));
        assert_eq!(host_duration_secs("30m"), Ok(1800));
        assert_eq!(host_duration_secs(" 8H "), Ok(8 * 3600));
        assert_eq!(
            host_duration_secs("0m").map_err(|e| e.0),
            Err("invalid duration '0m': use e.g. 30m, 8h, or seconds".into())
        );
        assert!(host_duration_secs("x").is_err());
        assert!(host_duration_secs("").is_err());
        assert_eq!(host_duration_from_int(5), Ok(5));
        assert!(host_duration_from_int(0).is_err());
        assert_eq!(host_duration_secs("365d"), Ok(MAX_HOST_DURATION_SECS));
        assert_eq!(
            host_duration_secs("366d").map_err(|e| e.0),
            Err("duration must be at most 365 days".into())
        );
        assert!(host_duration_secs("99999999999999999999999w").is_err());
        assert!(host_duration_from_int(i64::MAX).is_err());
        assert_eq!(host_duration_from_int(31_536_000), Ok(31_536_000));
    }

    proptest! {
        #[test]
        fn parse_never_panics_and_is_bounded(s in ".{0,30}") {
            if let Ok(d) = DurationSecs::parse(&s) {
                prop_assert!(d.get() >= 1 && d.get() <= MAX_DURATION_SECS);
            }
        }

        #[test]
        fn unit_forms(n in 0u64..2_000_000, unit in "[smhdw]") {
            let mult = match unit.as_str() { "s" => 1, "m" => 60, "h" => 3600, "d" => 86400, _ => 604_800 };
            let want = n.checked_mul(mult).unwrap();
            let got = DurationSecs::parse(&format!("{n}{unit}"));
            if want == 0 || want > u64::from(MAX_DURATION_SECS) {
                prop_assert!(got.is_err());
            } else {
                prop_assert_eq!(got.map(|d| u64::from(d.get())).ok(), Some(want));
            }
        }

        #[test]
        fn format_round_trips(secs in 1u32..=MAX_DURATION_SECS) {
            let text = format_duration(u64::from(secs));
            prop_assert_eq!(DurationSecs::parse(&text).map(DurationSecs::get).ok(), Some(secs));
        }
    }
}
