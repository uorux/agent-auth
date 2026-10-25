//! The one timestamp format on the wire: RFC 3339 in UTC with exactly six
//! fractional digits and `Z`, e.g. `2026-01-01T00:00:00.000005Z`.
//!
//! The Python mixed pydantic's `Z` (fraction only when non-zero) with
//! `isoformat()`'s `+00:00`; one fixed-width format sorts as text, needs no
//! URL-encoding in a query string (no `+`), and round-trips the a2a events
//! cursor and the audit `next` exactly: Postgres keeps microseconds, and so
//! does this format. Parsing accepts any RFC 3339 offset and truncates to
//! microseconds, so `parse(format(t)) == t` for every stored time.
//!
//! Use as `#[serde(with = "crate::timestamp")]` on an `OffsetDateTime` field,
//! or `#[serde(with = "crate::timestamp::option", default)]` on an
//! `Option<OffsetDateTime>`.

use serde::{Deserialize, Deserializer, Serializer};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, PrimitiveDateTime, UtcOffset};

/// Longer than any timestamp we accept (RFC 3339 with nanoseconds and an
/// offset is 35 characters).
const MAX_TEXT: usize = 64;

/// Not a timestamp this format can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampError(&'static str);

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for TimestampError {}

/// `t` in UTC with anything below a microsecond dropped: what the wire (and
/// Postgres) can represent.
#[must_use]
pub fn truncate_to_micros(t: OffsetDateTime) -> OffsetDateTime {
    let t = t.to_offset(UtcOffset::UTC);
    let nanos = t.nanosecond();
    let micros_only = nanos.saturating_sub(nanos.checked_rem(1000).unwrap_or(0));
    t.replace_nanosecond(micros_only).unwrap_or(t)
}

/// `2026-01-01T00:00:00.000000Z`. Years outside 0000..=9999 have no RFC 3339
/// form and are refused.
pub fn format(t: OffsetDateTime) -> Result<String, TimestampError> {
    let t = truncate_to_micros(t);
    if !(0..=9999).contains(&t.year()) {
        return Err(TimestampError("timestamp out of range"));
    }
    t.format(format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
    ))
    .map_err(|_| TimestampError("timestamp out of range"))
}

/// Any RFC 3339 timestamp, converted to UTC and truncated to microseconds.
pub fn parse(text: &str) -> Result<OffsetDateTime, TimestampError> {
    if text.len() > MAX_TEXT {
        return Err(TimestampError("not an RFC 3339 timestamp"));
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .map(truncate_to_micros)
        .map_err(|_| TimestampError("not an RFC 3339 timestamp"))
}

/// A timestamp from a query parameter (`/v1/a2a/events?after=`,
/// `/v1/audit/events?since=`): RFC 3339, or an ISO 8601 date-time without an
/// offset (read as UTC, as the Python did), or a bare date (midnight UTC).
/// A space may stand for the `T`.
pub fn parse_query(text: &str) -> Result<OffsetDateTime, TimestampError> {
    const BAD: TimestampError = TimestampError("not an ISO 8601 time");
    if text.len() > MAX_TEXT || !text.is_ascii() {
        return Err(BAD);
    }
    let normalized: String = text
        .char_indices()
        .map(|(i, c)| if i == 10 && c == ' ' { 'T' } else { c })
        .collect();
    if let Ok(t) = parse(&normalized) {
        return Ok(t);
    }
    let naive = [
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]"),
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]"),
        format_description!("[year]-[month]-[day]T[hour]:[minute]"),
    ];
    for fmt in naive {
        if let Ok(t) = PrimitiveDateTime::parse(&normalized, fmt) {
            return Ok(truncate_to_micros(t.assume_utc()));
        }
    }
    if let Ok(d) = Date::parse(&normalized, format_description!("[year]-[month]-[day]")) {
        return Ok(d.midnight().assume_utc());
    }
    Err(BAD)
}

pub fn serialize<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
    let text = format(*t).map_err(serde::ser::Error::custom)?;
    s.serialize_str(&text)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
    let text = String::deserialize(d)?;
    parse(&text).map_err(serde::de::Error::custom)
}

/// For `Option<OffsetDateTime>` fields (null when absent).
pub mod option {
    use super::{Deserialize, Deserializer, OffsetDateTime, Serializer, parse};

    pub fn serialize<S: Serializer>(t: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => super::serialize(t, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(text) => parse(&text).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use time::macros::datetime;

    #[test]
    fn fixed_width_with_z() {
        let t = datetime!(2026-01-01 00:00:00 UTC);
        assert_eq!(format(t).unwrap(), "2026-01-01T00:00:00.000000Z");
        let t = datetime!(2026-01-01 00:00:00.000005 UTC);
        assert_eq!(format(t).unwrap(), "2026-01-01T00:00:00.000005Z");
        // Other offsets are converted, sub-microseconds dropped.
        let t = datetime!(2026-01-01 02:00:00.123456789 +02:00);
        assert_eq!(format(t).unwrap(), "2026-01-01T00:00:00.123456Z");
    }

    #[test]
    fn parses_python_forms() {
        let want = datetime!(2026-01-01 00:00:00.000005 UTC);
        for text in [
            "2026-01-01T00:00:00.000005Z",
            "2026-01-01T00:00:00.000005+00:00",
            "2026-01-01T01:00:00.000005+01:00",
        ] {
            assert_eq!(parse(text).unwrap(), want, "{text}");
        }
        assert_eq!(
            parse("2026-01-01T00:00:00Z").unwrap(),
            datetime!(2026-01-01 00:00:00 UTC)
        );
        assert!(parse("2026-01-01").is_err());
        assert!(parse("yesterday").is_err());
    }

    #[test]
    fn query_times_may_be_naive() {
        let want = datetime!(2026-03-04 05:06:07.5 UTC);
        assert_eq!(parse_query("2026-03-04T05:06:07.5").unwrap(), want);
        assert_eq!(parse_query("2026-03-04 05:06:07.5").unwrap(), want);
        assert_eq!(parse_query("2026-03-04T05:06:07.5Z").unwrap(), want);
        assert_eq!(
            parse_query("2026-03-04").unwrap(),
            datetime!(2026-03-04 00:00:00 UTC)
        );
        assert!(parse_query("2026-03-04T05:06:07 00:00").is_err());
        assert!(parse_query("x").is_err());
    }

    #[test]
    fn out_of_range_years_are_refused() {
        let t = datetime!(-0001-01-01 00:00:00 UTC);
        assert!(format(t).is_err());
    }

    proptest! {
        /// The cursor property: any time Postgres can hold survives a trip
        /// through the wire unchanged.
        #[test]
        fn round_trips_at_microsecond_precision(micros in 0i64..253_402_300_799_999_999) {
            let nanos = i128::from(micros).checked_mul(1000).unwrap();
            let t = OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap();
            let text = format(t).unwrap();
            prop_assert_eq!(parse(&text).unwrap(), t);
            prop_assert_eq!(parse_query(&text).unwrap(), t);
            prop_assert_eq!(text.len(), 27);
        }

        /// Text order is time order, so string comparison of two wire
        /// timestamps agrees with the times.
        #[test]
        fn sorts_as_text(a in 0i64..253_402_300_799_999_999, b in 0i64..253_402_300_799_999_999) {
            let ta = OffsetDateTime::from_unix_timestamp_nanos(i128::from(a).checked_mul(1000).unwrap()).unwrap();
            let tb = OffsetDateTime::from_unix_timestamp_nanos(i128::from(b).checked_mul(1000).unwrap()).unwrap();
            prop_assert_eq!(format(ta).unwrap().cmp(&format(tb).unwrap()), ta.cmp(&tb));
        }
    }
}
