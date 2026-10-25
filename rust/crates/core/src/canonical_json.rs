//! JSON text exactly as Python's `json.dumps` writes it.
//!
//! Two outputs matter to the broker:
//!
//! - **Canonical JSON** for digests: `json.dumps(obj, sort_keys=True,
//!   separators=(",", ":"), ensure_ascii=True)`. A job spec's digest is the
//!   SHA-256 of this text (hashing lives in `agent-auth-crypto`), and a
//!   Python hostd computes the same digest, so the bytes must be identical.
//!   Only strings, integers, booleans, null, arrays and objects are allowed:
//!   a non-integer number is refused ([`CanonicalError::NonInteger`]) rather
//!   than risk a float printed differently on the two sides.
//! - **The length of Python's default `json.dumps(obj)`** (separators `", "`
//!   and `": "`, `ensure_ascii=True`), which is how the a2a payload size cap
//!   is measured. Floats are counted as Python's `repr` prints them.
//!
//! String escaping (both outputs, `ensure_ascii=True`): `\"`, `\\`, `\n`,
//! `\r`, `\t`, `\b`, `\f`; every other character outside `' '..='~'`
//! (including DEL, 0x7f) as `\uXXXX` with lowercase hex, astral characters
//! as a UTF-16 surrogate pair. `/` is not escaped.
//!
//! Keys are sorted by code point (Rust's `String` order is code-point
//! order, like Python's `str`). The default `json.dumps` keeps insertion
//! order instead, but the order does not change the length.

use serde_json::{Number, Value};

/// Why a value has no canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// Canonical JSON carries integers only (job specs never hold floats).
    #[error("canonical JSON allows only integer numbers")]
    NonInteger,
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn to_canonical_string(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out, Style::Canonical)?;
    Ok(out)
}

/// `len(json.dumps(value))` with Python's defaults (`", "`, `": "`,
/// `ensure_ascii=True`). Every output character is ASCII, so characters and
/// bytes coincide. Saturates at `usize::MAX` (never reached in practice).
pub fn python_dumps_len(value: &Value) -> usize {
    let mut counter = Counter(0);
    // The default style accepts every value serde_json can hold.
    match write_value(value, &mut counter, Style::PythonDefault) {
        Ok(()) | Err(_) => counter.0,
    }
}

/// `json.dumps(value)` with Python's defaults; mostly useful in tests and to
/// show what [`python_dumps_len`] measured.
pub fn to_python_default_string(value: &Value) -> String {
    let mut out = String::new();
    match write_value(value, &mut out, Style::PythonDefault) {
        Ok(()) | Err(_) => out,
    }
}

/// Python's `repr(float)` for a finite value: the shortest digits that
/// round-trip, in fixed notation when the decimal point falls within
/// `-4 < decpt <= 16`, otherwise `d.ddde±XX` (at least two exponent digits);
/// integral values in fixed notation get a trailing `.0`.
///
/// Non-finite values (which `serde_json` cannot hold) print as Python's
/// `json.dumps` would: `NaN`, `Infinity`, `-Infinity`.
pub fn python_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-Infinity".to_owned()
        } else {
            "Infinity".to_owned()
        };
    }
    // Rust's `{:e}` prints the shortest round-tripping digits, e.g. `-1.25e-7`.
    let sci = format!("{value:e}");
    let (negative, unsigned) = match sci.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, sci.as_str()),
    };
    let (mantissa, exponent) = unsigned.split_once('e').unwrap_or((unsigned, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let decpt = exponent.saturating_add(1);
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at_checked(1).unwrap_or((digits.as_str(), ""));
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let shown = decpt.saturating_sub(1);
        out.push('e');
        out.push(if shown < 0 { '-' } else { '+' });
        let magnitude = shown.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&magnitude.to_string());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..decpt.unsigned_abs() {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let point = usize::try_from(decpt).unwrap_or(usize::MAX);
        match digits.split_at_checked(point) {
            Some((int, frac)) if !frac.is_empty() => {
                out.push_str(int);
                out.push('.');
                out.push_str(frac);
            }
            _ => {
                out.push_str(&digits);
                for _ in digits.len()..point {
                    out.push('0');
                }
                out.push_str(".0");
            }
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Canonical,
    PythonDefault,
}

impl Style {
    fn item_sep(self) -> &'static str {
        match self {
            Style::Canonical => ",",
            Style::PythonDefault => ", ",
        }
    }
    fn key_sep(self) -> &'static str {
        match self {
            Style::Canonical => ":",
            Style::PythonDefault => ": ",
        }
    }
}

/// Where output goes: a string, or just a count of characters.
trait Sink {
    fn push_str(&mut self, s: &str);
    fn push(&mut self, c: char);
}

impl Sink for String {
    fn push_str(&mut self, s: &str) {
        String::push_str(self, s);
    }
    fn push(&mut self, c: char) {
        String::push(self, c);
    }
}

struct Counter(usize);

impl Sink for Counter {
    fn push_str(&mut self, s: &str) {
        self.0 = self.0.saturating_add(s.len());
    }
    fn push(&mut self, c: char) {
        self.0 = self.0.saturating_add(c.len_utf8());
    }
}

fn write_value(value: &Value, out: &mut impl Sink, style: Style) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out, style)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_sep());
                }
                write_value(item, out, style)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            // Sorted here rather than trusting the map's order: serde_json's
            // `preserve_order` feature, if anything in the build enables it,
            // would make `Map` iterate in insertion order.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_sep());
                }
                write_string(key, out);
                out.push_str(style.key_sep());
                write_value(item, out, style)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &Number, out: &mut impl Sink, style: Style) -> Result<(), CanonicalError> {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else {
        match style {
            Style::Canonical => return Err(CanonicalError::NonInteger),
            Style::PythonDefault => {
                out.push_str(&python_float_repr(n.as_f64().unwrap_or(f64::NAN)));
            }
        }
    }
    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_u16_escape(unit: u16, out: &mut impl Sink) {
    out.push_str("\\u");
    for shift in [12u16, 8, 4, 0] {
        let nibble = usize::from((unit >> shift) & 0xf);
        out.push(HEX.get(nibble).map_or('0', |b| char::from(*b)));
    }
}

/// A JSON string literal with Python's `ensure_ascii=True` escaping.
fn write_string(s: &str, out: &mut impl Sink) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    push_u16_escape(*unit, out);
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn escapes_like_python() {
        // Python: json.dumps("\x7f\x00\x1f\u00e9\U0001F600/<>&\u2028", ensure_ascii=True)
        let v = json!("\u{7f}\u{0}\u{1f}\u{e9}\u{1F600}/<>&\u{2028}");
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#""\u007f\u0000\u001f\u00e9\ud83d\ude00/<>&\u2028""#
        );
        let v = json!("\"\\\n\r\t\u{8}\u{c}\u{b}");
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#""\"\\\n\r\t\b\f\u000b""#
        );
    }

    #[test]
    fn sorts_and_compacts() {
        let v = json!({"b": [1, {"z": null, "a": true}], "a": false, "é": -3, "Z": ""});
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            r#"{"Z":"","a":false,"b":[1,{"a":true,"z":null}],"\u00e9":-3}"#
        );
    }

    #[test]
    fn refuses_floats() {
        assert_eq!(
            to_canonical_string(&json!({"a": 1.5})),
            Err(CanonicalError::NonInteger)
        );
        assert_eq!(
            to_canonical_string(&json!([1.0])),
            Err(CanonicalError::NonInteger)
        );
    }

    #[test]
    fn default_dumps() {
        let v = json!({"a": [1, {"b": null}], "c": true});
        assert_eq!(
            to_python_default_string(&v),
            r#"{"a": [1, {"b": null}], "c": true}"#
        );
        assert_eq!(python_dumps_len(&v), 34);
        assert_eq!(python_dumps_len(&json!({})), 2);
        assert_eq!(python_dumps_len(&json!("é")), 8);
        assert_eq!(python_dumps_len(&json!("\u{1F600}")), 14);
    }

    #[test]
    fn float_repr_matches_python() {
        // From Python's repr().
        let cases = [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1.5e-5, "1.5e-05"),
            (1e-4, "0.0001"),
            (123.456, "123.456"),
            (1.8446744073709552e19, "1.8446744073709552e+19"),
            (2.5e-308, "2.5e-308"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (0.1 + 0.2, "0.30000000000000004"),
            (100.0, "100.0"),
            (1e22, "1e+22"),
            (12345678901234567.0, "1.2345678901234568e+16"),
            (-2.5, "-2.5"),
        ];
        for (f, want) in cases {
            assert_eq!(python_float_repr(f), want, "{f:e}");
        }
        assert_eq!(python_float_repr(f64::NAN), "NaN");
        assert_eq!(python_float_repr(f64::NEG_INFINITY), "-Infinity");
    }

    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|i| json!(i)),
            any::<u64>().prop_map(|u| json!(u)),
            any::<String>().prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map(any::<String>(), inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 8 } else { 256 },
            // Miri isolates the file system; nothing to persist there.
            failure_persistence: if cfg!(miri) { None } else { ProptestConfig::default().failure_persistence },
            ..ProptestConfig::default()
        })]

        /// The canonical text is ASCII and parses back to the same value; the
        /// counted length is the length of the default text.
        #[test]
        fn canonical_roundtrips(v in arb_json()) {
            let text = to_canonical_string(&v).unwrap();
            prop_assert!(text.is_ascii());
            let back: Value = serde_json::from_str(&text).unwrap();
            prop_assert_eq!(&back, &v);
            prop_assert_eq!(python_dumps_len(&v), to_python_default_string(&v).len());
        }

        /// String escaping agrees with `pyfmt::json_str` (the same Python
        /// `json.dumps` of a string, used for messages).
        #[test]
        fn strings_agree_with_pyfmt(text in any::<String>()) {
            prop_assert_eq!(
                to_canonical_string(&Value::String(text.clone())).unwrap(),
                crate::pyfmt::json_str(&text)
            );
        }

        /// Every finite float's repr parses back to the same float.
        #[test]
        fn float_repr_roundtrips(f in any::<f64>().prop_filter("finite", |f| f.is_finite())) {
            let text = python_float_repr(f);
            let back: f64 = text.parse().unwrap();
            prop_assert_eq!(back.to_bits(), f.to_bits());
        }
    }
}
