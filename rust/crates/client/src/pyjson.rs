//! JSON text as Python's `json.dumps` writes it, for what the CLI prints
//! and what the MCP tools return (agents and the operator read it).
//!
//! - [`dumps_indent`]: `json.dumps(value, indent=2)`: `","` between items,
//!   `": "` after keys, two spaces per level, `[]`/`{}` for empty ones.
//! - [`dumps`]: `json.dumps(value)`: `", "` and `": "` on one line.
//!
//! Both with `ensure_ascii=True` (everything outside `' '..='~'` as
//! `\uXXXX`, astral characters as surrogate pairs) and floats as Python's
//! `repr`. Keys come in the order the value serializes them: a wire type's
//! field order (the Python model's), and sorted inside free-form objects.

use std::io;

use serde::Serialize;
use serde_json::ser::Formatter;

/// `json.dumps(value, indent=2)` (ASCII only).
pub fn dumps_indent<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    write(value, Some(2))
}

/// `json.dumps(value)` with Python's default separators (ASCII only).
pub fn dumps<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    write(value, None)
}

/// `json.dumps(value, separators=(",", ":"))` (ASCII only): one line.
pub fn dumps_compact<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    write_with(value, None, true)
}

fn write<T: Serialize + ?Sized>(
    value: &T,
    indent: Option<usize>,
) -> Result<String, serde_json::Error> {
    write_with(value, indent, false)
}

fn write_with<T: Serialize + ?Sized>(
    value: &T,
    indent: Option<usize>,
    tight: bool,
) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut out,
        PyFormatter {
            indent,
            tight,
            level: 0,
            has_value: false,
        },
    );
    value.serialize(&mut ser)?;
    // Every byte written is ASCII.
    Ok(String::from_utf8_lossy(&out).into_owned())
}

struct PyFormatter {
    indent: Option<usize>,
    /// `(",", ":")` instead of `(", ", ": ")` (without indent).
    tight: bool,
    level: usize,
    has_value: bool,
}

impl PyFormatter {
    fn newline<W: ?Sized + io::Write>(&self, w: &mut W) -> io::Result<()> {
        if let Some(step) = self.indent {
            w.write_all(b"\n")?;
            for _ in 0..self.level.saturating_mul(step) {
                w.write_all(b" ")?;
            }
        }
        Ok(())
    }

    fn separator<W: ?Sized + io::Write>(&self, w: &mut W, first: bool) -> io::Result<()> {
        match (first, self.indent) {
            (true, Some(_)) => self.newline(w),
            (true, None) => Ok(()),
            (false, Some(_)) => {
                w.write_all(b",")?;
                self.newline(w)
            }
            (false, None) if self.tight => w.write_all(b","),
            (false, None) => w.write_all(b", "),
        }
    }

    fn open<W: ?Sized + io::Write>(&mut self, w: &mut W, bracket: &[u8]) -> io::Result<()> {
        self.level = self.level.saturating_add(1);
        self.has_value = false;
        w.write_all(bracket)
    }

    fn close<W: ?Sized + io::Write>(&mut self, w: &mut W, bracket: &[u8]) -> io::Result<()> {
        self.level = self.level.saturating_sub(1);
        if self.has_value {
            self.newline(w)?;
        }
        w.write_all(bracket)
    }
}

impl Formatter for PyFormatter {
    fn write_f64<W: ?Sized + io::Write>(&mut self, w: &mut W, value: f64) -> io::Result<()> {
        w.write_all(agent_auth_core::canonical_json::python_float_repr(value).as_bytes())
    }

    fn write_f32<W: ?Sized + io::Write>(&mut self, w: &mut W, value: f32) -> io::Result<()> {
        self.write_f64(w, f64::from(value))
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // Quotes, backslashes and controls below 0x20 come through
        // `write_char_escape` (the same escapes as Python's); the rest of
        // what Python escapes (DEL and everything non-ASCII) is here.
        for c in fragment.chars() {
            if (' '..='~').contains(&c) {
                let mut buf = [0u8; 4];
                w.write_all(c.encode_utf8(&mut buf).as_bytes())?;
            } else {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(w, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.open(w, b"[")
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.close(w, b"]")
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.separator(w, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, _w: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.open(w, b"{")
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.close(w, b"}")
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.separator(w, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(if self.tight { b":" } else { b": " })
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, _w: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn indented_like_python() {
        // json.dumps({"a": [1, 2.5, {}], "b": {"c": None, "d": []}, "e": "x"}, indent=2)
        let v = json!({"a": [1, 2.5, {}], "b": {"c": null, "d": []}, "e": "x"});
        assert_eq!(
            dumps_indent(&v).unwrap(),
            "{\n  \"a\": [\n    1,\n    2.5,\n    {}\n  ],\n  \"b\": {\n    \"c\": null,\n    \"d\": []\n  },\n  \"e\": \"x\"\n}"
        );
        assert_eq!(dumps_indent(&json!([])).unwrap(), "[]");
        assert_eq!(dumps_indent(&json!({})).unwrap(), "{}");
        assert_eq!(dumps_indent(&json!("s")).unwrap(), "\"s\"");
    }

    #[test]
    fn compact_like_python() {
        // json.dumps({"error": "unknown or closed session", "status_code": 401})
        let v = json!({"error": "unknown or closed session", "status_code": 401});
        assert_eq!(
            dumps(&v).unwrap(),
            r#"{"error": "unknown or closed session", "status_code": 401}"#
        );
        assert_eq!(dumps(&json!([1, [2, 3], {}])).unwrap(), "[1, [2, 3], {}]");
        assert_eq!(
            dumps_compact(&json!({"a": [1, 2], "b": "\u{e9}"})).unwrap(),
            "{\"a\":[1,2],\"b\":\"\\u00e9\"}"
        );
    }

    #[test]
    fn ascii_only_like_python() {
        // json.dumps("é—😀\x7f\x01\"\\\n\t/")
        let v = json!("é\u{2014}😀\u{7f}\u{1}\"\\\n\t/");
        assert_eq!(
            dumps(&v).unwrap(),
            r#""\u00e9\u2014\ud83d\ude00\u007f\u0001\"\\\n\t/""#
        );
    }

    #[test]
    fn floats_like_python() {
        assert_eq!(
            dumps(&json!([60.0, 0.5, 1e300, 1e-7])).unwrap(),
            "[60.0, 0.5, 1e+300, 1e-07]"
        );
    }

    #[test]
    fn field_order_is_the_types() {
        #[derive(Serialize)]
        struct S {
            zeta: u8,
            alpha: Option<u8>,
        }
        assert_eq!(
            dumps_indent(&S {
                zeta: 1,
                alpha: None
            })
            .unwrap(),
            "{\n  \"zeta\": 1,\n  \"alpha\": null\n}"
        );
    }
}
