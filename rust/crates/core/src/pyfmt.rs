//! Python's text renderings that reach agents and operators verbatim:
//! `repr(str)` (in error messages), `json.dumps(str)` with its default
//! `ensure_ascii=True` (in risk notes and job descriptions), and
//! `shlex.quote`/`shlex.join` (in job descriptions).

use std::fmt::Write as _;

/// Python's `repr()` of a string: single quotes unless the text holds a `'`
/// and no `"`; backslash escapes for the quote, `\\`, `\t`, `\n`, `\r`, other
/// ASCII controls and DEL as `\xNN`, and non-printable non-ASCII characters
/// as `\xNN`/`\uNNNN`/`\UNNNNNNNN`.
///
/// Python decides "printable" from the Unicode database; this uses an
/// approximation (controls, separators other than the space, the common
/// format characters and private use are escaped). The texts that reach a
/// `repr` in this codebase are validated identifiers or ASCII in practice.
#[must_use]
pub fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c < ' ' || c == '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if c.is_ascii() => out.push(c),
            c if is_printable(c) => out.push(c),
            c => {
                let n = u32::from(c);
                if n <= 0xff {
                    let _ = write!(out, "\\x{n:02x}");
                } else if n <= 0xffff {
                    let _ = write!(out, "\\u{n:04x}");
                } else {
                    let _ = write!(out, "\\U{n:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

fn is_printable(c: char) -> bool {
    let n = u32::from(c);
    let format_char = matches!(
        n,
        0xad | 0x600..=0x605
            | 0x61c
            | 0x6dd
            | 0x70f
            | 0x180e
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x2064
            | 0x2066..=0x206f
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0xe0001
            | 0xe0020..=0xe007f
    );
    let private_use = matches!(n, 0xe000..=0xf8ff | 0xf0000..=0x10ffff);
    !(c.is_control() || (c.is_whitespace() && c != ' ') || format_char || private_use)
}

/// `json.dumps(s)` for a string (Python defaults: `ensure_ascii=True`):
/// `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, every other character outside
/// `' '..='~'` (DEL included) as `\uNNNN` in lowercase hex, astral
/// characters as a UTF-16 surrogate pair.
#[must_use]
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    push_json_str(&mut out, s);
    out
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// `json.dumps(d)` for a string-to-string mapping, in the order given
/// (default separators `", "` and `": "`).
#[must_use]
pub fn json_str_map<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in entries.into_iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        push_json_str(&mut out, k);
        out.push_str(": ");
        push_json_str(&mut out, v);
    }
    out.push('}');
    out
}

/// `shlex.quote`: unchanged when made only of `[A-Za-z0-9_@%+=:,./-]` (and
/// non-empty), else single-quoted with each `'` as `'"'"'`.
#[must_use]
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_owned();
    }
    let safe = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// `shlex.join`.
#[must_use]
pub fn shlex_join<S: AsRef<str>>(args: &[S]) -> String {
    args.iter()
        .map(|a| shlex_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr("apps-soc"), "'apps-soc'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(repr("it's \"x\""), "'it\\'s \"x\"'");
        assert_eq!(repr("a\\b"), "'a\\\\b'");
        assert_eq!(repr("a\nb\tc\rd"), "'a\\nb\\tc\\rd'");
        assert_eq!(repr("\u{1}\u{7f}"), "'\\x01\\x7f'");
        assert_eq!(repr("é"), "'é'");
        assert_eq!(repr("\u{a0}"), "'\\xa0'");
        assert_eq!(repr("\u{2028}"), "'\\u2028'");
        assert_eq!(repr("\u{feff}"), "'\\ufeff'");
        assert_eq!(repr("\u{10ffff}"), "'\\U0010ffff'");
        assert_eq!(repr(""), "''");
    }

    #[test]
    fn json_matches_python() {
        assert_eq!(
            json_str("a\u{7f}b\u{e9}\u{1F600}\u{1}\"\\/"),
            "\"a\\u007fb\\u00e9\\ud83d\\ude00\\u0001\\\"\\\\/\""
        );
        assert_eq!(
            json_str_map([("a", "1"), ("b", "x y")]),
            "{\"a\": \"1\", \"b\": \"x y\"}"
        );
        assert_eq!(json_str_map([]), "{}");
    }

    #[test]
    fn shlex_matches_python() {
        assert_eq!(shlex_join(&["ls", "-la", "/tmp"]), "ls -la /tmp");
        assert_eq!(
            shlex_join(&["echo", "a b", "", "it's"]),
            "echo 'a b' '' 'it'\"'\"'s'"
        );
        assert_eq!(shlex_quote("a=b,c:d@e%f+g"), "a=b,c:d@e%f+g");
        assert_eq!(shlex_quote("é"), "'é'");
    }
}
