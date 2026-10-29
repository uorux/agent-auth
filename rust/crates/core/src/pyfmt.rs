//! Python's text renderings that reach agents and operators verbatim:
//! `repr(str)` (in error messages), `json.dumps(str)` with its default
//! `ensure_ascii=True` (in risk notes and job descriptions), and
//! `shlex.quote`/`shlex.join` (in job descriptions).
//!
//! Every rendering here is *display-safe*: no control character (newline,
//! carriage return, escape...), bidirectional override or isolate, or
//! zero-width/invisible character reaches the output; they are written as
//! escapes. A command an approver reads is the command that runs, with no
//! fake second line and no reordered text. [`is_display_safe`] is the test.

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
            c => push_python_escape(&mut out, c),
        }
    }
    out.push(quote);
    out
}

/// `\xNN`, `\uNNNN` or `\UNNNNNNNN`, as Python's `repr` writes it.
fn push_python_escape(out: &mut String, c: char) {
    let n = u32::from(c);
    if n <= 0xff {
        let _ = write!(out, "\\x{n:02x}");
    } else if n <= 0xffff {
        let _ = write!(out, "\\u{n:04x}");
    } else {
        let _ = write!(out, "\\U{n:08x}");
    }
}

/// May this character be shown to a person as itself? Printable ASCII and
/// the space, and non-ASCII characters that are visible and don't reorder
/// or hide text. Not: controls (including `\t`, `\n`, `\r`, ESC, DEL),
/// line/paragraph separators and other non-space spaces, bidi controls
/// (U+202A..E, U+2066..9, U+200E/F, U+061C), zero-width and invisible
/// characters (U+200B..D, U+2060..F, U+FEFF, U+00AD, Hangul fillers), tag
/// characters, private use.
#[must_use]
pub fn is_display_safe(c: char) -> bool {
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }
    is_printable(c)
}

/// The text with every character that is not [display-safe](is_display_safe)
/// written as a Python escape (`\n`, `\t`, `\r`, `\x1b`, `\u202e`...);
/// backslashes are doubled so the result reads back unambiguously. For
/// free text shown inline (a host name, a pattern).
#[must_use]
pub fn escape_unprintable(s: &str) -> String {
    if s.chars().all(|c| is_display_safe(c) && c != '\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if is_display_safe(c) => out.push(c),
            c => push_python_escape(&mut out, c),
        }
    }
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
            // The whole invisible-operators block, U+2065 (unassigned) too.
            | 0x2060..=0x206f
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0xe0001
            | 0xe0020..=0xe007f
            // Hangul fillers and the combining grapheme joiner: render as
            // nothing.
            | 0x34f
            | 0x115f
            | 0x1160
            | 0x3164
            | 0xffa0
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
///
/// Unlike Python, an argument holding a character that is not
/// [display-safe](is_display_safe) is written in bash's ANSI-C quoting,
/// `$'...'`, with that character escaped (`$'a\nb'`, `$'\u202e'`): still
/// valid shell for the same argument, but it can't show a fake second line
/// or reorder what the approver reads.
#[must_use]
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_owned();
    }
    if !s.chars().all(is_display_safe) {
        return ansi_c_quote(s);
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

/// `$'...'`: `\\`, `\'`, `\t`, `\n`, `\r`, other unsafe ASCII as `\xNN`,
/// unsafe non-ASCII as `\uNNNN`/`\UNNNNNNNN` (fixed widths, so a
/// following hex digit is never swallowed).
fn ansi_c_quote(s: &str) -> String {
    let mut out = String::from("$'");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if is_display_safe(c) => out.push(c),
            c if c.is_ascii() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => {
                let n = u32::from(c);
                if n <= 0xffff {
                    let _ = write!(out, "\\u{n:04x}");
                } else {
                    let _ = write!(out, "\\U{n:08x}");
                }
            }
        }
    }
    out.push('\'');
    out
}

/// `shlex.join` (display-safe, see [`shlex_quote`]).
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

    #[test]
    fn unassigned_invisible_operator_is_escaped() {
        // Found by the argv proptest: U+2065 sat between the two ranges.
        assert!(!is_display_safe('\u{2065}'));
        assert_eq!(escape_unprintable("a\u{2065}b"), "a\\u2065b");
    }

    #[test]
    fn unsafe_characters_are_escaped_for_display() {
        assert_eq!(shlex_quote("a\nb"), "$'a\\nb'");
        assert_eq!(shlex_quote("echo ok\rrm -rf /"), "$'echo ok\\rrm -rf /'");
        assert_eq!(shlex_quote("x\u{202e}gpj.exe"), "$'x\\u202egpj.exe'");
        assert_eq!(shlex_quote("a\u{200b}b"), "$'a\\u200bb'");
        assert_eq!(shlex_quote("it's\t\\"), "$'it\\'s\\t\\\\'");
        assert_eq!(shlex_quote("\u{1b}[2J"), "$'\\x1b[2J'");
        assert_eq!(shlex_quote("\u{e0041}"), "$'\\U000e0041'");
        assert_eq!(escape_unprintable("host\nname"), "host\\nname");
        assert_eq!(escape_unprintable("a\\n"), "a\\\\n");
        assert_eq!(escape_unprintable("plain-é"), "plain-é");
        assert_eq!(repr("\u{202e}\u{2066}\u{200d}"), "'\\u202e\\u2066\\u200d'");
    }

    /// Decode bash `$'...'` (the subset `ansi_c_quote` writes).
    fn decode_ansi_c(q: &str) -> String {
        let body = q
            .strip_prefix("$'")
            .and_then(|b| b.strip_suffix('\''))
            .unwrap();
        let mut out = String::new();
        let mut it = body.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            let hex = |it: &mut std::str::Chars<'_>, n: usize| {
                let h: String = it.take(n).collect();
                char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap()
            };
            match it.next().unwrap() {
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                't' => out.push('\t'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                'x' => out.push(hex(&mut it, 2)),
                'u' => out.push(hex(&mut it, 4)),
                'U' => out.push(hex(&mut it, 8)),
                other => panic!("unexpected escape {other}"),
            }
        }
        out
    }

    fn is_dangerous(c: char) -> bool {
        c.is_control()
            || matches!(u32::from(c), 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff | 0x61c | 0x2028 | 0x2029 | 0xad)
    }

    proptest::proptest! {
        /// Any argv renders with no control, bidi or zero-width character,
        /// and each quoted argument still means the original.
        #[test]
        fn rendered_argv_is_display_safe(
            argv in proptest::collection::vec(
                "(.|[\\n\\r\\t\\x1b\\x7f\\u{200b}-\\u{200f}\\u{202a}-\\u{202e}\\u{2066}-\\u{2069}\\u{feff}'\\\\ a-z]){0,12}",
                1..5,
            )
        ) {
            let rendered = shlex_join(&argv);
            proptest::prop_assert!(!rendered.chars().any(is_dangerous), "{:?}", rendered);
            proptest::prop_assert!(rendered.chars().all(is_display_safe), "{:?}", rendered);
            for arg in &argv {
                let q = shlex_quote(arg);
                if q.starts_with("$'") {
                    proptest::prop_assert_eq!(&decode_ansi_c(&q), arg);
                }
                proptest::prop_assert!(escape_unprintable(arg).chars().all(is_display_safe));
                proptest::prop_assert!(repr(arg).chars().all(is_display_safe));
            }
        }
    }
}
