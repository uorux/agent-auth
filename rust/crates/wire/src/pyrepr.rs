//! Python's `repr()` of a string, for the error texts the spec quotes as
//! `{x!r}` (`invalid duration 'x': ...`, `invalid status 'x'`).
//!
//! Single quotes, unless the text holds a `'` and no `"`; backslash escapes
//! for the quote, `\\`, `\t`, `\n`, `\r`; `\xNN`, `\uNNNN` or `\UNNNNNNNN`
//! for characters Python does not consider printable. Python decides that
//! from the Unicode database; this covers the control, separator, format and
//! private-use characters, and prints unassigned code points as they are
//! (the only difference, and only in an error message).

use std::fmt::Write;

#[must_use]
pub fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c => {
                let n = u32::from(c);
                // Writing to a String cannot fail.
                let _ = if n <= 0xff {
                    write!(out, "\\x{n:02x}")
                } else if n <= 0xffff {
                    write!(out, "\\u{n:04x}")
                } else {
                    write!(out, "\\U{n:08x}")
                };
            }
        }
    }
    out.push(quote);
    out
}

/// Python's `str.isprintable()` for one character, without the Unicode
/// database's unassigned code points.
fn printable(c: char) -> bool {
    let n = u32::from(c);
    !matches!(n,
        // Cc
        0x00..=0x1f | 0x7f..=0x9f
        // Zs other than ' ', Zl, Zp
        | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
        // Cf
        | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f
        | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f
        | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f
        // Co
        | 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd
        // noncharacters
        | 0xfffe | 0xffff
    )
}

#[cfg(test)]
mod tests {
    use super::repr;

    #[test]
    fn matches_python() {
        // Each expectation is CPython's repr() of the input.
        let cases = [
            ("sometime", "'sometime'"),
            ("", "''"),
            ("it's", "\"it's\""),
            ("it's \"x\"", "'it\\'s \"x\"'"),
            ("a\\b", "'a\\\\b'"),
            ("tab\there", "'tab\\there'"),
            ("nl\n", "'nl\\n'"),
            ("\x00\x1b\x7f", "'\\x00\\x1b\\x7f'"),
            ("\u{85}\u{a0}", "'\\x85\\xa0'"),
            ("é ü 日本", "'é ü 日本'"),
            ("\u{200b}", "'\\u200b'"),
            ("\u{2028}", "'\\u2028'"),
            ("🙂", "'🙂'"),
            ("\u{e0001}", "'\\U000e0001'"),
        ];
        for (input, want) in cases {
            assert_eq!(repr(input), want, "{input:?}");
        }
    }
}
