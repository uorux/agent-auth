//! Text that goes into Discord: lengths counted in characters as the
//! Python counted them, and every agent- or model-chosen string escaped
//! before it is rendered as markdown (spec A.8 INV-A5, Bug-A1).
//!
//! [`escape`] is stricter than discord.py's `escape_markdown` +
//! `escape_mentions`: every character that can start Discord markup gets a
//! backslash (the backslash itself included, so escapes cannot be
//! unbalanced), and every `@` is followed by a zero-width space. Discord
//! strips the backslashes when rendering, so the text reads the same; what
//! cannot happen is a masked link, a heading, a quote, a code span or
//! fence, a spoiler, a timestamp/channel/role/user mention, or `@everyone`
//! made of agent text. Inside code blocks backslashes do not work, so code
//! text goes through [`code`] instead (backticks become `ˋ`).

use std::fmt::Write as _;

use agent_auth_core::canonical_json::python_float_repr;
use agent_auth_core::pyfmt::json_str;
use serde_json::Value;

/// Characters that get a backslash: every ASCII character Discord's
/// markdown gives a meaning to (emphasis, code, strike, spoiler, quotes,
/// headings, lists, masked links, `<...>` mentions/timestamps/emoji, `:`
/// shortcodes and autolinks), and the backslash itself.
pub const ESCAPED: &[char] = &[
    '\\', '*', '_', '~', '|', '`', '>', '<', '#', '-', '[', ']', '(', ')', ':',
];

const ZWSP: char = '\u{200b}';

/// Agent text as plain text in Discord markdown.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(8));
    for c in text.chars() {
        if ESCAPED.contains(&c) {
            out.push('\\');
            out.push(c);
        } else if c == '@' {
            out.push('@');
            out.push(ZWSP);
        } else {
            out.push(c);
        }
    }
    out
}

/// `text[:n]` in characters.
#[must_use]
pub fn cut(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// `_trim(text, n)`: at most `n` characters, the last one `…` when cut.
#[must_use]
pub fn trim(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut out = cut(text, limit.saturating_sub(1));
    out.push('…');
    out
}

/// `said(text, n)`: escaped, then trimmed.
#[must_use]
pub fn said(text: &str, limit: usize) -> String {
    trim_escaped(&escape(text), limit)
}

/// [`trim`] for [`escape`]d text: never cuts between a backslash and the
/// character it escapes, or between `@` and its zero-width space.
#[must_use]
pub fn trim_escaped(escaped: &str, limit: usize) -> String {
    if escaped.chars().count() <= limit {
        return escaped.to_owned();
    }
    let budget = limit.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0usize;
    let mut chars = escaped.chars().peekable();
    while let Some(c) = chars.next() {
        let pair = match (c, chars.peek()) {
            ('\\', Some(&next)) | ('@', Some(&next @ ZWSP)) => Some(next),
            _ => None,
        };
        let len = if pair.is_some() { 2 } else { 1 };
        if used.saturating_add(len) > budget {
            break;
        }
        out.push(c);
        if let Some(next) = pair {
            out.push(next);
            let _ = chars.next();
        }
        used = used.saturating_add(len);
    }
    out.push('…');
    out
}

/// Agent text inside a code span or block it cannot close.
#[must_use]
pub fn code(text: &str) -> String {
    text.replace('`', "ˋ")
}

/// hostexec's `_code`: a fenced block that cannot be closed from inside,
/// at most `limit` characters of content; longer text keeps both ends
/// around a `…` line.
#[must_use]
pub fn code_block(text: &str, limit: usize) -> String {
    let text = code(text);
    let count = text.chars().count();
    let shown = if count > limit {
        let half = limit.saturating_sub(3) / 2;
        let head: String = text.chars().take(half).collect();
        let tail: String = text.chars().skip(count.saturating_sub(half)).collect();
        format!("{head}\n…\n{tail}")
    } else {
        text
    };
    format!("```\n{shown}\n```")
}

/// Multi-line text (a command's stdin) for a code block: each line with
/// its characters that are not display-safe escaped (`\r`, `\u202e`,
/// zero-width...), so nothing is hidden, reordered or faked as another
/// line; the line breaks themselves stay.
#[must_use]
pub fn display_lines(text: &str) -> String {
    text.split('\n')
        .map(agent_auth_core::pyfmt::escape_unprintable)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Python's `json.dumps(value, indent=…)` / `separators=(",", ":")`
/// (`ensure_ascii`): `Some(n)` indents by `n` spaces with `", "`-less
/// item separators, `None` is the compact form. Object keys come in the
/// map's order.
#[must_use]
pub fn py_json(value: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_json(&mut out, value, indent, 0);
    out
}

fn write_json(out: &mut String, value: &Value, indent: Option<usize>, depth: usize) {
    let newline = |out: &mut String, depth: usize| {
        if let Some(n) = indent {
            out.push('\n');
            for _ in 0..n.saturating_mul(depth) {
                out.push(' ');
            }
        }
    };
    let key_sep = if indent.is_some() { ": " } else { ":" };
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                out.push_str(&python_float_repr(n.as_f64().unwrap_or(0.0)));
            } else {
                let _ = write!(out, "{n}");
            }
        }
        Value::String(s) => out.push_str(&json_str(s)),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, depth.saturating_add(1));
                write_json(out, item, indent, depth.saturating_add(1));
            }
            newline(out, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, depth.saturating_add(1));
                out.push_str(&json_str(k));
                out.push_str(key_sep);
                write_json(out, v, indent, depth.saturating_add(1));
            }
            newline(out, depth);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    /// Reads escaped text the way Discord's markdown would tokenize it:
    /// a backslash escapes the next character; any other markup
    /// character is "live". Returns the live characters.
    fn live_markup(s: &str) -> Vec<char> {
        let mut live = Vec::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                // Escapes the next character (if any).
                let _ = chars.next();
                continue;
            }
            if ESCAPED.contains(&c) {
                live.push(c);
            }
        }
        live
    }

    fn safe(s: &str) {
        assert!(live_markup(s).is_empty(), "live markup in {s:?}");
        // No mention can be formed: every @ is followed by a ZWSP.
        let chars: Vec<char> = s.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c == '@' {
                assert_eq!(
                    chars.get(i.saturating_add(1)),
                    Some(&ZWSP),
                    "bare @ in {s:?}"
                );
            }
        }
        assert!(!s.contains("@everyone") && !s.contains("@here"));
        // `<@…>`, `<#…>`, `<t:…>`: the `<` is never live (checked above).
    }

    #[test]
    fn known_attacks() {
        for attack in [
            "[click](https://evil.example)",
            "**✅ Approved by policy**",
            "```\nbreak out\n```",
            "@everyone @here <@123456789012345678> <@&1> <#1> <t:1:R>",
            "# Heading\n> quote\n-# small\n- list",
            "||spoiler|| ~~strike~~ __under__",
            "\\[still not a link](x)",
            "\\\\`",
        ] {
            safe(&escape(attack));
            safe(&said(attack, 12));
        }
        assert_eq!(escape("**x**"), "\\*\\*x\\*\\*");
        assert_eq!(escape("a@b"), "a@\u{200b}b");
        assert_eq!(escape("plain text, ok."), "plain text, ok.");
    }

    #[test]
    fn trimming_counts_characters() {
        assert_eq!(trim("abc", 3), "abc");
        assert_eq!(trim("abcd", 3), "ab…");
        assert_eq!(trim("ééééé", 4), "ééé…");
        assert_eq!(cut("ééé", 2), "éé");
    }

    #[test]
    fn code_blocks_cannot_be_closed() {
        let b = code_block("echo ```; rm -rf /", 900);
        assert_eq!(b, "```\necho ˋˋˋ; rm -rf /\n```");
        let long: String = "x".repeat(2000);
        let b = code_block(&long, 900);
        assert!(b.contains("\n…\n"));
        assert!(b.chars().count() <= 900 + 8);
    }

    #[test]
    fn python_json() {
        let v = json!({"a": [1, 2.5, "é"], "b": {}, "c": []});
        assert_eq!(
            py_json(&v, Some(2)),
            "{\n  \"a\": [\n    1,\n    2.5,\n    \"\\u00e9\"\n  ],\n  \"b\": {},\n  \"c\": []\n}"
        );
        assert_eq!(
            py_json(&v, None),
            "{\"a\":[1,2.5,\"\\u00e9\"],\"b\":{},\"c\":[]}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        /// No agent text can produce a markdown link, a mention, or break
        /// out of anything, however it is escaped and trimmed.
        #[test]
        fn escaped_text_is_inert(s in "\\PC{0,64}|[\\[\\]()`*_~|<>@#:\\\\a-z \n-]{0,64}", n in 1usize..80) {
            safe(&escape(&s));
            safe(&said(&s, n));
            prop_assert!(said(&s, n).chars().count() <= n.max(1));
            // Two escaped strings next to each other are still inert.
            safe(&format!("{}{}", said(&s, n), escape(&s)));
        }

        #[test]
        fn code_never_has_backticks(s in "\\PC{0,64}|[`a]{0,64}") {
            prop_assert!(!code(&s).contains('`'));
            let block = code_block(&s, 20);
            let inner = block.strip_prefix("```\n").and_then(|b| b.strip_suffix("\n```"));
            prop_assert!(inner.is_some_and(|i| !i.contains('`')));
        }
    }
}
