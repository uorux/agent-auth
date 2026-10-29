//! What a human approving a host command is shown (daemons-hostd bug 5).
//!
//! The Python cut a command to fit a dialog and collapsed its whitespace
//! (a newline inside a `sh -c` script rendered as a space), and never showed
//! stdin, although an approval covers the whole spec. Here a command is
//! shown so that the text says exactly what runs: arguments with control
//! characters are written in ANSI-C quoting (`$'a\nb'`), stdin is shown
//! (escaped the same way), and when it all does not fit, the text says so
//! explicitly and names the spec's digest instead of silently cutting.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::pyfmt::{is_display_safe, shlex_quote};

/// One argument, quoted for display: `shlex.quote` for printable text,
/// bash's `$'...'` when it holds control characters (newlines, tabs, ESC,
/// DEL, Unicode controls), so nothing is hidden or reformatted.
#[must_use]
pub fn display_arg(s: &str) -> String {
    if !s.chars().any(needs_escape) {
        return shlex_quote(s);
    }
    let mut out = String::from("$'");
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if needs_escape(c) => {
                let n = u32::from(c);
                if n <= 0xff {
                    let _ = write!(out, "\\x{n:02x}");
                } else {
                    let _ = write!(out, "\\u{n:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// Control, bidi, zero-width and other characters that do not show as
/// themselves (`pyfmt::is_display_safe`).
fn needs_escape(c: char) -> bool {
    !is_display_safe(c)
}

/// An argv as one unambiguous line.
#[must_use]
pub fn display_argv<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|a| display_arg(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The extras of a command (where, with what environment, what on stdin),
/// each a ` · `-separated part, everything shown.
#[must_use]
pub fn command_extras(
    cwd: Option<&str>,
    env: &BTreeMap<String, String>,
    stdin: Option<&str>,
) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(cwd) = cwd {
        parts.push(format!("in {}", display_arg(cwd)));
    }
    if !env.is_empty() {
        let vars: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{k}={}", display_arg(v)))
            .collect();
        parts.push(format!("env {}", vars.join(" ")));
    }
    if let Some(stdin) = stdin {
        parts.push(format!(
            "stdin ({} chars): {}",
            stdin.chars().count(),
            display_arg(stdin)
        ));
    }
    parts
}

/// `text` if it fits in `limit` characters; otherwise its head and an
/// explicit notice that it was cut, naming the digest the approval is for.
/// The result never exceeds `limit` characters (for `limit` ≥ 160).
#[must_use]
pub fn fit(text: &str, limit: usize, digest: &str) -> String {
    let total = text.chars().count();
    if total <= limit {
        return text.to_owned();
    }
    let short: String = digest.chars().take(16).collect();
    // The notice's own length depends on the number shown; size it for the
    // largest possible number first.
    let notice = |shown: usize| {
        format!(
            " … [cut: {shown} of {total} characters shown; the approval covers all of it, \
             sha256 {short}…]"
        )
    };
    let room = limit.saturating_sub(notice(total).chars().count());
    let head: String = text.chars().take(room).collect();
    let shown = head.chars().count();
    format!("{head}{}", notice(shown))
}

/// Python `" ".join(str(value).split())[:limit]`: one bounded line, for
/// text the broker supplies (it can't pose as a line of its own).
#[must_use]
pub fn one_line(text: &str, limit: usize) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_visible() {
        assert_eq!(display_arg("ls"), "ls");
        assert_eq!(display_arg("a b"), "'a b'");
        assert_eq!(display_arg("echo hi\nrm -rf /"), "$'echo hi\\nrm -rf /'");
        assert_eq!(display_arg("it's\t"), "$'it\\'s\\t'");
        assert_eq!(display_arg("\u{1b}[2J"), "$'\\x1b[2J'");
        assert_eq!(display_arg("a\u{202e}b"), "$'a\\u202eb'");
        assert_eq!(display_argv(&["sh", "-c", "a\nb"]), "sh -c $'a\\nb'");
    }

    #[test]
    fn extras_show_stdin_content() {
        let env: BTreeMap<String, String> = [("LANG".to_owned(), "C".to_owned())].into();
        assert_eq!(
            command_extras(Some("/tmp"), &env, Some("x\ny")),
            vec![
                "in /tmp".to_owned(),
                "env LANG=C".to_owned(),
                "stdin (3 chars): $'x\\ny'".to_owned()
            ]
        );
    }

    #[test]
    fn fit_says_when_it_cuts() {
        let digest = "ab".repeat(32);
        assert_eq!(fit("short", 600, &digest), "short");
        let long = "x".repeat(1000);
        let out = fit(&long, 600, &digest);
        assert!(out.chars().count() <= 600, "{}", out.chars().count());
        assert!(out.contains("of 1000 characters shown"));
        assert!(out.contains("abababababababab"));
        assert!(out.starts_with("xxxx"));
    }

    #[test]
    fn one_line_collapses() {
        assert_eq!(one_line("  a\n b\tc  ", 10), "a b c");
        assert_eq!(one_line("abcdef", 3), "abc");
    }
}
