//! Text clean-up shared by the parsers (`message.py` `_clean`).

/// Characters that hide or reorder text: zero-width, joiners, BOM, bidi
/// overrides and isolates, the invisible separators, the soft hyphen, and
/// the Unicode tag characters (U+E0000..U+E007F: "ASCII smuggling").
#[must_use]
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
            | '\u{00ad}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// `_clean`: invisible characters out, runs of spaces and tabs (and other
/// horizontal whitespace) to one space per line, lines trimmed, more than
/// one blank line to one, the whole trimmed.
#[must_use]
pub fn clean(text: &str) -> String {
    let text: String = text.chars().filter(|c| !is_invisible(*c)).collect();
    let text = text.replace("\r\n", "\n");
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let mut out = String::with_capacity(line.len());
        let mut space = false;
        for c in line.chars() {
            // `[ \t\r\f\v]+`
            if matches!(c, ' ' | '\t' | '\r' | '\x0c' | '\x0b') {
                space = true;
            } else {
                if space && !out.is_empty() {
                    out.push(' ');
                }
                space = false;
                out.push(c);
            }
        }
        // `.strip()` of the line: Python strips every Unicode space.
        lines.push(out.trim().to_owned());
    }
    // `\n\s*\n\s*\n+` → `\n\n`: lines are trimmed, so a run of two or more
    // empty lines between text is one.
    let mut joined = String::with_capacity(text.len());
    let mut blank_run = 0usize;
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            blank_run = blank_run.saturating_add(1);
            continue;
        }
        if i > 0 {
            let newlines = if blank_run >= 1 { 2 } else { 1 };
            for _ in 0..newlines {
                joined.push('\n');
            }
        }
        blank_run = 0;
        joined.push_str(line);
    }
    joined.trim().to_owned()
}

/// The first `n` characters.
#[must_use]
pub fn chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleaning() {
        assert_eq!(
            clean("  a \t b  \r\n\n\n\n c\u{200b}\u{202e}d "),
            "a b\n\ncd"
        );
        assert_eq!(clean("a\n\nb"), "a\n\nb");
        assert_eq!(clean("a\nb"), "a\nb");
        assert_eq!(clean("\n\n a"), "a");
        assert_eq!(clean("x\u{e0041}\u{e0042}y"), "xy");
    }
}
