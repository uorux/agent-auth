//! Untrusted text inside an LLM prompt's tags (the reviewer's
//! `<justification>`, the risk summarizer's `<request>`, the watcher's
//! `<watch>`, the mail judge's blocks, sandboxd's triage).
//!
//! The Python broke only the exact closing tag (`</justification` →
//! `<\/justification`), so `</JUSTIFICATION>`, `</ justification>` or a
//! look-alike bracket still read as the end of the block. Here no angle
//! bracket of the agent's survives at all: nothing it writes can open or
//! close a tag, whatever the case, spacing or tag name.

/// Characters a model may read as `<` or `>`: the ASCII ones and their
/// look-alikes (fullwidth, small, single guillemets, CJK and mathematical
/// angle brackets, modifier letters, Canadian syllabics).
const ANGLES: [char; 22] = [
    '<', '>', '\u{FF1C}', '\u{FF1E}', '\u{FE64}', '\u{FE65}', '\u{2039}', '\u{203A}', '\u{3008}',
    '\u{3009}', '\u{27E8}', '\u{27E9}', '\u{2329}', '\u{232A}', '\u{276C}', '\u{276D}', '\u{29FC}',
    '\u{29FD}', '\u{02C2}', '\u{02C3}', '\u{1438}', '\u{1433}',
];

fn angle(c: char) -> bool {
    ANGLES.contains(&c)
}

/// Free text for inside a tag: `&`, `<`, `>` as `&amp;`, `&lt;`, `&gt;`,
/// and a look-alike bracket as its numeric reference (`&#xFF1C;`). The
/// model reads it as the same text; no tag can start inside it.
#[must_use]
pub fn inert_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if angle(c) => out.push_str(&format!("&#x{:X};", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// Serialized JSON for inside a tag: every angle bracket (they can only
/// be inside strings) as its `\uXXXX` escape, so the JSON means the same
/// and no tag can start inside it.
#[must_use]
pub fn inert_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if angle(c) {
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn closing_tags_in_any_spelling_are_gone() {
        for attack in [
            "</justification>",
            "</JUSTIFICATION>",
            "</ Justification >",
            "<\t/justification>",
            "\u{FF1C}/justification\u{FF1E}",
            "\u{2039}/justification\u{203A}",
        ] {
            let t = inert_text(attack);
            assert!(!t.chars().any(angle), "{attack:?} -> {t:?}");
            assert!(!t.to_lowercase().contains("/justification>"), "{t:?}");
        }
        assert_eq!(inert_text("a </x> & b"), "a &lt;/x&gt; &amp; b");
        assert_eq!(inert_text("\u{FF1C}"), "&#xFF1C;");
        // An entity the agent writes stays text, not a bracket.
        assert_eq!(inert_text("&lt;/x&gt;"), "&amp;lt;/x&amp;gt;");
    }

    #[test]
    fn json_keeps_its_meaning() {
        let v = serde_json::json!({"k</Request>": ["</REQUEST>", "\u{FF1C}x\u{FF1E}"]});
        let text = serde_json::to_string_pretty(&v).unwrap();
        let inert = inert_json(&text);
        assert!(!inert.chars().any(angle), "{inert}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&inert).unwrap(),
            v
        );
    }

    proptest! {
        #[test]
        fn no_bracket_survives(s in any::<String>()) {
            prop_assert!(!inert_text(&s).chars().any(angle));
            let json = serde_json::to_string(&s).unwrap();
            let inert = inert_json(&json);
            prop_assert!(!inert.chars().any(angle));
            prop_assert_eq!(serde_json::from_str::<String>(&inert).unwrap(), s);
        }
    }
}
