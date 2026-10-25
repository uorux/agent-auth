//! HTML to text, keeping what a person would see apart from what is hidden
//! from them (`message.py` `_Text`, `html_to_text`).
//!
//! A small tokenizer in the manner of Python's `html.parser` (HTML5's tag,
//! attribute, comment and raw-text rules; character references decoded as
//! `html.unescape` does), then the Python's visible/hidden bookkeeping:
//! text inside an element styled away (`display:none`, zero font size,
//! zero opacity, transparent colour...), marked `hidden` or (on a few
//! containers) `aria-hidden="true"`, inside `<script>`, `<style>`,
//! `<head>`, `<title>`, `<template>`, and comments, is hidden text.
//!
//! Linear in the input: end tags find their element through an index, and
//! nesting deeper than [`MAX_DEPTH`] makes the rest of the document hidden
//! (never shown to an agent as if a person could see it).

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::entities::ENTITIES;
use crate::text::clean;

/// Deepest element nesting tracked. Past it everything that follows is
/// treated as hidden.
pub const MAX_DEPTH: usize = 4096;

const VOID: [&str; 13] = [
    "br", "hr", "img", "meta", "link", "input", "area", "base", "col", "embed", "source", "track",
    "wbr",
];
const BLOCK: [&str; 14] = [
    "p",
    "div",
    "br",
    "tr",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "blockquote",
    "section",
];
const SKIP: [&str; 5] = ["script", "style", "head", "title", "template"];
/// Parsed as raw text (HTML5 RAWTEXT): only their end tag ends them.
const RAWTEXT: [&str; 6] = ["script", "style", "xmp", "iframe", "noembed", "noframes"];
/// Raw text with character references (RCDATA).
const RCDATA: [&str; 2] = ["textarea", "title"];

fn hidden_style() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Only zero (or under a pixel) hides: 0.875rem is ordinary small
        // print. Python's `$` (end, or before a final newline) is `\n?\z`.
        let end = r"\s*(?:!important)?\s*(?:;|\n?\z)";
        let pattern = format!(
            r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0+(?:\.0+)?(?:px|pt|em|rem|%)?{end}|font-size\s*:\s*0?\.\d+px|font-size\s*:\s*1px|opacity\s*:\s*0(?:\.0*)?{end}|max-height\s*:\s*0(?:px)?{end}|height\s*:\s*0(?:px)?{end}|color\s*:\s*(?:transparent|rgba\([^)]*,\s*0(?:\.0*)?\s*\))"
        );
        Regex::new(&pattern).unwrap_or_else(|_| never())
    })
}

/// A pattern that matches nothing (only reached if a literal pattern above
/// failed to compile, which the tests rule out).
pub(crate) fn never() -> Regex {
    Regex::new(r"[^\s\S]").unwrap_or_else(|_| never())
}

/// Does an inline style hide its element's text from a reader?
#[must_use]
pub fn style_hides(style: &str) -> bool {
    hidden_style().is_match(style)
}

// --------------------------------------------------------- references

fn entity(name: &str) -> Option<&'static str> {
    ENTITIES
        .binary_search_by(|(k, _)| (*k).cmp(name))
        .ok()
        .and_then(|i| ENTITIES.get(i))
        .map(|(_, v)| *v)
}

/// `html._invalid_charrefs`: numeric references Windows-1252 style.
fn invalid_charref(n: u32) -> Option<char> {
    const CP1252: [u32; 32] = [
        0x20ac, 0x81, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x8d, 0x017d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013,
        0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x9d, 0x017e, 0x0178,
    ];
    match n {
        0 => Some('\u{fffd}'),
        0x0d => Some('\r'),
        0x80..=0x9f => {
            let i = usize::try_from(n.checked_sub(0x80)?).ok()?;
            CP1252.get(i).copied().and_then(char::from_u32)
        }
        _ => None,
    }
}

/// `html._invalid_codepoints`: dropped.
fn invalid_codepoint(n: u32) -> bool {
    matches!(n, 0x1..=0x8 | 0xb | 0xe..=0x1f | 0x7f..=0x9f | 0xfdd0..=0xfdef)
        || (n & 0xfffe) == 0xfffe && n <= 0x10ffff
}

fn numeric(digits: &str, radix: u32) -> String {
    // Saturates: anything past U+10FFFF is the replacement character.
    let n = digits.chars().fold(0u32, |acc, c| {
        let d = c.to_digit(radix).unwrap_or(0);
        acc.saturating_mul(radix).saturating_add(d)
    });
    if let Some(c) = invalid_charref(n) {
        return c.to_string();
    }
    if (0xd800..=0xdfff).contains(&n) || n > 0x10ffff {
        return "\u{fffd}".to_owned();
    }
    if invalid_codepoint(n) {
        return String::new();
    }
    char::from_u32(n).map(String::from).unwrap_or_default()
}

/// `html.unescape`: numeric and named character references, the longest
/// legacy name when the full one is unknown.
#[must_use]
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        let (before, from) = rest.split_at(i);
        out.push_str(before);
        let after = from.get(1..).unwrap_or("");
        match reference(after) {
            Some((text, used)) => {
                out.push_str(&text);
                rest = after.get(used..).unwrap_or("");
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// One reference after a `&`: `(replacement, bytes used)`.
fn reference(after: &str) -> Option<(String, usize)> {
    if let Some(num) = after.strip_prefix('#') {
        let (radix, digits_from) = match num.strip_prefix(['x', 'X']) {
            Some(hex) => (16, hex),
            None => (10, num),
        };
        let len = digits_from
            .bytes()
            .take_while(|b| char::from(*b).is_digit(radix))
            .count();
        if len == 0 {
            return None;
        }
        let digits = digits_from.get(..len)?;
        let prefix = after.len().checked_sub(digits_from.len())?;
        let mut used = prefix.checked_add(len)?;
        if digits_from.get(len..).is_some_and(|r| r.starts_with(';')) {
            used = used.checked_add(1)?;
        }
        return Some((numeric(digits, radix), used));
    }
    // `[^\t\n\f <&#;]{1,32};?`
    let mut end = 0usize;
    for (count, (i, c)) in after.char_indices().enumerate() {
        if count >= 32 || matches!(c, '\t' | '\n' | '\x0c' | ' ' | '<' | '&' | '#' | ';') {
            break;
        }
        end = i.checked_add(c.len_utf8())?;
    }
    if end == 0 {
        return None;
    }
    let mut name_end = end;
    if after.get(end..).is_some_and(|r| r.starts_with(';')) {
        name_end = end.checked_add(1)?;
    }
    let name = after.get(..name_end)?;
    if let Some(text) = entity(name) {
        return Some((text.to_owned(), name_end));
    }
    // The longest legacy prefix (at least two characters).
    let bounds: Vec<usize> = name.char_indices().map(|(i, _)| i).skip(2).collect();
    for &cut in bounds.iter().rev() {
        if let Some(text) = name.get(..cut).and_then(entity) {
            let mut s = text.to_owned();
            s.push_str(name.get(cut..)?);
            return Some((s, name_end));
        }
    }
    None
}

/// `_unescape_attrvalue`: in attribute values, numeric references always,
/// named ones only when exact and not followed by `=`.
#[must_use]
pub fn unescape_attr(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        let (before, from) = rest.split_at(i);
        out.push_str(before);
        let after = from.get(1..).unwrap_or("");
        // `&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)[;=]?`
        if after.starts_with('#') {
            match reference(after) {
                Some((text, used)) => {
                    out.push_str(&text);
                    rest = after.get(used..).unwrap_or("");
                }
                None => {
                    out.push('&');
                    rest = after;
                }
            }
            continue;
        }
        let len = if after
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
        {
            after.bytes().take_while(u8::is_ascii_alphanumeric).count()
        } else {
            0
        };
        if len == 0 {
            out.push('&');
            rest = after;
            continue;
        }
        let next = after.as_bytes().get(len).copied();
        let with_semi = next == Some(b';');
        let name_len = if with_semi {
            len.saturating_add(1)
        } else {
            len
        };
        let name = after.get(..name_len).unwrap_or("");
        match (next, entity(name)) {
            (Some(b'='), _) | (_, None) => {
                out.push('&');
                out.push_str(name);
            }
            (_, Some(text)) => out.push_str(text),
        }
        rest = after.get(name_len..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------- tokenizer

/// What the tokenizer reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Start {
        name: String,
        attrs: Vec<(String, Option<String>)>,
        self_closing: bool,
    },
    End(String),
    Text(String),
    Comment(String),
}

fn is_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r' | b'\x0c' | b' ')
}

/// Tokenize `html`. Calls `emit` for each token, in order.
pub fn tokenize(html: &str, mut emit: impl FnMut(Token)) {
    let bytes = html.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut text_from = 0usize;
    // The raw-text element we are in, if any (and whether it decodes refs).
    let mut raw: Option<(String, bool)> = None;
    let flush = |from: usize, to: usize, decode: bool, emit: &mut dyn FnMut(Token)| {
        if from < to
            && let Some(t) = html.get(from..to)
        {
            emit(Token::Text(if decode { unescape(t) } else { t.to_owned() }));
        }
    };
    while i < n {
        let Some(off) = bytes
            .get(i..)
            .and_then(|r| r.iter().position(|b| *b == b'<'))
        else {
            break;
        };
        i = i.saturating_add(off);
        if let Some((name, decode)) = &raw {
            // Only `</name` followed by a space, `/` or `>` ends it.
            let end = i.saturating_add(2).saturating_add(name.len());
            let closes = bytes.get(i.saturating_add(1)) == Some(&b'/')
                && html
                    .get(i.saturating_add(2)..end)
                    .is_some_and(|t| t.eq_ignore_ascii_case(name))
                && bytes
                    .get(end)
                    .is_none_or(|b| is_space(*b) || *b == b'/' || *b == b'>');
            if !closes {
                i = i.saturating_add(1);
                continue;
            }
            flush(text_from, i, *decode, &mut emit);
            let close = bytes
                .get(end..)
                .and_then(|r| r.iter().position(|b| *b == b'>'))
                .map_or(n, |p| end.saturating_add(p).saturating_add(1));
            emit(Token::End(name.clone()));
            raw = None;
            i = close;
            text_from = i;
            continue;
        }
        let next = bytes.get(i.saturating_add(1)).copied();
        let consumed = match next {
            Some(b) if b.is_ascii_alphabetic() => {
                let (token, end) = start_tag(html, i.saturating_add(1));
                flush(text_from, i, true, &mut emit);
                // As `html.parser`: `<script/>` is a start and an end, no
                // raw text.
                if let Some(Token::Start {
                    name,
                    self_closing: false,
                    ..
                }) = &token
                {
                    if RAWTEXT.contains(&name.as_str()) {
                        raw = Some((name.clone(), false));
                    } else if RCDATA.contains(&name.as_str()) {
                        raw = Some((name.clone(), true));
                    }
                }
                if let Some(t) = token {
                    emit(t);
                }
                Some(end)
            }
            Some(b'/') => {
                flush(text_from, i, true, &mut emit);
                let from = i.saturating_add(2);
                let close = bytes
                    .get(from..)
                    .and_then(|r| r.iter().position(|b| *b == b'>'))
                    .map_or(n, |p| from.saturating_add(p).saturating_add(1));
                match bytes.get(from) {
                    Some(b) if b.is_ascii_alphabetic() => {
                        let name_end = bytes
                            .get(from..close)
                            .and_then(|r| {
                                r.iter()
                                    .position(|b| is_space(*b) || *b == b'/' || *b == b'>')
                            })
                            .map_or(close, |p| from.saturating_add(p));
                        if let Some(name) = html.get(from..name_end) {
                            emit(Token::End(name.to_ascii_lowercase()));
                        }
                    }
                    // `</>`: nothing. `</ x>`: a bogus comment.
                    Some(b'>') => {}
                    _ => {
                        let body_end = close.saturating_sub(1).max(from);
                        if let Some(t) = html.get(from..body_end.min(n)) {
                            emit(Token::Comment(t.to_owned()));
                        }
                    }
                }
                Some(close)
            }
            Some(b'!') => {
                flush(text_from, i, true, &mut emit);
                Some(declaration(html, i, &mut emit))
            }
            Some(b'?') => {
                flush(text_from, i, true, &mut emit);
                // A processing instruction (bogus comment): not text.
                let from = i.saturating_add(2);
                Some(
                    bytes
                        .get(from..)
                        .and_then(|r| r.iter().position(|b| *b == b'>'))
                        .map_or(n, |p| from.saturating_add(p).saturating_add(1)),
                )
            }
            // A lone `<` is text.
            _ => None,
        };
        match consumed {
            Some(end) => {
                i = end;
                text_from = i;
            }
            None => i = i.saturating_add(1),
        }
    }
    let decode = raw.as_ref().is_none_or(|(_, d)| *d);
    flush(text_from, n, decode, &mut emit);
}

/// `<!...`: a comment, a doctype or CDATA (nothing), or a bogus comment.
fn declaration(html: &str, i: usize, emit: &mut impl FnMut(Token)) -> usize {
    let bytes = html.as_bytes();
    let n = bytes.len();
    let rest = html.get(i..).unwrap_or("");
    if let Some(body) = rest.strip_prefix("<!--") {
        // Abrupt closes `<!-->` and `<!--->`.
        if body.starts_with('>') {
            emit(Token::Comment(String::new()));
            return i.saturating_add(5);
        }
        if body.starts_with("->") {
            emit(Token::Comment(String::new()));
            return i.saturating_add(6);
        }
        let start = i.saturating_add(4);
        let (text_end, end) = match (body.find("-->"), body.find("--!>")) {
            (Some(a), Some(b)) if b < a => (b, b.saturating_add(4)),
            (Some(a), _) => (a, a.saturating_add(3)),
            (None, Some(b)) => (b, b.saturating_add(4)),
            (None, None) => (body.len(), body.len()),
        };
        if let Some(t) = body.get(..text_end) {
            emit(Token::Comment(t.to_owned()));
        }
        return start.saturating_add(end).min(n);
    }
    let close = bytes
        .get(i..)
        .and_then(|r| r.iter().position(|b| *b == b'>'))
        .map_or(n, |p| i.saturating_add(p).saturating_add(1));
    let lower = rest.get(..9).unwrap_or(rest).to_ascii_lowercase();
    if lower.starts_with("<!doctype") || rest.starts_with("<![") {
        return close;
    }
    let from = i.saturating_add(2);
    let body_end = close.saturating_sub(1).max(from);
    if let Some(t) = html.get(from..body_end.min(n)) {
        emit(Token::Comment(t.to_owned()));
    }
    close
}

/// A start tag from its name's first letter: the token, and where the
/// text after it starts. A tag cut off by the end of the input is
/// dropped (HTML5: EOF in a tag emits nothing).
fn start_tag(html: &str, from: usize) -> (Option<Token>, usize) {
    let bytes = html.as_bytes();
    let n = bytes.len();
    let mut i = from;
    while i < n
        && bytes
            .get(i)
            .is_some_and(|b| !is_space(*b) && *b != b'/' && *b != b'>')
    {
        i = i.saturating_add(1);
    }
    let name = html.get(from..i).unwrap_or("").to_ascii_lowercase();
    let mut attrs: Vec<(String, Option<String>)> = Vec::new();
    let mut self_closing = false;
    loop {
        while i < n && bytes.get(i).is_some_and(|b| is_space(*b)) {
            i = i.saturating_add(1);
        }
        match bytes.get(i) {
            None => return (None, n),
            Some(b'>') => {
                return (
                    Some(Token::Start {
                        name,
                        attrs,
                        self_closing,
                    }),
                    i.saturating_add(1),
                );
            }
            Some(b'/') => {
                i = i.saturating_add(1);
                if bytes.get(i) == Some(&b'>') {
                    self_closing = true;
                }
                continue;
            }
            Some(_) => {}
        }
        // An attribute name: up to space, `/`, `=` or `>` (a leading `=`
        // belongs to the name, as in HTML5).
        let name_from = i;
        i = i.saturating_add(1);
        while i < n
            && bytes
                .get(i)
                .is_some_and(|b| !is_space(*b) && !matches!(b, b'/' | b'=' | b'>'))
        {
            i = i.saturating_add(1);
        }
        let attr = html.get(name_from..i).unwrap_or("").to_ascii_lowercase();
        let mut j = i;
        while j < n && bytes.get(j).is_some_and(|b| is_space(*b)) {
            j = j.saturating_add(1);
        }
        if bytes.get(j) != Some(&b'=') {
            attrs.push((attr, None));
            continue;
        }
        j = j.saturating_add(1);
        while j < n && bytes.get(j).is_some_and(|b| is_space(*b)) {
            j = j.saturating_add(1);
        }
        let value = match bytes.get(j) {
            Some(q @ (b'"' | b'\'')) => {
                let start = j.saturating_add(1);
                let Some(len) = bytes
                    .get(start..)
                    .and_then(|r| r.iter().position(|b| b == q))
                else {
                    return (None, n);
                };
                let end = start.saturating_add(len);
                i = end.saturating_add(1);
                html.get(start..end).unwrap_or("")
            }
            _ => {
                let start = j;
                while j < n && bytes.get(j).is_some_and(|b| !is_space(*b) && *b != b'>') {
                    j = j.saturating_add(1);
                }
                i = j;
                html.get(start..j).unwrap_or("")
            }
        };
        attrs.push((attr, Some(unescape_attr(value))));
    }
}

// --------------------------------------------------------- the reader

struct Reader {
    visible: String,
    hidden: Vec<String>,
    /// Open elements: name and whether it hides.
    stack: Vec<(String, bool)>,
    /// Positions in `stack` of each open element name.
    index: HashMap<String, Vec<usize>>,
    hidden_open: usize,
    skip: usize,
    /// Nesting went past MAX_DEPTH: everything from here is hidden.
    too_deep: bool,
}

impl Reader {
    fn is_hidden(&self) -> bool {
        self.too_deep || self.hidden_open > 0
    }

    fn start(&mut self, tag: &str, attrs: &[(String, Option<String>)]) {
        let attr = |name: &str| attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        if SKIP.contains(&tag) {
            self.skip = self.skip.saturating_add(1);
        }
        if BLOCK.contains(&tag) {
            self.visible.push('\n');
        }
        if VOID.contains(&tag) {
            if tag == "img"
                && !self.is_hidden()
                && self.skip == 0
                && let Some(Some(alt)) = attr("alt")
                && !alt.is_empty()
            {
                self.visible.push_str("[image: ");
                self.visible.push_str(alt);
                self.visible.push(']');
            }
            return;
        }
        let style = attr("style").and_then(|v| v.as_deref()).unwrap_or("");
        let hidden = style_hides(style)
            || attr("hidden").is_some()
            || (attr("aria-hidden").is_some_and(|v| v.as_deref() == Some("true"))
                && matches!(tag, "div" | "span" | "p" | "td"));
        if self.stack.len() >= MAX_DEPTH {
            self.too_deep = true;
            return;
        }
        let pos = self.stack.len();
        self.stack.push((tag.to_owned(), hidden));
        self.index.entry(tag.to_owned()).or_default().push(pos);
        if hidden {
            self.hidden_open = self.hidden_open.saturating_add(1);
        }
    }

    fn end(&mut self, tag: &str) {
        if SKIP.contains(&tag) {
            self.skip = self.skip.saturating_sub(1);
        }
        let target = self.index.get(tag).and_then(|v| v.last().copied());
        if let Some(at) = target {
            while self.stack.len() > at {
                let Some((name, hidden)) = self.stack.pop() else {
                    break;
                };
                if let Some(v) = self.index.get_mut(&name) {
                    v.pop();
                }
                if hidden {
                    self.hidden_open = self.hidden_open.saturating_sub(1);
                }
            }
        }
        if BLOCK.contains(&tag) {
            self.visible.push('\n');
        }
    }

    fn text(&mut self, data: String) {
        if self.skip > 0 {
            if !data.trim().is_empty() {
                self.hidden.push(data);
            }
            return;
        }
        if self.is_hidden() {
            self.hidden.push(data);
        } else {
            self.visible.push_str(&data);
        }
    }
}

/// `(visible text, hidden text)`, each cleaned (`_clean`).
#[must_use]
pub fn html_to_text(html: &str) -> (String, String) {
    let mut r = Reader {
        visible: String::new(),
        hidden: Vec::new(),
        stack: Vec::new(),
        index: HashMap::new(),
        hidden_open: 0,
        skip: 0,
        too_deep: false,
    };
    tokenize(html, |t| match t {
        Token::Start {
            name,
            attrs,
            self_closing,
        } => {
            r.start(&name, &attrs);
            // `handle_startendtag`: a start then an end.
            if self_closing {
                r.end(&name);
            }
        }
        Token::End(name) => r.end(&name),
        Token::Text(t) => r.text(t),
        Token::Comment(c) => {
            if !c.trim().is_empty() {
                r.hidden.push(c);
            }
        }
    });
    (clean(&r.visible), clean(&r.hidden.join(" ")))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn styles() {
        for hides in [
            "display:none",
            "DISPLAY : NONE",
            "visibility:hidden",
            "font-size:0",
            "font-size:0px",
            "font-size: 0.0em !important;",
            "font-size:.5px",
            "font-size:1px",
            "opacity:0",
            "opacity:0.0;",
            "max-height:0px",
            "height:0",
            "color:transparent",
            "color: rgba(0,0,0,0)",
            "font-size:0\n",
        ] {
            assert!(style_hides(hides), "{hides}");
        }
        for shows in [
            "font-size:0.875rem",
            "font-size:12px",
            "opacity:0.5",
            "height:10px",
            "color:#000",
            "font-size:0.5em",
        ] {
            assert!(!style_hides(shows), "{shows}");
        }
    }

    /// `test_small_print_is_not_hidden`.
    #[test]
    fn small_print() {
        let (text, hidden) = html_to_text(
            "<p style='font-size:0.875rem'>Total 1200 AUD</p><span style='font-size:0px'>x</span>",
        );
        assert!(text.contains("1200"));
        assert_eq!(hidden, "x");
    }

    #[test]
    fn hidden_and_visible() {
        let (text, hidden) = html_to_text(
            "<div style='display:none'>Preview text</div><p>Hello <b>you</b></p><script>x()</script>",
        );
        assert_eq!(text, "Hello you");
        assert_eq!(hidden, "Preview text x()");
        let (text, hidden) = html_to_text(
            "<p>a</p><!-- note --><div hidden>h1</div><span aria-hidden=\"true\">h2</span><img alt='logo'><img alt='x' style='display:none'>",
        );
        assert_eq!(text, "a\n\n[image: logo][image: x]");
        assert_eq!(hidden, "note h1 h2");
    }

    #[test]
    fn references() {
        assert_eq!(
            unescape("a &amp; b &lt;c&gt; &#65;&#x42; &copy &notit;"),
            "a & b <c> AB © ¬it;"
        );
        assert_eq!(
            unescape("&#0; &#x80; &#xD800; &#1114112; &#1;"),
            "\u{fffd} € \u{fffd} \u{fffd} "
        );
        assert_eq!(unescape("&unknown; & &#; &#x;"), "&unknown; & &#; &#x;");
        assert_eq!(unescape_attr("display&colon;none"), "display:none");
        assert_eq!(unescape_attr("a&amp=b &ampx &#58;"), "a&amp=b &ampx :");
        // Entity-encoded hiding is seen as hiding.
        let (text, hidden) = html_to_text("<span style=\"display&colon;none\">secret</span>ok");
        assert_eq!((text.as_str(), hidden.as_str()), ("ok", "secret"));
    }

    #[test]
    fn raw_text_and_odd_markup() {
        let (text, hidden) = html_to_text("<style>p{}</style><script>if (a<b) {}</script>x");
        assert_eq!(text, "x");
        assert_eq!(hidden, "p{} if (a<b) {}");
        let (text, _) = html_to_text("a < b and <3 <> </> <!doctype html> <?php x ?>c");
        assert_eq!(text, "a < b and <3 <> c");
        let (text, hidden) = html_to_text("<title>T &amp; t</title><textarea>&lt;x</textarea>");
        assert_eq!(text, "<x");
        assert_eq!(hidden, "T & t");
        // A tag cut off by the end is dropped.
        let (text, _) = html_to_text("ok <span style='display:none");
        assert_eq!(text, "ok");
        // Comments: abrupt closes, unterminated.
        let (text, hidden) = html_to_text("a<!-->b<!--->c<!-- d --!>e<!-- f");
        assert_eq!(text, "abce");
        assert_eq!(hidden, "d f");
    }

    #[test]
    fn nesting_is_linear_and_bounded() {
        let deep = "<div>".repeat(MAX_DEPTH + 10) + "deep";
        let (text, hidden) = html_to_text(&deep);
        assert_eq!(text, "");
        assert_eq!(hidden, "deep");
        // Many unmatched end tags against a deep stack stay fast.
        let html = "<span>".repeat(4000) + &"</nope>".repeat(200_000) + "x";
        let started = std::time::Instant::now();
        let (text, _) = html_to_text(&html);
        assert_eq!(text, "x");
        assert!(started.elapsed().as_secs() < 5);
        // A hidden element closed by its own end tag, not an inner one.
        let (text, hidden) = html_to_text("<div style='display:none'><div>a</div>b</div>c");
        assert_eq!((text.trim(), hidden.as_str()), ("c", "a b"));
    }
}
