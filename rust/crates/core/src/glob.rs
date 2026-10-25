//! Shell-style globs, as Python's `fnmatch.fnmatchcase` on POSIX: the
//! matching language of every policy pattern (agents, resources, topics,
//! namespaces).
//!
//! - `*` matches any run of characters, `/` and newlines included.
//! - `?` matches exactly one character.
//! - `[...]` matches one character from a set: `[!...]` negates it, a `]`
//!   right after `[` or `[!` is a member, `a-z` is a range, a `-` first or
//!   last is a member. An unclosed `[` is a literal `[`.
//! - Everything else, backslash included, matches itself. Case-sensitive.
//!
//! Differences from CPython, deliberately: a reversed range (`[z-a]`)
//! matches nothing instead of CPython's merging of neighbouring chunks
//! (which can also raise), and the leading-`!` rule is the only negation.
//!
//! Matching is O(pattern × text) worst case (no exponential backtracking).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    AnyOne,
    Star,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassItem {
    Char(char),
    /// Inclusive; empty when lo > hi.
    Range(char, char),
}

impl ClassItem {
    fn contains(&self, c: char) -> bool {
        match *self {
            ClassItem::Char(x) => x == c,
            ClassItem::Range(lo, hi) => lo <= c && c <= hi,
        }
    }
}

/// A compiled glob pattern. Keeps its source text for display and serde.
#[derive(Clone)]
pub struct Glob {
    source: String,
    tokens: Vec<Token>,
}

impl Glob {
    #[must_use]
    pub fn new(pattern: &str) -> Glob {
        Glob {
            source: pattern.to_owned(),
            tokens: compile(pattern),
        }
    }

    /// The pattern that matches everything.
    #[must_use]
    pub fn any() -> Glob {
        Glob::new("*")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Does this pattern contain no wildcard at all (matches one string)?
    #[must_use]
    pub fn is_literal(&self) -> bool {
        self.tokens.iter().all(|t| matches!(t, Token::Literal(_)))
    }

    /// The one string this pattern matches, if it matches exactly one:
    /// literal characters and one-character sets (`[*]`, as [`escape`]
    /// writes them).
    #[must_use]
    pub fn literal_text(&self) -> Option<String> {
        self.tokens
            .iter()
            .map(|t| match t {
                Token::Literal(c) => Some(*c),
                Token::Class {
                    negated: false,
                    items,
                } => match items.as_slice() {
                    [ClassItem::Char(c)] => Some(*c),
                    [ClassItem::Range(lo, hi)] if lo == hi => Some(*lo),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        match_tokens(&self.tokens, &text)
    }

    /// Does this pattern match every non-empty string made of `alphabet`'s
    /// characters? Exact, not a heuristic: a literal or a set that misses
    /// some character `d` of the alphabet fails on `"d"` repeated; what is
    /// left (stars, `?`, sets covering the alphabet) matches every length
    /// from 1 up exactly when there is a star and at most one
    /// single-character token. (With a one-character alphabet a literal
    /// behaves like `?`; that case is handled too.)
    #[must_use]
    pub fn matches_every_nonempty_over(&self, alphabet: &[char]) -> bool {
        if alphabet.is_empty() {
            return false;
        }
        let covers_alphabet = |token: &Token| alphabet.iter().all(|&c| token_matches_one(token, c));
        let mut stars = 0usize;
        let mut singles = 0usize;
        for token in &self.tokens {
            if *token == Token::Star {
                stars = stars.saturating_add(1);
            } else if covers_alphabet(token) {
                singles = singles.saturating_add(1);
            } else {
                return false;
            }
        }
        stars > 0 && singles <= 1
    }
}

impl PartialEq for Glob {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}
impl Eq for Glob {}

impl std::hash::Hash for Glob {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.source.hash(state);
    }
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.source)
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Serialize for Glob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for Glob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Glob::new(&s))
    }
}

/// A glob matching exactly `text`: each `*`, `?` and `[` becomes `[*]`,
/// `[?]`, `[[]` (what a rule pinned to one resource stores; the Python's
/// `_literal`). Everything else already matches itself.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '?' | '[') {
            out.push('[');
            out.push(c);
            out.push(']');
        } else {
            out.push(c);
        }
    }
    out
}

/// `fnmatch(text, pattern)` without keeping the compiled pattern.
#[must_use]
pub fn fnmatch(text: &str, pattern: &str) -> bool {
    Glob::new(pattern).matches(text)
}

fn compile(pattern: &str) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        i = i.saturating_add(1);
        match c {
            '*' => {
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
            }
            '?' => tokens.push(Token::AnyOne),
            '[' => match parse_class(&chars, i) {
                Some((token, next)) => {
                    tokens.push(token);
                    i = next;
                }
                None => tokens.push(Token::Literal('[')),
            },
            other => tokens.push(Token::Literal(other)),
        }
    }
    tokens
}

/// Parse a class whose `[` was just before `start`. Returns the token and the
/// index after its `]`, or None when it is unclosed.
fn parse_class(chars: &[char], start: usize) -> Option<(Token, usize)> {
    let mut j = start;
    let negated = chars.get(j) == Some(&'!');
    if negated {
        j = j.saturating_add(1);
    }
    let body_start = j;
    // A `]` first in the set is a member, not the end.
    if chars.get(j) == Some(&']') {
        j = j.saturating_add(1);
    }
    while chars.get(j).is_some_and(|&c| c != ']') {
        j = j.saturating_add(1);
    }
    if j >= chars.len() {
        return None;
    }
    let body = chars.get(body_start..j)?;
    let mut items = Vec::new();
    let mut k = 0usize;
    while let Some(&lo) = body.get(k) {
        // `lo-hi`, unless the `-` is the last character of the set.
        if body.get(k.saturating_add(1)) == Some(&'-')
            && let Some(&hi) = body.get(k.saturating_add(2))
        {
            items.push(ClassItem::Range(lo, hi));
            k = k.saturating_add(3);
            continue;
        }
        items.push(ClassItem::Char(lo));
        k = k.saturating_add(1);
    }
    Some((Token::Class { negated, items }, j.saturating_add(1)))
}

fn token_matches_one(token: &Token, c: char) -> bool {
    match token {
        Token::Literal(x) => *x == c,
        Token::AnyOne => true,
        Token::Class { negated, items } => items.iter().any(|item| item.contains(c)) != *negated,
        Token::Star => false,
    }
}

/// Classic wildcard matching: advance greedily, and on a mismatch go back to
/// the most recent star and let it eat one more character. Only the last
/// star ever needs revisiting, so this is O(|tokens| * |text|).
fn match_tokens(tokens: &[Token], text: &[char]) -> bool {
    let (mut t, mut s) = (0usize, 0usize);
    let mut backtrack: Option<(usize, usize)> = None; // (token after star, text pos)
    loop {
        match (tokens.get(t), text.get(s)) {
            (Some(Token::Star), _) => {
                t = t.saturating_add(1);
                backtrack = Some((t, s));
            }
            (Some(token), Some(&c)) if token_matches_one(token, c) => {
                t = t.saturating_add(1);
                s = s.saturating_add(1);
            }
            (None, None) => return true,
            _ => match backtrack {
                Some((bt, bs)) if bs < text.len() => {
                    let bs = bs.saturating_add(1);
                    backtrack = Some((bt, bs));
                    t = bt;
                    s = bs;
                }
                _ => return false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Obviously-correct exponential reference.
    fn reference(tokens: &[Token], text: &[char]) -> bool {
        match tokens.split_first() {
            None => text.is_empty(),
            Some((Token::Star, rest)) => (0..=text.len()).any(|n| reference(rest, &text[n..])),
            Some((token, rest)) => match text.split_first() {
                Some((&c, more)) => token_matches_one(token, c) && reference(rest, more),
                None => false,
            },
        }
    }

    #[test]
    fn basics() {
        assert!(fnmatch("org/repo", "org/*"));
        assert!(fnmatch("org/a/b", "org/*"));
        assert!(!fnmatch("other/repo", "org/*"));
        assert!(fnmatch("anything", "*"));
        assert!(fnmatch("", "*"));
        assert!(!fnmatch("", "?"));
        assert!(fnmatch("a\nb", "a*b"));
        assert!(fnmatch("Kube", "Kube"));
        assert!(!fnmatch("kube", "Kube"));
        assert!(fnmatch("x", "[xyz]"));
        assert!(!fnmatch("x", "[!xyz]"));
        assert!(fnmatch("m", "[a-z]"));
        assert!(!fnmatch("M", "[a-z]"));
        assert!(fnmatch("-", "[a-]"));
        assert!(fnmatch("-", "[-a]"));
        assert!(fnmatch("]", "[]]"));
        assert!(fnmatch("]", "[]a]"));
        assert!(!fnmatch("]", "[!]a]"));
        assert!(fnmatch("[", "["));
        assert!(fnmatch("[ab", "[ab"));
        assert!(fnmatch("\\", "\\"));
        assert!(!fnmatch("m", "[z-a]"));
        assert!(fnmatch("kube-system", "kube-*"));
        assert!(fnmatch("é", "?"));
    }

    #[test]
    fn literal_detection() {
        assert!(Glob::new("org/repo").is_literal());
        assert!(!Glob::new("org/*").is_literal());
        assert!(!Glob::new("a?").is_literal());
        assert!(!Glob::new("[ab]").is_literal());
        assert!(Glob::new("[").is_literal());
        assert_eq!(Glob::new("a[*]b").literal_text().as_deref(), Some("a*b"));
        assert_eq!(Glob::new("a[*b]").literal_text(), None);
        assert_eq!(Glob::new("a*").literal_text(), None);
        assert_eq!(Glob::new("[!a]").literal_text(), None);
    }

    /// Differential test against CPython's `fnmatch.fnmatchcase` on a
    /// generated corpus of ordinary patterns (stars, `?`, sets with `!`,
    /// `]`, ranges and `-` in every position, backslashes, `^`). Needs
    /// `python3` on PATH (the dev shell has it); without it the test says
    /// so and passes.
    #[test]
    fn agrees_with_cpython() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        // A small LCG: deterministic, no dependency.
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |n: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap() % n
        };
        let pattern_chars: Vec<char> = "ab-]![*?^\\cz".chars().collect();
        let text_chars: Vec<char> = "ab-]![\\^cz*?".chars().collect();
        let mut corpus = Vec::new();
        for _ in 0..30_000 {
            let plen = next(9);
            let pattern: String = (0..plen)
                .map(|_| pattern_chars[next(pattern_chars.len())])
                .collect();
            let tlen = next(7);
            let text: String = (0..tlen)
                .map(|_| text_chars[next(text_chars.len())])
                .collect();
            corpus.push((pattern, text));
        }
        let script = "import sys, json, fnmatch\n\
                      out = []\n\
                      for line in sys.stdin:\n    p, t = json.loads(line)\n    out.append('1' if fnmatch.fnmatchcase(t, p) else '0')\n\
                      sys.stdout.write(''.join(out))\n";
        let child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("python3 not found: skipping the CPython differential test");
            return;
        };
        let mut input = String::new();
        for (p, t) in &corpus {
            input.push_str(&serde_json::to_string(&(p, t)).unwrap());
            input.push('\n');
        }
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let answers = String::from_utf8(output.stdout).unwrap();
        assert_eq!(answers.len(), corpus.len());
        // A reversed range (`[z-a]`) is the one deliberate difference
        // (DEVIATIONS.md): CPython merges it with its neighbours, which can
        // even turn `[z-?!]` into "any character".
        let reversed = |p: &str| {
            Glob::new(p).tokens.iter().any(|t| match t {
                Token::Class { items, .. } => items
                    .iter()
                    .any(|i| matches!(i, ClassItem::Range(lo, hi) if lo > hi)),
                _ => false,
            })
        };
        let mut mismatches = Vec::new();
        let mut compared = 0usize;
        for ((p, t), python) in corpus.iter().zip(answers.chars()) {
            if reversed(p) {
                continue;
            }
            compared = compared.saturating_add(1);
            if fnmatch(t, p) != (python == '1') {
                mismatches.push(format!("pattern {p:?} text {t:?}: python {python}"));
            }
        }
        assert!(compared > 25_000, "{compared}");
        assert!(
            mismatches.is_empty(),
            "{} mismatches, e.g. {:?}",
            mismatches.len(),
            &mismatches[..mismatches.len().min(10)]
        );
    }

    #[test]
    fn pathological_is_fast() {
        let text = "a".repeat(5000);
        let pattern = format!("{}b", "*a".repeat(200));
        assert!(!fnmatch(&text, &pattern));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]
        #[test]
        fn agrees_with_reference(pattern in "[ab*?\\[\\]!-]{0,10}", text in "[ab\\]!-]{0,10}") {
            let glob = Glob::new(&pattern);
            let chars: Vec<char> = text.chars().collect();
            prop_assert_eq!(glob.matches(&text), reference(&glob.tokens, &chars));
        }

        /// `matches_every_nonempty_over` against brute force over every
        /// string of length 1..=5 on a 3-letter alphabet. (A pattern that
        /// matches all of those but not some longer string would need more
        /// than 5 single-character tokens without a star, which the brute
        /// force sees fail at length 1 anyway.)
        #[test]
        fn matches_every_agrees_with_brute_force(pattern in "[ab*?\\[\\]!-]{0,8}") {
            let alphabet = ['a', 'b', '-'];
            let glob = Glob::new(&pattern);
            let mut all = true;
            let mut words: Vec<String> = vec![String::new()];
            for _ in 0..5 {
                words = words
                    .iter()
                    .flat_map(|w| alphabet.iter().map(move |c| format!("{w}{c}")))
                    .collect();
                if !words.iter().all(|w| glob.matches(w)) {
                    all = false;
                }
            }
            prop_assert_eq!(glob.matches_every_nonempty_over(&alphabet), all, "{}", pattern);
        }

        /// `escape(s)` matches `s` and nothing else, and is a literal.
        #[test]
        fn escape_matches_exactly_itself(s in "[a*?\\[\\]!^\\\\-]{0,10}", t in "[a*?\\[\\]!^\\\\-]{0,10}") {
            let g = Glob::new(&escape(&s));
            prop_assert!(g.matches(&s));
            prop_assert_eq!(g.matches(&t), s == t);
            prop_assert_eq!(g.literal_text(), Some(s.clone()));
        }

        #[test]
        fn escape_any_text(s in ".{0,20}") {
            prop_assert!(fnmatch(&s, &escape(&s)));
            let longer = format!("{s}x");
            prop_assert!(!fnmatch(&longer, &escape(&s)));
        }

        #[test]
        fn star_matches_all(text in ".{0,40}") {
            prop_assert!(fnmatch(&text, "*"));
        }

        #[test]
        fn literal_matches_only_itself(a in "[a-z/._-]{0,12}", b in "[a-z/._-]{0,12}") {
            prop_assert_eq!(fnmatch(&a, &b), a == b);
        }
    }
}
