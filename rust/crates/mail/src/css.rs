//! Just enough CSS to tell text styled away from a reader (review #4
//! item 7): comments removed and escapes decoded before anything is
//! matched, inline declarations read one by one, and `<style>` rules
//! whose declarations hide mapped to the classes and ids they name.
//!
//! What counts as hiding errs towards hiding (hidden text never reaches
//! an agent as if a person saw it; it is still scanned for injection
//! hints): `display:none`, `visibility:hidden|collapse`, `mso-hide:all`,
//! near-zero opacity, font sizes under 2 px, zero heights, zero widths
//! with overflow hidden, transparent colours, `scale(0)`, empty clips and
//! far off-screen positions.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

/// The most stylesheet text read for class rules.
pub const MAX_STYLESHEET: usize = 1 << 20;

/// Comments out, escapes decoded, lowercased.
#[must_use]
pub fn normalize(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for d in chars.by_ref() {
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
                // A comment separates like whitespace would not: nothing.
            }
            '\\' => {
                let mut hex = String::new();
                while hex.len() < 6 && chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    hex.extend(chars.next());
                }
                if hex.is_empty() {
                    // `\` + a character is that character (`\\n` aside).
                    if let Some(next) = chars.next()
                        && next != '\n'
                    {
                        out.extend(next.to_lowercase());
                    }
                } else {
                    if chars.peek().is_some_and(|c| c.is_whitespace()) {
                        chars.next();
                    }
                    let c = u32::from_str_radix(&hex, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .filter(|c| *c != '\0')
                        .unwrap_or('\u{fffd}');
                    out.extend(c.to_lowercase());
                }
            }
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// `prop: value` pairs of a (normalized) declaration block, `!important`
/// dropped, whitespace collapsed.
#[must_use]
pub fn declarations(block: &str) -> Vec<(String, String)> {
    block
        .split(';')
        .filter_map(|d| {
            let (p, v) = d.split_once(':')?;
            let v = v.replace("!important", "");
            let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
            Some((p.trim().to_owned(), v))
        })
        .collect()
}

/// A CSS length in (approximate) pixels; None when it is not one.
fn px(value: &str) -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^([+-]?(?:\d+\.?\d*|\.\d+))([a-z%]*)$")
            .unwrap_or_else(|_| crate::html::never())
    });
    let c = re.captures(value.trim())?;
    let n: f64 = c.get(1)?.as_str().parse().ok()?;
    let factor = match c.get(2).map_or("", |m| m.as_str()) {
        "" | "px" => 1.0,
        "pt" => 4.0 / 3.0,
        "pc" => 16.0,
        "em" | "rem" => 16.0,
        "%" => 0.16,
        "ex" | "ch" => 8.0,
        "vw" | "vh" | "vmin" | "vmax" => 10.0,
        "cm" => 37.8,
        "mm" => 3.78,
        "q" => 0.945,
        "in" => 96.0,
        _ => return None,
    };
    Some(n * factor)
}

fn zero(value: &str) -> bool {
    px(value).is_some_and(|v| v.abs() < 0.5)
}

/// An alpha-0 or transparent colour.
fn transparent(value: &str) -> bool {
    if value.trim() == "transparent" {
        return true;
    }
    let Some(args) = value
        .trim()
        .strip_prefix("rgba(")
        .or_else(|| value.trim().strip_prefix("hsla("))
        .or_else(|| value.trim().strip_prefix("rgb("))
        .or_else(|| value.trim().strip_prefix("hsl("))
        .and_then(|r| r.strip_suffix(')'))
    else {
        return false;
    };
    let alpha = match args.split_once('/') {
        Some((_, a)) => Some(a),
        None => {
            let parts: Vec<&str> = args.split(',').collect();
            if parts.len() == 4 {
                parts.last().copied()
            } else {
                None
            }
        }
    };
    alpha.is_some_and(|a| {
        let a = a.trim();
        match a.strip_suffix('%') {
            Some(p) => p.trim().parse::<f64>().is_ok_and(|p| p <= 5.0),
            None => a.parse::<f64>().is_ok_and(|v| v <= 0.05),
        }
    })
}

/// Do these declarations hide the element's text from a reader?
#[must_use]
pub fn hides(decls: &[(String, String)]) -> bool {
    let get = |p: &str| {
        decls
            .iter()
            .rev()
            .find(|(k, _)| k == p)
            .map(|(_, v)| v.as_str())
    };
    let clips = ["overflow", "overflow-x", "overflow-y"]
        .iter()
        .any(|p| get(p).is_some_and(|v| v == "hidden" || v == "clip"));
    let positioned = get("position").is_some_and(|v| v == "absolute" || v == "fixed");
    decls.iter().any(|(p, v)| {
        let v = v.as_str();
        match p.as_str() {
            "display" => v == "none",
            "visibility" => v == "hidden" || v == "collapse",
            "mso-hide" => v == "all",
            "opacity" => match v.strip_suffix('%') {
                Some(pct) => pct.trim().parse::<f64>().is_ok_and(|n| n <= 5.0),
                None => v.parse::<f64>().is_ok_and(|n| n <= 0.05),
            },
            "font-size" => px(v).is_some_and(|n| n < 2.0),
            "height" | "max-height" => zero(v),
            "width" | "max-width" => zero(v) && clips,
            "color" => transparent(v),
            "transform" => {
                v.contains("scale(0)") || v.contains("scale(0,") || v.contains("scale(0 ")
            }
            "clip" => v.replace([',', ' '], "") == "rect(0000)",
            "clip-path" => v.starts_with("inset(50%") || v.contains("circle(0"),
            "left" | "top" | "right" => positioned && px(v).is_some_and(|n| n <= -500.0),
            "text-indent" => px(v).is_some_and(|n| n <= -500.0),
            _ => false,
        }
    })
}

/// Does an inline `style` attribute hide its element's text?
#[must_use]
pub fn style_hides(style: &str) -> bool {
    hides(&declarations(&normalize(style)))
}

/// The classes and ids named by `<style>` rules whose declarations hide
/// (any `.class` or `#id` in the selector counts: an over-approximation,
/// on the hiding side).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HidingRules {
    pub classes: BTreeSet<String>,
    pub ids: BTreeSet<String>,
}

impl HidingRules {
    #[must_use]
    pub fn from_stylesheet(css: &str) -> HidingRules {
        static RULE: OnceLock<Regex> = OnceLock::new();
        static NAME: OnceLock<Regex> = OnceLock::new();
        let rule = RULE.get_or_init(|| {
            Regex::new(r"([^{}]*)\{([^{}]*)\}").unwrap_or_else(|_| crate::html::never())
        });
        let name = NAME.get_or_init(|| {
            Regex::new(r"([.#])(-?[_a-z\u{80}-\u{10ffff}][_a-z0-9\u{80}-\u{10ffff}-]*)")
                .unwrap_or_else(|_| crate::html::never())
        });
        let css = normalize(css.get(..MAX_STYLESHEET.min(css.len())).unwrap_or(css));
        let mut out = HidingRules::default();
        for c in rule.captures_iter(&css) {
            let (Some(sel), Some(body)) = (c.get(1), c.get(2)) else {
                continue;
            };
            if !hides(&declarations(body.as_str())) {
                continue;
            }
            for n in name.captures_iter(sel.as_str()) {
                if out.classes.len().saturating_add(out.ids.len()) >= 10_000 {
                    return out;
                }
                let (Some(kind), Some(id)) = (n.get(1), n.get(2)) else {
                    continue;
                };
                if kind.as_str() == "." {
                    out.classes.insert(id.as_str().to_owned());
                } else {
                    out.ids.insert(id.as_str().to_owned());
                }
            }
        }
        out
    }

    /// Does an element with these `class` and `id` attributes match?
    #[must_use]
    pub fn matches(&self, class: Option<&str>, id: Option<&str>) -> bool {
        class.is_some_and(|c| {
            c.split_whitespace()
                .any(|c| self.classes.contains(&c.to_lowercase()))
        }) || id.is_some_and(|i| self.ids.contains(&i.trim().to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizing() {
        assert_eq!(normalize(r"Display:\6e one"), "display:none");
        assert_eq!(normalize("display:/**/none"), "display:none");
        assert_eq!(normalize(r"di\splay:none"), "display:none");
    }

    #[test]
    fn rules() {
        let r = HidingRules::from_stylesheet(
            "@media screen { .x, div #y { display: none } } .shown{color:red} .tiny{font-size:1px}",
        );
        assert!(r.matches(Some("a X"), None));
        assert!(r.matches(None, Some("y")));
        assert!(r.matches(Some("tiny"), None));
        assert!(!r.matches(Some("shown"), None));
    }
}
