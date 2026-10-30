//! `/rules`: an ephemeral browser over the saved rules (spec A.7). Pure
//! rendering; the interaction handler loads the rules and applies
//! toggles and deletes.
//!
//! The Python's view lived 600 s in memory; here every component carries
//! its page (and rule) in its custom id, so the browser is stateless and
//! each click redraws from the database after the owner check.

use agent_auth_core::RuleId;
use agent_auth_core::durations::format_duration;
use agent_auth_store::rules::{RuleAction, RuleRow};
use twilight_model::channel::message::component::ButtonStyle;
use twilight_model::channel::message::{Component, Embed};

use super::model::{
    COLOR_APPROVED, COLOR_DENIED, COLOR_ENDED, COLOR_LIST, Message, add_field, button, embed, row,
    select_option, set_footer, string_select, timestamp,
};
use super::text::{cut, escape, said};
use super::views::CustomId;

/// Discord's select limit, and so the page size.
pub const PAGE_SIZE: usize = 25;

fn emoji(a: RuleAction) -> &'static str {
    match a {
        RuleAction::AutoApprove => "✅",
        RuleAction::AutoDeny => "⛔",
    }
}

fn action_label(a: RuleAction) -> &'static str {
    match a {
        RuleAction::AutoApprove => "auto-approve",
        RuleAction::AutoDeny => "auto-deny",
    }
}

/// `*` for a rule over any privilege, else the authority's label (made
/// from a parsed authority: the broker's own vocabulary, not escaped).
#[must_use]
pub fn privilege(rule: &RuleRow) -> String {
    rule.authority
        .as_ref()
        .map_or_else(|| "*".to_owned(), agent_auth_core::Authority::label)
}

fn short(id: RuleId) -> String {
    cut(&id.to_string(), 8)
}

#[must_use]
pub fn rule_summary(rule: &RuleRow) -> String {
    let mut line = format!(
        "{} `{}` **{}** → {}/{} on `{}`",
        emoji(rule.action),
        short(rule.id),
        escape(&rule.agent_pattern),
        rule.platform.as_str(),
        privilege(rule),
        super::text::code(&rule.resource_pattern)
    );
    if !rule.enabled {
        line.push_str(" *(disabled)*");
    }
    line
}

/// One page of rules, clamped (deletes can strand a page index).
#[derive(Debug, Clone)]
pub struct Page {
    pub rules: Vec<RuleRow>,
    pub page: usize,
    pub pages: usize,
    pub total: usize,
}

/// Page `page` of `all` (newest first, as the store lists them).
#[must_use]
pub fn paginate(all: Vec<RuleRow>, page: i64) -> Page {
    let total = all.len();
    let pages = total.div_ceil(PAGE_SIZE).max(1);
    let last = i64::try_from(pages.saturating_sub(1)).unwrap_or(0);
    let page = usize::try_from(page.clamp(0, last)).unwrap_or(0);
    let rules = all
        .into_iter()
        .skip(page.saturating_mul(PAGE_SIZE))
        .take(PAGE_SIZE)
        .collect();
    Page {
        rules,
        page,
        pages,
        total,
    }
}

#[must_use]
pub fn rules_embed(p: &Page) -> Embed {
    let mut e = embed();
    e.title = Some("🧾 Decision rules".to_owned());
    e.color = Some(COLOR_LIST);
    if p.rules.is_empty() {
        e.description =
            Some("No rules yet. Create one from a request's **Edit** dialogue.".to_owned());
        return e;
    }
    let lines: Vec<String> = p.rules.iter().map(rule_summary).collect();
    e.description = Some(lines.join("\n"));
    if p.pages > 1 {
        set_footer(
            &mut e,
            format!(
                "Page {}/{} · {} rules, newest first",
                p.page.saturating_add(1),
                p.pages,
                p.total
            ),
        );
    }
    e
}

#[must_use]
pub fn rule_detail_embed(rule: &RuleRow) -> Embed {
    let color = if !rule.enabled {
        COLOR_ENDED
    } else if rule.action == RuleAction::AutoApprove {
        COLOR_APPROVED
    } else {
        COLOR_DENIED
    };
    let mut e = embed();
    e.title = Some(format!(
        "{} Rule {} — {}",
        emoji(rule.action),
        short(rule.id),
        action_label(rule.action)
    ));
    e.color = Some(color);
    add_field(&mut e, "Agent", said(&rule.agent_pattern, 1000), true);
    if let Some(d) = &rule.delegator_pattern {
        add_field(&mut e, "🤝 Delegator", said(d, 1000), true);
    }
    add_field(&mut e, "Platform", rule.platform.as_str(), true);
    add_field(
        &mut e,
        "Privilege",
        super::text::trim(&privilege(rule), 1000),
        true,
    );
    add_field(&mut e, "Resource", said(&rule.resource_pattern, 1000), true);
    add_field(
        &mut e,
        "Max duration",
        rule.max_duration_secs
            .filter(|d| *d > 0)
            .map_or_else(|| "—".to_owned(), |d| format_duration(u64::from(d))),
        true,
    );
    add_field(
        &mut e,
        "Enabled",
        if rule.enabled { "yes" } else { "no" },
        true,
    );
    if !rule.created_by.is_empty() {
        add_field(&mut e, "Created by", said(&rule.created_by, 1000), true);
    }
    if !rule.notes.is_empty() {
        add_field(&mut e, "Notes", said(&rule.notes, 1000), false);
    }
    set_footer(&mut e, format!("rule {}", rule.id));
    e.timestamp = timestamp(rule.created_at);
    e
}

/// The browser's components: the select (if any rules), page buttons (if
/// more than one page), and Disable/Enable + Delete for a selection.
#[must_use]
pub fn rules_view(p: &Page, selected: Option<&RuleRow>) -> Vec<Component> {
    let page = i64::try_from(p.page).unwrap_or(0);
    let pages = i64::try_from(p.pages).unwrap_or(1);
    let mut rows = Vec::new();
    if !p.rules.is_empty() {
        let options = p
            .rules
            .iter()
            .map(|r| {
                select_option(
                    cut(
                        &format!(
                            "{} · {}/{}",
                            r.agent_pattern,
                            r.platform.as_str(),
                            privilege(r)
                        ),
                        100,
                    ),
                    Some(cut(&format!("on {}", r.resource_pattern), 100)),
                    emoji(r.action),
                    r.id.to_string(),
                    selected.is_some_and(|s| s.id == r.id),
                )
            })
            .collect();
        rows.push(row(vec![string_select(
            CustomId::RulesSelect { page }.render(),
            "Select a rule to manage…",
            options,
        )]));
    }
    if p.pages > 1 {
        let nav = |label: &str, target: i64| {
            button(
                label,
                ButtonStyle::Primary,
                CustomId::RulesPage { target }.render(),
                !(0..pages).contains(&target),
            )
        };
        rows.push(row(vec![
            nav("◀ Prev", page.saturating_sub(1)),
            nav("Next ▶", page.saturating_add(1)),
        ]));
    }
    if let Some(s) = selected {
        let (label, style) = if s.enabled {
            ("Disable", ButtonStyle::Secondary)
        } else {
            ("Enable", ButtonStyle::Success)
        };
        rows.push(row(vec![
            button(
                label,
                style,
                CustomId::RulesToggle { page, rule: s.id }.render(),
                false,
            ),
            button(
                "Delete",
                ButtonStyle::Danger,
                CustomId::RulesDelete { page, rule: s.id }.render(),
                false,
            ),
        ]));
    }
    rows
}

/// The whole browser as a message (embeds and components).
#[must_use]
pub fn render(p: &Page, selected: Option<RuleId>) -> Message {
    let selected = selected.and_then(|id| p.rules.iter().find(|r| r.id == id));
    let mut embeds = vec![rules_embed(p)];
    if let Some(s) = selected {
        embeds.push(rule_detail_embed(s));
    }
    Message {
        embeds: Some(embeds),
        components: Some(rules_view(p, selected)),
        allowed_mentions: Some(super::model::mentions(None)),
        ..Message::default()
    }
}
