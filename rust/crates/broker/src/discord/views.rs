//! Buttons and modals (spec A.6): custom ids, the views posted with a
//! card, the modals they open, and reading a submitted modal into a
//! [`HumanDecision`]. Pure: no I/O.
//!
//! Every component is stateless: what it acts on is in its `custom_id`
//! (a request id, a rule id and a page), so buttons keep working after a
//! restart. A custom id is parsed strictly (the request id must be a
//! canonical UUID), and nothing else in the interaction says what to act
//! on (INV-A3).

use agent_auth_core::canonical_json::to_python_default_string;
use agent_auth_core::durations::{DurationSecs, format_duration};
use agent_auth_core::names::DaemonName;
use agent_auth_core::{RequestId, RuleId};
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleAction;
use agent_auth_wire::admin::LockdownScope;
use serde_json::{Map, Value};
use twilight_model::channel::message::Component;
use twilight_model::channel::message::component::ButtonStyle;
use uuid::Uuid;

use super::embeds::{capability, scope};
use super::model::{Input, Modal, button, row};
use super::ops::HumanDecision;
use super::text::cut;
use crate::models::{self, Kind};

/// What a component or modal custom id names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomId {
    Approve(RequestId),
    Deny(RequestId),
    Edit(RequestId),
    /// hostexec: approve with a TOTP code.
    Totp(RequestId),
    /// hostexec: end an active shell.
    EndShell(RequestId),
    /// hostexec: "Approve all…", a time-boxed window rule.
    ApproveAll(RequestId),
    /// hostexec: stop the frozen agent VMs after a lockdown. The host is
    /// a daemon name (≤ 63 characters), so the id stays ≤ 100.
    KillVms {
        scope: LockdownScope,
        host: Option<String>,
    },
    /// Modal: the approve/deny decision (reason, duration).
    DecisionModal {
        approve: bool,
        request: RequestId,
    },
    EditModal(RequestId),
    TotpModal(RequestId),
    WindowModal(RequestId),
    /// Rules browser: the select (value = rule id), on `page`.
    RulesSelect {
        page: i64,
    },
    RulesPage {
        target: i64,
    },
    RulesToggle {
        page: i64,
        rule: RuleId,
    },
    RulesDelete {
        page: i64,
        rule: RuleId,
    },
    /// Held mail: let it through (send it, for outbound).
    MailRelease(agent_auth_core::MailItemId),
    /// Held mail: keep it back.
    MailDiscard(agent_auth_core::MailItemId),
    /// A model's decision was wrong: ask what it should have been.
    WrongCall(Uuid),
    /// Modal: what the decision should have been, and why.
    WrongCallModal(Uuid),
    /// Take back a label given from Discord.
    Unlabel(Uuid),
}

impl CustomId {
    /// Parse a custom id; anything not exactly one of ours is `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<CustomId> {
        let rid = |r: &str| r.parse::<RequestId>().ok();
        // Canonical (hyphenated, lowercase) only, like a request id.
        let call = |c: &str| {
            Uuid::parse_str(c)
                .ok()
                .filter(|u| u.hyphenated().to_string() == c)
        };
        let page = |p: &str| p.parse::<i64>().ok().filter(|n| n.to_string() == p);
        let mut parts = s.split(':');
        if parts.next()? != "aa" {
            return None;
        }
        let kind = parts.next()?;
        let rest: Vec<&str> = parts.collect();
        let id = match (kind, rest.as_slice()) {
            ("approve", [r]) => CustomId::Approve(rid(r)?),
            ("deny", [r]) => CustomId::Deny(rid(r)?),
            ("edit", [r]) => CustomId::Edit(rid(r)?),
            ("hxtotp", [r]) => CustomId::Totp(rid(r)?),
            ("hxend", [r]) => CustomId::EndShell(rid(r)?),
            ("hxall", [r]) => CustomId::ApproveAll(rid(r)?),
            ("hxallm", [r]) => CustomId::WindowModal(rid(r)?),
            ("hxkill", [scope, host]) => CustomId::KillVms {
                scope: scope_of(scope)?,
                host: if host.is_empty() {
                    None
                } else {
                    Some(DaemonName::parse(host).ok()?.as_str().to_owned())
                },
            },
            ("decision", ["approve", r]) => CustomId::DecisionModal {
                approve: true,
                request: rid(r)?,
            },
            ("decision", ["deny", r]) => CustomId::DecisionModal {
                approve: false,
                request: rid(r)?,
            },
            ("editmodal", [r]) => CustomId::EditModal(rid(r)?),
            ("hxtotpm", [r]) => CustomId::TotpModal(rid(r)?),
            ("rules", ["sel", p]) => CustomId::RulesSelect { page: page(p)? },
            ("rules", ["page", p]) => CustomId::RulesPage { target: page(p)? },
            ("rules", ["toggle", p, r]) => CustomId::RulesToggle {
                page: page(p)?,
                rule: r.parse().ok()?,
            },
            ("rules", ["del", p, r]) => CustomId::RulesDelete {
                page: page(p)?,
                rule: r.parse().ok()?,
            },
            ("mlrel", [m]) => CustomId::MailRelease(m.parse().ok()?),
            ("mldis", [m]) => CustomId::MailDiscard(m.parse().ok()?),
            ("mcw", [c]) => CustomId::WrongCall(call(c)?),
            ("mcwm", [c]) => CustomId::WrongCallModal(call(c)?),
            ("mcu", [c]) => CustomId::Unlabel(call(c)?),
            _ => return None,
        };
        Some(id)
    }

    /// The custom id text (≤ 100 characters for every variant).
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            CustomId::Approve(r) => format!("aa:approve:{r}"),
            CustomId::Deny(r) => format!("aa:deny:{r}"),
            CustomId::Edit(r) => format!("aa:edit:{r}"),
            CustomId::Totp(r) => format!("aa:hxtotp:{r}"),
            CustomId::EndShell(r) => format!("aa:hxend:{r}"),
            CustomId::ApproveAll(r) => format!("aa:hxall:{r}"),
            CustomId::WindowModal(r) => format!("aa:hxallm:{r}"),
            CustomId::KillVms { scope, host } => format!(
                "aa:hxkill:{}:{}",
                scope_word(*scope),
                host.as_deref().unwrap_or("")
            ),
            CustomId::DecisionModal { approve, request } => format!(
                "aa:decision:{}:{request}",
                if *approve { "approve" } else { "deny" }
            ),
            CustomId::EditModal(r) => format!("aa:editmodal:{r}"),
            CustomId::TotpModal(r) => format!("aa:hxtotpm:{r}"),
            CustomId::RulesSelect { page } => format!("aa:rules:sel:{page}"),
            CustomId::RulesPage { target } => format!("aa:rules:page:{target}"),
            CustomId::RulesToggle { page, rule } => format!("aa:rules:toggle:{page}:{rule}"),
            CustomId::RulesDelete { page, rule } => format!("aa:rules:del:{page}:{rule}"),
            CustomId::MailRelease(m) => format!("aa:mlrel:{m}"),
            CustomId::MailDiscard(m) => format!("aa:mldis:{m}"),
            CustomId::WrongCall(c) => format!("aa:mcw:{c}"),
            CustomId::WrongCallModal(c) => format!("aa:mcwm:{c}"),
            CustomId::Unlabel(c) => format!("aa:mcu:{c}"),
        }
    }
}

/// The lockdown scope's word (`sandboxes`, `all`, `host`).
#[must_use]
pub fn scope_word(scope: LockdownScope) -> &'static str {
    match scope {
        LockdownScope::Sandboxes => "sandboxes",
        LockdownScope::All => "all",
        LockdownScope::Host => "host",
    }
}

#[must_use]
pub fn scope_of(word: &str) -> Option<LockdownScope> {
    match word {
        "sandboxes" => Some(LockdownScope::Sandboxes),
        "all" => Some(LockdownScope::All),
        "host" => Some(LockdownScope::Host),
        _ => None,
    }
}

fn live(label: &str, style: ButtonStyle, id: CustomId) -> Component {
    button(label, style, id.render(), false)
}

/// `pending_view`: Approve, Deny, Edit.
#[must_use]
pub fn pending_view(rid: RequestId) -> Vec<Component> {
    vec![row(vec![
        live("Approve", ButtonStyle::Success, CustomId::Approve(rid)),
        live("Deny", ButtonStyle::Danger, CustomId::Deny(rid)),
        live("Edit", ButtonStyle::Secondary, CustomId::Edit(rid)),
    ])]
}

/// hostexec's pending view: a shell gets Approve with TOTP and Deny only
/// (INV-A7); a run or template gets Approve, Approve with TOTP, Deny,
/// Edit. ("Approve all…", the window rule, is not ported yet.)
#[must_use]
pub fn hostexec_pending_view(request: &RequestRow) -> Vec<Component> {
    let rid = request.id;
    let totp = live(
        "Approve with TOTP",
        ButtonStyle::Primary,
        CustomId::Totp(rid),
    );
    let deny = live("Deny", ButtonStyle::Danger, CustomId::Deny(rid));
    if capability(request) == "shell" {
        return vec![row(vec![totp, deny])];
    }
    vec![row(vec![
        live("Approve", ButtonStyle::Success, CustomId::Approve(rid)),
        live(
            "Approve all…",
            ButtonStyle::Secondary,
            CustomId::ApproveAll(rid),
        ),
        totp,
        deny,
        live("Edit", ButtonStyle::Secondary, CustomId::Edit(rid)),
    ])]
}

/// The lockdown message's "Kill VMs" button (none when the VMs were
/// stopped already).
#[must_use]
pub fn kill_vm_view(scope: LockdownScope, host: Option<&str>, disabled: bool) -> Vec<Component> {
    let id = CustomId::KillVms {
        scope,
        host: host.map(str::to_owned),
    };
    vec![row(vec![button(
        "Kill VMs",
        ButtonStyle::Danger,
        id.render(),
        disabled,
    )])]
}

/// hostexec's `WindowModal`: how long to approve every command of this
/// tier, from this agent, on this host.
#[must_use]
pub fn window_modal(request: &RequestRow, default: &str) -> Modal {
    let tier = scope(request)
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Modal {
        custom_id: CustomId::WindowModal(request.id).render(),
        title: "Approve all for a while".to_owned(),
        inputs: vec![Input {
            value: Some(default.to_owned()),
            max_length: Some(16),
            ..Input::new(
                DURATION,
                &cut(&format!("{tier} commands on {}, for", request.resource), 45),
            )
        }],
    }
}

/// The window modal's answer: the duration, at most `max`.
pub fn read_window(form: &Submitted, max: DurationSecs) -> Result<DurationSecs, Refusal> {
    let d = duration(form.get(DURATION))?;
    if d > max {
        return Err(Refusal(format!(
            "A window lasts at most {}.",
            format_duration(u64::from(max.get()))
        )));
    }
    Ok(d)
}

/// `disabled_view`: the three buttons, greyed out. They keep their custom
/// ids: Discord refuses a button without one, disabled or not (code 50035,
/// `BUTTON_COMPONENT_CUSTOM_ID_REQUIRED`), and with it the whole edit.
#[must_use]
pub fn disabled_view(rid: RequestId) -> Vec<Component> {
    let off = |label, style, id: CustomId| button(label, style, id.render(), true);
    vec![row(vec![
        off("Approve", ButtonStyle::Success, CustomId::Approve(rid)),
        off("Deny", ButtonStyle::Danger, CustomId::Deny(rid)),
        off("Edit", ButtonStyle::Secondary, CustomId::Edit(rid)),
    ])]
}

/// `shell_view`: End shell.
#[must_use]
pub fn shell_view(rid: RequestId) -> Vec<Component> {
    vec![row(vec![live(
        "End shell",
        ButtonStyle::Danger,
        CustomId::EndShell(rid),
    )])]
}

/// The button on a message that reports a model's decision: say it was
/// wrong (an eval label, `crate::models`).
#[must_use]
pub fn wrong_call_button(call: Uuid) -> Component {
    live(
        "Wrong call",
        ButtonStyle::Secondary,
        CustomId::WrongCall(call),
    )
}

/// `wrong_call_button` alone in a row.
#[must_use]
pub fn wrong_call_view(call: Uuid) -> Vec<Component> {
    vec![row(vec![wrong_call_button(call)])]
}

/// After labelling from Discord: take it back.
#[must_use]
pub fn unlabel_view(call: Uuid) -> Vec<Component> {
    vec![row(vec![live(
        "Undo",
        ButtonStyle::Secondary,
        CustomId::Unlabel(call),
    )])]
}

// ----------------------------------------------------------------- modals

const REASON: &str = "reason";
const DURATION: &str = "duration";
const RESOURCE: &str = "resource";
const SCOPE: &str = "scope";
const RULE: &str = "rule";
const NOTES: &str = "notes";
const CODE: &str = "code";
const EXPECTED: &str = "expected";
const NOTE: &str = "note";

/// Longest resource / scope text the Edit modal can hold.
pub const EDIT_RESOURCE_MAX: usize = 512;
pub const EDIT_SCOPE_MAX: usize = 4000;

fn reason_input() -> Input {
    Input {
        paragraph: true,
        required: false,
        max_length: Some(500),
        ..Input::new(REASON, "Reason (optional)")
    }
}

/// `DecisionModal`: title, custom id, Reason (and Duration to approve).
#[must_use]
pub fn decision_modal(rid: RequestId, approve: bool) -> Modal {
    let mut inputs = vec![reason_input()];
    if approve {
        inputs.push(Input {
            required: false,
            placeholder: Some("e.g. 4h, 30m, 2d".to_owned()),
            max_length: Some(16),
            ..Input::new(DURATION, "Duration (blank = requested, capped)")
        });
    }
    Modal {
        custom_id: CustomId::DecisionModal {
            approve,
            request: rid,
        }
        .render(),
        title: if approve {
            "Approve request"
        } else {
            "Deny request"
        }
        .to_owned(),
        inputs,
    }
}

/// Why the Edit modal is not offered (Bug-A2: a prefill cut to fit the
/// modal would approve something other than what was asked).
pub const EDIT_TOO_LONG: &str = "This request is too long to edit here (resource over 512 or scope over 4000 characters): approve or deny it as it is.";

/// `EditModal`: exactly 5 inputs. `None` when the resource or scope does
/// not fit the modal whole.
#[must_use]
pub fn edit_modal(request: &RequestRow) -> Option<Modal> {
    let scope_json = to_python_default_string(&Value::Object(scope(request)));
    if request.resource.chars().count() > EDIT_RESOURCE_MAX
        || scope_json.chars().count() > EDIT_SCOPE_MAX
    {
        return None;
    }
    Some(Modal {
        custom_id: CustomId::EditModal(request.id).render(),
        title: "Edit & approve".to_owned(),
        inputs: vec![
            Input {
                value: Some(format_duration(u64::from(request.requested_duration_secs))),
                max_length: Some(16),
                ..Input::new(DURATION, "Duration")
            },
            Input {
                value: Some(request.resource.clone()),
                max_length: Some(512),
                ..Input::new(RESOURCE, "Resource")
            },
            Input {
                paragraph: true,
                required: false,
                value: Some(scope_json),
                ..Input::new(SCOPE, "Scope (JSON)")
            },
            Input {
                required: false,
                placeholder: Some(
                    "approve|deny[:exact|:capability|:platform] — blank = decide once".to_owned(),
                ),
                max_length: Some(32),
                ..Input::new(RULE, "Rule (optional)")
            },
            Input {
                paragraph: true,
                required: false,
                max_length: Some(500),
                ..Input::new(NOTES, "Notes (optional)")
            },
        ],
    })
}

/// hostexec's `TotpModal`: the code (6–8), a shell's duration, a reason.
#[must_use]
pub fn totp_modal(request: &RequestRow) -> Modal {
    let tier = scope(request)
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let mut inputs = vec![Input {
        min_length: Some(6),
        max_length: Some(8),
        placeholder: Some("123456".to_owned()),
        ..Input::new(
            CODE,
            &cut(
                &format!(
                    "{} {}",
                    request.resource,
                    // A shell takes its tier's shell code, or its arm code
                    // while the host has no shell secret of that tier.
                    if capability(request) == "shell" {
                        format!("{tier}-shell (or -arm) code")
                    } else {
                        format!("{tier}-direct code")
                    }
                ),
                45,
            ),
        )
    }];
    if capability(request) == "shell" {
        inputs.push(Input {
            value: Some(format_duration(u64::from(request.requested_duration_secs))),
            max_length: Some(16),
            ..Input::new(DURATION, "Shell duration")
        });
    }
    inputs.push(reason_input());
    Modal {
        custom_id: CustomId::TotpModal(request.id).render(),
        title: cut(&format!("Approve with TOTP ({})", request.resource), 45),
        inputs,
    }
}

/// The Wrong call modal: what the decision should have been (prefilled
/// with the likely answer, `crate::models::likely_fix`), and a note for
/// whoever tunes the prompt.
#[must_use]
pub fn wrong_call_modal(call: Uuid, kind: Kind, class: Option<&str>) -> Modal {
    let classes = models::recipe(kind).classes;
    let fix = class.map(|c| models::likely_fix(kind, c));
    Modal {
        custom_id: CustomId::WrongCallModal(call).render(),
        title: cut(&format!("Wrong call: {}", models::kind_title(kind)), 45),
        inputs: vec![
            Input {
                value: fix.map(str::to_owned),
                placeholder: Some(cut(&classes.join(" | "), 100)),
                max_length: Some(64),
                ..Input::new(EXPECTED, "It should have been")
            },
            Input {
                paragraph: true,
                required: false,
                max_length: Some(1000),
                placeholder: Some("what it missed (for tuning the prompt)".to_owned()),
                ..Input::new(NOTE, "Note (optional)")
            },
        ],
    }
}

/// The Wrong call modal's answer: `(expected, note)`, the expected class
/// one `kind` can decide (or a pattern of them, `*` for a part).
pub fn read_wrong_call(kind: Kind, form: &Submitted) -> Result<(String, String), Refusal> {
    let expected = form.get(EXPECTED).trim().to_lowercase();
    if !models::valid_pattern(kind, &expected) {
        return Err(Refusal(format!(
            "`{}` is not something the {} decides: one of {}.",
            super::text::cut(&super::text::code(&expected), 64),
            models::kind_title(kind),
            models::recipe(kind).classes.join(", ")
        )));
    }
    Ok((expected, form.get(NOTE).trim().to_owned()))
}

/// The values of a submitted modal, by input custom id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Submitted(pub Vec<(String, String)>);

impl Submitted {
    #[must_use]
    pub fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// A modal answer that cannot become a decision: the ephemeral reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

fn duration(text: &str) -> Result<DurationSecs, Refusal> {
    DurationSecs::parse(text.trim()).map_err(|e| Refusal(format!("Invalid duration: {e}")))
}

/// The Decision modal's answer.
pub fn read_decision(approve: bool, form: &Submitted) -> Result<HumanDecision, Refusal> {
    let text = form.get(DURATION).trim();
    let duration_secs = if approve && !text.is_empty() {
        Some(duration(text)?)
    } else {
        None
    };
    Ok(HumanDecision {
        approve,
        reason: form.get(REASON).trim().to_owned(),
        duration_secs,
        ..HumanDecision::default()
    })
}

/// The TOTP modal's answer: an approval carrying the code.
pub fn read_totp(form: &Submitted) -> Result<HumanDecision, Refusal> {
    let text = form.get(DURATION).trim();
    let duration_secs = if text.is_empty() {
        None
    } else {
        Some(duration(text)?)
    };
    Ok(HumanDecision {
        approve: true,
        reason: form.get(REASON).trim().to_owned(),
        duration_secs,
        totp: Some(form.get(CODE).trim().to_owned()),
        ..HumanDecision::default()
    })
}

/// A rule asked for in the Edit modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleChoice {
    pub action: RuleAction,
    /// `capability`/`platform`: any resource (`*`).
    pub any_resource: bool,
    /// `platform`: any privilege.
    pub any_authority: bool,
}

/// `(approve|deny)(:(exact|capability|platform))?`, lowercased and
/// stripped; blank is no rule.
pub fn parse_rule(text: &str) -> Result<Option<RuleChoice>, Refusal> {
    let raw = text.trim().to_lowercase();
    if raw.is_empty() {
        return Ok(None);
    }
    let bad = || Refusal("Invalid rule: use approve|deny[:exact|:capability|:platform]".to_owned());
    let (verb, breadth) = match raw.split_once(':') {
        Some((v, b)) => (v, b),
        None => (raw.as_str(), "exact"),
    };
    let action = match verb {
        "approve" => RuleAction::AutoApprove,
        "deny" => RuleAction::AutoDeny,
        _ => return Err(bad()),
    };
    let (any_resource, any_authority) = match breadth {
        "exact" => (false, false),
        "capability" => (true, false),
        "platform" => (true, true),
        _ => return Err(bad()),
    };
    Ok(Some(RuleChoice {
        action,
        any_resource,
        any_authority,
    }))
}

/// The Edit modal's answer. A deny rule also denies this request.
pub fn read_edit(form: &Submitted) -> Result<HumanDecision, Refusal> {
    let duration_secs = duration(form.get(DURATION))?;
    let scope_text = form.get(SCOPE);
    let scope_override = if scope_text.trim().is_empty() {
        None
    } else {
        match serde_json::from_str::<Value>(scope_text) {
            Ok(Value::Object(m)) => Some(m),
            Ok(_) => {
                return Err(Refusal(
                    "Invalid scope JSON: scope must be a JSON object".to_owned(),
                ));
            }
            Err(e) => return Err(Refusal(format!("Invalid scope JSON: {e}"))),
        }
    };
    let rule = parse_rule(form.get(RULE))?;
    let resource = form.get(RESOURCE).trim();
    Ok(HumanDecision {
        approve: rule.is_none_or(|r| r.action == RuleAction::AutoApprove),
        reason: form.get(NOTES).trim().to_owned(),
        duration_secs: Some(duration_secs),
        resource_override: (!resource.is_empty()).then(|| resource.to_owned()),
        scope_override: scope_override.map(|m: Map<String, Value>| m),
        rule_action: rule.map(|r| r.action),
        rule_resource_pattern: rule.and_then(|r| r.any_resource.then(|| "*".to_owned())),
        rule_any_authority: rule.is_some_and(|r| r.any_authority),
        totp: None,
    })
}

/// `_apply_decision`'s reply on success.
#[must_use]
pub fn decided_text(rid: RequestId, decision: &HumanDecision, result: &RequestRow) -> String {
    let verb = if decision.approve {
        "Approved"
    } else {
        "Denied"
    };
    let mut extra = String::new();
    if let Some(d) = result
        .approved_duration_secs
        .filter(|d| decision.approve && *d > 0)
    {
        extra.push_str(&format!(" for {}", format_duration(u64::from(d))));
    }
    if decision.rule_action.is_some() {
        extra.push_str(" (rule saved — manage with /rules)");
    }
    format!("{verb} `{}`{extra}.", cut(&rid.to_string(), 8))
}
