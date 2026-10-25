//! The cards (spec A.5): pure functions from rows to embeds. Every string
//! an agent or a model chose is escaped ([`text::said`]) or put in a code
//! span it cannot close ([`text::code`]); this fixes Bug-A1 (an agent
//! could render "✅ Approved by policy" or a masked link in the card).

use agent_auth_core::durations::format_duration;
use agent_auth_core::pyfmt::{escape_unprintable, shlex_join, shlex_quote};
use agent_auth_core::{Authority, DecisionSource, GrantStatus, Platform, RequestStatus};
use agent_auth_store::a2a::ThreadRow;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::GrantRow;
use agent_auth_store::hostexec::{JobRow, JobStatus};
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleRow;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use twilight_model::channel::message::Embed;

use super::model::{
    COLOR_APPROVED, COLOR_DENIED, COLOR_ENDED, COLOR_PENDING, File, add_field, discord_time, embed,
    set_footer, timestamp,
};
use super::text::{
    code, code_block, cut, display_lines, escape, py_json, said, trim, trim_escaped,
};

/// hostexec's `MAX_CODE`.
pub const MAX_CODE: usize = 900;
const COLOR_RUN: u32 = 0xF1_C4_0F;
const COLOR_ROOT: u32 = 0xE6_7E_22;
const COLOR_SHELL: u32 = 0xE7_4C_3C;
/// hostexec's `TAIL_LINES`.
const TAIL_LINES: usize = 30;

#[must_use]
pub fn platform_emoji(p: Platform) -> &'static str {
    match p {
        Platform::Github => "🐙",
        Platform::Homelab => "🏠",
        Platform::A2a => "🤝",
        Platform::Google => "📅",
        _ => "🔑",
    }
}

/// What a card shows of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    pub status: GrantStatus,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoke_reason: Option<String>,
}

impl From<&GrantRow> for GrantView {
    fn from(g: &GrantRow) -> GrantView {
        GrantView {
            status: g.status,
            expires_at: g.expires_at,
            revoked_at: g.revoked_at,
            revoke_reason: g.revoke_reason.clone(),
        }
    }
}

/// The request's capability as the agent sees it (the parsed authority's,
/// else what was submitted).
#[must_use]
pub fn capability(r: &RequestRow) -> String {
    r.authority
        .as_ref()
        .map_or_else(|| r.requested_capability.clone(), Authority::capability)
}

/// The request's scope (the parsed authority's, else what was submitted).
#[must_use]
pub fn scope(r: &RequestRow) -> Map<String, Value> {
    match &r.authority {
        Some(a) => a.scope(),
        None => match &r.requested_scope {
            Value::Object(m) => m.clone(),
            _ => Map::new(),
        },
    }
}

/// `describe(agent)`: `runtime · project · host · VM`, present parts only.
#[must_use]
pub fn describe_agent(a: &AgentRow) -> String {
    let vm = (a.placement == agent_auth_core::containment::Placement::Sandbox).then_some("VM");
    [
        a.runtime.as_deref(),
        a.project.as_deref(),
        a.host.as_deref(),
        vm,
    ]
    .into_iter()
    .flatten()
    .filter(|p| !p.is_empty())
    .collect::<Vec<_>>()
    .join(" · ")
}

/// (name, value) of the Scope field. Approving applies the whole scope, so
/// a cut one says so instead of passing for all of it.
#[must_use]
pub fn scope_field(scope: &Map<String, Value>) -> (String, String) {
    let value = Value::Object(scope.clone());
    for dumped in [py_json(&value, Some(2)), py_json(&value, None)] {
        let shown = format!("```json\n{}\n```", code(&dumped));
        if shown.chars().count() <= 1024 {
            return ("Scope".to_owned(), shown);
        }
    }
    (
        "⚠️ Scope (too long to show: open Edit to see all of it before approving)".to_owned(),
        format!("```json\n{}…\n```", cut(&code(&py_json(&value, None)), 980)),
    )
}

fn risk_field(e: &mut Embed, notes: &[String]) {
    if !notes.is_empty() {
        let lines: Vec<String> = notes.iter().map(|n| format!("• {}", escape(n))).collect();
        add_field(
            e,
            "⚠️ Risk context",
            trim_escaped(&lines.join("\n"), 1000),
            false,
        );
    }
}

fn delegator_value(delegator: &AgentRow, thread: Option<&ThreadRow>) -> String {
    let topic = thread
        .and_then(|t| t.topic.as_deref())
        .filter(|t| !t.is_empty())
        .map(|t| format!(" (thread topic `{}`)", code(t)))
        .unwrap_or_default();
    trim(&format!("**{}**{topic}", escape(&delegator.name)), 256)
}

/// `build_request_embed`.
#[must_use]
pub fn request_embed(
    request: &RequestRow,
    agent: &AgentRow,
    delegator: Option<&AgentRow>,
    thread: Option<&ThreadRow>,
) -> Embed {
    let mut e = embed();
    e.title = Some(format!(
        "{} Access request: {}/{}",
        platform_emoji(request.platform),
        request.platform.as_str(),
        capability(request)
    ));
    e.description = Some(said(&request.justification, 1000));
    e.color = Some(COLOR_PENDING);
    let what = describe_agent(agent);
    let name = escape(&agent.name);
    add_field(
        &mut e,
        "Agent",
        if what.is_empty() {
            name
        } else {
            format!("{name}\n{}", escape(&what))
        },
        true,
    );
    if let Some(d) = delegator {
        add_field(&mut e, "🤝 On behalf of", delegator_value(d, thread), true);
    }
    add_field(&mut e, "Resource", said(&request.resource, 256), true);
    add_field(
        &mut e,
        "Requested duration",
        format_duration(u64::from(request.requested_duration_secs)),
        true,
    );
    let scope = scope(request);
    if !scope.is_empty() {
        let (name, value) = scope_field(&scope);
        add_field(&mut e, name, value, false);
    }
    risk_field(&mut e, &request.risk_notes);
    if request.attempt > 1 {
        add_field(&mut e, "LLM attempt", request.attempt.to_string(), true);
    }
    set_footer(&mut e, format!("request {}", request.id));
    e.timestamp = timestamp(request.created_at);
    e
}

/// `apply_outcome`: colour and an `Outcome` field (earlier fields stay).
#[must_use]
pub fn apply_outcome(mut e: Embed, request: &RequestRow, grant: Option<&GrantView>) -> Embed {
    let decided_by = request.decided_by.as_deref().unwrap_or("");
    let mut line = match request.status {
        RequestStatus::Granted | RequestStatus::Provisioning => {
            e.color = Some(COLOR_APPROVED);
            let mut line = format!("✅ Approved by {}", escape(decided_by));
            if let Some(d) = request.approved_duration_secs.filter(|d| *d > 0) {
                line.push_str(&format!(" for **{}**", format_duration(u64::from(d))));
            }
            if let Some(g) = grant {
                line.push_str(&format!(" — expires {}", discord_time(g.expires_at, 'R')));
            }
            line
        }
        RequestStatus::ProvisionFailed => {
            e.color = Some(COLOR_DENIED);
            "⚠️ Approved but provisioning **failed**".to_owned()
        }
        _ => {
            e.color = Some(COLOR_DENIED);
            let by = if decided_by.is_empty() {
                "policy".to_owned()
            } else {
                escape(decided_by)
            };
            format!("⛔ Denied by {by}")
        }
    };
    if let Some(reason) = request.decision_reason.as_deref().filter(|r| !r.is_empty()) {
        line.push_str(&format!("\n> {}", said(reason, 500)));
    }
    add_field(&mut e, "Outcome", line, false);
    e
}

/// `apply_grant_ended`: grey, plus `Expired` or `Revoked`.
#[must_use]
pub fn apply_grant_ended(mut e: Embed, grant: &GrantView) -> Embed {
    e.color = Some(COLOR_ENDED);
    let label = if grant.status == GrantStatus::Expired {
        "Expired"
    } else {
        "Revoked"
    };
    let when = grant
        .revoked_at
        .map(|t| discord_time(t, 'f'))
        .unwrap_or_default();
    let reason = said(grant.revoke_reason.as_deref().unwrap_or(""), 900);
    add_field(&mut e, label, format!("{when} — {reason}"), false);
    e
}

/// The audit line of a request decided without a human (no buttons).
#[must_use]
pub fn rule_applied_embed(
    request: &RequestRow,
    agent: &AgentRow,
    rule: Option<&RuleRow>,
    grant: Option<&GrantView>,
) -> Embed {
    let (verb, color) = match request.status {
        RequestStatus::Denied => ("auto-denied", COLOR_DENIED),
        RequestStatus::ProvisionFailed => ("auto-approved (provisioning **failed**)", COLOR_DENIED),
        _ => ("auto-approved", COLOR_APPROVED),
    };
    let decider = match request.decision_source {
        Some(DecisionSource::Policy) => "Policy",
        Some(DecisionSource::Llm) => "LLM reviewer",
        _ => "Rule",
    };
    let mut line = format!(
        "{} {decider} {verb}: **{}** → {}/{} on `{}`",
        platform_emoji(request.platform),
        escape(&agent.name),
        request.platform.as_str(),
        capability(request),
        trim(&code(request.final_resource()), 256)
    );
    if let Some(g) = grant.filter(|g| g.status == GrantStatus::Active) {
        line.push_str(&format!(
            " for **{}** — expires {}",
            format_duration(u64::from(request.approved_duration_secs.unwrap_or(0))),
            discord_time(g.expires_at, 'R')
        ));
    }
    if decider == "Rule" {
        match rule {
            Some(r) => {
                line.push_str(&format!("\nby rule `{}`", cut(&r.id.to_string(), 8)));
                if !r.notes.is_empty() {
                    line.push_str(&format!(" ({})", said(&r.notes, 200)));
                }
            }
            None => line.push_str("\nby a since-deleted rule"),
        }
        line.push_str(" — manage with /rules");
    } else {
        let why = escape(request.decision_reason.as_deref().unwrap_or(""));
        if !why.is_empty() {
            let lead = if decider == "Policy" { "by" } else { "because" };
            line.push_str(&format!("\n{lead}: {}", trim_escaped(&why, 300)));
        }
        if request.delegation.is_some() {
            line.push_str(" (on another agent's behalf)");
        }
    }
    let mut e = embed();
    e.description = Some(line);
    e.color = Some(color);
    set_footer(&mut e, format!("request {}", request.id));
    e.timestamp = request.decided_at.and_then(timestamp);
    e
}

// ------------------------------------------------------------- hostexec

fn scope_str<'a>(scope: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    scope
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// What the card shows as the command.
#[must_use]
pub fn hostexec_command(request: &RequestRow) -> String {
    let cap = capability(request);
    let scope = scope(request);
    if cap == "shell" {
        return "(any command, one at a time)".to_owned();
    }
    if let Some(template) = cap.strip_prefix("tpl.") {
        let params: Vec<String> = scope
            .get("params")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k}={}", shlex_quote(v.as_str().unwrap_or(""))))
                    .collect()
            })
            .unwrap_or_default();
        return format!("template {template} {}", params.join(" "))
            .trim()
            .to_owned();
    }
    shlex_join(&argv(scope.get("argv")))
}

fn argv(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|s| s.as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The host's state line (`_host_line`), from its status (`hostexec.hosts()`
/// entry). Only fixed words, the tier and a timestamp come from the status.
#[must_use]
pub fn host_line(host: Option<&Value>, tier: &str, shell: bool) -> String {
    let Some(host) = host.filter(|h| h.get("online").and_then(Value::as_bool) == Some(true)) else {
        return "⚫ offline".to_owned();
    };
    if host.get("lockdown").and_then(Value::as_bool) == Some(true) {
        return "⛔ locked down".to_owned();
    }
    let state = host.get("tiers").and_then(|t| t.get(tier));
    let flag = |k: &str| state.and_then(|s| s.get(k)).and_then(Value::as_bool) == Some(true);
    if !flag("enabled") {
        return format!("⛔ the {tier} tier is not enabled on this host");
    }
    if shell {
        return if flag("shell") {
            "🔐 a shell is approved with a TOTP code only".to_owned()
        } else {
            "⛔ shells are not enabled here".to_owned()
        };
    }
    match state
        .and_then(|s| s.get("armed_until"))
        .and_then(Value::as_f64)
    {
        Some(until) if until > 0.0 => {
            // A seconds timestamp, truncated as Python's int().
            let secs = format!("{}", until.trunc());
            format!("🔓 {tier} tier armed until <t:{secs}:t> — Approve works")
        }
        _ => {
            format!("🔒 {tier} tier not armed — Approve needs `/arm`; Approve with TOTP works now")
        }
    }
}

/// hostexec's `build_embed`.
#[must_use]
pub fn hostexec_embed(
    request: &RequestRow,
    agent: &AgentRow,
    delegator: Option<&AgentRow>,
    thread: Option<&ThreadRow>,
    host: Option<&Value>,
) -> Embed {
    let scope = scope(request);
    let tier = scope_str(&scope, "tier").unwrap_or("").to_owned();
    let shell = capability(request) == "shell";
    let resource = escape(&request.resource);
    let mut e = embed();
    if shell {
        e.title = Some(if tier == "root" {
            format!("🚨 ROOT SHELL on {resource}")
        } else {
            format!("⚠️ USER SHELL on {resource}")
        });
        e.color = Some(COLOR_SHELL);
    } else {
        let who = if tier == "root" { "ROOT" } else { "your user" };
        e.title = Some(format!("🖥️ Run on {resource} as {who}"));
        e.color = Some(if tier == "root" {
            COLOR_ROOT
        } else {
            COLOR_RUN
        });
    }
    e.description = Some(cut(&escape(&request.justification), 1000));
    add_field(
        &mut e,
        "Command",
        code_block(&hostexec_command(request), MAX_CODE),
        false,
    );
    add_field(&mut e, "Agent", escape(&agent.name), true);
    if let Some(p) = agent.project.as_deref().filter(|p| !p.is_empty()) {
        add_field(&mut e, "Project", escape(p), true);
    }
    if let Some(d) = delegator {
        add_field(&mut e, "🤝 On behalf of", delegator_value(d, thread), true);
    }
    if let Some(cwd) = scope_str(&scope, "cwd") {
        add_field(
            &mut e,
            "cwd",
            code_block(&escape_unprintable(&cut(cwd, 200)), 300),
            true,
        );
    }
    if let Some(env) = scope
        .get("env")
        .and_then(Value::as_object)
        .filter(|m| !m.is_empty())
    {
        let lines: Vec<String> = env
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    escape_unprintable(k),
                    shlex_quote(v.as_str().unwrap_or(""))
                )
            })
            .collect();
        add_field(&mut e, "env", code_block(&lines.join("\n"), 500), false);
    }
    if let Some(stdin) = scope_str(&scope, "stdin") {
        add_field(
            &mut e,
            format!("stdin ({} chars)", stdin.chars().count()),
            code_block(&display_lines(stdin), 700),
            false,
        );
    }
    if shell {
        add_field(
            &mut e,
            "For",
            format_duration(u64::from(request.requested_duration_secs)),
            true,
        );
    } else if let Some(t) = scope
        .get("timeout")
        .and_then(Value::as_u64)
        .filter(|t| *t > 0)
    {
        add_field(&mut e, "Timeout", format_duration(t), true);
    }
    add_field(&mut e, "Host", host_line(host, &tier, shell), false);
    risk_field(&mut e, &request.risk_notes);
    set_footer(&mut e, format!("request {}", request.id));
    e.timestamp = timestamp(request.created_at);
    e
}

/// hostexec's `tail`: the last 30 lines, at most `limit` characters.
#[must_use]
pub fn tail(output: &str, limit: usize) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let text = lines
        .get(lines.len().saturating_sub(TAIL_LINES)..)
        .unwrap_or_default()
        .join("\n");
    let n = text.chars().count();
    text.chars().skip(n.saturating_sub(limit)).collect()
}

/// One line on how a job ended.
#[must_use]
pub fn result_line(job: &JobRow) -> String {
    let error = job.error.as_deref().filter(|e| !e.is_empty());
    if job.status == JobStatus::Refused {
        return format!(
            "⛔ refused by {}: {}",
            escape(&job.host),
            said(error.unwrap_or("?"), 300)
        );
    }
    if let (Some(err), None) = (error, job.exit_code) {
        return format!("⚠️ {}", said(err, 300));
    }
    let took = job
        .duration_ms
        .map(|ms| {
            #[expect(clippy::as_conversions, reason = "display only")]
            let secs = ms as f64 / 1000.0;
            format!(" in {secs:.1}s")
        })
        .unwrap_or_default();
    let mark = if job.exit_code == Some(0) {
        "✅"
    } else {
        "❌"
    };
    let code = job
        .exit_code
        .map_or_else(|| "None".to_owned(), |c| c.to_string());
    let extra = error
        .map(|e| format!(" ({})", said(e, 300)))
        .unwrap_or_default();
    format!("{mark} exit {code}{took}{extra}")
}

/// The `Result` field: the line, the output's end, at most 1024 characters.
#[must_use]
pub fn result_field(job: &JobRow) -> String {
    let mut text = result_line(job);
    let shown = tail(
        job.output.as_deref().unwrap_or(""),
        MAX_CODE.saturating_sub(20),
    );
    if !shown.is_empty() {
        text.push('\n');
        text.push_str(&code_block(&shown, MAX_CODE));
    }
    if job.truncated {
        text.push_str("\n(the host kept only the last 1 MiB)");
    }
    cut(&text, 1024)
}

/// The whole output, when the message shows only its end.
#[must_use]
pub fn output_file(job: &JobRow) -> Option<File> {
    let output = job.output.as_deref()?;
    if output.is_empty() || output.chars().count() <= MAX_CODE.saturating_sub(20) {
        return None;
    }
    Some(File {
        name: format!("output-{}.txt", cut(&job.id.to_string(), 8)),
        bytes: output.as_bytes().to_vec(),
    })
}
