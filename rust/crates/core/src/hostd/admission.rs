//! Admission: re-validating a broker's spec against this host's policy, the
//! host's own approvals (TOTP codes, desk answers), arming, and the decision
//! itself (daemons-hostd spec §8.2-§8.10).

use std::collections::BTreeMap;

use serde_json::Value;

use super::totp::{AcceptedCode, Purpose, SecretName};
use super::{
    HostPolicy, LocalId, LockState, Refused, Source, SpecDigest, UnixMillis, Via, repr_value,
    tier_word,
};
use crate::authority::Tier;
use crate::hostexec::{Command, CommandSpec, JobSpec, ShellSpec, match_argv, shell_spec};

/// How long a TOTP code's or a desk answer's approval waits for its job.
pub const AUTHZ_TTL_SECS: u64 = 300;

// ------------------------------------------------------------- tier, spec

/// What every decision reads: the host's policy, its arm state, whether it
/// is locked down, and the time.
#[derive(Debug, Clone, Copy)]
pub struct HostView<'a> {
    pub policy: &'a HostPolicy,
    pub arm: &'a ArmState,
    pub lock: LockState,
    pub now: UnixMillis,
}

/// What the broker says about a job's approval (believed only while
/// armed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence {
    pub source: Option<Source>,
    /// An approve-all window approved it.
    pub window: bool,
}

/// `_tier`: a tier name this host has enabled.
pub fn check_tier(policy: &HostPolicy, tier: Option<&Value>) -> Result<Tier, Refused> {
    let tier = tier
        .and_then(Value::as_str)
        .and_then(Tier::parse)
        .ok_or_else(|| Refused::new("tier must be user or root"))?;
    tier_enabled(policy, tier)
}

fn tier_enabled(policy: &HostPolicy, tier: Tier) -> Result<Tier, Refused> {
    if policy.tier(tier).enable {
        Ok(tier)
    } else {
        Err(Refused(format!(
            "the {} tier is not enabled on {}",
            tier_word(tier),
            policy.name
        )))
    }
}

fn locked_refusal(policy: &HostPolicy) -> Refused {
    Refused(format!("{} is locked down", policy.name))
}

/// A broker spec re-validated from scratch against this host's policy, and
/// resolved to what would run (a template expanded from this host's own
/// copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    spec: CommandSpec,
    argv: Vec<String>,
}

impl Normalized {
    #[must_use]
    pub fn spec(&self) -> &CommandSpec {
        &self.spec
    }

    /// What runs.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        self.spec.tier()
    }

    #[must_use]
    pub fn is_run(&self) -> bool {
        matches!(self.spec.command(), Command::Run { .. })
    }

    /// The normalized spec for the journal: the expanded argv, stdin as its
    /// size only (its content is never logged).
    #[must_use]
    pub fn loggable(&self) -> Value {
        loggable(&self.spec.to_json(), Some(&self.argv))
    }
}

/// A spec for the journal: stdin as `<N chars>`.
#[must_use]
pub fn loggable(spec: &Value, argv: Option<&[String]>) -> Value {
    let Value::Object(map) = spec else {
        return Value::Null;
    };
    let mut out = map.clone();
    if let Some(Value::String(stdin)) = out.get("stdin") {
        let n = stdin.chars().count();
        out.insert("stdin".to_owned(), Value::String(format!("<{n} chars>")));
    }
    if let Some(argv) = argv {
        out.insert("argv".to_owned(), serde_json::json!(argv));
    }
    Value::Object(out)
}

/// `_normalize(raw, shell_command)`: refused unless this host would run
/// it — addressed to this host, a run/tpl job (a template never in a
/// shell, only this host's own template, of its own tier), an enabled
/// tier, a timeout within this host's maximum, only allowed environment
/// variables, and no deny pattern matching (INV-15).
pub fn normalize(
    policy: &HostPolicy,
    raw: &Value,
    shell_command: bool,
) -> Result<Normalized, Refused> {
    let Value::Object(map) = raw else {
        return Err(Refused::new("malformed job"));
    };
    if map.get("host").and_then(Value::as_str) != Some(policy.name.as_str()) {
        return Err(Refused(format!(
            "that job is for {}, this is {}",
            repr_value(map.get("host")),
            policy.name
        )));
    }
    match map.get("kind").and_then(Value::as_str) {
        Some("run" | "tpl") => {}
        _ => return Err(Refused::new("not a runnable job")),
    }
    let JobSpec::Command(spec) = JobSpec::from_json(raw, policy.default_timeout_secs)? else {
        return Err(Refused::new("not a runnable job"));
    };
    let argv = match spec.command() {
        Command::Run { argv } => argv.clone(),
        Command::Template { template, params } => {
            if shell_command {
                return Err(Refused::new("templates don't run inside a shell"));
            }
            let Some(host_template) = policy.templates.get(template.as_str()) else {
                return Err(Refused(format!(
                    "no template {} on {}",
                    crate::pyfmt::repr(template.as_str()),
                    policy.name
                )));
            };
            if host_template.tier != spec.tier() {
                return Err(Refused(format!(
                    "template {} is a {}-tier template",
                    crate::pyfmt::repr(template.as_str()),
                    tier_word(host_template.tier)
                )));
            }
            host_template.expand(params)?
        }
    };
    tier_enabled(policy, spec.tier())?;
    if spec.timeout() > policy.max_timeout_secs {
        return Err(Refused(format!(
            "timeout exceeds this host's maximum ({}s)",
            policy.max_timeout_secs
        )));
    }
    let extra: Vec<&str> = spec
        .env()
        .keys()
        .map(|k| k.as_str())
        .filter(|k| !policy.env_allow.contains(*k))
        .collect();
    if !extra.is_empty() {
        return Err(Refused(format!(
            "environment variables not allowed on this host: {}",
            extra.join(", ")
        )));
    }
    if policy
        .deny_commands
        .iter()
        .any(|p| match_argv(p, &argv, true))
    {
        return Err(Refused::new("that command is denied by this host's policy"));
    }
    Ok(Normalized { spec, argv })
}

// ----------------------------------------------------- the host's approvals

/// How this host itself approved a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalVia {
    Totp,
    Desk,
}

/// A direct TOTP code accepted for one digest. Its tier is the tier of the
/// secret that verified the code, whatever the broker later names, so a
/// user code relayed for a root digest approves nothing (INV-17).
#[derive(Debug, PartialEq, Eq)]
pub struct TotpApproval {
    tier: Tier,
    digest: SpecDigest,
}

impl TotpApproval {
    /// The approval a `{tier}-direct` code stands for. An arm code is not
    /// a direct approval.
    pub fn new(code: AcceptedCode, digest: SpecDigest) -> Result<TotpApproval, Refused> {
        let name = code.name();
        if name.purpose != Purpose::Direct {
            return Err(Refused(format!("{name} is not a direct approval code")));
        }
        Ok(TotpApproval {
            tier: name.tier,
            digest,
        })
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    #[must_use]
    pub fn digest(&self) -> &SpecDigest {
        &self.digest
    }

    /// Exactly a job of its own tier with its digest.
    #[must_use]
    pub fn covers(&self, tier: Tier, digest: &SpecDigest) -> bool {
        self.tier == tier && &self.digest == digest
    }
}

/// Allow at this host's desk for a command on this host.
#[derive(Debug, PartialEq, Eq)]
pub struct DeskApproval {
    tier: Tier,
    digest: SpecDigest,
}

impl DeskApproval {
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
}

/// A desk prompt about a command on this host: Allow approves exactly its
/// digest. Registered only when `desktop.approve.{tier}` is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeskPrompt {
    job: LocalId,
    digest: SpecDigest,
    tier: Tier,
    message: String,
}

impl DeskPrompt {
    #[must_use]
    pub fn job(&self) -> &LocalId {
        &self.job
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// What polkit shows with the password prompt (root).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// polkit authenticated the desk's user as an administrator for this
/// prompt (`pkcheck` exited 0). Made only by hostd's executor after it did.
#[derive(Debug)]
pub struct PolkitConfirmed(());

impl PolkitConfirmed {
    /// Call only after `pkcheck` for the run-as-root action succeeded for
    /// the helper process that answered.
    #[must_use]
    pub fn after_successful_pkcheck() -> PolkitConfirmed {
        PolkitConfirmed(())
    }
}

/// A prompt about a command at this desk (`_desk_job`): `Some` when Allow
/// here approves it; `None` when it does not but the tier is armed (Allow is
/// then only a click relayed to the broker). Refused when locked, or when
/// neither holds.
pub fn desk_prompt(
    host: HostView<'_>,
    job: LocalId,
    raw_digest: SpecDigest,
    normalized: &Normalized,
    message: String,
) -> Result<Option<DeskPrompt>, Refused> {
    let HostView {
        policy,
        arm,
        lock,
        now,
    } = host;
    if lock.is_locked() {
        return Err(locked_refusal(policy));
    }
    let tier = normalized.tier();
    if policy.desk_approves(tier) {
        return Ok(Some(DeskPrompt {
            job,
            digest: raw_digest,
            tier,
            message,
        }));
    }
    if !arm.armed(tier, now) {
        let t = tier_word(tier);
        return Err(Refused(format!(
            "the {t} tier is not armed, and this desk doesn't approve {t} commands"
        )));
    }
    Ok(None)
}

/// An Allow answer to a desk prompt: an approval when the host is not
/// locked, the answer came over the current helper connection, and (root)
/// polkit confirmed the user's password. Otherwise the prompt comes back
/// and the answer counts as "discord" (INV-19).
pub fn desk_approval(
    prompt: DeskPrompt,
    from_current_helper: bool,
    lock: LockState,
    polkit: Option<PolkitConfirmed>,
) -> Result<(LocalId, DeskApproval), DeskPrompt> {
    let ok =
        !lock.is_locked() && from_current_helper && (prompt.tier == Tier::User || polkit.is_some());
    if !ok {
        return Err(prompt);
    }
    Ok((
        prompt.job,
        DeskApproval {
            tier: prompt.tier,
            digest: prompt.digest,
        },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Authorization {
    digest: SpecDigest,
    tier: Tier,
    via: ApprovalVia,
    expires_at: UnixMillis,
}

impl Authorization {
    fn facts(&self, digest: &SpecDigest, now: UnixMillis) -> AuthzFacts {
        AuthzFacts {
            via: self.via,
            tier: self.tier,
            digest_matches: &self.digest == digest,
            unexpired: self.expires_at > now,
        }
    }

    fn admits(&self, tier: Tier, digest: &SpecDigest, now: UnixMillis) -> Option<ApprovalVia> {
        let f = self.facts(digest, now);
        (f.unexpired && f.digest_matches && f.tier == tier).then_some(self.via)
    }
}

/// The host's own approvals, by job (or shell) id, each for one digest and
/// tier, for [`AUTHZ_TTL_SECS`]. Memory only.
#[derive(Debug, Default)]
pub struct Authorizations {
    map: BTreeMap<LocalId, Authorization>,
}

impl Authorizations {
    fn insert(&mut self, job: LocalId, a: Authorization, now: UnixMillis) {
        self.map.retain(|_, v| v.expires_at > now);
        self.map.insert(job, a);
    }

    /// A direct code for `job` (replacing any earlier approval of it).
    pub fn record_totp(&mut self, job: LocalId, approval: TotpApproval, now: UnixMillis) {
        let a = Authorization {
            digest: approval.digest,
            tier: approval.tier,
            via: ApprovalVia::Totp,
            expires_at: now.plus_secs(AUTHZ_TTL_SECS),
        };
        self.insert(job, a, now);
    }

    /// Allow at the desk for `job`.
    pub fn record_desk(&mut self, job: LocalId, approval: DeskApproval, now: UnixMillis) {
        let a = Authorization {
            digest: approval.digest,
            tier: approval.tier,
            via: ApprovalVia::Desk,
            expires_at: now.plus_secs(AUTHZ_TTL_SECS),
        };
        self.insert(job, a, now);
    }

    fn take(&mut self, job: &LocalId) -> Option<Authorization> {
        self.map.remove(job)
    }

    fn peek(&self, job: &str) -> Option<&Authorization> {
        self.map.get(job)
    }

    /// Lockdown: every approval is gone.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------- arming

/// Who on the host asked over hostctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCaller {
    /// uid 0.
    Root,
    /// The configured user.
    User,
}

/// What arming (or unlocking) rests on: the tier's arm code, or someone at
/// the host. Root arming needs the root-arm code or root (INV-20).
#[derive(Debug)]
pub enum ArmProof {
    Totp(AcceptedCode),
    Local(LocalCaller),
}

/// How long each tier is armed. Memory only: a restart disarms (INV-25).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArmState {
    user: UnixMillis,
    root: UnixMillis,
}

impl ArmState {
    #[must_use]
    pub fn armed_until(&self, tier: Tier) -> UnixMillis {
        match tier {
            Tier::User => self.user,
            Tier::Root => self.root,
        }
    }

    #[must_use]
    pub fn armed(&self, tier: Tier, now: UnixMillis) -> bool {
        self.armed_until(tier) > now
    }

    /// Everything that refuses arming, checked before a code is spent on it
    /// (bug 8: the Python burned a valid arm code on a locked host).
    pub fn check_can_arm(policy: &HostPolicy, tier: Tier, lock: LockState) -> Result<(), Refused> {
        tier_enabled(policy, tier)?;
        if lock.is_locked() {
            return Err(locked_refusal(policy));
        }
        Ok(())
    }

    /// Arm `tier` for `secs`, capped at the tier's `max_arm`.
    pub fn arm(
        &mut self,
        policy: &HostPolicy,
        tier: Tier,
        secs: u64,
        proof: ArmProof,
        lock: LockState,
        now: UnixMillis,
    ) -> Result<UnixMillis, Refused> {
        match &proof {
            ArmProof::Totp(code) if code.name() != SecretName::new(tier, Purpose::Arm) => {
                return Err(Refused(format!(
                    "a {} code does not arm the {} tier",
                    code.name(),
                    tier_word(tier)
                )));
            }
            ArmProof::Local(LocalCaller::User) if tier != Tier::User => {
                return Err(Refused::new("arm needs root"));
            }
            _ => {}
        }
        ArmState::check_can_arm(policy, tier, lock)?;
        let secs = secs.min(u64::from(policy.tier(tier).max_arm_secs));
        let until = now.plus_secs(secs);
        match tier {
            Tier::User => self.user = until,
            Tier::Root => self.root = until,
        }
        Ok(until)
    }

    /// One tier, or both. Needs no proof: it only takes authority away.
    pub fn disarm(&mut self, tier: Option<Tier>) {
        match tier {
            Some(Tier::User) => self.user = UnixMillis(0),
            Some(Tier::Root) => self.root = UnixMillis(0),
            None => {
                self.user = UnixMillis(0);
                self.root = UnixMillis(0);
            }
        }
    }

    /// What may lift a lockdown: the root-arm code, or root on the host
    /// (INV-26).
    pub fn check_unlock(proof: &ArmProof) -> Result<(), Refused> {
        match proof {
            ArmProof::Totp(code) if code.name() == SecretName::new(Tier::Root, Purpose::Arm) => {
                Ok(())
            }
            ArmProof::Local(LocalCaller::Root) => Ok(()),
            ArmProof::Totp(code) => Err(Refused(format!(
                "{} does not unlock; the root-arm code does",
                code.name()
            ))),
            ArmProof::Local(LocalCaller::User) => Err(Refused::new("unlock needs root")),
        }
    }
}

// --------------------------------------------------------- the decision

/// What the host knows about a job's approval, reduced to what the
/// decision depends on (so it can be model-checked whole).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthzFacts {
    pub via: ApprovalVia,
    /// The tier the approval was given for.
    pub tier: Tier,
    pub digest_matches: bool,
    pub unexpired: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFacts {
    pub locked: bool,
    pub tier: Tier,
    /// A `run` job (not a template).
    pub kind_run: bool,
    /// The host's own approval under this job id, if any.
    pub authorization: Option<AuthzFacts>,
    /// An `auto_commands` pattern matches (strict program match).
    pub auto_match: bool,
    /// Who the broker says approved (believed only while armed).
    pub source: Option<Source>,
    pub window: bool,
    pub armed: bool,
    pub accept_approve_all: bool,
    pub accept_machine_approvals: bool,
}

/// Why the decision refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    Locked,
    NoEvidence,
    NoWindows,
    HumanOnly(Source),
    NotArmed,
}

/// `_admit`, in order (§8.4): locked; the host's own approval of exactly
/// this digest and tier; a user-tier `run` matching an auto pattern; and
/// otherwise the broker's evidence, believed only while armed.
pub fn decide(f: &AdmissionFacts) -> Result<Via, RefusalKind> {
    if f.locked {
        return Err(RefusalKind::Locked);
    }
    if let Some(a) = f.authorization
        && a.unexpired
        && a.digest_matches
        && a.tier == f.tier
    {
        return Ok(match a.via {
            ApprovalVia::Totp => Via::Totp,
            ApprovalVia::Desk => Via::Desk,
        });
    }
    if f.kind_run && f.tier == Tier::User && f.auto_match {
        return Ok(Via::Auto);
    }
    let Some(source) = f.source else {
        return Err(RefusalKind::NoEvidence);
    };
    if !f.armed {
        return Err(RefusalKind::NotArmed);
    }
    if f.window {
        return if f.accept_approve_all {
            Ok(Via::ArmedWindow)
        } else {
            Err(RefusalKind::NoWindows)
        };
    }
    match source {
        Source::Human => Ok(Via::ArmedHuman),
        _ if !f.accept_machine_approvals => Err(RefusalKind::HumanOnly(source)),
        Source::Rule => Ok(Via::ArmedRule),
        Source::Llm => Ok(Via::ArmedLlm),
        Source::Policy => Ok(Via::ArmedPolicy),
    }
}

fn refusal_text(policy: &HostPolicy, tier: Tier, kind: RefusalKind) -> Refused {
    let name = &policy.name;
    let t = tier_word(tier);
    Refused(match kind {
        RefusalKind::Locked => format!("{name} is locked down"),
        RefusalKind::NoEvidence => "no approval evidence".to_owned(),
        RefusalKind::NoWindows => {
            format!("{name} does not accept approve-all windows for the {t} tier")
        }
        RefusalKind::HumanOnly(source) => format!(
            "{name} only accepts a human's approval for the {t} tier (this one came from {})",
            source.as_str()
        ),
        RefusalKind::NotArmed => format!(
            "not_armed: the {t} tier of {name} is not armed — arm it (/arm) or approve with a TOTP code"
        ),
    })
}

fn facts(
    host: HostView<'_>,
    job: &Normalized,
    authorization: Option<AuthzFacts>,
    evidence: Evidence,
) -> AdmissionFacts {
    let HostView {
        policy,
        arm,
        lock,
        now,
    } = host;
    let tier = job.tier();
    let cfg = policy.tier(tier);
    AdmissionFacts {
        locked: lock.is_locked(),
        tier,
        kind_run: job.is_run(),
        authorization,
        auto_match: policy
            .auto_commands
            .iter()
            .any(|p| match_argv(p, job.argv(), false)),
        source: evidence.source,
        window: evidence.window,
        armed: arm.armed(tier, now),
        accept_approve_all: cfg.accept_approve_all,
        accept_machine_approvals: cfg.accept_machine_approvals,
    }
}

/// A job hostd will run. Only [`admit`] and [`admit_shell_command`] make
/// one; the executor takes nothing else.
#[derive(Debug)]
pub struct AdmittedJob {
    id: LocalId,
    tier: Tier,
    argv: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    timeout: u32,
    stdin: Option<String>,
    via: Via,
    shell: Option<LocalId>,
    loggable: Value,
}

impl AdmittedJob {
    fn new(id: LocalId, job: Normalized, via: Via, shell: Option<LocalId>) -> AdmittedJob {
        let loggable = job.loggable();
        let spec = job.spec;
        AdmittedJob {
            id,
            tier: spec.tier(),
            cwd: spec.cwd().map(str::to_owned),
            env: spec
                .env()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
                .collect(),
            timeout: spec.timeout(),
            stdin: spec.stdin().map(str::to_owned),
            argv: job.argv,
            via,
            shell,
            loggable,
        }
    }

    #[must_use]
    pub fn id(&self) -> &LocalId {
        &self.id
    }
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    #[must_use]
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }
    #[must_use]
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
    #[must_use]
    pub fn timeout_secs(&self) -> u32 {
        self.timeout
    }
    #[must_use]
    pub fn stdin(&self) -> Option<&str> {
        self.stdin.as_deref()
    }
    #[must_use]
    pub fn via(&self) -> Via {
        self.via
    }
    #[must_use]
    pub fn shell(&self) -> Option<&LocalId> {
        self.shell.as_ref()
    }
    /// The spec for the journal (stdin as a size).
    #[must_use]
    pub fn loggable(&self) -> &Value {
        &self.loggable
    }
}

/// `job.start`'s decision (`_admit`). The approval under `job_id` is taken
/// (spent) whether or not it matches (INV-18); a locked host refuses first.
pub fn admit(
    host: HostView<'_>,
    job_id: LocalId,
    job: Normalized,
    raw_digest: &SpecDigest,
    evidence: Evidence,
    auths: &mut Authorizations,
) -> Result<AdmittedJob, Refused> {
    let HostView {
        policy, lock, now, ..
    } = host;
    let tier = job.tier();
    if lock.is_locked() {
        return Err(refusal_text(policy, tier, RefusalKind::Locked));
    }
    let authorization = auths.take(&job_id).map(|a| a.facts(raw_digest, now));
    let f = facts(host, &job, authorization, evidence);
    match decide(&f) {
        Ok(via) => Ok(AdmittedJob::new(job_id, job, via, None)),
        Err(kind) => Err(refusal_text(policy, tier, kind)),
    }
}

/// `hostexec.precheck` for a job: would it be admitted now? Consumes
/// nothing. A denied command (or anything else `normalize` refuses) is
/// refused before a TOTP code is spent on it.
///
/// `totp`: a code will come with the approval (the host then only checks
/// it would not refuse the spec). `job_id`: it may already be approved at
/// this host's desk.
pub fn precheck_job(
    host: HostView<'_>,
    raw: &Value,
    raw_digest: &SpecDigest,
    totp: bool,
    job_id: Option<&str>,
    evidence: Evidence,
    auths: &Authorizations,
) -> Result<Via, Refused> {
    let HostView {
        policy, lock, now, ..
    } = host;
    let job = normalize(policy, raw, false)?;
    let tier = job.tier();
    if totp {
        if lock.is_locked() {
            return Err(locked_refusal(policy));
        }
        return Ok(Via::Totp);
    }
    if let Some(id) = job_id
        && !lock.is_locked()
        && let Some(via) = auths.peek(id).and_then(|a| a.admits(tier, raw_digest, now))
    {
        return Ok(match via {
            ApprovalVia::Totp => Via::Totp,
            ApprovalVia::Desk => Via::Desk,
        });
    }
    let f = facts(host, &job, None, evidence);
    decide(&f).map_err(|kind| refusal_text(policy, tier, kind))
}

/// `hostexec.precheck` for a shell: everything the host would refuse,
/// before a code is spent. Replied `{"needs": "totp"}`.
pub fn precheck_shell(
    policy: &HostPolicy,
    tier: Option<&Value>,
    duration: Option<&Value>,
    lock: LockState,
) -> Result<(), Refused> {
    let tier = check_tier(policy, tier)?;
    let cfg = policy.tier(tier);
    let t = tier_word(tier);
    if !cfg.shell_enable {
        return Err(Refused(format!(
            "{t} shells are not enabled on {}",
            policy.name
        )));
    }
    if lock.is_locked() {
        return Err(locked_refusal(policy));
    }
    if let Some(d) = duration.and_then(Value::as_u64)
        && d > u64::from(cfg.shell_max_duration_secs)
    {
        return Err(Refused(format!(
            "a {t} shell on {} lasts at most {}s",
            policy.name, cfg.shell_max_duration_secs
        )));
    }
    Ok(())
}

// ----------------------------------------------------------------- shells

/// The shell request in a `shell.open`, as the canonical shell spec whose
/// digest a TOTP code must have been typed for.
pub fn parse_shell_request(policy: &HostPolicy, raw: &Value) -> Result<ShellSpec, Refused> {
    let Value::Object(map) = raw else {
        return Err(Refused::new("malformed shell request"));
    };
    if map.get("host").and_then(Value::as_str) != Some(policy.name.as_str()) {
        return Err(Refused::new("malformed shell request"));
    }
    let spec = shell_spec(&policy.name, map.get("tier"), map.get("duration"))?;
    tier_enabled(policy, spec.tier())?;
    Ok(spec)
}

/// An open shell: its tier and when it ends (fixed at opening; nothing the
/// broker sends extends it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenShell {
    id: LocalId,
    tier: Tier,
    expires_at: UnixMillis,
}

impl OpenShell {
    #[must_use]
    pub fn id(&self) -> &LocalId {
        &self.id
    }
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
    #[must_use]
    pub fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// `shell.open`: only a TOTP approval for this exact shell spec opens a
/// shell (INV-23); arming, windows, rules and desk answers never do. The
/// approval under `shell_id` is spent.
pub fn open_shell(
    policy: &HostPolicy,
    shell_id: LocalId,
    spec: &ShellSpec,
    digest: &SpecDigest,
    auths: &mut Authorizations,
    lock: LockState,
    now: UnixMillis,
) -> Result<OpenShell, Refused> {
    let tier = spec.tier();
    let cfg = policy.tier(tier);
    let t = tier_word(tier);
    if lock.is_locked() {
        return Err(locked_refusal(policy));
    }
    if !cfg.shell_enable {
        return Err(Refused(format!(
            "{t} shells are not enabled on {}",
            policy.name
        )));
    }
    if spec.duration() > cfg.shell_max_duration_secs {
        return Err(Refused(format!(
            "a {t} shell on {} lasts at most {}s",
            policy.name, cfg.shell_max_duration_secs
        )));
    }
    let via = auths
        .take(&shell_id)
        .and_then(|a| a.admits(tier, digest, now));
    if via != Some(ApprovalVia::Totp) {
        return Err(Refused::new("a shell is opened with a TOTP code only"));
    }
    Ok(OpenShell {
        id: shell_id,
        tier,
        expires_at: now.plus_secs(u64::from(spec.duration())),
    })
}

/// `shell.exec`: a command in an open, unexpired shell of the same tier,
/// on an unlocked host (INV-24). The shell's opening was the approval.
pub fn admit_shell_command(
    policy: &HostPolicy,
    shell: Option<&OpenShell>,
    job_id: LocalId,
    raw: &Value,
    lock: LockState,
    now: UnixMillis,
) -> Result<AdmittedJob, Refused> {
    if lock.is_locked() {
        return Err(locked_refusal(policy));
    }
    let Some(shell) = shell.filter(|s| s.expires_at > now) else {
        return Err(Refused::new(
            "no such shell on this host (expired, closed, or hostd restarted)",
        ));
    };
    let job = normalize(policy, raw, true)?;
    if job.tier() != shell.tier {
        return Err(Refused(format!(
            "that is a {} shell",
            tier_word(shell.tier)
        )));
    }
    Ok(AdmittedJob::new(
        job_id,
        job,
        Via::Shell,
        Some(shell.id.clone()),
    ))
}
