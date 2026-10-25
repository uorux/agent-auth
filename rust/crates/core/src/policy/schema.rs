//! The policy file's sections, typed (`policy/schema.py`). Every struct
//! refuses unknown keys (bug B-1: the Python ignored them in most sections,
//! so `match: {agnet: x}` silently became a match-everything rule).
//! Defaults are the Python's.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::durations::DurationSecs;
use crate::glob::Glob;
use crate::hostexec::Template;
use crate::names::{McpServerName, TemplateName};
use crate::platform::Platform;
use crate::pool::{PropValue, item_name_ok};
use crate::pyfmt::repr;
use crate::routing::PolicyAction;

use super::agents::AgentPattern;

fn secs(text: &str) -> DurationSecs {
    // Only ever called with the literal defaults below, which parse.
    DurationSecs::parse(text).unwrap_or(DurationSecs::MAX)
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn globs(items: &[&str]) -> Vec<Glob> {
    items.iter().map(|s| Glob::new(s)).collect()
}

/// `match` of a policy rule. The default matches everything.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Match {
    /// Which agents: fields, or a glob on the name.
    pub agent: AgentPattern,
    /// None = any platform.
    pub platform: Option<Platform>,
    /// Glob on the request's capability.
    pub capability: Glob,
    /// Glob on the resource; may use `{agent.runtime|project|host|repos}`.
    pub resource: String,
    /// For on-behalf-of requests. None: the rule was written without
    /// delegation in mind (deny/surface still apply to delegated requests,
    /// approve/llm never do).
    pub delegator: Option<AgentPattern>,
}

impl Default for Match {
    fn default() -> Self {
        Match {
            agent: AgentPattern::default(),
            platform: None,
            capability: Glob::any(),
            resource: "*".to_owned(),
            delegator: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Constraints {
    pub max_duration: Option<DurationSecs>,
    pub llm_model: Option<String>,
    pub retry_budget: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    #[serde(default, rename = "match")]
    pub matches: Match,
    pub action: PolicyAction,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    pub action: PolicyAction,
    pub max_duration: DurationSecs,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            action: PolicyAction::Surface,
            max_duration: secs("24h"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LlmConfig {
    pub model: String,
    /// LLM denials the agent may retry before human escalation.
    pub retry_budget: u32,
    pub timeout_secs: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            model: "deepseek/deepseek-v4.1-flash-1017".to_owned(),
            retry_budget: 2,
            timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GithubConfig {
    pub repo_allowlist: Vec<Glob>,
    /// Checked before the allowlist.
    pub repo_denylist: Vec<Glob>,
    /// e.g. {contents: write, secrets: write}
    pub permission_ceiling: BTreeMap<String, String>,
    pub sensitive_permissions: Vec<String>,
    /// Organizations the broker may create repos in; empty = no creation.
    pub create_owners: Vec<String>,
}

impl Default for GithubConfig {
    fn default() -> Self {
        GithubConfig {
            repo_allowlist: Vec::new(),
            repo_denylist: Vec::new(),
            permission_ceiling: BTreeMap::new(),
            sensitive_permissions: strings(&["secrets", "administration"]),
            create_owners: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HomelabConfig {
    pub allowed_groups: Vec<String>,
    pub group_descriptions: BTreeMap<String, String>,
    pub managed_accounts: bool,
    /// At most 32 characters.
    pub managed_username_prefix: String,
    /// Not empty.
    pub managed_email_domain: String,
}

impl Default for HomelabConfig {
    fn default() -> Self {
        HomelabConfig {
            allowed_groups: Vec::new(),
            group_descriptions: BTreeMap::new(),
            managed_accounts: true,
            managed_username_prefix: "svc-".to_owned(),
            managed_email_domain: "agents.invalid".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KubernetesConfig {
    pub namespace_allowlist: Vec<Glob>,
    pub role_allowlist: Vec<String>,
    pub cluster_role_allowlist: Vec<String>,
    pub cluster_grant_namespace: String,
    pub role_descriptions: BTreeMap<String, String>,
    pub sensitive_roles: Vec<String>,
    pub sensitive_namespaces: Vec<Glob>,
    /// Where every grant's ServiceAccount lives: a namespace no grant may
    /// target, so nobody with rights in a target namespace can run a pod
    /// as another grant's ServiceAccount.
    pub grant_namespace: String,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        KubernetesConfig {
            namespace_allowlist: Vec::new(),
            role_allowlist: strings(&["view"]),
            cluster_role_allowlist: Vec::new(),
            cluster_grant_namespace: "default".to_owned(),
            role_descriptions: BTreeMap::new(),
            sensitive_roles: strings(&["edit", "admin"]),
            sensitive_namespaces: globs(&[
                "kube-system",
                "kube-public",
                "kube-node-lease",
                "flux-system",
            ]),
            grant_namespace: "agent-auth-grants".to_owned(),
        }
    }
}

/// A glob matched against case-folded (lowercased) resources: lowercased
/// too, or a pattern with a capital would never match (and a denylist
/// would fail open).
fn lower_glob(g: &Glob) -> Glob {
    Glob::new(&g.as_str().to_lowercase())
}

impl GithubConfig {
    /// Repos are matched lowercased (`owner/repo`).
    pub(crate) fn normalize(&mut self) {
        self.repo_allowlist = self.repo_allowlist.iter().map(lower_glob).collect();
        self.repo_denylist = self.repo_denylist.iter().map(lower_glob).collect();
    }
}

impl KubernetesConfig {
    /// Namespaces are matched lowercased; the grant namespace must be a
    /// namespace name.
    pub(crate) fn normalize(&mut self) -> Result<(), String> {
        self.namespace_allowlist = self.namespace_allowlist.iter().map(lower_glob).collect();
        self.sensitive_namespaces = self.sensitive_namespaces.iter().map(lower_glob).collect();
        self.cluster_grant_namespace = self.cluster_grant_namespace.to_lowercase();
        self.grant_namespace = self.grant_namespace.to_lowercase();
        if !label63(&self.grant_namespace) {
            return Err("grant_namespace: a namespace name".to_owned());
        }
        Ok(())
    }

    #[must_use]
    pub fn namespace_is_sensitive(&self, namespace: &str) -> bool {
        namespace == self.cluster_grant_namespace
            || self
                .sensitive_namespaces
                .iter()
                .any(|g| g.matches(namespace))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsConfig {
    /// Runtimes an agent VM may mint identities for.
    pub runtimes: Vec<String>,
    /// A minted agent's identity lease.
    pub lease: DurationSecs,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        AgentsConfig {
            runtimes: strings(&["claude", "codex"]),
            lease: secs("30d"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HostexecConfig {
    /// Mirrors of the hosts' templates, for early checks and display.
    pub templates: BTreeMap<TemplateName, Template>,
    pub risk_summary: bool,
    /// Default: `llm.model`.
    pub risk_model: Option<String>,
    pub watch: bool,
    pub window_default: DurationSecs,
    pub window_max: DurationSecs,
}

impl Default for HostexecConfig {
    fn default() -> Self {
        HostexecConfig {
            templates: BTreeMap::new(),
            risk_summary: true,
            risk_model: None,
            watch: true,
            window_default: secs("30m"),
            window_max: secs("8h"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tools: Vec<String>,
    /// Default: the url.
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct McpConfig {
    pub issuer: String,
    pub token_ttl: DurationSecs,
    pub servers: BTreeMap<McpServerName, McpServer>,
}

impl Default for McpConfig {
    fn default() -> Self {
        McpConfig {
            issuer: String::new(),
            token_ttl: secs("1h"),
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModelsConfig {
    pub name: String,
    pub url: String,
    pub admin_url: Option<String>,
    pub models: Vec<String>,
    pub by_runtime: BTreeMap<String, Vec<String>>,
    pub max_budget: Option<f64>,
    pub budget_duration: String,
}

impl Default for ModelsConfig {
    fn default() -> Self {
        ModelsConfig {
            name: "litellm".to_owned(),
            url: String::new(),
            admin_url: None,
            models: Vec::new(),
            by_runtime: BTreeMap::new(),
            max_budget: None,
            budget_duration: "30d".to_owned(),
        }
    }
}

/// One Google account the broker holds a login for: an OAuth client and a
/// refresh token (any Gmail or Workspace account), or, on Workspace, a
/// service account with domain-wide delegation acting as `subject`. The
/// files are secrets (LoadCredential paths); nothing secret is in here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleAccount {
    /// Lowercased at load.
    pub address: String,
    /// The OAuth client JSON from the Google Cloud console.
    #[serde(default)]
    pub client_secret_file: String,
    /// The refresh token `agent-auth admin google-consent` wrote.
    #[serde(default)]
    pub refresh_token_file: String,
    /// Workspace only: a service account key with domain-wide delegation.
    #[serde(default)]
    pub service_account_file: String,
    /// Whom the service account acts as; default: the address.
    #[serde(default)]
    pub subject: Option<String>,
}

/// Google accounts (platform `google`). Calendar and Drive grants are
/// access tokens for the Google API, account-wide by Google's design;
/// Gmail is never one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GoogleConfig {
    pub accounts: BTreeMap<String, GoogleAccount>,
}

/// `[^@\s]+@[^@\s]+\.[^@\s]+`, whole string.
#[must_use]
pub fn email_address_ok(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    let plain = |s: &str| !s.is_empty() && !s.chars().any(|c| c == '@' || c.is_whitespace());
    // The domain's last dot must leave something on both sides.
    let dotted = domain
        .rsplit_once('.')
        .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty());
    plain(local) && plain(domain) && dotted
}

/// `[a-z0-9][a-z0-9_-]{0,62}`: a Google account's or a pool's name.
#[must_use]
pub fn config_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

impl GoogleConfig {
    pub(crate) fn normalize(&mut self) -> Result<(), String> {
        for (name, account) in &mut self.accounts {
            if !config_name_ok(name) {
                return Err(format!(
                    "google account name {}: lowercase letters, digits, - and _",
                    repr(name)
                ));
            }
            if !email_address_ok(&account.address) {
                return Err(format!(
                    "google account address {} is not an email address",
                    repr(&account.address)
                ));
            }
            account.address = account.address.to_lowercase();
            let oauth =
                !account.client_secret_file.is_empty() && !account.refresh_token_file.is_empty();
            if oauth == !account.service_account_file.is_empty() {
                return Err(format!(
                    "google account {}: either client_secret_file + refresh_token_file, \
                     or service_account_file (Workspace domain-wide delegation)",
                    account.address
                ));
            }
        }
        Ok(())
    }
}

/// One thing in a pool: what it is (properties, shown to agents) and its
/// secret (what the holder's credential returns).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolItem {
    pub description: String,
    pub properties: BTreeMap<String, PropValue>,
    /// Returned to the holder as the credential, verbatim.
    pub secret_file: String,
    /// Only leased by name, and always by a human.
    pub sensitive: bool,
    /// Who may hold it; empty: whoever the pool admits.
    pub agents: Vec<AgentPattern>,
}

/// Scarce things (accounts, licences, devices) an agent holds alone for a
/// while: platform `pool`, capability `lease`, resource the pool.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolConfig {
    pub description: String,
    /// By name. "Any" tries them in name order (the policy is read as JSON,
    /// whose objects keep no order).
    pub items: BTreeMap<String, PoolItem>,
    /// Holders of one item at once: 1 to 100.
    pub capacity: u32,
    /// Items of this pool one agent may hold at once: at least 1.
    pub max_per_agent: u32,
    /// Who may lease from it at all; empty: anyone.
    pub agents: Vec<AgentPattern>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            description: String::new(),
            items: BTreeMap::new(),
            capacity: 1,
            max_per_agent: 1,
            agents: Vec::new(),
        }
    }
}

/// The largest `max_per_agent` (a slot number is stored as an integer).
pub const MAX_POOL_PER_AGENT: u32 = 10_000;

impl PoolConfig {
    pub(crate) fn validate(&self, name: &str) -> Result<(), String> {
        if !config_name_ok(name) {
            return Err(format!(
                "pool name {}: lowercase letters, digits, - and _",
                repr(name)
            ));
        }
        for item in self.items.keys() {
            if !item_name_ok(item) {
                return Err(format!("pool item {}: letters, digits, . _ -", repr(item)));
            }
        }
        if !(1..=100).contains(&self.capacity) {
            return Err(format!("platforms.pools.{name}.capacity: from 1 to 100"));
        }
        if !(1..=MAX_POOL_PER_AGENT).contains(&self.max_per_agent) {
            return Err(format!(
                "platforms.pools.{name}.max_per_agent: from 1 to {MAX_POOL_PER_AGENT}"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PlatformsConfig {
    pub github: GithubConfig,
    pub homelab: HomelabConfig,
    pub kubernetes: KubernetesConfig,
    pub agents: AgentsConfig,
    pub hostexec: HostexecConfig,
    pub mcp: McpConfig,
    pub models: ModelsConfig,
    pub google: GoogleConfig,
    /// Platform `pool`: scarce things, by pool name.
    pub pools: BTreeMap<String, PoolConfig>,
    pub mail: super::mail::MailConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DesktopConfig {
    pub enabled: bool,
    pub agents: Vec<AgentPattern>,
    /// Empty = every platform.
    pub platforms: Vec<Platform>,
    pub sensitive: bool,
    pub timeout: DurationSecs,
    pub per_agent_per_hour: u32,
    pub per_hour: u32,
    pub deny_cooldown: DurationSecs,
    pub mute: DurationSecs,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        DesktopConfig {
            enabled: false,
            agents: Vec::new(),
            platforms: Vec::new(),
            sensitive: false,
            timeout: secs("90s"),
            per_agent_per_hour: 6,
            per_hour: 20,
            deny_cooldown: secs("10m"),
            mute: secs("1h"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WikiConfig {
    /// "owner/name"; empty = no wiki.
    pub repo: String,
    pub branch: String,
    pub editors: Vec<AgentPattern>,
    pub max_page_bytes: u32,
    pub refresh_secs: u32,
}

impl Default for WikiConfig {
    fn default() -> Self {
        WikiConfig {
            repo: String::new(),
            branch: "main".to_owned(),
            editors: Vec::new(),
            max_page_bytes: 64 * 1024,
            refresh_secs: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    pub enabled: bool,
    pub base_url: String,
    pub issuer: String,
    pub client_id: String,
    pub admin_group: String,
    pub session_ttl: DurationSecs,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            enabled: false,
            base_url: String::new(),
            issuer: String::new(),
            client_id: "agent-auth-admin".to_owned(),
            admin_group: "agent-auth-admins".to_owned(),
            session_ttl: secs("8h"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NotifyConfig {
    pub auto_approvals: bool,
    pub skip_platforms: Vec<Platform>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ContainmentConfig {
    /// Which agents may contain others.
    pub agents: Vec<AgentPattern>,
    /// May they contain every agent at once?
    pub allow_all: bool,
}

/// Resources only these agents reach (zones).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedZone {
    /// At least one.
    pub members: Vec<AgentPattern>,
    /// Namespace globs.
    #[serde(default)]
    pub kubernetes: Vec<Glob>,
    /// owner/repo globs.
    #[serde(default)]
    pub github: Vec<Glob>,
    /// May members write the shared wiki?
    #[serde(default)]
    pub wiki: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    pub readers: Vec<AgentPattern>,
}

/// Evals: recording the broker's model decisions, and replaying them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvalsConfig {
    /// Record every model call (facts, prompts, answer). Default true.
    pub record: bool,
    /// How long unlabelled calls (and replays) are kept. Labelled calls
    /// are the eval set and are kept until unlabelled.
    pub retention: DurationSecs,
    /// Model calls a replay makes at once (1..=16).
    pub replay_concurrency: u8,
    /// Calls one replay may take at most (1..=2000).
    pub max_replay: u32,
}

impl Default for EvalsConfig {
    fn default() -> Self {
        EvalsConfig {
            record: true,
            retention: secs("90d"),
            replay_concurrency: 4,
            max_replay: 500,
        }
    }
}

impl EvalsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=16).contains(&self.replay_concurrency) {
            return Err("evals.replay_concurrency: 1 to 16".to_owned());
        }
        if !(1..=2000).contains(&self.max_replay) {
            return Err("evals.max_replay: 1 to 2000".to_owned());
        }
        Ok(())
    }
}

/// The tools a web UI gets by default.
pub const REMOTE_MCP_TOOLS: [&str; 23] = [
    "whoami",
    "list_capabilities",
    "list_grants",
    "request_access",
    "wait_for_decision",
    "check_status",
    "retry_request",
    "escalate_request",
    "create_session",
    "close_session",
    "check_a2a",
    "a2a_open",
    "a2a_send",
    "a2a_poll",
    "a2a_threads",
    "a2a_accept",
    "a2a_reject",
    "a2a_close",
    "wiki_search",
    "wiki_read",
    "wiki_list",
    "notify_operator",
    // Ending one's own grant only ever takes access away.
    "release_grant",
];

/// Every MCP tool's name (`mcp_names.TOOL_NAMES`). The MCP crate keeps its
/// tools and this list the same.
pub const MCP_TOOL_NAMES: [&str; 36] = [
    "whoami",
    "list_capabilities",
    "request_access",
    "wait_for_decision",
    "check_status",
    "retry_request",
    "escalate_request",
    "list_grants",
    "get_credential",
    "release_grant",
    "mail_list",
    "mail_read",
    "mail_attachment",
    "mail_send",
    "create_session",
    "close_session",
    "check_a2a",
    "a2a_open",
    "a2a_send",
    "a2a_poll",
    "a2a_threads",
    "a2a_accept",
    "a2a_reject",
    "a2a_close",
    "a2a_events",
    "wiki_search",
    "wiki_read",
    "wiki_list",
    "wiki_write",
    "wiki_delete",
    "notify_operator",
    "host_run",
    "host_job",
    "host_shell_exec",
    "host_shell_close",
    "host_shell_scope",
];

/// The web UIs' OAuth callbacks a connector may register by default:
/// Claude (claude.ai and claude.com) and ChatGPT.
pub const REMOTE_MCP_REDIRECT_URIS: [&str; 3] = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
];

/// Whether `uri` may be a registrable callback: `https://`, a host, no
/// fragment, no userinfo (`@`), no backslashes (browsers and URL parsers
/// disagree on both), no whitespace or control characters, at most 512
/// characters.
#[must_use]
pub fn redirect_uri_ok(uri: &str) -> bool {
    uri.len() <= 512
        && uri
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && !uri.contains(['#', '@', '\\'])
        && !uri.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RemoteMcpConfig {
    pub enabled: bool,
    pub base_url: String,
    /// The callback URIs a connector may register, compared exactly
    /// (the Python allowed any https URI on a listed host).
    pub redirect_uris: Vec<String>,
    pub tools: Vec<String>,
    pub access_ttl: DurationSecs,
    pub refresh_ttl: DurationSecs,
    pub max_clients: u32,
}

impl Default for RemoteMcpConfig {
    fn default() -> Self {
        RemoteMcpConfig {
            enabled: false,
            base_url: String::new(),
            redirect_uris: strings(&REMOTE_MCP_REDIRECT_URIS),
            tools: strings(&REMOTE_MCP_TOOLS),
            access_ttl: secs("1h"),
            refresh_ttl: secs("30d"),
            max_clients: 50,
        }
    }
}

// ------------------------------------------------------------ validation
// The field validators pydantic ran after parsing a section.

/// `[a-z0-9][a-z0-9-]{0,62}`
fn label63(s: &str) -> bool {
    crate::names::DaemonName::parse(s).is_ok()
}

/// `https?://[^\s/]+(/[^\s]*)?`, whole string.
fn http_url(s: &str) -> bool {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    let Some(rest) = rest else { return false };
    let is_space = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    let (host, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    !host.is_empty() && !host.chars().any(is_space) && !path.chars().any(is_space)
}

impl HomelabConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.managed_username_prefix.chars().count() > 32 {
            return Err("managed_username_prefix: at most 32 characters".to_owned());
        }
        if self.managed_email_domain.is_empty() {
            return Err("managed_email_domain: at least 1 character".to_owned());
        }
        Ok(())
    }
}

impl McpConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !self.servers.is_empty() && !self.issuer.starts_with("https://") {
            return Err(
                "platforms.mcp.issuer (the broker's https URL) is required when servers are listed"
                    .to_owned(),
            );
        }
        // A token is checked only against its audience: two servers with
        // one audience would accept each other's tokens.
        let mut seen = std::collections::BTreeMap::new();
        for (name, server) in &self.servers {
            let aud = server
                .audience
                .as_deref()
                .filter(|a| !a.is_empty())
                .unwrap_or(&server.url);
            if let Some(other) = seen.insert(aud, name) {
                return Err(format!(
                    "platforms.mcp.servers: {other} and {name} have the same audience {}",
                    repr(aud)
                ));
            }
        }
        Ok(())
    }
}

impl ModelsConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for value in std::iter::once(&self.url).chain(self.admin_url.iter()) {
            if !value.is_empty() && !http_url(value) {
                return Err(format!(
                    "platforms.models: {} is not an http(s) URL",
                    repr(value)
                ));
            }
        }
        if !label63(&self.name) {
            return Err("platforms.models.name: lowercase letters, digits and dashes".to_owned());
        }
        if self.max_budget.is_some_and(|b| !b.is_finite()) {
            return Err("platforms.models.max_budget: a number".to_owned());
        }
        Ok(())
    }
}

impl WikiConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let part = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        };
        let ok = self.repo.is_empty()
            || self
                .repo
                .split_once('/')
                .is_some_and(|(owner, name)| part(owner) && part(name));
        if ok {
            Ok(())
        } else {
            Err(format!("wiki.repo {}: owner/name", repr(&self.repo)))
        }
    }
}

impl UiConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.enabled {
            for (name, value) in [("base_url", &self.base_url), ("issuer", &self.issuer)] {
                if !value.starts_with("https://") {
                    return Err(format!(
                        "ui.{name}: an https URL is required when the panel is enabled"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl RestrictedZone {
    /// Namespaces and repos are matched lowercased.
    pub(crate) fn normalize(&mut self) {
        self.kubernetes = self.kubernetes.iter().map(lower_glob).collect();
        self.github = self.github.iter().map(lower_glob).collect();
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.members.is_empty() {
            return Err("members: at least one agent pattern".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(http_url("https://litellm.example"));
        assert!(http_url("http://10.0.0.1:4000/v1"));
        assert!(!http_url("https://"));
        assert!(!http_url("ftp://x"));
        assert!(!http_url("https://a b"));
        assert!(!http_url("https:///x"));
        assert!(http_url("https://a/"));
    }

    #[test]
    fn redirect_uris_with_userinfo_or_backslashes_are_refused() {
        assert!(redirect_uri_ok("https://claude.ai/api/mcp/auth_callback"));
        for bad in [
            "https://evil.example\\@claude.ai/cb",
            "https://u@claude.ai/cb",
            "https://claude.ai/a b",
            "https://claude.ai/a\tb",
            "https://claude.ai/cb#x",
            "http://claude.ai/cb",
        ] {
            assert!(!redirect_uri_ok(bad), "{bad}");
        }
        assert!(!redirect_uri_ok(&format!(
            "https://claude.ai/{}",
            "a".repeat(600)
        )));
    }

    #[test]
    fn tool_lists() {
        for tool in REMOTE_MCP_TOOLS {
            assert!(MCP_TOOL_NAMES.contains(&tool), "{tool}");
        }
        let mut names = MCP_TOOL_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), MCP_TOOL_NAMES.len());
    }
}
