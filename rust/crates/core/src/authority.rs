//! The privilege a grant conveys over its resource.
//!
//! On the wire a request carries `(platform, capability, scope)`; each
//! platform keeps its privilege in whichever of the two is ergonomic
//! (Kubernetes in the capability, GitHub in the scope). The Python kept one
//! canonical dict per platform (`authority.fold`); here it is a typed enum
//! whose variant *is* the platform, so a platform/authority mismatch cannot
//! be represented, and rule pinning compares typed values instead of dicts.
//!
//! `Authority::from_wire` checks structure only (types, known keys, sizes);
//! each platform's validator in the broker applies allowlists and ceilings
//! and may return a narrowed authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map, Value, json};

use crate::glob::Glob;
use crate::platform::Platform;
use crate::pool::{MAX_MATCH_KEYS, MAX_PROP_CHARS, PoolChoice, PropMatch, PropValue, match_covers};

/// Structural problems with a request's capability/scope. The text is shown
/// to the requesting agent (prefixed "validator: ").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AuthorityError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, AuthorityError> {
    Err(AuthorityError(msg.into()))
}

// ---------------------------------------------------------------- github

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GithubAccess {
    Read,
    Write,
    Admin,
}

impl GithubAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GithubAccess::Read => "read",
            GithubAccess::Write => "write",
            GithubAccess::Admin => "admin",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    Private,
    Public,
}

impl Visibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Public => "public",
        }
    }
}

/// A GitHub App permission name (`contents`, `pull_requests`, ...).
pub type GithubPermissions = BTreeMap<String, GithubAccess>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GithubAuthority {
    /// Installation tokens for one repo with these permissions.
    Repo { permissions: GithubPermissions },
    /// The broker creates the repo. A different privilege from any access
    /// to one: no rule pinned to repo access ever covers a create.
    Create { visibility: Visibility },
}

// ------------------------------------------------------------ kubernetes

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KubernetesAuthority {
    /// The (Cluster)Role bound.
    pub role: String,
    /// Bound cluster-wide (ClusterRoleBinding): always a human's call.
    pub cluster: bool,
}

// -------------------------------------------------------------- sandbox

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectAccess {
    Read,
    Write,
}

impl ProjectAccess {
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            ProjectAccess::Read => "project.read",
            ProjectAccess::Write => "project.write",
        }
    }
}

// ------------------------------------------------------------- hostexec

/// Who a host command runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    User,
    Root,
}

impl Tier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::User => "user",
            Tier::Root => "root",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "root" => Some(Self::Root),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a run/tpl command carries besides its argv or template.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandOptions {
    pub tier: Tier,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<u32>,
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostexecAuthority {
    /// One command. The whole command is the privilege: a rule pinned to
    /// one argv never approves another.
    Run {
        argv: Vec<String>,
        options: CommandOptions,
    },
    /// One run of a template the host defines.
    Template {
        template: String,
        params: BTreeMap<String, String>,
        options: CommandOptions,
    },
    /// A time-boxed shell: every one is opened by a human with a TOTP code.
    Shell { tier: Tier },
    /// Only ever a saved rule's authority: an "approve all" window covering
    /// any run/tpl command of its tier (never a shell).
    Window { tier: Tier },
}

impl HostexecAuthority {
    #[must_use]
    pub fn tier(&self) -> Tier {
        match self {
            HostexecAuthority::Run { options, .. }
            | HostexecAuthority::Template { options, .. } => options.tier,
            HostexecAuthority::Shell { tier } | HostexecAuthority::Window { tier } => *tier,
        }
    }
}

// ------------------------------------------------------------------ mcp

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolSet {
    All,
    /// Non-empty, sorted, no "*".
    Some(BTreeSet<String>),
}

impl ToolSet {
    /// Does `self` (a rule's tools) cover `wanted`? All covers everything;
    /// a set covers subsets of itself and never All.
    #[must_use]
    pub fn covers(&self, wanted: &ToolSet) -> bool {
        match (self, wanted) {
            (ToolSet::All, _) => true,
            (ToolSet::Some(_), ToolSet::All) => false,
            (ToolSet::Some(allowed), ToolSet::Some(wanted)) => wanted.is_subset(allowed),
        }
    }
}

// ------------------------------------------------------------- authority

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Authority {
    Github(GithubAuthority),
    /// Membership of the LLDAP group named by the resource.
    Homelab,
    Kubernetes(KubernetesAuthority),
    /// Opening threads to the resource agent, optionally only on topics
    /// matching the glob.
    A2a {
        topic: Option<Glob>,
    },
    Google {
        action: String,
    },
    /// Minting an identity in an agent VM.
    Agents {
        action: String,
        runtime: Option<String>,
    },
    Sandbox {
        access: ProjectAccess,
    },
    Hostexec(HostexecAuthority),
    Mcp {
        tools: ToolSet,
    },
    Models,
    /// A lease of one item of the pool named by the resource.
    Pool(PoolChoice),
}

/// The Google capabilities a grant may carry (each one access-token
/// scope). Gmail is never one: mail goes through the broker.
pub const GOOGLE_CAPABILITIES: [&str; 3] = ["calendar.read", "calendar.write", "drive.read"];

/// The parts of the policy configuration that sensitivity depends on.
#[derive(Debug, Clone)]
pub struct SensitivityConfig {
    pub github_sensitive_permissions: BTreeSet<String>,
    pub kubernetes_sensitive_roles: BTreeSet<String>,
    pub kubernetes_sensitive_namespaces: Vec<Glob>,
    /// Its ServiceAccounts back cluster-wide grants: always sensitive.
    pub kubernetes_cluster_grant_namespace: String,
    /// Per pool, its items marked sensitive (leased by name, by a human).
    pub pool_sensitive_items: BTreeMap<String, BTreeSet<String>>,
}

impl Default for SensitivityConfig {
    fn default() -> Self {
        SensitivityConfig {
            github_sensitive_permissions: ["secrets", "administration"].map(String::from).into(),
            kubernetes_sensitive_roles: ["edit", "admin"].map(String::from).into(),
            kubernetes_sensitive_namespaces: [
                "kube-system",
                "kube-public",
                "kube-node-lease",
                "flux-system",
            ]
            .map(Glob::new)
            .into(),
            kubernetes_cluster_grant_namespace: "default".to_owned(),
            pool_sensitive_items: BTreeMap::new(),
        }
    }
}

impl SensitivityConfig {
    #[must_use]
    pub fn namespace_is_sensitive(&self, namespace: &str) -> bool {
        namespace == self.kubernetes_cluster_grant_namespace
            || self
                .kubernetes_sensitive_namespaces
                .iter()
                .any(|g| g.matches(namespace))
    }
}

impl Authority {
    #[must_use]
    pub fn platform(&self) -> Platform {
        match self {
            Authority::Github(_) => Platform::Github,
            Authority::Homelab => Platform::Homelab,
            Authority::Kubernetes(_) => Platform::Kubernetes,
            Authority::A2a { .. } => Platform::A2a,
            Authority::Google { .. } => Platform::Google,
            Authority::Agents { .. } => Platform::Agents,
            Authority::Sandbox { .. } => Platform::Sandbox,
            Authority::Hostexec(_) => Platform::Hostexec,
            Authority::Mcp { .. } => Platform::Mcp,
            Authority::Models => Platform::Models,
            Authority::Pool(_) => Platform::Pool,
        }
    }

    /// May only a rule that names this authority clear it (approve or route
    /// to the LLM)? Catch-all rules never do.
    #[must_use]
    pub fn needs_explicit_rule(&self) -> bool {
        matches!(
            self,
            Authority::Github(GithubAuthority::Create { .. })
                | Authority::Agents { .. }
                | Authority::Hostexec(_)
                | Authority::Mcp { .. }
                | Authority::Models
                // Someone's accounts, calendar, files: only a rule written
                // for that platform, never a catch-all for an agent.
                | Authority::Pool(_)
                | Authority::Google { .. }
        )
    }

    /// Never decided by a rule or the LLM, whoever wrote the rule.
    #[must_use]
    pub fn human_only(&self) -> bool {
        matches!(self, Authority::Hostexec(HostexecAuthority::Shell { .. }))
    }

    /// Does this authority (over that resource) always require a human,
    /// whatever the policy routing says (unless a human's pinned rule)?
    #[must_use]
    pub fn is_sensitive(&self, cfg: &SensitivityConfig, resource: &str) -> bool {
        self.sensitive_at(cfg, Some(resource))
    }

    /// Sensitive because of *where* (the resource: a sensitive namespace, a
    /// pool's sensitive item), not *what* (the authority itself): only a
    /// pinned rule naming that very resource clears it (`engine
    /// .sensitive_by_resource`).
    #[must_use]
    pub fn sensitive_by_resource(&self, cfg: &SensitivityConfig, resource: &str) -> bool {
        self.sensitive_at(cfg, Some(resource)) && !self.sensitive_at(cfg, None)
    }

    /// `is_sensitive` with the resource, or without one (`None`: what the
    /// authority alone makes sensitive).
    fn sensitive_at(&self, cfg: &SensitivityConfig, resource: Option<&str>) -> bool {
        match self {
            Authority::Github(GithubAuthority::Create { visibility }) => {
                *visibility != Visibility::Private
            }
            Authority::Github(GithubAuthority::Repo { permissions }) => permissions
                .keys()
                .any(|p| cfg.github_sensitive_permissions.contains(p)),
            Authority::Kubernetes(k) => {
                k.cluster
                    || resource.is_some_and(|r| cfg.namespace_is_sensitive(r))
                    || cfg.kubernetes_sensitive_roles.contains(&k.role)
            }
            // A named item marked sensitive.
            Authority::Pool(PoolChoice::Item(item)) => resource.is_some_and(|pool| {
                cfg.pool_sensitive_items
                    .get(pool)
                    .is_some_and(|items| items.contains(item))
            }),
            // Writing a calendar, or reading every file in a Drive.
            Authority::Google { action } => {
                matches!(action.as_str(), "calendar.write" | "drive.read")
            }
            Authority::Sandbox { access } => *access == ProjectAccess::Write,
            Authority::Hostexec(h) => {
                h.tier() == Tier::Root || matches!(h, HostexecAuthority::Shell { .. })
            }
            _ => false,
        }
    }

    /// The wire capability (`split(...)[0]` in the Python).
    #[must_use]
    pub fn capability(&self) -> String {
        match self {
            Authority::Github(GithubAuthority::Create { .. }) => "create".to_owned(),
            Authority::Github(GithubAuthority::Repo { .. }) => "repo".to_owned(),
            Authority::Homelab => "group".to_owned(),
            Authority::Kubernetes(k) => k.role.clone(),
            Authority::A2a { .. } => "talk".to_owned(),
            Authority::Google { action } | Authority::Agents { action, .. } => action.clone(),
            Authority::Sandbox { access } => access.capability().to_owned(),
            Authority::Hostexec(HostexecAuthority::Shell { .. }) => "shell".to_owned(),
            Authority::Hostexec(HostexecAuthority::Template { template, .. }) => {
                format!("tpl.{template}")
            }
            Authority::Hostexec(
                HostexecAuthority::Run { .. } | HostexecAuthority::Window { .. },
            ) => "run".to_owned(),
            Authority::Mcp { .. } | Authority::Models => "use".to_owned(),
            Authority::Pool(_) => "lease".to_owned(),
        }
    }

    /// The wire scope (`split(...)[1]`).
    #[must_use]
    pub fn scope(&self) -> Map<String, Value> {
        let value = match self {
            Authority::Github(GithubAuthority::Create { visibility }) => {
                json!({"visibility": visibility.as_str()})
            }
            Authority::Github(GithubAuthority::Repo { permissions }) => {
                json!({"permissions": permissions_json(permissions)})
            }
            Authority::Kubernetes(k) if k.cluster => json!({"cluster": true}),
            Authority::A2a { topic: Some(t) } => json!({"topic": t.as_str()}),
            Authority::Agents { runtime, .. } => json!({"runtime": runtime}),
            Authority::Hostexec(
                HostexecAuthority::Shell { tier } | HostexecAuthority::Window { tier },
            ) => {
                json!({"tier": tier.as_str()})
            }
            Authority::Hostexec(HostexecAuthority::Run { argv, options }) => {
                let mut scope = options_scope(options);
                scope.insert("argv".to_owned(), json!(argv));
                Value::Object(scope)
            }
            Authority::Hostexec(HostexecAuthority::Template {
                params, options, ..
            }) => {
                let mut scope = options_scope(options);
                scope.insert("params".to_owned(), json!(params));
                Value::Object(scope)
            }
            Authority::Mcp { tools } => json!({"tools": tools_json(tools)}),
            Authority::Pool(PoolChoice::Item(item)) => json!({"item": item}),
            Authority::Pool(PoolChoice::Previous) => json!({"previous": true}),
            Authority::Pool(PoolChoice::Any(m)) if !m.is_empty() => {
                json!({"match": match_json(m)})
            }
            _ => json!({}),
        };
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    /// Short human/policy-facing name (admin listings, rule display).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Authority::Github(GithubAuthority::Create { visibility }) => {
                format!("create:{}", visibility.as_str())
            }
            Authority::Github(GithubAuthority::Repo { permissions }) => {
                let joined: Vec<String> = permissions
                    .iter()
                    .map(|(k, v)| format!("{k}:{}", v.as_str()))
                    .collect();
                if joined.is_empty() {
                    "repo".to_owned()
                } else {
                    joined.join("+")
                }
            }
            Authority::Kubernetes(k) => {
                let role = if k.role.is_empty() {
                    "*"
                } else {
                    k.role.as_str()
                };
                if k.cluster {
                    format!("{role} (cluster-wide)")
                } else {
                    role.to_owned()
                }
            }
            Authority::Agents { runtime, .. } => {
                format!("mint:{}", runtime.as_deref().unwrap_or("?"))
            }
            Authority::Mcp {
                tools: ToolSet::All,
            } => "all tools".to_owned(),
            Authority::Mcp {
                tools: ToolSet::Some(tools),
            } => tools.iter().cloned().collect::<Vec<_>>().join(","),
            Authority::Hostexec(HostexecAuthority::Window { tier }) => {
                format!("approve-all:{tier}")
            }
            Authority::Hostexec(HostexecAuthority::Template {
                template, options, ..
            }) => {
                format!("tpl.{template}:{}", options.tier)
            }
            Authority::Hostexec(HostexecAuthority::Run { options, .. }) => {
                format!("run:{}", options.tier)
            }
            Authority::Hostexec(HostexecAuthority::Shell { tier }) => format!("shell:{tier}"),
            Authority::Pool(PoolChoice::Item(item)) => format!("lease:{item}"),
            Authority::Pool(PoolChoice::Previous) => "lease:previous".to_owned(),
            Authority::Pool(PoolChoice::Any(m)) => {
                if m.is_empty() {
                    "lease:any".to_owned()
                } else {
                    let parts: Vec<String> = m
                        .iter()
                        .map(|(k, v)| format!("{k}={}", v.py_str()))
                        .collect();
                    format!("lease:{}", parts.join(","))
                }
            }
            other => {
                let cap = other.capability();
                if cap.is_empty() { "*".to_owned() } else { cap }
            }
        }
    }

    /// Parse a request's wire `(capability, scope)` for `platform`, checking
    /// structure only. Unknown scope keys are refused (the Python ignored
    /// them on most platforms, and stored a2a's verbatim).
    pub fn from_wire(
        platform: Platform,
        capability: &str,
        scope: &Map<String, Value>,
    ) -> Result<Authority, AuthorityError> {
        match platform {
            Platform::Github => github_from_wire(capability, scope),
            Platform::Homelab => {
                only_keys(scope, &[], "a homelab grant takes no scope")?;
                if !capability.is_empty() && capability != "group" {
                    return err("homelab capability is \"group\"");
                }
                Ok(Authority::Homelab)
            }
            Platform::Kubernetes => {
                only_keys(
                    scope,
                    &["cluster"],
                    "a kubernetes scope is {\"cluster\": true} or empty",
                )?;
                let cluster = match scope.get("cluster") {
                    None | Some(Value::Null) | Some(Value::Bool(false)) => false,
                    Some(Value::Bool(true)) => true,
                    Some(_) => return err("\"cluster\" must be true or false"),
                };
                if capability.is_empty() {
                    return err("kubernetes capability is the role name");
                }
                Ok(Authority::Kubernetes(KubernetesAuthority {
                    role: capability.to_owned(),
                    cluster,
                }))
            }
            Platform::A2a => {
                if capability != "talk" {
                    return err("a2a capability must be 'talk'");
                }
                only_keys(
                    scope,
                    &["topic"],
                    "an a2a scope is {\"topic\": \"<glob>\"} or empty",
                )?;
                let topic = match scope.get("topic") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(t)) if t == "*" => None,
                    Some(Value::String(t)) if !t.is_empty() && t.len() <= 256 => Some(Glob::new(t)),
                    Some(_) => return err("\"topic\" must be a glob of 1 to 256 characters"),
                };
                Ok(Authority::A2a { topic })
            }
            Platform::Google => {
                only_keys(scope, &[], "a google grant takes no scope")?;
                Ok(Authority::Google {
                    action: capability.to_owned(),
                })
            }
            Platform::Agents => {
                only_keys(
                    scope,
                    &["runtime"],
                    "an agents scope is {\"runtime\": \"<runtime>\"}",
                )?;
                let runtime = match scope.get("runtime") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(r)) => Some(r.clone()),
                    Some(_) => return err("\"runtime\" must be a string"),
                };
                Ok(Authority::Agents {
                    action: capability.to_owned(),
                    runtime,
                })
            }
            Platform::Sandbox => {
                only_keys(scope, &[], "a sandbox grant takes no scope")?;
                let access = match capability {
                    "project.read" => ProjectAccess::Read,
                    "project.write" => ProjectAccess::Write,
                    _ => return err("sandbox capability is \"project.read\" or \"project.write\""),
                };
                Ok(Authority::Sandbox { access })
            }
            Platform::Hostexec => hostexec_from_wire(capability, scope),
            Platform::Mcp => {
                if capability != "use" {
                    return err("mcp capability is \"use\"");
                }
                only_keys(
                    scope,
                    &["tools"],
                    "an mcp scope is {\"tools\": [...]} (omit it for every tool)",
                )?;
                let tools = match scope.get("tools") {
                    None | Some(Value::Null) => ToolSet::All,
                    Some(Value::Array(items))
                        if !items.is_empty() && items.len() <= MAX_MCP_TOOLS =>
                    {
                        let mut set = BTreeSet::new();
                        for item in items {
                            match item {
                                Value::String(s) => {
                                    set.insert(s.clone());
                                }
                                _ => return err("malformed tool name"),
                            }
                        }
                        if set.contains("*") {
                            ToolSet::All
                        } else {
                            ToolSet::Some(set)
                        }
                    }
                    Some(_) => {
                        return err(format!(
                            "\"tools\" is a list of 1 to {MAX_MCP_TOOLS} tool names, or [\"*\"]"
                        ));
                    }
                };
                Ok(Authority::Mcp { tools })
            }
            Platform::Models => {
                if capability != "use" {
                    return err("models capability is \"use\"");
                }
                only_keys(scope, &[], "a models grant takes no scope")?;
                Ok(Authority::Models)
            }
            Platform::Pool => pool_from_wire(capability, scope),
        }
    }

    /// The canonical stored form (`grants.authority`, `rules.authority`):
    /// the Python's dict shape, so the stored JSON stays readable.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Authority::Github(GithubAuthority::Create { visibility }) => {
                json!({"action": "create", "visibility": visibility.as_str()})
            }
            Authority::Github(GithubAuthority::Repo { permissions }) => {
                json!({"permissions": permissions_json(permissions)})
            }
            Authority::Homelab => json!({}),
            Authority::Kubernetes(k) if k.cluster => json!({"role": k.role, "cluster": true}),
            Authority::Kubernetes(k) => json!({"role": k.role}),
            Authority::A2a { topic: Some(t) } => json!({"topic": t.as_str()}),
            Authority::A2a { topic: None } => json!({}),
            Authority::Google { action } => json!({"action": action}),
            Authority::Agents { action, runtime } => json!({"action": action, "runtime": runtime}),
            Authority::Sandbox { access } => json!({"access": access.capability()}),
            Authority::Hostexec(HostexecAuthority::Shell { tier }) => {
                json!({"action": "shell", "tier": tier.as_str()})
            }
            Authority::Hostexec(HostexecAuthority::Window { tier }) => {
                json!({"action": "window", "tier": tier.as_str()})
            }
            Authority::Hostexec(HostexecAuthority::Run { argv, options }) => {
                let mut map = options_json(options);
                map.insert("action".to_owned(), json!("run"));
                map.insert("argv".to_owned(), json!(argv));
                Value::Object(map)
            }
            Authority::Hostexec(HostexecAuthority::Template {
                template,
                params,
                options,
            }) => {
                let mut map = options_json(options);
                map.insert("action".to_owned(), json!("tpl"));
                map.insert("template".to_owned(), json!(template));
                map.insert("params".to_owned(), json!(params));
                Value::Object(map)
            }
            Authority::Mcp { tools } => json!({"tools": tools_json(tools)}),
            Authority::Models => json!({"action": "use"}),
            Authority::Pool(choice) => {
                let (item, previous, m) = match choice {
                    PoolChoice::Item(i) => (Some(i.as_str()), false, None),
                    PoolChoice::Previous => (None, true, None),
                    PoolChoice::Any(m) => (None, false, Some(m)),
                };
                json!({
                    "action": "lease",
                    "item": item,
                    "previous": previous,
                    "match": m.map_or_else(|| json!({}), match_json),
                })
            }
        }
    }

    /// Inverse of `to_json` for a row of `platform`. Strict: anything this
    /// version would not have written is an error (a corrupted or
    /// hand-edited row must not silently widen into something else).
    pub fn from_json(platform: Platform, value: &Value) -> Result<Authority, AuthorityError> {
        let Value::Object(map) = value else {
            return err("stored authority is not an object");
        };
        let s = |key: &str| map.get(key).and_then(Value::as_str);
        let parsed = match platform {
            Platform::Github => {
                if s("action") == Some("create") {
                    Authority::Github(GithubAuthority::Create {
                        visibility: match s("visibility") {
                            Some("private") => Visibility::Private,
                            Some("public") => Visibility::Public,
                            _ => return err("stored github visibility"),
                        },
                    })
                } else {
                    let mut permissions = GithubPermissions::new();
                    if let Some(Value::Object(perms)) = map.get("permissions") {
                        for (k, v) in perms {
                            let access = v
                                .as_str()
                                .and_then(GithubAccess::parse)
                                .ok_or_else(|| AuthorityError("stored github permission".into()))?;
                            permissions.insert(k.clone(), access);
                        }
                    }
                    Authority::Github(GithubAuthority::Repo { permissions })
                }
            }
            Platform::Homelab => Authority::Homelab,
            Platform::Kubernetes => Authority::Kubernetes(KubernetesAuthority {
                role: s("role")
                    .ok_or_else(|| AuthorityError("stored kubernetes role".into()))?
                    .to_owned(),
                cluster: map.get("cluster").and_then(Value::as_bool).unwrap_or(false),
            }),
            Platform::A2a => Authority::A2a {
                topic: s("topic").map(Glob::new),
            },
            Platform::Google => Authority::Google {
                action: s("action").unwrap_or_default().to_owned(),
            },
            Platform::Agents => Authority::Agents {
                action: s("action").unwrap_or("mint").to_owned(),
                runtime: s("runtime").map(str::to_owned),
            },
            Platform::Sandbox => Authority::Sandbox {
                access: match s("access") {
                    Some("project.read") => ProjectAccess::Read,
                    Some("project.write") => ProjectAccess::Write,
                    _ => return err("stored sandbox access"),
                },
            },
            Platform::Hostexec => {
                let tier = s("tier")
                    .and_then(Tier::parse)
                    .ok_or_else(|| AuthorityError("stored hostexec tier".into()))?;
                match s("action") {
                    Some("shell") => Authority::Hostexec(HostexecAuthority::Shell { tier }),
                    Some("window") => Authority::Hostexec(HostexecAuthority::Window { tier }),
                    Some("run") => Authority::Hostexec(HostexecAuthority::Run {
                        argv: string_list(map.get("argv"))?,
                        options: options_from_json(map, tier)?,
                    }),
                    Some("tpl") => Authority::Hostexec(HostexecAuthority::Template {
                        template: s("template")
                            .ok_or_else(|| AuthorityError("stored template".into()))?
                            .to_owned(),
                        params: string_map(map.get("params"))?,
                        options: options_from_json(map, tier)?,
                    }),
                    _ => return err("stored hostexec action"),
                }
            }
            Platform::Mcp => {
                let tools = string_list(map.get("tools"))?;
                if tools.is_empty() || tools.iter().any(|t| t == "*") {
                    Authority::Mcp {
                        tools: ToolSet::All,
                    }
                } else {
                    Authority::Mcp {
                        tools: ToolSet::Some(tools.into_iter().collect()),
                    }
                }
            }
            Platform::Models => Authority::Models,
            Platform::Pool => {
                let item = match map.get("item") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(i)) => Some(i.clone()),
                    Some(_) => return err("stored pool item"),
                };
                let previous = map.get("previous").and_then(Value::as_bool) == Some(true);
                let m = match_from_json(map.get("match"))
                    .map_err(|_| AuthorityError("stored pool match".into()))?;
                Authority::Pool(match (item, previous) {
                    (Some(i), false) if m.is_empty() => PoolChoice::Item(i),
                    (None, true) if m.is_empty() => PoolChoice::Previous,
                    (None, false) => PoolChoice::Any(m),
                    _ => return err("stored pool choice"),
                })
            }
        };
        // Round-trip check: what we parsed must serialize back to exactly
        // what was stored, or the row held something we would not write.
        if parsed.to_json() != *value {
            return err(format!("stored {platform} authority is not canonical"));
        }
        Ok(parsed)
    }
}

/// Does a saved rule's pinned authority cover a request's? Equality, with two
/// widenings: a hostexec window covers any run/tpl of its tier (never a
/// shell), and an mcp rule for some tools covers a request for fewer.
/// A rule with no pinned authority (`None`) covers anything — but such a rule
/// never counts as pinned for the sensitive gate (see `routing`).
#[must_use]
pub fn rule_covers(rule: Option<&Authority>, request: &Authority) -> bool {
    let Some(rule) = rule else {
        return true;
    };
    if rule == request {
        return true;
    }
    match (rule, request) {
        (
            Authority::Hostexec(HostexecAuthority::Window { tier }),
            Authority::Hostexec(
                h @ (HostexecAuthority::Run { .. } | HostexecAuthority::Template { .. }),
            ),
        ) => h.tier() == *tier,
        (Authority::Mcp { tools: allowed }, Authority::Mcp { tools: wanted }) => {
            allowed.covers(wanted)
        }
        // A rule for "any matching X" covers any, or the previous one, with
        // at least X; never a named item (it may be one only a human
        // leases). A rule for a named item or "previous" covers only itself.
        (Authority::Pool(PoolChoice::Any(have)), Authority::Pool(PoolChoice::Any(want))) => {
            match_covers(have, want)
        }
        (Authority::Pool(PoolChoice::Any(have)), Authority::Pool(PoolChoice::Previous)) => {
            match_covers(have, &PropMatch::new())
        }
        _ => false,
    }
}

pub const MAX_MCP_TOOLS: usize = 64;

fn only_keys(
    scope: &Map<String, Value>,
    allowed: &[&str],
    message: &str,
) -> Result<(), AuthorityError> {
    let unknown: Vec<&str> = scope
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        err(format!(
            "{message} (unknown scope keys: {})",
            unknown.join(", ")
        ))
    }
}

fn permissions_json(permissions: &GithubPermissions) -> Value {
    Value::Object(
        permissions
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.as_str().to_owned())))
            .collect(),
    )
}

fn tools_json(tools: &ToolSet) -> Value {
    match tools {
        ToolSet::All => json!(["*"]),
        ToolSet::Some(set) => json!(set),
    }
}

fn match_json(m: &PropMatch) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
}

fn match_from_json(value: Option<&Value>) -> Result<PropMatch, AuthorityError> {
    let bad = || AuthorityError("match maps a property to a value (or a list of strings)".into());
    match value {
        None | Some(Value::Null) => Ok(PropMatch::new()),
        Some(Value::Object(map)) if map.len() <= MAX_MATCH_KEYS => map
            .iter()
            .map(|(k, v)| {
                if k.is_empty() || k.chars().count() > MAX_PROP_CHARS {
                    return Err(bad());
                }
                PropValue::from_json(v)
                    .map(|v| (k.clone(), v))
                    .ok_or_else(bad)
            })
            .collect(),
        Some(_) => Err(bad()),
    }
}

/// A pool lease: `{}` or `{"match": {...}}` for any matching item,
/// `{"previous": true}`, or `{"item": "<name>"}` (one of them).
fn pool_from_wire(
    capability: &str,
    scope: &Map<String, Value>,
) -> Result<Authority, AuthorityError> {
    if capability != "lease" {
        return err("pool capability is \"lease\"");
    }
    let mut extra: Vec<&str> = scope
        .keys()
        .map(String::as_str)
        .filter(|k| !matches!(*k, "item" | "previous" | "match"))
        .collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        let listed: Vec<String> = extra.iter().map(|k| crate::pyfmt::repr(k)).collect();
        return err(format!(
            "a pool scope has \"item\", \"previous\" or \"match\"; not [{}]",
            listed.join(", ")
        ));
    }
    let item = match scope.get("item") {
        None | Some(Value::Null) => None,
        Some(Value::String(i)) if i.is_empty() => None,
        Some(Value::String(i)) if i.chars().count() <= 128 => Some(i.clone()),
        Some(_) => return err("item is an item's name"),
    };
    let previous = match scope.get("previous") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return err("\"previous\" must be true or false"),
    };
    let m = match_from_json(scope.get("match"))?;
    let choice = match (item, previous) {
        (None, false) => PoolChoice::Any(m),
        (Some(i), false) if m.is_empty() => PoolChoice::Item(i),
        (None, true) if m.is_empty() => PoolChoice::Previous,
        _ => {
            return err(
                "ask for one of: an \"item\" by name, the \"previous\" one, or any (with \"match\")",
            );
        }
    };
    Ok(Authority::Pool(choice))
}

fn github_from_wire(
    capability: &str,
    scope: &Map<String, Value>,
) -> Result<Authority, AuthorityError> {
    if capability == "create" {
        only_keys(
            scope,
            &["visibility"],
            "a github create scope is {\"visibility\": \"private\"|\"public\"}",
        )?;
        let visibility = match scope.get("visibility") {
            None | Some(Value::Null) => Visibility::Private,
            Some(Value::String(v)) if v == "private" => Visibility::Private,
            Some(Value::String(v)) if v == "public" => Visibility::Public,
            Some(_) => return err("visibility must be \"private\" or \"public\""),
        };
        return Ok(Authority::Github(GithubAuthority::Create { visibility }));
    }
    if capability != "repo" {
        return err("github capability is \"repo\" or \"create\"");
    }
    only_keys(
        scope,
        &["permissions"],
        "a github scope is {\"permissions\": {...}}",
    )?;
    let mut permissions = GithubPermissions::new();
    match scope.get("permissions") {
        None | Some(Value::Null) => {}
        Some(Value::Object(perms)) => {
            if perms.len() > 64 {
                return err("too many permissions");
            }
            for (name, level) in perms {
                let valid_name = !name.is_empty()
                    && name.len() <= 64
                    && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
                if !valid_name {
                    return err(format!("unknown GitHub permission {name:?}"));
                }
                let Some(access) = level.as_str().and_then(GithubAccess::parse) else {
                    return err(format!(
                        "permission {name:?} must be \"read\", \"write\" or \"admin\""
                    ));
                };
                permissions.insert(name.clone(), access);
            }
        }
        Some(_) => return err("\"permissions\" must be an object"),
    }
    Ok(Authority::Github(GithubAuthority::Repo { permissions }))
}

fn hostexec_from_wire(
    capability: &str,
    scope: &Map<String, Value>,
) -> Result<Authority, AuthorityError> {
    let tier = match scope
        .get("tier")
        .and_then(Value::as_str)
        .and_then(Tier::parse)
    {
        Some(t) => t,
        None => return err("tier must be \"user\" or \"root\""),
    };
    if capability == "shell" {
        only_keys(
            scope,
            &["tier"],
            "a shell's scope is {\"tier\": \"user\"|\"root\"}",
        )?;
        return Ok(Authority::Hostexec(HostexecAuthority::Shell { tier }));
    }
    let options = |scope: &Map<String, Value>| -> Result<CommandOptions, AuthorityError> {
        Ok(CommandOptions {
            tier,
            cwd: match scope.get("cwd") {
                None | Some(Value::Null) => None,
                Some(Value::String(c)) if c.is_empty() => None,
                Some(Value::String(c)) => Some(c.clone()),
                Some(_) => return err("cwd must be an absolute path"),
            },
            env: match scope.get("env") {
                None | Some(Value::Null) => BTreeMap::new(),
                Some(v) => string_map(Some(v))
                    .map_err(|_| AuthorityError("env must be an object of strings".into()))?,
            },
            timeout: match scope.get("timeout") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => match n.as_u64().and_then(|n| u32::try_from(n).ok()) {
                    Some(t) => Some(t),
                    None => return err("timeout must be a number of seconds between 1 and 86400"),
                },
                Some(_) => return err("timeout must be a number of seconds between 1 and 86400"),
            },
            stdin: match scope.get("stdin") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return err("stdin must be text"),
            },
        })
    };
    if let Some(template) = capability.strip_prefix("tpl.") {
        only_keys(
            scope,
            &["tier", "cwd", "env", "timeout", "stdin", "params"],
            "a template's scope",
        )?;
        return Ok(Authority::Hostexec(HostexecAuthority::Template {
            template: template.to_owned(),
            params: match scope.get("params") {
                None | Some(Value::Null) => BTreeMap::new(),
                Some(v) => string_map(Some(v)).map_err(|_| {
                    AuthorityError("template params must be an object of strings".into())
                })?,
            },
            options: options(scope)?,
        }));
    }
    if capability == "run" {
        only_keys(
            scope,
            &["tier", "cwd", "env", "timeout", "stdin", "argv"],
            "a command's scope",
        )?;
        let argv = string_list(scope.get("argv"))
            .map_err(|_| AuthorityError("argv must be a non-empty list of strings".into()))?;
        return Ok(Authority::Hostexec(HostexecAuthority::Run {
            argv,
            options: options(scope)?,
        }));
    }
    err("hostexec capability is \"run\", \"tpl.<name>\" or \"shell\"")
}

fn options_scope(options: &CommandOptions) -> Map<String, Value> {
    // split() drops empty fields from the wire scope.
    let mut map = Map::new();
    map.insert("tier".to_owned(), json!(options.tier.as_str()));
    if let Some(cwd) = &options.cwd {
        map.insert("cwd".to_owned(), json!(cwd));
    }
    if !options.env.is_empty() {
        map.insert("env".to_owned(), json!(options.env));
    }
    if let Some(timeout) = options.timeout {
        map.insert("timeout".to_owned(), json!(timeout));
    }
    if let Some(stdin) = &options.stdin
        && !stdin.is_empty()
    {
        map.insert("stdin".to_owned(), json!(stdin));
    }
    map
}

fn options_json(options: &CommandOptions) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("tier".to_owned(), json!(options.tier.as_str()));
    map.insert("cwd".to_owned(), json!(options.cwd));
    map.insert("env".to_owned(), json!(options.env));
    map.insert("timeout".to_owned(), json!(options.timeout));
    map.insert("stdin".to_owned(), json!(options.stdin));
    map
}

fn options_from_json(
    map: &Map<String, Value>,
    tier: Tier,
) -> Result<CommandOptions, AuthorityError> {
    Ok(CommandOptions {
        tier,
        cwd: map.get("cwd").and_then(Value::as_str).map(str::to_owned),
        env: string_map(map.get("env"))?,
        timeout: map
            .get("timeout")
            .and_then(Value::as_u64)
            .map(|t| u32::try_from(t).map_err(|_| AuthorityError("stored timeout".into())))
            .transpose()?,
        stdin: map.get("stdin").and_then(Value::as_str).map(str::to_owned),
    })
}

fn string_list(value: Option<&Value>) -> Result<Vec<String>, AuthorityError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| AuthorityError("expected strings".into()))
            })
            .collect(),
        Some(_) => err("expected a list of strings"),
    }
}

fn string_map(value: Option<&Value>) -> Result<BTreeMap<String, String>, AuthorityError> {
    match value {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|v| (k.clone(), v.to_owned()))
                    .ok_or_else(|| AuthorityError("expected an object of strings".into()))
            })
            .collect(),
        Some(_) => err("expected an object of strings"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(platform: Platform, cap: &str, scope: Value) -> Result<Authority, AuthorityError> {
        let Value::Object(map) = scope else {
            panic!("scope must be an object")
        };
        Authority::from_wire(platform, cap, &map)
    }

    fn sample_authorities() -> Vec<Authority> {
        let opts = CommandOptions {
            tier: Tier::User,
            cwd: None,
            env: BTreeMap::new(),
            timeout: Some(600),
            stdin: None,
        };
        vec![
            Authority::Github(GithubAuthority::Repo {
                permissions: [("contents".to_owned(), GithubAccess::Write)].into(),
            }),
            Authority::Github(GithubAuthority::Repo {
                permissions: GithubPermissions::new(),
            }),
            Authority::Github(GithubAuthority::Create {
                visibility: Visibility::Public,
            }),
            Authority::Homelab,
            Authority::Kubernetes(KubernetesAuthority {
                role: "view".into(),
                cluster: false,
            }),
            Authority::Kubernetes(KubernetesAuthority {
                role: "view".into(),
                cluster: true,
            }),
            Authority::A2a { topic: None },
            Authority::A2a {
                topic: Some(Glob::new("deploy/*")),
            },
            Authority::Google {
                action: "calendar.read".into(),
            },
            Authority::Agents {
                action: "mint".into(),
                runtime: Some("claude".into()),
            },
            Authority::Sandbox {
                access: ProjectAccess::Write,
            },
            Authority::Hostexec(HostexecAuthority::Run {
                argv: vec!["ls".into(), "-la".into()],
                options: opts.clone(),
            }),
            Authority::Hostexec(HostexecAuthority::Template {
                template: "restart".into(),
                params: [("unit".to_owned(), "nginx".to_owned())].into(),
                options: opts,
            }),
            Authority::Hostexec(HostexecAuthority::Shell { tier: Tier::Root }),
            Authority::Hostexec(HostexecAuthority::Window { tier: Tier::User }),
            Authority::Mcp {
                tools: ToolSet::All,
            },
            Authority::Mcp {
                tools: ToolSet::Some(["a".to_owned(), "b".to_owned()].into()),
            },
            Authority::Models,
            Authority::Pool(PoolChoice::Any(PropMatch::new())),
            Authority::Pool(PoolChoice::Any(
                [
                    ("edition".to_owned(), PropValue::Str("java".into())),
                    ("tags".to_owned(), PropValue::List(vec!["optifine".into()])),
                ]
                .into(),
            )),
            Authority::Pool(PoolChoice::Previous),
            Authority::Pool(PoolChoice::Item("alt-1".into())),
        ]
    }

    #[test]
    fn stored_form_round_trips() {
        for a in sample_authorities() {
            let json = a.to_json();
            assert_eq!(
                Authority::from_json(a.platform(), &json).as_ref(),
                Ok(&a),
                "{json}"
            );
        }
    }

    #[test]
    fn wire_form_round_trips() {
        for a in sample_authorities() {
            if matches!(a, Authority::Hostexec(HostexecAuthority::Window { .. })) {
                continue; // never requested over the wire
            }
            let back = Authority::from_wire(a.platform(), &a.capability(), &a.scope());
            let expected = match &a {
                Authority::Homelab => Ok(Authority::Homelab),
                other => Ok(other.clone()),
            };
            assert_eq!(back, expected, "{a:?}");
        }
    }

    #[test]
    fn non_canonical_rows_are_refused() {
        // An extra key would otherwise be dropped silently.
        let row = json!({"role": "view", "cluster": false});
        assert!(Authority::from_json(Platform::Kubernetes, &row).is_err());
        let row = json!({"permissions": {"contents": "write"}, "extra": 1});
        assert!(Authority::from_json(Platform::Github, &row).is_err());
    }

    #[test]
    fn unknown_scope_keys_are_refused() {
        assert!(wire(Platform::A2a, "talk", json!({"topic": "x", "anything": 1})).is_err());
        assert!(
            wire(
                Platform::Github,
                "repo",
                json!({"permissions": {}, "repos": ["x"]})
            )
            .is_err()
        );
        assert!(
            wire(
                Platform::Hostexec,
                "shell",
                json!({"tier": "user", "argv": ["sh"]})
            )
            .is_err()
        );
    }

    #[test]
    fn window_covers_its_tier_but_never_a_shell() {
        let window = Authority::Hostexec(HostexecAuthority::Window { tier: Tier::User });
        let opts = CommandOptions {
            tier: Tier::User,
            cwd: None,
            env: BTreeMap::new(),
            timeout: None,
            stdin: None,
        };
        let run = Authority::Hostexec(HostexecAuthority::Run {
            argv: vec!["x".into()],
            options: opts.clone(),
        });
        let root_run = Authority::Hostexec(HostexecAuthority::Run {
            argv: vec!["x".into()],
            options: CommandOptions {
                tier: Tier::Root,
                ..opts
            },
        });
        assert!(rule_covers(Some(&window), &run));
        assert!(!rule_covers(Some(&window), &root_run));
        assert!(!rule_covers(
            Some(&window),
            &Authority::Hostexec(HostexecAuthority::Shell { tier: Tier::User })
        ));
    }

    #[test]
    fn mcp_coverage() {
        let some = |t: &[&str]| Authority::Mcp {
            tools: ToolSet::Some(t.iter().map(|s| (*s).to_owned()).collect()),
        };
        let all = Authority::Mcp {
            tools: ToolSet::All,
        };
        assert!(rule_covers(Some(&all), &some(&["a"])));
        assert!(rule_covers(Some(&some(&["a", "b"])), &some(&["a"])));
        assert!(!rule_covers(Some(&some(&["a"])), &some(&["a", "b"])));
        assert!(!rule_covers(Some(&some(&["a"])), &all));
    }

    #[test]
    fn create_never_covered_by_repo_rule() {
        let repo = Authority::Github(GithubAuthority::Repo {
            permissions: GithubPermissions::new(),
        });
        let create = Authority::Github(GithubAuthority::Create {
            visibility: Visibility::Private,
        });
        assert!(!rule_covers(Some(&repo), &create));
        assert!(!rule_covers(Some(&create), &repo));
        assert!(create.needs_explicit_rule());
        assert!(!repo.needs_explicit_rule());
    }

    #[test]
    fn sensitivity() {
        let cfg = SensitivityConfig::default();
        let k8s = |role: &str, cluster| {
            Authority::Kubernetes(KubernetesAuthority {
                role: role.into(),
                cluster,
            })
        };
        assert!(!k8s("view", false).is_sensitive(&cfg, "apps"));
        assert!(k8s("view", true).is_sensitive(&cfg, "apps"));
        assert!(k8s("edit", false).is_sensitive(&cfg, "apps"));
        assert!(k8s("view", false).is_sensitive(&cfg, "kube-system"));
        assert!(k8s("view", false).is_sensitive(&cfg, "default"));
        let gh = Authority::Github(GithubAuthority::Repo {
            permissions: [("secrets".to_owned(), GithubAccess::Read)].into(),
        });
        assert!(gh.is_sensitive(&cfg, "o/r"));
        assert!(
            Authority::Hostexec(HostexecAuthority::Shell { tier: Tier::User })
                .is_sensitive(&cfg, "h")
        );
        assert!(
            Authority::Sandbox {
                access: ProjectAccess::Write
            }
            .is_sensitive(&cfg, "p")
        );
        assert!(
            !Authority::Sandbox {
                access: ProjectAccess::Read
            }
            .is_sensitive(&cfg, "p")
        );
    }

    #[test]
    fn pool_scopes() {
        let any = wire(Platform::Pool, "lease", json!({})).expect("any");
        assert_eq!(any, Authority::Pool(PoolChoice::Any(PropMatch::new())));
        assert_eq!(any.label(), "lease:any");
        assert!(wire(Platform::Pool, "take", json!({})).is_err());
        let both = wire(
            Platform::Pool,
            "lease",
            json!({"item": "a", "previous": true}),
        );
        assert!(both.is_err_and(|e| e.0.starts_with("ask for one of")));
        let extra = wire(Platform::Pool, "lease", json!({"colour": "red"}));
        assert_eq!(
            extra,
            Err(AuthorityError(
                "a pool scope has \"item\", \"previous\" or \"match\"; not ['colour']".into()
            ))
        );
        assert!(wire(Platform::Pool, "lease", json!({"item": 3})).is_err());
        assert!(wire(Platform::Pool, "lease", json!({"match": {"a": {"b": 1}}})).is_err());
        let m = wire(
            Platform::Pool,
            "lease",
            json!({"match": {"tags": ["x"], "n": 2}}),
        )
        .expect("match");
        assert_eq!(m.label(), "lease:n=2,tags=['x']");
        // An empty item is no item (the Python's `or None`).
        assert_eq!(wire(Platform::Pool, "lease", json!({"item": ""})), Ok(any));
    }

    #[test]
    fn pool_coverage() {
        let pool = |scope: Value| wire(Platform::Pool, "lease", scope).expect("pool");
        let rule = pool(json!({"match": {"edition": "java"}}));
        let narrower = pool(json!({"match": {"edition": "java", "tags": "optifine"}}));
        let other = pool(json!({"match": {"edition": "bedrock"}}));
        let named = pool(json!({"item": "main"}));
        let previous = pool(json!({"previous": true}));
        assert!(rule_covers(Some(&rule), &narrower));
        assert!(!rule_covers(Some(&rule), &other));
        assert!(!rule_covers(Some(&rule), &named));
        let any_rule = pool(json!({}));
        assert!(rule_covers(Some(&any_rule), &previous));
        assert!(!rule_covers(Some(&any_rule), &named));
        assert!(!rule_covers(Some(&rule), &previous));
        assert!(rule_covers(Some(&named), &named));
        assert!(!rule_covers(Some(&previous), &any_rule));
        assert!(named.needs_explicit_rule());
    }

    #[test]
    fn pool_and_google_sensitivity() {
        let mut cfg = SensitivityConfig::default();
        cfg.pool_sensitive_items
            .insert("minecraft".into(), ["main".to_owned()].into());
        let named = Authority::Pool(PoolChoice::Item("main".into()));
        assert!(named.is_sensitive(&cfg, "minecraft"));
        assert!(named.sensitive_by_resource(&cfg, "minecraft"));
        assert!(!named.is_sensitive(&cfg, "other"));
        let alt = Authority::Pool(PoolChoice::Item("alt-1".into()));
        assert!(!alt.is_sensitive(&cfg, "minecraft"));
        let google = |a: &str| Authority::Google { action: a.into() };
        assert!(!google("calendar.read").is_sensitive(&cfg, "main"));
        assert!(google("calendar.write").is_sensitive(&cfg, "main"));
        assert!(google("drive.read").is_sensitive(&cfg, "main"));
        assert!(!google("drive.read").sensitive_by_resource(&cfg, "main"));
        assert!(google("calendar.read").needs_explicit_rule());
        // A sensitive namespace is the resource's doing; an edit role is not.
        let k8s = |role: &str| {
            Authority::Kubernetes(KubernetesAuthority {
                role: role.into(),
                cluster: false,
            })
        };
        assert!(k8s("view").sensitive_by_resource(&cfg, "kube-system"));
        assert!(!k8s("edit").sensitive_by_resource(&cfg, "kube-system"));
        assert!(!k8s("view").sensitive_by_resource(&cfg, "apps"));
    }
}
