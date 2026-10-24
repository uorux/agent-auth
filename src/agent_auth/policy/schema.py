from __future__ import annotations

import enum
import re
from fnmatch import fnmatchcase as fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.states import Platform
from ..schemas import parse_duration
from .agents import AgentMatch, AgentPattern, Project, check_resource, valid_attr


class PolicyAction(str, enum.Enum):
    DENY = "deny"
    APPROVE = "approve"
    LLM = "llm"
    SURFACE = "surface"


class Match(BaseModel):
    # Which agents: fields ({runtime: claude, placement: sandbox}), or a glob
    # on the name (the older form).
    agent: AgentPattern = "*"
    platform: Platform | None = None
    # Glob. "*" (the default) never clears a github "create": that takes a
    # rule naming it exactly (see authority.needs_explicit_rule).
    capability: str = "*"
    # Glob. May use the requesting agent's own fields: {agent.project},
    # {agent.host}, {agent.runtime}, and {agent.repos} (each repo of its
    # project, from `projects:`). An agent without the field is not matched.
    resource: str = "*"
    # Which delegator, for on-behalf-of requests: fields or a name glob, as
    # for `agent`. Omitted = the
    # rule was written without delegation in mind: deny/surface still apply to
    # delegated requests (fail-safe), approve/llm never do.
    delegator: AgentPattern | None = None


class Constraints(BaseModel):
    max_duration: str | int | None = None
    llm_model: str | None = None
    retry_budget: int | None = None

    @property
    def max_duration_secs(self) -> int | None:
        return parse_duration(self.max_duration) if self.max_duration is not None else None

    @field_validator("max_duration")
    @classmethod
    def _valid(cls, v):
        if v is not None:
            parse_duration(v)
        return v


class PolicyRule(BaseModel):
    match: Match = Field(default_factory=Match)
    action: PolicyAction
    constraints: Constraints = Field(default_factory=Constraints)
    reason: str = ""


class Defaults(BaseModel):
    action: PolicyAction = PolicyAction.SURFACE
    max_duration: str | int = "24h"

    @property
    def max_duration_secs(self) -> int:
        return parse_duration(self.max_duration)

    @field_validator("max_duration")
    @classmethod
    def _valid(cls, v):
        parse_duration(v)
        return v


class LLMConfig(BaseModel):
    model: str = "anthropic/claude-sonnet-4.5"
    retry_budget: int = 2
    timeout_secs: int = 60


class GithubPlatformConfig(BaseModel):
    repo_allowlist: list[str] = Field(default_factory=list)
    # Checked before the allowlist — carve sensitive repos (e.g. the repo that
    # configures this broker's host) out of a broad allowlist. Globs on
    # normalized "owner/repo".
    repo_denylist: list[str] = Field(default_factory=list)
    # capability ceiling, e.g. {contents: write, secrets: write}
    permission_ceiling: dict[str, str] = Field(default_factory=dict)
    # Requests touching these permissions are always surfaced to a human, even
    # when a policy/YAML rule would auto-approve or LLM-review them. A human's
    # own saved auto-approve rule (scope-pinned) still applies.
    sensitive_permissions: list[str] = Field(
        default_factory=lambda: ["secrets", "administration"]
    )
    # Organizations the broker may create repos in (capability "create",
    # resource "org/name"). Empty = creation disabled. The new repo must also
    # pass repo_allowlist/repo_denylist. The GitHub App needs Administration:
    # write on these installations; the broker uses it for the create call
    # alone and never hands that token out. Only a rule that names creation
    # auto-approves or LLM-routes it — a YAML rule with `capability: create`
    # (exactly), or a saved rule pinned to the create authority; repo-access
    # rules, null-authority rules and the default surface it instead. Creating
    # a PUBLIC repo is sensitive on top (only a pinned saved rule clears it).
    # Organizations only: an installation token can't create repos under a
    # personal account.
    create_owners: list[str] = Field(default_factory=list)


class HomelabPlatformConfig(BaseModel):
    allowed_groups: list[str] = Field(default_factory=list)
    # Optional human descriptions surfaced to agents via GET /v1/catalog.
    group_descriptions: dict[str, str] = Field(default_factory=dict)
    # Managed accounts: an agent registered without --lldap-username gets an
    # LLDAP service account created by the broker at its first homelab grant,
    # named <managed_username_prefix><agent name> with a generated password.
    # Requires ENCRYPTION_KEY (the password is stored Fernet-wrapped).
    managed_accounts: bool = True
    managed_username_prefix: str = Field(default="svc-", max_length=32)
    # LLDAP requires an email per user; nothing is ever sent to it.
    managed_email_domain: str = Field(default="agents.invalid", min_length=1)


class KubernetesPlatformConfig(BaseModel):
    # Globs of namespaces that may be brokered; empty = nothing grantable.
    # ["*"] is reasonable — containment comes from tight roles + human review,
    # not from walling off namespaces (an agent with gitops access can reach
    # them anyway).
    namespace_allowlist: list[str] = Field(default_factory=list)
    # ClusterRole/Role names agents may request. The broker's own RBAC must
    # hold `bind` on exactly these. Prefer narrow custom roles over edit/admin.
    role_allowlist: list[str] = Field(default_factory=lambda: ["view"])
    # Roles grantable CLUSTER-WIDE (request namespace "*"), bound via a
    # ClusterRoleBinding across every namespace. Separate from role_allowlist so
    # cluster scope is opt-in per role; empty (default) = cluster-wide disabled.
    # Every cluster-wide grant is sensitive (always human-reviewed) regardless.
    cluster_role_allowlist: list[str] = Field(default_factory=list)
    # Namespace that hosts the per-grant ServiceAccount backing a cluster-wide
    # grant (the SA must live somewhere; the ClusterRoleBinding is what makes it
    # cluster-scoped). The broker needs SA create/delete rights here.
    cluster_grant_namespace: str = "default"
    # Optional human descriptions (what each role actually grants) surfaced to
    # agents via GET /v1/catalog — the broker can't infer this from a role name.
    role_descriptions: dict[str, str] = Field(default_factory=dict)
    # Roles always surfaced to a human, even when a rule would auto-approve or
    # LLM-review them (a human's own scope-pinned auto-approve rule still holds).
    sensitive_roles: list[str] = Field(default_factory=lambda: ["edit", "admin"])
    # Namespaces (globs) where every grant reaches a human, whatever the role
    # or rule: a role that can patch a workload or start a Job there runs as
    # that namespace's ServiceAccounts — in these, the cluster's own
    # controllers. Add the namespace holding the broker's own credential.
    # cluster_grant_namespace is always one (its SAs back cluster-wide grants).
    sensitive_namespaces: list[str] = Field(
        default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease", "flux-system"]
    )

    def namespace_is_sensitive(self, namespace: str) -> bool:
        return namespace == self.cluster_grant_namespace or any(
            fnmatch(namespace, p) for p in self.sensitive_namespaces
        )


class AgentsPlatformConfig(BaseModel):
    # Runtimes an agent VM may mint identities for (capability "mint",
    # resource "<runtime>-<project>-<host>-sandbox"). Empty = minting disabled.
    runtimes: list[str] = Field(default_factory=lambda: ["claude", "codex"])
    # A minted agent's identity lease: minting it again renews it; past it the
    # agent (and everything it minted) is disabled. Independent of the mint
    # grant's own duration, which only bounds the request.
    lease: str | int = "30d"

    @property
    def lease_secs(self) -> int:
        return parse_duration(self.lease)

    @field_validator("lease")
    @classmethod
    def _valid(cls, v):
        parse_duration(v)
        return v


class HostexecTemplate(BaseModel):
    tier: str = Field(pattern=r"^(user|root)$")
    argv: list[str] = Field(min_length=1)
    # parameter name -> regex its value must match in full
    params: dict[str, str] = Field(default_factory=dict)
    description: str = ""


class HostexecPlatformConfig(BaseModel):
    # Commands on hosts, run by each host's hostd (capability "run" |
    # "tpl.<name>" | "shell", resource = the host). Each host's own config
    # decides what it accepts; nothing here can loosen that.
    #
    # Templates mirrored from the hosts' configs, so the broker can check
    # parameters early and show the expanded command. The host expands its
    # own copy and that is what runs.
    templates: dict[str, HostexecTemplate] = Field(default_factory=dict)
    # One advisory line + low|medium|high on each request shown to a human,
    # from an OpenRouter model. Never approves or denies anything.
    risk_summary: bool = True
    risk_model: str | None = None  # default: llm.model
    # The same model looks at each shell command, and each command no human
    # saw individually (a rule, a window, the reviewer), as it runs, and has
    # the operator pinged about one it finds alarming. It stops nothing.
    watch: bool = True
    # "Approve all" windows: default and longest duration.
    window_default: str | int = "30m"
    window_max: str | int = "8h"

    @field_validator("window_default", "window_max")
    @classmethod
    def _valid(cls, v):
        parse_duration(v)
        return v


class McpServer(BaseModel):
    # Where agents connect (an MCP endpoint, or any HTTP tool behind a proxy
    # that checks agent-auth's tokens).
    url: str
    description: str = ""
    # The tools it offers, if you want requests checked against them and the
    # catalog to list them. Empty: any tool name is accepted in a request.
    tools: list[str] = Field(default_factory=list)
    # The `aud` of tokens for this server; what its proxy is configured to
    # require. Default: the url.
    audience: str | None = None


class McpPlatformConfig(BaseModel):
    """MCP servers (and other HTTP tools) that take agent-auth's own tokens.
    A grant is for one server and a set of its tools; its credential is a
    short-lived signed token (ES256, keys at <issuer>/.well-known/jwks.json)
    that the server's proxy validates, or a reverse proxy checks at
    /v1/tokens/verify. agent-auth is never in the data path."""

    # The `iss` of tokens: the broker's own public URL, where the proxies
    # fetch its keys. Required once servers are listed.
    issuer: str = ""
    # A token's lifetime (never past its grant's). Agents re-fetch.
    token_ttl: str | int = "1h"
    servers: dict[str, McpServer] = Field(default_factory=dict)

    @field_validator("token_ttl")
    @classmethod
    def _valid(cls, v):
        parse_duration(v)
        return v

    @model_validator(mode="after")
    def _issuer(self):
        if self.servers and not self.issuer.startswith("https://"):
            raise ValueError("platforms.mcp.issuer (the broker's https URL) is required when servers are listed")
        for name in self.servers:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
                raise ValueError(f"mcp server name {name!r}: lowercase letters, digits and dashes")
        return self


class ModelsPlatformConfig(BaseModel):
    """The LiteLLM gateway agents send model calls through. A grant is a
    virtual key of the agent's own (provisioners/models.py); the gateway's
    master key is LITELLM_MASTER_KEY in the broker's environment. Off while
    `url` is empty."""

    # Its name in requests (the resource of a "models" grant).
    name: str = "litellm"
    # Where agents reach it (Anthropic-native at this URL, OpenAI at /v1).
    url: str = ""
    # Where the broker reaches its admin API, if not at `url`.
    admin_url: str | None = None
    # Model names (LiteLLM's model_name, wildcards as it defines them) a
    # key may call. Empty: everything the gateway serves.
    models: list[str] = Field(default_factory=list)
    # Per runtime instead: an agent's key may call only its runtime's list
    # ("*": every runtime not named), and an agent whose runtime has no list
    # gets no key. This is what keeps a subscription meant for one tool
    # (Claude Code) away from anything else:
    # {claude: ["claude-*", "gpt-*"], "*": ["gpt-*"]}.
    by_runtime: dict[str, list[str]] = Field(default_factory=dict)
    # Spend limit per key, in the gateway's (notional, for subscriptions)
    # dollars, reset every budget_duration. None: no limit.
    max_budget: float | None = None
    budget_duration: str = "30d"

    @model_validator(mode="after")
    def _urls(self):
        for value in (self.url, self.admin_url):
            if value and not re.fullmatch(r"https?://[^\s/]+(/[^\s]*)?", value):
                raise ValueError(f"platforms.models: {value!r} is not an http(s) URL")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", self.name):
            raise ValueError("platforms.models.name: lowercase letters, digits and dashes")
        return self


class DesktopConfig(BaseModel):
    """Approval prompts and notifications on the desktops you are at
    (hostd-user), next to Discord. Off unless enabled; see
    docs/sandbox-design.md §8.10."""

    enabled: bool = False
    # Which requests may be asked on a desktop: globs on the requesting
    # agent's name, and platforms (empty = every platform).
    agents: list[AgentPattern] = Field(default_factory=list)
    platforms: list[Platform] = Field(default_factory=list)
    # Sensitive requests (write access to another project, secrets
    # permissions, …) stay on Discord unless this is set. A command on a host
    # is the exception: at that host's own desk the host decides. Shells
    # never reach a desktop.
    sensitive: bool = False
    # How long a dialog stays up before the request is left to Discord.
    timeout: str | int = "90s"
    # Rate limits; beyond them requests go to Discord only.
    per_agent_per_hour: int = 6
    per_hour: int = 20
    # After a Deny, that agent's desktop prompts pause; three in an hour mute it.
    deny_cooldown: str | int = "10m"
    mute: str | int = "1h"

    @field_validator("timeout", "deny_cooldown", "mute")
    @classmethod
    def _valid(cls, v):
        parse_duration(v)
        return v


class WikiConfig(BaseModel):
    """The agents' shared wiki (core/wiki.py): markdown in one GitHub repo
    that the broker reads and writes as its GitHub App. Off while `repo` is
    empty. Every agent reads it; an agent writes under projects/<its
    project>/, and `editors` write anywhere."""

    model_config = ConfigDict(extra="forbid")

    repo: str = ""  # "owner/name"
    branch: str = "main"
    # Who may write every page (the shared ones too), as in a rule's `agent`.
    editors: list[AgentPattern] = Field(default_factory=list)
    max_page_bytes: int = 64 * 1024
    # How stale the broker's copy may be before it looks at the repo again
    # (edits made on GitHub by hand show up within this).
    refresh_secs: int = 30

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if v and not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", v):
            raise ValueError(f"wiki.repo {v!r}: owner/name")
        return v


class UiConfig(BaseModel):
    """The admin panel (core/webui.py): a page the broker serves at /ui,
    signed into at the homelab's OpenID provider. Off unless enabled."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # Where the browser reaches the broker; the provider's client must list
    # <base_url>/ui/callback as a redirect URI.
    base_url: str = ""
    issuer: str = ""
    # A public client with PKCE: the broker holds no client secret.
    client_id: str = "agent-auth-admin"
    # Membership the broker itself requires, from the token's `groups`.
    admin_group: str = "agent-auth-admins"
    session_ttl: str | int = "8h"

    @field_validator("session_ttl")
    @classmethod
    def _ttl(cls, v):
        parse_duration(v)
        return v

    @model_validator(mode="after")
    def _urls(self):
        if self.enabled:
            for name in ("base_url", "issuer"):
                if not getattr(self, name).startswith("https://"):
                    raise ValueError(f"ui.{name}: an https URL is required when the panel is enabled")
        return self


class PlatformsConfig(BaseModel):
    github: GithubPlatformConfig = Field(default_factory=GithubPlatformConfig)
    homelab: HomelabPlatformConfig = Field(default_factory=HomelabPlatformConfig)
    kubernetes: KubernetesPlatformConfig = Field(default_factory=KubernetesPlatformConfig)
    agents: AgentsPlatformConfig = Field(default_factory=AgentsPlatformConfig)
    hostexec: HostexecPlatformConfig = Field(default_factory=HostexecPlatformConfig)
    mcp: McpPlatformConfig = Field(default_factory=McpPlatformConfig)
    models: ModelsPlatformConfig = Field(default_factory=ModelsPlatformConfig)


class ContainmentConfig(BaseModel):
    """Which agents may contain others (core/lockdown.py), and how far.
    Lifting is always the operator's."""

    agents: list[AgentPattern] = Field(default_factory=list)
    # May it contain every agent at once ({}), not only some?
    allow_all: bool = False


# The tools a web UI gets by default (remote_mcp.tools): asking for access,
# talking to agents, reading the wiki. Not get_credential (a secret would land
# in a third party's chat history), not host commands or shells, not wiki
# writes; a2a_events is for service agents.
REMOTE_MCP_TOOLS = [
    "whoami", "list_capabilities", "list_grants", "request_access", "wait_for_decision",
    "check_status", "retry_request", "escalate_request", "create_session", "close_session",
    "check_a2a", "a2a_open", "a2a_send", "a2a_poll", "a2a_threads", "a2a_accept",
    "a2a_reject", "a2a_close", "wiki_search", "wiki_read", "wiki_list", "notify_operator",
]


class RemoteMcpConfig(BaseModel):
    """The broker as a remote MCP server for web UIs (claude.ai, ChatGPT
    connectors): /mcp, signed into with OAuth (/oauth/*), where the person
    authorizing signs in at the admin panel's OpenID provider and must be in
    its admin group (ui.*). Each connector acts as an agent of its own,
    `web-<name>`, runtime `web`, and asks for access like any agent. Off
    unless enabled. README "Web UIs (remote MCP)"."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # The public address the UIs reach (its /oauth/callback must be a
    # redirect URI of the provider's client, ui.client_id).
    base_url: str = ""
    # Where a connector may send the browser back to: a client registering
    # any other redirect is refused, so a link someone else registered can't
    # hand them a token after you sign in.
    redirect_hosts: list[str] = Field(
        default_factory=lambda: ["claude.ai", "claude.com", "chatgpt.com", "chat.openai.com"]
    )
    tools: list[str] = Field(default_factory=lambda: list(REMOTE_MCP_TOOLS))
    access_ttl: str | int = "1h"
    refresh_ttl: str | int = "30d"
    # Registered clients at most (registration is open to the internet).
    max_clients: int = 50

    @field_validator("access_ttl", "refresh_ttl")
    @classmethod
    def _ttl(cls, v):
        parse_duration(v)
        return v


class RestrictedZone(BaseModel):
    """Resources only these agents reach (core/zones.py). To every other
    agent they don't exist, whatever any rule says."""

    model_config = ConfigDict(extra="forbid")

    members: list[AgentPattern] = Field(min_length=1)
    kubernetes: list[str] = Field(default_factory=list)  # namespace globs
    github: list[str] = Field(default_factory=list)  # owner/repo globs
    # May members write the shared wiki (which every agent reads)?
    wiki: bool = False


class AuditConfig(BaseModel):
    """Agents that read the broker's own record (GET /v1/audit/events):
    requests and decisions, grants, host commands, a2a threads,
    containment, refused keys. To any other agent the route doesn't exist."""

    readers: list[AgentPattern] = Field(default_factory=list)


class NotifyConfig(BaseModel):
    """What is posted to the Discord channel besides requests that need you.
    A saved rule's decisions always are; these are the rest."""

    # A line for every request approved without you: by the policy file or
    # the LLM reviewer.
    auto_approvals: bool = False
    # ...except these platforms (e.g. models: a key per VM agent each day).
    skip_platforms: list[Platform] = Field(default_factory=list)


class PolicyFile(BaseModel):
    defaults: Defaults = Field(default_factory=Defaults)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    platforms: PlatformsConfig = Field(default_factory=PlatformsConfig)
    desktop: DesktopConfig = Field(default_factory=DesktopConfig)
    wiki: WikiConfig = Field(default_factory=WikiConfig)
    ui: UiConfig = Field(default_factory=UiConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    containment: ContainmentConfig = Field(default_factory=ContainmentConfig)
    # Restricted zones (core/zones.py), by name.
    restricted: dict[str, RestrictedZone] = Field(default_factory=dict)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    remote_mcp: RemoteMcpConfig = Field(default_factory=RemoteMcpConfig)
    # The projects agents work on. A rule may only name a project listed
    # here, so a mistyped one is an error at load and not a rule that never
    # matches.
    projects: dict[str, Project] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _references(self):
        for name in self.projects:
            valid_attr(name)
        patterns = [(f"rules[{i}]", r.match.agent) for i, r in enumerate(self.rules)]
        patterns += [(f"rules[{i}] delegator", r.match.delegator) for i, r in enumerate(self.rules)]
        patterns += [(f"desktop.agents[{i}]", p) for i, p in enumerate(self.desktop.agents)]
        patterns += [(f"wiki.editors[{i}]", p) for i, p in enumerate(self.wiki.editors)]
        patterns += [(f"containment.agents[{i}]", p) for i, p in enumerate(self.containment.agents)]
        patterns += [(f"audit.readers[{i}]", p) for i, p in enumerate(self.audit.readers)]
        patterns += [
            (f"restricted.{name}.members[{i}]", p)
            for name, zone in self.restricted.items()
            for i, p in enumerate(zone.members)
        ]
        for where, pattern in patterns:
            if isinstance(pattern, AgentMatch):
                for project in pattern.project or []:
                    if project not in self.projects:
                        raise ValueError(f"{where}: project {project!r} is not listed under `projects`")
        if self.remote_mcp.enabled:
            if not (self.ui.issuer and self.ui.client_id and self.remote_mcp.base_url):
                raise ValueError("remote_mcp needs base_url, and ui.issuer and ui.client_id to sign in with")
            from ..mcp_names import TOOL_NAMES

            unknown = set(self.remote_mcp.tools) - TOOL_NAMES
            if unknown:
                raise ValueError(f"remote_mcp.tools: no such tools: {', '.join(sorted(unknown))}")
        for i, rule in enumerate(self.rules):
            try:
                check_resource(rule.match.resource)
            except ValueError as exc:
                raise ValueError(f"rules[{i}]: {exc}") from None
        return self


def _overlay(base: Any, extra: Any) -> Any:
    """Mappings merge key by key; lists put the overlay's items first (its
    rules are matched before the base file's); anything else is replaced."""
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for key, value in extra.items():
            out[key] = _overlay(base[key], value) if key in base else value
        return out
    if isinstance(base, list) and isinstance(extra, list):
        return [*extra, *base]
    return extra


def load_policy(path: str | Path, overlays: list[str | Path] | tuple = ()) -> PolicyFile:
    """The policy file, with each overlay merged over it in order.

    An overlay is policy that must not sit in the repo the base file lives
    in (read by agents): a restricted zone's project, rules and
    containment, kept in a sops secret. A missing overlay is an error, not
    an empty one: what it holds is usually what keeps something closed.
    """
    p = Path(path)
    data: Any = (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}
    for extra in overlays:
        q = Path(extra)
        if not q.exists():
            raise FileNotFoundError(f"policy overlay {q} is missing")
        data = _overlay(data, yaml.safe_load(q.read_text()) or {})
    return PolicyFile.model_validate(data)
