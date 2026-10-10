from __future__ import annotations

import enum
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.states import Platform
from ..schemas import parse_duration


class PolicyAction(str, enum.Enum):
    DENY = "deny"
    APPROVE = "approve"
    LLM = "llm"
    SURFACE = "surface"


class Match(BaseModel):
    agent: str = "*"
    platform: Platform | None = None
    # Glob. "*" (the default) never clears a github "create": that takes a
    # rule naming it exactly (see authority.needs_explicit_rule).
    capability: str = "*"
    resource: str = "*"
    # Glob on the delegator's name for on-behalf-of requests. Omitted = the
    # rule was written without delegation in mind: deny/surface still apply to
    # delegated requests (fail-safe), approve/llm never do.
    delegator: str | None = None


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


class DesktopConfig(BaseModel):
    """Approval prompts and notifications on the desktops you are at
    (hostd-user), next to Discord. Off unless enabled; see
    docs/sandbox-design.md §8.10."""

    enabled: bool = False
    # Which requests may be asked on a desktop: globs on the requesting
    # agent's name, and platforms (empty = every platform).
    agents: list[str] = Field(default_factory=list)
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


class PlatformsConfig(BaseModel):
    github: GithubPlatformConfig = Field(default_factory=GithubPlatformConfig)
    homelab: HomelabPlatformConfig = Field(default_factory=HomelabPlatformConfig)
    kubernetes: KubernetesPlatformConfig = Field(default_factory=KubernetesPlatformConfig)
    agents: AgentsPlatformConfig = Field(default_factory=AgentsPlatformConfig)
    hostexec: HostexecPlatformConfig = Field(default_factory=HostexecPlatformConfig)
    mcp: McpPlatformConfig = Field(default_factory=McpPlatformConfig)


class PolicyFile(BaseModel):
    defaults: Defaults = Field(default_factory=Defaults)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    platforms: PlatformsConfig = Field(default_factory=PlatformsConfig)
    desktop: DesktopConfig = Field(default_factory=DesktopConfig)
    rules: list[PolicyRule] = Field(default_factory=list)


def load_policy(path: str | Path) -> PolicyFile:
    p = Path(path)
    if not p.exists():
        return PolicyFile()
    data = yaml.safe_load(p.read_text()) or {}
    return PolicyFile.model_validate(data)
