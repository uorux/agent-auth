from __future__ import annotations

import enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

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


class HomelabPlatformConfig(BaseModel):
    allowed_groups: list[str] = Field(default_factory=list)
    # Optional human descriptions surfaced to agents via GET /v1/catalog.
    group_descriptions: dict[str, str] = Field(default_factory=dict)


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


class PlatformsConfig(BaseModel):
    github: GithubPlatformConfig = Field(default_factory=GithubPlatformConfig)
    homelab: HomelabPlatformConfig = Field(default_factory=HomelabPlatformConfig)
    kubernetes: KubernetesPlatformConfig = Field(default_factory=KubernetesPlatformConfig)


class PolicyFile(BaseModel):
    defaults: Defaults = Field(default_factory=Defaults)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    platforms: PlatformsConfig = Field(default_factory=PlatformsConfig)
    rules: list[PolicyRule] = Field(default_factory=list)


def load_policy(path: str | Path) -> PolicyFile:
    p = Path(path)
    if not p.exists():
        return PolicyFile()
    data = yaml.safe_load(p.read_text()) or {}
    return PolicyFile.model_validate(data)
