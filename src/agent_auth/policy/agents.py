"""What an agent is, as recorded fields: who runs it (runtime), what it works
on (project), where (host), and whether in an agent VM (placement). Policy
matches on these; the name is a label for people.

The broker sets them — at registration by the operator, at minting from the
sandbox the request came through — and an agent cannot change its own.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PLACEMENTS = ("host", "sandbox")
KINDS = ("service", "ephemeral")
# A runtime, project or host: what may appear in a name, a path or a rule.
ATTR_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

Values = list[str]


def valid_attr(value: str | None) -> str | None:
    if value is not None and not ATTR_RE.fullmatch(value):
        raise ValueError(f"{value!r}: lowercase letters, digits, dots, dashes and underscores")
    return value


class AgentMatch(BaseModel):
    """Which agents a rule is about. Every field given must hold; a field
    takes one value or a list of them, compared exactly. `name` is the one
    glob, for the agents no field tells apart."""

    model_config = ConfigDict(extra="forbid")

    name: str = "*"
    runtime: Values | None = None
    project: Values | None = None
    host: Values | None = None
    placement: list[Literal["host", "sandbox"]] | None = None
    kind: list[Literal["service", "ephemeral"]] | None = None

    @field_validator("runtime", "project", "host", "placement", "kind", mode="before")
    @classmethod
    def _one_or_many(cls, v: Any) -> Any:
        return [v] if isinstance(v, str) else v

    @field_validator("runtime", "project", "host")
    @classmethod
    def _valid(cls, v: Values | None) -> Values | None:
        for item in v or []:
            valid_attr(item)
        if v is not None and not v:
            raise ValueError("an empty list matches no agent; leave the field out for any")
        return v

    def matches(self, agent: Any) -> bool:
        for field in ("runtime", "project", "host", "placement", "kind"):
            wanted = getattr(self, field)
            # An agent without the field is not matched by a rule that asks for it.
            if wanted is not None and getattr(agent, field, None) not in wanted:
                return False
        return fnmatch(agent.name, self.name)


AgentPattern = str | AgentMatch


def agent_matches(pattern: AgentPattern, agent: Any) -> bool:
    """A string is a glob on the name (the older form); a mapping is fields."""
    if isinstance(pattern, str):
        return fnmatch(agent.name, pattern)
    return pattern.matches(agent)


def pattern_text(pattern: AgentPattern) -> str:
    """A pattern as a person would write it in the policy."""
    if isinstance(pattern, str):
        return pattern
    fields = pattern.model_dump(exclude_defaults=True)
    return "{" + ", ".join(f"{k}: {'|'.join(v) if isinstance(v, list) else v}" for k, v in fields.items()) + "}"


class Project(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = ""
    # GitHub repos ("owner/repo") this project's agents work in: what
    # `{agent.repos}` stands for in a rule's resource.
    repos: list[str] = Field(default_factory=list)


PLACEHOLDER_RE = re.compile(r"\{agent\.([a-z]+)\}")
PLACEHOLDERS = ("runtime", "project", "host", "repos")


def check_resource(resource: str) -> None:
    """Refuse a rule whose resource names a placeholder that doesn't exist."""
    for name in PLACEHOLDER_RE.findall(resource):
        if name not in PLACEHOLDERS:
            raise ValueError(
                f"resource {resource!r}: unknown placeholder {{agent.{name}}} "
                f"(there are: {', '.join('{agent.' + p + '}' for p in PLACEHOLDERS)})"
            )
    if "{" in PLACEHOLDER_RE.sub("", resource):
        raise ValueError(f"resource {resource!r}: a brace that is not an {{agent.…}} placeholder")


def resources_for(resource: str, agent: Any, projects: dict[str, Project]) -> list[str]:
    """The rule's resource globs with the agent's own fields filled in. A
    placeholder the agent has no value for leaves nothing to match: a rule
    about "your project's repo" says nothing to an agent without a project."""
    names = set(PLACEHOLDER_RE.findall(resource))
    if not names:
        return [resource]
    out = [resource]
    for name in names:
        if name == "repos":
            project = projects.get(getattr(agent, "project", None) or "")
            values = list(project.repos) if project else []
        else:
            value = getattr(agent, name, None)
            values = [value] if value else []
        out = [r.replace("{agent." + name + "}", _literal(v)) for r in out for v in values]
    return out


def _literal(value: str) -> str:
    """The value as itself inside a glob."""
    return re.sub(r"([*?\[])", r"[\1]", value)


def attributes(agent: Any) -> dict[str, str | None]:
    return {
        "runtime": agent.runtime,
        "project": agent.project,
        "host": agent.host,
        "placement": agent.placement,
    }


def describe(agent: Any) -> str:
    """The fields as one line for a person: "claude · agent-auth · excelsior · VM"."""
    parts = [agent.runtime, agent.project, agent.host, "VM" if agent.placement == "sandbox" else None]
    return " · ".join(p for p in parts if p)
