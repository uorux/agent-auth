from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .core.states import DecisionSource, GrantStatus, Platform, RequestStatus

_DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
_UNIT_SECS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(value: str | int) -> int:
    """Accepts seconds as int, or strings like '30m', '8h', '2d'."""
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("duration must be positive")
        return value
    value = value.strip().lower()
    if value.isdigit():
        return parse_duration(int(value))
    m = _DURATION_RE.match(value)
    if not m:
        raise ValueError(f"invalid duration {value!r}: use e.g. '30m', '8h', '2d', or seconds")
    return int(m.group(1)) * _UNIT_SECS[m.group(2)]


def format_duration(secs: int) -> str:
    for unit, div in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)):
        if secs % div == 0 and secs >= div:
            return f"{secs // div}{unit}"
    return f"{secs}s"


class RequestCreate(BaseModel):
    platform: Platform
    capability: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)
    scope: dict[str, Any] = Field(default_factory=dict)
    justification: str = Field(min_length=1, max_length=4000)
    requested_duration: str | int
    # Delegation: id of the OPEN a2a thread whose conversation asked for this
    # work — only that thread; the other participant becomes the delegator.
    on_behalf_of_thread: str | None = Field(default=None, max_length=36)

    @field_validator("requested_duration")
    @classmethod
    def _valid_duration(cls, v: str | int) -> str | int:
        parse_duration(v)
        return v

    @property
    def duration_secs(self) -> int:
        return parse_duration(self.requested_duration)


class RequestOut(BaseModel):
    id: str
    agent: str
    platform: Platform
    capability: str
    resource: str
    scope: dict[str, Any]
    justification: str
    requested_duration_secs: int
    status: RequestStatus
    attempt: int
    decision_source: DecisionSource | None = None
    decision_reason: str | None = None
    approved_duration_secs: int | None = None
    approved_scope: dict[str, Any] | None = None
    approved_resource: str | None = None
    grant_id: str | None = None
    delegator: str | None = None
    delegation_thread_id: str | None = None
    created_at: datetime
    # Actionable hint for agents: e.g. "you may retry with a better justification"
    guidance: str | None = None


class RetryBody(BaseModel):
    justification: str = Field(min_length=1, max_length=4000)


class GrantOut(BaseModel):
    id: str
    request_id: str
    agent: str
    platform: Platform
    capability: str
    resource: str
    scope: dict[str, Any]
    granted_at: datetime
    expires_at: datetime
    status: GrantStatus
    delegator: str | None = None
    delegation_thread_id: str | None = None


class CredentialOut(BaseModel):
    kind: str
    value: str | None = None
    expires_at: datetime | None = None
    note: str | None = None


_MAX_PAYLOAD_BYTES = 16 * 1024


def _check_payload_size(v: dict) -> dict:
    import json

    if len(json.dumps(v)) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {_MAX_PAYLOAD_BYTES} bytes")
    return v


class SessionCreate(BaseModel):
    label: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")


class SessionOut(BaseModel):
    session_id: str
    name: str
    created_at: datetime


class ThreadOpenBody(BaseModel):
    to: str = Field(min_length=1, max_length=128)
    topic: str | None = Field(default=None, max_length=256)
    payload: dict[str, Any] = Field(default_factory=dict)

    _size = field_validator("payload")(_check_payload_size)


class ThreadMessageBody(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)

    _size = field_validator("payload")(_check_payload_size)


class ThreadCloseBody(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class A2ACheckOut(BaseModel):
    allowed: bool
    grant_id: str | None = None
    expires_at: datetime | None = None
    reason: str | None = None


def validate_webhook_url(v: str | None) -> str | None:
    if v is None:
        return v
    from urllib.parse import urlparse

    parsed = urlparse(v)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("webhook_url must be an http(s) URL with a host")
    return v


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    description: str = Field(default="", max_length=2000)
    kind: str = Field(default="service", pattern=r"^(service|ephemeral)$")
    webhook_url: str | None = Field(default=None, max_length=512)
    lldap_username: str | None = Field(default=None, max_length=128)

    _valid_webhook = field_validator("webhook_url")(validate_webhook_url)


class SetWebhookBody(BaseModel):
    # null clears the webhook (and its secret)
    webhook_url: str | None = Field(default=None, max_length=512)

    _valid_webhook = field_validator("webhook_url")(validate_webhook_url)


class AgentOut(BaseModel):
    id: str
    name: str
    description: str
    kind: str = "service"
    webhook_url: str | None
    lldap_username: str | None
    disabled: bool
    api_key: str | None = None  # only set on create/rotate
    webhook_secret: str | None = None  # only set on create/rotate-webhook-secret


class CatalogEntry(BaseModel):
    name: str
    description: str | None = None
    # Resource-agnostic policy routing, best-effort: "auto-approve" | "human
    # review" | "llm review" | "denied". Actual routing may differ by the
    # specific resource/justification.
    typical_disposition: str | None = None


class PlatformCatalog(BaseModel):
    platform: Platform
    capability_hint: str
    resource_hint: str
    roles: list[CatalogEntry] | None = None
    # Roles requestable cluster-wide via resource "*" (always human-reviewed).
    cluster_roles: list[str] | None = None
    namespace_allowlist: list[str] | None = None
    repo_allowlist: list[str] | None = None
    permission_ceiling: dict[str, str] | None = None
    groups: list[CatalogEntry] | None = None
    capabilities: list[str] | None = None
    peers: list[str] | None = None


class CatalogOut(BaseModel):
    platforms: list[PlatformCatalog]


class RuleOut(BaseModel):
    id: str
    action: str
    agent_pattern: str
    # Delegator glob for delegated requests; null = rule never auto-approves them.
    delegator_pattern: str | None = None
    platform: Platform
    # Derived display label for the pinned authority ('*' = any privilege).
    capability_pattern: str
    resource_pattern: str
    # Exact privilege this rule is pinned to; null = any.
    authority: dict[str, Any] | None = None
    max_duration_secs: int | None
    enabled: bool
    created_by: str
    notes: str
