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
    justification: str = Field(min_length=1)
    requested_duration: str | int

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
    created_at: datetime
    # Actionable hint for agents: e.g. "you may retry with a better justification"
    guidance: str | None = None


class RetryBody(BaseModel):
    justification: str = Field(min_length=1)


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


class CredentialOut(BaseModel):
    kind: str
    value: str | None = None
    expires_at: datetime | None = None
    note: str | None = None


class A2ASendBody(BaseModel):
    to: str
    scope: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class A2ACheckOut(BaseModel):
    allowed: bool
    grant_id: str | None = None
    expires_at: datetime | None = None
    reason: str | None = None


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    description: str = ""
    webhook_url: str | None = None
    lldap_username: str | None = None


class AgentOut(BaseModel):
    id: str
    name: str
    description: str
    webhook_url: str | None
    lldap_username: str | None
    disabled: bool
    api_key: str | None = None  # only set on create/rotate


class RuleOut(BaseModel):
    id: str
    action: str
    agent_pattern: str
    platform: Platform
    capability_pattern: str
    resource_pattern: str
    max_duration_secs: int | None
    enabled: bool
    created_by: str
    notes: str
