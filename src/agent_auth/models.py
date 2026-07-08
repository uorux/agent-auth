from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .core.states import (
    DecisionSource,
    GrantStatus,
    Platform,
    RequestStatus,
    RuleAction,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class TZDateTime(TypeDecorator):
    """Timezone-aware datetimes on any backend: Postgres timestamptz returns
    aware values natively; SQLite (used in tests) returns naive UTC, which this
    re-tags so comparisons against utcnow() are always valid."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            raise ValueError("naive datetime written to TZDateTime column")
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)


def _enum(e, name: str):
    # values_callable so the DB stores the lowercase .value, not the member name
    return Enum(e, name=name, values_callable=lambda x: [m.value for m in x])


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    key_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(64))
    webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    lldap_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class AccessRequest(Base, TimestampMixin):
    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    platform: Mapped[Platform] = mapped_column(_enum(Platform, "platform"))
    capability: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(String(512))
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    justification: Mapped[str] = mapped_column(Text)
    requested_duration_secs: Mapped[int] = mapped_column(Integer)
    risk_notes: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[RequestStatus] = mapped_column(
        _enum(RequestStatus, "request_status"), default=RequestStatus.PENDING, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    decision_source: Mapped[DecisionSource | None] = mapped_column(
        _enum(DecisionSource, "decision_source"), nullable=True
    )
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_duration_secs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    approved_scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approved_resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    discord_channel_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    discord_message_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime(), default=utcnow, onupdate=utcnow
    )


class LLMEvaluation(Base, TimestampMixin):
    __tablename__ = "llm_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[str] = mapped_column(ForeignKey("access_requests.id"), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    model: Mapped[str] = mapped_column(String(128))
    verdict: Mapped[str] = mapped_column(String(16))
    reasoning: Mapped[str] = mapped_column(Text, default="")
    suggested_duration_secs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_response: Mapped[dict] = mapped_column(JSON, default=dict)


class Grant(Base, TimestampMixin):
    __tablename__ = "grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("access_requests.id"), unique=True, index=True
    )
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    platform: Mapped[Platform] = mapped_column(_enum(Platform, "platform"))
    capability: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(String(512))
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    granted_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime(), index=True)
    status: Mapped[GrantStatus] = mapped_column(
        _enum(GrantStatus, "grant_status"), default=GrantStatus.ACTIVE, index=True
    )
    provisioner_state: Mapped[dict] = mapped_column(JSON, default=dict)
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_grants_active_expiry", "status", "expires_at"),)


class Rule(Base, TimestampMixin):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    action: Mapped[RuleAction] = mapped_column(_enum(RuleAction, "rule_action"))
    agent_pattern: Mapped[str] = mapped_column(String(128), default="*")
    platform: Mapped[Platform] = mapped_column(_enum(Platform, "platform"))
    capability_pattern: Mapped[str] = mapped_column(String(128), default="*")
    resource_pattern: Mapped[str] = mapped_column(String(512), default="*")
    # Exact normalized scope this rule was created for; null = any scope.
    # Prevents an "approve contents:write" rule from rubber-stamping secrets:write.
    scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    max_duration_secs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    grant_id: Mapped[str] = mapped_column(ForeignKey("grants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    value_encrypted: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime())


class A2AMessage(Base, TimestampMixin):
    __tablename__ = "a2a_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    sender_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    recipient_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("grants.id"))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    delivered_via: Mapped[str | None] = mapped_column(String(16), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
