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
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from . import authority as authority_mod
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


class AuthoritySugar:
    """Bridges the wire's (capability, scope) pair to the stored `authority` dict.

    Accepts capability=/scope= at construction as sugar (they are two projections
    of one privilege — see agent_auth.authority) and exposes them back as
    read-only properties, so serializers, provisioners, and the LLM/Discord
    surfaces keep speaking capability/scope while `authority` is the single
    source of truth that security logic compares.
    """

    def __init__(self, **kw):
        if "authority" not in kw and ("capability" in kw or "scope" in kw):
            kw["authority"] = authority_mod.fold(
                kw["platform"], kw.pop("capability", ""), kw.pop("scope", None)
            )
        else:
            kw.pop("capability", None)
            kw.pop("scope", None)
        super().__init__(**kw)

    @property
    def capability(self) -> str:
        return authority_mod.split(self.platform, self.authority)[0]

    @property
    def scope(self) -> dict:
        return authority_mod.split(self.platform, self.authority)[1]


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
    # "service" = always-on (may host a webhook, can receive a2a threads);
    # "ephemeral" = short-lived CLI instances that operate through sessions
    # and can only initiate threads, never receive them.
    kind: Mapped[str] = mapped_column(String(16), default="service")
    last_seen_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    # Per-agent HMAC key for webhook pings; must stay recoverable for signing,
    # so it is stored plaintext (same trust level as the env-var global secret;
    # Fernet-wrapping under encryption_key is a possible future hardening).
    webhook_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AgentSession(Base, TimestampMixin):
    """One live instance of an ephemeral agent (e.g. a single Claude Code run).

    a2a grants requested from a session bind to it, and threads it opens close
    with peer_gone once it idles out — conversations are session-lived.
    """

    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))  # "<label>-<hex4>"
    last_seen_at: Mapped[datetime] = mapped_column(TZDateTime(), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    close_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        UniqueConstraint("agent_id", "name", name="uq_agent_sessions_agent_name"),
        Index("ix_agent_sessions_open", "agent_id", "closed_at"),
    )


class A2AThread(Base, TimestampMixin):
    """A conversation between two agents with TCP-like open/close semantics.

    Fast-open: the opening request carries the first message and leaves the
    thread pending_open until the responder accepts (explicitly or by replying)
    or rejects. The initiator's grant backs the whole thread — both directions —
    so revoking it closes the conversation.
    """

    __tablename__ = "a2a_threads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    initiator_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    # Null = the initiator is a service agent (no session machinery).
    initiator_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id"), nullable=True
    )
    responder_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    topic: Mapped[str | None] = mapped_column(String(256), nullable=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("grants.id"))
    state: Mapped[str] = mapped_column(String(16), default="pending_open", index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    last_activity_at: Mapped[datetime] = mapped_column(
        TZDateTime(), default=utcnow, index=True
    )
    # Per-thread monotonic message counter; bumped in the message-insert
    # transaction, which serializes under SQLite's single writer.
    last_seq: Mapped[int] = mapped_column(Integer, default=0)
    closed_by: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), nullable=True)
    close_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    close_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class AccessRequest(AuthoritySugar, Base, TimestampMixin):
    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    # Session the caller supplied when creating the request. Audit only —
    # grants are agent-level (the per-folder API key is the boundary; sessions
    # scope threads and liveness, not permissions).
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id"), nullable=True
    )
    platform: Mapped[Platform] = mapped_column(_enum(Platform, "platform"))
    resource: Mapped[str] = mapped_column(String(512))
    # Canonical privilege (capability+scope folded); see agent_auth.authority.
    authority: Mapped[dict] = mapped_column(JSON, default=dict)
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
    approved_authority: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approved_resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(TZDateTime(), nullable=True)
    discord_channel_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    discord_message_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime(), default=utcnow, onupdate=utcnow
    )

    @property
    def approved_scope(self) -> dict | None:
        if self.approved_authority is None:
            return None
        return authority_mod.split(self.platform, self.approved_authority)[1]


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


class Grant(AuthoritySugar, Base, TimestampMixin):
    __tablename__ = "grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("access_requests.id"), unique=True, index=True
    )
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    # Copied from the request; see AccessRequest.session_id.
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id"), nullable=True
    )
    platform: Mapped[Platform] = mapped_column(_enum(Platform, "platform"))
    resource: Mapped[str] = mapped_column(String(512))
    # Canonical privilege (capability+scope folded); see agent_auth.authority.
    authority: Mapped[dict] = mapped_column(JSON, default=dict)
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
    # Glob on the object axis (which repo/namespace/group/agent).
    resource_pattern: Mapped[str] = mapped_column(String(512), default="*")
    # Exact privilege this rule was created for; null = any privilege. Pinning
    # the whole authority (role AND scope, per platform) is what stops an
    # approval of a narrow request from auto-approving a broader one — and a
    # null pin never bypasses the sensitive-capability human-review gate.
    authority: Mapped[dict | None] = mapped_column(JSON, nullable=True)
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
    """One message in a thread. Rows with thread_id NULL predate the thread
    protocol and are kept as audit history only — excluded from all APIs."""

    __tablename__ = "a2a_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    thread_id: Mapped[str | None] = mapped_column(
        ForeignKey("a2a_threads.id"), nullable=True, index=True
    )
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sender_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    sender_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_sessions.id"), nullable=True
    )
    recipient_agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    # The thread's backing grant (the initiator's), for both directions.
    grant_id: Mapped[str] = mapped_column(ForeignKey("grants.id"))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_a2a_messages_thread_seq", "thread_id", "seq", unique=True),
    )
