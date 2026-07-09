from __future__ import annotations

import enum


class Platform(str, enum.Enum):
    GITHUB = "github"
    HOMELAB = "homelab"
    KUBERNETES = "kubernetes"
    A2A = "a2a"
    GOOGLE = "google"


class RequestStatus(str, enum.Enum):
    PENDING = "pending"
    LLM_EVALUATING = "llm_evaluating"
    LLM_DENIED = "llm_denied"
    AWAITING_HUMAN = "awaiting_human"
    APPROVED = "approved"
    PROVISIONING = "provisioning"
    GRANTED = "granted"
    PROVISION_FAILED = "provision_failed"
    DENIED = "denied"


class DecisionSource(str, enum.Enum):
    POLICY = "policy"
    RULE = "rule"
    LLM = "llm"
    HUMAN = "human"


class GrantStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PROVISION_FAILED = "provision_failed"


class RuleAction(str, enum.Enum):
    AUTO_APPROVE = "auto_approve"
    AUTO_DENY = "auto_deny"


# --- agents & a2a threads (plain strings in the DB, not enums) ---

AGENT_KINDS = ("service", "ephemeral")

THREAD_PENDING_OPEN = "pending_open"
THREAD_OPEN = "open"
THREAD_CLOSED = "closed"
THREAD_STATES = (THREAD_PENDING_OPEN, THREAD_OPEN, THREAD_CLOSED)

# Why a thread reached CLOSED. "closed" = a participant hung up normally.
CLOSE_REJECTED = "rejected"
CLOSE_CLOSED = "closed"
CLOSE_OPEN_TIMEOUT = "open_timeout"
CLOSE_IDLE_TIMEOUT = "idle_timeout"
CLOSE_PEER_GONE = "peer_gone"
CLOSE_GRANT_REVOKED = "grant_revoked"
CLOSE_REASONS = (
    CLOSE_REJECTED,
    CLOSE_CLOSED,
    CLOSE_OPEN_TIMEOUT,
    CLOSE_IDLE_TIMEOUT,
    CLOSE_PEER_GONE,
    CLOSE_GRANT_REVOKED,
)

SESSION_CLOSE_IDLE = "idle"
SESSION_CLOSE_CLOSED = "closed"


# Statuses an agent is still waiting on (long-poll keeps blocking while in these).
# AWAITING_HUMAN is included: the agent is blocked on the human, so the poll holds
# until the decision lands (or times out, returning the current status + guidance).
WAITING_STATUSES = frozenset(
    {
        RequestStatus.PENDING,
        RequestStatus.LLM_EVALUATING,
        RequestStatus.AWAITING_HUMAN,
        RequestStatus.APPROVED,
        RequestStatus.PROVISIONING,
    }
)

# Statuses from which no further transition is allowed.
TERMINAL_STATUSES = frozenset(
    {RequestStatus.DENIED, RequestStatus.GRANTED, RequestStatus.PROVISION_FAILED}
)

ALLOWED_TRANSITIONS: dict[RequestStatus, frozenset[RequestStatus]] = {
    RequestStatus.PENDING: frozenset(
        {
            RequestStatus.DENIED,
            RequestStatus.APPROVED,
            RequestStatus.LLM_EVALUATING,
            RequestStatus.AWAITING_HUMAN,
        }
    ),
    RequestStatus.LLM_EVALUATING: frozenset(
        {RequestStatus.APPROVED, RequestStatus.LLM_DENIED, RequestStatus.AWAITING_HUMAN}
    ),
    RequestStatus.LLM_DENIED: frozenset(
        {RequestStatus.LLM_EVALUATING, RequestStatus.AWAITING_HUMAN}
    ),
    RequestStatus.AWAITING_HUMAN: frozenset({RequestStatus.APPROVED, RequestStatus.DENIED}),
    RequestStatus.APPROVED: frozenset({RequestStatus.PROVISIONING}),
    RequestStatus.PROVISIONING: frozenset(
        {RequestStatus.GRANTED, RequestStatus.PROVISION_FAILED}
    ),
    RequestStatus.GRANTED: frozenset(),
    RequestStatus.PROVISION_FAILED: frozenset(),
    RequestStatus.DENIED: frozenset(),
}


def can_transition(current: RequestStatus, new: RequestStatus) -> bool:
    return new in ALLOWED_TRANSITIONS[current]
