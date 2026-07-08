"""Stdio MCP server exposing the broker to agents.

Configure per-agent:
    AGENT_AUTH_URL=https://auth.example  AGENT_AUTH_API_KEY=aa_...  agent-auth-mcp
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import BrokerClient, BrokerError

mcp = FastMCP("agent-auth")


def _client() -> BrokerClient:
    return BrokerClient()


def _safe(fn) -> str:
    try:
        return json.dumps(fn(), indent=2, default=str)
    except BrokerError as exc:
        return json.dumps({"error": exc.detail, "status_code": exc.status_code})


@mcp.tool()
def request_access(
    platform: str,
    capability: str,
    resource: str,
    justification: str,
    duration: str = "1h",
    scope: dict[str, Any] | None = None,
) -> str:
    """Request time-bounded access to a resource. The broker may auto-approve,
    deny, review with an LLM, or ask a human on Discord.

    platform/capability/resource conventions:
    - github: capability="repo", resource="owner/repo",
      scope={"permissions": {"contents": "write", "secrets": "write"}}
    - homelab: capability="group", resource=<lldap group, e.g. "svc-gitea">
      (once granted, your service account is in the group; authenticate to the
      service yourself — e.g. mint your own Gitea token)
    - kubernetes: capability="namespace", resource=<namespace>,
      scope={"role": "view"|"edit"|...} — grants a ServiceAccount in that
      namespace; get_credential returns a short-lived bearer token for kubectl
      (--token) or the API
    - a2a: capability="talk", resource=<agent name>, scope={"topic": "deploy/*"}
    - google: capability in {calendar.read, calendar.write, gmail.read, drive.read}

    Write a SPECIFIC justification (what task, why this resource, why this
    duration) — vague justifications get denied. duration examples: "30m", "8h", "2d".
    Then call wait_for_decision with the returned request id."""
    return _safe(
        lambda: _client().request_access(
            platform, capability, resource, justification, duration, scope
        )
    )


@mcp.tool()
def wait_for_decision(request_id: str, timeout_secs: float = 120) -> str:
    """Block until the request is decided (or timeout). Read `status` and `guidance`:
    - granted: access is live; use get_credential(grant_id) if a token is needed
    - llm_denied: read decision_reason, then retry_request with a better
      justification, or escalate to a human
    - awaiting_human: a human was pinged on Discord; keep waiting (this can take
      a while — poll again rather than giving up immediately)
    - denied: final; do not resubmit the same request unchanged"""
    return _safe(lambda: _client().wait(request_id, timeout_secs))


@mcp.tool()
def check_status(request_id: str) -> str:
    """Get a request's current status without blocking."""
    return _safe(lambda: _client().get_request(request_id))


@mcp.tool()
def retry_request(request_id: str, justification: str) -> str:
    """After an LLM denial, retry with a REVISED justification that addresses the
    denial reasoning. Limited attempts; when exhausted, use escalate_request."""
    return _safe(lambda: _client().retry(request_id, justification))


@mcp.tool()
def escalate_request(request_id: str) -> str:
    """Escalate an LLM-denied request to human review on Discord."""
    return _safe(lambda: _client().escalate(request_id))


@mcp.tool()
def list_grants(status: str = "active") -> str:
    """List your grants (status: active|expired|revoked|all). Check here before
    requesting access you might already have."""
    return _safe(lambda: _client().grants(status))


@mcp.tool()
def get_credential(grant_id: str) -> str:
    """Fetch the live credential for an active grant. GitHub grants return a
    short-lived installation token — refetch rather than storing it; it stops
    being issued the moment the grant expires."""
    return _safe(lambda: _client().credential(grant_id))


@mcp.tool()
def check_a2a(peer: str, direction: str = "out", topic: str | None = None) -> str:
    """Check agent-to-agent permission. direction="out": may I message peer?
    direction="in": may peer message me? Recipients should verify inbound
    messages with direction="in" before acting on them."""
    return _safe(lambda: _client().a2a_check(peer, direction, topic))


@mcp.tool()
def a2a_send(to: str, payload: dict[str, Any], topic: str | None = None) -> str:
    """Send a message to another agent through the broker relay. Requires an
    active a2a grant (request one with request_access platform="a2a")."""
    return _safe(lambda: _client().a2a_send(to, payload, topic))


@mcp.tool()
def a2a_inbox() -> str:
    """Fetch unacknowledged messages other agents sent you, oldest first.
    Acknowledge each with a2a_ack after processing."""
    return _safe(lambda: _client().a2a_inbox())


@mcp.tool()
def a2a_ack(message_id: str) -> str:
    """Acknowledge an inbox message so it is not delivered again."""
    return _safe(lambda: _client().a2a_ack(message_id))


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
