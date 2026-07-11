"""Stdio MCP server exposing the broker to agents.

Configure per-agent:
    AGENT_AUTH_URL=https://agent-auth.rooty.dev  AGENT_AUTH_API_KEY=aa_...  agent-auth-mcp
"""

from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import BrokerClient, BrokerError

mcp = FastMCP("agent-auth")

# One client per MCP server process so the a2a session (minted lazily below)
# sticks for the life of this agent instance — exactly the intended lifetime
# of an ephemeral agent's session.
_CLIENT: BrokerClient | None = None
_KIND: str | None = None


def _client() -> BrokerClient:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = BrokerClient()
    return _CLIENT


def _session_client() -> BrokerClient:
    """Client for a2a calls: ephemeral agents get a session auto-created on
    first use (label = cwd basename); service agents skip session machinery."""
    global _KIND
    client = _client()
    if client.session_id:
        return client
    if _KIND is None:
        _KIND = client.me().get("kind", "service")
    if _KIND == "ephemeral":
        label = os.path.basename(os.getcwd()) or "session"
        label = "".join(c for c in label if c.isalnum() or c in "._-")[:64] or "session"
        client.create_session(label)
    return client


def _client_for(session_key: str | None) -> BrokerClient:
    """Session-scoped client for ONE call. An explicit session_key builds a
    fresh client and never touches the process-global, so concurrent
    conversations sharing this MCP process (service runtimes like Hermes —
    one stdio subprocess for all Discord/cron/a2a conversations) can't clobber
    each other. Omitted → the legacy path: ephemeral cwd-auto session,
    service sessionless."""
    if session_key:
        client = BrokerClient()
        client.session_id = session_key  # → X-Agent-Session on this call
        return client
    return _session_client()


def _safe(fn) -> str:
    try:
        return json.dumps(fn(), indent=2, default=str)
    except BrokerError as exc:
        return json.dumps({"error": exc.detail, "status_code": exc.status_code})


@mcp.tool()
def list_capabilities() -> str:
    """List what you can request from this broker before composing a request.

    Returns each enabled platform and the exact roles / groups / repos /
    permissions you may ask for — with descriptions and each entry's typical
    routing (auto-approve, human review, llm review). Use it to (1) ask for
    something valid instead of guessing and getting denied, and (2) pick the
    narrowest capability that does the job — an auto-approved narrow role beats
    a broad one that a human has to review."""
    return _safe(lambda: _client().catalog())


@mcp.tool()
def request_access(
    platform: str,
    capability: str,
    resource: str,
    justification: str,
    duration: str = "1h",
    scope: dict[str, Any] | None = None,
    on_behalf_of_thread: str | None = None,
    session_key: str | None = None,
) -> str:
    """Request time-bounded access to a resource. The broker may auto-approve,
    deny, review with an LLM, or ask a human on Discord.

    on_behalf_of_thread (delegation): when another agent asked you, in an a2a
    thread, to do work that needs this access, pass THAT thread's id — only
    the thread whose conversation is asking for this request, never any other
    thread you happen to have open. The broker derives the delegator from the
    thread (its other participant), policy authorizes the pair, and the grant
    is revoked the moment the thread closes — so keep the thread open until
    the work is done, then close it to release the access.

    session_key: your conversation's session id (from create_session). A
    delegated (on_behalf_of_thread) request MUST pass the SAME session_key
    that accepted the thread — the broker checks the thread's session binding
    and denies a mismatched or missing one.

    platform/capability/resource conventions:
    - github: capability="repo", resource="owner/repo",
      scope={"permissions": {"contents": "write", "secrets": "write"}}
    - homelab: capability="group", resource=<lldap group, e.g. "svc-gitea">
      (once granted, your service account is in the group; authenticate to the
      service yourself — e.g. mint your own Gitea token)
    - kubernetes: capability=<role>, resource=<namespace> — the capability is
      the role you want (view, logs-reader, edit, or a narrow custom role like
      traefik-patcher; ask the operator which roles exist). Grants a
      ServiceAccount bound to that role in the namespace; get_credential returns
      a short-lived bearer token for kubectl (--token) or the API. Request the
      narrowest role that does the job — broad roles (edit/admin) get surfaced
      to a human, narrow ones are often auto-approved.
    - a2a: capability="talk", resource=<agent name>, scope={"topic": "deploy/*"}
    - google: capability in {calendar.read, calendar.write, gmail.read, drive.read}

    Write a SPECIFIC justification (what task, why this resource, why this
    duration) — vague justifications get denied. duration examples: "30m", "8h", "2d".
    Then call wait_for_decision with the returned request id."""
    return _safe(
        lambda: _client_for(session_key).request_access(
            platform,
            capability,
            resource,
            justification,
            duration,
            scope,
            on_behalf_of_thread=on_behalf_of_thread,
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
def create_session(label: str = "session") -> str:
    """Mint one session at the start of THIS conversation and pass the returned
    session_id as `session_key` on every subsequent a2a_* / request_access call,
    so your threads and delegated requests bind to this conversation. One
    session may span multiple threads (to different peers). If you omit
    session_key, calls are agent-level (not bound to this conversation)."""
    # Fresh client: minting must NOT mutate the process-global — concurrent
    # conversations share this MCP process in service runtimes.
    return _safe(lambda: BrokerClient().create_session(label))


@mcp.tool()
def close_session(session_key: str) -> str:
    """Close this conversation's session when its work is done: threads it
    owns end peer_gone for their peers and delegated grants get revoked."""

    def go():
        client = BrokerClient()
        client.session_id = session_key
        return client.close_session()

    return _safe(go)


@mcp.tool()
def check_a2a(
    peer: str,
    direction: str = "out",
    topic: str | None = None,
    session_key: str | None = None,
) -> str:
    """Check agent-to-agent permission. direction="out": may I open a thread to
    peer? direction="in": may peer open one to me? Grants belong to your agent
    identity (one identity per folder/workspace), so all your sessions share them."""
    return _safe(lambda: _client_for(session_key).a2a_check(peer, direction, topic))


@mcp.tool()
def a2a_open(
    to: str,
    payload: dict[str, Any],
    topic: str | None = None,
    session_key: str | None = None,
) -> str:
    """Open a conversation thread with another agent; payload is your first
    message (it rides the open). Requires an active a2a grant — on 403, call
    request_access(platform="a2a", capability="talk", resource=<to>) first;
    grants belong to your agent identity, so other sessions in this folder may
    already have one (check list_grants). If your grant is topic-scoped you
    MUST pass a topic matching its glob.

    The thread starts pending_open until the peer accepts or replies. Next:
    a2a_poll(thread_id) to wait for the reply."""
    return _safe(lambda: _client_for(session_key).a2a_open(to, payload, topic))


@mcp.tool()
def a2a_send(
    thread_id: str, payload: dict[str, Any], session_key: str | None = None
) -> str:
    """Send a message into an open thread you participate in. Replying to a
    pending_open thread you received accepts it implicitly (pass your
    session_key to bind the thread to this conversation)."""
    return _safe(lambda: _client_for(session_key).a2a_send(thread_id, payload))


@mcp.tool()
def a2a_poll(
    thread_id: str,
    after_seq: int = 0,
    wait: float = 60,
    session_key: str | None = None,
) -> str:
    """Read a thread past your cursor; this is how you wait for a reply. Blocks
    up to `wait` seconds for new messages or a state change, and returns the
    thread status too. Track the highest seq you've processed and pass it back
    as after_seq. If state is "closed", read close_reason — "peer_gone" means
    the other side's session ended: open a new thread, don't try to resume."""
    return _safe(lambda: _client_for(session_key).a2a_poll(thread_id, after_seq, wait))


@mcp.tool()
def a2a_threads(state: str | None = None, session_key: str | None = None) -> str:
    """List your threads (state: pending_open|open|closed), most recently
    active first, with peer liveness (peer_alive/peer_last_seen_at). With a
    session_key: only that conversation's threads."""
    return _safe(lambda: _client_for(session_key).a2a_threads(state))


@mcp.tool()
def a2a_accept(thread_id: str, session_key: str | None = None) -> str:
    """Accept a pending_open thread another agent opened to you (service
    agents; sending a reply accepts implicitly too). Pass your conversation's
    session_key (from create_session) — the thread then binds to it: wakes
    route only to that session, its liveness is the conversation's liveness,
    and the thread ends peer_gone when the session dies. Sessionless accept
    keeps the thread agent-level."""
    return _safe(lambda: _client_for(session_key).a2a_accept(thread_id))


@mcp.tool()
def a2a_reject(
    thread_id: str, reason: str | None = None, session_key: str | None = None
) -> str:
    """Reject a pending_open thread another agent opened to you."""
    return _safe(lambda: _client_for(session_key).a2a_reject(thread_id, reason))


@mcp.tool()
def a2a_close(
    thread_id: str, reason: str | None = None, session_key: str | None = None
) -> str:
    """Close a thread you participate in (hang up). Conversations are
    session-lived: your threads also close automatically if your session ends."""
    return _safe(lambda: _client_for(session_key).a2a_close(thread_id, reason))


@mcp.tool()
def a2a_events(
    wait: float = 60, after: str | None = None, session_key: str | None = None
) -> str:
    """Service agents: run this in a loop. Sessionless (dispatcher) calls see
    pending opens awaiting accept/reject plus all unbound-thread activity;
    calls with a session_key see only that conversation's threads. Returns
    a cursor to pass back next call. Use a2a_poll on a thread to read messages."""
    return _safe(lambda: _client_for(session_key).a2a_events(wait, after))


def run() -> None:
    mcp.run()


if __name__ == "__main__":
    run()
