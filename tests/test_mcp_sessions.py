"""MCP per-conversation sessions via explicit session_key: a shared MCP server
process (service runtimes like Hermes) binds each conversation to its own
broker session without any process-global mutation. Tools are exercised
directly; respx intercepts the underlying BrokerClient HTTP."""

from __future__ import annotations

import json

import pytest
import respx

import agent_auth.mcp_server as m

BROKER = "http://broker.test"


@pytest.fixture(autouse=True)
def _mcp_env(monkeypatch):
    monkeypatch.setenv("AGENT_AUTH_URL", BROKER)
    monkeypatch.setenv("AGENT_AUTH_API_KEY", "aa_abcdef_secret")
    monkeypatch.delenv("AGENT_AUTH_SESSION", raising=False)
    # Fresh module globals; _KIND="service" skips the /v1/me kind probe.
    m._CLIENT = None
    m._KIND = "service"
    yield
    m._CLIENT = None
    m._KIND = None


def test_create_session_returns_id_without_touching_global():
    with respx.mock(assert_all_called=False) as mock:
        mock.post(f"{BROKER}/v1/sessions").respond(
            200, json={"session_id": "sess-1", "name": "task-ab12", "created_at": "2026-07-09"}
        )
        threads = mock.get(f"{BROKER}/v1/a2a/threads").respond(200, json=[])

        out = json.loads(m.create_session("task"))
        assert out["session_id"] == "sess-1"

        # the global client was NOT mutated: a subsequent call without
        # session_key is still sessionless/agent-level
        m.a2a_threads()
        req = threads.calls[0].request
        assert "X-Agent-Session" not in req.headers
        assert m._client().session_id == ""


def test_session_key_routes_independently():
    with respx.mock(assert_all_called=False) as mock:
        accept = mock.post(url__regex=rf"{BROKER}/v1/a2a/threads/[^/]+/accept").respond(
            200, json={"state": "open"}
        )
        m.a2a_accept("t1", session_key="sess-A")
        m.a2a_accept("t2", session_key="sess-B")  # concurrent conversation, other key
        m.a2a_accept("t3")  # sessionless dispatcher-style call

        headers = [c.request.headers.get("X-Agent-Session") for c in accept.calls]
        assert headers == ["sess-A", "sess-B", None]


def test_request_access_forwards_delegation_and_session_key():
    with respx.mock(assert_all_called=False) as mock:
        reqs = mock.post(f"{BROKER}/v1/requests").respond(
            200, json={"id": "r1", "status": "granted"}
        )
        m.request_access(
            "homelab",
            "group",
            "svc-gitea",
            "claude asked in-thread",
            on_behalf_of_thread="tid-1",
            session_key="sess-A",
        )
        call = reqs.calls[0].request
        assert json.loads(call.content)["on_behalf_of_thread"] == "tid-1"
        assert call.headers["X-Agent-Session"] == "sess-A"


def test_close_session_targets_the_given_key():
    with respx.mock(assert_all_called=False) as mock:
        close = mock.post(f"{BROKER}/v1/sessions/close").respond(
            200, json={"ok": True, "threads_closed": 1}
        )
        out = json.loads(m.close_session("sess-A"))
        assert out["ok"] is True
        assert close.calls[0].request.headers["X-Agent-Session"] == "sess-A"
        assert m._client().session_id == ""  # global untouched