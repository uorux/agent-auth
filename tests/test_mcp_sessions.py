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
    m._MINTED = False
    yield
    m._CLIENT = None
    m._KIND = None
    m._MINTED = False


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

def test_server_instructions_orient_an_agent():
    # Clients defer MCP tools to names only; the instructions are what an
    # agent reads first, so they must name the workflow's tools.
    text = m.mcp.instructions
    for tool in ("whoami", "list_capabilities", "request_access", "wait_for_decision",
                 "get_credential", "a2a_open", "create_session"):
        assert tool in text
        assert tool in {t.name for t in m.mcp._tool_manager.list_tools()}


def test_whoami():
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{BROKER}/v1/me").respond(200, json={"name": "claude-x-host", "kind": "ephemeral"})
        out = json.loads(m.whoami())
    assert out["name"] == "claude-x-host"


def _broker_with_idle_sweep(mock):
    """Sessions sess-1, sess-2, ... are minted in turn; those in `closed` are
    refused the way the broker refuses an idled-out session."""
    import httpx

    closed: set[str] = set()
    minted: list[str] = []

    def mint(request):
        minted.append(f"sess-{len(minted) + 1}")
        return httpx.Response(200, json={"session_id": minted[-1]})

    def answer(request):
        if request.headers.get("X-Agent-Session") in closed:
            return httpx.Response(401, json={"detail": "unknown or closed session"})
        return httpx.Response(200, json=[])

    mock.post(f"{BROKER}/v1/sessions").mock(side_effect=mint)
    me = mock.get(f"{BROKER}/v1/me").mock(side_effect=answer)
    threads = mock.get(f"{BROKER}/v1/a2a/threads").mock(side_effect=answer)
    threads.me = me
    return closed, minted, threads


def test_a_minted_session_the_broker_closed_is_replaced():
    m._KIND = "ephemeral"
    with respx.mock(assert_all_called=False) as mock:
        closed, minted, threads = _broker_with_idle_sweep(mock)

        assert json.loads(m.a2a_threads()) == []
        closed.add("sess-1")  # a long wait for a human: the broker idles it out
        assert json.loads(m.a2a_threads()) == []
        assert json.loads(m.a2a_threads()) == []

        assert minted == ["sess-1", "sess-2"]
        assert [c.request.headers["X-Agent-Session"] for c in threads.calls] == [
            "sess-1",
            "sess-1",
            "sess-2",
            "sess-2",
        ]


def test_a_session_the_caller_named_is_not_replaced():
    m._KIND = "ephemeral"
    with respx.mock(assert_all_called=False) as mock:
        closed, minted, _ = _broker_with_idle_sweep(mock)
        closed.add("sess-theirs")

        assert json.loads(m.a2a_threads())  == []  # mints sess-1, which stays live
        out = json.loads(m.a2a_threads(session_key="sess-theirs"))

        assert out == {"error": "unknown or closed session", "status_code": 401}
        assert minted == ["sess-1"]
        assert m._client().session_id == "sess-1"


def test_get_credential_to_file_keeps_the_token_out_of_the_reply(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BROKER}/v1/grants/g-1/credential").respond(
            200, json={"kind": "github_installation_token", "value": "ghs_secret"}
        )
        mock.get(f"{BROKER}/v1/grants/g-2/credential").respond(
            200, json={"kind": "github_repo", "value": "https://github.com/o/r"}
        )

        raw = m.get_credential("g-1", to_file=True)
        out = json.loads(raw)
        path = tmp_path / "agent-auth" / "credentials" / "g-1"

        assert "ghs_secret" not in raw and out["value"] is None
        assert out["file"] == str(path) and path.read_text() == "ghs_secret"
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert str(path) in out["git_helper"]
        # nothing secret about a created repo's URL: it stays in the reply
        assert json.loads(m.get_credential("g-2", to_file=True))["value"].endswith("/o/r")
        assert json.loads(m.get_credential("g-1"))["value"] == "ghs_secret"


def test_a_long_wait_is_several_short_requests(monkeypatch):
    """A proxy in front of the broker cuts a request at 100s; no single
    long-poll may be longer than a slice."""
    import agent_auth.client as c

    clock = [0.0]
    monkeypatch.setattr(c.time, "monotonic", lambda: clock[0])
    asked: list[float] = []

    def answer(request):
        import httpx

        wait = float(request.url.params["timeout"])
        asked.append(wait)
        clock[0] += wait
        status = "granted" if clock[0] >= 200 else "awaiting_human"
        return httpx.Response(200, json={"id": "r-1", "status": status})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BROKER}/v1/requests/r-1/wait").mock(side_effect=answer)
        assert json.loads(m.wait_for_decision("r-1", timeout_secs=150))["status"] == "awaiting_human"
        assert asked == [60, 60, 30]
        assert json.loads(m.wait_for_decision("r-1", timeout_secs=240))["status"] == "granted"
        assert asked == [60, 60, 30, 60]


def test_a_minted_session_is_kept_in_use_while_the_agent_is_quiet(monkeypatch):
    import time

    monkeypatch.setattr(m, "KEEPALIVE_SECS", 0.02)
    m._KIND = "ephemeral"
    with respx.mock(assert_all_called=False) as mock:
        closed, minted, threads = _broker_with_idle_sweep(mock)
        me = threads.me

        assert json.loads(m.a2a_threads()) == []
        time.sleep(0.2)  # the agent does nothing for a while
        touched = [c.request.headers.get("X-Agent-Session") for c in me.calls]
        assert len(touched) >= 3 and set(touched) == {"sess-1"}

        # Closed all the same (the broker restarted, say): forgotten, and the
        # next call gets a new one, which is kept in use in its turn.
        closed.add("sess-1")
        time.sleep(0.1)
        assert m._client().session_id == ""
        before = len(me.calls)
        time.sleep(0.1)
        assert len(me.calls) == before  # the old session's thread has stopped
        assert json.loads(m.a2a_threads()) == []
        assert minted == ["sess-1", "sess-2"]
        time.sleep(0.1)
        assert me.calls[-1].request.headers["X-Agent-Session"] == "sess-2"
        m._client().session_id = ""  # stop the thread before the mock goes away
        time.sleep(0.05)
