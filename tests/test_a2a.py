"""a2a threads: handshake, sessions, per-session grants, liveness, sweeps,
webhook pings. The happy-path smoke test lives in test_api.py."""

from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import json
from datetime import timedelta

import httpx
import respx

from agent_auth.models import A2AMessage, A2AThread, AccessRequest, AgentSession, Grant, utcnow

from .conftest import make_agent

ADMIN = {"Authorization": "Bearer admin-secret"}


def auth(key: str, session_id: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {key}"}
    if session_id:
        headers["X-Agent-Session"] = session_id
    return headers


async def _mk_service(api, name: str, webhook_url: str | None = None) -> dict:
    body = {"name": name}
    if webhook_url:
        body["webhook_url"] = webhook_url
    resp = await api.post("/admin/agents", headers=ADMIN, json=body)
    assert resp.status_code == 200
    return resp.json()


async def _mk_ephemeral(api, name: str) -> dict:
    resp = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": name, "kind": "ephemeral"}
    )
    assert resp.status_code == 200
    return resp.json()


async def _session(api, key: str, label: str = "worktree") -> str:
    resp = await api.post("/v1/sessions", headers=auth(key), json={"label": label})
    assert resp.status_code == 200
    out = resp.json()
    assert out["name"].startswith(f"{label}-")
    return out["session_id"]


async def _grant_a2a(api, key: str, to: str, session_id: str | None = None, topic=None) -> str:
    scope = {"topic": topic} if topic else {}
    resp = await api.post(
        "/v1/requests",
        headers=auth(key, session_id),
        json={
            "platform": "a2a",
            "capability": "talk",
            "resource": to,
            "scope": scope,
            "justification": "coordinate work",
            "requested_duration": "1h",
        },
    )
    body = resp.json()
    assert body["status"] == "granted", body
    return body["grant_id"]


async def _open(api, key: str, to: str, session_id=None, payload=None, topic=None):
    body = {"to": to, "payload": payload or {"q": 1}}
    if topic:
        body["topic"] = topic
    return await api.post("/v1/a2a/threads", headers=auth(key, session_id), json=body)


# --------------------------------------------------------------- sessions


async def test_session_lifecycle(api, db):
    await _mk_ephemeral(api, "claude-host1")
    agents = (await api.get("/admin/agents", headers=ADMIN)).json()
    key = None  # key only shown on create; re-create to capture
    a = await api.post("/admin/agents", headers=ADMIN, json={"name": "claude-host2", "kind": "ephemeral"})
    key = a.json()["api_key"]

    sid = await _session(api, key, "agent-auth")
    me = (await api.get("/v1/me", headers=auth(key, sid))).json()
    assert me["kind"] == "ephemeral"
    assert me["session"]["id"] == sid
    assert me["session"]["name"].startswith("agent-auth-")

    # unknown session id → 401
    assert (await api.get("/v1/me", headers=auth(key, "bogus"))).status_code == 401

    # closed session → 401
    assert (await api.post("/v1/sessions/close", headers=auth(key, sid))).status_code == 200
    assert (await api.get("/v1/me", headers=auth(key, sid))).status_code == 401

    # another agent's session → 401
    b = await api.post("/admin/agents", headers=ADMIN, json={"name": "claude-host3", "kind": "ephemeral"})
    sid_b = await _session(api, b.json()["api_key"])
    assert (await api.get("/v1/me", headers=auth(key, sid_b))).status_code == 401


# -------------------------------------------------------------- handshake


async def test_explicit_accept_and_close(api, db):
    s = await _mk_service(api, "auto-open1")
    r = await _mk_service(api, "svc-resp1")
    await _grant_a2a(api, s["api_key"], "svc-resp1")

    thread = (await _open(api, s["api_key"], "svc-resp1")).json()
    tid = thread["thread_id"]
    assert thread["state"] == "pending_open"

    # only the responder may accept
    assert (
        await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(s["api_key"]))
    ).status_code == 403
    accepted = (
        await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(r["api_key"]))
    ).json()
    assert accepted["state"] == "open"
    # accepting twice conflicts
    assert (
        await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(r["api_key"]))
    ).status_code == 409

    # now the initiator may send follow-ups
    sent = (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages", headers=auth(s["api_key"]), json={"payload": {"n": 2}}
        )
    ).json()
    assert sent["seq"] == 2

    closed = (
        await api.post(f"/v1/a2a/threads/{tid}/close", headers=auth(s["api_key"]), json={})
    ).json()
    assert closed["state"] == "closed" and closed["close_reason"] == "closed"
    # no sends after close
    assert (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages", headers=auth(r["api_key"]), json={"payload": {}}
        )
    ).status_code == 409


async def test_reject(api, db):
    s = await _mk_service(api, "auto-open2")
    r = await _mk_service(api, "svc-resp2")
    await _grant_a2a(api, s["api_key"], "svc-resp2")
    tid = (await _open(api, s["api_key"], "svc-resp2")).json()["thread_id"]

    rejected = (
        await api.post(
            f"/v1/a2a/threads/{tid}/reject",
            headers=auth(r["api_key"]),
            json={"reason": "busy, try later"},
        )
    ).json()
    assert rejected["state"] == "closed"
    assert rejected["close_reason"] == "rejected"
    assert rejected["close_note"] == "busy, try later"
    # initiator sees the rejection
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(s["api_key"]))).json()
    assert seen["close_reason"] == "rejected"


async def test_initiator_cannot_send_on_pending_open(api, db):
    s = await _mk_service(api, "auto-open3")
    await _mk_service(api, "svc-resp3")
    await _grant_a2a(api, s["api_key"], "svc-resp3")
    tid = (await _open(api, s["api_key"], "svc-resp3")).json()["thread_id"]
    resp = await api.post(
        f"/v1/a2a/threads/{tid}/messages", headers=auth(s["api_key"]), json={"payload": {}}
    )
    assert resp.status_code == 409


async def test_non_participant_gets_404(api, db):
    s = await _mk_service(api, "auto-open4")
    await _mk_service(api, "svc-resp4")
    c = await _mk_service(api, "svc-nosy")
    await _grant_a2a(api, s["api_key"], "svc-resp4")
    tid = (await _open(api, s["api_key"], "svc-resp4")).json()["thread_id"]
    assert (
        await api.get(f"/v1/a2a/threads/{tid}", headers=auth(c["api_key"]))
    ).status_code == 404
    assert (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages", headers=auth(c["api_key"]), json={"payload": {}}
        )
    ).status_code == 404


# ------------------------------------------------------ per-session grants


async def test_grants_shared_across_sessions(api, db):
    """The per-folder agent key is the permission boundary; sessions of one
    identity share its grants but keep their own threads."""
    await _mk_service(api, "svc-homelab")
    a = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": "claude-desk", "kind": "ephemeral"}
    )
    key = a.json()["api_key"]

    # a grant may be requested even outside a session (grants are agent-level)
    sid_a = await _session(api, key, "proj-a")
    await _grant_a2a(api, key, "svc-homelab", session_id=sid_a)
    assert (await _open(api, key, "svc-homelab", session_id=sid_a)).status_code == 200

    # a second session shares the identity's grant — no re-request needed
    sid_b = await _session(api, key, "proj-b")
    check = (
        await api.get(
            "/v1/a2a/check", headers=auth(key, sid_b), params={"peer": "svc-homelab"}
        )
    ).json()
    assert check["allowed"] is True
    assert (await _open(api, key, "svc-homelab", session_id=sid_b)).status_code == 200

    # but threads stay session-scoped even though the grant is shared
    tid_a = (
        await api.get("/v1/a2a/threads", headers=auth(key, sid_a))
    ).json()
    assert len(tid_a) == 1  # only session A's own thread

    # sessions are still mandatory for a2a use (threads/liveness need one)
    assert (await _open(api, key, "svc-homelab")).status_code == 400


async def test_thread_access_bound_to_session(api, db):
    """Session binding covers reads/list/events/close, not just sends —
    conversations are session-lived even against later sessions of the same
    agent identity."""
    await _mk_service(api, "svc-bound")
    a = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": "claude-bound", "kind": "ephemeral"}
    )
    key = a.json()["api_key"]
    sid_a = await _session(api, key, "proj-a")
    await _grant_a2a(api, key, "svc-bound", session_id=sid_a)
    tid = (await _open(api, key, "svc-bound", session_id=sid_a)).json()["thread_id"]

    sid_b = await _session(api, key, "proj-b")
    # session B can't read, poll, close, or send on A's thread
    assert (
        await api.get(f"/v1/a2a/threads/{tid}", headers=auth(key, sid_b))
    ).status_code == 403
    assert (
        await api.get(f"/v1/a2a/threads/{tid}/messages", headers=auth(key, sid_b))
    ).status_code == 403
    assert (
        await api.post(f"/v1/a2a/threads/{tid}/close", headers=auth(key, sid_b), json={})
    ).status_code == 403
    assert (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages", headers=auth(key, sid_b), json={"payload": {}}
        )
    ).status_code == 403
    # B's listing/events don't include A's thread
    assert (await api.get("/v1/a2a/threads", headers=auth(key, sid_b))).json() == []
    ev = (await api.get("/v1/a2a/events", headers=auth(key, sid_b))).json()
    assert ev["pending_opens"] == [] and ev["activity"] == []

    # omitting the session header doesn't widen anything for ephemeral agents
    for path in (f"/v1/a2a/threads/{tid}", f"/v1/a2a/threads/{tid}/messages",
                 "/v1/a2a/threads", "/v1/a2a/events"):
        assert (await api.get(path, headers=auth(key))).status_code == 400

    # the owning session still has full access
    assert (
        await api.get(f"/v1/a2a/threads/{tid}", headers=auth(key, sid_a))
    ).status_code == 200


async def test_ephemeral_cannot_receive(api, db):
    s = await _mk_service(api, "auto-caller")
    await _mk_ephemeral(api, "claude-target")

    # request-time: validator rejects ephemeral targets
    resp = await api.post(
        "/v1/requests",
        headers=auth(s["api_key"]),
        json={
            "platform": "a2a",
            "capability": "talk",
            "resource": "claude-target",
            "justification": "x",
            "requested_duration": "1h",
        },
    )
    body = resp.json()
    assert body["status"] == "denied"
    assert "service agents" in body["decision_reason"]

    # thread-layer defense in depth: a manufactured grant still can't open
    async with db.session() as dbs:
        from sqlalchemy import select

        from agent_auth.models import Agent

        caller = (
            await dbs.execute(select(Agent).where(Agent.name == "auto-caller"))
        ).scalar_one()
        req = AccessRequest(
            agent_id=caller.id,
            platform="a2a",
            capability="talk",
            resource="claude-target",
            justification="manufactured",
            requested_duration_secs=3600,
        )
        dbs.add(req)
        await dbs.flush()
        dbs.add(
            Grant(
                request_id=req.id,
                agent_id=caller.id,
                platform="a2a",
                capability="talk",
                resource="claude-target",
                expires_at=utcnow() + timedelta(hours=1),
            )
        )
    resp = await _open(api, s["api_key"], "claude-target")
    assert resp.status_code == 403
    assert "ephemeral" in resp.json()["detail"]


# ---------------------------------------------------------------- topics


async def test_topic_glob_enforced_at_open(api, db):
    s = await _mk_service(api, "auto-topic")
    await _mk_service(api, "svc-topic")
    await _grant_a2a(api, s["api_key"], "svc-topic", topic="deploy/*")

    assert (
        await _open(api, s["api_key"], "svc-topic", topic="deploy/cactus")
    ).status_code == 200
    assert (await _open(api, s["api_key"], "svc-topic", topic="gossip")).status_code == 403
    # omitting the topic must not bypass a topic-scoped grant
    assert (await _open(api, s["api_key"], "svc-topic")).status_code == 403
    # the informational check without a topic still reports "some grant exists"
    check = (
        await api.get(
            "/v1/a2a/check", headers=auth(s["api_key"]), params={"peer": "svc-topic"}
        )
    ).json()
    assert check["allowed"] is True
    # but a mismatched explicit topic is still refused by check
    check = (
        await api.get(
            "/v1/a2a/check",
            headers=auth(s["api_key"]),
            params={"peer": "svc-topic", "topic": "gossip"},
        )
    ).json()
    assert check["allowed"] is False

    # an unscoped grant keeps allowing topic-less opens
    s2 = await _mk_service(api, "auto-topic2")
    await _grant_a2a(api, s2["api_key"], "svc-topic")
    assert (await _open(api, s2["api_key"], "svc-topic")).status_code == 200


# ------------------------------------------------------------- long-polls


async def test_message_longpoll_wakes_on_reply(api, db):
    s = await _mk_service(api, "auto-poll")
    r = await _mk_service(api, "svc-poll")
    await _grant_a2a(api, s["api_key"], "svc-poll")
    tid = (await _open(api, s["api_key"], "svc-poll")).json()["thread_id"]

    async def reply_soon():
        await asyncio.sleep(0.2)
        await api.post(
            f"/v1/a2a/threads/{tid}/messages",
            headers=auth(r["api_key"]),
            json={"payload": {"answer": 42}},
        )

    task = asyncio.create_task(reply_soon())
    t0 = asyncio.get_event_loop().time()
    resp = await api.get(
        f"/v1/a2a/threads/{tid}/messages",
        headers=auth(s["api_key"]),
        params={"after_seq": 1, "wait": 10},
    )
    await task
    elapsed = asyncio.get_event_loop().time() - t0
    body = resp.json()
    assert [m["payload"] for m in body["messages"]] == [{"answer": 42}]
    assert elapsed < 5  # woke on the event, not the deadline

    # empty wait times out with no messages
    resp = await api.get(
        f"/v1/a2a/threads/{tid}/messages",
        headers=auth(s["api_key"]),
        params={"after_seq": 2, "wait": 0.5},
    )
    assert resp.json()["messages"] == []


async def test_events_longpoll_and_cursor(api, db):
    s = await _mk_service(api, "auto-ev")
    r = await _mk_service(api, "svc-ev")
    await _grant_a2a(api, s["api_key"], "svc-ev")

    async def open_soon():
        await asyncio.sleep(0.2)
        return (await _open(api, s["api_key"], "svc-ev")).json()

    task = asyncio.create_task(open_soon())
    resp = await api.get(
        "/v1/a2a/events", headers=auth(r["api_key"]), params={"wait": 10}
    )
    thread = await task
    body = resp.json()
    assert [t["thread_id"] for t in body["pending_opens"]] == [thread["thread_id"]]
    assert body["cursor"] is not None

    # cursor advances: nothing new since
    again = (
        await api.get(
            "/v1/a2a/events",
            headers=auth(r["api_key"]),
            params={"wait": 0, "after": body["cursor"]},
        )
    ).json()
    assert again["activity"] == []
    # pending opens are always shown until resolved
    assert [t["thread_id"] for t in again["pending_opens"]] == [thread["thread_id"]]


# ----------------------------------------------------------------- sweeps


async def test_open_timeout_sweep(api, db, a2a_service, settings):
    s = await _mk_service(api, "auto-sweep1")
    await _mk_service(api, "svc-sweep1")
    await _grant_a2a(api, s["api_key"], "svc-sweep1")
    tid = (await _open(api, s["api_key"], "svc-sweep1")).json()["thread_id"]

    async with db.session() as dbs:
        row = await dbs.get(A2AThread, tid)
        row.created_at = utcnow() - timedelta(seconds=settings.a2a_open_timeout_secs + 60)

    counts = await a2a_service.sweep()
    assert counts["open_timeout"] == 1
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(s["api_key"]))).json()
    assert seen["state"] == "closed" and seen["close_reason"] == "open_timeout"


async def test_idle_thread_sweep(api, db, a2a_service, settings):
    s = await _mk_service(api, "auto-sweep2")
    r = await _mk_service(api, "svc-sweep2")
    await _grant_a2a(api, s["api_key"], "svc-sweep2")
    tid = (await _open(api, s["api_key"], "svc-sweep2")).json()["thread_id"]
    await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(r["api_key"]))

    async with db.session() as dbs:
        row = await dbs.get(A2AThread, tid)
        row.last_activity_at = utcnow() - timedelta(
            seconds=settings.a2a_thread_idle_timeout_secs + 60
        )

    counts = await a2a_service.sweep()
    assert counts["idle_timeout"] == 1
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(s["api_key"]))).json()
    assert seen["close_reason"] == "idle_timeout"


async def test_idle_session_sweep_closes_threads_peer_gone(api, db, a2a_service, settings):
    await _mk_service(api, "svc-sweep3")
    a = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": "claude-sweep", "kind": "ephemeral"}
    )
    key = a.json()["api_key"]
    sid = await _session(api, key)
    sid_fresh = await _session(api, key, "fresh")
    await _grant_a2a(api, key, "svc-sweep3", session_id=sid)
    tid = (await _open(api, key, "svc-sweep3", session_id=sid)).json()["thread_id"]

    async with db.session() as dbs:
        row = await dbs.get(AgentSession, sid)
        row.last_seen_at = utcnow() - timedelta(seconds=settings.session_idle_timeout_secs + 60)

    counts = await a2a_service.sweep()
    assert counts["sessions_idled"] == 1

    async with db.session() as dbs:
        stale = await dbs.get(AgentSession, sid)
        fresh = await dbs.get(AgentSession, sid_fresh)
        thread = await dbs.get(A2AThread, tid)
    assert stale.closed_at is not None and stale.close_reason == "idle"
    assert fresh.closed_at is None  # recent session untouched
    assert thread.state == "closed" and thread.close_reason == "peer_gone"

    # the dead session no longer authenticates
    assert (await api.get("/v1/me", headers=auth(key, sid))).status_code == 401


async def test_grant_revocation_closes_thread(api, db, a2a_service):
    # lazy path: revocation detected on the next send
    s = await _mk_service(api, "auto-rev1")
    r = await _mk_service(api, "svc-rev1")
    grant_id = await _grant_a2a(api, s["api_key"], "svc-rev1")
    tid = (await _open(api, s["api_key"], "svc-rev1")).json()["thread_id"]
    await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(r["api_key"]))

    assert (
        await api.post(f"/admin/grants/{grant_id}/revoke", headers=ADMIN)
    ).status_code == 200
    resp = await api.post(
        f"/v1/a2a/threads/{tid}/messages", headers=auth(s["api_key"]), json={"payload": {}}
    )
    assert resp.status_code == 403
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(r["api_key"]))).json()
    assert seen["state"] == "closed" and seen["close_reason"] == "grant_revoked"
    # responder can't keep talking either
    assert (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages", headers=auth(r["api_key"]), json={"payload": {}}
        )
    ).status_code == 409

    # sweep path: nobody sends, the scheduler still closes it
    s2 = await _mk_service(api, "auto-rev2")
    await _mk_service(api, "svc-rev2")
    grant2 = await _grant_a2a(api, s2["api_key"], "svc-rev2")
    tid2 = (await _open(api, s2["api_key"], "svc-rev2")).json()["thread_id"]
    await api.post(f"/admin/grants/{grant2}/revoke", headers=ADMIN)
    counts = await a2a_service.sweep()
    assert counts["grant_revoked"] == 1
    seen = (await api.get(f"/v1/a2a/threads/{tid2}", headers=auth(s2["api_key"]))).json()
    assert seen["close_reason"] == "grant_revoked"


# ---------------------------------------------------------------- liveness


async def test_peer_liveness_fields(api, db, settings):
    s = await _mk_service(api, "auto-live")
    r = await _mk_service(api, "svc-live")
    await _grant_a2a(api, s["api_key"], "svc-live")
    tid = (await _open(api, s["api_key"], "svc-live")).json()["thread_id"]

    # responder has authenticated (agent creation isn't a call; poke /v1/me)
    await api.get("/v1/me", headers=auth(r["api_key"]))
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(s["api_key"]))).json()
    assert seen["peer"] == "svc-live"
    assert seen["peer_alive"] is True

    from sqlalchemy import select

    from agent_auth.models import Agent

    async with db.session() as dbs:
        peer = (
            await dbs.execute(select(Agent).where(Agent.name == "svc-live"))
        ).scalar_one()
        peer.last_seen_at = utcnow() - timedelta(
            seconds=settings.liveness_threshold_secs + 60
        )
    seen = (await api.get(f"/v1/a2a/threads/{tid}", headers=auth(s["api_key"]))).json()
    assert seen["peer_alive"] is False


# ---------------------------------------------------------------- webhooks


async def test_webhook_ping_shape_and_signature(api, db):
    captured: list[httpx.Request] = []

    def capture(request):
        captured.append(request)
        return httpx.Response(200)

    s = await _mk_service(api, "auto-hook")
    r = await _mk_service(api, "svc-hook", webhook_url="http://hook.test/cb")
    secret = r["webhook_secret"]
    assert secret  # shown once at create
    # listings never include it
    listing = (await api.get("/admin/agents", headers=ADMIN)).json()
    assert all(a.get("webhook_secret") is None for a in listing)

    await _grant_a2a(api, s["api_key"], "svc-hook")
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://hook.test/cb").mock(side_effect=capture)
        thread = (await _open(api, s["api_key"], "svc-hook", payload={"secret": "no"})).json()

    assert len(captured) == 1
    body = json.loads(captured[0].content)
    assert body["type"] == "a2a_thread_open"
    assert body["thread_id"] == thread["thread_id"]
    assert body["from"] == "auto-hook"
    assert "payload" not in body  # notify-only: pull via cursor read
    sig = captured[0].headers["X-Agent-Auth-Signature"]
    expected = hmac_mod.new(secret.encode(), captured[0].content, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"

    # webhook failure doesn't fail the API call; the open still exists
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://hook.test/cb").mock(side_effect=httpx.ConnectError("down"))
        resp = await api.post(
            f"/v1/a2a/threads/{thread['thread_id']}/reject",
            headers=auth(r["api_key"]),
            json={},
        )
    assert resp.status_code == 200


async def test_webhook_global_secret_fallback(api, db, settings):
    settings.webhook_signing_secret = "global-fallback"
    captured: list[httpx.Request] = []

    s = await _mk_service(api, "auto-hook2")
    r = await _mk_service(api, "svc-hook2", webhook_url="http://hook2.test/cb")
    # strip the per-agent secret to exercise the fallback
    from sqlalchemy import select

    from agent_auth.models import Agent

    async with db.session() as dbs:
        peer = (
            await dbs.execute(select(Agent).where(Agent.name == "svc-hook2"))
        ).scalar_one()
        peer.webhook_secret = None

    await _grant_a2a(api, s["api_key"], "svc-hook2")
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://hook2.test/cb").mock(
            side_effect=lambda req: (captured.append(req), httpx.Response(200))[1]
        )
        await _open(api, s["api_key"], "svc-hook2")

    sig = captured[0].headers["X-Agent-Auth-Signature"]
    expected = hmac_mod.new(b"global-fallback", captured[0].content, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


async def test_unsigned_pings_never_sent(api, db, settings):
    """No per-agent secret and no global secret → the ping is skipped, not
    sent unsigned; the API call itself still succeeds."""
    settings.webhook_signing_secret = ""
    s = await _mk_service(api, "auto-nosig")
    await _mk_service(api, "svc-nosig", webhook_url="http://nosig.test/cb")
    from sqlalchemy import select

    from agent_auth.models import Agent

    async with db.session() as dbs:
        peer = (
            await dbs.execute(select(Agent).where(Agent.name == "svc-nosig"))
        ).scalar_one()
        peer.webhook_secret = None

    await _grant_a2a(api, s["api_key"], "svc-nosig")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post("http://nosig.test/cb").respond(200)
        resp = await _open(api, s["api_key"], "svc-nosig")
    assert resp.status_code == 200
    assert not route.called


async def test_rotate_webhook_secret(api, db):
    r = await _mk_service(api, "svc-rot", webhook_url="http://rot.test/cb")
    rotated = (
        await api.post(f"/admin/agents/{r['id']}/rotate-webhook-secret", headers=ADMIN)
    ).json()
    assert rotated["webhook_secret"] and rotated["webhook_secret"] != r["webhook_secret"]
    # the agent can read its own secret for verifier config
    me = (await api.get("/v1/me", headers=auth(r["api_key"]))).json()
    assert me["webhook_secret"] == rotated["webhook_secret"]


# ------------------------------------------------------------------ legacy


async def test_legacy_null_thread_messages_invisible(api, db):
    s = await _mk_service(api, "auto-legacy")
    r = await _mk_service(api, "svc-legacy")
    grant_id = await _grant_a2a(api, s["api_key"], "svc-legacy")

    from sqlalchemy import select

    from agent_auth.models import Agent

    async with db.session() as dbs:
        sender = (
            await dbs.execute(select(Agent).where(Agent.name == "auto-legacy"))
        ).scalar_one()
        recip = (
            await dbs.execute(select(Agent).where(Agent.name == "svc-legacy"))
        ).scalar_one()
        dbs.add(
            A2AMessage(
                sender_agent_id=sender.id,
                recipient_agent_id=recip.id,
                grant_id=grant_id,
                payload={"pre-thread": True},
            )
        )

    # legacy row surfaces nowhere in the thread APIs
    assert (await api.get("/v1/a2a/threads", headers=auth(r["api_key"]))).json() == []
    events = (await api.get("/v1/a2a/events", headers=auth(r["api_key"]))).json()
    assert events["pending_opens"] == [] and events["activity"] == []
