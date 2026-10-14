"""The admin panel's chat: the operator writing to agents over a2a threads."""

from __future__ import annotations

import asyncio

import httpx
import respx

from agent_auth.core import webui
from agent_auth.core.a2a import OPERATOR_KIND
from agent_auth.models import A2AThread, utcnow

from .conftest import make_agent
from .test_webui import BASE, provider, session_headers, ui  # noqa: F401  (fixtures)

ADMIN = {"Authorization": "Bearer admin-secret"}


async def hermes(db, name="hermes-homelab-recusant"):
    agent, key = await make_agent(db, name, runtime="hermes", project="homelab", last_listen_at=utcnow())
    return agent, {"Authorization": f"Bearer {key}"}


async def test_the_operator_writes_and_an_agent_answers(api, db):
    _, as_hermes = await hermes(db)
    opened = await api.post(
        "/admin/chat/threads",
        headers=ADMIN,
        json={"to": "hermes-homelab-recusant", "topic": "backups", "text": "Did last night's backup run?"},
    )
    assert opened.status_code == 200, opened.text
    thread_id = opened.json()["thread_id"]
    assert opened.json()["state"] == "pending_open"

    # Hermes sees an ordinary thread, from `operator`.
    events = (await api.get("/v1/a2a/events", headers=as_hermes)).json()
    pending = events["pending_opens"]
    assert [t["peer"] for t in pending] == ["operator"] and pending[0]["topic"] == "backups"
    got = (await api.get(f"/v1/a2a/threads/{thread_id}/messages", headers=as_hermes)).json()
    assert got["messages"][0]["from"] == "operator"
    assert got["messages"][0]["payload"] == {
        "type": "message",
        "text": "Did last night's backup run?",
        "operator": "admin token",
    }
    reply = await api.post(
        f"/v1/a2a/threads/{thread_id}/messages",
        headers=as_hermes,
        json={"payload": {"type": "message", "text": "Yes, at 03:00."}},
    )
    assert reply.status_code == 200, reply.text

    read = (await api.get(f"/admin/chat/threads/{thread_id}", headers=ADMIN)).json()
    assert read["thread"]["state"] == "open" and read["thread"]["peer"] == "hermes-homelab-recusant"
    assert [(m["from"], m["text"]) for m in read["messages"]] == [
        ("operator", "Did last night's backup run?"),
        ("hermes-homelab-recusant", "Yes, at 03:00."),
    ]
    assert (await api.get(f"/admin/chat/threads/{thread_id}?after_seq=2", headers=ADMIN)).json()["messages"] == []

    sent = await api.post(f"/admin/chat/threads/{thread_id}/messages", headers=ADMIN, json={"text": "Thanks."})
    assert sent.status_code == 200 and sent.json()["seq"] == 3

    listed = (await api.get("/admin/chat/threads", headers=ADMIN)).json()
    assert [(t["to"], t["preview"], t["last_from_operator"]) for t in listed] == [
        ("hermes-homelab-recusant", "Thanks.", True)
    ]

    # Hermes' result message is shown as its summary.
    await api.post(
        f"/v1/a2a/threads/{thread_id}/messages",
        headers=as_hermes,
        json={"payload": {"type": "result", "status": "done", "summary": "Answered."}},
    )
    last = (await api.get(f"/admin/chat/threads/{thread_id}?after_seq=3", headers=ADMIN)).json()["messages"]
    assert [(m["type"], m["status"], m["summary"]) for m in last] == [("result", "done", "Answered.")]

    closed = await api.post(f"/admin/chat/threads/{thread_id}/close", headers=ADMIN, json={})
    assert closed.status_code == 200 and closed.json()["state"] == "closed"
    again = await api.post(f"/admin/chat/threads/{thread_id}/messages", headers=ADMIN, json={"text": "?"})
    assert again.status_code == 409


async def test_a_reply_wakes_the_waiting_panel(api, db):
    _, as_hermes = await hermes(db)
    thread_id = (
        await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "hermes-homelab-recusant", "text": "hi"})
    ).json()["thread_id"]
    waiting = asyncio.create_task(api.get(f"/admin/chat/threads/{thread_id}?after_seq=1&wait=20", headers=ADMIN))
    await asyncio.sleep(0.2)
    assert not waiting.done()
    await api.post(
        f"/v1/a2a/threads/{thread_id}/messages", headers=as_hermes, json={"payload": {"type": "message", "text": "hello"}}
    )
    got = await asyncio.wait_for(waiting, timeout=3)
    assert [m["text"] for m in got.json()["messages"]] == ["hello"]


async def test_no_grant_backs_it_and_the_sweep_leaves_it_open(api, db, app):
    _, as_hermes = await hermes(db)
    thread_id = (
        await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "hermes-homelab-recusant", "text": "hi"})
    ).json()["thread_id"]
    await api.post(f"/v1/a2a/threads/{thread_id}/accept", headers=as_hermes)
    counts = await app.state.a2a.sweep()
    assert counts["grant_revoked"] == 0
    async with db.session() as session:
        thread = await session.get(A2AThread, thread_id)
        assert thread.grant_id is None and thread.state == "open"


async def test_only_service_agents_that_listen(api, db):
    await make_agent(db, "claude-x-galaxy", kind="ephemeral")
    await make_agent(db, "hermes-asleep", runtime="hermes")  # never listened
    await hermes(db)
    peers = {p["name"]: p["reachable"] for p in (await api.get("/admin/chat/peers", headers=ADMIN)).json()}
    assert peers == {"hermes-asleep": False, "hermes-homelab-recusant": True}
    to_cli = await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "claude-x-galaxy", "text": "hi"})
    assert to_cli.status_code == 403
    to_asleep = await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "hermes-asleep", "text": "hi"})
    assert to_asleep.status_code == 409


async def test_the_operator_row_speaks_only_through_the_panel(api, db, app):
    await hermes(db)
    await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "hermes-homelab-recusant", "text": "hi"})
    operator = await app.state.a2a.operator()
    assert operator.kind == OPERATOR_KIND and operator.name == "operator"
    for method, path, body in [
        ("POST", f"/admin/agents/{operator.id}/rotate-key", None),
        ("POST", f"/admin/agents/{operator.id}/rename", {"name": "someone"}),
        ("POST", f"/admin/agents/{operator.id}/set-kind", {"kind": "service"}),
        ("POST", f"/admin/agents/{operator.id}/set-webhook", {"webhook_url": "https://x.test/hook"}),
        ("POST", f"/admin/agents/{operator.id}/rotate-webhook-secret", None),
        ("PATCH", f"/admin/agents/{operator.id}/attributes", {"runtime": "claude"}),
    ]:
        resp = await api.request(method, path, headers=ADMIN, json=body)
        assert resp.status_code == 409, (path, resp.text)
    # No other agent takes the name.
    assert (await api.post("/admin/agents", headers=ADMIN, json={"name": "operator"})).status_code == 409
    other, _ = await make_agent(db, "claude-y")
    resp = await api.post(f"/admin/agents/{other.id}/rename", headers=ADMIN, json={"name": "operator"})
    assert resp.status_code == 409

    # Even a row of the kind with a real key does not authenticate.
    _, key = await make_agent(db, "op2", kind=OPERATOR_KIND)
    assert (await api.get("/v1/me", headers={"Authorization": f"Bearer {key}"})).status_code == 401


async def test_an_agent_named_operator_blocks_the_chat_until_renamed(api, db):
    await make_agent(db, "operator")
    await hermes(db)
    resp = await api.post("/admin/chat/threads", headers=ADMIN, json={"to": "hermes-homelab-recusant", "text": "hi"})
    assert resp.status_code == 409 and "rename" in resp.json()["detail"]


@respx.mock
async def test_from_the_panel_the_signed_in_user_is_recorded(app, db, ui, provider):  # noqa: F811
    _, as_hermes = await hermes(db)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as panel:
        headers, csrf = await session_headers(panel, provider)
        opened = await panel.post(
            "/admin/chat/threads",
            headers={**headers, webui.CSRF_HEADER: csrf},
            json={"to": "hermes-homelab-recusant", "text": "hi"},
        )
        assert opened.status_code == 200, opened.text
        no_csrf = await panel.post("/admin/chat/threads", headers=headers, json={"to": "hermes-homelab-recusant", "text": "x"})
        assert no_csrf.status_code == 403
        thread_id = opened.json()["thread_id"]
        got = (await panel.get(f"/v1/a2a/threads/{thread_id}/messages", headers=as_hermes)).json()
    assert got["messages"][0]["payload"]["operator"] == "jrt"
