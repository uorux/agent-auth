from __future__ import annotations

import asyncio

from agent_auth.core.service import HumanDecision

from .conftest import make_agent


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


ADMIN = {"Authorization": "Bearer admin-secret"}


async def test_auth_rejections(api, agent):
    _, key = agent
    assert (await api.get("/v1/me")).status_code == 401
    assert (await api.get("/v1/me", headers=auth("aa_bogus_key"))).status_code == 401
    assert (await api.get("/v1/me", headers=auth("garbage"))).status_code == 401
    resp = await api.get("/v1/me", headers=auth(key))
    assert resp.status_code == 200
    assert resp.json()["name"] == "test-agent"


async def test_admin_auth(api):
    assert (await api.get("/admin/agents")).status_code == 401
    assert (
        await api.get("/admin/agents", headers=auth("wrong"))
    ).status_code == 401
    assert (await api.get("/admin/agents", headers=ADMIN)).status_code == 200


async def test_admin_create_agent_shows_key_once(api):
    resp = await api.post(
        "/admin/agents",
        headers=ADMIN,
        json={"name": "new-agent", "description": "created via api"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["api_key"].startswith("aa_")
    # duplicate name rejected
    resp = await api.post("/admin/agents", headers=ADMIN, json={"name": "new-agent"})
    assert resp.status_code == 409
    # listing does not include keys
    listing = (await api.get("/admin/agents", headers=ADMIN)).json()
    assert all(a["api_key"] is None for a in listing)
    # the key works
    me = await api.get("/v1/me", headers=auth(body["api_key"]))
    assert me.status_code == 200


async def test_request_flow_via_api(api, db, service):
    sender_resp = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": "api-sender"}
    )
    key = sender_resp.json()["api_key"]
    await make_agent(db, "api-peer")

    resp = await api.post(
        "/v1/requests",
        headers=auth(key),
        json={
            "platform": "a2a",
            "capability": "talk",
            "resource": "api-peer",
            "justification": "coordinate the cactus deploy",
            "requested_duration": "45m",
        },
    )
    assert resp.status_code == 200
    req = resp.json()
    assert req["status"] == "awaiting_human"
    assert "Discord" in req["guidance"]

    # long-poll in background; decide meanwhile; poll returns the decision
    async def decide_soon():
        await asyncio.sleep(0.2)
        await service.decide(
            req["id"], HumanDecision(approve=True, decided_by="jrt", duration_secs=600)
        )

    task = asyncio.create_task(decide_soon())
    resp = await api.get(f"/v1/requests/{req['id']}/wait", headers=auth(key), params={"timeout": 10})
    await task
    decided = resp.json()
    assert decided["status"] == "granted"
    assert decided["approved_duration_secs"] == 600
    assert decided["grant_id"]

    grants = (await api.get("/v1/grants", headers=auth(key))).json()
    assert len(grants) == 1
    assert grants[0]["resource"] == "api-peer"

    # a2a credential endpoint explains check-based model
    cred = await api.get(f"/v1/grants/{decided['grant_id']}/credential", headers=auth(key))
    assert cred.status_code == 200
    assert cred.json()["kind"] == "a2a_grant"


async def test_request_isolation_between_agents(api, db):
    a1 = (await api.post("/admin/agents", headers=ADMIN, json={"name": "iso-1"})).json()
    a2 = (await api.post("/admin/agents", headers=ADMIN, json={"name": "iso-2"})).json()
    await make_agent(db, "iso-peer")
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(a1["api_key"]),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "iso-peer",
                "justification": "x",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert (
        await api.get(f"/v1/requests/{req['id']}", headers=auth(a2["api_key"]))
    ).status_code == 404
    assert (
        await api.get(f"/v1/requests/{req['id']}", headers=auth(a1["api_key"]))
    ).status_code == 200


async def test_a2a_check_send_inbox_ack(api, db, service):
    sender = (await api.post("/admin/agents", headers=ADMIN, json={"name": "auto-s"})).json()
    recipient = (await api.post("/admin/agents", headers=ADMIN, json={"name": "auto-r"})).json()
    skey, rkey = sender["api_key"], recipient["api_key"]

    # no grant yet
    check = (await api.get("/v1/a2a/check", headers=auth(skey), params={"peer": "auto-r"})).json()
    assert check["allowed"] is False
    send = await api.post(
        "/v1/a2a/send", headers=auth(skey), json={"to": "auto-r", "payload": {"hi": 1}}
    )
    assert send.status_code == 403

    # auto-* rule auto-approves a2a
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(skey),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "auto-r",
                "justification": "handoff deploy task",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert req["status"] == "granted"

    check = (await api.get("/v1/a2a/check", headers=auth(skey), params={"peer": "auto-r"})).json()
    assert check["allowed"] is True
    # recipient verifies inbound
    check_in = (
        await api.get(
            "/v1/a2a/check", headers=auth(rkey), params={"peer": "auto-s", "direction": "in"}
        )
    ).json()
    assert check_in["allowed"] is True

    # send lands in inbox (no webhook configured)
    send = (
        await api.post(
            "/v1/a2a/send",
            headers=auth(skey),
            json={"to": "auto-r", "payload": {"task": "deploy cactus"}},
        )
    ).json()
    assert send["delivered_via"] == "inbox"

    inbox = (await api.get("/v1/a2a/inbox", headers=auth(rkey))).json()
    assert len(inbox) == 1
    assert inbox[0]["from"] == "auto-s"
    assert inbox[0]["payload"]["body"] == {"task": "deploy cactus"}

    ack = await api.post(f"/v1/a2a/inbox/{inbox[0]['message_id']}/ack", headers=auth(rkey))
    assert ack.status_code == 200
    assert (await api.get("/v1/a2a/inbox", headers=auth(rkey))).json() == []

    # sender can't read recipient's inbox message
    assert (
        await api.post(f"/v1/a2a/inbox/{inbox[0]['message_id']}/ack", headers=auth(skey))
    ).status_code == 404


async def test_admin_rules_and_revoke(api, db, service):
    sender = (await api.post("/admin/agents", headers=ADMIN, json={"name": "auto-s2"})).json()
    await make_agent(db, "auto-r2")
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(sender["api_key"]),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "auto-r2",
                "justification": "x",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert req["status"] == "granted"

    revoke = await api.post(
        f"/admin/grants/{req['grant_id']}/revoke", headers=ADMIN, params={"reason": "test"}
    )
    assert revoke.status_code == 200
    check = (
        await api.get(
            "/v1/a2a/check", headers=auth(sender["api_key"]), params={"peer": "auto-r2"}
        )
    ).json()
    assert check["allowed"] is False

    reqs = (await api.get("/admin/requests", headers=ADMIN)).json()
    assert any(r["id"] == req["id"] for r in reqs)


async def test_admin_decide_endpoint(api, db):
    a = (await api.post("/admin/agents", headers=ADMIN, json={"name": "hd-agent"})).json()
    await make_agent(db, "hd-peer")
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(a["api_key"]),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "hd-peer",
                "justification": "x",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert req["status"] == "awaiting_human"
    decided = await api.post(
        f"/admin/requests/{req['id']}/decide",
        headers=ADMIN,
        json={"approve": True, "reason": "via api", "duration": "10m"},
    )
    assert decided.status_code == 200
    body = decided.json()
    assert body["status"] == "granted"
    assert body["approved_duration_secs"] == 600
    # deciding again conflicts
    again = await api.post(
        f"/admin/requests/{req['id']}/decide", headers=ADMIN, json={"approve": False}
    )
    assert again.status_code == 409


async def test_catalog(api, db):
    a = (await api.post("/admin/agents", headers=ADMIN, json={"name": "cat-agent"})).json()
    await make_agent(db, "cat-peer")
    resp = await api.get("/v1/catalog", headers=auth(a["api_key"]))
    assert resp.status_code == 200
    by_platform = {p["platform"]: p for p in resp.json()["platforms"]}

    # kubernetes: roles carry descriptions + a typical disposition
    k = by_platform["kubernetes"]
    assert k["namespace_allowlist"] == ["apps-*", "personal-site"]
    roles = {r["name"]: r for r in k["roles"]}
    assert set(roles) == {"view", "logs-reader", "edit"}
    assert roles["view"]["description"] == "read-only in the namespace"
    # conftest rule auto-approves view, surfaces edit
    assert roles["view"]["typical_disposition"] == "auto-approve"
    assert roles["edit"]["typical_disposition"] == "human review"

    # github: allowlist + permission ceiling
    gh = by_platform["github"]
    assert gh["repo_allowlist"] == ["jrt/*"]
    assert gh["permission_ceiling"]["contents"] == "write"

    # a2a: peers list other registered agents, not self
    a2a = by_platform["a2a"]
    assert "cat-peer" in a2a["peers"]
    assert "cat-agent" not in a2a["peers"]

    # unused fields are omitted (response_model_exclude_none)
    assert "roles" not in gh
    assert "repo_allowlist" not in k


async def test_catalog_requires_auth(api):
    assert (await api.get("/v1/catalog")).status_code == 401


async def test_webhook_url_validated(api):
    bad = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": "wh-bad", "webhook_url": "ftp://x/h"}
    )
    assert bad.status_code == 422
    ok = await api.post(
        "/admin/agents",
        headers=ADMIN,
        json={"name": "wh-ok", "webhook_url": "https://hooks.internal/agent"},
    )
    assert ok.status_code == 200


async def test_field_size_caps(api, db):
    a = (await api.post("/admin/agents", headers=ADMIN, json={"name": "big-agent"})).json()
    await make_agent(db, "big-peer")
    # oversized justification
    resp = await api.post(
        "/v1/requests",
        headers=auth(a["api_key"]),
        json={
            "platform": "a2a",
            "capability": "talk",
            "resource": "big-peer",
            "justification": "x" * 5000,
            "requested_duration": "1h",
        },
    )
    assert resp.status_code == 422
    # oversized a2a payload
    resp = await api.post(
        "/v1/a2a/send",
        headers=auth(a["api_key"]),
        json={"to": "big-peer", "payload": {"blob": "z" * 20000}},
    )
    assert resp.status_code == 422


async def test_invalid_duration_rejected(api):
    a = (await api.post("/admin/agents", headers=ADMIN, json={"name": "dur-agent"})).json()
    resp = await api.post(
        "/v1/requests",
        headers=auth(a["api_key"]),
        json={
            "platform": "a2a",
            "capability": "talk",
            "resource": "whatever",
            "justification": "x",
            "requested_duration": "sometime",
        },
    )
    assert resp.status_code == 422
