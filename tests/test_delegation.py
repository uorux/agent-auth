"""Thread-anchored delegated auth: a request cites the OPEN a2a thread whose
conversation asked for the work; the thread's other participant becomes the
structural delegator, policy authorizes the pair, and the grant dies with the
thread."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from agent_auth.core.service import HumanDecision
from agent_auth.core.states import RuleAction
from agent_auth.discord_bot import embeds
from agent_auth.models import A2AThread, AccessRequest, Agent, Grant, Rule, utcnow

ADMIN = {"Authorization": "Bearer admin-secret"}


def auth(key: str, session_id: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {key}"}
    if session_id:
        headers["X-Agent-Session"] = session_id
    return headers


async def _mk_agent(api, name: str, kind: str = "service", **extra) -> dict:
    resp = await api.post(
        "/admin/agents", headers=ADMIN, json={"name": name, "kind": kind, **extra}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _open_thread(api, claude_key: str, hermes_key: str, hermes_name: str):
    """claude (ephemeral, sessioned) opens to hermes; hermes replies → OPEN.
    Returns (thread_id, claude_session_id)."""
    sid = (
        await api.post(
            "/v1/sessions", headers=auth(claude_key), json={"label": "nixos-dots"}
        )
    ).json()["session_id"]
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(claude_key, sid),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": hermes_name,
                "justification": "need homelab work done",
                "requested_duration": "30m",
            },
        )
    ).json()
    assert req["status"] == "granted", req
    tid = (
        await api.post(
            "/v1/a2a/threads",
            headers=auth(claude_key, sid),
            json={"to": hermes_name, "payload": {"task": "deploy cactus"}},
        )
    ).json()["thread_id"]
    reply = (
        await api.post(
            f"/v1/a2a/threads/{tid}/messages",
            headers=auth(hermes_key),
            json={"payload": {"ok": True}},
        )
    ).json()
    assert reply["thread_state"] == "open"
    return tid, sid


def _delegated_body(resource: str, tid: str) -> dict:
    return {
        "platform": "homelab",
        "capability": "group",
        "resource": resource,
        "justification": "claude asked me to deploy cactus; need Gitea to push the repo",
        "requested_duration": "1h",
        "on_behalf_of_thread": tid,
    }


async def test_delegated_request_happy_path(api, db, lldap_mock):
    hermes = await _mk_agent(api, "hermes-homelab-x", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-x", kind="ephemeral")
    tid, _sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-x")

    req = (
        await api.post(
            "/v1/requests", headers=auth(hermes["api_key"]), json=_delegated_body("svc-gitea", tid)
        )
    ).json()
    assert req["status"] == "granted", req
    assert req["delegator"] == "claude-nixos-dots-x"
    assert req["delegation_thread_id"] == tid

    # grant carries the pair and never outlives the thread's backing a2a grant
    async with db.session() as session:
        grant = await session.get(Grant, req["grant_id"])
        thread = await session.get(A2AThread, tid)
        backing = await session.get(Grant, thread.grant_id)
        delegator = await session.get(Agent, grant.delegator_agent_id)
    assert grant.delegation_thread_id == tid
    assert delegator.name == "claude-nixos-dots-x"
    assert grant.expires_at <= backing.expires_at  # 1h clamped to the 30m a2a grant

    # GrantOut exposes the pair
    grants = (await api.get("/v1/grants", headers=auth(hermes["api_key"]))).json()
    assert grants[0]["delegator"] == "claude-nixos-dots-x"
    assert grants[0]["delegation_thread_id"] == tid


async def test_delegation_validation(api, db):
    hermes = await _mk_agent(api, "hermes-homelab-v", lldap_username="svc-hermes")
    other = await _mk_agent(api, "hermes-other-v", lldap_username="svc-other")
    claude = await _mk_agent(api, "claude-nixos-dots-v", kind="ephemeral")
    tid, sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-v")

    async def denied(key, body, needle, session_id=None):
        req = (
            await api.post("/v1/requests", headers=auth(key, session_id), json=body)
        ).json()
        assert req["status"] == "denied", req
        assert needle in req["decision_reason"], req["decision_reason"]

    # unknown thread
    await denied(hermes["api_key"], _delegated_body("svc-gitea", "nope"), "unknown thread")
    # non-participant citing someone else's thread
    await denied(other["api_key"], _delegated_body("svc-gitea", tid), "unknown thread")
    # a2a itself cannot be delegated (depth 1)
    await denied(
        hermes["api_key"],
        {
            "platform": "a2a",
            "capability": "talk",
            "resource": "hermes-other-v",
            "justification": "x",
            "requested_duration": "1h",
            "on_behalf_of_thread": tid,
        },
        "cannot be requested on behalf",
    )
    # pending_open thread: claude opens a second thread nobody accepted
    tid2 = (
        await api.post(
            "/v1/a2a/threads",
            headers=auth(claude["api_key"], sid),
            json={"to": "hermes-homelab-v", "payload": {"q": 2}},
        )
    ).json()["thread_id"]
    await denied(hermes["api_key"], _delegated_body("svc-gitea", tid2), "OPEN thread")
    # closed thread
    await api.post(f"/v1/a2a/threads/{tid}/close", headers=auth(hermes["api_key"]), json={})
    await denied(hermes["api_key"], _delegated_body("svc-gitea", tid), "OPEN thread")

    # ephemeral initiator citing its own thread from the wrong session
    tid3, sid3 = await _open_thread(
        api, claude["api_key"], hermes["api_key"], "hermes-homelab-v"
    )
    sid_other = (
        await api.post(
            "/v1/sessions", headers=auth(claude["api_key"]), json={"label": "elsewhere"}
        )
    ).json()["session_id"]
    await denied(
        claude["api_key"],
        _delegated_body("svc-gitea", tid3),
        "different session",
        session_id=sid_other,
    )


async def test_delegation_respects_responder_session_binding(api, db, lldap_mock):
    """A thread claimed by one worker session is delegation proof for that
    session ONLY — not for other workers or the sessionless dispatcher."""
    hermes = await _mk_agent(api, "hermes-homelab-w", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-w", kind="ephemeral")
    # open WITHOUT implicit accept: claude opens, then worker-a accepts bound
    sid = (
        await api.post(
            "/v1/sessions", headers=auth(claude["api_key"]), json={"label": "nixos-dots"}
        )
    ).json()["session_id"]
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(claude["api_key"], sid),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "hermes-homelab-w",
                "justification": "work",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert req["status"] == "granted"
    tid = (
        await api.post(
            "/v1/a2a/threads",
            headers=auth(claude["api_key"], sid),
            json={"to": "hermes-homelab-w", "payload": {"task": "x"}},
        )
    ).json()["thread_id"]
    worker_a = (
        await api.post(
            "/v1/sessions", headers=auth(hermes["api_key"]), json={"label": "worker-a"}
        )
    ).json()["session_id"]
    accepted = (
        await api.post(f"/v1/a2a/threads/{tid}/accept", headers=auth(hermes["api_key"], worker_a))
    ).json()
    assert accepted["state"] == "open"

    async def request_as(session_id):
        return (
            await api.post(
                "/v1/requests",
                headers=auth(hermes["api_key"], session_id),
                json=_delegated_body("svc-gitea", tid),
            )
        ).json()

    # another worker session: denied
    worker_b = (
        await api.post(
            "/v1/sessions", headers=auth(hermes["api_key"]), json={"label": "worker-b"}
        )
    ).json()["session_id"]
    denied_b = await request_as(worker_b)
    assert denied_b["status"] == "denied"
    assert "different session" in denied_b["decision_reason"]

    # sessionless dispatcher: denied
    denied_disp = await request_as(None)
    assert denied_disp["status"] == "denied"
    assert "different session" in denied_disp["decision_reason"]

    # the owning worker session: granted via the delegated pair rule
    granted = await request_as(worker_a)
    assert granted["status"] == "granted", granted


async def test_delegation_rule_semantics(api, db):
    hermes = await _mk_agent(api, "hermes-homelab-r", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-r", kind="ephemeral")
    tid, _sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-r")

    # svc-sonarr has a plain approve rule (no delegator) — it must NOT
    # auto-approve the delegated version; falls through to default surface.
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-sonarr", tid),
        )
    ).json()
    assert req["status"] == "awaiting_human", req

    # deny rules apply to delegated requests too (agent glob denied-*)
    denied_agent = await _mk_agent(api, "denied-exec", lldap_username="svc-denied")
    tid2, _ = await _open_thread(api, claude["api_key"], denied_agent["api_key"], "denied-exec")
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(denied_agent["api_key"]),
            json=_delegated_body("svc-gitea", tid2),
        )
    ).json()
    assert req["status"] == "denied"
    assert "naughty" in req["decision_reason"]

    # delegator glob mismatch: a service→service thread (delegator auto-*, not
    # claude-*) doesn't satisfy the delegated svc-gitea rule → surface.
    svc = await _mk_agent(api, "auto-delegator")
    a2a_req = (
        await api.post(
            "/v1/requests",
            headers=auth(svc["api_key"]),
            json={
                "platform": "a2a",
                "capability": "talk",
                "resource": "hermes-homelab-r",
                "justification": "handoff",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert a2a_req["status"] == "granted"
    tid3 = (
        await api.post(
            "/v1/a2a/threads",
            headers=auth(svc["api_key"]),
            json={"to": "hermes-homelab-r", "payload": {"q": 1}},
        )
    ).json()["thread_id"]
    await api.post(f"/v1/a2a/threads/{tid3}/accept", headers=auth(hermes["api_key"]))
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-gitea", tid3),
        )
    ).json()
    assert req["status"] == "awaiting_human", req


async def test_decide_pins_delegator_on_saved_rule(api, db, service, lldap_mock):
    hermes = await _mk_agent(api, "hermes-homelab-d", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-d", kind="ephemeral")
    tid, _sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-d")

    # svc-k8s-gitops has no YAML rule at all → surfaces
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-k8s-gitops", tid),
        )
    ).json()
    assert req["status"] == "awaiting_human"

    await service.decide(
        req["id"],
        HumanDecision(
            approve=True,
            decided_by="jrt",
            duration_secs=600,
            rule_action=RuleAction.AUTO_APPROVE,
        ),
    )
    async with db.session() as session:
        rule = (
            await session.execute(select(Rule).order_by(Rule.created_at.desc()))
        ).scalars().first()
    assert rule.delegator_pattern == "claude-nixos-dots-d"

    # same delegated pair now auto-approves via the saved rule
    req2 = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-k8s-gitops", tid),
        )
    ).json()
    assert req2["status"] == "granted", req2
    assert req2["decision_source"] == "rule"

    # ...but the pinned rule never applies to a NON-delegated request
    req3 = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json={
                "platform": "homelab",
                "capability": "group",
                "resource": "svc-k8s-gitops",
                "justification": "for myself this time",
                "requested_duration": "1h",
            },
        )
    ).json()
    assert req3["status"] == "awaiting_human", req3


async def test_thread_close_cascades_revocation(api, db, service, a2a_service, lldap_mock):
    hermes = await _mk_agent(api, "hermes-homelab-c", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-c", kind="ephemeral")
    tid, sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-c")

    req = (
        await api.post(
            "/v1/requests", headers=auth(hermes["api_key"]), json=_delegated_body("svc-gitea", tid)
        )
    ).json()
    assert req["status"] == "granted"

    # credential issuable while the thread is open
    cred = await api.get(
        f"/v1/grants/{req['grant_id']}/credential", headers=auth(hermes["api_key"])
    )
    assert cred.status_code == 200

    # claude hangs up → credential blocked immediately, grant revoked by sweep
    await api.post(
        f"/v1/a2a/threads/{tid}/close", headers=auth(claude["api_key"], sid), json={}
    )
    cred = await api.get(
        f"/v1/grants/{req['grant_id']}/credential", headers=auth(hermes["api_key"])
    )
    assert cred.status_code == 403
    assert "delegation thread" in cred.json()["detail"]

    revoked = await service.revoke_delegated_for_closed_threads()
    assert revoked == 1
    async with db.session() as session:
        grant = await session.get(Grant, req["grant_id"])
    assert grant.status.value == "revoked"
    assert "delegation thread closed" in grant.revoke_reason


async def test_provision_recheck_after_thread_closed(api, db, service):
    hermes = await _mk_agent(api, "hermes-homelab-p", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-p", kind="ephemeral")
    tid, sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-p")

    # surfaces (svc-sonarr delegated has no delegated rule)
    req = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-sonarr", tid),
        )
    ).json()
    assert req["status"] == "awaiting_human"

    # thread closes before the human gets to it → approval can't provision
    await api.post(
        f"/v1/a2a/threads/{tid}/close", headers=auth(claude["api_key"], sid), json={}
    )
    decided = await service.decide(
        req["id"], HumanDecision(approve=True, decided_by="jrt", duration_secs=600)
    )
    assert decided.status.value == "provision_failed"
    assert "no longer open" in decided.decision_reason


async def test_embed_shows_delegation(api, db):
    hermes = await _mk_agent(api, "hermes-homelab-e", lldap_username="svc-hermes")
    claude = await _mk_agent(api, "claude-nixos-dots-e", kind="ephemeral")
    tid, _sid = await _open_thread(api, claude["api_key"], hermes["api_key"], "hermes-homelab-e")

    req = (
        await api.post(
            "/v1/requests",
            headers=auth(hermes["api_key"]),
            json=_delegated_body("svc-sonarr", tid),  # surfaces
        )
    ).json()
    async with db.session() as session:
        request = await session.get(AccessRequest, req["id"])
        agent = await session.get(Agent, request.agent_id)
        delegator = await session.get(Agent, request.delegator_agent_id)
        thread = await session.get(A2AThread, request.delegation_thread_id)
        embed = embeds.build_request_embed(request, agent, delegator, thread)
    fields = {f.name: f.value for f in embed.fields}
    assert "🤝 On behalf of" in fields
    assert "claude-nixos-dots-e" in fields["🤝 On behalf of"]
    # risk notes carry the structural context for the LLM/human too
    assert any("on behalf of claude-nixos-dots-e" in n for n in request.risk_notes)
