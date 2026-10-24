"""Containment: holding agents wherever they run (core/lockdown.py)."""

from __future__ import annotations

import pytest

from agent_auth.core.service import HumanDecision, TransitionError
from agent_auth.core.states import GrantStatus, Platform, RequestStatus
from agent_auth.models import AccessRequest, Grant
from agent_auth.policy.agents import AgentMatch
from agent_auth.schemas import RequestCreate

from .conftest import make_agent, openrouter_verdicts
from .test_lifecycle import a2a_request, wait_for_status

ADMIN = {"Authorization": "Bearer admin-secret"}


class Recorder:
    def __init__(self):
        self.events: list[dict] = []

    def __getattr__(self, name):
        async def nothing(*a, **k):
            return None

        return nothing

    async def contained(self, event):
        self.events.append(event)


async def grant_of(db, request_id) -> Grant:
    from sqlalchemy import select

    async with db.session() as session:
        return (await session.execute(select(Grant).where(Grant.request_id == request_id))).scalar_one()


async def test_a_held_agent_loses_its_grants_and_gets_nothing_new_until_lifted(api, db, service):
    notes = Recorder()
    service.set_notifier(notes)
    held, held_key = await make_agent(db, "auto-x-galaxy", project="x")
    other, _ = await make_agent(db, "auto-y-galaxy", project="y")
    await make_agent(db, "peer")
    first = await service.create_request(held.id, a2a_request("peer"))
    kept = await service.create_request(other.id, a2a_request("peer"))
    assert first.status == kept.status == RequestStatus.GRANTED

    out = await api.post("/admin/containment", headers=ADMIN, json={"match": {"project": "x"}, "reason": "odd pushes"})
    assert out.status_code == 200, out.text
    entry = out.json()
    assert entry["agents"] == ["auto-x-galaxy"] and entry["grants_revoked"] == 1
    assert (await grant_of(db, first.id)).status == GrantStatus.REVOKED
    assert (await grant_of(db, kept.id)).status == GrantStatus.ACTIVE
    # The operator is told, with who and why.
    assert [e["reason"] for e in notes.events] == ["odd pushes"]

    again = await service.create_request(held.id, a2a_request("peer"))
    assert again.status == RequestStatus.DENIED and again.decision_reason.startswith(f"contained ({entry['id']})")
    cred = await api.get(f"/v1/grants/{(await grant_of(db, first.id)).id}/credential", headers={"Authorization": f"Bearer {held_key}"})
    assert cred.status_code == 403
    assert (await service.create_request(other.id, a2a_request("peer"))).status == RequestStatus.GRANTED

    listed = (await api.get("/admin/containment", headers=ADMIN)).json()
    assert [e["id"] for e in listed] == [entry["id"]]
    lifted = await api.post("/admin/containment/lift", headers=ADMIN, json={"id": entry["id"]})
    assert lifted.status_code == 200 and lifted.json()["lifted"][0]["id"] == entry["id"]
    assert (await service.create_request(held.id, a2a_request("peer"))).status == RequestStatus.GRANTED


def github_write(repo="jrt/cactus"):
    return RequestCreate(
        platform=Platform.GITHUB, capability="repo", resource=repo,
        scope={"permissions": {"contents": "write"}}, justification="push the fix", requested_duration="2h",
    )


def k8s_edit(namespace="apps-a"):
    return RequestCreate(
        platform=Platform.KUBERNETES, capability="edit", resource=namespace,
        justification="debug the deploy", requested_duration="1h",
    )


async def test_nothing_is_provisioned_for_a_held_agent_whatever_approves_it(app, db, service):
    """The request was made before the hold: a retry, an escalation or a
    human's Approve (who may not know) still provisions nothing."""
    agent, _ = await make_agent(db, "dev-x", project="x")
    with openrouter_verdicts({"verdict": "deny", "reasoning": "vague"}):
        denied = await service.create_request(agent.id, github_write())
        await wait_for_status(db, denied.id, {RequestStatus.LLM_DENIED})
    waiting = await service.create_request(agent.id, k8s_edit())
    assert waiting.status == RequestStatus.AWAITING_HUMAN

    # Recorded only, so the pending requests are left for the gates below.
    entry = await app.state.containment.record({"project": "x"}, "odd pushes", "jrt")
    with pytest.raises(TransitionError, match=f"contained \\({entry['id']}\\)"):
        await service.retry(denied.id, agent.id, "but really")
    with pytest.raises(TransitionError, match="contained"):
        await service.escalate(denied.id, agent.id)
    done = await service.decide(waiting.id, HumanDecision(approve=True, decided_by="jrt"))
    assert done.status == RequestStatus.PROVISION_FAILED and "contained" in done.decision_reason
    async with db.session() as session:
        from sqlalchemy import select

        assert (await session.execute(select(Grant).where(Grant.request_id == waiting.id))).first() is None


async def test_containing_denies_pending_requests_and_takes_the_agent_out_of_a2a(api, db, service):
    held, _ = await make_agent(db, "auto-x-galaxy", project="x")
    peer, peer_key = await make_agent(db, "auto-y-galaxy", project="y")
    pending = await service.create_request(held.id, k8s_edit())
    assert pending.status == RequestStatus.AWAITING_HUMAN
    # Another agent's talk grant to the one about to be held.
    assert (await service.create_request(peer.id, a2a_request("auto-x-galaxy"))).status == RequestStatus.GRANTED

    out = await api.post("/admin/containment", headers=ADMIN, json={"match": {"project": "x"}, "reason": "odd"})
    assert out.status_code == 200, out.text
    assert out.json()["requests_denied"] == 1
    async with db.session() as session:
        assert (await session.get(AccessRequest, pending.id)).status == RequestStatus.DENIED

    opened = await api.post(
        "/v1/a2a/threads", headers={"Authorization": f"Bearer {peer_key}"}, json={"to": "auto-x-galaxy", "payload": {"q": 1}}
    )
    assert opened.status_code == 403 and "contained" in opened.text

    await api.post("/admin/containment/lift", headers=ADMIN, json={"id": out.json()["id"]})
    opened = await api.post(
        "/v1/a2a/threads", headers={"Authorization": f"Bearer {peer_key}"}, json={"to": "auto-x-galaxy", "payload": {"q": 1}}
    )
    # Past the hold; only liveness is left (nothing polls for this test agent).
    assert opened.status_code == 409 and "not listening" in opened.text, opened.text


async def test_an_allowed_agent_may_contain_but_not_everyone_and_not_lift(api, db, service):
    service.engine.policy.containment.agents = [AgentMatch(runtime=["soc"])]
    _, soc_key = await make_agent(db, "soc-recusant", runtime="soc")
    _, other_key = await make_agent(db, "claude-z", runtime="claude")
    await make_agent(db, "codex-q", runtime="codex")
    soc = {"Authorization": f"Bearer {soc_key}"}

    body = {"match": {"name": "codex-q"}, "reason": "exfiltration attempt", "evidence": "curl ... | base64"}
    refused = await api.post("/v1/containment", headers={"Authorization": f"Bearer {other_key}"}, json=body)
    assert refused.status_code == 404  # to other agents, there is nothing here
    garbled = await api.post("/v1/containment", headers={"Authorization": f"Bearer {other_key}"}, content=b"{")
    assert garbled.status_code == 404
    done = await api.post("/v1/containment", headers=soc, json=body)
    assert done.status_code == 200 and done.json()["by"] == "soc-recusant" and done.json()["source"] == "agent"
    assert (await api.post("/v1/containment", headers=soc, json={**body, "match": {}})).status_code == 403
    assert (await api.post("/v1/containment", headers=soc, json={**body, "match": {"bogus": 1}})).status_code == 422
    # Lifting is an admin route: an agent's key is not the admin token.
    assert (await api.post("/admin/containment/lift", headers=soc, json={})).status_code == 401
    service.engine.policy.containment.allow_all = True
    assert (await api.post("/v1/containment", headers=soc, json={**body, "match": {}})).status_code == 200


async def test_lockdown_entries_are_lifted_by_unlock_and_others_are_not(app, db):
    containment = app.state.containment
    await containment.record({"host": "galaxy"}, "lockdown (host galaxy)", "jrt", source="lockdown")
    await containment.record({}, "lockdown (all)", "jrt", source="lockdown")
    mine = await containment.record({"project": "x"}, "odd pushes", "jrt", source="operator")
    await containment.lift_where(lambda e: e.get("source") == "lockdown" and e.get("match") == {"host": "galaxy"}, "jrt")
    assert [e["reason"] for e in await containment.list()] == ["lockdown (all)", "odd pushes"]
    await containment.lift_where(lambda e: e.get("source") == "lockdown", "jrt")
    assert [e["id"] for e in await containment.list()] == [mine["id"]]


async def test_discord_commands_contain_list_and_release(app, db, settings):
    """The slash commands, called as Discord would, by the owner."""
    from types import SimpleNamespace

    from agent_auth.discord_bot.bot import AgentAuthBot

    settings.discord_owner_id = 42
    bot = AgentAuthBot(settings, db, app.state.service)
    bot.containment = app.state.containment
    await make_agent(db, "codex-food-galaxy", project="food")
    names = {c.name for c in bot.tree.get_commands()}
    assert {"contain", "contained", "release"} <= names

    sent: list[str] = []

    class Response:
        def is_done(self):
            return False

        async def send_message(self, text=None, **kw):
            sent.append(text)

        async def defer(self, **kw):
            pass

    class Followup:
        async def send(self, text=None, **kw):
            sent.append(text)

    def interaction(user_id=42):
        return SimpleNamespace(
            client=bot, user=SimpleNamespace(id=user_id), response=Response(), followup=Followup()
        )

    contain = bot.tree.get_command("contain")
    await contain.callback(interaction(), reason="odd", project="food")
    assert sent[-1].startswith("Contained `") and "1 agent(s)" in sent[-1]
    entry = (await app.state.containment.list())[0]
    await bot.tree.get_command("contained").callback(interaction())
    assert entry["id"] in sent[-1]
    # Not the owner: refused, nothing lifted.
    await bot.tree.get_command("release").callback(interaction(user_id=7), entry=entry["id"])
    assert len(await app.state.containment.list()) == 1
    await bot.tree.get_command("release").callback(interaction(), entry=entry["id"])
    assert await app.state.containment.list() == []
