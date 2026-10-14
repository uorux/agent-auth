"""Containment: holding agents wherever they run (core/lockdown.py)."""

from __future__ import annotations

from agent_auth.core.states import GrantStatus, RequestStatus
from agent_auth.models import Grant
from agent_auth.policy.agents import AgentMatch

from .conftest import make_agent
from .test_lifecycle import a2a_request

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
