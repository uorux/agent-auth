"""Restricted zones (core/zones.py), policy overlays, and the audit feed."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from agent_auth.core.states import Platform, RequestStatus
from agent_auth.core.zones import Zones
from agent_auth.models import Grant, Rule, RuleAction, utcnow
from agent_auth.policy.agents import AgentMatch
from agent_auth.policy.schema import RestrictedZone, load_policy
from agent_auth.core.service import HumanDecision
from agent_auth.schemas import RequestCreate

from .conftest import make_agent
from .test_lifecycle import a2a_request

ADMIN = {"Authorization": "Bearer admin-secret"}


def k8s(namespace: str, role: str = "view") -> RequestCreate:
    return RequestCreate(platform=Platform.KUBERNETES, capability=role, resource=namespace,
                         justification="read the pods to debug a crash loop", requested_duration="1h")


def zone(service, registry=None, **kw):
    service.engine.policy.restricted = {
        "soc": RestrictedZone(members=[AgentMatch(project=["soc"])], kubernetes=["apps-soc"], github=["jrt/soc"], **kw)
    }
    if registry is not None:
        registry.get(Platform.KUBERNETES).zones = Zones(service.engine.policy)


async def test_outside_a_zone_its_resources_are_not_brokered_whatever_the_rules(db, service, k8s_mock):
    zone(service)
    outsider, _ = await make_agent(db, "claude-ops", project="ops")
    member, _ = await make_agent(db, "claude-soc", project="soc")
    # A saved rule that would approve anything in any namespace: it is read
    # after the zone check, so it doesn't open the zone.
    async with db.session() as session:
        session.add(Rule(action=RuleAction.AUTO_APPROVE, agent_pattern="*", platform=Platform.KUBERNETES,
                         resource_pattern="*", authority=None))

    refused = await service.create_request(outsider.id, k8s("apps-soc"))
    assert refused.status == RequestStatus.DENIED
    # The same words as a namespace the broker doesn't broker at all.
    assert refused.decision_reason == "validator: namespace 'apps-soc' is not brokered (allowlist)"
    assert (await service.create_request(member.id, k8s("apps-soc"))).status == RequestStatus.GRANTED
    # Members reach outside their zone like anyone.
    assert (await service.create_request(member.id, k8s("personal-site"))).status == RequestStatus.GRANTED

    gh = RequestCreate(platform=Platform.GITHUB, capability="repo", resource="jrt/soc",
                       scope={"permissions": {"contents": "read"}}, justification="read it", requested_duration="1h")
    out = await service.create_request(outsider.id, gh)
    assert out.status == RequestStatus.DENIED and "never brokered" in out.decision_reason


async def test_members_and_outsiders_are_not_peers(db, service, api):
    zone(service)
    outsider, outsider_key = await make_agent(db, "claude-ops", project="ops")
    member, member_key = await make_agent(db, "codex-soc", project="soc")
    await make_agent(db, "peer-ops", project="ops")

    assert (await service.create_request(outsider.id, a2a_request("codex-soc"))).status == RequestStatus.DENIED
    assert (await service.create_request(member.id, a2a_request("peer-ops"))).status == RequestStatus.DENIED
    check = await api.get("/v1/a2a/check", params={"peer": "codex-soc"}, headers={"Authorization": f"Bearer {outsider_key}"})
    assert check.json()["reason"] == "unknown agent 'codex-soc'"
    catalog = (await api.get("/v1/catalog", headers={"Authorization": f"Bearer {outsider_key}"})).json()
    peers = [p["name"] for pl in catalog["platforms"] if pl["platform"] == "a2a" for p in pl["peers"]]
    assert "codex-soc" not in peers and "peer-ops" in peers


async def test_a_cluster_wide_grant_leaves_the_zone_out(db, service, registry, k8s_mock):
    zone(service, registry)
    ops, _ = await make_agent(db, "ops-agent")
    req = await service.create_request(ops.id, k8s("*"))
    assert req.status == RequestStatus.AWAITING_HUMAN
    await service.decide(req.id, HumanDecision(approve=True, decided_by="jrt", duration_secs=1800))
    created = [p for m, p in k8s_mock.paths if m == "POST" and p.endswith("/rolebindings")]
    assert sorted(p.split("/")[5] for p in created) == ["agent-auth", "apps-a", "personal-site"]
    assert ("create", "ClusterRoleBinding") not in k8s_mock.calls
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        assert grant.provisioner_state["bound_namespaces"] == ["agent-auth", "apps-a", "personal-site"]
        await session.execute(Grant.__table__.update().where(Grant.id == grant.id).values(expires_at=utcnow() - timedelta(seconds=1)))
    assert await service.expire_due_grants() == 1
    deleted = [p for m, p in k8s_mock.paths if m == "DELETE" and "/rolebindings/" in p]
    assert len(deleted) == 3


async def test_a_member_is_never_minted_without_a_human(db, service):
    from agent_auth.models import Daemon

    zone(service)
    async with db.session() as session:
        daemon = Daemon(name="galaxy", role="sandbox", public_key="x" * 44)
        session.add(daemon)
        await session.flush()
    orchestrator, _ = await make_agent(db, "orchestrator-galaxy-sandbox", runtime="orchestrator",
                                       placement="sandbox", sandbox_id=daemon.id, host="galaxy")
    async with db.session() as session:
        o = await session.get(type(orchestrator), orchestrator.id)
        zoned = await Zones(service.engine.policy).check(session, o, Platform.AGENTS, "codex-soc-galaxy-sandbox", {"runtime": "codex"})
        assert zoned is not None and zoned[0] == "human"
        assert await Zones(service.engine.policy).check(session, o, Platform.AGENTS, "codex-ops-galaxy-sandbox", {"runtime": "codex"}) is None
        # Nor may an outsider in the VM read the zone's project.
        denied = await Zones(service.engine.policy).check(session, o, Platform.SANDBOX, "soc", {})
        assert denied is not None and denied[0] == "deny"


async def test_members_do_not_write_the_wiki_unless_the_zone_says_so(service):
    zone(service)
    zones = Zones(service.engine.policy)
    member = type("A", (), {"name": "claude-soc", "project": "soc", "kind": "service"})()
    other = type("A", (), {"name": "claude-ops", "project": "ops", "kind": "service"})()
    assert not zones.may_write_wiki(member) and zones.may_write_wiki(other)
    zone(service, wiki=True)
    assert Zones(service.engine.policy).may_write_wiki(member)


def test_an_overlay_merges_over_the_policy_and_must_exist(tmp_path):
    base = tmp_path / "policy.yaml"
    base.write_text(
        "projects: {ops: {}}\n"
        "rules:\n  - {match: {platform: a2a}, action: approve}\n"
    )
    private = tmp_path / "private.yaml"
    private.write_text(
        "projects: {soc: {}}\n"
        "rules:\n  - {match: {agent: {project: soc}, platform: a2a}, action: deny}\n"
        "restricted:\n  soc: {members: [{project: soc}], kubernetes: [soc]}\n"
        "audit: {readers: [{project: soc}]}\n"
    )
    policy = load_policy(base, [private])
    assert set(policy.projects) == {"ops", "soc"}
    # The overlay's rules come first.
    assert [r.action.value for r in policy.rules] == ["deny", "approve"]
    assert policy.restricted["soc"].kubernetes == ["soc"]
    with pytest.raises(FileNotFoundError):
        load_policy(base, [tmp_path / "gone.yaml"])
    # A zone naming a project that isn't listed is an error, as in a rule.
    private.write_text("restricted:\n  soc: {members: [{project: nope}]}\n")
    with pytest.raises(ValueError, match="nope"):
        load_policy(base, [private])


async def test_the_audit_feed_is_its_readers_alone(db, service, api):
    service.engine.policy.audit.readers = [AgentMatch(runtime=["soc"])]
    _, soc_key = await make_agent(db, "soc-mon", runtime="soc", kind="ephemeral")
    other, other_key = await make_agent(db, "auto-x", project="x")
    await make_agent(db, "peer")
    since = (utcnow() - timedelta(seconds=5)).isoformat()
    await service.create_request(other.id, a2a_request("peer"))
    bad = await api.get("/v1/catalog", headers={"Authorization": "Bearer aa_nope_nothing"})
    assert bad.status_code == 401

    hidden = await api.get("/v1/audit/events", headers={"Authorization": f"Bearer {other_key}"})
    assert hidden.status_code == 404
    feed = await api.get("/v1/audit/events", params={"since": since}, headers={"Authorization": f"Bearer {soc_key}"})
    assert feed.status_code == 200, feed.text
    kinds = [e["kind"] for e in feed.json()["events"]]
    assert "request" in kinds and "grant.issued" in kinds and "agent.created" in kinds
    assert "security.bad_key" in kinds
    req = next(e for e in feed.json()["events"] if e["kind"] == "request")
    assert req["agent"] == "auto-x" and req["status"] == "granted" and req["justification"]
