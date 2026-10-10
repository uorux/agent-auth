"""What an agent is, as recorded fields, and policy that matches on them
instead of on the name."""

from __future__ import annotations

import importlib

import pytest
from pydantic import ValidationError

from agent_auth.core.states import Platform
from agent_auth.models import AccessRequest
from agent_auth.policy.agents import AgentMatch, agent_matches, describe, resources_for
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyAction, PolicyFile

from .conftest import make_agent
from .test_api import ADMIN, auth


def _policy(rules, **extra) -> PolicyFile:
    return PolicyFile.model_validate({"rules": rules, **extra})


def _request(agent, platform, resource, capability="repo"):
    return AccessRequest(
        agent_id=agent.id, platform=platform, capability=capability, resource=resource,
        scope={}, justification="test", requested_duration_secs=3600,
    )


async def _decide(db, policy, agent, request) -> PolicyAction:
    async with db.session() as session:
        return (await PolicyEngine(policy).evaluate(session, agent, request)).action


async def test_a_rule_matches_fields_not_the_name(db):
    policy = _policy([
        {"match": {"agent": {"placement": "sandbox", "runtime": ["claude", "codex"]},
                   "platform": "a2a"}, "action": "approve"},
    ])
    # Named like a sandbox agent, registered as nothing of the kind.
    imposter, _ = await make_agent(db, "claude-thing-excelsior-sandbox")
    real, _ = await make_agent(db, "whatever", runtime="codex", placement="sandbox", host="excelsior")
    other, _ = await make_agent(db, "hermes-x", runtime="hermes", placement="sandbox")

    assert await _decide(db, policy, real, _request(real, Platform.A2A, "peer", "talk")) == PolicyAction.APPROVE
    assert await _decide(db, policy, imposter, _request(imposter, Platform.A2A, "peer", "talk")) == PolicyAction.SURFACE
    assert await _decide(db, policy, other, _request(other, Platform.A2A, "peer", "talk")) == PolicyAction.SURFACE


async def test_a_rule_about_the_agents_own_project(db):
    policy = _policy(
        [
            {"match": {"agent": {"runtime": "claude"}, "platform": "github",
                       "resource": "{agent.repos}"}, "action": "approve"},
            {"match": {"platform": "kubernetes", "capability": "view",
                       "resource": "{agent.project}"}, "action": "approve"},
        ],
        projects={"agent-auth": {"repos": ["uorux/agent-auth", "uorux/homelab"]}, "larder": {}},
    )
    mine, _ = await make_agent(db, "a", runtime="claude", project="agent-auth")
    theirs, _ = await make_agent(db, "b", runtime="claude", project="larder")
    none, _ = await make_agent(db, "c", runtime="claude")

    async def gh(agent, repo):
        return await _decide(db, policy, agent, _request(agent, Platform.GITHUB, repo))

    assert await gh(mine, "uorux/agent-auth") == PolicyAction.APPROVE
    assert await gh(mine, "uorux/homelab") == PolicyAction.APPROVE
    assert await gh(mine, "uorux/larder") == PolicyAction.SURFACE
    assert await gh(theirs, "uorux/agent-auth") == PolicyAction.SURFACE  # a project with no repos
    # No project: "your project's" anything is nothing, never everything.
    assert await gh(none, "uorux/agent-auth") == PolicyAction.SURFACE
    for agent, namespace, expected in [
        (mine, "agent-auth", PolicyAction.APPROVE), (mine, "larder", PolicyAction.SURFACE),
        (none, "", PolicyAction.SURFACE), (none, "None", PolicyAction.SURFACE),
    ]:
        request = _request(agent, Platform.KUBERNETES, namespace, "view")
        assert await _decide(db, policy, agent, request) == expected


def test_a_field_value_is_literal_inside_the_glob():
    class A:
        runtime, project, host, placement, name = "claude", "a*b", "h", "host", "n"

    assert resources_for("org/{agent.project}-*", A, {}) == ["org/a[*]b-*"]
    assert resources_for("plain/*", A, {}) == ["plain/*"]


@pytest.mark.parametrize(
    "policy, why",
    [
        ({"rules": [{"match": {"agent": {"project": "nope"}}, "action": "deny"}]}, "not listed under `projects`"),
        ({"rules": [{"match": {"agent": {"runtme": "claude"}}, "action": "deny"}]}, "runtme"),
        ({"rules": [{"match": {"agent": {"placement": "vm"}}, "action": "deny"}]}, "placement"),
        ({"rules": [{"match": {"agent": {"runtime": []}}, "action": "deny"}]}, "empty list"),
        ({"rules": [{"match": {"resource": "x/{agent.projct}"}, "action": "deny"}]}, "unknown placeholder"),
        ({"rules": [{"match": {"resource": "x/{project}"}, "action": "deny"}]}, "not an {agent"),
        ({"desktop": {"agents": [{"project": "nope"}]}}, "desktop.agents[0]"),
        ({"projects": {"Bad Name": {}}}, "lowercase"),
    ],
)
def test_a_mistake_in_the_policy_fails_at_load(policy, why):
    with pytest.raises(ValidationError) as exc:
        PolicyFile.model_validate(policy)
    assert why in str(exc.value)


async def test_name_globs_still_work(db):
    policy = _policy([{"match": {"agent": "deploy-*", "platform": "a2a"}, "action": "approve"}])
    agent, _ = await make_agent(db, "deploy-bot")
    assert await _decide(db, policy, agent, _request(agent, Platform.A2A, "peer", "talk")) == PolicyAction.APPROVE
    assert agent_matches("deploy-*", agent) and not agent_matches("other-*", agent)
    assert agent_matches(AgentMatch(name="deploy-*", placement="host"), agent)
    assert describe(agent) == ""


async def test_the_operator_sets_and_corrects_the_fields(api, db):
    made = (await api.post("/admin/agents", headers=ADMIN, json={
        "name": "claude-larder-galaxy", "kind": "ephemeral",
        "runtime": "claude", "project": "larder", "host": "galaxy",
    })).json()
    assert (made["runtime"], made["project"], made["host"], made["placement"]) == ("claude", "larder", "galaxy", "host")
    assert (await api.post("/admin/agents", headers=ADMIN, json={"name": "x", "host": "Not A Host"})).status_code == 422

    # The agent sees what it is, and has no way to change it.
    me = (await api.get("/v1/me", headers=auth(made["api_key"]))).json()
    assert me["project"] == "larder" and me["placement"] == "host"
    path = "/admin/agents/claude-larder-galaxy/attributes"
    assert (await api.patch(path, headers=auth(made["api_key"]), json={"project": "homelab"})).status_code == 401

    fixed = (await api.patch(path, headers=ADMIN, json={"host": "excelsior", "project": ""})).json()
    assert (fixed["runtime"], fixed["project"], fixed["host"]) == ("claude", None, "excelsior")
    assert (await api.patch("/admin/agents/nobody/attributes", headers=ADMIN, json={})).status_code == 404


def test_existing_agents_get_their_fields_from_their_names():
    migration = importlib.import_module("agent_auth.migrations.versions.a3b4c5d6e7f8_agent_attributes")
    f = migration.from_name
    assert f("claude-agent-auth-galaxy") == {"runtime": "claude", "project": "agent-auth", "host": "galaxy"}
    assert f("hermes-homelab-recusant") == {"runtime": "hermes", "project": "homelab", "host": "recusant"}
    assert f("codex-x-excelsior-sandbox") == {"runtime": "codex", "project": "x", "host": "excelsior"}
    assert f("orchestrator-excelsior") == {"runtime": "orchestrator", "host": "excelsior"}
    assert f("auto-deployer") == {} and f("claude") == {}


async def test_a_delegator_is_matched_by_its_fields_too(db):
    policy = _policy([
        {"match": {"agent": {"runtime": "hermes"}, "platform": "kubernetes", "capability": "view",
                   "delegator": {"runtime": "claude", "placement": "sandbox"}}, "action": "approve"},
    ])
    hermes, _ = await make_agent(db, "h", runtime="hermes")
    vm_claude, _ = await make_agent(db, "c1", runtime="claude", placement="sandbox")
    host_claude, _ = await make_agent(db, "c2", runtime="claude")

    async def asked_by(delegator):
        request = _request(hermes, Platform.KUBERNETES, "media", "view")
        request.delegator_agent_id = delegator.id if delegator else None
        return await _decide(db, policy, hermes, request)

    assert await asked_by(vm_claude) == PolicyAction.APPROVE
    assert await asked_by(host_claude) == PolicyAction.SURFACE
    assert await asked_by(None) == PolicyAction.SURFACE
