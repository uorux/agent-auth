from __future__ import annotations

import pytest

from agent_auth.core.states import Platform, RuleAction
from agent_auth.models import AccessRequest, Rule
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyAction
from agent_auth.schemas import parse_duration

from .conftest import make_agent


def _request(agent, platform=Platform.A2A, capability="talk", resource="other-agent"):
    return AccessRequest(
        agent_id=agent.id,
        platform=platform,
        capability=capability,
        resource=resource,
        scope={},
        justification="test",
        requested_duration_secs=3600,
    )


def test_parse_duration():
    assert parse_duration("30m") == 1800
    assert parse_duration("8h") == 8 * 3600
    assert parse_duration("2d") == 2 * 86400
    assert parse_duration(90) == 90
    assert parse_duration("90") == 90
    with pytest.raises(ValueError):
        parse_duration("soon")
    with pytest.raises(ValueError):
        parse_duration(-5)


async def test_yaml_rule_matching(db, policy):
    engine = PolicyEngine(policy)
    agent, _ = await make_agent(db, "auto-deployer")
    denied, _ = await make_agent(db, "denied-agent")

    async with db.session() as session:
        d = await engine.evaluate(session, agent, _request(agent))
        assert d.action == PolicyAction.APPROVE
        assert d.max_duration_secs == 2 * 3600

        d = await engine.evaluate(session, denied, _request(denied))
        assert d.action == PolicyAction.DENY

        d = await engine.evaluate(
            session, agent, _request(agent, Platform.GITHUB, "repo", "jrt/x")
        )
        assert d.action == PolicyAction.LLM
        assert d.llm_model == "test/judge"
        assert d.retry_budget == 2


async def test_default_action_surface(db, policy):
    engine = PolicyEngine(policy)
    agent, _ = await make_agent(db, "plain-agent")
    async with db.session() as session:
        d = await engine.evaluate(session, agent, _request(agent))
        assert d.action == PolicyAction.SURFACE
        assert d.source == "policy"


async def test_db_rule_beats_yaml(db, policy):
    engine = PolicyEngine(policy)
    # YAML says deny for denied-*; a human-created DB rule overrides it.
    agent, _ = await make_agent(db, "denied-but-trusted")
    async with db.session() as session:
        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern="denied-but-trusted",
                platform=Platform.A2A,
                capability_pattern="talk",
                resource_pattern="*",
                max_duration_secs=600,
            )
        )
        await session.flush()
        d = await engine.evaluate(session, agent, _request(agent))
        assert d.action == PolicyAction.APPROVE
        assert d.source == "rule"
        assert d.max_duration_secs == 600


async def test_disabled_db_rule_ignored(db, policy):
    engine = PolicyEngine(policy)
    agent, _ = await make_agent(db, "plain-agent-2")
    async with db.session() as session:
        session.add(
            Rule(
                action=RuleAction.AUTO_DENY,
                agent_pattern="*",
                platform=Platform.A2A,
                enabled=False,
            )
        )
        await session.flush()
        d = await engine.evaluate(session, agent, _request(agent))
        assert d.action == PolicyAction.SURFACE


async def test_scope_pinned_rule_does_not_widen(db, policy):
    """A rule pinned to contents:write must not auto-approve secrets:write."""
    engine = PolicyEngine(policy)
    agent, _ = await make_agent(db, "sde-widen")
    async with db.session() as session:
        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern="sde-widen",
                platform=Platform.GITHUB,
                capability_pattern="repo",
                resource_pattern="jrt/cactus",
                scope={"permissions": {"contents": "write"}},
            )
        )
        await session.flush()

        exact = _request(agent, Platform.GITHUB, "repo", "jrt/cactus")
        exact.scope = {"permissions": {"contents": "write"}}
        d = await engine.evaluate(session, agent, exact)
        assert d.action == PolicyAction.APPROVE and d.source == "rule"

        wider = _request(agent, Platform.GITHUB, "repo", "jrt/cactus")
        wider.scope = {"permissions": {"secrets": "write"}}
        d = await engine.evaluate(session, agent, wider)
        # falls through the pinned rule to the YAML github → llm rule
        assert d.action == PolicyAction.LLM


async def test_is_sensitive(db, policy):
    engine = PolicyEngine(policy)
    agent, _ = await make_agent(db, "s-agent")
    secrets_req = _request(agent, Platform.GITHUB, "repo", "jrt/x")
    secrets_req.scope = {"permissions": {"secrets": "write"}}
    assert engine.is_sensitive(secrets_req) is True
    contents_req = _request(agent, Platform.GITHUB, "repo", "jrt/x")
    contents_req.scope = {"permissions": {"contents": "write"}}
    assert engine.is_sensitive(contents_req) is False
    edit_req = _request(agent, Platform.KUBERNETES, "edit", "media")
    assert engine.is_sensitive(edit_req) is True


def test_duration_capping(policy):
    engine = PolicyEngine(policy)
    assert engine.cap_duration(3600, 7200) == 3600  # requested below cap
    assert engine.cap_duration(10 * 3600, 7200) == 7200  # rule cap wins
    # defaults cap (24h) applies even with no rule cap
    assert engine.cap_duration(48 * 3600, None) == 24 * 3600
