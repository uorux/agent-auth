from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from agent_auth.core.service import HumanDecision, TransitionError
from agent_auth.core.states import (
    GrantStatus,
    Platform,
    RequestStatus,
    RuleAction,
)
from agent_auth.models import AccessRequest, Grant, Rule, utcnow
from agent_auth.schemas import RequestCreate

from .conftest import make_agent, openrouter_verdicts


def a2a_request(resource: str, duration="1h", justification="need to coordinate deploys"):
    return RequestCreate(
        platform=Platform.A2A,
        capability="talk",
        resource=resource,
        justification=justification,
        requested_duration=duration,
    )


async def wait_for_status(db, request_id, statuses, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with db.session() as session:
            req = await session.get(AccessRequest, request_id)
            if req.status in statuses:
                return req
        await asyncio.sleep(0.02)
    raise AssertionError(f"request {request_id} never reached {statuses}; at {req.status}")


async def test_auto_approve_grants_and_caps_duration(db, service):
    sender, _ = await make_agent(db, "auto-sender")
    peer, _ = await make_agent(db, "peer-agent")

    req = await service.create_request(sender.id, a2a_request("peer-agent", duration="8h"))
    assert req.status == RequestStatus.GRANTED
    # capped by the a2a auto-approve rule's 2h
    assert req.approved_duration_secs == 2 * 3600

    async with db.session() as session:
        grant = (
            (await session.execute(
                __import__("sqlalchemy").select(Grant).where(Grant.request_id == req.id)
            )).scalar_one()
        )
        assert grant.status == GrantStatus.ACTIVE
        drift = grant.expires_at - grant.granted_at - timedelta(hours=2)
        assert abs(drift) < timedelta(seconds=1)


async def test_validator_deny_unknown_peer(db, service):
    sender, _ = await make_agent(db, "auto-sender2")
    req = await service.create_request(sender.id, a2a_request("nonexistent-agent"))
    assert req.status == RequestStatus.DENIED
    assert "unknown target agent" in req.decision_reason


async def test_policy_deny(db, service):
    agent, _ = await make_agent(db, "denied-agent-x")
    peer, _ = await make_agent(db, "peer2")
    req = await service.create_request(agent.id, a2a_request("peer2"))
    assert req.status == RequestStatus.DENIED
    assert req.decision_reason == "agent is on the naughty list"


async def test_surface_then_human_approve(db, service):
    agent, _ = await make_agent(db, "plain-agent")
    peer, _ = await make_agent(db, "peer3")
    req = await service.create_request(agent.id, a2a_request("peer3"))
    assert req.status == RequestStatus.AWAITING_HUMAN

    decided = await service.decide(
        req.id, HumanDecision(approve=True, decided_by="jrt", duration_secs=1800)
    )
    assert decided.status == RequestStatus.GRANTED
    assert decided.approved_duration_secs == 1800
    assert decided.decided_by == "jrt"


async def test_surface_then_human_deny(db, service):
    agent, _ = await make_agent(db, "plain-agent-b")
    peer, _ = await make_agent(db, "peer4")
    req = await service.create_request(agent.id, a2a_request("peer4"))
    decided = await service.decide(
        req.id, HumanDecision(approve=False, decided_by="jrt", reason="nope")
    )
    assert decided.status == RequestStatus.DENIED
    # double-decide is rejected
    with pytest.raises(TransitionError):
        await service.decide(req.id, HumanDecision(approve=True, decided_by="jrt"))


async def test_human_edit_creates_rule_and_next_request_auto_approves(db, service):
    agent, _ = await make_agent(db, "plain-agent-c")
    peer, _ = await make_agent(db, "peer5")
    req = await service.create_request(agent.id, a2a_request("peer5"))
    await service.decide(
        req.id,
        HumanDecision(
            approve=True,
            decided_by="jrt",
            duration_secs=900,
            rule_action=RuleAction.AUTO_APPROVE,
            rule_resource_pattern="*",
        ),
    )
    # identical request now auto-approves via the DB rule
    req2 = await service.create_request(agent.id, a2a_request("peer5"))
    assert req2.status == RequestStatus.GRANTED
    assert req2.decision_source.value == "rule"
    assert req2.approved_duration_secs == 900  # rule max_duration caps it


async def test_llm_approve_flow(db, service, github_mock):
    agent, _ = await make_agent(db, "dev-agent")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="pushing a fix to the deploy workflow",
        requested_duration="4h",
    )
    with openrouter_verdicts(
        {"verdict": "approve", "reasoning": "specific and proportionate", "suggested_duration_secs": 3600}
    ):
        req = await service.create_request(agent.id, body)
        assert req.status == RequestStatus.LLM_EVALUATING
        req = await wait_for_status(db, req.id, {RequestStatus.GRANTED})
    assert req.decision_source.value == "llm"
    assert req.approved_duration_secs == 3600  # LLM suggested less than the 8h cap
    assert github_mock.called


async def test_llm_deny_retry_then_escalate(db, service):
    agent, _ = await make_agent(db, "dev-agent-2")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="need access",
        requested_duration="4h",
    )
    with openrouter_verdicts(
        {"verdict": "deny", "reasoning": "justification too vague"},
        {"verdict": "deny", "reasoning": "still vague"},
    ):
        req = await service.create_request(agent.id, body)
        req = await wait_for_status(db, req.id, {RequestStatus.LLM_DENIED})
        assert "too vague" in req.decision_reason

        # retry with a better justification (attempt 2 of budget 2)
        await service.retry(req.id, agent.id, "pushing PR #42 fixing CVE-2026-1234")
        req = await wait_for_status(
            db, req.id, {RequestStatus.LLM_DENIED, RequestStatus.AWAITING_HUMAN}
        )
        # budget exhausted on the second deny → escalated to human
        assert req.status == RequestStatus.AWAITING_HUMAN

    # retry after escalation is rejected
    with pytest.raises(TransitionError):
        await service.retry(req.id, agent.id, "please")


async def test_llm_error_escalates_to_human(db, service):
    agent, _ = await make_agent(db, "dev-agent-3")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "read"}},
        justification="read the CI config to debug the build",
        requested_duration="1h",
    )
    # No openrouter mock → the HTTP call fails → fail-safe to human review.
    import respx

    with respx.mock(assert_all_called=False):
        req = await service.create_request(agent.id, body)
        req = await wait_for_status(db, req.id, {RequestStatus.AWAITING_HUMAN})
    assert req.status == RequestStatus.AWAITING_HUMAN


async def test_agent_escalate_from_llm_denied(db, service):
    agent, _ = await make_agent(db, "dev-agent-4")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="need access",
        requested_duration="4h",
    )
    with openrouter_verdicts({"verdict": "deny", "reasoning": "too vague"}):
        req = await service.create_request(agent.id, body)
        await wait_for_status(db, req.id, {RequestStatus.LLM_DENIED})
    req = await service.escalate(req.id, agent.id)
    assert req.status == RequestStatus.AWAITING_HUMAN
    # human can still approve after escalation
    decided = await service.decide(
        req.id, HumanDecision(approve=False, decided_by="jrt", reason="not needed")
    )
    assert decided.status == RequestStatus.DENIED


async def test_human_preempts_llm_denied(db, service):
    """Human clicks Approve while the agent is mid-retry-loop."""
    agent, _ = await make_agent(db, "dev-agent-5")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="need access",
        requested_duration="4h",
    )
    with openrouter_verdicts({"verdict": "deny", "reasoning": "vague"}):
        req = await service.create_request(agent.id, body)
        await wait_for_status(db, req.id, {RequestStatus.LLM_DENIED})

    decided = await service.decide(
        req.id, HumanDecision(approve=False, decided_by="jrt", reason="overruled")
    )
    assert decided.status == RequestStatus.DENIED
    with pytest.raises(TransitionError):
        await service.retry(req.id, agent.id, "but wait")


async def test_expiry_scheduler_catchup(db, service):
    """Grants already past expires_at (e.g. broker was down) get revoked on the next tick."""
    sender, _ = await make_agent(db, "auto-sender3")
    peer, _ = await make_agent(db, "peer6")
    req = await service.create_request(sender.id, a2a_request("peer6"))
    assert req.status == RequestStatus.GRANTED

    async with db.session() as session:
        from sqlalchemy import select, update

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
        await session.execute(
            update(Grant)
            .where(Grant.id == grant.id)
            .values(expires_at=utcnow() - timedelta(minutes=5))
        )

    expired = await service.expire_due_grants()
    assert expired == 1
    async with db.session() as session:
        from sqlalchemy import select

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
        assert grant.status == GrantStatus.EXPIRED
        assert grant.revoke_reason == "expired"

    # second tick is a no-op
    assert await service.expire_due_grants() == 0


async def test_edited_approval_revalidated(db, service):
    """An override that violates a platform ceiling is rejected; the request
    stays awaiting_human for a re-edit."""
    sender, _ = await make_agent(db, "plain-edit")
    await make_agent(db, "real-peer")
    req = await service.create_request(sender.id, a2a_request("real-peer"))
    assert req.status == RequestStatus.AWAITING_HUMAN

    # resource_override to a non-existent agent → a2a validator rejects it
    with pytest.raises(TransitionError, match="rejected by validator"):
        await service.decide(
            req.id,
            HumanDecision(approve=True, decided_by="jrt", resource_override="ghost-agent"),
        )
    async with db.session() as session:
        fresh = await session.get(AccessRequest, req.id)
        assert fresh.status == RequestStatus.AWAITING_HUMAN  # rolled back

    # a valid override succeeds
    await make_agent(db, "other-peer")
    decided = await service.decide(
        req.id,
        HumanDecision(approve=True, decided_by="jrt", resource_override="other-peer"),
    )
    assert decided.status == RequestStatus.GRANTED
    assert decided.approved_resource == "other-peer"


async def test_github_scope_override_ceiling_enforced(db, service, github_mock):
    """A human editing scope above the permission ceiling is rejected."""
    agent, _ = await make_agent(db, "dev-edit")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="push a fix",
        requested_duration="2h",
    )
    # no openrouter mock → llm errors → escalates to awaiting_human
    import respx

    with respx.mock(assert_all_called=False):
        req = await service.create_request(agent.id, body)
        req = await wait_for_status(db, req.id, {RequestStatus.AWAITING_HUMAN})

    with pytest.raises(TransitionError, match="rejected by validator"):
        await service.decide(
            req.id,
            HumanDecision(
                approve=True,
                decided_by="jrt",
                scope_override={"permissions": {"administration": "write"}},
            ),
        )


async def test_sensitive_scope_forced_to_human(db, service):
    """secrets:write is sensitive → surfaces even though github routes to llm."""
    agent, _ = await make_agent(db, "sde-secret")
    body = RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"secrets": "write"}},
        justification="upload a registry token as an actions secret",
        requested_duration="2h",
    )
    req = await service.create_request(agent.id, body)
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert any("sensitive" in n for n in req.risk_notes)


async def test_human_duration_capped_at_one_year(db, service):
    agent, _ = await make_agent(db, "plain-dur")
    await make_agent(db, "dur-peer")
    req = await service.create_request(agent.id, a2a_request("dur-peer"))
    decided = await service.decide(
        req.id,
        HumanDecision(approve=True, decided_by="jrt", duration_secs=10 * 365 * 86400),
    )
    assert decided.status == RequestStatus.GRANTED
    assert decided.approved_duration_secs == 365 * 86400


async def test_admin_revoke(db, service):
    sender, _ = await make_agent(db, "auto-sender4")
    peer, _ = await make_agent(db, "peer7")
    req = await service.create_request(sender.id, a2a_request("peer7"))
    async with db.session() as session:
        from sqlalchemy import select

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
    revoked = await service.revoke_grant(grant.id, "compromised", "admin")
    assert revoked.status == GrantStatus.REVOKED
    with pytest.raises(TransitionError):
        await service.revoke_grant(grant.id, "again", "admin")
