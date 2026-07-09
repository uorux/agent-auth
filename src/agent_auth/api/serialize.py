from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import RequestStatus
from ..models import AccessRequest, Agent, Grant
from ..schemas import GrantOut, RequestOut

_GUIDANCE = {
    RequestStatus.LLM_DENIED: (
        "Denied by LLM review — see decision_reason. You may POST /v1/requests/{id}/retry "
        "with a revised justification, or POST /v1/requests/{id}/escalate for human review."
    ),
    RequestStatus.AWAITING_HUMAN: (
        "Waiting for a human decision on Discord. Poll GET /v1/requests/{id}/wait."
    ),
    RequestStatus.LLM_EVALUATING: "Under LLM review. Poll GET /v1/requests/{id}/wait.",
    RequestStatus.GRANTED: (
        "Granted. Fetch credentials with GET /v1/grants/{grant_id}/credential if applicable."
    ),
}


async def request_out(
    session: AsyncSession, request: AccessRequest, agent_name: str | None = None
) -> RequestOut:
    if agent_name is None:
        agent = await session.get(Agent, request.agent_id)
        agent_name = agent.name if agent else "?"
    delegator_name = None
    if request.delegator_agent_id is not None:
        delegator = await session.get(Agent, request.delegator_agent_id)
        delegator_name = delegator.name if delegator else "?"
    grant = (
        await session.execute(select(Grant.id).where(Grant.request_id == request.id))
    ).scalar_one_or_none()
    guidance = _GUIDANCE.get(request.status)
    if guidance:
        guidance = guidance.replace("{id}", request.id).replace("{grant_id}", grant or "?")
    return RequestOut(
        id=request.id,
        agent=agent_name,
        platform=request.platform,
        capability=request.capability,
        resource=request.resource,
        scope=request.scope,
        justification=request.justification,
        requested_duration_secs=request.requested_duration_secs,
        status=request.status,
        attempt=request.attempt,
        decision_source=request.decision_source,
        decision_reason=request.decision_reason,
        approved_duration_secs=request.approved_duration_secs,
        approved_scope=request.approved_scope,
        approved_resource=request.approved_resource,
        grant_id=grant,
        delegator=delegator_name,
        delegation_thread_id=request.delegation_thread_id,
        created_at=request.created_at,
        guidance=guidance,
    )


def grant_out(grant: Grant, agent_name: str, delegator_name: str | None = None) -> GrantOut:
    return GrantOut(
        id=grant.id,
        request_id=grant.request_id,
        agent=agent_name,
        platform=grant.platform,
        capability=grant.capability,
        resource=grant.resource,
        scope=grant.scope,
        granted_at=grant.granted_at,
        expires_at=grant.expires_at,
        status=grant.status,
        delegator=delegator_name,
        delegation_thread_id=grant.delegation_thread_id,
    )
