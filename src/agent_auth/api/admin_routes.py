from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from .. import authority as authority_mod
from ..core.service import HumanDecision, TransitionError
from ..crypto import generate_api_key
from ..models import AccessRequest, Agent, Rule
from ..schemas import AgentCreate, AgentOut, RequestOut, RuleOut, parse_duration
from .deps import require_admin
from .serialize import request_out

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


def _agent_out(agent: Agent, api_key: str | None = None) -> AgentOut:
    return AgentOut(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        webhook_url=agent.webhook_url,
        lldap_username=agent.lldap_username,
        disabled=agent.disabled,
        api_key=api_key,
    )


@router.post("/agents", response_model=AgentOut)
async def create_agent(body: AgentCreate, request: Request):
    state = request.app.state
    full_key, key_id, key_hash = generate_api_key()
    async with state.db.session() as session:
        existing = (
            await session.execute(select(Agent).where(Agent.name == body.name))
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(409, f"agent {body.name!r} already exists")
        agent = Agent(
            name=body.name,
            description=body.description,
            key_id=key_id,
            api_key_hash=key_hash,
            webhook_url=body.webhook_url,
            lldap_username=body.lldap_username,
        )
        session.add(agent)
        await session.flush()
        return _agent_out(agent, api_key=full_key)


@router.get("/agents", response_model=list[AgentOut])
async def list_agents(request: Request):
    async with request.app.state.db.session() as session:
        agents = (await session.execute(select(Agent).order_by(Agent.name))).scalars()
        return [_agent_out(a) for a in agents]


@router.post("/agents/{agent_id}/rotate-key", response_model=AgentOut)
async def rotate_key(agent_id: str, request: Request):
    full_key, key_id, key_hash = generate_api_key()
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        agent.key_id = key_id
        agent.api_key_hash = key_hash
        return _agent_out(agent, api_key=full_key)


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(request: Request):
    async with request.app.state.db.session() as session:
        rules = (await session.execute(select(Rule).order_by(Rule.created_at.desc()))).scalars()
        return [
            RuleOut(
                id=r.id,
                action=r.action.value,
                agent_pattern=r.agent_pattern,
                platform=r.platform,
                capability_pattern=authority_mod.label(r.platform, r.authority)
                if r.authority is not None
                else "*",
                resource_pattern=r.resource_pattern,
                authority=r.authority,
                max_duration_secs=r.max_duration_secs,
                enabled=r.enabled,
                created_by=r.created_by,
                notes=r.notes,
            )
            for r in rules
        ]


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, request: Request):
    async with request.app.state.db.session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            raise HTTPException(404, "unknown rule")
        await session.delete(rule)
    return {"ok": True}


@router.get("/requests", response_model=list[RequestOut])
async def list_requests(request: Request, limit: int = 100):
    async with request.app.state.db.session() as session:
        rows = (
            await session.execute(
                select(AccessRequest)
                .order_by(AccessRequest.created_at.desc())
                .limit(min(limit, 500))
            )
        ).scalars()
        return [await request_out(session, r) for r in rows]


class DecideBody(BaseModel):
    approve: bool
    reason: str = ""
    duration: str | int | None = None
    resource_override: str | None = None
    scope_override: dict | None = None


@router.post("/requests/{request_id}/decide", response_model=RequestOut)
async def decide_request(request_id: str, body: DecideBody, request: Request):
    """Human decision via API — the fallback surface when Discord is unavailable."""
    duration_secs = None
    if body.duration is not None:
        try:
            duration_secs = parse_duration(body.duration)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    try:
        req = await request.app.state.service.decide(
            request_id,
            HumanDecision(
                approve=body.approve,
                decided_by="admin-api",
                reason=body.reason,
                duration_secs=duration_secs,
                resource_override=body.resource_override,
                scope_override=body.scope_override,
            ),
        )
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    async with request.app.state.db.session() as session:
        return await request_out(session, req)


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant(grant_id: str, request: Request, reason: str = "revoked by admin"):
    try:
        grant = await request.app.state.service.revoke_grant(grant_id, reason, "admin")
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True, "grant_id": grant.id, "status": grant.status.value}
