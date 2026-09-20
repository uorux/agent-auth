from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from .. import authority as authority_mod
from ..core.service import HumanDecision, TransitionError
from ..crypto import generate_api_key
from ..core.states import GrantStatus, Platform
from ..models import AccessRequest, Agent, Grant, Rule
from ..schemas import (
    AgentCreate,
    AgentOut,
    RequestOut,
    RuleOut,
    SetKindBody,
    SetWebhookBody,
    parse_duration,
)
from .deps import require_admin
from .serialize import request_out

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


def _agent_out(
    agent: Agent, api_key: str | None = None, webhook_secret: str | None = None
) -> AgentOut:
    return AgentOut(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        kind=agent.kind,
        webhook_url=agent.webhook_url,
        lldap_username=agent.lldap_username,
        lldap_managed=agent.lldap_password_encrypted is not None,
        disabled=agent.disabled,
        last_seen_at=agent.last_seen_at,
        api_key=api_key,
        webhook_secret=webhook_secret,
    )


@router.post("/agents", response_model=AgentOut, response_model_exclude_none=True)
async def create_agent(body: AgentCreate, request: Request):
    state = request.app.state
    full_key, key_id, key_hash = generate_api_key()
    async with state.db.session() as session:
        existing = (
            await session.execute(select(Agent).where(Agent.name == body.name))
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(409, f"agent {body.name!r} already exists")
        webhook_secret = secrets.token_urlsafe(32) if body.webhook_url else None
        agent = Agent(
            name=body.name,
            description=body.description,
            kind=body.kind,
            key_id=key_id,
            api_key_hash=key_hash,
            webhook_url=body.webhook_url,
            webhook_secret=webhook_secret,
            lldap_username=body.lldap_username,
        )
        session.add(agent)
        await session.flush()
        return _agent_out(agent, api_key=full_key, webhook_secret=webhook_secret)


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


@router.post(
    "/agents/{agent_id}/rotate-webhook-secret",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def rotate_webhook_secret(agent_id: str, request: Request):
    """Mint (or replace) the per-agent HMAC key for webhook pings — also how
    pre-existing agents opt out of the global-secret fallback."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        agent.webhook_secret = secrets.token_urlsafe(32)
        return _agent_out(agent, webhook_secret=agent.webhook_secret)


@router.post(
    "/agents/{agent_id}/rotate-lldap-password",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def rotate_lldap_password(agent_id: str, request: Request):
    """Replace the password of the agent's broker-managed LLDAP account. The
    agent picks the new one up on its next homelab credential fetch; it is
    never printed. Refused for hand-registered accounts."""
    from ..provisioners.base import ProvisionerError, SpecValidationError

    state = request.app.state
    try:
        provisioner = state.registry.get(Platform.HOMELAB)
    except SpecValidationError as exc:
        raise HTTPException(501, str(exc))
    async with state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        try:
            await provisioner.rotate_password(session, agent)
        except ProvisionerError as exc:
            raise HTTPException(409, str(exc))
        return _agent_out(agent)


@router.post(
    "/agents/{agent_id}/set-kind",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def set_kind(agent_id: str, body: SetKindBody, request: Request):
    """Reclassify an existing agent without rotating its API key — the fix for
    a CLI agent registered on the default kind (`service`), which leaves it
    advertised as an a2a peer that never answers.

    Demoting to `ephemeral` also drops the webhook (meaningless: pings only go
    to service agents), closes any thread the agent was RESPONDING to, since
    it can no longer receive them, and revokes every active a2a grant that
    targets it — an ephemeral agent cannot be the resource of a talk grant, so
    none may linger from before the reclassification. Initiators are notified
    `peer_gone` rather than being left to wait out the idle sweep.
    """
    state = request.app.state
    closed = 0
    revoked = 0
    async with state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        was = agent.kind
        agent.kind = body.kind
        if body.kind != "service":
            agent.webhook_url = None
            agent.webhook_secret = None
            agent.last_listen_at = None
        out = _agent_out(agent)
    if body.kind != "service" and was == "service":
        closed = await state.a2a.orphan_inbound_threads(agent_id)
        revoked = await _revoke_a2a_grants_targeting(state, out.name)
    if closed or revoked:
        log.info(
            "set-kind %s → %s closed %d inbound thread(s), revoked %d a2a grant(s)",
            agent_id,
            body.kind,
            closed,
            revoked,
        )
    return out


async def _revoke_a2a_grants_targeting(state, agent_name: str) -> int:
    """Revoke active a2a grants whose resource is `agent_name`. Runs after the
    kind flip so a concurrent open loses either way: the open re-checks the
    responder's kind, and the grant it would ride is gone."""
    async with state.db.session() as session:
        grant_ids = list(
            (
                await session.execute(
                    select(Grant.id).where(
                        Grant.platform == Platform.A2A,
                        Grant.resource == agent_name,
                        Grant.status == GrantStatus.ACTIVE,
                    )
                )
            ).scalars()
        )
    revoked = 0
    for grant_id in grant_ids:
        try:
            await state.service.revoke_grant(
                grant_id, f"target {agent_name!r} reclassified ephemeral", "admin"
            )
            revoked += 1
        except TransitionError:
            # Expired or revoked between the select and now; nothing to do.
            continue
    return revoked


@router.post(
    "/agents/{agent_id}/set-webhook",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def set_webhook(agent_id: str, body: SetWebhookBody, request: Request):
    """Set/replace an existing agent's webhook_url (null clears it). Setting a
    URL mints a fresh webhook_secret, shown ONCE in the response."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        agent.webhook_url = body.webhook_url
        agent.webhook_secret = secrets.token_urlsafe(32) if body.webhook_url else None
        return _agent_out(agent, webhook_secret=agent.webhook_secret)


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(request: Request):
    async with request.app.state.db.session() as session:
        rules = (await session.execute(select(Rule).order_by(Rule.created_at.desc()))).scalars()
        return [
            RuleOut(
                id=r.id,
                action=r.action.value,
                agent_pattern=r.agent_pattern,
                delegator_pattern=r.delegator_pattern,
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
