from __future__ import annotations

import asyncio
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.service import TransitionError
from ..core.states import GrantStatus, RequestStatus, WAITING_STATUSES
from ..models import A2AMessage, AccessRequest, Agent, Grant, utcnow
from ..provisioners import a2a as a2a_mod
from ..provisioners.base import ProvisionerError, SpecValidationError
from ..schemas import (
    A2ACheckOut,
    A2ASendBody,
    CatalogOut,
    CredentialOut,
    GrantOut,
    RequestCreate,
    RequestOut,
    RetryBody,
)
from .catalog import build_catalog
from .deps import get_agent
from .serialize import grant_out, request_out

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1")


@router.get("/me")
async def me(agent: Agent = Depends(get_agent)):
    return {
        "id": agent.id,
        "name": agent.name,
        "description": agent.description,
        "webhook_url": agent.webhook_url,
        "lldap_username": agent.lldap_username,
    }


@router.get("/catalog", response_model=CatalogOut, response_model_exclude_none=True)
async def catalog(request: Request, agent: Agent = Depends(get_agent)):
    """What this agent may request: enabled platforms and the roles/groups/repos
    (with descriptions and typical routing) available to it."""
    state = request.app.state
    async with state.db.session() as session:
        return await build_catalog(session, agent, state.registry, state.service.engine)


@router.post("/requests", response_model=RequestOut)
async def create_request(
    body: RequestCreate, request: Request, agent: Agent = Depends(get_agent)
):
    state = request.app.state
    try:
        req = await state.service.create_request(agent.id, body)
    except SpecValidationError as exc:
        raise HTTPException(400, str(exc))
    async with state.db.session() as session:
        return await request_out(session, req, agent.name)


@router.get("/requests/{request_id}", response_model=RequestOut)
async def get_request(request_id: str, request: Request, agent: Agent = Depends(get_agent)):
    state = request.app.state
    async with state.db.session() as session:
        req = await session.get(AccessRequest, request_id)
        if req is None or req.agent_id != agent.id:
            raise HTTPException(404, "unknown request")
        return await request_out(session, req, agent.name)


@router.get("/requests/{request_id}/wait", response_model=RequestOut)
async def wait_request(
    request_id: str,
    request: Request,
    agent: Agent = Depends(get_agent),
    timeout: float = 60,
):
    """Long-poll: returns when the request leaves a waiting status or on timeout."""
    state = request.app.state
    timeout = min(max(timeout, 1), 300)
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        async with state.db.session() as session:
            req = await session.get(AccessRequest, request_id)
            if req is None or req.agent_id != agent.id:
                raise HTTPException(404, "unknown request")
            if req.status not in WAITING_STATUSES:
                return await request_out(session, req, agent.name)
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            async with state.db.session() as session:
                req = await session.get(AccessRequest, request_id)
                return await request_out(session, req, agent.name)
        # Event wakeups with a short re-check interval as the fallback.
        await state.events.wait(request_id, timeout=min(remaining, 2.0))


@router.post("/requests/{request_id}/retry", response_model=RequestOut)
async def retry_request(
    request_id: str, body: RetryBody, request: Request, agent: Agent = Depends(get_agent)
):
    state = request.app.state
    try:
        req = await state.service.retry(request_id, agent.id, body.justification)
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    async with state.db.session() as session:
        return await request_out(session, req, agent.name)


@router.post("/requests/{request_id}/escalate", response_model=RequestOut)
async def escalate_request(
    request_id: str, request: Request, agent: Agent = Depends(get_agent)
):
    state = request.app.state
    try:
        req = await state.service.escalate(request_id, agent.id)
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    async with state.db.session() as session:
        return await request_out(session, req, agent.name)


@router.get("/grants", response_model=list[GrantOut])
async def list_grants(
    request: Request, agent: Agent = Depends(get_agent), status: str = "active"
):
    from sqlalchemy import select

    state = request.app.state
    query = select(Grant).where(Grant.agent_id == agent.id)
    if status != "all":
        try:
            query = query.where(Grant.status == GrantStatus(status))
        except ValueError:
            raise HTTPException(400, f"invalid status {status!r}")
    async with state.db.session() as session:
        grants = (await session.execute(query.order_by(Grant.granted_at.desc()))).scalars()
        return [grant_out(g, agent.name) for g in grants]


@router.get("/grants/{grant_id}/credential", response_model=CredentialOut)
async def get_credential(grant_id: str, request: Request, agent: Agent = Depends(get_agent)):
    state = request.app.state
    async with state.db.session() as session:
        grant = await session.get(Grant, grant_id)
        if grant is None or grant.agent_id != agent.id:
            raise HTTPException(404, "unknown grant")
        provisioner = state.registry.get(grant.platform)
        try:
            return await provisioner.get_credential(session, grant)
        except ProvisionerError as exc:
            raise HTTPException(403, str(exc))
        except NotImplementedError as exc:
            raise HTTPException(501, str(exc))


# ------------------------------------------------------------------- A2A


@router.get("/a2a/check", response_model=A2ACheckOut)
async def a2a_check(
    peer: str,
    request: Request,
    agent: Agent = Depends(get_agent),
    direction: str = "out",
    topic: str | None = None,
):
    """direction=out: may I talk to peer? direction=in: may peer talk to me?"""
    from sqlalchemy import select

    state = request.app.state
    async with state.db.session() as session:
        peer_agent = (
            await session.execute(select(Agent).where(Agent.name == peer))
        ).scalar_one_or_none()
        if peer_agent is None:
            return A2ACheckOut(allowed=False, reason=f"unknown agent {peer!r}")
        if direction == "out":
            grant = await a2a_mod.check_grant(session, agent.id, peer_agent.name, topic)
        elif direction == "in":
            grant = await a2a_mod.check_grant(session, peer_agent.id, agent.name, topic)
        else:
            raise HTTPException(400, "direction must be 'out' or 'in'")
    if grant is None:
        return A2ACheckOut(allowed=False, reason="no active a2a grant")
    return A2ACheckOut(allowed=True, grant_id=grant.id, expires_at=grant.expires_at)


@router.post("/a2a/send")
async def a2a_send(body: A2ASendBody, request: Request, agent: Agent = Depends(get_agent)):
    from sqlalchemy import select

    state = request.app.state
    if not state.settings.a2a_relay_enabled:
        raise HTTPException(404, "a2a relay is disabled on this broker")
    async with state.db.session() as session:
        recipient = (
            await session.execute(select(Agent).where(Agent.name == body.to))
        ).scalar_one_or_none()
        if recipient is None or recipient.disabled:
            raise HTTPException(404, f"unknown recipient {body.to!r}")
        grant = await a2a_mod.check_grant(session, agent.id, recipient.name, body.scope)
        if grant is None:
            raise HTTPException(
                403,
                f"no active a2a grant to talk to {body.to!r}; request one via POST /v1/requests "
                f'{{"platform": "a2a", "capability": "talk", "resource": "{body.to}"}}',
            )
        message = A2AMessage(
            sender_agent_id=agent.id,
            recipient_agent_id=recipient.id,
            grant_id=grant.id,
            payload={"from": agent.name, "topic": body.scope, "body": body.payload},
        )
        session.add(message)
        await session.flush()
        message_id = message.id
        webhook_url = recipient.webhook_url

    delivered_via = "inbox"
    if webhook_url:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    webhook_url,
                    json={
                        "type": "a2a_message",
                        "message_id": message_id,
                        "from": agent.name,
                        "topic": body.scope,
                        "payload": body.payload,
                        "grant_id": grant.id,
                    },
                )
            if resp.status_code < 300:
                delivered_via = "webhook"
        except httpx.HTTPError:
            log.warning("webhook delivery to %s failed; message stays in inbox", body.to)

    async with state.db.session() as session:
        msg = await session.get(A2AMessage, message_id)
        msg.delivered_via = delivered_via
        if delivered_via == "webhook":
            msg.acked_at = utcnow()
    return {"message_id": message_id, "delivered_via": delivered_via}


@router.get("/a2a/inbox")
async def a2a_inbox(request: Request, agent: Agent = Depends(get_agent), limit: int = 50):
    from sqlalchemy import select

    state = request.app.state
    async with state.db.session() as session:
        rows = (
            await session.execute(
                select(A2AMessage, Agent.name)
                .join(Agent, Agent.id == A2AMessage.sender_agent_id)
                .where(
                    A2AMessage.recipient_agent_id == agent.id,
                    A2AMessage.acked_at.is_(None),
                )
                .order_by(A2AMessage.created_at)
                .limit(min(limit, 200))
            )
        ).all()
    return [
        {
            "message_id": m.id,
            "from": sender_name,
            "payload": m.payload,
            "created_at": m.created_at.isoformat(),
        }
        for m, sender_name in rows
    ]


@router.post("/a2a/inbox/{message_id}/ack")
async def a2a_ack(message_id: str, request: Request, agent: Agent = Depends(get_agent)):
    state = request.app.state
    async with state.db.session() as session:
        msg = await session.get(A2AMessage, message_id)
        if msg is None or msg.recipient_agent_id != agent.id:
            raise HTTPException(404, "unknown message")
        msg.acked_at = utcnow()
    return {"ok": True}
