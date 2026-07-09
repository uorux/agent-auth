from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.service import TransitionError
from ..core.states import GrantStatus, RequestStatus, WAITING_STATUSES
from ..models import AccessRequest, Agent, Grant
from ..provisioners.base import ProvisionerError, SpecValidationError
from ..schemas import (
    CatalogOut,
    CredentialOut,
    GrantOut,
    RequestCreate,
    RequestOut,
    RetryBody,
)
from .catalog import build_catalog
from .deps import Caller, get_agent, get_caller
from .serialize import grant_out, request_out

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1")


@router.get("/me")
async def me(caller: Caller = Depends(get_caller)):
    agent = caller.agent
    # webhook_secret is deliberately NOT here: it's show-once at admin
    # create/rotate-webhook-secret. Exposing it on every authenticated call
    # would let anything holding the API key mint forged signed pings.
    out = {
        "id": agent.id,
        "name": agent.name,
        "description": agent.description,
        "kind": agent.kind,
        "webhook_url": agent.webhook_url,
        "lldap_username": agent.lldap_username,
    }
    if caller.session is not None:
        out["session"] = {"id": caller.session.id, "name": caller.session.name}
    return out


@router.get("/catalog", response_model=CatalogOut, response_model_exclude_none=True)
async def catalog(request: Request, agent: Agent = Depends(get_agent)):
    """What this agent may request: enabled platforms and the roles/groups/repos
    (with descriptions and typical routing) available to it."""
    state = request.app.state
    async with state.db.session() as session:
        return await build_catalog(session, agent, state.registry, state.service.engine)


@router.post("/requests", response_model=RequestOut)
async def create_request(
    body: RequestCreate, request: Request, caller: Caller = Depends(get_caller)
):
    state = request.app.state
    try:
        req = await state.service.create_request(
            caller.agent.id,
            body,
            session_id=caller.session.id if caller.session else None,
        )
    except SpecValidationError as exc:
        raise HTTPException(400, str(exc))
    async with state.db.session() as session:
        return await request_out(session, req, caller.agent.name)


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
        from sqlalchemy import select as _select

        grants = list(
            (await session.execute(query.order_by(Grant.granted_at.desc()))).scalars()
        )
        delegator_ids = {g.delegator_agent_id for g in grants if g.delegator_agent_id}
        names: dict[str, str] = {}
        if delegator_ids:
            rows = await session.execute(
                _select(Agent.id, Agent.name).where(Agent.id.in_(delegator_ids))
            )
            names = dict(rows.all())
        return [
            grant_out(g, agent.name, names.get(g.delegator_agent_id)) for g in grants
        ]


@router.get("/grants/{grant_id}/credential", response_model=CredentialOut)
async def get_credential(grant_id: str, request: Request, agent: Agent = Depends(get_agent)):
    state = request.app.state
    async with state.db.session() as session:
        grant = await session.get(Grant, grant_id)
        if grant is None or grant.agent_id != agent.id:
            raise HTTPException(404, "unknown grant")
        # Delegated grants stop minting the moment their thread closes — the
        # scheduler revokes them within a tick, but credentials must not be
        # issuable in the gap.
        if grant.delegation_thread_id is not None:
            from ..core.states import THREAD_OPEN
            from ..models import A2AThread

            thread = await session.get(A2AThread, grant.delegation_thread_id)
            if thread is None or thread.state != THREAD_OPEN:
                raise HTTPException(
                    403, "delegation thread is closed; credential no longer issuable"
                )
        provisioner = state.registry.get(grant.platform)
        try:
            return await provisioner.get_credential(session, grant)
        except ProvisionerError as exc:
            raise HTTPException(403, str(exc))
        except NotImplementedError as exc:
            raise HTTPException(501, str(exc))
