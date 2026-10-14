"""Containment (core/lockdown.py): the operator's, and allowed agents'.

The operator contains and lifts with the admin token. An agent the policy
names under `containment.agents` may contain (never lift), not every agent
at once unless `containment.allow_all`. To any other agent the route does
not exist (404).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.lockdown import ContainError
from ..models import Agent
from ..policy.agents import agent_matches
from .deps import get_agent, require_admin

admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
agents = APIRouter(prefix="/v1")


class ContainBody(BaseModel):
    # An agent match, as in a rule: {name: "claude-x-*"}, {project: x},
    # {host: galaxy}, {runtime: codex}, {placement: sandbox}; {} = everyone.
    match: dict[str, Any]
    reason: str = Field(min_length=1, max_length=500)
    evidence: str = Field(default="", max_length=4000)


class LiftBody(BaseModel):
    id: str | None = None  # None: every containment


def _service(request: Request):
    containment = getattr(request.app.state, "containment", None)
    if containment is None:
        raise HTTPException(503, "containment is not set up on this broker")
    return containment


@admin.get("/containment")
async def list_containment(request: Request):
    return await _service(request).list()


@admin.post("/containment")
async def contain(body: ContainBody, request: Request):
    try:
        return await _service(request).contain(
            body.match, body.reason, by=getattr(request.state, "admin_user", "admin"), evidence=body.evidence, source="operator"
        )
    except ContainError as exc:
        raise HTTPException(422, str(exc)) from None


@admin.post("/containment/lift")
async def lift(body: LiftBody, request: Request):
    try:
        return {"lifted": await _service(request).lift(body.id, by=getattr(request.state, "admin_user", "admin"))}
    except ContainError as exc:
        raise HTTPException(404, str(exc)) from None


def _allowed(request: Request, agent: Agent) -> None:
    allowed = request.app.state.service.engine.policy.containment
    if not any(agent_matches(p, agent) for p in allowed.agents):
        raise HTTPException(404, "Not Found")


@agents.post("/containment")
async def agent_contain(request: Request, agent: Agent = Depends(get_agent)):
    """An allowed agent contains others. It cannot lift a containment; the
    operator is pinged every time. The body is read only after the caller
    is known to be allowed: a malformed one must not answer 422 to an agent
    the route does not exist for."""
    _allowed(request, agent)
    try:
        body = ContainBody.model_validate(await request.json())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if not body.match and not request.app.state.service.engine.policy.containment.allow_all:
        raise HTTPException(403, "containing every agent at once is the operator's")
    try:
        return await _service(request).contain(
            body.match, body.reason, by=agent.name, evidence=body.evidence, source="agent"
        )
    except ContainError as exc:
        raise HTTPException(422, str(exc)) from None


@agents.get("/containment")
async def agent_list(request: Request, agent: Agent = Depends(get_agent)):
    _allowed(request, agent)
    return await _service(request).list()
