"""The operator chatting with agents from the admin panel (README "Admin
panel"): ordinary a2a threads, opened by the operator's agent row
(core.a2a.OPERATOR_KIND) to a service agent. The agent sees a thread from
`operator`; the broker vouches that only a signed-in admin writes it.

The panel's session is the authority, not a grant, so these routes are
admin routes. Who wrote each message is recorded in its payload
(`operator`: the panel user) and in the broker's log.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import authority as authority_mod
from ..core.a2a import A2AError, reachability
from ..models import A2AMessage, A2AThread, AccessRequest, Agent, utcnow
from .deps import clamp_wait, require_admin

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/chat", dependencies=[Depends(require_admin)])

_MAX_WAIT_SECS = 25
TEXT_MAX = 20_000


class ChatOpen(BaseModel):
    to: str = Field(min_length=1, max_length=128)
    topic: str | None = Field(default=None, max_length=256)
    text: str = Field(min_length=1, max_length=TEXT_MAX)


class ChatSend(BaseModel):
    text: str = Field(min_length=1, max_length=TEXT_MAX)


class ChatClose(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


def _state(request: Request):
    state = request.app.state
    if not state.settings.a2a_relay_enabled:
        raise HTTPException(404, "a2a is disabled on this broker")
    return state


async def _operator(request: Request) -> Agent:
    """The operator's row, marked seen: while the panel is open the agents'
    side of these threads reports their peer alive."""
    state = _state(request)
    try:
        operator = await state.a2a.operator()
    except A2AError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    if operator.disabled:
        raise HTTPException(409, "the operator's identity is disabled")
    async with state.db.session() as db:
        row = await db.get(Agent, operator.id)
        row.last_seen_at = utcnow()
    return operator


def _payload(request: Request, text: str) -> dict[str, Any]:
    return {"type": "message", "text": text, "operator": request.state.admin_user}


def _message(m: A2AMessage, sender: str) -> dict[str, Any]:
    p = m.payload if isinstance(m.payload, dict) else {}
    return {
        "seq": m.seq,
        "at": m.created_at,
        "from": sender,
        "type": p.get("type"),
        "text": p.get("text") if isinstance(p.get("text"), str) else None,
        # A result message ({"type": "result", ...}) and anything else are
        # shown as they came.
        "status": p.get("status") if isinstance(p.get("status"), str) else None,
        "summary": p.get("summary") if isinstance(p.get("summary"), str) else None,
        "payload": None if isinstance(p.get("text"), str) else m.payload,
        "operator": p.get("operator") if isinstance(p.get("operator"), str) else None,
    }


def _preview(m: A2AMessage | None) -> str:
    if m is None:
        return ""
    shown = _message(m, "")
    return (shown["text"] or shown["summary"] or shown["type"] or "")[:200]


@router.get("/peers")
async def peers(request: Request):
    """The agents the operator can write to: service agents, and whether
    anything is reading their threads right now."""
    state = _state(request)
    threshold = state.settings.a2a_listen_threshold_secs
    async with state.db.session() as db:
        agents = (
            await db.execute(
                select(Agent).where(Agent.kind == "service", Agent.disabled.is_(False)).order_by(Agent.name)
            )
        ).scalars().all()
    return [
        {
            **reachability(a, threshold),
            "runtime": a.runtime,
            "project": a.project,
            "host": a.host,
            "placement": a.placement,
            "description": a.description,
        }
        for a in agents
    ]


@router.get("/threads")
async def threads(request: Request, limit: int = 100):
    """The operator's conversations, most recent first, each with its last
    message for the list."""
    state = _state(request)
    operator = await _operator(request)
    limit = max(1, min(limit, 500))
    async with state.db.session() as db:
        rows = (
            await db.execute(
                select(A2AThread)
                .where(A2AThread.initiator_agent_id == operator.id)
                .order_by(A2AThread.last_activity_at.desc())
                .limit(limit)
            )
        ).scalars().all()
        ids = [t.id for t in rows] or [""]
        # A thread's last_seq is its last message's.
        last = {
            m.thread_id: m
            for m in (
                await db.execute(
                    select(A2AMessage)
                    .join(A2AThread, A2AThread.id == A2AMessage.thread_id)
                    .where(A2AThread.id.in_(ids), A2AMessage.seq == A2AThread.last_seq)
                )
            ).scalars()
        }
        peer_ids = {t.responder_agent_id for t in rows} or {""}
        names = dict((await db.execute(select(Agent.id, Agent.name).where(Agent.id.in_(peer_ids)))).all())
    out = []
    for t in rows:
        m = last.get(t.id)
        out.append(
            {
                "id": t.id,
                "to": names.get(t.responder_agent_id, "?"),
                "topic": t.topic,
                "state": t.state,
                "close_reason": t.close_reason,
                "opened": t.created_at,
                "last": t.last_activity_at,
                "last_seq": t.last_seq,
                "preview": _preview(m),
                "last_from_operator": m is not None and m.sender_agent_id == operator.id,
            }
        )
    return out


@router.post("/threads")
async def open_thread(body: ChatOpen, request: Request):
    state = _state(request)
    operator = await _operator(request)
    try:
        out = await state.a2a.open_thread(operator, None, body.to, body.topic, _payload(request, body.text))
    except A2AError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    log.info("admin panel chat: %s opened a thread to %s (%s)", request.state.admin_user, body.to, out["thread_id"])
    return out


@router.get("/threads/{thread_id}")
async def read_thread(thread_id: str, request: Request, after_seq: int = 0, wait: float = 0):
    """The thread and its messages after `after_seq`; wait>0 holds the
    request until a new message or a change of state (at most 25s)."""
    state = _state(request)
    operator = await _operator(request)
    wait = clamp_wait(wait, 0, _MAX_WAIT_SECS)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    start = None
    while True:
        out = await _read(state, operator, thread_id, after_seq)
        start = start or out["thread"]["state"]
        remaining = deadline - loop.time()
        if out["messages"] or out["thread"]["state"] != start or start == "closed" or remaining <= 0:
            return out
        # Replies wake the initiator's key: the operator's agent id.
        await state.a2a_events.wait(operator.id, timeout=min(remaining, 5.0))


async def _read(state, operator: Agent, thread_id: str, after_seq: int) -> dict[str, Any]:
    async with state.db.session() as db:
        thread = await db.get(A2AThread, thread_id)
        if thread is None or thread.initiator_agent_id != operator.id:
            raise HTTPException(404, "unknown conversation")
        rows = (
            await db.execute(
                select(A2AMessage, Agent.name)
                .join(Agent, Agent.id == A2AMessage.sender_agent_id)
                .where(A2AMessage.thread_id == thread_id, A2AMessage.seq > after_seq)
                .order_by(A2AMessage.seq)
            )
        ).all()
        requests = (
            await db.execute(
                select(AccessRequest)
                .where(AccessRequest.delegation_thread_id == thread_id)
                .order_by(AccessRequest.created_at)
            )
        ).scalars().all()
        info = await state.a2a._thread_out(db, thread, operator.id)
    return {
        "thread": info,
        "messages": [_message(m, name) for m, name in rows],
        # Access the agent asked for on this conversation's behalf; those are
        # decided where every request is (rules, the reviewer, Discord).
        "requests": [
            {
                "id": r.id,
                "platform": r.platform.value,
                "what": authority_mod.label(r.platform, r.authority),
                "resource": r.resource,
                "status": r.status.value,
                "source": r.decision_source.value if r.decision_source else None,
            }
            for r in requests
        ],
    }


@router.post("/threads/{thread_id}/messages")
async def send(thread_id: str, body: ChatSend, request: Request):
    state = _state(request)
    operator = await _operator(request)
    try:
        return await state.a2a.send_message(operator, None, thread_id, _payload(request, body.text))
    except A2AError as exc:
        raise HTTPException(exc.status, exc.detail) from None


@router.post("/threads/{thread_id}/close")
async def close(thread_id: str, body: ChatClose, request: Request):
    state = _state(request)
    operator = await _operator(request)
    try:
        return await state.a2a.close(operator, None, thread_id, body.reason)
    except A2AError as exc:
        raise HTTPException(exc.status, exc.detail) from None
