from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from ..core.a2a import A2AError
from ..models import Agent, AgentSession, utcnow
from ..provisioners import a2a as a2a_mod
from ..schemas import (
    A2ACheckOut,
    SessionCreate,
    SessionOut,
    ThreadCloseBody,
    ThreadMessageBody,
    ThreadOpenBody,
)
from .deps import Caller, get_caller

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1")

_MAX_WAIT_SECS = 300


def _a2a(request: Request):
    state = request.app.state
    if not state.settings.a2a_relay_enabled:
        raise HTTPException(404, "a2a is disabled on this broker")
    return state


def _raise(exc: A2AError):
    raise HTTPException(exc.status, exc.detail)


# ------------------------------------------------------------------ sessions


@router.post("/sessions", response_model=SessionOut)
async def create_session(body: SessionCreate, request: Request, caller: Caller = Depends(get_caller)):
    """Mint a session for this agent instance. Ephemeral agents need one for
    all a2a activity; pass its id back in the X-Agent-Session header."""
    state = request.app.state
    async with state.db.session() as db:
        for _ in range(5):
            name = f"{body.label}-{secrets.token_hex(2)}"
            clash = (
                await db.execute(
                    select(AgentSession).where(
                        AgentSession.agent_id == caller.agent.id,
                        AgentSession.name == name,
                    )
                )
            ).scalar_one_or_none()
            if clash is None:
                break
        else:  # pragma: no cover - 5 hex4 collisions
            raise HTTPException(500, "could not allocate a session name")
        row = AgentSession(agent_id=caller.agent.id, name=name)
        db.add(row)
        await db.flush()
        return SessionOut(session_id=row.id, name=row.name, created_at=row.created_at)


@router.post("/sessions/close")
async def close_session(request: Request, caller: Caller = Depends(get_caller)):
    """Close the session named by X-Agent-Session; its threads end peer_gone."""
    if caller.session is None:
        raise HTTPException(400, "no X-Agent-Session header")
    state = request.app.state
    try:
        closed = await state.a2a.end_session(caller.agent, caller.session.id)
    except A2AError as exc:
        _raise(exc)
    return {"ok": True, "threads_closed": closed}


# ------------------------------------------------------------------- threads


@router.post("/a2a/threads")
async def open_thread(body: ThreadOpenBody, request: Request, caller: Caller = Depends(get_caller)):
    state = _a2a(request)
    try:
        return await state.a2a.open_thread(
            caller.agent, caller.session, body.to, body.topic, body.payload
        )
    except A2AError as exc:
        _raise(exc)


@router.get("/a2a/threads")
async def list_threads(
    request: Request,
    caller: Caller = Depends(get_caller),
    thread_state: str | None = Query(default=None, alias="state"),
    role: str | None = None,
):
    state = _a2a(request)
    try:
        return await state.a2a.list_threads(caller.agent, caller.session, thread_state, role)
    except A2AError as exc:
        _raise(exc)


@router.get("/a2a/threads/{thread_id}")
async def get_thread(thread_id: str, request: Request, caller: Caller = Depends(get_caller)):
    state = _a2a(request)
    try:
        return await state.a2a.get_thread(caller.agent, caller.session, thread_id)
    except A2AError as exc:
        _raise(exc)


@router.post("/a2a/threads/{thread_id}/accept")
async def accept_thread(thread_id: str, request: Request, caller: Caller = Depends(get_caller)):
    state = _a2a(request)
    try:
        return await state.a2a.accept(caller.agent, caller.session, thread_id)
    except A2AError as exc:
        _raise(exc)


@router.post("/a2a/threads/{thread_id}/reject")
async def reject_thread(
    thread_id: str,
    body: ThreadCloseBody,
    request: Request,
    caller: Caller = Depends(get_caller),
):
    state = _a2a(request)
    try:
        return await state.a2a.reject(caller.agent, caller.session, thread_id, body.reason)
    except A2AError as exc:
        _raise(exc)


@router.post("/a2a/threads/{thread_id}/close")
async def close_thread(
    thread_id: str,
    body: ThreadCloseBody,
    request: Request,
    caller: Caller = Depends(get_caller),
):
    state = _a2a(request)
    try:
        return await state.a2a.close(caller.agent, caller.session, thread_id, body.reason)
    except A2AError as exc:
        _raise(exc)


@router.post("/a2a/threads/{thread_id}/messages")
async def send_message(
    thread_id: str,
    body: ThreadMessageBody,
    request: Request,
    caller: Caller = Depends(get_caller),
):
    state = _a2a(request)
    try:
        return await state.a2a.send_message(
            caller.agent, caller.session, thread_id, body.payload
        )
    except A2AError as exc:
        _raise(exc)


@router.get("/a2a/threads/{thread_id}/messages")
async def read_messages(
    thread_id: str,
    request: Request,
    caller: Caller = Depends(get_caller),
    after_seq: int = 0,
    wait: float = 0,
):
    """Cursor read; wait>0 long-polls until a new message or state change.
    The poll loop refreshes the caller's last-seen — it doubles as keep-alive."""
    state = _a2a(request)
    wait = min(max(wait, 0), _MAX_WAIT_SECS)
    deadline = asyncio.get_event_loop().time() + wait
    wake_key = state.a2a.wake_key(caller.agent, caller.session)
    try:
        first = await state.a2a.read_messages(caller.agent, caller.session, thread_id, after_seq)
    except A2AError as exc:
        _raise(exc)
    start_state = first["thread"]["state"]
    if first["messages"] or wait <= 0 or start_state == "closed":
        return first
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return first
        await state.a2a_events.wait(wake_key, timeout=min(remaining, 2.0))
        await _touch_caller(state, caller)
        try:
            result = await state.a2a.read_messages(
                caller.agent, caller.session, thread_id, after_seq
            )
        except A2AError as exc:
            _raise(exc)
        if result["messages"] or result["thread"]["state"] != start_state:
            return result
        first = result


@router.get("/a2a/events")
async def a2a_events(
    request: Request,
    caller: Caller = Depends(get_caller),
    wait: float = 0,
    after: datetime | None = None,
):
    """Pending opens awaiting my accept + my threads with activity since the
    cursor. Service agents run this in a loop; wait>0 long-polls."""
    state = _a2a(request)
    if after is not None and after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    wait = min(max(wait, 0), _MAX_WAIT_SECS)
    deadline = asyncio.get_event_loop().time() + wait
    wake_key = state.a2a.wake_key(caller.agent, caller.session)
    while True:
        try:
            snapshot = await state.a2a.events_snapshot(caller.agent, caller.session, after)
        except A2AError as exc:
            _raise(exc)
        if snapshot["pending_opens"] or snapshot["activity"]:
            return snapshot
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return snapshot
        await state.a2a_events.wait(wake_key, timeout=min(remaining, 2.0))
        await _touch_caller(state, caller)


@router.get("/a2a/check", response_model=A2ACheckOut)
async def a2a_check(
    peer: str,
    request: Request,
    caller: Caller = Depends(get_caller),
    direction: str = "out",
    topic: str | None = None,
):
    """direction=out: may I open a thread to peer? direction=in: may peer open
    one to me? Grants are agent-level; sessions of one agent share them."""
    state = _a2a(request)
    async with state.db.session() as db:
        peer_agent = (
            await db.execute(select(Agent).where(Agent.name == peer))
        ).scalar_one_or_none()
        if peer_agent is None:
            return A2ACheckOut(allowed=False, reason=f"unknown agent {peer!r}")
        # topic=None here means "any grant at all" — informational only; the
        # open/send paths enforce strict topic matching.
        if direction == "out":
            grant = await a2a_mod.check_grant(
                db, caller.agent.id, peer_agent.name, topic, any_topic=topic is None
            )
        elif direction == "in":
            grant = await a2a_mod.check_grant(
                db, peer_agent.id, caller.agent.name, topic, any_topic=topic is None
            )
        else:
            raise HTTPException(400, "direction must be 'out' or 'in'")
    if grant is None:
        return A2ACheckOut(allowed=False, reason="no active a2a grant")
    return A2ACheckOut(allowed=True, grant_id=grant.id, expires_at=grant.expires_at)


async def _touch_caller(state, caller: Caller) -> None:
    """Refresh last-seen inside long-poll loops so a parked poll counts as
    liveness (deps only touches once per request)."""
    now = utcnow()
    async with state.db.session() as db:
        agent = await db.get(Agent, caller.agent.id)
        if agent is not None:
            agent.last_seen_at = now
        if caller.session is not None:
            row = await db.get(AgentSession, caller.session.id)
            if row is not None and row.closed_at is None:
                row.last_seen_at = now
