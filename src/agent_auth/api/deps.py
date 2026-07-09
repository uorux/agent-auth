from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from ..crypto import parse_api_key, verify_secret
from ..models import Agent, AgentSession, utcnow

_bearer = HTTPBearer(auto_error=False)

# Liveness bookkeeping: skip the UPDATE when last_seen is this fresh. Keeps hot
# paths read-only; the skew is invisible against the 120s liveness threshold.
_LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=20)


@dataclass
class Caller:
    agent: Agent
    session: AgentSession | None  # present iff X-Agent-Session was sent


def get_state(request: Request):
    return request.app.state


def _touch(row, now) -> bool:
    if row.last_seen_at is None or now - row.last_seen_at > _LAST_SEEN_WRITE_INTERVAL:
        row.last_seen_at = now
        return True
    return False


async def get_caller(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Caller:
    if creds is None:
        raise HTTPException(401, "missing bearer token")
    parsed = parse_api_key(creds.credentials)
    if parsed is None:
        raise HTTPException(401, "malformed API key")
    key_id, secret = parsed
    session_header = request.headers.get("X-Agent-Session")
    now = utcnow()
    async with request.app.state.db.session() as db:
        agent = (
            await db.execute(select(Agent).where(Agent.key_id == key_id))
        ).scalar_one_or_none()
        if agent is None or agent.disabled or not verify_secret(secret, agent.api_key_hash):
            raise HTTPException(401, "invalid API key")
        agent_session = None
        if session_header:
            agent_session = await db.get(AgentSession, session_header)
            if (
                agent_session is None
                or agent_session.agent_id != agent.id
                or agent_session.closed_at is not None
            ):
                # 401 (not 404): the auth context is stale — mint a new session.
                raise HTTPException(401, "unknown or closed session")
            _touch(agent_session, now)
        _touch(agent, now)
    return Caller(agent=agent, session=agent_session)


async def get_agent(caller: Caller = Depends(get_caller)) -> Agent:
    return caller.agent


async def require_admin(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    admin_token = request.app.state.settings.admin_token
    if not admin_token:
        raise HTTPException(503, "admin API disabled: ADMIN_TOKEN not configured")
    if creds is None or not hmac.compare_digest(creds.credentials, admin_token):
        raise HTTPException(401, "invalid admin token")
