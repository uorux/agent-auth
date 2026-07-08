from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from ..crypto import parse_api_key, verify_secret
from ..models import Agent

_bearer = HTTPBearer(auto_error=False)


def get_state(request: Request):
    return request.app.state


async def get_agent(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Agent:
    if creds is None:
        raise HTTPException(401, "missing bearer token")
    parsed = parse_api_key(creds.credentials)
    if parsed is None:
        raise HTTPException(401, "malformed API key")
    key_id, secret = parsed
    async with request.app.state.db.session() as session:
        agent = (
            await session.execute(select(Agent).where(Agent.key_id == key_id))
        ).scalar_one_or_none()
    if agent is None or agent.disabled or not verify_secret(secret, agent.api_key_hash):
        raise HTTPException(401, "invalid API key")
    return agent


async def require_admin(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    admin_token = request.app.state.settings.admin_token
    if not admin_token:
        raise HTTPException(503, "admin API disabled: ADMIN_TOKEN not configured")
    if creds is None or not hmac.compare_digest(creds.credentials, admin_token):
        raise HTTPException(401, "invalid admin token")
