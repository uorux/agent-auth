"""The broker as a token issuer (core/tokens.py): its public keys, and a
check a reverse proxy can call per request (Traefik forwardAuth, nginx
auth_request). Unauthenticated on purpose: the keys are public, and verify
answers only yes or no about a token the caller already holds."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from ..core.states import GrantStatus, Platform
from ..core.tokens import TokenError
from ..models import Agent, Grant, utcnow
from ..provisioners.mcp import audience

router = APIRouter()


def _tokens(request: Request):
    tokens = getattr(request.app.state, "tokens", None)
    if tokens is None:
        raise HTTPException(404)
    return tokens


@router.get("/.well-known/jwks.json")
async def jwks(request: Request):
    return _tokens(request).jwks()


@router.get("/.well-known/openid-configuration")
async def discovery(request: Request):
    return _tokens(request).discovery()


def _no(why: str) -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{why}"'})


@router.get("/v1/tokens/verify")
async def verify(request: Request, server: str):
    """200 if the bearer token is one of ours for that server and its grant
    is still active; 401 otherwise. On 200, X-Agent-Auth-Agent / -Tools say
    who and for which tools (for the proxy to pass on, or to log)."""
    tokens = _tokens(request)
    entry = request.app.state.service.engine.policy.platforms.mcp.servers.get(server)
    scheme, _, token = (request.headers.get("authorization") or "").partition(" ")
    if entry is None or scheme.lower() != "bearer" or not token:
        return _no("a bearer token for a known server is required")
    try:
        claims = tokens.verify(token.strip(), audience(entry))
    except TokenError:
        return _no("not a valid token for this server")
    if claims.get("server") != server:
        return _no("not a valid token for this server")
    async with request.app.state.db.session() as session:
        grant = await session.get(Grant, str(claims.get("grant") or ""))
        agent = await session.get(Agent, grant.agent_id) if grant is not None else None
    if (
        grant is None
        or agent is None
        or agent.disabled
        or grant.platform != Platform.MCP
        or grant.resource != server
        or grant.status != GrantStatus.ACTIVE
        or grant.expires_at <= utcnow()
    ):
        return _no("the grant behind this token has ended")
    return Response(
        status_code=200,
        headers={"X-Agent-Auth-Agent": agent.name, "X-Agent-Auth-Tools": ",".join(claims.get("tools") or [])},
    )
