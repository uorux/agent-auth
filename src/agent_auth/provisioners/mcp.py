"""MCP servers (and other HTTP tools) that take agent-auth's own tokens.

A grant is for one catalogued server and a set of its tools. Nothing is
changed anywhere when it is given: its credential is a short-lived token
signed by the broker (core/tokens.py), which the server's own proxy checks.
The broker is never in the data path, and holds no upstream credentials.

So revocation is the token running out (`token_ttl`, an hour by default; no
new one is issued once the grant ends), or at once for a proxy that asks
/v1/tokens/verify on each request.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..core.tokens import TokenIssuer
from ..models import Agent, Grant, utcnow
from ..policy.schema import McpPlatformConfig, McpServer
from ..schemas import CredentialOut, parse_duration
from .base import ProvisionerError, RequestSpec, SpecValidationError

TOOL_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
MAX_TOOLS = 64


def audience(server: McpServer) -> str:
    return server.audience or server.url


class McpProvisioner:
    platform = Platform.MCP

    def __init__(self, config: McpPlatformConfig, tokens: TokenIssuer):
        self.config = config
        self.tokens = tokens

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        name = spec.resource.strip().lower()
        server = self.config.servers.get(name)
        if server is None:
            known = ", ".join(sorted(self.config.servers)) or "none"
            raise SpecValidationError(f"no MCP server {name!r} in the catalog (there is: {known})")
        if spec.capability != "use":
            raise SpecValidationError('mcp capability is "use"')
        if set(spec.scope) - {"tools"}:
            raise SpecValidationError('an mcp scope is {"tools": [...]} (omit it for every tool)')
        tools = spec.scope.get("tools", ["*"])
        if not isinstance(tools, list) or not tools or len(tools) > MAX_TOOLS:
            raise SpecValidationError(f'"tools" is a list of 1 to {MAX_TOOLS} tool names, or ["*"]')
        if not all(isinstance(t, str) and (t == "*" or TOOL_RE.fullmatch(t)) for t in tools):
            raise SpecValidationError("malformed tool name")
        tools = ["*"] if "*" in tools else sorted(set(tools))
        if server.tools and tools != ["*"]:
            unknown = sorted(set(tools) - set(server.tools))
            if unknown:
                raise SpecValidationError(f"{name} has no tool {', '.join(unknown)}")
        spec.resource = name
        spec.scope = {"tools": tools}
        what = "every tool" if tools == ["*"] else f"tools {', '.join(tools)}"
        spec.notes.append(f"{what} of {name} ({server.url})" + (f": {server.description}" if server.description else ""))
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        if grant.resource not in self.config.servers:
            raise ProvisionerError(f"MCP server {grant.resource!r} is no longer in the catalog")
        return {"server": grant.resource}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        return None  # nothing was changed anywhere; tokens stop being issued

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
            raise ProvisionerError("grant is not active")
        server = self.config.servers.get(grant.resource)
        if server is None:
            raise ProvisionerError(f"MCP server {grant.resource!r} is no longer in the catalog")
        agent = await session.get(Agent, grant.agent_id)
        remaining = int((grant.expires_at - utcnow()).total_seconds())
        token, expires = self.tokens.mint(
            subject=f"agent:{agent.name}",
            audience=audience(server),
            ttl_secs=min(parse_duration(self.config.token_ttl), remaining),
            claims={
                "agent": agent.name,
                "server": grant.resource,
                "tools": list((grant.scope or {}).get("tools") or ["*"]),
                "grant": grant.id,
            },
        )
        return CredentialOut(
            kind="mcp_token",
            value=token,
            expires_at=datetime.fromtimestamp(expires, timezone.utc),
            note=(
                f"Send it to {server.url} as `Authorization: Bearer <value>`. It is short-lived: "
                "call get_credential again for a fresh one (nothing new is issued once the grant ends)."
            ),
        )
