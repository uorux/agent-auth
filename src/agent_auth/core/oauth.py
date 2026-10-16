"""The OAuth server that lets web UIs (claude.ai, ChatGPT connectors) use
the broker as a remote MCP server (policy `remote_mcp`; the routes are
api/oauth_routes.py, the MCP endpoint api/remote_mcp.py).

- Registration is dynamic (RFC 7591) and open: a UI registers itself. A
  client may only send the browser back to `remote_mcp.redirect_hosts`.
- Authorization is the authorization-code flow with PKCE (S256 only). The
  person authorizing signs in at the admin panel's OpenID provider and must
  be in its admin group; then they see the client's name and where it sends
  the browser, and name the agent it will act as.
- A client acts as one agent, `web-<name>` (runtime `web`, kind
  `ephemeral`, no usable API key of its own), bound at its first
  authorization. Everything it does goes through policy and approvals as
  that agent; disabling the agent, containing it, or revoking the client
  stops it.
- Access tokens (`aat_`) are short-lived and opaque; refresh tokens (`art_`)
  rotate, and one used twice revokes everything that authorization gave
  (it was stolen or replayed). Only their sha256 is stored.

What it does not do: tell a malicious UI from an honest one once you have
authorized it (it is then that agent, within policy), or keep what the UI
shows in its chat away from the UI's operator: the tool set
(`remote_mcp.tools`) leaves out credentials for that reason.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select, update

from ..crypto import generate_api_key
from ..models import Agent, OAuthClient, OAuthToken, new_uuid, utcnow
from ..policy.schema import RemoteMcpConfig
from ..schemas import parse_duration

log = logging.getLogger(__name__)

ACCESS_PREFIX, REFRESH_PREFIX, CODE_PREFIX = "aat_", "art_", "aac_"
CODE_TTL = timedelta(minutes=5)
WEB_RUNTIME = "web"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error, self.description, self.status = error, description, status


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def pkce_ok(verifier: str, challenge: str) -> bool:
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return secrets.compare_digest(digest, challenge)


def agent_name(label: str) -> str:
    label = re.sub(r"[^a-z0-9-]+", "-", label.lower()).strip("-")[:40] or "connector"
    return label if label.startswith("web-") else f"web-{label}"


@dataclass
class Authorization:
    """A validated /oauth/authorize request, before the person agrees."""

    client_id: str
    client_name: str
    redirect_uri: str
    state: str
    code_challenge: str


class OAuthService:
    def __init__(self, db, config: RemoteMcpConfig):
        self.db = db
        self.config = config
        self.access_ttl = timedelta(seconds=parse_duration(config.access_ttl))
        self.refresh_ttl = timedelta(seconds=parse_duration(config.refresh_ttl))

    # ── registration ──────────────────────────────────────────────────────

    def _redirect_ok(self, uri: str) -> bool:
        try:
            parsed = urlparse(uri)
        except ValueError:
            return False
        host = (parsed.hostname or "").lower()
        return parsed.scheme == "https" and not parsed.fragment and host in [h.lower() for h in self.config.redirect_hosts]

    async def register(self, body: dict[str, Any]) -> dict[str, Any]:
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            raise OAuthError("invalid_redirect_uri", "redirect_uris: a list of URLs")
        bad = [u for u in uris if not self._redirect_ok(u)]
        if bad:
            raise OAuthError(
                "invalid_redirect_uri",
                f"this broker sends the browser back only to {', '.join(self.config.redirect_hosts)} (https)",
            )
        method = body.get("token_endpoint_auth_method") or "none"
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            raise OAuthError("invalid_client_metadata", f"token_endpoint_auth_method {method!r} is not supported")
        name = str(body.get("client_name") or "")[:200]
        async with self.db.session() as session:
            count = (
                await session.execute(select(func.count()).select_from(OAuthClient).where(OAuthClient.revoked_at.is_(None)))
            ).scalar_one()
            if count >= self.config.max_clients:
                raise OAuthError("invalid_client_metadata", "too many registered clients; the operator can revoke some", 400)
            secret = secrets.token_urlsafe(32) if method != "none" else None
            client = OAuthClient(
                id=f"mcpc_{secrets.token_urlsafe(16)}",
                name=name,
                redirect_uris=list(uris),
                secret_hash=_hash(secret) if secret else None,
                created_at=utcnow(),
            )
            session.add(client)
        log.info("oauth: client %s registered (%r, %s)", client.id, name, ", ".join(uris))
        out = {
            "client_id": client.id,
            "client_id_issued_at": int(client.created_at.timestamp()),
            "client_name": name,
            "redirect_uris": list(uris),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if secret:
            out["client_secret"] = secret
            out["client_secret_expires_at"] = 0
        return out

    async def client(self, client_id: str | None) -> OAuthClient | None:
        if not client_id:
            return None
        async with self.db.session() as session:
            found = await session.get(OAuthClient, client_id)
        return found if found is not None and found.revoked_at is None else None

    # ── authorization ─────────────────────────────────────────────────────

    async def check_authorize(self, params: dict[str, str]) -> Authorization:
        """Validate /oauth/authorize. Errors before the redirect URI is known
        good are shown to the person, never sent to the redirect."""
        client = await self.client(params.get("client_id"))
        if client is None:
            raise OAuthError("invalid_client", "unknown client")
        redirect_uri = params.get("redirect_uri") or (client.redirect_uris[0] if len(client.redirect_uris) == 1 else "")
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "redirect_uri is not one this client registered")
        if params.get("response_type") != "code":
            raise OAuthError("unsupported_response_type", "only response_type=code")
        challenge = params.get("code_challenge") or ""
        if params.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", challenge):
            raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
        return Authorization(client.id, client.name, redirect_uri, params.get("state") or "", challenge)

    async def bound_agent(self, client_id: str) -> Agent | None:
        async with self.db.session() as session:
            client = await session.get(OAuthClient, client_id)
            return await session.get(Agent, client.agent_id) if client and client.agent_id else None

    async def approve(self, auth: Authorization, label: str, by: str) -> str:
        """The person agreed: bind the client to its agent (made if need be)
        and return a code for the redirect."""
        code = CODE_PREFIX + secrets.token_urlsafe(32)
        async with self.db.session() as session:
            client = await session.get(OAuthClient, auth.client_id)
            if client is None or client.revoked_at is not None:
                raise OAuthError("invalid_client", "unknown client")
            agent = await session.get(Agent, client.agent_id) if client.agent_id else None
            if agent is None:
                name = agent_name(label)
                if not NAME_RE.fullmatch(name.removeprefix("web-")):
                    raise OAuthError("invalid_request", "name: lowercase letters, digits and '-'")
                agent = (await session.execute(select(Agent).where(Agent.name == name))).scalar_one_or_none()
                if agent is not None and agent.runtime != WEB_RUNTIME:
                    raise OAuthError("invalid_request", f"{name} exists and is not a web connector's agent")
                if agent is None:
                    _, key_id, key_hash = generate_api_key()  # never shown: it has no key of its own
                    agent = Agent(
                        name=name,
                        description=f"Web UI connector: {client.name or client.id}, authorized by {by}",
                        kind="ephemeral",
                        runtime=WEB_RUNTIME,
                        key_id=key_id,
                        api_key_hash=key_hash,
                    )
                    session.add(agent)
                    await session.flush()
                client.agent_id = agent.id
            if agent.disabled:
                raise OAuthError("access_denied", f"{agent.name} is disabled")
            session.add(
                OAuthToken(
                    kind="code",
                    token_hash=_hash(code),
                    client_id=client.id,
                    agent_id=agent.id,
                    family=new_uuid(),
                    expires_at=utcnow() + CODE_TTL,
                    code_challenge=auth.code_challenge,
                    redirect_uri=auth.redirect_uri,
                    authorized_by=by,
                    created_at=utcnow(),
                )
            )
        log.warning("oauth: %s authorized client %s (%r) as %s", by, auth.client_id, auth.client_name, agent.name)
        return code

    # ── tokens ────────────────────────────────────────────────────────────

    async def _authenticate(self, session, client_id: str | None, secret: str | None) -> OAuthClient:
        client = await session.get(OAuthClient, client_id) if client_id else None
        if client is None or client.revoked_at is not None:
            raise OAuthError("invalid_client", "unknown client", 401)
        if client.secret_hash and not (secret and secrets.compare_digest(_hash(secret), client.secret_hash)):
            raise OAuthError("invalid_client", "client authentication failed", 401)
        return client

    async def _pair(self, session, client: OAuthClient, agent_id: str, family: str, by: str) -> dict[str, Any]:
        access, refresh = ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
        now = utcnow()
        for kind, token, ttl in (("access", access, self.access_ttl), ("refresh", refresh, self.refresh_ttl)):
            session.add(
                OAuthToken(kind=kind, token_hash=_hash(token), client_id=client.id, agent_id=agent_id, family=family,
                           expires_at=now + ttl, authorized_by=by, created_at=now)
            )
        client.last_used_at = now
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(self.access_ttl.total_seconds()),
            "refresh_token": refresh,
        }

    async def _revoke_family(self, session, family: str) -> None:
        await session.execute(
            update(OAuthToken).where(OAuthToken.family == family, OAuthToken.revoked_at.is_(None)).values(revoked_at=utcnow())
        )

    async def exchange(self, form: dict[str, str], basic: tuple[str, str] | None) -> dict[str, Any]:
        """/oauth/token. A refusal that revokes something (a code or refresh
        token used twice) is committed before it is raised."""
        async with self.db.session() as session:
            out = await self._exchange(session, form, basic)
        if isinstance(out, OAuthError):
            raise out
        return out

    async def _exchange(self, session, form: dict[str, str], basic: tuple[str, str] | None) -> dict[str, Any] | OAuthError:
        client_id = (basic[0] if basic else None) or form.get("client_id")
        secret = (basic[1] if basic else None) or form.get("client_secret")
        grant = form.get("grant_type")
        try:
            client = await self._authenticate(session, client_id, secret)
        except OAuthError as exc:
            return exc
        if grant == "authorization_code":
            row = await self._find(session, "code", form.get("code") or "")
            if row is None or row.client_id != client.id:
                return OAuthError("invalid_grant", "unknown or expired code")
            if row.used_at is not None:
                # A code used twice: whatever the first use got is revoked too.
                await self._revoke_family(session, row.family)
                return OAuthError("invalid_grant", "this code was already used")
            row.used_at = utcnow()
            if (form.get("redirect_uri") or row.redirect_uri) != row.redirect_uri:
                return OAuthError("invalid_grant", "redirect_uri differs from the authorization's")
            if not pkce_ok(form.get("code_verifier") or "", row.code_challenge or ""):
                return OAuthError("invalid_grant", "PKCE verification failed")
            return await self._pair(session, client, row.agent_id, row.family, row.authorized_by)
        if grant == "refresh_token":
            row = await self._find(session, "refresh", form.get("refresh_token") or "")
            if row is None or row.client_id != client.id:
                return OAuthError("invalid_grant", "unknown or expired refresh token")
            if row.used_at is not None:
                await self._revoke_family(session, row.family)
                log.warning("oauth: refresh token reused for client %s: its authorization is revoked", client.id)
                return OAuthError("invalid_grant", "refresh token reused; sign in again")
            row.used_at = utcnow()
            agent = await session.get(Agent, row.agent_id)
            if agent is None or agent.disabled:
                return OAuthError("invalid_grant", "the connector's agent is disabled")
            return await self._pair(session, client, row.agent_id, row.family, row.authorized_by)
        return OAuthError("unsupported_grant_type", "authorization_code or refresh_token")

    async def _find(self, session, kind: str, token: str) -> OAuthToken | None:
        if not token:
            return None
        row = (await session.execute(select(OAuthToken).where(OAuthToken.token_hash == _hash(token)))).scalar_one_or_none()
        if row is None or row.kind != kind or row.revoked_at is not None or row.expires_at <= utcnow():
            return None
        return row

    async def agent_for_access(self, session, token: str) -> Agent | None:
        """The agent an access token speaks for, or None."""
        row = await self._find(session, "access", token)
        if row is None:
            return None
        client = await session.get(OAuthClient, row.client_id)
        if client is None or client.revoked_at is not None:
            return None
        return await session.get(Agent, row.agent_id)

    async def revoke(self, token: str) -> None:
        """RFC 7009: revoking either token ends the whole authorization."""
        async with self.db.session() as session:
            for kind in ("access", "refresh"):
                row = await self._find(session, kind, token)
                if row is not None:
                    await self._revoke_family(session, row.family)

    # ── the operator's ────────────────────────────────────────────────────

    async def clients(self) -> list[dict[str, Any]]:
        async with self.db.session() as session:
            rows = (await session.execute(select(OAuthClient).order_by(OAuthClient.created_at.desc()))).scalars().all()
            names = {a.id: a.name for a in (await session.execute(select(Agent).where(Agent.runtime == WEB_RUNTIME))).scalars()}
            live = dict(
                (
                    await session.execute(
                        select(OAuthToken.client_id, func.count())
                        .where(OAuthToken.kind == "refresh", OAuthToken.revoked_at.is_(None), OAuthToken.used_at.is_(None),
                               OAuthToken.expires_at > utcnow())
                        .group_by(OAuthToken.client_id)
                    )
                ).all()
            )
        return [
            {
                "client_id": c.id,
                "name": c.name,
                "redirect_uris": c.redirect_uris,
                "agent": names.get(c.agent_id),
                "created_at": c.created_at,
                "last_used_at": c.last_used_at,
                "revoked_at": c.revoked_at,
                "live_authorizations": live.get(c.id, 0),
            }
            for c in rows
        ]

    async def revoke_client(self, client_id: str) -> bool:
        async with self.db.session() as session:
            client = await session.get(OAuthClient, client_id)
            if client is None:
                return False
            client.revoked_at = client.revoked_at or utcnow()
            await session.execute(
                update(OAuthToken).where(OAuthToken.client_id == client_id, OAuthToken.revoked_at.is_(None)).values(revoked_at=utcnow())
            )
        log.warning("oauth: client %s revoked", client_id)
        return True
