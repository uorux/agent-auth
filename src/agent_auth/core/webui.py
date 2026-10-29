"""The admin panel's sign-in (README "Admin panel"): the operator logs in at
the homelab's OpenID provider (Authelia), the broker checks the ID token
itself and that the user is in the admin group, and keeps a session in an
encrypted cookie.

Nothing here trusts a header a proxy adds: whoever can reach the broker's
port could send one. The proof is the provider's signature on the ID token.

A session is not the admin token. `allowed()` lists the admin routes one may
call; deciding requests, arming hosts and lifting a lockdown are not among
them and stay on Discord, the CLI and the hosts' TOTP codes. A session may
write to agents as the operator (api/chat_routes.py).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..policy.schema import UiConfig
from ..schemas import parse_duration

log = logging.getLogger(__name__)

SESSION_COOKIE = "aa_ui"
LOGIN_COOKIE = "aa_ui_login"
LOGIN_TTL = 600
CSRF_HEADER = "X-CSRF-Token"

# What a signed-in session may call of the admin API: looking, and setting
# agents and hosts up. (method, path) with {} for one path segment.
ALLOWED = [
    ("GET", "/admin/agents"),
    ("GET", "/admin/rules"),
    ("GET", "/admin/daemons"),
    ("GET", "/admin/hosts"),
    ("GET", "/admin/broker-key"),
    ("GET", "/admin/projects"),
    ("GET", "/admin/log/decisions"),
    ("GET", "/admin/log/commands"),
    ("GET", "/admin/log/commands/{}"),
    ("GET", "/admin/a2a/graph"),
    ("GET", "/admin/a2a/threads/{}"),
    ("GET", "/admin/models/usage"),
    ("GET", "/admin/connectors"),
    ("POST", "/admin/connectors/{}/revoke"),
    ("GET", "/admin/chat/peers"),
    ("GET", "/admin/chat/threads"),
    ("GET", "/admin/chat/threads/{}"),
    ("POST", "/admin/chat/threads"),
    ("POST", "/admin/chat/threads/{}/messages"),
    ("POST", "/admin/chat/threads/{}/close"),
    ("POST", "/admin/agents"),
    ("PATCH", "/admin/agents/{}/attributes"),
    ("POST", "/admin/agents/{}/rename"),
    ("POST", "/admin/agents/{}/rotate-key"),
    ("POST", "/admin/agents/{}/disable"),
    ("DELETE", "/admin/rules/{}"),
    ("POST", "/admin/daemons/pairing-codes"),
    ("DELETE", "/admin/daemons/{}"),
]
_ALLOWED = [(m, re.compile("^" + re.escape(p).replace(r"\{\}", "[^/]+") + "$")) for m, p in ALLOWED]


def allowed(method: str, path: str) -> bool:
    return any(m == method and rx.match(path) for m, rx in _ALLOWED)


class UiAuthError(Exception):
    """Sign-in refused; the text is shown to the person signing in."""


@dataclass
class Session:
    user: str
    csrf: str
    expires: int


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class UiAuth:
    def __init__(self, config: UiConfig, encryption_key: str):
        self.config = config
        self.base = config.base_url.rstrip("/")
        self.issuer = config.issuer.rstrip("/")
        self.ttl = parse_duration(config.session_ttl)
        # A key of its own, derived: a session cookie is never a stored
        # credential's ciphertext, nor the other way round.
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"agent-auth admin panel session").derive(
            base64.urlsafe_b64decode(encryption_key.encode())
        )
        self._box = Fernet(base64.urlsafe_b64encode(derived))
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    def serves(self, headers) -> bool:
        """Whether this request came for the panel's own address. The panel
        is not served under the broker's other names (the public one that
        agents use): a request a proxy forwarded for another host gets no
        page and no session. This narrows where the panel shows up; it is
        not what keeps anyone out (the sign-in is)."""
        own = urlparse(self.base).netloc.lower()
        for name in ("host", "x-forwarded-host"):
            value = (headers.get(name) or "").split(",")[0].strip().lower()
            if value and value != own and value.split(":")[0] not in ("127.0.0.1", "localhost", "[::1]"):
                return False
        return True

    @property
    def redirect_uri(self) -> str:
        return f"{self.base}/ui/callback"

    # ── cookies ───────────────────────────────────────────────────────────

    def _seal(self, kind: str, data: dict[str, Any]) -> str:
        return self._box.encrypt(json.dumps({"k": kind, **data}).encode()).decode()

    def _open(self, kind: str, value: str | None, max_age: int) -> dict[str, Any] | None:
        if not value:
            return None
        try:
            data = json.loads(self._box.decrypt(value.encode(), ttl=max_age))
        except (InvalidToken, ValueError):
            return None
        return data if isinstance(data, dict) and data.get("k") == kind else None

    def session(self, cookie: str | None) -> Session | None:
        data = self._open("session", cookie, self.ttl)
        if data is None or data.get("exp", 0) <= time.time():
            return None
        return Session(user=data["user"], csrf=data["csrf"], expires=data["exp"])

    # ── the provider ──────────────────────────────────────────────────────

    async def _discover(self) -> dict[str, Any]:
        if self._discovery is None:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(f"{self.issuer}/.well-known/openid-configuration")
            resp.raise_for_status()
            found = resp.json()
            if found.get("issuer", "").rstrip("/") != self.issuer:
                raise UiAuthError("the provider's discovery document names another issuer")
            self._discovery = found
        return self._discovery

    async def _keys(self, refresh: bool = False) -> dict[str, Any]:
        if self._jwks is None or refresh:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get((await self._discover())["jwks_uri"])
            resp.raise_for_status()
            self._jwks = resp.json()
        return self._jwks

    async def begin(self, redirect_uri: str | None = None, carry: dict[str, Any] | None = None) -> tuple[str, str]:
        """Where to send the browser, and the cookie that ties its return to
        this attempt (state, nonce and the PKCE verifier). `redirect_uri` and
        `carry` are for another sign-in than the panel's (the OAuth server
        for web UIs, api/oauth_routes.py): where the provider sends the
        browser back, and what the cookie carries for the return."""
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.config.client_id,
                "redirect_uri": redirect_uri or self.redirect_uri,
                "scope": "openid profile groups",
                "state": state,
                "nonce": nonce,
                "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
                "code_challenge_method": "S256",
            }
        )
        url = f"{(await self._discover())['authorization_endpoint']}?{query}"
        sealed = {"state": state, "nonce": nonce, "verifier": verifier, "redirect_uri": redirect_uri or self.redirect_uri}
        return url, self._seal("login", {**sealed, "carry": carry or {}})

    async def finish(self, login_cookie: str | None, code: str, state: str) -> str:
        """The provider sent the browser back: check everything and return a
        session cookie, or raise UiAuthError."""
        user, _ = await self.identify(login_cookie, code, state)
        log.info("admin panel: %s signed in", user)
        return self._seal(
            "session", {"user": user, "csrf": secrets.token_urlsafe(24), "exp": int(time.time()) + self.ttl}
        )

    def seal(self, kind: str, data: dict[str, Any]) -> str:
        return self._seal(kind, data)

    def unseal(self, kind: str, value: str | None, max_age: int) -> dict[str, Any] | None:
        return self._open(kind, value, max_age)

    async def identify(self, login_cookie: str | None, code: str, state: str) -> tuple[str, dict[str, Any]]:
        """Who signed in, if they are in the admin group (else UiAuthError),
        and what the attempt carried."""
        attempt = self._open("login", login_cookie, LOGIN_TTL)
        if attempt is None or not secrets.compare_digest(attempt["state"], state or ""):
            raise UiAuthError("this sign-in was not started here, or took too long; try again")
        found = await self._discover()
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                found["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": attempt.get("redirect_uri") or self.redirect_uri,
                    "client_id": self.config.client_id,
                    "code_verifier": attempt["verifier"],
                },
            )
            if resp.status_code != 200:
                log.warning("admin panel: the provider refused the code (%s): %s", resp.status_code, resp.text[:200])
                raise UiAuthError("the provider refused the sign-in")
            tokens = resp.json()
            claims = await self._verify(tokens.get("id_token", ""), attempt["nonce"])
            groups = claims.get("groups")
            user = claims.get("preferred_username")
            if groups is None or user is None:
                # Providers may keep these out of the ID token (Authelia does
                # by default) and serve them from userinfo.
                info = await client.get(
                    found["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens.get('access_token', '')}"}
                )
                if info.status_code != 200 or info.json().get("sub") != claims["sub"]:
                    raise UiAuthError("the provider did not say who signed in")
                groups = groups if groups is not None else info.json().get("groups")
                user = user or info.json().get("preferred_username")
        user = user or claims["sub"]
        if not isinstance(groups, list) or self.config.admin_group not in groups:
            log.warning("admin panel: %s signed in but is not in %s", user, self.config.admin_group)
            raise UiAuthError(f"{user} is not in the group {self.config.admin_group}")
        return user, attempt.get("carry") or {}

    async def _verify(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            key = None
            for refresh in (False, True):
                keys = [k for k in (await self._keys(refresh)).get("keys", []) if kid is None or k.get("kid") == kid]
                if keys:
                    key = jwt.PyJWK(keys[0]).key
                    break
            if key is None:
                raise UiAuthError("the ID token is signed with a key the provider does not publish")
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256", "ES256"],
                audience=self.config.client_id,
                issuer=[self.issuer, self.issuer + "/"],
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            log.warning("admin panel: ID token rejected: %s", exc)
            raise UiAuthError("the provider's ID token did not check out") from None
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise UiAuthError("the ID token answers a different sign-in")
        return claims
