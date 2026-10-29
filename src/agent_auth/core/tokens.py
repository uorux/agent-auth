"""Tokens agent-auth signs itself: short-lived JWTs that an MCP server's
proxy (ToolHive) or a reverse proxy validates without calling back, from the
keys at /.well-known/jwks.json.

ES256, because that is what the validators accept (ToolHive takes RSA and
ECDSA, not EdDSA). The key is derived from the broker's signing key (HKDF,
its own label), so there is no second secret to keep: rotating
BROKER_SIGNING_KEY rotates this too, and the key id changes with it.

A token says who (the agent), for what (one server: `aud`; which of its
tools: `tools`) and under which grant. It is as good as its signature until
it expires, so lifetimes are short; /v1/tokens/verify also checks that the
grant is still active, for proxies that ask.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHM = "ES256"
_LABEL = b"agent-auth token signing key v1 (ES256)"
# The order of P-256's group.
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class TokenError(Exception):
    pass


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TokenIssuer:
    def __init__(self, broker_key: Ed25519PrivateKey, issuer: str):
        seed = broker_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        # 48 bytes reduced into [1, n-1]: the bias is negligible.
        okm = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=_LABEL).derive(seed)
        self._key = ec.derive_private_key(int.from_bytes(okm, "big") % (_N - 1) + 1, ec.SECP256R1())
        self.issuer = issuer.rstrip("/")
        numbers = self._key.public_key().public_numbers()
        jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": _b64u(numbers.x.to_bytes(32, "big")),
            "y": _b64u(numbers.y.to_bytes(32, "big")),
        }
        # RFC 7638 thumbprint: the members above, sorted, no whitespace.
        self.kid = _b64u(hashlib.sha256(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()).digest())
        self._jwk = {**jwk, "kid": self.kid, "use": "sig", "alg": ALGORITHM}

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self._jwk]}

    def discovery(self) -> dict[str, Any]:
        """Enough of an OIDC discovery document for a validator to find the keys."""
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": [ALGORITHM],
            "subject_types_supported": ["public"],
            "response_types_supported": ["token"],
        }

    def mint(self, *, subject: str, audience: str, ttl_secs: int, claims: dict[str, Any]) -> tuple[str, int]:
        """(token, expiry as a unix time)."""
        now = int(time.time())
        expires = now + max(1, int(ttl_secs))
        payload = {
            **claims,
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now - 5,
            "exp": expires,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._key, algorithm=ALGORITHM, headers={"kid": self.kid}), expires

    def verify(self, token: str, audience: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self._key.public_key(),
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
                leeway=5,
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from None
