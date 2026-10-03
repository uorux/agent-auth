"""The signing contract between the broker and its paired daemons.

Three pieces, all ed25519 + HMAC-SHA256:

- **Pairing** binds a daemon's public key to its (role, name) once, using a
  one-time code an admin carries from `agent-auth admin daemon-pair` to the
  host. Both sides prove knowledge of the code over the exact keys being
  exchanged, so whoever relays the HTTP request can't swap either key.
- **Hello** authenticates each WebSocket connection: both sides sign a
  transcript of both nonces, so neither signature can be replayed into
  another connection.
- **Envelopes** carry every message after the hello. Each names its sender
  (`iss`) and its recipient (`aud`), so a job the broker signed for host A
  is refused by host B, and carries an id + expiry for replay protection.

Every signed or MACed byte string is a length-prefixed transcript with a
context label first, so no field boundary is ambiguous and no signature made
for one purpose verifies for another.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROLES = ("host", "sandbox")
BROKER = "broker"

PUBLIC_KEY_PREFIX = "ed25519:"

_CTX_PAIR_KEY = b"agent-auth/v1/pair-key"
_CTX_PAIR = b"agent-auth/v1/pair"
_CTX_HELLO = b"agent-auth/v1/hello"
_CTX_MSG = b"agent-auth/v1/msg"

# Envelope lifetimes are capped so the replay cache (ids remembered until they
# expire) stays bounded no matter what a peer claims.
MAX_ENVELOPE_TTL_SECS = 3600
DEFAULT_ENVELOPE_TTL_SECS = 60
MAX_CLOCK_SKEW_SECS = 30

# Crockford-style alphabet without I, L, O, U, 0, 1: easy to read aloud and type.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
_CODE_GROUPS, _CODE_GROUP_LEN = 3, 4  # 12 symbols ≈ 59 bits


class EnvelopeError(Exception):
    """A message failed verification. Never act on its contents."""


# --- encoding ---------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _transcript(*parts: bytes | str) -> bytes:
    out = bytearray()
    for part in parts:
        raw = part.encode() if isinstance(part, str) else part
        out += len(raw).to_bytes(4, "big") + raw
    return bytes(out)


# --- keys -------------------------------------------------------------------


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_text(key: Ed25519PrivateKey) -> str:
    """The raw 32-byte seed, base64url — the BROKER_SIGNING_KEY format."""
    return _b64(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )


def private_key_from_text(text: str) -> Ed25519PrivateKey:
    try:
        seed = _unb64(text.strip())
    except ValueError as exc:
        raise ValueError("signing key is not base64") from exc
    if len(seed) != 32:
        raise ValueError("signing key must be a 32-byte ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_text(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return PUBLIC_KEY_PREFIX + _b64(raw)


def parse_public_key(text: str) -> Ed25519PublicKey:
    if not isinstance(text, str) or not text.startswith(PUBLIC_KEY_PREFIX):
        raise ValueError(f"public key must start with {PUBLIC_KEY_PREFIX!r}")
    try:
        raw = _unb64(text[len(PUBLIC_KEY_PREFIX) :])
    except ValueError as exc:
        raise ValueError("public key is not base64") from exc
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def fingerprint(public_key: str) -> str:
    """Short human-comparable form, shown on both sides at pairing."""
    digest = hashlib.sha256(parse_public_key(public_key).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )).hexdigest()[:32]
    return ":".join(digest[i : i + 4] for i in range(0, 32, 4))


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """The daemon's identity key: created 0400 on first start, then reused.

    O_EXCL makes creation race-free; a key file anyone else can read is
    refused rather than silently used.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"{path} is accessible by other users (mode {mode:o}); fix it to 0400"
            )
        return private_key_from_text(path.read_text())
    key = generate_private_key()
    with os.fdopen(fd, "w") as f:
        f.write(private_key_to_text(key) + "\n")
    return key


# --- pairing ----------------------------------------------------------------


def generate_pairing_code() -> str:
    symbols = [secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_GROUPS * _CODE_GROUP_LEN)]
    return "-".join(
        "".join(symbols[i : i + _CODE_GROUP_LEN])
        for i in range(0, len(symbols), _CODE_GROUP_LEN)
    )


def normalize_pairing_code(code: str) -> str:
    return "".join(c for c in code.upper() if c.isalnum())


def pairing_key(code: str) -> bytes:
    """The HMAC key both sides derive from the code."""
    return hashlib.sha256(_CTX_PAIR_KEY + normalize_pairing_code(code).encode()).digest()


def daemon_pair_proof(key: bytes, role: str, name: str, daemon_public_key: str) -> str:
    return hmac.new(
        key, _transcript(_CTX_PAIR, "daemon", role, name, daemon_public_key), hashlib.sha256
    ).hexdigest()


def broker_pair_proof(
    key: bytes, role: str, name: str, daemon_public_key: str, broker_public_key: str
) -> str:
    return hmac.new(
        key,
        _transcript(_CTX_PAIR, BROKER, role, name, daemon_public_key, broker_public_key),
        hashlib.sha256,
    ).hexdigest()


def proofs_equal(a: str, b: str) -> bool:
    return isinstance(a, str) and isinstance(b, str) and hmac.compare_digest(a, b)


# --- hello ------------------------------------------------------------------


def new_nonce() -> str:
    return _b64(secrets.token_bytes(32))


def hello_transcript(
    speaker: str, role: str, name: str, broker_nonce: str, daemon_nonce: str
) -> bytes:
    """`speaker` is "daemon" or "broker": each side's signature covers who is
    speaking, so the broker's welcome can't be reflected as a daemon hello."""
    return _transcript(_CTX_HELLO, speaker, role, name, broker_nonce, daemon_nonce)


def sign_hello(key: Ed25519PrivateKey, *args: str) -> str:
    return _b64(key.sign(hello_transcript(*args)))


def verify_hello(public_key: str, signature: str, *args: str) -> bool:
    try:
        parse_public_key(public_key).verify(_unb64(signature), hello_transcript(*args))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- envelopes --------------------------------------------------------------


def daemon_principal(role: str, name: str) -> str:
    return f"{role}:{name}"


def seal(
    key: Ed25519PrivateKey,
    payload: dict[str, Any],
    *,
    sender: str,
    audience: str,
    ttl: float = DEFAULT_ENVELOPE_TTL_SECS,
    now: float | None = None,
) -> str:
    now = time.time() if now is None else now
    body = dict(payload)
    body.update(id=uuid.uuid4().hex, iss=sender, aud=audience, iat=now, exp=now + ttl)
    p = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return json.dumps({"p": _b64(p), "s": _b64(key.sign(_transcript(_CTX_MSG, p)))})


class EnvelopeVerifier:
    """Verifies one peer's envelopes on one connection, remembering ids until
    they expire so a captured message can't be replayed."""

    def __init__(self, peer_public_key: str, *, expected_sender: str, expected_audience: str):
        self._peer = parse_public_key(peer_public_key)
        self._sender = expected_sender
        self._audience = expected_audience
        self._seen: dict[str, float] = {}

    def open(self, raw: str | bytes, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        try:
            outer = json.loads(raw)
            p, s = _unb64(outer["p"]), _unb64(outer["s"])
        except (ValueError, KeyError, TypeError) as exc:
            raise EnvelopeError("malformed envelope") from exc
        try:
            self._peer.verify(s, _transcript(_CTX_MSG, p))
        except InvalidSignature as exc:
            raise EnvelopeError("bad signature") from exc
        try:
            body = json.loads(p)
            msg_id, iss, aud = body["id"], body["iss"], body["aud"]
            iat, exp = float(body["iat"]), float(body["exp"])
        except (ValueError, KeyError, TypeError) as exc:
            raise EnvelopeError("malformed envelope body") from exc
        if iss != self._sender or aud != self._audience:
            raise EnvelopeError(f"envelope from {iss!r} to {aud!r} is not for this channel")
        if iat > now + MAX_CLOCK_SKEW_SECS:
            raise EnvelopeError("envelope issued in the future")
        if exp < now:
            raise EnvelopeError("envelope expired")
        if exp - iat > MAX_ENVELOPE_TTL_SECS:
            raise EnvelopeError("envelope lifetime too long")
        if not isinstance(msg_id, str) or msg_id in self._seen:
            raise EnvelopeError("replayed envelope")
        self._seen = {k: v for k, v in self._seen.items() if v >= now}
        self._seen[msg_id] = exp
        return body
