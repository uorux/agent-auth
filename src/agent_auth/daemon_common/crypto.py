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
  is refused by host B. Each is signed over the connection's session id
  (both hello nonces) and carries a per-direction sequence number, so it
  can't be replayed into another connection, or reordered or repeated
  within its own; and it carries an expiry, so a stalled one goes stale.

Every signed or MACed byte string is a length-prefixed transcript with a
context label first, so no field boundary is ambiguous and no signature made
for one purpose verifies for another.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import stat
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
_CTX_PAIR_SELECTOR = b"agent-auth/v1/pair-selector"
_CTX_SESSION = b"agent-auth/v1/session"
_CTX_HELLO = b"agent-auth/v1/hello"
_CTX_MSG = b"agent-auth/v1/msg"

# Envelope lifetimes are capped so a delayed message can't be held back and
# delivered long after it was meant to act.
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

    The key is written to a temporary file and linked into place, so a crash
    mid-write never leaves a truncated key behind, and two racing first
    starts agree on one key. A key file that isn't ours, isn't a regular
    file, or that anyone else can read is refused rather than silently used.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        key = generate_private_key()
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(private_key_to_text(key) + "\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass  # another process won the race; use its key
            else:
                dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            tmp.unlink(missing_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"{path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise PermissionError(f"{path} is owned by uid {st.st_uid}, not this user")
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"{path} is accessible by other users (mode {mode:o}); fix it to 0400"
            )
        return private_key_from_text(f.read())


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


def pairing_selector(key: bytes) -> str:
    """Names which pending code a pairing attempt is for, without revealing
    it. Attempts whose selector doesn't match are refused before the proof
    is checked, so they can't spend (and burn) the code's attempts: only
    someone who has the code can."""
    return hmac.new(key, _CTX_PAIR_SELECTOR, hashlib.sha256).hexdigest()[:32]


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
    # Bytes, not str: compare_digest raises on non-ASCII str input.
    return (
        isinstance(a, str)
        and isinstance(b, str)
        and hmac.compare_digest(a.encode(), b.encode())
    )


# --- hello ------------------------------------------------------------------


def new_nonce() -> str:
    return _b64(secrets.token_bytes(32))


def hello_transcript(
    speaker: str, role: str, name: str, broker_nonce: str, daemon_nonce: str, params: str = ""
) -> bytes:
    """`speaker` is "daemon" or "broker": each side's signature covers who is
    speaking, so the broker's welcome can't be reflected as a daemon hello.
    `params` is the speaker's settings for the connection (a JSON string),
    signed so a relay can't alter them."""
    return _transcript(_CTX_HELLO, speaker, role, name, broker_nonce, daemon_nonce, params)


def session_id(role: str, name: str, broker_nonce: str, daemon_nonce: str) -> bytes:
    """Every envelope on a connection is signed over this, so none verifies
    on any other connection."""
    return hashlib.sha256(
        _transcript(_CTX_SESSION, role, name, broker_nonce, daemon_nonce)
    ).digest()


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
    session: bytes,
    seq: int,
    ttl: float = DEFAULT_ENVELOPE_TTL_SECS,
    now: float | None = None,
) -> str:
    now = time.time() if now is None else now
    body = dict(payload)
    body.update(id=uuid.uuid4().hex, iss=sender, aud=audience, seq=seq, iat=now, exp=now + ttl)
    p = json.dumps(body, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()
    return json.dumps({"p": _b64(p), "s": _b64(key.sign(_transcript(_CTX_MSG, session, p)))})


class EnvelopeSealer:
    """Seals one direction of one connection, numbering messages in order.
    Callers sending concurrently must seal and send under one lock, so the
    peer sees sequence numbers in the order they were assigned."""

    def __init__(self, key: Ed25519PrivateKey, *, sender: str, audience: str, session: bytes):
        self._key = key
        self._sender = sender
        self._audience = audience
        self._session = session
        self._seq = 0

    def seal(self, payload: dict[str, Any], ttl: float = DEFAULT_ENVELOPE_TTL_SECS) -> str:
        self._seq += 1
        return seal(
            self._key,
            payload,
            sender=self._sender,
            audience=self._audience,
            session=self._session,
            seq=self._seq,
            ttl=ttl,
        )


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} in envelope")


class EnvelopeVerifier:
    """Verifies one peer's envelopes on one connection. Sequence numbers must
    strictly increase, so a captured message can't be replayed or reordered."""

    def __init__(
        self,
        peer_public_key: str,
        *,
        expected_sender: str,
        expected_audience: str,
        session: bytes,
    ):
        self._peer = parse_public_key(peer_public_key)
        self._sender = expected_sender
        self._audience = expected_audience
        self._session = session
        self._last_seq = 0

    def open(self, raw: str | bytes, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        try:
            outer = json.loads(raw)
            p, s = _unb64(outer["p"]), _unb64(outer["s"])
        except (ValueError, KeyError, TypeError) as exc:
            raise EnvelopeError("malformed envelope") from exc
        try:
            self._peer.verify(s, _transcript(_CTX_MSG, self._session, p))
        except InvalidSignature as exc:
            raise EnvelopeError("bad signature") from exc
        try:
            body = json.loads(p, parse_constant=_reject_constant)
            msg_id, iss, aud, seq = body["id"], body["iss"], body["aud"], body["seq"]
            iat, exp = float(body["iat"]), float(body["exp"])
        except (ValueError, KeyError, TypeError) as exc:
            raise EnvelopeError("malformed envelope body") from exc
        if not (isinstance(msg_id, str) and type(seq) is int and math.isfinite(iat) and math.isfinite(exp)):
            raise EnvelopeError("malformed envelope body")
        if iss != self._sender or aud != self._audience:
            raise EnvelopeError(f"envelope from {iss!r} to {aud!r} is not for this channel")
        if seq <= self._last_seq:
            raise EnvelopeError("replayed or reordered envelope")
        if iat > now + MAX_CLOCK_SKEW_SECS:
            raise EnvelopeError("envelope issued in the future")
        if exp < now:
            raise EnvelopeError("envelope expired")
        if exp - iat > MAX_ENVELOPE_TTL_SECS:
            raise EnvelopeError("envelope lifetime too long")
        self._last_seq = seq
        return body
