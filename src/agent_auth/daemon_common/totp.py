"""TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 s) and a host's set of secrets.

A host keeps four secrets, generated on the host and never sent anywhere
(docs/sandbox-design.md §8.3):

    user-arm, root-arm        open an arming window for a tier
    user-direct, root-direct  approve one request, armed or not

Codes are single use: the step a code was accepted for is persisted, and that
step or any earlier one is refused from then on. Wrong codes are counted, and
a secret that collects too many is locked for a while, so whoever relays
codes to the host (Discord, the broker) can't search the code space.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote

SECRET_NAMES = ("user-arm", "user-direct", "root-arm", "root-direct")
STEP_SECS = 30
DIGITS = 6
# A code for the step before or after the current one is accepted (clock skew,
# and the time it takes to type it into Discord).
WINDOW_STEPS = 1
MAX_FAILURES = 5
LOCKOUT_SECS = 300


class TotpError(Exception):
    pass


def generate_secret() -> str:
    """160 random bits, base32 (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def otpauth_uri(secret: str, host: str, name: str) -> str:
    label = quote(f"agent-auth:{host} {name}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=agent-auth&digits={DIGITS}&period={STEP_SECS}"


class TotpStore:
    """The secrets of one host, in a root-only directory."""

    def __init__(self, directory: Path):
        self.directory = directory

    def _secret_path(self, name: str) -> Path:
        if name not in SECRET_NAMES:
            raise TotpError(f"unknown TOTP secret {name!r}")
        return self.directory / name

    def _state_path(self, name: str) -> Path:
        return self.directory / f"{name}.state"

    def enrolled(self, name: str) -> bool:
        return self._secret_path(name).exists()

    def enroll(self, name: str, *, replace: bool = False) -> str:
        """Create one secret and return it (shown once, by the caller)."""
        path = self._secret_path(name)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists():
            if not replace:
                raise TotpError(f"{name} is already enrolled (rotate it to replace it)")
            path.unlink()
        secret = generate_secret()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "w") as f:
            f.write(secret + "\n")
        self._state_path(name).unlink(missing_ok=True)
        return secret

    def _read_state(self, name: str) -> dict:
        try:
            state = json.loads(self._state_path(name).read_text())
            return state if isinstance(state, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_state(self, name: str, state: dict) -> None:
        path = self._state_path(name)
        tmp = path.with_name(f".{path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(state))
        tmp.replace(path)

    def verify(self, name: str, code: str, now: float | None = None) -> None:
        """Accept `code` for secret `name` once, or raise TotpError saying why not."""
        now = time.time() if now is None else now
        path = self._secret_path(name)
        try:
            secret = path.read_text().strip()
        except OSError:
            raise TotpError(f"no {name} secret on this host (run totp-enroll)") from None
        state = self._read_state(name)
        if state.get("locked_until", 0) > now:
            raise TotpError(f"too many wrong codes; {name} is locked for {int(state['locked_until'] - now)}s")
        code = "".join(ch for ch in str(code) if ch.isdigit())
        current = int(now // STEP_SECS)
        matched = None
        for step in range(current - WINDOW_STEPS, current + WINDOW_STEPS + 1):
            if len(code) == DIGITS and hmac.compare_digest(code_at(secret, step), code):
                matched = step
        if matched is None:
            failures = state.get("failures", 0) + 1
            state["failures"] = failures
            if failures >= MAX_FAILURES:
                state["failures"] = 0
                state["locked_until"] = now + LOCKOUT_SECS
            self._write_state(name, state)
            raise TotpError("wrong code")
        if matched <= state.get("last_step", -1):
            raise TotpError("that code was already used; wait for the next one")
        # Persisted before the caller acts on it: a crash can't make a code reusable.
        self._write_state(name, {"last_step": matched, "failures": 0})
