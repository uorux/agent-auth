"""Paired daemons: pairing, the per-connection handshake, heartbeats, and the
map of live connections that later phases send jobs and controls through.

Daemons dial out (no inbound ports on hosts) and hold one WebSocket each:

    broker → {"type": "challenge", "nonce": bn}
    daemon → {"type": "hello", "role", "name", "nonce": dn, "params", "sig"}
    broker → {"type": "welcome", "params", "sig"}
    …then signed envelopes both ways (agent_auth.daemon_common.crypto),
    bound to this connection's session id.

The hello is verified against the public key bound at pairing; the welcome is
verified by the daemon against the broker key pinned in its own config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from starlette.websockets import WebSocket, WebSocketDisconnect

from ..config import Settings
from ..daemon_common.crypto import (
    BROKER,
    DEFAULT_ENVELOPE_TTL_SECS,
    ROLES,
    EnvelopeError,
    EnvelopeSealer,
    EnvelopeVerifier,
    broker_pair_proof,
    daemon_pair_proof,
    daemon_principal,
    fingerprint,
    generate_pairing_code,
    new_nonce,
    pairing_key,
    pairing_selector,
    parse_public_key,
    private_key_from_text,
    proofs_equal,
    public_key_text,
    session_id,
    sign_hello,
    verify_hello,
)
from ..db import Database
from ..models import Daemon, DaemonPairingCode, utcnow

log = logging.getLogger(__name__)

NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# Daemon-supplied and shown in Discord: a plain version string or nothing.
VERSION_RE = re.compile(r"[0-9A-Za-z.+_-]{1,64}")
HELLO_TIMEOUT_SECS = 10
# Connections that haven't authenticated yet are anyone's; cap how many may
# be pending at once.
MAX_PENDING_HANDSHAKES = 32
# A connection that sends nothing valid for this many heartbeat intervals is
# dropped, so "online" means the daemon is actually talking to us.
MISSED_HEARTBEATS = 3
# Heartbeat status is informational and daemon-supplied; cap what we store.
MAX_STATUS_BYTES = 16 * 1024
# One pairing refusal for every case, so the endpoint doesn't reveal which
# daemons have a code pending.
PAIRING_REFUSED = "pairing refused: no pending code for this daemon matches (expired, used, or wrong code)"

# WebSocket close codes (4000-4999 are application-defined).
CLOSE_BAD_HELLO = 4400
CLOSE_UNAUTHORIZED = 4401
CLOSE_REPLACED = 4409
CLOSE_DISABLED = 4503
CLOSE_TRY_AGAIN = 1013


class DaemonsDisabled(Exception):
    """BROKER_SIGNING_KEY is not configured."""


class PairingError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _version(value: Any) -> str | None:
    return value if isinstance(value, str) and VERSION_RE.fullmatch(value) else None


def validate_identity(role: str, name: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("name must be a lowercase hostname label ([a-z0-9-], ≤63)")


@dataclass
class LiveConnection:
    ws: WebSocket
    daemon_id: str
    role: str
    name: str
    public_key: str  # the key the hello was verified against
    sealer: EnvelopeSealer
    session: bytes
    # The identity's generation when the hello was checked against the DB:
    # if a re-pair or unpair happened since, the connection is refused.
    generation: int
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_status_write: float = 0.0


class DaemonHub:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings
        self._key = (
            private_key_from_text(settings.broker_signing_key)
            if settings.broker_signing_key
            else None
        )
        self._live: dict[tuple[str, str], LiveConnection] = {}
        # Bumped whenever an identity's key changes or goes away (re-pair,
        # unpair). A handshake verified against the old key may still be in
        # flight when that happens; serve() compares generations before it
        # registers the connection.
        self._generation: dict[tuple[str, str], int] = {}
        self._pending_handshakes = asyncio.Semaphore(MAX_PENDING_HANDSHAKES)

    # --- state ---------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._key is not None

    @property
    def public_key(self) -> str:
        if self._key is None:
            raise DaemonsDisabled("BROKER_SIGNING_KEY not configured")
        return public_key_text(self._key)

    def is_online(self, role: str, name: str) -> bool:
        return (role, name) in self._live

    async def list_daemons(self) -> list[dict[str, Any]]:
        async with self.db.session() as session:
            rows = (
                await session.execute(select(Daemon).order_by(Daemon.role, Daemon.name))
            ).scalars().all()
        return [self.describe(row) for row in rows]

    def describe(self, row: Daemon) -> dict[str, Any]:
        return {
            "id": row.id,
            "role": row.role,
            "name": row.name,
            "fingerprint": fingerprint(row.public_key),
            "online": self.is_online(row.role, row.name),
            "paired_at": row.paired_at,
            "last_seen_at": row.last_seen_at,
            "version": row.version,
            "status": row.last_status,
        }

    # --- pairing -------------------------------------------------------------

    async def create_pairing_code(self, role: str, name: str) -> tuple[str, Any]:
        if not self.enabled:
            raise DaemonsDisabled("BROKER_SIGNING_KEY not configured")
        validate_identity(role, name)
        code = generate_pairing_code()
        now = utcnow()
        expires_at = now + timedelta(seconds=self.settings.daemon_pairing_code_ttl_secs)
        async with self.db.session() as session:
            # Only the newest code for a daemon is live.
            await session.execute(
                update(DaemonPairingCode)
                .where(
                    DaemonPairingCode.role == role,
                    DaemonPairingCode.name == name,
                    DaemonPairingCode.used_at.is_(None),
                )
                .values(used_at=now)
            )
            session.add(
                DaemonPairingCode(
                    role=role,
                    name=name,
                    pairing_key=pairing_key(code).hex(),
                    expires_at=expires_at,
                )
            )
        return code, expires_at

    async def pair(
        self, role: str, name: str, public_key: str, selector: str, proof: str
    ) -> dict[str, str]:
        if not self.enabled:
            raise DaemonsDisabled("BROKER_SIGNING_KEY not configured")
        try:
            validate_identity(role, name)
            parse_public_key(public_key)
        except ValueError as exc:
            raise PairingError(400, str(exc)) from None
        principal = daemon_principal(role, name)
        now = utcnow()
        refused = False
        async with self.db.session() as session:
            code = (
                await session.execute(
                    select(DaemonPairingCode)
                    .where(
                        DaemonPairingCode.role == role,
                        DaemonPairingCode.name == name,
                        DaemonPairingCode.used_at.is_(None),
                        DaemonPairingCode.expires_at > now,
                        DaemonPairingCode.failed_attempts
                        < self.settings.daemon_pairing_max_attempts,
                    )
                    .order_by(DaemonPairingCode.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            key = bytes.fromhex(code.pairing_key) if code is not None else b""
            # Without the code there's no matching selector, so attempts that
            # don't have it can't spend this code's attempts and burn it.
            if code is None or not proofs_equal(pairing_selector(key), selector):
                raise PairingError(403, PAIRING_REFUSED)
            # Spend an attempt atomically before checking the proof, so
            # concurrent guesses can't evaluate more than the cap allows.
            spent = await session.execute(
                update(DaemonPairingCode)
                .where(
                    DaemonPairingCode.id == code.id,
                    DaemonPairingCode.used_at.is_(None),
                    DaemonPairingCode.failed_attempts
                    < self.settings.daemon_pairing_max_attempts,
                )
                .values(failed_attempts=DaemonPairingCode.failed_attempts + 1)
            )
            if spent.rowcount != 1:
                raise PairingError(403, PAIRING_REFUSED)
            if not proofs_equal(daemon_pair_proof(key, role, name, public_key), proof):
                refused = True  # committed below; raising here would roll back the attempt
            else:
                claimed = await session.execute(
                    update(DaemonPairingCode)
                    .where(DaemonPairingCode.id == code.id, DaemonPairingCode.used_at.is_(None))
                    .values(used_at=now)
                )
                if claimed.rowcount != 1:
                    raise PairingError(403, PAIRING_REFUSED)
                daemon = (
                    await session.execute(
                        select(Daemon).where(Daemon.role == role, Daemon.name == name)
                    )
                ).scalar_one_or_none()
                if daemon is None:
                    session.add(Daemon(role=role, name=name, public_key=public_key, paired_at=now))
                else:
                    daemon.public_key = public_key
                    daemon.paired_at = now
                    daemon.last_status = None
        if refused:
            log.warning("pairing proof for %s did not verify", principal)
            raise PairingError(403, PAIRING_REFUSED)
        # A connection authenticated with the old key must not outlive it.
        await self._kick(role, name, "re-paired")
        log.info("paired %s (%s)", principal, fingerprint(public_key))
        broker_key = self.public_key
        return {
            "broker_public_key": broker_key,
            "proof": broker_pair_proof(key, role, name, public_key, broker_key),
            "fingerprint": fingerprint(public_key),
        }

    async def unpair(self, daemon_id: str) -> bool:
        async with self.db.session() as session:
            daemon = await session.get(Daemon, daemon_id)
            if daemon is None:
                return False
            role, name = daemon.role, daemon.name
            await session.delete(daemon)
            # An unused code would let whoever holds it pair straight back.
            await session.execute(
                update(DaemonPairingCode)
                .where(
                    DaemonPairingCode.role == role,
                    DaemonPairingCode.name == name,
                    DaemonPairingCode.used_at.is_(None),
                )
                .values(used_at=utcnow())
            )
        await self._kick(role, name, "unpaired")
        log.info("unpaired %s", daemon_principal(role, name))
        return True

    # --- connections ---------------------------------------------------------

    async def serve(self, ws: WebSocket) -> None:
        await ws.accept()
        if self._key is None:
            await ws.close(code=CLOSE_DISABLED, reason="daemon channel disabled")
            return
        if self._pending_handshakes.locked():
            await self._close_quietly(ws, CLOSE_TRY_AGAIN, "too many pending handshakes")
            return
        async with self._pending_handshakes:
            live = await self._handshake(ws)
        if live is None:
            return
        key = (live.role, live.name)
        # No await between this check and registering: a re-pair or unpair
        # either happened before (refuse) or will find and kick this entry.
        if self._generation.get(key, 0) != live.generation:
            # Not 4401: a daemon re-paired a moment ago may land here with its
            # new key, and should simply reconnect.
            await self._close_quietly(ws, CLOSE_REPLACED, "re-paired or unpaired during handshake")
            return
        replaced = self._live.get(key)
        self._live[key] = live
        if replaced is not None:
            await self._close(replaced, CLOSE_REPLACED, "replaced by a newer connection")
        log.info("daemon %s connected", daemon_principal(live.role, live.name))
        verifier = EnvelopeVerifier(
            live.public_key,
            expected_sender=daemon_principal(live.role, live.name),
            expected_audience=BROKER,
            session=live.session,
        )
        idle_timeout = self.settings.daemon_heartbeat_secs * MISSED_HEARTBEATS
        try:
            while True:
                try:
                    raw = await asyncio.wait_for(ws.receive_text(), idle_timeout)
                except TimeoutError:
                    log.warning(
                        "daemon %s sent nothing for %ss; closing",
                        daemon_principal(live.role, live.name),
                        idle_timeout,
                    )
                    await self._close_quietly(ws, CLOSE_BAD_HELLO, "heartbeat timeout")
                    return
                try:
                    message = verifier.open(raw)
                except EnvelopeError as exc:
                    # An authenticated peer sending bad envelopes is a bug or
                    # an attack; either way, stop trusting this connection.
                    log.warning(
                        "daemon %s sent a bad envelope (%s); closing",
                        daemon_principal(live.role, live.name),
                        exc,
                    )
                    await self._close_quietly(ws, CLOSE_BAD_HELLO, "bad envelope")
                    return
                if not await self._dispatch(live, message):
                    return
        except WebSocketDisconnect:
            pass
        finally:
            if self._live.get(key) is live:
                del self._live[key]
                log.info("daemon %s disconnected", daemon_principal(live.role, live.name))

    async def _handshake(self, ws: WebSocket) -> LiveConnection | None:
        broker_nonce = new_nonce()
        try:
            await ws.send_json({"type": "challenge", "nonce": broker_nonce})
            hello = await asyncio.wait_for(ws.receive_json(), HELLO_TIMEOUT_SECS)
            if not isinstance(hello, dict) or hello.get("type") != "hello":
                raise ValueError("malformed hello")
            role, name = hello["role"], hello["name"]
            daemon_nonce, signature, params = hello["nonce"], hello["sig"], hello["params"]
            if not all(isinstance(v, str) for v in (role, name, daemon_nonce, signature, params)):
                raise ValueError("malformed hello")
            validate_identity(role, name)
        except (TimeoutError, ValueError, KeyError, TypeError, WebSocketDisconnect):
            await self._close_quietly(ws, CLOSE_BAD_HELLO, "bad hello")
            return None
        generation = self._generation.get((role, name), 0)
        async with self.db.session() as session:
            daemon = (
                await session.execute(select(Daemon).where(Daemon.role == role, Daemon.name == name))
            ).scalar_one_or_none()
            if daemon is not None and verify_hello(
                daemon.public_key, signature, "daemon", role, name, broker_nonce, daemon_nonce, params
            ):
                daemon.last_seen_at = utcnow()
                try:
                    version = _version(json.loads(params).get("version"))
                except (ValueError, AttributeError):
                    version = None
                if version is not None:
                    daemon.version = version
                daemon_id, public_key = daemon.id, daemon.public_key
            else:
                daemon_id = public_key = None
        if daemon_id is None:
            log.warning("rejected hello from %s: not paired or bad signature", daemon_principal(role, name))
            await self._close_quietly(ws, CLOSE_UNAUTHORIZED, "not paired or bad signature")
            return None
        welcome_params = json.dumps({"heartbeat_secs": self.settings.daemon_heartbeat_secs})
        try:
            await ws.send_json(
                {
                    "type": "welcome",
                    "params": welcome_params,
                    "sig": sign_hello(
                        self._key, BROKER, role, name, broker_nonce, daemon_nonce, welcome_params
                    ),
                }
            )
        except Exception:
            return None
        sid = session_id(role, name, broker_nonce, daemon_nonce)
        return LiveConnection(
            ws=ws,
            daemon_id=daemon_id,
            role=role,
            name=name,
            public_key=public_key,
            sealer=EnvelopeSealer(
                self._key, sender=BROKER, audience=daemon_principal(role, name), session=sid
            ),
            session=sid,
            generation=generation,
        )

    async def _dispatch(self, live: LiveConnection, message: dict[str, Any]) -> bool:
        """False = the connection was closed."""
        kind = message.get("type")
        if kind == "heartbeat":
            # Envelopes already prove the sender; this only throttles how
            # often a chatty (or hostile) daemon makes us write.
            now = time.monotonic()
            if now - live.last_status_write < self.settings.daemon_heartbeat_secs / 2:
                return True
            live.last_status_write = now
            status = message.get("status")
            if not isinstance(status, dict) or len(json.dumps(status)) > MAX_STATUS_BYTES:
                status = {"error": "status missing or too large"}
            async with self.db.session() as session:
                daemon = await session.get(Daemon, live.daemon_id)
                revoked = daemon is None or daemon.public_key != live.public_key
                if not revoked:
                    daemon.last_seen_at = utcnow()
                    daemon.last_status = status
                    version = _version(status.get("version"))
                    if version is not None:
                        daemon.version = version
            if revoked:
                # Backstop for a revocation the generation check missed.
                if self._live.get((live.role, live.name)) is live:
                    del self._live[(live.role, live.name)]
                await self._close(live, CLOSE_UNAUTHORIZED, "no longer paired with this key")
                return False
        else:
            log.debug("ignoring %r from %s", kind, daemon_principal(live.role, live.name))
        return True

    async def send(
        self,
        role: str,
        name: str,
        payload: dict[str, Any],
        ttl: float = DEFAULT_ENVELOPE_TTL_SECS,
    ) -> bool:
        """Sign and send one message to a connected daemon. False = offline."""
        live = self._live.get((role, name))
        if live is None or self._key is None:
            return False
        try:
            async with live.send_lock:
                await live.ws.send_text(live.sealer.seal(payload, ttl))
        except Exception:
            log.warning("send to %s failed", daemon_principal(role, name), exc_info=True)
            return False
        return True

    async def _kick(self, role: str, name: str, reason: str) -> None:
        self._generation[(role, name)] = self._generation.get((role, name), 0) + 1
        live = self._live.pop((role, name), None)
        if live is not None:
            await self._close(live, CLOSE_REPLACED, reason)

    async def _close(self, live: LiveConnection, code: int, reason: str) -> None:
        await self._close_quietly(live.ws, code, reason)

    @staticmethod
    async def _close_quietly(ws: WebSocket, code: int, reason: str) -> None:
        try:
            await ws.close(code=code, reason=reason)
        except Exception:
            pass
