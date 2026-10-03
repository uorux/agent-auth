"""Paired daemons: pairing, the per-connection handshake, heartbeats, and the
map of live connections that later phases send jobs and controls through.

Daemons dial out (no inbound ports on hosts) and hold one WebSocket each:

    broker → {"type": "challenge", "nonce": bn}
    daemon → {"type": "hello", "role", "name", "nonce": dn, "sig", "version"}
    broker → {"type": "welcome", "sig", "heartbeat_secs"}
    …then signed envelopes both ways (agent_auth.daemon_common.crypto).

The hello is verified against the public key bound at pairing; the welcome is
verified by the daemon against the broker key pinned in its own config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
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
    EnvelopeVerifier,
    broker_pair_proof,
    daemon_pair_proof,
    daemon_principal,
    fingerprint,
    generate_pairing_code,
    new_nonce,
    pairing_key,
    parse_public_key,
    private_key_from_text,
    proofs_equal,
    public_key_text,
    seal,
    sign_hello,
    verify_hello,
)
from ..db import Database
from ..models import Daemon, DaemonPairingCode, utcnow

log = logging.getLogger(__name__)

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
HELLO_TIMEOUT_SECS = 10
# Heartbeat status is informational and daemon-supplied; cap what we store.
MAX_STATUS_BYTES = 16 * 1024

# WebSocket close codes (4000-4999 are application-defined).
CLOSE_BAD_HELLO = 4400
CLOSE_UNAUTHORIZED = 4401
CLOSE_REPLACED = 4409
CLOSE_DISABLED = 4503


class DaemonsDisabled(Exception):
    """BROKER_SIGNING_KEY is not configured."""


class PairingError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def validate_identity(role: str, name: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if not NAME_RE.match(name or ""):
        raise ValueError("name must be a lowercase hostname label ([a-z0-9-], ≤63)")


@dataclass
class LiveConnection:
    ws: WebSocket
    daemon_id: str
    role: str
    name: str
    public_key: str  # the key the hello was verified against
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


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

    async def pair(self, role: str, name: str, public_key: str, proof: str) -> dict[str, str]:
        if not self.enabled:
            raise DaemonsDisabled("BROKER_SIGNING_KEY not configured")
        try:
            validate_identity(role, name)
            parse_public_key(public_key)
        except ValueError as exc:
            raise PairingError(400, str(exc)) from None
        principal = daemon_principal(role, name)
        now = utcnow()
        rejected = False
        async with self.db.session() as session:
            code = (
                await session.execute(
                    select(DaemonPairingCode)
                    .where(
                        DaemonPairingCode.role == role,
                        DaemonPairingCode.name == name,
                        DaemonPairingCode.used_at.is_(None),
                        DaemonPairingCode.expires_at > now,
                    )
                    .order_by(DaemonPairingCode.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if code is None:
                raise PairingError(
                    403, f"no pending pairing code for {principal} (expired, used, or never issued)"
                )
            key = bytes.fromhex(code.pairing_key)
            if not proofs_equal(daemon_pair_proof(key, role, name, public_key), proof):
                # Committed below (not raised here, which would roll it back).
                code.failed_attempts += 1
                if code.failed_attempts >= self.settings.daemon_pairing_max_attempts:
                    code.used_at = now
                rejected = True
            else:
                code.used_at = now
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
        if rejected:
            log.warning("pairing proof for %s did not verify", principal)
            raise PairingError(403, "pairing proof did not verify (wrong code?)")
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
        await self._kick(role, name, "unpaired")
        log.info("unpaired %s", daemon_principal(role, name))
        return True

    # --- connections ---------------------------------------------------------

    async def serve(self, ws: WebSocket) -> None:
        await ws.accept()
        if self._key is None:
            await ws.close(code=CLOSE_DISABLED, reason="daemon channel disabled")
            return
        live = await self._handshake(ws)
        if live is None:
            return
        key = (live.role, live.name)
        replaced = self._live.get(key)
        self._live[key] = live
        if replaced is not None:
            await self._close(replaced, CLOSE_REPLACED, "replaced by a newer connection")
        log.info("daemon %s connected", daemon_principal(live.role, live.name))
        verifier = EnvelopeVerifier(
            live.public_key,
            expected_sender=daemon_principal(live.role, live.name),
            expected_audience=BROKER,
        )
        try:
            while True:
                raw = await ws.receive_text()
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
                    await ws.close(code=CLOSE_BAD_HELLO, reason="bad envelope")
                    return
                await self._dispatch(live, message)
        except WebSocketDisconnect:
            pass
        finally:
            if self._live.get(key) is live:
                del self._live[key]
                log.info("daemon %s disconnected", daemon_principal(live.role, live.name))

    async def _handshake(self, ws: WebSocket) -> LiveConnection | None:
        broker_nonce = new_nonce()
        await ws.send_json({"type": "challenge", "nonce": broker_nonce})
        try:
            hello = await asyncio.wait_for(ws.receive_json(), HELLO_TIMEOUT_SECS)
            role, name = hello["role"], hello["name"]
            daemon_nonce, signature = hello["nonce"], hello["sig"]
            if hello.get("type") != "hello" or not all(
                isinstance(v, str) for v in (role, name, daemon_nonce, signature)
            ):
                raise ValueError("malformed hello")
            validate_identity(role, name)
        except (TimeoutError, ValueError, KeyError, TypeError, WebSocketDisconnect):
            await self._close_quietly(ws, CLOSE_BAD_HELLO, "bad hello")
            return None
        async with self.db.session() as session:
            daemon = (
                await session.execute(select(Daemon).where(Daemon.role == role, Daemon.name == name))
            ).scalar_one_or_none()
            if daemon is not None and verify_hello(
                daemon.public_key, signature, "daemon", role, name, broker_nonce, daemon_nonce
            ):
                daemon.last_seen_at = utcnow()
                version = hello.get("version")
                if isinstance(version, str):
                    daemon.version = version[:64]
                daemon_id, public_key = daemon.id, daemon.public_key
            else:
                daemon_id = public_key = None
        if daemon_id is None:
            log.warning("rejected hello from %s: not paired or bad signature", daemon_principal(role, name))
            await self._close_quietly(ws, CLOSE_UNAUTHORIZED, "not paired or bad signature")
            return None
        await ws.send_json(
            {
                "type": "welcome",
                "sig": sign_hello(self._key, BROKER, role, name, broker_nonce, daemon_nonce),
                "heartbeat_secs": self.settings.daemon_heartbeat_secs,
            }
        )
        return LiveConnection(
            ws=ws, daemon_id=daemon_id, role=role, name=name, public_key=public_key
        )

    async def _dispatch(self, live: LiveConnection, message: dict[str, Any]) -> None:
        kind = message.get("type")
        if kind == "heartbeat":
            status = message.get("status")
            if not isinstance(status, dict) or len(json.dumps(status)) > MAX_STATUS_BYTES:
                status = {"error": "status missing or too large"}
            async with self.db.session() as session:
                daemon = await session.get(Daemon, live.daemon_id)
                if daemon is not None:
                    daemon.last_seen_at = utcnow()
                    daemon.last_status = status
                    version = status.get("version")
                    if isinstance(version, str):
                        daemon.version = version[:64]
        else:
            log.debug("ignoring %r from %s", kind, daemon_principal(live.role, live.name))

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
        envelope = seal(
            self._key, payload, sender=BROKER, audience=daemon_principal(role, name), ttl=ttl
        )
        try:
            async with live.send_lock:
                await live.ws.send_text(envelope)
        except Exception:
            log.warning("send to %s failed", daemon_principal(role, name), exc_info=True)
            return False
        return True

    async def _kick(self, role: str, name: str, reason: str) -> None:
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
