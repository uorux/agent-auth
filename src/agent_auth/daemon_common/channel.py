"""The daemon side of the broker channel, shared by hostd and sandboxd:
pairing, and a self-reconnecting signed WebSocket that sends heartbeats and
hands verified broker messages to a callback.

Trust runs one way: the broker's public key comes from the daemon's own
config (`brokerPublicKey`, set by an audited nix commit), never from the
network. Pairing and every connection check the broker against it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx
import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import (
    BROKER,
    DEFAULT_ENVELOPE_TTL_SECS,
    EnvelopeError,
    EnvelopeSealer,
    EnvelopeVerifier,
    broker_pair_proof,
    daemon_pair_proof,
    daemon_principal,
    new_nonce,
    pairing_key,
    pairing_selector,
    proofs_equal,
    public_key_text,
    session_id,
    sign_hello,
    verify_hello,
)

log = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT_SECS = 15
MAX_BACKOFF_SECS = 60
# Not paired / key replaced: retrying quickly can't help until an admin acts.
REJECTED_BACKOFF_SECS = 300
CLOSE_UNAUTHORIZED = 4401


class PairingFailed(Exception):
    pass


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def check_broker_url(url: str) -> None:
    """Envelopes are signed, not encrypted: confidentiality is TLS's job, so
    plain http is only accepted for a broker on this machine."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    raise ValueError(f"broker URL must be https:// (plain http only for localhost): {url!r}")


class HandshakeRejected(Exception):
    """The broker refused us, or failed to prove it holds the pinned key."""


@dataclass
class DaemonIdentity:
    role: str
    name: str
    key: Ed25519PrivateKey
    broker_url: str
    broker_public_key: str  # pinned from local config

    def __post_init__(self) -> None:
        check_broker_url(self.broker_url)

    @property
    def principal(self) -> str:
        return daemon_principal(self.role, self.name)

    @property
    def public_key(self) -> str:
        return public_key_text(self.key)


def pair(
    identity: DaemonIdentity,
    code: str,
    *,
    timeout: float = 30,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Bind this daemon's key to its (role, name) using a one-time code."""
    key = pairing_key(code)
    body = {
        "role": identity.role,
        "name": identity.name,
        "public_key": identity.public_key,
        "selector": pairing_selector(key),
        "proof": daemon_pair_proof(key, identity.role, identity.name, identity.public_key),
    }
    with httpx.Client(timeout=timeout, transport=transport) as client:
        resp = client.post(f"{identity.broker_url.rstrip('/')}/v1/daemons/pair", json=body)
    try:
        data = resp.json()
    except ValueError:
        data = None
    if resp.status_code != 200:
        detail = data.get("detail") if isinstance(data, dict) else None
        raise PairingFailed(f"broker refused pairing [{resp.status_code}]: {detail or resp.text[:200]!s}")
    if not isinstance(data, dict):
        raise PairingFailed("the broker's pairing response is not a JSON object")
    if data.get("broker_public_key") != identity.broker_public_key:
        raise PairingFailed(
            "the broker's key does not match the pinned brokerPublicKey — wrong broker, "
            "or the pin is stale. Not trusting it."
        )
    expected = broker_pair_proof(
        key, identity.role, identity.name, identity.public_key, identity.broker_public_key
    )
    if not proofs_equal(expected, data.get("proof", "")):
        raise PairingFailed("the broker's pairing proof did not verify")
    return data


def ws_url(broker_url: str) -> str:
    url = broker_url.rstrip("/")
    if url.startswith("https://"):
        url = "wss://" + url[len("https://") :]
    elif url.startswith("http://"):
        url = "ws://" + url[len("http://") :]
    return url + "/v1/daemons/connect"


MessageHandler = Callable[[dict[str, Any]], Awaitable[None]]


class DaemonChannel:
    """Holds the connection to the broker until cancelled, reconnecting with
    backoff. `status()` is sampled for every heartbeat."""

    def __init__(
        self,
        identity: DaemonIdentity,
        *,
        version: str,
        status: Callable[[], dict[str, Any]],
        on_message: MessageHandler | None = None,
    ):
        self.identity = identity
        self.version = version
        self._status = status
        self._on_message = on_message
        self._ws = None
        self._sealer: EnvelopeSealer | None = None
        self._send_lock = asyncio.Lock()
        self.connected = asyncio.Event()

    async def run(self) -> None:
        backoff = 1.0
        while True:
            delay = backoff
            try:
                async with websockets.connect(
                    ws_url(self.identity.broker_url),
                    open_timeout=HANDSHAKE_TIMEOUT_SECS,
                    ping_interval=20,
                    ping_timeout=20,
                ) as ws:
                    heartbeat_secs, sid = await self._handshake(ws)
                    log.info("connected to broker as %s", self.identity.principal)
                    backoff = 1.0
                    await self._session(ws, heartbeat_secs, sid)
                    delay = 1.0
            except HandshakeRejected as exc:
                log.error("broker handshake failed: %s", exc)
                delay = REJECTED_BACKOFF_SECS
            except (OSError, TimeoutError, websockets.WebSocketException) as exc:
                log.warning("broker connection lost: %s", exc)
                backoff = min(backoff * 2, MAX_BACKOFF_SECS)
            except Exception:
                # Whatever the broker (or someone posing as it) sends must not
                # end the daemon: log it and keep retrying.
                log.exception("unexpected error on the broker connection")
                backoff = min(backoff * 2, MAX_BACKOFF_SECS)
            finally:
                self._ws = None
                self._sealer = None
                self.connected.clear()
            await asyncio.sleep(delay * random.uniform(0.8, 1.2))

    async def _handshake(self, ws) -> tuple[int, bytes]:
        """Returns the heartbeat interval and the session id."""
        ident = self.identity
        try:
            challenge = json.loads(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT_SECS))
            if not isinstance(challenge, dict) or challenge.get("type") != "challenge":
                raise ValueError("unexpected first message")
            broker_nonce = challenge["nonce"]
            if not isinstance(broker_nonce, str):
                raise ValueError("unexpected first message")
            daemon_nonce = new_nonce()
            params = json.dumps({"version": self.version})
            await ws.send(
                json.dumps(
                    {
                        "type": "hello",
                        "role": ident.role,
                        "name": ident.name,
                        "nonce": daemon_nonce,
                        "params": params,
                        "sig": sign_hello(
                            ident.key,
                            "daemon",
                            ident.role,
                            ident.name,
                            broker_nonce,
                            daemon_nonce,
                            params,
                        ),
                    }
                )
            )
            welcome = json.loads(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT_SECS))
            if not isinstance(welcome, dict):
                raise ValueError("welcome is not an object")
        except websockets.ConnectionClosed as exc:
            if exc.rcvd is not None and exc.rcvd.code == CLOSE_UNAUTHORIZED:
                raise HandshakeRejected(
                    f"broker does not recognize {ident.principal} (not paired, or re-paired "
                    "with another key) — run `pair` with a new code"
                ) from None
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise HandshakeRejected(f"malformed handshake: {exc}") from None
        broker_params = welcome.get("params")
        if (
            welcome.get("type") != "welcome"
            or not isinstance(broker_params, str)
            or not verify_hello(
                ident.broker_public_key,
                welcome.get("sig", ""),
                BROKER,
                ident.role,
                ident.name,
                broker_nonce,
                daemon_nonce,
                broker_params,
            )
        ):
            raise HandshakeRejected("broker did not prove possession of the pinned key")
        sid = session_id(ident.role, ident.name, broker_nonce, daemon_nonce)
        try:
            heartbeat = json.loads(broker_params).get("heartbeat_secs", 30)
            return min(max(int(heartbeat), 5), 300), sid
        except (AttributeError, TypeError, ValueError, OverflowError):
            return 30, sid

    async def _session(self, ws, heartbeat_secs: int, sid: bytes) -> None:
        verifier = EnvelopeVerifier(
            self.identity.broker_public_key,
            expected_sender=BROKER,
            expected_audience=self.identity.principal,
            session=sid,
        )
        self._sealer = EnvelopeSealer(
            self.identity.key, sender=self.identity.principal, audience=BROKER, session=sid
        )
        self._ws = ws
        self.connected.set()
        heartbeats = asyncio.create_task(self._heartbeats(heartbeat_secs))
        try:
            async for raw in ws:
                try:
                    message = verifier.open(raw)
                except EnvelopeError as exc:
                    log.error("refusing broker message (%s); reconnecting", exc)
                    return
                if self._on_message is not None:
                    try:
                        await self._on_message(message)
                    except Exception:
                        log.exception("handler failed for %r", message.get("type"))
        finally:
            heartbeats.cancel()

    async def _heartbeats(self, interval: int) -> None:
        while True:
            try:
                status = dict(self._status())
            except Exception:
                log.exception("status() failed")
                status = {"error": "status unavailable"}
            status.setdefault("version", self.version)
            await self.send({"type": "heartbeat", "status": status})
            await asyncio.sleep(interval)

    async def send(self, payload: dict[str, Any], ttl: float = DEFAULT_ENVELOPE_TTL_SECS) -> bool:
        ws, sealer = self._ws, self._sealer
        if ws is None or sealer is None:
            return False
        try:
            async with self._send_lock:
                await ws.send(sealer.seal(payload, ttl))
        except websockets.ConnectionClosed:
            return False
        return True
