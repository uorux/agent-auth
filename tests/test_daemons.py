"""Paired daemons: the signing contract, pairing, and the live channel."""

from __future__ import annotations

import asyncio
import json
import socket
import time

import httpx
import pytest
import uvicorn
import websockets

from agent_auth.api.app import create_app
from agent_auth.config import Settings
from agent_auth.core.daemons import DaemonHub
from agent_auth.daemon_common import crypto as dc
from agent_auth.daemon_common.channel import (
    DaemonChannel,
    DaemonIdentity,
    HandshakeRejected,
    PairingFailed,
    pair,
)
from agent_auth.models import Daemon, DaemonPairingCode
from sqlalchemy import select

ADMIN = {"Authorization": "Bearer admin-secret"}


# --- the signing contract ------------------------------------------------------


def test_envelope_roundtrip_and_tampering():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    raw = dc.seal(key, {"type": "job", "argv": ["true"]}, sender="broker", audience="host:a")
    v = dc.EnvelopeVerifier(pub, expected_sender="broker", expected_audience="host:a")
    assert v.open(raw)["argv"] == ["true"]

    outer = json.loads(raw)
    body = json.loads(dc._unb64(outer["p"]))
    body["argv"] = ["rm", "-rf", "/"]
    outer["p"] = dc._b64(json.dumps(body).encode())
    with pytest.raises(dc.EnvelopeError, match="bad signature"):
        dc.EnvelopeVerifier(pub, expected_sender="broker", expected_audience="host:a").open(
            json.dumps(outer)
        )


def test_envelope_is_bound_to_its_audience_and_sender():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    raw = dc.seal(key, {"type": "job"}, sender="broker", audience="host:a")
    with pytest.raises(dc.EnvelopeError, match="not for this channel"):
        dc.EnvelopeVerifier(pub, expected_sender="broker", expected_audience="host:b").open(raw)
    with pytest.raises(dc.EnvelopeError, match="not for this channel"):
        dc.EnvelopeVerifier(pub, expected_sender="host:a", expected_audience="host:a").open(raw)


def test_envelope_replay_expiry_and_lifetime():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    v = dc.EnvelopeVerifier(pub, expected_sender="broker", expected_audience="host:a")
    raw = dc.seal(key, {"type": "x"}, sender="broker", audience="host:a")
    v.open(raw)
    with pytest.raises(dc.EnvelopeError, match="replayed"):
        v.open(raw)

    now = time.time()
    old = dc.seal(key, {}, sender="broker", audience="host:a", ttl=10, now=now - 100)
    with pytest.raises(dc.EnvelopeError, match="expired"):
        v.open(old)
    future = dc.seal(key, {}, sender="broker", audience="host:a", now=now + 600)
    with pytest.raises(dc.EnvelopeError, match="future"):
        v.open(future)
    forever = dc.seal(key, {}, sender="broker", audience="host:a", ttl=10 * 86400)
    with pytest.raises(dc.EnvelopeError, match="too long"):
        v.open(forever)


def test_hello_signatures_name_their_speaker():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    sig = dc.sign_hello(key, "broker", "host", "a", "bn", "dn")
    assert dc.verify_hello(pub, sig, "broker", "host", "a", "bn", "dn")
    # A broker welcome can't be reflected back as a daemon hello...
    assert not dc.verify_hello(pub, sig, "daemon", "host", "a", "bn", "dn")
    # ...or reused on a connection with other nonces.
    assert not dc.verify_hello(pub, sig, "broker", "host", "a", "bn2", "dn")


def test_pairing_code_shape_and_normalization():
    code = dc.generate_pairing_code()
    assert len(code) == 14 and code.count("-") == 2
    assert dc.pairing_key(code) == dc.pairing_key(code.lower().replace("-", " "))


def test_key_file_is_private_and_reused(tmp_path):
    path = tmp_path / "state" / "key"
    key = dc.load_or_create_key(path)
    assert path.stat().st_mode & 0o777 == 0o400
    assert dc.public_key_text(dc.load_or_create_key(path)) == dc.public_key_text(key)
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        dc.load_or_create_key(path)


# --- broker side ----------------------------------------------------------------


@pytest.fixture
def broker_key():
    return dc.generate_private_key()


@pytest.fixture
def daemon_settings(broker_key) -> Settings:
    return Settings(
        database_url="unused",
        admin_token="admin-secret",
        broker_signing_key=dc.private_key_to_text(broker_key),
        daemon_heartbeat_secs=5,
        _env_file=None,
    )


@pytest.fixture
def hub(db, daemon_settings):
    return DaemonHub(db, daemon_settings)


@pytest.fixture
def daemon_app(daemon_settings, db, service, registry, events, a2a_service, hub):
    return create_app(daemon_settings, db, service, registry, events, a2a_service, hub)


@pytest.fixture
async def dapi(daemon_app):
    transport = httpx.ASGITransport(app=daemon_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _issue_code(dapi, name="excelsior", role="host") -> str:
    resp = await dapi.post(
        "/admin/daemons/pairing-codes", json={"role": role, "name": name}, headers=ADMIN
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["code"]


def _pair_body(code, key, name="excelsior", role="host", proof=None):
    pub = dc.public_key_text(key)
    return {
        "role": role,
        "name": name,
        "public_key": pub,
        "proof": proof or dc.daemon_pair_proof(dc.pairing_key(code), role, name, pub),
    }


async def test_pairing_binds_key_and_broker_proves_itself(dapi, db, broker_key):
    code = await _issue_code(dapi)
    daemon_key = dc.generate_private_key()
    resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, daemon_key))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    broker_pub = dc.public_key_text(broker_key)
    assert data["broker_public_key"] == broker_pub
    assert data["proof"] == dc.broker_pair_proof(
        dc.pairing_key(code), "host", "excelsior", dc.public_key_text(daemon_key), broker_pub
    )
    async with db.session() as session:
        row = (await session.execute(select(Daemon))).scalar_one()
    assert (row.role, row.name, row.public_key) == ("host", "excelsior", dc.public_key_text(daemon_key))

    # Single use.
    again = await dapi.post("/v1/daemons/pair", json=_pair_body(code, dc.generate_private_key()))
    assert again.status_code == 403


async def test_code_is_bound_to_its_daemon(dapi):
    code = await _issue_code(dapi, name="excelsior")
    resp = await dapi.post(
        "/v1/daemons/pair", json=_pair_body(code, dc.generate_private_key(), name="galaxy")
    )
    assert resp.status_code == 403


async def test_wrong_proofs_burn_the_code(dapi, db):
    code = await _issue_code(dapi)
    key = dc.generate_private_key()
    for _ in range(5):
        resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, key, proof="00" * 32))
        assert resp.status_code == 403
        assert "did not verify" in resp.json()["detail"]
    # Burned: even the right proof is refused now.
    resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, key))
    assert resp.status_code == 403
    assert "no pending pairing code" in resp.json()["detail"]


async def test_new_code_supersedes_old(dapi):
    old = await _issue_code(dapi)
    new = await _issue_code(dapi)
    key = dc.generate_private_key()
    assert (await dapi.post("/v1/daemons/pair", json=_pair_body(old, key))).status_code == 403
    assert (await dapi.post("/v1/daemons/pair", json=_pair_body(new, key))).status_code == 200


async def test_expired_code_is_refused(dapi, db):
    code = await _issue_code(dapi)
    async with db.session() as session:
        row = (await session.execute(select(DaemonPairingCode))).scalar_one()
        row.expires_at = row.created_at
    resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, dc.generate_private_key()))
    assert resp.status_code == 403


async def test_invalid_identity_and_disabled_broker(dapi, api):
    resp = await dapi.post(
        "/admin/daemons/pairing-codes", json={"role": "host", "name": "Bad Name"}, headers=ADMIN
    )
    assert resp.status_code == 400
    resp = await dapi.post(
        "/admin/daemons/pairing-codes", json={"role": "laptop", "name": "x"}, headers=ADMIN
    )
    assert resp.status_code == 400
    # The default test app has no BROKER_SIGNING_KEY.
    resp = await api.post(
        "/admin/daemons/pairing-codes", json={"role": "host", "name": "x"}, headers=ADMIN
    )
    assert resp.status_code == 503
    assert (await api.get("/admin/broker-key", headers=ADMIN)).status_code == 503


async def test_admin_endpoints_require_admin(dapi):
    assert (await dapi.get("/admin/daemons")).status_code == 401
    assert (
        await dapi.post("/admin/daemons/pairing-codes", json={"role": "host", "name": "x"})
    ).status_code == 401


# --- the live channel (real server, real client) --------------------------------


@pytest.fixture
async def live(daemon_app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(daemon_app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await asyncio.wait_for(task, 10)


async def _paired_identity(live, dapi, broker_key, name="excelsior") -> DaemonIdentity:
    code = await _issue_code(dapi, name=name)
    identity = DaemonIdentity(
        role="host",
        name=name,
        key=dc.generate_private_key(),
        broker_url=live,
        broker_public_key=dc.public_key_text(broker_key),
    )
    await asyncio.to_thread(pair, identity, code)
    return identity


async def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_channel_end_to_end(live, dapi, db, hub, broker_key):
    identity = await _paired_identity(live, dapi, broker_key)
    received: list[dict] = []

    async def on_message(msg):
        received.append(msg)

    channel = DaemonChannel(
        identity, version="9.9.9", status=lambda: {"jobs": 0}, on_message=on_message
    )
    task = asyncio.create_task(channel.run())
    try:
        await asyncio.wait_for(channel.connected.wait(), 5)
        assert hub.is_online("host", "excelsior")

        async def heartbeat_landed():
            async with db.session() as session:
                row = (await session.execute(select(Daemon))).scalar_one()
                return row.last_status == {"jobs": 0, "version": "9.9.9"}

        assert await _wait_for(heartbeat_landed)

        listing = (await dapi.get("/admin/daemons", headers=ADMIN)).json()
        assert listing[0]["online"] is True and listing[0]["version"] == "9.9.9"
        assert listing[0]["fingerprint"] == dc.fingerprint(identity.public_key)

        # Broker → daemon: signed, addressed, delivered.
        assert await hub.send("host", "excelsior", {"type": "ping", "n": 1})

        async def got_ping():
            return any(m.get("type") == "ping" for m in received)

        assert await _wait_for(got_ping)
        assert received[-1]["aud"] == "host:excelsior"

        # Unpairing drops the connection, and the old key no longer gets in.
        daemon_id = listing[0]["id"]
        assert (await dapi.delete(f"/admin/daemons/{daemon_id}", headers=ADMIN)).status_code == 200

        async def offline():
            return not hub.is_online("host", "excelsior")

        assert await _wait_for(offline)
        await asyncio.sleep(0.5)
        assert not hub.is_online("host", "excelsior")
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_daemon_refuses_a_broker_without_the_pinned_key(live, dapi, broker_key):
    identity = await _paired_identity(live, dapi, broker_key)
    impostor_pin = dc.public_key_text(dc.generate_private_key())
    imposter_view = DaemonIdentity(
        role=identity.role,
        name=identity.name,
        key=identity.key,
        broker_url=identity.broker_url,
        broker_public_key=impostor_pin,
    )
    channel = DaemonChannel(imposter_view, version="1", status=dict)
    async with websockets.connect(f"{live.replace('http', 'ws')}/v1/daemons/connect") as ws:
        with pytest.raises(HandshakeRejected, match="pinned key"):
            await channel._handshake(ws)


async def test_pairing_refuses_unpinned_broker(live, dapi):
    code = await _issue_code(dapi)
    identity = DaemonIdentity(
        role="host",
        name="excelsior",
        key=dc.generate_private_key(),
        broker_url=live,
        broker_public_key=dc.public_key_text(dc.generate_private_key()),
    )
    with pytest.raises(PairingFailed, match="pinned"):
        await asyncio.to_thread(pair, identity, code)


async def _raw_hello(live, role, name, key, nonce_override=None):
    async with websockets.connect(f"{live.replace('http', 'ws')}/v1/daemons/connect") as ws:
        challenge = json.loads(await ws.recv())
        dn = dc.new_nonce()
        bn = nonce_override or challenge["nonce"]
        await ws.send(
            json.dumps(
                {
                    "type": "hello",
                    "role": role,
                    "name": name,
                    "nonce": dn,
                    "sig": dc.sign_hello(key, "daemon", role, name, bn, dn),
                }
            )
        )
        try:
            return json.loads(await ws.recv())
        except websockets.ConnectionClosed as exc:
            return exc.rcvd.code


async def test_hello_rejections(live, dapi, broker_key):
    # Unknown daemon.
    assert await _raw_hello(live, "host", "nobody", dc.generate_private_key()) == 4401
    identity = await _paired_identity(live, dapi, broker_key)
    # Right name, wrong key.
    assert await _raw_hello(live, "host", identity.name, dc.generate_private_key()) == 4401
    # Right key, but signing a different connection's nonce.
    assert await _raw_hello(live, "host", identity.name, identity.key, nonce_override="x") == 4401
    # Right key and nonce: welcomed.
    welcome = await _raw_hello(live, "host", identity.name, identity.key)
    assert welcome["type"] == "welcome"


async def test_bad_envelope_after_hello_closes_connection(live, dapi, broker_key, hub):
    identity = await _paired_identity(live, dapi, broker_key)
    channel = DaemonChannel(identity, version="1", status=dict)
    async with websockets.connect(f"{live.replace('http', 'ws')}/v1/daemons/connect") as ws:
        await channel._handshake(ws)
        # Signed by someone else, claiming to be this daemon.
        forged = dc.seal(
            dc.generate_private_key(),
            {"type": "heartbeat", "status": {}},
            sender="host:excelsior",
            audience="broker",
        )
        await ws.send(forged)
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await asyncio.wait_for(ws.recv(), 5)
        assert exc_info.value.rcvd.code == 4400


async def test_newer_connection_replaces_older(live, dapi, broker_key, hub):
    identity = await _paired_identity(live, dapi, broker_key)
    first = DaemonChannel(identity, version="1", status=dict)
    url = f"{live.replace('http', 'ws')}/v1/daemons/connect"
    async with websockets.connect(url) as ws1:
        await first._handshake(ws1)
        async with websockets.connect(url) as ws2:
            await DaemonChannel(identity, version="1", status=dict)._handshake(ws2)
            with pytest.raises(websockets.ConnectionClosed) as exc_info:
                await asyncio.wait_for(ws1.recv(), 5)
            assert exc_info.value.rcvd.code == 4409


def test_hosts_embed():
    from datetime import datetime, timezone

    from agent_auth.discord_bot.hosts import build_hosts_embed

    assert "No paired daemons" in build_hosts_embed([]).description
    embed = build_hosts_embed(
        [
            {
                "name": "excelsior",
                "role": "host",
                "online": True,
                "version": "0.1.0",
                "last_seen_at": datetime(2026, 10, 3, tzinfo=timezone.utc),
                "fingerprint": "e6c4:3ab3:bdce:125a:f325:8d43:690e:4f1f",
            },
            {
                "name": "galaxy",
                "role": "host",
                "online": False,
                "version": None,
                "last_seen_at": None,
                "fingerprint": "0000:1111:2222:3333:4444:5555:6666:7777",
            },
        ]
    )
    assert "🟢 online **excelsior**" in embed.description
    assert "never connected" in embed.description
    assert embed.footer.text == "1/2 online"
