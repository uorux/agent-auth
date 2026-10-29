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


SID = dc.session_id("host", "a", "bn", "dn")


def _verifier(pub, sender="broker", audience="host:a", session=SID):
    return dc.EnvelopeVerifier(
        pub, expected_sender=sender, expected_audience=audience, session=session
    )


def _seal(key, payload, sender="broker", audience="host:a", session=SID, seq=1, **kw):
    return dc.seal(key, payload, sender=sender, audience=audience, session=session, seq=seq, **kw)


def test_envelope_roundtrip_and_tampering():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    raw = _seal(key, {"type": "job", "argv": ["true"]})
    assert _verifier(pub).open(raw)["argv"] == ["true"]

    outer = json.loads(raw)
    body = json.loads(dc._unb64(outer["p"]))
    body["argv"] = ["rm", "-rf", "/"]
    outer["p"] = dc._b64(json.dumps(body).encode())
    with pytest.raises(dc.EnvelopeError, match="bad signature"):
        _verifier(pub).open(json.dumps(outer))


def test_envelope_is_bound_to_its_audience_and_sender():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    raw = _seal(key, {"type": "job"})
    with pytest.raises(dc.EnvelopeError, match="not for this channel"):
        _verifier(pub, audience="host:b").open(raw)
    with pytest.raises(dc.EnvelopeError, match="not for this channel"):
        _verifier(pub, sender="host:a").open(raw)


def test_envelope_is_bound_to_its_connection():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    raw = _seal(key, {"type": "job"})
    assert _verifier(pub).open(raw)
    # Captured on one connection, replayed into the next: refused.
    other = dc.session_id("host", "a", "bn2", "dn2")
    with pytest.raises(dc.EnvelopeError, match="bad signature"):
        _verifier(pub, session=other).open(raw)


def test_envelope_replay_reorder_expiry_and_lifetime():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    v = _verifier(pub)
    first, second = _seal(key, {"n": 1}, seq=1), _seal(key, {"n": 2}, seq=2)
    v.open(second)
    with pytest.raises(dc.EnvelopeError, match="replayed or reordered"):
        v.open(first)
    with pytest.raises(dc.EnvelopeError, match="replayed or reordered"):
        v.open(second)

    now = time.time()
    old = _seal(key, {}, seq=10, ttl=10, now=now - 100)
    with pytest.raises(dc.EnvelopeError, match="expired"):
        v.open(old)
    future = _seal(key, {}, seq=11, now=now + 600)
    with pytest.raises(dc.EnvelopeError, match="future"):
        v.open(future)
    forever = _seal(key, {}, seq=12, ttl=10 * 86400)
    with pytest.raises(dc.EnvelopeError, match="too long"):
        v.open(forever)


def test_envelope_rejects_non_finite_times():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    body = json.dumps(
        {"id": "x", "iss": "broker", "aud": "host:a", "seq": 1, "iat": 0, "exp": float("nan")}
    ).encode()
    raw = json.dumps(
        {"p": dc._b64(body), "s": dc._b64(key.sign(dc._transcript(dc._CTX_MSG, SID, body)))}
    )
    with pytest.raises(dc.EnvelopeError, match="malformed"):
        _verifier(pub).open(raw)


def test_sealer_numbers_messages_in_order():
    key = dc.generate_private_key()
    sealer = dc.EnvelopeSealer(key, sender="broker", audience="host:a", session=SID)
    v = _verifier(dc.public_key_text(key))
    assert [v.open(sealer.seal({"n": i}))["seq"] for i in range(3)] == [1, 2, 3]


def test_hello_signatures_name_their_speaker():
    key = dc.generate_private_key()
    pub = dc.public_key_text(key)
    sig = dc.sign_hello(key, "broker", "host", "a", "bn", "dn", "{}")
    assert dc.verify_hello(pub, sig, "broker", "host", "a", "bn", "dn", "{}")
    # A broker welcome can't be reflected back as a daemon hello...
    assert not dc.verify_hello(pub, sig, "daemon", "host", "a", "bn", "dn", "{}")
    # ...or reused on a connection with other nonces...
    assert not dc.verify_hello(pub, sig, "broker", "host", "a", "bn2", "dn", "{}")
    # ...or have its parameters rewritten.
    assert not dc.verify_hello(pub, sig, "broker", "host", "a", "bn", "dn", '{"x":1}')


def test_proofs_equal_tolerates_garbage():
    assert not dc.proofs_equal("é" * 64, "00" * 32)
    assert not dc.proofs_equal(None, "00")


def test_pairing_code_shape_and_normalization():
    code = dc.generate_pairing_code()
    assert len(code) == 14 and code.count("-") == 2
    assert dc.pairing_key(code) == dc.pairing_key(code.lower().replace("-", " "))


def test_key_file_is_private_and_reused(tmp_path):
    path = tmp_path / "state" / "key"
    key = dc.load_or_create_key(path)
    assert path.stat().st_mode & 0o777 == 0o400
    assert dc.public_key_text(dc.load_or_create_key(path)) == dc.public_key_text(key)
    assert [p.name for p in path.parent.iterdir()] == ["key"]  # no temp files left
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        dc.load_or_create_key(path)


def test_key_file_symlink_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    dc.load_or_create_key(real)
    link = tmp_path / "state" / "key"
    link.parent.mkdir()
    link.symlink_to(real)
    with pytest.raises(OSError):
        dc.load_or_create_key(link)


def test_identity_refuses_plain_http_off_localhost():
    key = dc.generate_private_key()
    pin = dc.public_key_text(dc.generate_private_key())
    for url in ("http://agent-auth.example", "ftp://x", "https://"):
        with pytest.raises(ValueError, match="https"):
            DaemonIdentity("host", "a", key, url, pin)
    for url in ("https://agent-auth.example", "http://127.0.0.1:8400", "http://localhost"):
        DaemonIdentity("host", "a", key, url, pin)


def test_identity_names_must_match_exactly():
    from agent_auth.core.daemons import validate_identity

    validate_identity("host", "excelsior")
    with pytest.raises(ValueError):
        validate_identity("host", "excelsior\n")


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


def _pair_body(code, key, name="excelsior", role="host", proof=None, selector=None):
    pub = dc.public_key_text(key)
    pkey = dc.pairing_key(code)
    return {
        "role": role,
        "name": name,
        "public_key": pub,
        "selector": selector or dc.pairing_selector(pkey),
        "proof": proof or dc.daemon_pair_proof(pkey, role, name, pub),
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
    details = set()
    for _ in range(5):
        resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, key, proof="00" * 32))
        assert resp.status_code == 403
        details.add(resp.json()["detail"])
    # Burned: even the right proof is refused now, with the same message (no
    # oracle for whether a code is pending).
    resp = await dapi.post("/v1/daemons/pair", json=_pair_body(code, key))
    assert resp.status_code == 403
    details.add(resp.json()["detail"])
    nobody = await dapi.post(
        "/v1/daemons/pair", json=_pair_body(code, key, name="never-issued")
    )
    details.add(nobody.json()["detail"])
    assert len(details) == 1


async def test_attempts_without_the_code_cant_burn_it(dapi, db):
    code = await _issue_code(dapi)
    key = dc.generate_private_key()
    for _ in range(20):
        resp = await dapi.post(
            "/v1/daemons/pair",
            json=_pair_body(code, key, selector="ab" * 16, proof="00" * 32),
        )
        assert resp.status_code == 403
    async with db.session() as session:
        row = (await session.execute(select(DaemonPairingCode))).scalar_one()
    assert row.failed_attempts == 0 and row.used_at is None
    assert (await dapi.post("/v1/daemons/pair", json=_pair_body(code, key))).status_code == 200


async def test_concurrent_wrong_proofs_respect_the_cap(dapi, db, hub, monkeypatch):
    code = await _issue_code(dapi)
    key = dc.generate_private_key()
    checked = 0
    real = dc.daemon_pair_proof

    def counting(*args):
        nonlocal checked
        checked += 1
        return real(*args)

    monkeypatch.setattr("agent_auth.core.daemons.daemon_pair_proof", counting)
    await asyncio.gather(
        *(
            dapi.post("/v1/daemons/pair", json=_pair_body(code, key, proof="00" * 32))
            for _ in range(30)
        )
    )
    assert checked <= hub.settings.daemon_pairing_max_attempts


async def test_malformed_proof_is_a_validation_error(dapi):
    code = await _issue_code(dapi)
    resp = await dapi.post(
        "/v1/daemons/pair", json=_pair_body(code, dc.generate_private_key(), proof="é" * 64)
    )
    assert resp.status_code == 422


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


async def test_unpair_burns_pending_codes(dapi, db):
    code = await _issue_code(dapi)
    key = dc.generate_private_key()
    assert (await dapi.post("/v1/daemons/pair", json=_pair_body(code, key))).status_code == 200
    leaked = await _issue_code(dapi)
    daemon_id = (await dapi.get("/admin/daemons", headers=ADMIN)).json()[0]["id"]
    assert (await dapi.delete(f"/admin/daemons/{daemon_id}", headers=ADMIN)).status_code == 200
    resp = await dapi.post("/v1/daemons/pair", json=_pair_body(leaked, key))
    assert resp.status_code == 403


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
                    "params": "{}",
                    "sig": dc.sign_hello(key, "daemon", role, name, bn, dn, "{}"),
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
        _, sid = await channel._handshake(ws)
        # Signed by someone else, claiming to be this daemon.
        forged = dc.seal(
            dc.generate_private_key(),
            {"type": "heartbeat", "status": {}},
            sender="host:excelsior",
            audience="broker",
            session=sid,
            seq=1,
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


async def test_envelope_from_an_earlier_connection_is_refused(live, dapi, broker_key, hub):
    identity = await _paired_identity(live, dapi, broker_key)
    url = f"{live.replace('http', 'ws')}/v1/daemons/connect"
    async with websockets.connect(url) as ws1:
        _, sid1 = await DaemonChannel(identity, version="1", status=dict)._handshake(ws1)
        captured = dc.seal(
            identity.key,
            {"type": "heartbeat", "status": {}},
            sender=identity.principal,
            audience="broker",
            session=sid1,
            seq=1,
        )
    async with websockets.connect(url) as ws2:
        await DaemonChannel(identity, version="1", status=dict)._handshake(ws2)
        await ws2.send(captured)
        with pytest.raises(websockets.ConnectionClosed) as exc_info:
            await asyncio.wait_for(ws2.recv(), 5)
        assert exc_info.value.rcvd.code == 4400


async def test_unpair_during_handshake_does_not_leave_a_live_connection(
    live, dapi, broker_key, hub, monkeypatch
):
    identity = await _paired_identity(live, dapi, broker_key)
    daemon_id = (await dapi.get("/admin/daemons", headers=ADMIN)).json()[0]["id"]
    real_handshake = hub._handshake

    async def handshake_then_unpair(ws):
        live_conn = await real_handshake(ws)
        # Verified against the key, not yet registered: revoke it now.
        await hub.unpair(daemon_id)
        return live_conn

    monkeypatch.setattr(hub, "_handshake", handshake_then_unpair)
    url = f"{live.replace('http', 'ws')}/v1/daemons/connect"
    async with websockets.connect(url) as ws:
        await DaemonChannel(identity, version="1", status=dict)._handshake(ws)
        with pytest.raises(websockets.ConnectionClosed):
            await asyncio.wait_for(ws.recv(), 5)
    assert not hub.is_online("host", identity.name)


async def test_silent_connection_is_dropped(live, dapi, broker_key, hub):
    hub.settings.daemon_heartbeat_secs = 0.1  # idle timeout = 3 intervals
    identity = await _paired_identity(live, dapi, broker_key)
    url = f"{live.replace('http', 'ws')}/v1/daemons/connect"
    async with websockets.connect(url) as ws:
        await DaemonChannel(identity, version="1", status=dict)._handshake(ws)
        with pytest.raises(websockets.ConnectionClosed):
            await asyncio.wait_for(ws.recv(), 5)
    assert not hub.is_online("host", identity.name)


async def test_daemon_survives_a_garbage_welcome():
    key = dc.generate_private_key()
    identity = DaemonIdentity(
        "host", "a", key, "https://broker.example", dc.public_key_text(dc.generate_private_key())
    )
    channel = DaemonChannel(identity, version="1", status=dict)

    class FakeWS:
        def __init__(self, frames):
            self.frames = list(frames)

        async def recv(self):
            return self.frames.pop(0)

        async def send(self, _):
            pass

    for welcome in ("[]", '"x"', "1", json.dumps({"type": "welcome", "params": 5, "sig": "x"})):
        ws = FakeWS([json.dumps({"type": "challenge", "nonce": "n"}), welcome])
        with pytest.raises(HandshakeRejected):
            await channel._handshake(ws)


def test_hosts_embed_escapes_daemon_supplied_text():
    from datetime import datetime, timezone

    from agent_auth.discord_bot.hosts import build_hosts_embed

    embed = build_hosts_embed(
        [
            {
                "name": "excelsior",
                "role": "host",
                "online": True,
                "version": "1_[x](y)",
                "last_seen_at": datetime(2026, 10, 3, tzinfo=timezone.utc),
                "fingerprint": "e6c4:3ab3:bdce:125a:f325:8d43:690e:4f1f",
            }
        ]
    )
    # An escaped "[" can't start a masked link.
    assert "v1\\_\\[x" in embed.description


def test_version_strings_are_validated():
    from agent_auth.core.daemons import _version

    assert _version("0.1.0+abc") == "0.1.0+abc"
    assert _version("1 · [verify](https://evil.example)") is None
    assert _version(5) is None
