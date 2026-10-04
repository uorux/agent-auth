"""Agent VMs, broker side: the orchestrator bootstrap, key delivery to the
sandbox daemon only, minting with lineage and leases, cascade disable, and
cross-project grants carried out by the daemon."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import timedelta

import httpx
import pytest
import uvicorn
from sqlalchemy import select, update

from agent_auth.api.app import create_app
from agent_auth.config import Settings
from agent_auth.core.daemons import DaemonHub
from agent_auth.core.events import KeyedEvents
from agent_auth.core.sandboxes import SandboxService, disable_agent_tree
from agent_auth.core.service import RequestService
from agent_auth.core.states import GrantStatus, Platform, RequestStatus
from agent_auth.crypto import SecretBox, generate_fernet_key
from agent_auth.daemon_common import crypto as dc
from agent_auth.daemon_common.channel import DaemonChannel, DaemonIdentity, pair
from agent_auth.models import Agent, Grant, PendingKeyDelivery, utcnow
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyFile
from agent_auth.provisioners.a2a import A2AProvisioner
from agent_auth.provisioners.agents import AgentsProvisioner
from agent_auth.provisioners.base import ProvisionerRegistry
from agent_auth.provisioners.sandbox import SandboxProvisioner
from agent_auth.schemas import RequestCreate

from .conftest import make_agent

ADMIN = {"Authorization": "Bearer admin-secret"}

POLICY = {
    "defaults": {"action": "surface", "max_duration": "24h"},
    "platforms": {"agents": {"runtimes": ["claude", "codex"], "lease": "30d"}},
    "rules": [
        {
            "match": {"agent": "orchestrator-*-sandbox", "platform": "agents", "capability": "mint"},
            "action": "approve",
        },
        # A catch-all that must NOT clear mints (needs a rule naming "mint").
        {"match": {"agent": "catchall-*"}, "action": "approve"},
        {"match": {"platform": "sandbox", "capability": "project.read"}, "action": "approve"},
    ],
}


@pytest.fixture
def broker_key():
    return dc.generate_private_key()


@pytest.fixture
def sb_settings(broker_key):
    return Settings(
        database_url="unused",
        admin_token="admin-secret",
        broker_signing_key=dc.private_key_to_text(broker_key),
        encryption_key=generate_fernet_key(),
        daemon_heartbeat_secs=5,
        _env_file=None,
    )


@pytest.fixture
def stack(db, sb_settings, a2a_service):
    policy = PolicyFile.model_validate(POLICY)
    hub = DaemonHub(db, sb_settings)
    sandboxes = SandboxService(db, hub, SecretBox(sb_settings.encryption_key))
    registry = ProvisionerRegistry()
    registry.register(A2AProvisioner())
    registry.register(AgentsProvisioner(policy.platforms.agents, sandboxes))
    registry.register(SandboxProvisioner(hub))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents(), notifier=None)
    app = create_app(sb_settings, db, service, registry, KeyedEvents(), a2a_service, hub)
    return {"hub": hub, "sandboxes": sandboxes, "service": service, "app": app}


@pytest.fixture
async def live(stack):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(stack["app"], host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await asyncio.wait_for(task, 10)


async def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(0.05)
    return False


class FakeSandbox:
    """A sandbox daemon: pairs, connects, records keys, acks them, and answers
    project grants the way sandboxd does."""

    def __init__(self, live, broker_key, name="excelsior", grant_ok=True):
        self.live, self.name, self.grant_ok = live, name, grant_ok
        self.identity = DaemonIdentity(
            role="sandbox",
            name=name,
            key=dc.generate_private_key(),
            broker_url=live,
            broker_public_key=dc.public_key_text(broker_key),
        )
        self.keys: dict[str, dict] = {}
        self.calls: list[dict] = []
        self.channel = DaemonChannel(self.identity, version="1", status=dict, on_message=self.on_message)
        self.task = None

    async def pair(self, stack):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
            code = (
                await api.post(
                    "/admin/daemons/pairing-codes",
                    json={"role": "sandbox", "name": self.name},
                    headers=ADMIN,
                )
            ).json()["code"]
        await asyncio.to_thread(pair, self.identity, code)

    async def start(self):
        self.task = asyncio.create_task(self.channel.run())
        await asyncio.wait_for(self.channel.connected.wait(), 5)

    async def stop(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

    async def on_message(self, msg):
        if msg["type"] == "key":
            self.keys[msg["name"]] = msg
            await self.channel.send({"type": "key.ack", "agent_id": msg["agent_id"]})
        elif msg["type"] in ("project.grant", "project.revoke"):
            self.calls.append(msg)
            await self.channel.send(
                {"type": "reply", "call_id": msg["call_id"], "ok": self.grant_ok,
                 "error": None if self.grant_ok else "no such project"}
            )


@pytest.fixture
async def sandbox(live, stack, broker_key):
    sb = FakeSandbox(live, broker_key)
    await sb.pair(stack)
    await sb.start()
    yield sb
    await sb.stop()


async def _orchestrator(db, name="orchestrator-excelsior-sandbox") -> Agent:
    async with db.session() as session:
        return (await session.execute(select(Agent).where(Agent.name == name))).scalar_one()


async def _api_as(stack, key):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=stack["app"]),
        base_url="http://t",
        headers={"Authorization": f"Bearer {key}"},
    )


def mint(name, runtime=None):
    return RequestCreate(
        platform=Platform.AGENTS,
        capability="mint",
        resource=name,
        scope={"runtime": runtime} if runtime else {},
        justification="set up the larder project",
        requested_duration="10m",
    )


# --- the orchestrator and key delivery ---------------------------------------


async def test_pairing_bootstraps_the_orchestrator_and_delivers_its_key(db, sandbox):
    assert await _wait_for(lambda: _has_key(sandbox, "orchestrator-excelsior-sandbox"))
    orch = await _orchestrator(db)
    assert orch.runtime == "orchestrator" and orch.kind == "service" and not orch.disabled
    # The delivered key authenticates as the orchestrator…
    key = sandbox.keys["orchestrator-excelsior-sandbox"]["api_key"]
    async with httpx.AsyncClient(base_url=sandbox.live, headers={"Authorization": f"Bearer {key}"}) as c:
        assert (await c.get("/v1/me")).json()["name"] == "orchestrator-excelsior-sandbox"

    # …and once acknowledged, the broker no longer holds it.
    async def gone():
        async with db.session() as session:
            return (await session.execute(select(PendingKeyDelivery))).first() is None

    assert await _wait_for(gone)


async def _has_key(sandbox, name):
    return name in sandbox.keys


async def test_repairing_rotates_the_orchestrator_key(db, sandbox, stack, live, broker_key):
    assert await _wait_for(lambda: _has_key(sandbox, "orchestrator-excelsior-sandbox"))
    old = sandbox.keys.pop("orchestrator-excelsior-sandbox")["api_key"]
    await sandbox.stop()
    again = FakeSandbox(live, broker_key)
    await again.pair(stack)
    await again.start()
    try:
        assert await _wait_for(lambda: _has_key(again, "orchestrator-excelsior-sandbox"))
        new = again.keys["orchestrator-excelsior-sandbox"]["api_key"]
        assert new != old
        async with httpx.AsyncClient(base_url=live, headers={"Authorization": f"Bearer {old}"}) as c:
            assert (await c.get("/v1/me")).status_code == 401
    finally:
        await again.stop()


# --- minting -----------------------------------------------------------------------


async def test_mint_creates_a_child_whose_key_only_the_sandbox_gets(db, sandbox, stack):
    orch = await _orchestrator(db)
    req = await stack["service"].create_request(orch.id, mint("claude-larder-excelsior-sandbox"))
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    async with db.session() as session:
        child = (
            await session.execute(select(Agent).where(Agent.name == "claude-larder-excelsior-sandbox"))
        ).scalar_one()
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        cred = await stack["service"].registry.get(Platform.AGENTS).get_credential(session, grant)
    assert (child.parent_agent_id, child.sandbox_id) == (orch.id, orch.sandbox_id)
    assert (child.runtime, child.project, child.kind) == ("claude", "larder", "service")
    assert child.lease_expires_at - utcnow() > timedelta(days=29)
    # The orchestrator's credential names the agent; the key is not in it.
    assert cred.kind == "agent_identity" and cred.value == child.name
    assert await _wait_for(lambda: _has_key(sandbox, "claude-larder-excelsior-sandbox"))
    assert sandbox.keys["claude-larder-excelsior-sandbox"]["project"] == "larder"


async def test_minting_again_renews_without_a_new_key(db, sandbox, stack):
    orch = await _orchestrator(db)
    await stack["service"].create_request(orch.id, mint("codex-site-excelsior-sandbox"))
    assert await _wait_for(lambda: _has_key(sandbox, "codex-site-excelsior-sandbox"))
    first = sandbox.keys.pop("codex-site-excelsior-sandbox")
    async with db.session() as session:
        await session.execute(
            update(Agent).where(Agent.name == "codex-site-excelsior-sandbox")
            .values(lease_expires_at=utcnow() + timedelta(days=1), disabled=True)
        )
    req = await stack["service"].create_request(orch.id, mint("codex-site-excelsior-sandbox"))
    assert req.status == RequestStatus.GRANTED
    async with db.session() as session:
        child = (
            await session.execute(select(Agent).where(Agent.name == "codex-site-excelsior-sandbox"))
        ).scalar_one()
    assert not child.disabled and child.lease_expires_at - utcnow() > timedelta(days=29)
    await asyncio.sleep(1)
    assert "codex-site-excelsior-sandbox" not in sandbox.keys  # the old key still stands
    async with httpx.AsyncClient(
        base_url=sandbox.live, headers={"Authorization": f"Bearer {first['api_key']}"}
    ) as c:
        assert (await c.get("/v1/me")).status_code == 200


@pytest.mark.parametrize(
    "name, why",
    [
        ("claude-larder-galaxy-sandbox", "resource must be"),  # another host's VM
        ("gemini-larder-excelsior-sandbox", "resource must be"),  # runtime not allowed
        ("claude-Bad_Name-excelsior-sandbox", "invalid project"),
        ("claude--excelsior-sandbox", "invalid project"),
        ("claude-" + "a" * 31 + "-excelsior-sandbox", "invalid project"),
    ],
)
async def test_mint_validation(db, sandbox, stack, name, why):
    orch = await _orchestrator(db)
    req = await stack["service"].create_request(orch.id, mint(name))
    assert req.status == RequestStatus.DENIED
    assert why in req.decision_reason


async def test_only_agents_in_a_vm_can_mint(db, sandbox, stack):
    outsider, _ = await make_agent(db, "catchall-hermes")
    req = await stack["service"].create_request(outsider.id, mint("claude-larder-excelsior-sandbox"))
    assert req.status == RequestStatus.DENIED and "agent VM" in req.decision_reason


async def test_a_catchall_rule_does_not_clear_a_mint(db, sandbox, stack):
    orch = await _orchestrator(db)
    async with db.session() as session:
        await session.execute(update(Agent).where(Agent.id == orch.id).values(name="catchall-orch"))
    # Same VM agent, now only matched by the catch-all approve rule.
    req = await stack["service"].create_request(orch.id, mint("claude-larder-excelsior-sandbox"))
    assert req.status == RequestStatus.AWAITING_HUMAN


async def test_sandbox_can_rotate_only_its_own_agents_keys(db, sandbox, stack):
    assert await _wait_for(lambda: _has_key(sandbox, "orchestrator-excelsior-sandbox"))
    old = sandbox.keys.pop("orchestrator-excelsior-sandbox")["api_key"]
    outsider, _ = await make_agent(db, "hand-registered")
    await sandbox.channel.send({"type": "key.rotate", "name": "hand-registered"})
    await sandbox.channel.send({"type": "key.rotate", "name": "orchestrator-excelsior-sandbox"})
    assert await _wait_for(lambda: _has_key(sandbox, "orchestrator-excelsior-sandbox"))
    assert sandbox.keys["orchestrator-excelsior-sandbox"]["api_key"] != old
    assert "hand-registered" not in sandbox.keys


# --- disabling and leases ------------------------------------------------------------


async def test_disable_cascades_to_minted_agents_and_ends_their_grants(db, sandbox, stack):
    orch = await _orchestrator(db)
    await stack["service"].create_request(orch.id, mint("claude-larder-excelsior-sandbox"))
    async with db.session() as session:
        names = await disable_agent_tree(session, orch.id)
    assert set(names) == {"orchestrator-excelsior-sandbox", "claude-larder-excelsior-sandbox"}
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.agent_id == orch.id))).scalar_one()
        assert grant.expires_at <= utcnow()
    await stack["service"].expire_due_grants()
    async with db.session() as session:
        assert (await session.get(Grant, grant.id)).status == GrantStatus.EXPIRED


async def test_lease_sweep(db, sandbox, stack):
    orch = await _orchestrator(db)
    await stack["service"].create_request(orch.id, mint("claude-larder-excelsior-sandbox"))
    async with db.session() as session:
        await session.execute(
            update(Agent).where(Agent.name == "claude-larder-excelsior-sandbox")
            .values(lease_expires_at=utcnow() - timedelta(seconds=1))
        )
    assert await stack["sandboxes"].sweep_leases() == 1
    async with db.session() as session:
        child = (
            await session.execute(select(Agent).where(Agent.name == "claude-larder-excelsior-sandbox"))
        ).scalar_one()
        orch_now = await session.get(Agent, orch.id)
    assert child.disabled and not orch_now.disabled


async def test_admin_disable_endpoint(db, sandbox, stack):
    orch = await _orchestrator(db)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
        resp = await api.post(f"/admin/agents/{orch.id}/disable", headers=ADMIN)
        assert resp.status_code == 200 and resp.json()["disabled"] == ["orchestrator-excelsior-sandbox"]
        listing = (await api.get("/admin/agents", headers=ADMIN)).json()
    row = next(a for a in listing if a["name"] == "orchestrator-excelsior-sandbox")
    assert row["disabled"] and row["runtime"] == "orchestrator"


# --- cross-project access --------------------------------------------------------------


async def _child(db, stack, name="claude-larder-excelsior-sandbox"):
    orch = await _orchestrator(db)
    await stack["service"].create_request(orch.id, mint(name))
    async with db.session() as session:
        return (await session.execute(select(Agent).where(Agent.name == name))).scalar_one()


def access(target, capability="project.read"):
    return RequestCreate(
        platform=Platform.SANDBOX,
        capability=capability,
        resource=target,
        scope={},
        justification="read the shared schema",
        requested_duration="1h",
    )


async def test_project_read_is_applied_and_removed_by_the_sandbox(db, sandbox, stack):
    child = await _child(db, stack)
    req = await stack["service"].create_request(child.id, access("site"))
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    grant_call = sandbox.calls[-1]
    assert (grant_call["type"], grant_call["project"], grant_call["target"], grant_call["access"]) == (
        "project.grant", "larder", "site", "project.read"
    )
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    await stack["service"].revoke_grant(grant.id, "test")
    assert sandbox.calls[-1]["type"] == "project.revoke"


async def test_project_write_needs_a_human_and_own_project_is_refused(db, sandbox, stack):
    child = await _child(db, stack)
    assert (await stack["service"].create_request(child.id, access("site", "project.write"))).status == (
        RequestStatus.AWAITING_HUMAN
    )
    own = await stack["service"].create_request(child.id, access("larder"))
    assert own.status == RequestStatus.DENIED and "own project" in own.decision_reason


async def test_sandbox_refusal_fails_provisioning(db, sandbox, stack):
    child = await _child(db, stack)
    sandbox.grant_ok = False
    req = await stack["service"].create_request(child.id, access("nope"))
    assert req.status == RequestStatus.PROVISION_FAILED
    assert "no such project" in (req.decision_reason or "")


async def test_catalog_shows_vm_platforms_only_to_vm_agents(db, sandbox, stack):
    child = await _child(db, stack)
    outsider, outsider_key = await make_agent(db, "outsider")
    assert await _wait_for(lambda: _has_key(sandbox, child.name))
    child_key = sandbox.keys[child.name]["api_key"]
    async with await _api_as(stack, child_key) as c:
        platforms = {p["platform"] for p in (await c.get("/v1/catalog")).json()["platforms"]}
    assert {"agents", "sandbox"} <= platforms
    async with await _api_as(stack, outsider_key) as c:
        platforms = {p["platform"] for p in (await c.get("/v1/catalog")).json()["platforms"]}
    assert not {"agents", "sandbox"} & platforms
