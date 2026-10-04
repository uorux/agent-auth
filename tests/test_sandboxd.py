"""sandboxd end to end: a real broker, the real daemon logic, a fake host
(units are local processes) and a fake `claude` speaking stream-json.

Covers: pairing → the orchestrator's key; a2a open → routed conversation →
process → reply on the thread; park and resume on the same runtime session;
the agent API (orchestrator-only calls, token + uid check); minting through
it; spawning a project agent; cross-project grants applied by the daemon;
the operator API; an interactive TUI in tmux.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import socket
import sys
import textwrap
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from agent_auth.api.app import create_app
from agent_auth.config import Settings
from agent_auth.core.daemons import DaemonHub
from agent_auth.core.events import KeyedEvents
from agent_auth.core.sandboxes import SandboxService
from agent_auth.core.service import RequestService
from agent_auth.crypto import SecretBox, generate_fernet_key
from agent_auth.daemon_common import crypto as dc
from agent_auth.daemon_common.channel import pair
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyFile
from agent_auth.provisioners.a2a import A2AProvisioner
from agent_auth.provisioners.agents import AgentsProvisioner
from agent_auth.provisioners.base import ProvisionerRegistry
from agent_auth.provisioners.sandbox import SandboxProvisioner
from agent_auth.sandboxd.config import Config, RuntimeConfig
from agent_auth.sandboxd.daemon import Sandboxd
from agent_auth.sandboxd.host import UnitSpec
from agent_auth.sandboxd.localapi import AgentApi, ApiError, OperatorApi

from .conftest import make_agent

ADMIN = {"Authorization": "Bearer admin-secret"}
POLICY = {
    "defaults": {"action": "surface", "max_duration": "24h"},
    "platforms": {"agents": {"runtimes": ["claude", "codex"]}},
    "rules": [
        {"match": {"agent": "orchestrator-*-sandbox", "platform": "agents", "capability": "mint"},
         "action": "approve"},
        {"match": {"platform": "a2a"}, "action": "approve"},
        {"match": {"platform": "sandbox", "capability": "project.read"}, "action": "approve"},
    ],
}

FAKE_CLAUDE = textwrap.dedent(
    """\
    #!{python}
    # A stand-in for `claude -p` (stream-json) or the TUI: logs what it was
    # asked; answers a2a turns on their thread through the broker.
    import json, os, sys, time, urllib.request
    args = sys.argv[1:]
    sid = args[args.index("--session-id") + 1] if "--session-id" in args else args[args.index("--resume") + 1]
    log = open(os.environ["FAKE_LOG"], "a")
    def note(**kw):
        log.write(json.dumps(kw) + "\\n"); log.flush()
    note(start=sid, resumed="--resume" in args, cwd=os.getcwd(), tui="-p" not in args,
         session=os.environ.get("AGENT_AUTH_SESSION"), mcp="--mcp-config" in args)
    if "-p" not in args:  # the TUI: just stay up
        time.sleep(3600)
    print(json.dumps({{"type": "system", "subtype": "init", "session_id": sid}}), flush=True)
    def api(method, path, body=None):
        req = urllib.request.Request(
            os.environ["AGENT_AUTH_URL"] + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={{"Authorization": "Bearer " + os.environ["AGENT_AUTH_API_KEY"],
                     "X-Agent-Session": os.environ["AGENT_AUTH_SESSION"],
                     "Content-Type": "application/json"}})
        return json.load(urllib.request.urlopen(req))
    for line in sys.stdin:
        text = json.loads(line)["message"]["content"]
        note(turn=text[:300])
        if text.startswith("[a2a] thread ") and "is closed" not in text:
            tid = text.split()[2]
            body = " ".join(text.splitlines()[1:-1])
            api("POST", f"/v1/a2a/threads/{{tid}}/messages",
                {{"payload": {{"type": "result", "status": "done", "summary": "echo " + body}}}})
        print(json.dumps({{"type": "assistant", "message": {{"content": [{{"type": "text", "text": "handled"}}]}}}}), flush=True)
        print(json.dumps({{"type": "result", "result": "ok", "session_id": sid}}), flush=True)
    """
)


class FakeHost:
    """Units are plain local processes; /tmp in a unit's argv maps to its tmp
    dir (systemd's BindPaths= in the real thing). Records what it was asked."""

    def __init__(self):
        self.fake_log = os.environ["FAKE_LOG"]
        self.users: dict[str, int] = {}
        self.acls: list[tuple] = []
        self.chowns: list[tuple] = []
        self.procs: dict[str, asyncio.subprocess.Process] = {}

    def ensure_user(self, name, uid, home):
        self.users[name] = uid

    def make_dirs(self, uid, *paths):
        for p in paths:
            p.mkdir(parents=True, exist_ok=True)

    async def grant_acl(self, path, uid, write):
        self.acls.append(("grant", str(path), uid, write))

    async def revoke_acl(self, path, uid):
        self.acls.append(("revoke", str(path), uid))

    async def chown_tree(self, path, uid):
        self.chowns.append((str(path), uid))

    def write_file(self, path, content, uid, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def _env(self, spec: UnitSpec):
        return {**os.environ, **spec.env, "FAKE_LOG": self.fake_log}

    def _argv(self, spec: UnitSpec):
        # Only what the daemon puts under the unit's /tmp (its sockets): this
        # test's own files live under the real /tmp too.
        return [re.sub(r"(^|unix://)/tmp/(?=(tmux|codex)-)", rf"\g<1>{spec.tmp}/", a) for a in spec.argv]

    async def start_piped(self, spec):
        proc = await asyncio.create_subprocess_exec(
            *self._argv(spec), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            env=self._env(spec), cwd=spec.workdir, start_new_session=True,
        )
        self.procs[spec.name] = proc
        return proc

    async def start_detached(self, spec):
        proc = await asyncio.create_subprocess_exec(
            *self._argv(spec), env=self._env(spec), cwd=spec.workdir, start_new_session=True,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        self.procs[spec.name] = proc

    async def stop_unit(self, name):
        proc = self.procs.pop(name, None)
        if proc and proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            await proc.wait()

    async def unit_active(self, name):
        proc = self.procs.get(name)
        return proc is not None and proc.returncode is None

    async def run_as(self, uid, argv):
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=dict(os.environ)
        )
        out, _ = await proc.communicate()
        return proc.returncode, out.decode()


# --- the broker ------------------------------------------------------------------


@pytest.fixture
def broker_key():
    return dc.generate_private_key()


@pytest.fixture
def stack(db, a2a_service, broker_key):
    settings = Settings(
        database_url="unused",
        admin_token="admin-secret",
        broker_signing_key=dc.private_key_to_text(broker_key),
        encryption_key=generate_fernet_key(),
        daemon_heartbeat_secs=5,
        _env_file=None,
    )
    policy = PolicyFile.model_validate(POLICY)
    hub = DaemonHub(db, settings)
    sandboxes = SandboxService(db, hub, SecretBox(settings.encryption_key))
    registry = ProvisionerRegistry()
    registry.register(A2AProvisioner())
    registry.register(AgentsProvisioner(policy.platforms.agents, sandboxes))
    registry.register(SandboxProvisioner(hub))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents(), notifier=None)
    app = create_app(settings, db, service, registry, KeyedEvents(), a2a_service, hub)
    return {"app": app, "service": service, "hub": hub}


@pytest.fixture
async def live(stack):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        # Disconnected long-polls keep their handlers waiting: don't wait for them.
        uvicorn.Config(stack["app"], host="127.0.0.1", port=port, log_level="critical", lifespan="off",
                       timeout_graceful_shutdown=1)
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await asyncio.wait_for(task, 10)


# --- the daemon --------------------------------------------------------------------


@pytest.fixture
def fake_log(tmp_path, monkeypatch):
    path = tmp_path / "fake.log"
    path.touch()
    monkeypatch.setenv("FAKE_LOG", str(path))
    return path


def read_log(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
async def sbx(tmp_path, live, stack, broker_key, fake_log):
    script = tmp_path / "fake-claude"
    script.write_text(FAKE_CLAUDE.format(python=sys.executable))
    script.chmod(0o755)
    # AF_UNIX paths are short: keep the sockets out of pytest's long tmp dir.
    sock_dir = Path(f"/tmp/sbx-test-{os.getpid()}-{id(tmp_path) % 10000}")
    sock_dir.mkdir(exist_ok=True)
    cfg = Config(
        broker_url=live,
        broker_public_key=dc.public_key_text(broker_key),
        name="excelsior",
        state_dir=tmp_path / "state",
        sandbox_root=sock_dir / "sandbox",  # tmux sockets live under it
        userdb_dir=tmp_path / "userdb",
        runtime_dir=tmp_path / "run",
        agent_socket=sock_dir / "agent.sock",
        runtimes={"claude": RuntimeConfig(command=str(script))},
        agent_path=os.environ["PATH"],
        tmux=shutil.which("tmux") or "tmux",
        uid_base=os.getuid(),  # the orchestrator is "us": the agent API's uid check passes
        park_grace_secs=0.5,
    )
    host = FakeHost()
    daemon = Sandboxd(cfg, host)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
        code = (await api.post("/admin/daemons/pairing-codes", json={"role": "sandbox", "name": "excelsior"},
                               headers=ADMIN)).json()["code"]
    await asyncio.to_thread(pair, daemon.identity(), code)
    task = asyncio.create_task(daemon.run())
    assert await wait_for(lambda: daemon.state.agent("orchestrator-excelsior-sandbox") is not None)
    yield daemon, host
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    for conv_id in list(daemon.live):
        await host.stop_unit(daemon._unit(conv_id))
        await host.stop_unit(daemon._tui_unit(conv_id))
    shutil.rmtree(sock_dir, ignore_errors=True)


async def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if asyncio.iscoroutine(result):
            result = await result
        if result:
            return True
        await asyncio.sleep(0.05)
    return False


async def peer(db, live, name="hermes-test"):
    """A service agent outside the VM, with a client."""
    _, key = await make_agent(db, name)
    return httpx.AsyncClient(base_url=live, headers={"Authorization": f"Bearer {key}"}, timeout=30)


async def open_thread(client, to: str, payload: dict) -> str:
    grant = (await client.post("/v1/requests", json={
        "platform": "a2a", "capability": "talk", "resource": to, "scope": {},
        "justification": "test", "requested_duration": "1h"})).json()
    assert grant["status"] == "granted", grant
    resp = await client.post("/v1/a2a/threads", json={"to": to, "payload": payload})
    assert resp.status_code == 200, resp.text
    return resp.json()["thread_id"]


async def reply_on(client, tid: str, after: int = 0, timeout: float = 20) -> list[dict]:
    """Messages after `after`, waiting through state changes (the long-poll
    also returns when the thread goes from pending_open to open)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = await client.get(f"/v1/a2a/threads/{tid}/messages", params={"after_seq": after, "wait": 5})
        msgs = resp.json()["messages"]
        if msgs:
            return msgs
    return []


# --- tests ---------------------------------------------------------------------------


async def test_a2a_open_is_answered_by_a_routed_conversation_that_parks_and_resumes(db, live, sbx, fake_log):
    daemon, host = sbx
    hermes = await peer(db, live)
    async with hermes:
        tid = await open_thread(hermes, "orchestrator-excelsior-sandbox", {"task": "ping"})
        msgs = await reply_on(hermes, tid, after=1)
        assert msgs and msgs[0]["payload"]["status"] == "done"
        assert "ping" in msgs[0]["payload"]["summary"]

        convs = daemon.state.conversations(agent="orchestrator-excelsior-sandbox")
        assert len(convs) == 1
        conv = convs[0]
        assert daemon.state.thread(tid)["conversation_id"] == conv.id
        # The process runs as the orchestrator, in its workspace, with the
        # conversation's broker session and its MCP servers.
        start = next(e for e in read_log(fake_log) if "start" in e)
        assert start["cwd"].endswith("orchestrator") and start["session"] == conv.broker_session_id
        assert start["mcp"] and not start["resumed"]

        # Idle → parked; the next message resumes the same runtime session.
        assert await wait_for(lambda: daemon.state.conversation(conv.id).state == "parked")
        await hermes.post(f"/v1/a2a/threads/{tid}/messages", json={"payload": {"task": "again"}})
        msgs = await reply_on(hermes, tid, after=3)
        assert msgs and "again" in msgs[0]["payload"]["summary"]
        starts = [e for e in read_log(fake_log) if "start" in e]
        assert len(starts) == 2 and starts[1]["resumed"] and starts[1]["start"] == start["start"]


async def test_hint_routes_into_an_existing_conversation(db, live, sbx, fake_log):
    daemon, _ = sbx
    hermes = await peer(db, live)
    async with hermes:
        first = await open_thread(hermes, "orchestrator-excelsior-sandbox", {"task": "one"})
        await reply_on(hermes, first, after=1)
        conv = daemon.state.thread(first)["conversation_id"]
        second = await open_thread(
            hermes, "orchestrator-excelsior-sandbox", {"task": "two", "_sandbox": {"conversation": conv}}
        )
        await reply_on(hermes, second, after=1)
    assert daemon.state.thread(second)["conversation_id"] == conv
    assert len(daemon.state.conversations(agent="orchestrator-excelsior-sandbox")) == 1


async def _orch_token(daemon) -> str:
    """Start an orchestrator conversation and return its agent-API token."""
    conv = await daemon.new_conversation("orchestrator-excelsior-sandbox", created_by="test")
    return conv, daemon._live(conv.id).token


async def test_agent_api_orchestrator_sets_up_a_project_and_its_agent(db, live, sbx, fake_log, stack):
    daemon, host = sbx
    api = AgentApi(daemon)
    conv, token = await _orch_token(daemon)
    me = await api("whoami", {}, token, os.getuid())
    assert me["orchestrator"] and me["agent"] == "orchestrator-excelsior-sandbox"

    created = await api("project_create", {"name": "larder"}, token, os.getuid())
    assert host.users["p-larder"] == created["uid"]
    assert ("grant", created["path"], os.getuid(), True) in host.acls  # setup access
    minted = await api("agent_mint", {"runtime": "claude", "project": "larder"}, token, os.getuid())
    assert minted["status"] == "granted" and minted["key_received"], minted

    spawned = await api("agent_spawn", {"agent": "claude-larder-excelsior-sandbox", "prompt": "hello"},
                        token, os.getuid())
    # Spawning seals the project: ownership to its user, setup access gone.
    assert (created["path"], created["uid"]) in host.chowns
    assert ("revoke", created["path"], os.getuid()) in host.acls
    assert await wait_for(lambda: any(e.get("turn") == "hello" for e in read_log(fake_log)))
    start = [e for e in read_log(fake_log) if "start" in e][-1]
    assert start["cwd"] == created["path"]
    assert spawned["agent"] == "claude-larder-excelsior-sandbox"


async def test_agent_api_refuses_wrong_uid_bad_token_and_non_orchestrators(db, live, sbx):
    daemon, _ = sbx
    api = AgentApi(daemon)
    conv, token = await _orch_token(daemon)
    with pytest.raises(ApiError, match="another user"):
        await api("whoami", {}, token, os.getuid() + 12345)
    with pytest.raises(ApiError, match="unknown conversation"):
        await api("whoami", {}, "forged", os.getuid())
    # A project agent's conversation can't use orchestrator calls.
    daemon.create_project("site")
    await daemon.mint("claude", "site", "test")
    pconv = await daemon.new_conversation("claude-site-excelsior-sandbox", created_by="test")
    ptoken = daemon._live(pconv.id).token
    puid = daemon.project_uid("site")
    with pytest.raises(ApiError, match="for the orchestrator"):
        await api("project_create", {"name": "evil"}, ptoken, puid)
    assert (await api("whoami", {}, ptoken, puid))["project"] == "site"


async def test_project_grant_from_the_broker_is_applied_and_revoked(db, live, sbx, stack):
    daemon, host = sbx
    for p in ("larder", "site"):
        daemon.create_project(p)
    await daemon.mint("claude", "larder", "test")
    rec = daemon.state.agent("claude-larder-excelsior-sandbox")
    async with httpx.AsyncClient(base_url=live, headers={"Authorization": f"Bearer {rec.api_key}"}) as c:
        req = (await c.post("/v1/requests", json={
            "platform": "sandbox", "capability": "project.read", "resource": "site", "scope": {},
            "justification": "read the shared schema", "requested_duration": "1h"})).json()
    assert req["status"] == "granted", req
    site_path = str(daemon._paths("site")[0])
    assert ("grant", site_path, daemon.project_uid("larder"), False) in host.acls
    await stack["service"].revoke_grant(req["grant_id"], "test")
    assert ("revoke", site_path, daemon.project_uid("larder")) in host.acls


async def test_operator_api(db, live, sbx, fake_log):
    daemon, _ = sbx
    op = OperatorApi(daemon)
    with pytest.raises(ApiError, match="operators only"):
        await op("status", {}, None, 1000)
    status = await op("status", {}, None, 0)
    assert status["host"] == "excelsior" and status["agents"] == 1
    await op("project_create", {"name": "larder"}, None, 0)
    await op("mint", {"runtime": "claude", "project": "larder"}, None, 0)
    out = await op("new", {"agent": "claude-larder-excelsior-sandbox", "prompt": "hi", "attach": False}, None, 0)
    conv_id = out["conversation"]["id"]
    assert await wait_for(lambda: any(e.get("turn") == "hi" for e in read_log(fake_log)))
    await op("send", {"conversation": conv_id, "text": "more"}, None, 0)
    assert await wait_for(lambda: any(e.get("turn") == "more" for e in read_log(fake_log)))
    log_path = await op("log_path", {"conversation": conv_id}, None, 0)
    dirs = [json.loads(line)["dir"] for line in Path(log_path).read_text().splitlines()]
    assert "in" in dirs and "out" in dirs
    await op("close", {"conversation": conv_id}, None, 0)
    assert daemon.state.conversation(conv_id).state == "closed"
    with pytest.raises(ApiError, match="secrets"):
        await op("secret_set", {"name": "../../etc/passwd", "value": "x"}, None, 0)


@pytest.mark.skipif(shutil.which("tmux") is None, reason="needs tmux")
async def test_interactive_attach_hands_the_session_to_a_tui(db, live, sbx, fake_log):
    daemon, host = sbx
    hermes = await peer(db, live)
    async with hermes:
        tid = await open_thread(hermes, "orchestrator-excelsior-sandbox", {"task": "ping"})
        await reply_on(hermes, tid, after=1)
    conv = daemon.state.thread(tid)["conversation_id"]
    info = await daemon.attach(conv, now=True)
    assert info["argv"][-3:] == ["attach", "-t", "conv"]
    # The headless process is gone; the TUI resumed the same session.
    assert daemon._live(conv).run is None and daemon.state.conversation(conv).state == "attached"
    assert await wait_for(lambda: any(e.get("tui") for e in read_log(fake_log) if "start" in e))
    tui = [e for e in read_log(fake_log) if e.get("tui")][-1]
    first = [e for e in read_log(fake_log) if "start" in e][0]
    assert tui["start"] == first["start"] and tui["resumed"]
    # While attached, a2a messages queue for the TUI's prompt hook.
    await daemon.deliver(conv, "[a2a] queued while attached")
    assert daemon.state.peek(conv) == ["[a2a] queued while attached"]
    # Detaching for good: back to headless, and the queue is delivered there.
    await daemon.stop_tui(conv)
    assert await wait_for(lambda: any(e.get("turn", "").startswith("[a2a] queued") for e in read_log(fake_log)))


async def test_an_open_that_cannot_be_served_is_rejected_not_retried(db, live, sbx, stack):
    daemon, _ = sbx
    daemon.runtimes.clear()  # no runtime for the orchestrator any more
    hermes = await peer(db, live)
    async with hermes:
        tid = await open_thread(hermes, "orchestrator-excelsior-sandbox", {"task": "ping"})

        async def closed():
            t = (await hermes.get(f"/v1/a2a/threads/{tid}")).json()
            return t["state"] == "closed" and "sandbox:" in (t.get("close_note") or "")

        assert await wait_for(closed)
