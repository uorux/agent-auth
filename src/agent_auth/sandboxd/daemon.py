"""The sandboxd daemon (docs/sandbox-design.md §6).

Pieces, all on one event loop:

- the broker channel (role "sandbox"): agent keys arrive here (to this daemon
  alone) and are acknowledged; project grants are applied and answered;
- one sessionless a2a dispatcher per agent: pending opens are routed to a
  conversation — the one a hint names, else a new one — which claims the
  thread with its own broker session;
- one watcher per conversation: a session-scoped events long-poll that keeps
  the broker session alive while the process is parked and turns new thread
  messages into turns;
- processes: started on demand, parked after a grace period of idleness,
  resumed on the next message (same runtime session, transcript, scratchpad);
- interactive attach: claude hands the session to a TUI in tmux (stop
  headless, resume interactively); codex's TUI joins the live app-server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import shlex
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__
from ..daemon_common.channel import DaemonChannel, DaemonIdentity
from ..daemon_common.crypto import load_or_create_key
from .broker import Broker, BrokerCallError
from .config import Config
from .host import ORCHESTRATOR_DIR, ORCHESTRATOR_USER, Host, project_user
from .runtimes import ClaudeRuntime, CodexRuntime, Event, Run, Runtime, SpawnContext
from .state import AgentRecord, Conversation, State

log = logging.getLogger(__name__)

ROLE = "sandbox"
PROJECT_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?")
EVENTS_WAIT = 60
RETRY_SECS = 5


def orchestrator_name(host: str) -> str:
    return f"orchestrator-{host}-sandbox"


SYSTEM_PROMPT = """\
You are {agent}, an agent running headless in the agent VM on {host}.
{where}
You have no human at this terminal. Requests reach you as a2a messages from
other agents (or from the operator); they appear as user turns starting with
"[a2a]". Answer an a2a request with the agent-auth MCP tool a2a_send on that
thread — your final message is {{"type": "result", "status":
"done"|"failed"|"declined", "summary": "..."}} — then a2a_close. Plain text
you write here is only logged.
Access you don't have (GitHub, homelab services, Kubernetes, other agents)
goes through the agent-auth MCP tools: list_capabilities, request_access,
wait_for_decision, get_credential. Never ask anyone for credentials.
The sandbox MCP tools describe this VM (sandbox_whoami, project_list,
conversations).{extra}"""

ORCHESTRATOR_EXTRA = """
You are the orchestrator: you set projects up and start their agents.
- project_create(name) makes a project (a directory and its own user) and
  gives you write access until project_seal(name). Clone or prepare it there
  (request a github "repo" grant first, or "create" a new uorux repo).
- agent_mint(runtime, project) asks the broker for <runtime>-<project>-{host}-sandbox;
  agent_spawn(agent, prompt) starts a conversation of it with a first message.
- Seal a project before its agents start (spawning one seals it for you).
- To hand a requester its new agent, reply with the agent's name: the
  requester opens its own thread to it (there is no handoff of threads)."""


def format_a2a(thread: dict[str, Any], msg: dict[str, Any]) -> str:
    topic = f" · topic {thread['topic']}" if thread.get("topic") else ""
    payload = msg.get("payload")
    body = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    return (
        f"[a2a] thread {thread['thread_id']} · from {msg.get('from')}{topic} · seq {msg.get('seq')}\n"
        f"{body}\n"
        f'(reply: a2a_send(thread_id="{thread["thread_id"]}", payload={{...}}))'
    )


@dataclass
class Live:
    """In-memory side of a conversation."""

    conv_id: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    run: Run | None = None
    ctx: SpawnContext | None = None
    pump: asyncio.Task | None = None
    park_timer: asyncio.Task | None = None
    watcher: asyncio.Task | None = None
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    tui: bool = False  # an interactive TUI holds the session


class Sandboxd:
    def __init__(self, config: Config, host: Host, broker: Broker | None = None):
        self.config = config
        self.host = host
        self.state = State(config.state_dir / "state.db")
        self.broker = broker or Broker(config.broker_url)
        self.runtimes: dict[str, Runtime] = {}
        for name, rc in config.runtimes.items():
            cls = {"claude": ClaudeRuntime, "codex": CodexRuntime}.get(name)
            if cls is not None:
                self.runtimes[name] = cls(rc.command, rc.model)
        self.live: dict[str, Live] = {}
        self.dispatchers: dict[str, asyncio.Task] = {}
        self._thread_locks: dict[str, asyncio.Lock] = {}
        self.channel: DaemonChannel | None = None
        self._tasks: set[asyncio.Task] = set()
        self._spawn_slots = asyncio.Semaphore(config.max_processes)
        self.started_at = time.time()
        self.orchestrator = orchestrator_name(config.name)

    # --- lifecycle -----------------------------------------------------------------

    def _task(self, coro, name: str) -> asyncio.Task:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def identity(self) -> DaemonIdentity:
        return DaemonIdentity(
            role=ROLE,
            name=self.config.name,
            key=load_or_create_key(self.config.state_dir / "key"),
            broker_url=self.config.broker_url,
            broker_public_key=self.config.broker_public_key,
        )

    async def startup(self) -> None:
        """Clean slate for processes (their stdio died with the previous
        daemon), keep conversations: they resume on their next message."""
        c = self.config
        for d in ("projects", "homes", "tmp"):
            (c.sandbox_root / d).mkdir(mode=0o711, parents=True, exist_ok=True)
        self.host.ensure_user(ORCHESTRATOR_USER, c.uid_base, c.sandbox_root / "homes" / ORCHESTRATOR_DIR)
        self.host.make_dirs(
            c.uid_base,
            c.sandbox_root / "orchestrator",
            c.sandbox_root / "homes" / ORCHESTRATOR_DIR,
            c.sandbox_root / "tmp" / ORCHESTRATOR_DIR,
        )
        (c.state_dir / "logs").mkdir(mode=0o700, parents=True, exist_ok=True)
        for conv in self.state.conversations():
            await self.host.stop_unit(self._unit(conv.id))
            await self.host.stop_unit(self._tui_unit(conv.id))
            self.state.update_conversation(conv.id, state="parked")
            self._watch(conv)
        for agent in self.state.agents():
            self._dispatch(agent)

    async def run(self) -> None:
        try:
            await self.startup()
            self.channel = DaemonChannel(
                self.identity(), version=__version__, status=self.status, on_message=self.on_broker_message
            )
            self._task(self._reaper(), "reaper")
            await self.channel.run()
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Stop polling and the processes' plumbing. Units are left to the
        next startup (it stops them); conversations stay resumable."""
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for lv in self.live.values():
            if lv.run is not None:
                try:
                    await lv.run.stop()
                except Exception:
                    log.exception("stopping conversation %s", lv.conv_id)
                lv.run = None
        await self.broker.aclose()

    def status(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for conv in self.state.conversations():
            counts[conv.state] = counts.get(conv.state, 0) + 1
        return {
            "version": __version__,
            "role": ROLE,
            "host": self.config.name,
            "agents": len(self.state.agents()),
            "projects": len(self.state.projects()),
            "conversations": counts,
            "processes": sum(1 for lv in self.live.values() if lv.run is not None),
        }

    # --- the broker channel ------------------------------------------------------------

    async def on_broker_message(self, msg: dict[str, Any]) -> None:
        kind = msg.get("type")
        if kind == "key":
            rec = AgentRecord(
                name=msg["name"],
                agent_id=msg["agent_id"],
                runtime=msg.get("runtime"),
                project=msg.get("project"),
                api_key=msg["api_key"],
            )
            self.state.put_agent(rec)
            log.info("received the key of %s", rec.name)
            if self.channel:
                await self.channel.send({"type": "key.ack", "agent_id": rec.agent_id})
            self._dispatch(rec, restart=True)
        elif kind in ("project.grant", "project.revoke"):
            try:
                if kind == "project.grant":
                    await self.apply_project_grant(msg["grant_id"], msg["project"], msg["target"], msg["access"])
                else:
                    await self.remove_project_grant(msg["grant_id"])
                reply = {"ok": True}
            except Exception as exc:  # reported to the broker, which fails the grant
                reply = {"ok": False, "error": str(exc)}
            if self.channel:
                await self.channel.send({"type": "reply", "call_id": msg.get("call_id"), **reply})

    async def _key_lost(self, agent: str) -> None:
        log.warning("the broker no longer accepts the key of %s; asking for a new one", agent)
        if self.channel:
            await self.channel.send({"type": "key.rotate", "name": agent})

    # --- projects ---------------------------------------------------------------------------

    def _paths(self, project: str | None) -> tuple[Path, Path, Path]:
        root = self.config.sandbox_root
        if project is None:
            return root / "orchestrator", root / "homes" / ORCHESTRATOR_DIR, root / "tmp" / ORCHESTRATOR_DIR
        return root / "projects" / project, root / "homes" / project, root / "tmp" / project

    def project_uid(self, project: str | None) -> int:
        if project is None:
            return self.config.uid_base
        proj = self.state.project(project)
        if proj is None:
            raise LookupError(f"no project {project!r}")
        return proj["uid"]

    def create_project(self, name: str) -> dict[str, Any]:
        if not PROJECT_RE.fullmatch(name):
            raise ValueError("project names: lowercase letters, digits and '-', at most 30")
        if self.state.project(name):
            raise ValueError(f"project {name!r} exists")
        used = self.state.used_uids() | {self.config.uid_base}
        uid = next((u for u in range(self.config.uid_base + 1, self.config.uid_max + 1) if u not in used), None)
        if uid is None:
            raise RuntimeError("no free uids for projects")
        workdir, home, tmp = self._paths(name)
        self.host.ensure_user(project_user(name), uid, home)
        self.host.make_dirs(uid, workdir, home, tmp)
        self.state.add_project(name, uid)
        return {"project": name, "path": str(workdir), "uid": uid}

    async def open_project_for_setup(self, name: str) -> None:
        """The orchestrator may write the project until it's sealed."""
        proj = self.state.project(name)
        if proj is None or proj["sealed"]:
            raise ValueError(f"project {name!r} is not open for setup")
        await self.host.grant_acl(self._paths(name)[0], self.config.uid_base, write=True)

    async def seal_project(self, name: str) -> None:
        proj = self.state.project(name)
        if proj is None:
            raise LookupError(f"no project {name!r}")
        if proj["sealed"]:
            return
        workdir = self._paths(name)[0]
        await self.host.revoke_acl(workdir, self.config.uid_base)
        await self.host.chown_tree(workdir, proj["uid"])
        self.state.seal_project(name)

    async def apply_project_grant(self, grant_id: str, project: str, target: str, access: str) -> None:
        if access not in ("project.read", "project.write"):
            raise ValueError(f"unknown access {access!r}")
        uid = self.project_uid(project)
        self.project_uid(target)  # must exist
        await self.host.grant_acl(self._paths(target)[0], uid, write=access == "project.write")
        self.state.add_project_grant(grant_id, project, target, access)

    async def remove_project_grant(self, grant_id: str) -> None:
        grant = self.state.pop_project_grant(grant_id)
        if grant is None:
            return  # already gone: revocation is idempotent
        uid = self.project_uid(grant["project"])
        path = self._paths(grant["target"])[0]
        await self.host.revoke_acl(path, uid)
        # Another grant may still give the same pair access.
        for other in self.state.project_grants(grant["project"], grant["target"]):
            await self.host.grant_acl(path, uid, write=other["access"] == "project.write")

    # --- agents and dispatch --------------------------------------------------------------

    def _dispatch(self, agent: AgentRecord, restart: bool = False) -> None:
        current = self.dispatchers.get(agent.name)
        if current and not current.done():
            if not restart:
                return
            current.cancel()
        self.dispatchers[agent.name] = self._task(self._dispatcher(agent.name), f"dispatch:{agent.name}")

    async def _dispatcher(self, agent_name: str) -> None:
        """Sessionless events loop: pending opens are this agent's queue. The
        long-poll is also what tells peers this agent is reachable."""
        after = None
        while True:
            rec = self.state.agent(agent_name)
            if rec is None:
                return
            try:
                snap = await self.broker.events(rec.api_key, wait=EVENTS_WAIT, after=after)
                after = snap.get("cursor") or after
                for thread in snap.get("pending_opens", []):
                    await self.route_open(rec, thread)
            except BrokerCallError as exc:
                if exc.status == 401:
                    await self._key_lost(agent_name)
                    return  # restarted when the new key arrives
                log.warning("events for %s: %s", agent_name, exc)
                await asyncio.sleep(RETRY_SECS)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("events for %s: %s", agent_name, exc)
                await asyncio.sleep(RETRY_SECS)

    async def route_open(self, rec: AgentRecord, thread: dict[str, Any]) -> None:
        tid = thread["thread_id"]
        if self.state.thread(tid):
            return  # already claimed; the broker may not have caught up
        first = await self.broker.messages(rec.api_key, tid, 0)
        msgs = first.get("messages", [])
        hint = None
        if msgs and isinstance(msgs[0].get("payload"), dict):
            hint = (msgs[0]["payload"].get("_sandbox") or {}).get("conversation")
        conv = self.state.conversation(hint) if isinstance(hint, str) else None
        if conv is None or conv.agent != rec.name or conv.state == "closed":
            conv = await self.new_conversation(
                rec.name,
                created_by=f"a2a:{thread.get('peer')}",
                title=f"{thread.get('peer')}: {thread.get('topic') or tid[:8]}",
            )
        await self.claim(conv, thread)

    # --- conversations ----------------------------------------------------------------------

    def _unit(self, conv_id: str) -> str:
        return f"sbx-conv-{conv_id}"

    def _tui_unit(self, conv_id: str) -> str:
        return f"sbx-tui-{conv_id}"

    def _live(self, conv_id: str) -> Live:
        if conv_id not in self.live:
            self.live[conv_id] = Live(conv_id)
        return self.live[conv_id]

    def _runtime_of(self, rec: AgentRecord) -> str:
        runtime = rec.runtime if rec.runtime in self.runtimes else None
        if rec.name == self.orchestrator:
            runtime = self.config.orchestrator_runtime
        if runtime not in self.runtimes:
            raise RuntimeError(f"no runtime configured for {rec.name} ({rec.runtime})")
        return runtime

    async def new_conversation(
        self, agent: str, *, created_by: str, title: str = "", mode: str = "headless"
    ) -> Conversation:
        rec = self.state.agent(agent)
        if rec is None:
            raise LookupError(f"no key for agent {agent!r} in this VM")
        conv = self.state.new_conversation(
            agent, self._runtime_of(rec), mode=mode, title=title, created_by=created_by
        )
        sid = await self.broker.create_session(rec.api_key, f"conv-{conv.id}")
        self.state.update_conversation(conv.id, broker_session_id=sid)
        conv = self.state.conversation(conv.id)
        self._watch(conv)
        return conv

    async def claim(self, conv: Conversation, thread: dict[str, Any]) -> None:
        rec = self.state.agent(conv.agent)
        await self.broker.accept(rec.api_key, thread["thread_id"], conv.broker_session_id)
        self.state.bind_thread(
            thread["thread_id"], conv.id, thread.get("peer"), thread.get("role", "responder"), thread.get("topic")
        )
        await self._read_thread(conv, rec, thread)

    def _watch(self, conv: Conversation) -> None:
        lv = self._live(conv.id)
        if lv.watcher is None or lv.watcher.done():
            lv.watcher = self._task(self._watcher(conv.id), f"watch:{conv.id}")

    async def _watcher(self, conv_id: str) -> None:
        after = None
        while True:
            conv = self.state.conversation(conv_id)
            if conv is None or conv.state == "closed":
                return
            rec = self.state.agent(conv.agent)
            if rec is None or conv.broker_session_id is None:
                return
            try:
                snap = await self.broker.events(
                    rec.api_key, wait=EVENTS_WAIT, after=after, session=conv.broker_session_id
                )
                after = snap.get("cursor") or after
                for thread in snap.get("activity", []):
                    if self.state.thread(thread["thread_id"]) is None:
                        # Opened by this conversation's agent: adopt it.
                        self.state.bind_thread(
                            thread["thread_id"], conv_id, thread.get("peer"), thread.get("role"), thread.get("topic")
                        )
                    await self._read_thread(conv, rec, thread)
            except BrokerCallError as exc:
                if exc.status == 401 and "session" in exc.detail:
                    # The broker ended the session (idle, closed): the
                    # conversation's threads are gone with it.
                    log.info("conversation %s lost its broker session", conv_id)
                    self.state.update_conversation(conv_id, broker_session_id=None)
                    return
                if exc.status == 401:
                    await self._key_lost(conv.agent)
                await asyncio.sleep(RETRY_SECS)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("watching %s: %s", conv_id, exc)
                await asyncio.sleep(RETRY_SECS)

    async def _read_thread(self, conv: Conversation, rec: AgentRecord, thread: dict[str, Any]) -> None:
        """Deliver a thread's new messages (and its closing) exactly once.
        The claim and the conversation's watcher can both get here for the
        same activity: one at a time per thread, cursor moved before
        delivering."""
        tid = thread["thread_id"]
        lock = self._thread_locks.setdefault(tid, asyncio.Lock())
        async with lock:
            bound = self.state.thread(tid) or {}
            cursor = bound.get("cursor", 0)
            fresh: list[dict[str, Any]] = []
            if thread.get("last_seq", 0) > cursor:
                page = await self.broker.messages(rec.api_key, tid, cursor, session=conv.broker_session_id)
                fresh = [m for m in page.get("messages", []) if m["seq"] > cursor]
                if fresh:
                    self.state.set_thread(tid, cursor=max(m["seq"] for m in fresh))
            closing = thread.get("state") == "closed" and bound.get("state") != "closed"
            if closing:
                self.state.set_thread(tid, state="closed")
        for msg in fresh:
            if msg.get("from") != rec.name:
                await self.deliver(conv.id, format_a2a(thread, msg))
        if closing:
            reason = thread.get("close_reason") or "closed"
            await self.deliver(
                conv.id,
                f"[a2a] thread {tid} with {thread.get('peer')} is closed ({reason}). Nothing more will arrive on it.",
            )

    # --- processes ---------------------------------------------------------------------------

    def _context(self, conv: Conversation, lv: Live) -> SpawnContext:
        rec = self.state.agent(conv.agent)
        project = None if rec.name == self.orchestrator else rec.project
        workdir, home, tmp = self._paths(project)
        uid = self.project_uid(project)
        c = self.config
        env = {
            "HOME": str(home),
            "USER": project_user(project) if project else ORCHESTRATOR_USER,
            "LOGNAME": project_user(project) if project else ORCHESTRATOR_USER,
            "PATH": c.agent_path,
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "AGENT_AUTH_URL": c.broker_url,
            "AGENT_AUTH_API_KEY": rec.api_key,
            "AGENT_AUTH_SESSION": conv.broker_session_id or "",
            "AGENT_AUTH_SANDBOX_SOCKET": str(c.agent_socket),
            "AGENT_AUTH_SANDBOX_TOKEN": lv.token,
            "CODEX_HOME": str(home / ".codex"),
        }
        token_file = c.secrets_dir / "claude-oauth-token"
        if token_file.exists():
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token_file.read_text().strip()
        where = (
            f"Your project is {project}, at {workdir} (your working directory)."
            if project
            else f"Your workspace is {workdir}; projects are under {c.sandbox_root / 'projects'}."
        )
        prompt = SYSTEM_PROMPT.format(
            agent=rec.name,
            host=c.name,
            where=where,
            extra=ORCHESTRATOR_EXTRA.format(host=c.name) if project is None else "",
        )
        env_vars = ["AGENT_AUTH_URL", "AGENT_AUTH_API_KEY", "AGENT_AUTH_SESSION"]
        return SpawnContext(
            conversation_id=conv.id,
            unit=self._unit(conv.id),
            uid=uid,
            workdir=workdir,
            home=home,
            tmp=tmp,
            env=env,
            system_prompt=prompt,
            runtime_session_id=conv.runtime_session_id,
            mcp_servers={
                "agent-auth": {"command": c.agent_auth_mcp, "env_vars": env_vars},
                "sandbox": {
                    "command": c.sandbox_mcp,
                    "env_vars": ["AGENT_AUTH_SANDBOX_SOCKET", "AGENT_AUTH_SANDBOX_TOKEN"],
                },
            },
            model=c.runtimes[conv.runtime].model if conv.runtime in c.runtimes else None,
        )

    def _sync_codex_auth(self, home: Path, into_project: bool) -> None:
        """One subscription login shared by every project: copy the newest
        auth.json each way around a codex process (refresh rotates tokens)."""
        shared = self.config.secrets_dir / "codex-auth.json"
        local = home / ".codex" / "auth.json"
        src, dst = (shared, local) if into_project else (local, shared)
        try:
            if src.exists() and (not dst.exists() or src.stat().st_mtime > dst.stat().st_mtime):
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        except OSError as exc:
            log.warning("codex auth sync: %s", exc)

    async def _ensure_running(self, conv: Conversation, lv: Live) -> Run:
        if lv.run is not None:
            return lv.run
        rec = self.state.agent(conv.agent)
        if rec.project and not (self.state.project(rec.project) or {}).get("sealed"):
            await self.seal_project(rec.project)
        async with self._spawn_slots:
            ctx = self._context(conv, lv)
            if conv.runtime == "codex":
                self._sync_codex_auth(ctx.home, into_project=True)
            run = await self.runtimes[conv.runtime].start(self.host, ctx)
        lv.run, lv.ctx = run, ctx
        if run.runtime_session_id and run.runtime_session_id != conv.runtime_session_id:
            self.state.update_conversation(conv.id, runtime_session_id=run.runtime_session_id)
        self.state.update_conversation(conv.id, state="running")
        lv.pump = self._task(self._pump(conv.id, run), f"pump:{conv.id}")
        return run

    async def deliver(self, conv_id: str, text: str) -> None:
        conv = self.state.conversation(conv_id)
        if conv is None or conv.state == "closed":
            return
        lv = self._live(conv_id)
        self._log(conv_id, "in", text)
        self.state.touch(conv_id)
        if lv.tui and not self.runtimes[conv.runtime].shares_live_process:
            # Claude's TUI holds the session: queue; its prompt hook (or the
            # next headless start) picks these up.
            self.state.queue(conv_id, text)
            return
        async with lv.lock:
            if lv.park_timer:
                lv.park_timer.cancel()
                lv.park_timer = None
            pending = self.state.drain(conv_id)
            run = await self._ensure_running(conv, lv)
            for queued in pending:
                await run.send(queued)
            await run.send(text)

    async def _pump(self, conv_id: str, run: Run) -> None:
        while True:
            event: Event = await run.events.get()
            if event.kind == "text":
                self._log(conv_id, "out", event.text)
            elif event.kind in ("turn_done", "error"):
                if event.kind == "error":
                    self._log(conv_id, "error", event.text)
                conv = self.state.conversation(conv_id)
                if conv:
                    self.state.update_conversation(conv_id, turns=conv.turns + 1)
                if not run.busy:
                    self._schedule_park(conv_id, run)
            elif event.kind == "exit":
                lv = self._live(conv_id)
                if lv.run is run:
                    lv.run = None
                    conv = self.state.conversation(conv_id)
                    if conv and conv.state == "running":
                        self.state.update_conversation(conv_id, state="parked")
                return

    def _schedule_park(self, conv_id: str, run: Run) -> None:
        lv = self._live(conv_id)
        if lv.tui:
            return  # an attached operator decides

        async def park_later():
            await asyncio.sleep(self.config.park_grace_secs)
            await self.park(conv_id, expected=run)

        if lv.park_timer:
            lv.park_timer.cancel()
        lv.park_timer = self._task(park_later(), f"park:{conv_id}")

    async def park(self, conv_id: str, expected: Run | None = None) -> None:
        lv = self._live(conv_id)
        async with lv.lock:
            run = lv.run
            if run is None or (expected is not None and run is not expected) or run.busy:
                return
            lv.run = None
            await run.stop()
            conv = self.state.conversation(conv_id)
            if conv and conv.runtime == "codex" and lv.ctx:
                self._sync_codex_auth(lv.ctx.home, into_project=False)
            if conv and conv.state != "closed":
                self.state.update_conversation(conv_id, state="parked")
        log.info("parked conversation %s", conv_id)

    async def close(self, conv_id: str) -> None:
        conv = self.state.conversation(conv_id)
        if conv is None:
            return
        lv = self._live(conv_id)
        await self.stop_tui(conv_id)
        async with lv.lock:
            if lv.run is not None:
                await lv.run.stop()
                lv.run = None
        self.state.update_conversation(conv_id, state="closed")
        rec = self.state.agent(conv.agent)
        if rec and conv.broker_session_id:
            try:  # ends the conversation's threads (peer_gone) and delegated grants
                await self.broker.close_session(rec.api_key, conv.broker_session_id)
            except BrokerCallError as exc:
                log.info("closing the session of %s: %s", conv_id, exc)
        if lv.watcher:
            lv.watcher.cancel()

    async def _reaper(self) -> None:
        """Ends TUIs nobody is attached to, and notices TUIs that exited."""
        while True:
            await asyncio.sleep(10)
            for conv_id, lv in list(self.live.items()):
                if lv.tui and not await self.host.unit_active(self._tui_unit(conv_id)):
                    await self._tui_ended(conv_id)

    # --- interactive ---------------------------------------------------------------------------

    def tui_socket(self, conv_id: str) -> tuple[Path, Path]:
        """(host path, path inside the unit) of the conversation's tmux socket."""
        conv = self.state.conversation(conv_id)
        rec = self.state.agent(conv.agent)
        project = None if rec.name == self.orchestrator else rec.project
        tmp = self._paths(project)[2]
        return tmp / f"tmux-{conv_id}.sock", Path(f"/tmp/tmux-{conv_id}.sock")

    async def attach(self, conv_id: str, now: bool = False) -> dict[str, Any]:
        """Put the conversation in a TUI (tmux) and return how to attach."""
        conv = self.state.conversation(conv_id)
        if conv is None or conv.state == "closed":
            raise LookupError(f"no open conversation {conv_id}")
        lv = self._live(conv_id)
        runtime = self.runtimes[conv.runtime]
        host_sock, _ = self.tui_socket(conv_id)
        if lv.tui and await self.host.unit_active(self._tui_unit(conv_id)):
            return self._attach_info(conv_id, host_sock)
        async with lv.lock:
            if lv.park_timer:
                lv.park_timer.cancel()
                lv.park_timer = None
            if runtime.shares_live_process:
                # codex: the TUI is a second client of the live app-server.
                run = await self._ensure_running(conv, lv)
            else:
                # claude: one writer per session — the headless process ends
                # at a turn boundary, the TUI resumes the same session.
                if lv.run is not None:
                    deadline = time.monotonic() + (0 if now else 600)
                    while lv.run.busy and time.monotonic() < deadline:
                        await asyncio.sleep(0.5)
                    await lv.run.stop()
                    lv.run = None
                run = None
            ctx = self._context(self.state.conversation(conv_id), lv)
            if conv.runtime == "claude" and not ctx.runtime_session_id:
                import uuid

                ctx.runtime_session_id = str(uuid.uuid4())
                self.state.update_conversation(conv_id, runtime_session_id=ctx.runtime_session_id)
                tui = runtime.tui_argv(ctx, run)
                tui[tui.index("--resume")] = "--session-id"
            else:
                tui = runtime.tui_argv(ctx, run)
            if conv.runtime == "claude":
                tui += ["--settings", json.dumps(self._claude_tui_settings())]
            await self._start_tui(conv_id, ctx, tui)
            lv.tui = True
            self.state.update_conversation(conv_id, state="attached")
        return self._attach_info(conv_id, host_sock)

    def _claude_tui_settings(self) -> dict[str, Any]:
        # Messages that arrive while you're attached are added to your next
        # prompt (agent-auth-sandbox-mcp hook prints them).
        return {
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"type": "command", "command": f"{self.config.sandbox_mcp} hook"}]}
                ]
            }
        }

    async def _start_tui(self, conv_id: str, ctx: SpawnContext, tui: list[str]) -> None:
        host_sock, unit_sock = self.tui_socket(conv_id)
        host_sock.unlink(missing_ok=True)
        tmux = self.config.tmux
        server = ctx.unit_spec([tmux, "-D", "-S", str(unit_sock), "-f", "/dev/null"], f"tui {conv_id}")
        server.name = self._tui_unit(conv_id)
        await self.host.start_detached(server)
        for _ in range(100):
            if host_sock.exists():
                break
            await asyncio.sleep(0.1)
        # The session runs inside the server, so inside the unit's sandbox;
        # when the TUI exits the server goes too and the unit ends.
        command = f"{shlex.join(tui)}; {shlex.quote(tmux)} -S {shlex.quote(str(unit_sock))} kill-server"
        code, out = await self.host.run_as(
            ctx.uid,
            [tmux, "-S", str(host_sock), "new-session", "-d", "-s", "conv", "-c", str(ctx.workdir), "sh", "-c", command],
        )
        if code != 0:
            await self.host.stop_unit(self._tui_unit(conv_id))
            raise RuntimeError(f"tmux new-session failed: {out.strip()[:300]}")

    def _attach_info(self, conv_id: str, host_sock: Path) -> dict[str, Any]:
        conv = self.state.conversation(conv_id)
        rec = self.state.agent(conv.agent)
        project = None if rec.name == self.orchestrator else rec.project
        return {
            "conversation": conv_id,
            "uid": self.project_uid(project),
            "argv": [self.config.tmux, "-S", str(host_sock), "attach", "-t", "conv"],
        }

    async def stop_tui(self, conv_id: str) -> None:
        lv = self._live(conv_id)
        if lv.tui:
            await self.host.stop_unit(self._tui_unit(conv_id))
            await self._tui_ended(conv_id)

    async def _tui_ended(self, conv_id: str) -> None:
        lv = self._live(conv_id)
        lv.tui = False
        conv = self.state.conversation(conv_id)
        if conv is None or conv.state == "closed":
            return
        self.state.update_conversation(conv_id, state="running" if lv.run else "parked")
        if lv.run is not None and not lv.run.busy:
            self._schedule_park(conv_id, lv.run)
        # What arrived while the TUI held the session, headless now.
        queued = self.state.drain(conv_id)
        if queued:
            await self.deliver(conv_id, "\n\n".join(queued))

    # --- logs ------------------------------------------------------------------------------------

    def log_path(self, conv_id: str) -> Path:
        return self.config.state_dir / "logs" / f"{conv_id}.log"

    def _log(self, conv_id: str, direction: str, text: str) -> None:
        try:
            with open(self.log_path(conv_id), "a") as f:
                f.write(json.dumps({"t": time.time(), "dir": direction, "text": text}) + "\n")
        except OSError:
            pass

    # --- what agents and operators ask for (localapi.py) -----------------------------------------

    def conversation_by_token(self, token: str) -> Conversation | None:
        for conv_id, lv in self.live.items():
            if secrets.compare_digest(lv.token, token):
                return self.state.conversation(conv_id)
        return None

    async def mint(self, runtime: str, project: str, why: str, wait_secs: float = 120) -> dict[str, Any]:
        """Ask the broker, as the orchestrator, for <runtime>-<project>-<host>-sandbox."""
        orch = self.state.agent(self.orchestrator)
        if orch is None:
            raise RuntimeError("this VM has no orchestrator key yet (is it paired?)")
        if self.state.project(project) is None:
            raise LookupError(f"create project {project!r} first")
        name = f"{runtime}-{project}-{self.config.name}-sandbox"
        req = await self.broker.request_access(
            orch.api_key,
            {
                "platform": "agents",
                "capability": "mint",
                "resource": name,
                "scope": {"runtime": runtime},
                "justification": why or f"run {runtime} on project {project}",
                "requested_duration": "1h",
            },
        )
        if req["status"] not in ("granted", "denied", "provision_failed"):
            req = await self.broker.wait(orch.api_key, req["id"], wait_secs)
        out = {"agent": name, "request_id": req["id"], "status": req["status"], "reason": req.get("decision_reason")}
        if req["status"] == "granted":
            for _ in range(int(wait_secs * 10)):  # the key follows over the channel
                if self.state.agent(name):
                    break
                await asyncio.sleep(0.1)
            out["key_received"] = self.state.agent(name) is not None
        return out

    async def spawn(self, agent: str, prompt: str, created_by: str, title: str = "") -> Conversation:
        conv = await self.new_conversation(agent, created_by=created_by, title=title or prompt[:80])
        await self.deliver(conv.id, prompt)
        return conv
