"""Codex headless: `codex app-server` on a unix socket, driven as a client.

Verified (2026-10-03, codex-cli 0.156.1; the socket and the handshake again
on 0.161.0, 2026-10-10; docs/sandbox-design.md §6.4):
JSON-RPC over WebSocket on the socket; several clients can share one server
(after thread/resume each gets the thread's events), which is how an
operator's TUI (`codex --remote unix://… resume <thread>`) joins a live
conversation. turn/steer adds input to a running turn. The rollout (what
thread/resume needs) is written at the first turn, or when the thread is
named (thread/name/set; 0.161.0), which is what makes a new conversation
attachable at once.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
from pathlib import Path
from typing import Any

import websockets
from websockets.asyncio.client import unix_connect

from ..host import Host
from .base import Event, SpawnContext

log = logging.getLogger(__name__)

SOCKET_WAIT_SECS = 30


def _toml_str(s: str) -> str:
    return json.dumps(s)  # a JSON string is a valid TOML basic string


def socket_on_host(path: Path, tmp: Path) -> Path:
    """Where the app-server's socket is, seen from outside its unit. codex
    (0.161) leaves a symlink at the path it was given, to the real socket
    under /tmp/codex-daemon-<uid>/: the unit's /tmp, which is `tmp` here."""
    try:
        target = Path(os.readlink(path))
    except OSError:
        return path
    if target.is_absolute() and target.parts[1:2] == ("tmp",) and ".." not in target.parts:
        return tmp.joinpath(*target.parts[2:])
    return path


def connect_unix(path: Path) -> socket.socket:
    """A connected stream socket. The real socket's path (the project's tmp
    dir + codex-daemon-<uid>/<64 hex>) is longer than a unix address may be
    (108 bytes), so it is reached through its directory's descriptor."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dir_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        sock.connect(f"/proc/self/fd/{dir_fd}/{path.name}")
    except BaseException:
        sock.close()
        raise
    finally:
        os.close(dir_fd)
    sock.setblocking(False)
    return sock


class CodexRun:
    def __init__(self, host: Host, ctx: SpawnContext, socket_host_path):
        self.host, self.ctx, self.socket_host_path = host, ctx, socket_host_path
        self.runtime_session_id: str | None = ctx.runtime_session_id
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self._ws = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._turn_id: str | None = None
        self._queued: list[str] = []
        self._reader: asyncio.Task | None = None
        self._send_lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._turn_id is not None or bool(self._queued)

    async def connect(self) -> None:
        for _ in range(SOCKET_WAIT_SECS * 10):
            if (sock := socket_on_host(self.socket_host_path, self.ctx.tmp)).is_socket():
                break
            await asyncio.sleep(0.1)
        else:
            await self.host.stop_unit(self.ctx.unit)
            raise RuntimeError(
                f"codex app-server did not open its socket within {SOCKET_WAIT_SECS} s"
                f" (in the VM: journalctl -u {self.ctx.unit})"
            )
        self._ws = await unix_connect(sock=connect_unix(sock), uri="ws://localhost/")
        self._reader = asyncio.create_task(self._read())
        await self._call("initialize", {"clientInfo": {"name": "sandboxd", "version": "1"}})
        base = {
            "cwd": str(self.ctx.workdir),
            "approvalPolicy": "never",
            "sandbox": "danger-full-access",  # the unit is the sandbox
            "developerInstructions": self.ctx.system_prompt,
        }
        if self.ctx.model:
            base["model"] = self.ctx.model
        if self.runtime_session_id:
            result = await self._call("thread/resume", {**base, "threadId": self.runtime_session_id})
        else:
            result = await self._call("thread/start", base)
        self.runtime_session_id = result["thread"]["id"]
        if not self.ctx.runtime_session_id:
            # A thread has no rollout until its first turn, and without one
            # no second client (the operator's TUI) can resume it. Naming it
            # writes the rollout, and adds nothing to what the model sees.
            try:
                await self._call(
                    "thread/name/set",
                    {"threadId": self.runtime_session_id, "name": f"conversation {self.ctx.conversation_id}"},
                )
            except RuntimeError as exc:
                log.warning("codex: could not name the new thread (the TUI may not attach before a turn): %s", exc)

    async def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        rid = self._next_id
        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        async with self._send_lock:
            await self._ws.send(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
        msg = await asyncio.wait_for(fut, 120)
        if "error" in msg:
            raise RuntimeError(f"codex {method}: {msg['error'].get('message', msg['error'])}")
        return msg.get("result") or {}

    async def _read(self) -> None:
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if "id" in msg and ("result" in msg or "error" in msg):
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                    continue
                method, params = msg.get("method"), msg.get("params") or {}
                if params.get("threadId") not in (None, self.runtime_session_id):
                    continue
                if method == "turn/started":
                    self._turn_id = params["turn"]["id"]
                elif method == "item/completed":
                    item = params.get("item") or {}
                    if item.get("type") == "agentMessage" and item.get("text"):
                        await self.events.put(Event("text", item["text"]))
                elif method == "turn/completed":
                    self._turn_id = None
                    error = (params.get("turn") or {}).get("error")
                    await self.events.put(
                        Event("error" if error else "turn_done", json.dumps(error) if error else "")
                    )
                    if self._queued:
                        await self._start_turn(self._queued.pop(0))
                elif method == "error" and not params.get("willRetry"):
                    await self.events.put(Event("error", json.dumps(params.get("error"))))
        except websockets.ConnectionClosed:
            pass
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("codex app-server went away"))
            await self.events.put(Event("exit"))

    def _input(self, text: str) -> list[dict[str, Any]]:
        return [{"type": "text", "text": text}]

    async def _start_turn(self, text: str) -> None:
        result = await self._call("turn/start", {"threadId": self.runtime_session_id, "input": self._input(text)})
        self._turn_id = (result.get("turn") or {}).get("id") or self._turn_id

    async def send(self, text: str) -> None:
        if self._turn_id is None:
            await self._start_turn(text)
            return
        try:
            # Mid-turn: join the running turn instead of waiting for its end.
            await self._call(
                "turn/steer",
                {"threadId": self.runtime_session_id, "expectedTurnId": self._turn_id, "input": self._input(text)},
            )
        except (RuntimeError, ConnectionError):
            self._queued.append(text)  # the turn ended meanwhile: next one

    async def stop(self) -> None:
        if self._ws is not None:
            await self._ws.close()
        await self.host.stop_unit(self.ctx.unit)
        if self._reader:
            await asyncio.gather(self._reader, return_exceptions=True)


class CodexRuntime:
    name = "codex"
    shares_live_process = True
    doorbell = False  # turn/steer delivers into a running turn

    def __init__(self, command: str, model: str | None = None):
        self.command = command
        self.model = model

    def socket_name(self, ctx: SpawnContext) -> str:
        return f"codex-{ctx.conversation_id}.sock"

    async def start(self, host: Host, ctx: SpawnContext) -> CodexRun:
        sock = self.socket_name(ctx)
        (ctx.tmp / sock).unlink(missing_ok=True)
        argv = [self.command, "app-server", "--listen", f"unix:///tmp/{sock}"]
        for name, server in ctx.mcp_servers.items():
            prefix = f"mcp_servers.{name}"
            argv += ["-c", f"{prefix}.command={_toml_str(server['command'])}"]
            if server.get("args"):
                argv += ["-c", f"{prefix}.args={json.dumps(server['args'])}"]
            # codex hands MCP servers a scrubbed environment: name what passes.
            if server.get("env_vars"):
                argv += ["-c", f"{prefix}.env_vars={json.dumps(server['env_vars'])}"]
        await host.start_detached(ctx.unit_spec(argv, f"codex conversation {ctx.conversation_id}"))
        run = CodexRun(host, ctx, ctx.tmp / sock)
        if ctx.model is None:
            ctx.model = self.model
        await run.connect()
        return run

    def tui_argv(self, ctx: SpawnContext, run=None) -> list[str]:
        argv = [self.command, "--remote", f"unix:///tmp/{self.socket_name(ctx)}", "resume"]
        if ctx.runtime_session_id:
            argv.append(ctx.runtime_session_id)
        return argv

    def triage_argv(self, model: str | None) -> list[str]:
        # NOT verified against a live codex: `exec -` reads the prompt from
        # stdin and prints the final message on stdout (progress on stderr).
        argv = [self.command, "exec", "--skip-git-repo-check", "--ephemeral", "-s", "read-only"]
        if model or self.model:
            argv += ["-m", model or self.model]
        return argv + ["-"]

    def triage_answer(self, stdout: str) -> str:
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        return lines[-1] if lines else ""
