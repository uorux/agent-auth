"""Claude Code headless: `claude -p` with stream-json in and out.

Verified (2026-10-03, Claude Code 2.1.280; docs/sandbox-design.md §6.4): the
chosen --session-id is honoured; --resume continues the same id and
transcript; one process takes many turns — each user line written after a
`result` starts the next turn, and lines written mid-turn queue up as turns of
their own. The TUI resumes the same session (`claude --resume <id>`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from ..host import Host
from .base import Event, SpawnContext

log = logging.getLogger(__name__)


def mcp_config(ctx: SpawnContext) -> str:
    # stdio MCP servers inherit claude's environment, keys included; the file
    # itself holds none.
    return json.dumps(
        {
            "mcpServers": {
                name: {"command": s["command"], "args": s.get("args", [])}
                for name, s in ctx.mcp_servers.items()
            }
        }
    )


class ClaudeRun:
    def __init__(self, host: Host, ctx: SpawnContext, proc: asyncio.subprocess.Process, sid: str):
        self.host, self.ctx, self.proc = host, ctx, proc
        self.runtime_session_id = sid
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self._pending_turns = 0
        self._reader = asyncio.create_task(self._read())

    @property
    def busy(self) -> bool:
        return self._pending_turns > 0

    async def _read(self) -> None:
        assert self.proc.stdout is not None
        try:
            async for raw in self.proc.stdout:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                kind = msg.get("type")
                if kind == "system" and msg.get("session_id"):
                    self.runtime_session_id = msg["session_id"]
                elif kind == "assistant":
                    text = "".join(
                        c.get("text", "")
                        for c in (msg.get("message") or {}).get("content", [])
                        if isinstance(c, dict) and c.get("type") == "text"
                    )
                    if text:
                        await self.events.put(Event("text", text))
                elif kind == "result":
                    self._pending_turns = max(0, self._pending_turns - 1)
                    await self.events.put(
                        Event(
                            "error" if msg.get("is_error") else "turn_done",
                            msg.get("result") or "",
                            {"pending": self._pending_turns},
                        )
                    )
        finally:
            code = await self.proc.wait()
            await self.events.put(Event("exit", data={"code": code}))

    async def send(self, text: str) -> None:
        assert self.proc.stdin is not None
        line = json.dumps({"type": "user", "message": {"role": "user", "content": text}})
        self._pending_turns += 1
        self.proc.stdin.write(line.encode() + b"\n")
        await self.proc.stdin.drain()

    async def stop(self) -> None:
        if self.proc.returncode is None:
            await self.host.stop_unit(self.ctx.unit)
            try:
                await asyncio.wait_for(self.proc.wait(), 15)
            except TimeoutError:
                self.proc.kill()
        await asyncio.gather(self._reader, return_exceptions=True)


class ClaudeRuntime:
    name = "claude"
    shares_live_process = False

    def __init__(self, command: str, model: str | None = None):
        self.command = command
        self.model = model

    def _common(self, ctx: SpawnContext) -> list[str]:
        argv = [
            "--append-system-prompt", ctx.system_prompt,
            "--mcp-config", mcp_config(ctx),
            "--permission-mode", "bypassPermissions",
        ]
        model = ctx.model or self.model
        if model:
            argv += ["--model", model]
        return argv

    async def start(self, host: Host, ctx: SpawnContext) -> ClaudeRun:
        sid = ctx.runtime_session_id or str(uuid.uuid4())
        session_args = ["--resume", sid] if ctx.runtime_session_id else ["--session-id", sid]
        argv = [
            self.command, "-p",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--verbose",
            *self._common(ctx),
            *session_args,
        ]
        proc = await host.start_piped(ctx.unit_spec(argv, f"claude conversation {ctx.conversation_id}"))
        return ClaudeRun(host, ctx, proc, sid)

    def tui_argv(self, ctx: SpawnContext, run=None) -> list[str]:
        argv = [self.command, *self._common(ctx)]
        if ctx.runtime_session_id:
            argv += ["--resume", ctx.runtime_session_id]
        return argv
