"""sandboxd's local APIs: JSON lines over unix sockets.

- agent socket (/run/sandboxd-agent/agent.sock, any uid): the sandbox MCP's
  backend. A caller is the conversation whose token it presents, AND must be
  that conversation's unix user (SO_PEERCRED) — a token leaked to another
  project is useless there. Orchestrator-only calls check it is the
  orchestrator.
- operator socket (/run/sandboxd/operator.sock, root only): `avm` and
  agent-auth-sandboxctl.

Request: {"method": "...", "params": {...}, "token": "..."}
Reply:   {"ok": true, "result": ...} | {"ok": false, "error": "..."}
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
from dataclasses import asdict
from pathlib import Path
from typing import Any, Awaitable, Callable

from .daemon import Sandboxd

log = logging.getLogger(__name__)

MAX_LINE = 1024 * 1024


class ApiError(Exception):
    pass


def peer_uid(writer: asyncio.StreamWriter) -> int:
    sock = writer.get_extra_info("socket")
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


async def _serve_conn(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    handler: Callable[[str, dict, str | None, int], Awaitable[Any]],
) -> None:
    try:
        uid = peer_uid(writer)
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                req = json.loads(line)
                if not isinstance(req, dict) or not isinstance(req.get("method"), str):
                    raise ApiError("bad request")
                params = req.get("params") or {}
                if not isinstance(params, dict):
                    raise ApiError("params must be an object")
                result = await handler(req["method"], params, req.get("token"), uid)
                reply = {"ok": True, "result": result}
            except (ApiError, LookupError, ValueError, RuntimeError) as exc:
                reply = {"ok": False, "error": str(exc)}
            except Exception as exc:
                log.exception("local API %r failed", line[:200])
                reply = {"ok": False, "error": f"internal error: {exc}"}
            writer.write(json.dumps(reply, default=str).encode() + b"\n")
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def serve_unix(path: Path, mode: int, handler) -> asyncio.base_events.Server:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(
        lambda r, w: _serve_conn(r, w, handler), path=str(path), limit=MAX_LINE
    )
    os.chmod(path, mode)
    return server


def _conv(conv) -> dict[str, Any]:
    d = asdict(conv)
    d.pop("broker_session_id", None)
    return d


class AgentApi:
    def __init__(self, sbx: Sandboxd):
        self.sbx = sbx

    async def __call__(self, method: str, params: dict, token: str | None, uid: int) -> Any:
        conv = self.sbx.conversation_by_token(token or "") if token else None
        if conv is None:
            raise ApiError("unknown conversation token")
        rec = self.sbx.state.agent(conv.agent)
        is_orch = rec.name == self.sbx.orchestrator
        if uid != self.sbx.project_uid(None if is_orch else rec.project):
            raise ApiError("this token belongs to another user's conversation")

        def orch_only():
            if not is_orch:
                raise ApiError(f"{method} is for the orchestrator")

        p = params
        if method == "whoami":
            return {
                "agent": rec.name,
                "conversation": conv.id,
                "project": None if is_orch else rec.project,
                "host": self.sbx.config.name,
                "orchestrator": is_orch,
            }
        if method == "project_list":
            return self.sbx.state.projects()
        if method == "conversations":
            return [_conv(c) for c in self.sbx.state.conversations(agent=rec.name)]
        if method == "inbox":
            return self.sbx.state.drain(conv.id) if p.get("drain") else self.sbx.state.peek(conv.id)
        if method == "project_create":
            orch_only()
            out = self.sbx.create_project(str(p["name"]))
            await self.sbx.open_project_for_setup(out["project"])
            return out
        if method == "project_seal":
            orch_only()
            await self.sbx.seal_project(str(p["name"]))
            return {"sealed": p["name"]}
        if method == "agent_mint":
            orch_only()
            return await self.sbx.mint(str(p["runtime"]), str(p["project"]), str(p.get("why") or ""))
        if method == "agent_spawn":
            orch_only()
            new = await self.sbx.spawn(str(p["agent"]), str(p["prompt"]), created_by=f"spawn:{rec.name}")
            return _conv(new)
        raise ApiError(f"unknown method {method!r}")


class OperatorApi:
    SECRETS = {"claude-oauth-token", "codex-auth.json"}

    def __init__(self, sbx: Sandboxd):
        self.sbx = sbx

    async def __call__(self, method: str, params: dict, token: str | None, uid: int) -> Any:
        if uid != 0:
            raise ApiError("operators only")
        s, p = self.sbx, params
        if method == "status":
            return s.status()
        if method == "agents":
            return [{"name": a.name, "runtime": a.runtime, "project": a.project} for a in s.state.agents()]
        if method == "projects":
            return s.state.projects()
        if method == "conversations":
            convs = s.state.conversations(include_closed=bool(p.get("all")))
            if p.get("project"):
                names = {a.name for a in s.state.agents() if a.project == p["project"]}
                convs = [c for c in convs if c.agent in names]
            return [_conv(c) for c in convs]
        if method == "project_create":
            out = s.create_project(str(p["name"]))
            if not p.get("sealed", True):
                await s.open_project_for_setup(out["project"])
            else:
                await s.seal_project(out["project"])
            return out
        if method == "mint":
            return await s.mint(str(p["runtime"]), str(p["project"]), str(p.get("why") or "operator request"))
        if method == "new":
            agent = str(p["agent"])
            if s.state.agent(agent) is None:
                raise LookupError(f"no key for {agent} in this VM (mint it first)")
            conv = await s.new_conversation(agent, created_by="operator", title=str(p.get("title") or ""))
            if p.get("prompt"):
                await s.deliver(conv.id, str(p["prompt"]))
            if p.get("attach", True):
                return {"conversation": _conv(s.state.conversation(conv.id)), "attach": await s.attach(conv.id)}
            return {"conversation": _conv(s.state.conversation(conv.id))}
        if method == "attach":
            return await s.attach(str(p["conversation"]), now=bool(p.get("now")))
        if method == "send":
            await s.deliver(str(p["conversation"]), str(p["text"]))
            return {"sent": True}
        if method == "stop":
            await s.stop_tui(str(p["conversation"]))
            await s.park(str(p["conversation"]))
            return {"parked": p["conversation"]}
        if method == "close":
            await s.close(str(p["conversation"]))
            return {"closed": p["conversation"]}
        if method == "log_path":
            return str(s.log_path(str(p["conversation"])))
        if method == "shell":
            project = str(p["project"])
            workdir = s._paths(project)[0]
            return {"uid": s.project_uid(project), "workdir": str(workdir)}
        if method == "secret_set":
            name = str(p["name"])
            if name not in self.SECRETS:
                raise ApiError(f"secrets: {', '.join(sorted(self.SECRETS))}")
            s.host.write_file(s.config.secrets_dir / name, str(p["value"]), None, 0o600)
            return {"stored": name}
        raise ApiError(f"unknown method {method!r}")
