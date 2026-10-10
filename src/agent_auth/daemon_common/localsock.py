"""JSON lines over a unix socket, with the caller's uid from SO_PEERCRED:
the local APIs of sandboxd (agents, operators) and hostd (hostctl).

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
from pathlib import Path
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)

MAX_LINE = 1024 * 1024


class ApiError(Exception):
    pass


class LocalApiError(Exception):
    """Client side: the daemon said no, or didn't answer."""


def peer_uid(writer: asyncio.StreamWriter) -> int:
    sock = writer.get_extra_info("socket")
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


def peer_pid(writer: asyncio.StreamWriter) -> int:
    sock = writer.get_extra_info("socket")
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[0]


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


def call(path: str, method: str, params: dict[str, Any] | None = None, token: str | None = None,
         timeout: float = 600) -> Any:
    """Synchronous client: one request, one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps({"method": method, "params": params or {}, "token": token}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    reply = json.loads(buf or b"{}")
    if not reply.get("ok"):
        raise LocalApiError(reply.get("error") or "no reply from the daemon")
    return reply.get("result")
