"""Synchronous client for sandboxd's local sockets (MCP shim, sandboxctl)."""

from __future__ import annotations

import json
import os
import socket
from typing import Any

AGENT_SOCKET_ENV = "AGENT_AUTH_SANDBOX_SOCKET"
TOKEN_ENV = "AGENT_AUTH_SANDBOX_TOKEN"
OPERATOR_SOCKET = "/run/sandboxd/operator.sock"


class LocalApiError(Exception):
    pass


def call(path: str, method: str, params: dict[str, Any] | None = None, token: str | None = None,
         timeout: float = 600) -> Any:
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
        raise LocalApiError(reply.get("error") or "no reply from sandboxd")
    return reply.get("result")


def agent_call(method: str, params: dict[str, Any] | None = None) -> Any:
    return call(
        os.environ.get(AGENT_SOCKET_ENV, "/run/sandboxd-agent/agent.sock"),
        method,
        params,
        token=os.environ.get(TOKEN_ENV),
    )


def operator_call(method: str, params: dict[str, Any] | None = None) -> Any:
    return call(os.environ.get("AGENT_AUTH_SANDBOXD_OPERATOR", OPERATOR_SOCKET), method, params)
