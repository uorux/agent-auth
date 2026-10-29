"""Synchronous client for sandboxd's local sockets (MCP shim, sandboxctl)."""

from __future__ import annotations

import os
from typing import Any

from ..daemon_common.localsock import LocalApiError, call

__all__ = ["LocalApiError", "agent_call", "call", "operator_call"]

AGENT_SOCKET_ENV = "AGENT_AUTH_SANDBOX_SOCKET"
TOKEN_ENV = "AGENT_AUTH_SANDBOX_TOKEN"
OPERATOR_SOCKET = "/run/sandboxd/operator.sock"


def agent_call(method: str, params: dict[str, Any] | None = None) -> Any:
    return call(
        os.environ.get(AGENT_SOCKET_ENV, "/run/sandboxd-agent/agent.sock"),
        method,
        params,
        token=os.environ.get(TOKEN_ENV),
    )


def operator_call(method: str, params: dict[str, Any] | None = None) -> Any:
    return call(os.environ.get("AGENT_AUTH_SANDBOXD_OPERATOR", OPERATOR_SOCKET), method, params)
