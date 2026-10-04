"""agent-auth-sandbox-mcp: the sandbox MCP server agents in an agent VM get
(docs/sandbox-design.md §6.5), plus `hook`, claude's UserPromptSubmit hook
for attached TUIs."""

from __future__ import annotations

import json
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import LocalApiError, agent_call

INSTRUCTIONS = """\
You are running in an agent VM, as one project's agent (or as the VM's
orchestrator). These tools describe and manage the VM itself; access to
anything outside it (GitHub, homelab, Kubernetes, other agents) goes through
the agent-auth MCP server instead.

sandbox_whoami tells you your agent name, project and conversation. a2a
messages arrive as turns starting with "[a2a]"; answer them with agent-auth's
a2a_send. The orchestrator alone uses project_create, project_seal,
agent_mint and agent_spawn to set projects and their agents up.\
"""

mcp = FastMCP("sandbox", instructions=INSTRUCTIONS)


def _safe(method: str, params: dict[str, Any] | None = None) -> str:
    try:
        return json.dumps(agent_call(method, params), indent=2, default=str)
    except LocalApiError as exc:
        return json.dumps({"error": str(exc)})
    except OSError as exc:
        return json.dumps({"error": f"sandboxd unreachable: {exc}"})


@mcp.tool()
def sandbox_whoami() -> str:
    """Your agent name, project, conversation id, and whether you are the
    orchestrator."""
    return _safe("whoami")


@mcp.tool()
def project_list() -> str:
    """Projects in this VM. Each has its own directory under
    /var/lib/sandbox/projects and its own unix user; reading another project
    needs a "sandbox" grant (request_access platform="sandbox",
    capability="project.read", resource=<project>)."""
    return _safe("project_list")


@mcp.tool()
def conversations() -> str:
    """Your agent's conversations in this VM (running, parked, attached).
    To continue one from another agent, the opener of an a2a thread can put
    {"_sandbox": {"conversation": "<id>"}} in its first message."""
    return _safe("conversations")


@mcp.tool()
def inbox() -> str:
    """Messages queued for this conversation that haven't been delivered yet
    (normally they arrive as turns on their own)."""
    return _safe("inbox", {"drain": False})


@mcp.tool()
def project_create(name: str) -> str:
    """Orchestrator: create a project (lowercase letters, digits, '-', ≤30):
    its directory, its own unix user, and write access for you until
    project_seal. Then put the code there (git clone with a github grant)."""
    return _safe("project_create", {"name": name})


@mcp.tool()
def project_seal(name: str) -> str:
    """Orchestrator: hand the project over to its own user and drop your write
    access. Spawning one of its agents seals it automatically."""
    return _safe("project_seal", {"name": name})


@mcp.tool()
def agent_mint(runtime: str, project: str, why: str = "") -> str:
    """Orchestrator: ask the broker for <runtime>-<project>-<host>-sandbox
    (runtime "claude" or "codex"; the project must exist). Waits for the
    decision (a human may be asked); the key goes to sandboxd, not to you.
    Minting an existing agent renews its lease."""
    return _safe("agent_mint", {"runtime": runtime, "project": project, "why": why})


@mcp.tool()
def agent_spawn(agent: str, prompt: str) -> str:
    """Orchestrator: start a new conversation of a minted agent with `prompt`
    as its first message (e.g. "set up the dev shell and report back on
    thread X"). Returns the conversation id."""
    return _safe("agent_spawn", {"agent": agent, "prompt": prompt})


def hook() -> None:
    """claude UserPromptSubmit hook: hand queued a2a messages to the next
    prompt of an attached TUI."""
    try:
        queued = agent_call("inbox", {"drain": True}) or []
    except Exception:
        queued = []
    if queued:
        context = "Messages that arrived for this conversation while you were working:\n\n" + "\n\n".join(queued)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": context}}))


def run() -> None:
    if sys.argv[1:2] == ["hook"]:
        hook()
        return
    mcp.run()
