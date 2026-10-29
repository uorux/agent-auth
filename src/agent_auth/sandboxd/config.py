"""sandboxd's configuration: one JSON file written by its NixOS module."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_ENV = "AGENT_AUTH_SANDBOXD_CONFIG"


@dataclass
class RuntimeConfig:
    command: str  # the runtime's binary (claude / codex), unwrapped
    model: str | None = None


@dataclass
class Config:
    broker_url: str
    broker_public_key: str
    name: str  # the physical host's name: agents are <runtime>-<project>-<name>-sandbox
    state_dir: Path = Path("/var/lib/sandboxd")
    sandbox_root: Path = Path("/var/lib/sandbox")
    userdb_dir: Path = Path("/var/lib/userdb")
    runtime_dir: Path = Path("/run/sandboxd")  # root only: env files, operator socket
    agent_socket: Path = Path("/run/sandboxd-agent/agent.sock")  # every agent unit
    runtimes: dict[str, RuntimeConfig] = field(default_factory=dict)
    # PATH inside agent units (git, nix, coreutils, …, and the MCP servers).
    agent_path: str = "/run/current-system/sw/bin"
    agent_auth_mcp: str = "agent-auth-mcp"
    sandbox_mcp: str = "agent-auth-sandbox-mcp"
    mcp_bridge: str = "agent-auth-mcp-bridge"
    tmux: str = "tmux"
    systemd_run: str = "systemd-run"
    systemctl: str = "systemctl"
    setfacl: str = "setfacl"
    # Which runtime the orchestrator runs (any configured one).
    orchestrator_runtime: str = "claude"
    uid_base: int = 40000
    uid_max: int = 49999
    park_grace_secs: float = 30
    # Routing triage (docs/sandbox-design.md §6.3 rule 3): when a new thread
    # could continue one of the agent's conversations, a one-shot cheap-model
    # call decides. Off = always a new conversation unless the opener hints.
    triage: bool = True
    triage_runtime: str | None = None  # default: the orchestrator's runtime
    triage_model: str | None = None  # default: the runtime's cheap model
    triage_timeout_secs: float = 60
    interactive_idle_secs: float = 1800
    max_processes: int = 16
    max_processes_per_project: int = 4
    unit_memory_max: str = "8G"
    unit_tasks_max: int = 4096

    @property
    def secrets_dir(self) -> Path:
        return self.state_dir / "secrets"

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        path = path or os.environ.get(CONFIG_ENV) or "/etc/agent-auth/sandboxd.json"
        raw = json.loads(Path(path).read_text())
        runtimes = {k: RuntimeConfig(**v) for k, v in raw.pop("runtimes", {}).items()}
        for key in ("state_dir", "sandbox_root", "userdb_dir", "runtime_dir", "agent_socket"):
            if key in raw:
                raw[key] = Path(raw[key])
        return cls(runtimes=runtimes, **raw)
