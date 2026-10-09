from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..host import Host, UnitSpec


@dataclass
class Event:
    kind: str  # "text" (assistant output) | "turn_done" | "error" | "exit"
    text: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SpawnContext:
    """Everything a runtime needs to start one conversation's process."""

    conversation_id: str
    unit: str
    uid: int
    workdir: Path
    home: Path
    tmp: Path  # the host path bound to /tmp in the unit
    env: dict[str, str]  # secrets included; goes into the root-only env file
    system_prompt: str
    # The runtime's own session/thread id: None = new conversation.
    runtime_session_id: str | None
    mcp_servers: dict[str, dict[str, Any]]  # name -> {"command", "args", "env_vars"}
    read_write: list[Path] = field(default_factory=list)
    model: str | None = None
    # Hook commands by event name (claude: PostToolUse, UserPromptSubmit).
    hooks: dict[str, str] = field(default_factory=dict)

    def unit_spec(self, argv: list[str], description: str) -> UnitSpec:
        return UnitSpec(
            name=self.unit,
            uid=self.uid,
            argv=argv,
            workdir=self.workdir,
            home=self.home,
            tmp=self.tmp,
            env=self.env,
            read_write=self.read_write,
            description=description,
        )


class Run(Protocol):
    """One live process of a conversation."""

    runtime_session_id: str | None
    events: asyncio.Queue[Event]

    @property
    def busy(self) -> bool: ...
    async def send(self, text: str) -> None: ...
    async def stop(self) -> None: ...


class Runtime(Protocol):
    name: str
    # Whether an interactive TUI can join the live process (codex app-server)
    # or must take the session over (claude: stop, then resume in the TUI).
    shares_live_process: bool
    # Whether a message for a busy process should wait in the inbox for the
    # runtime's own hook to pick up mid-turn (claude's PostToolUse), instead
    # of being written to the process (codex steers the running turn itself).
    doorbell: bool

    async def start(self, host: Host, ctx: SpawnContext) -> Run: ...
    def tui_argv(self, ctx: SpawnContext, run: Run | None) -> list[str]: ...
    # One-shot, tool-less call for routing triage: the prompt goes to stdin,
    # triage_answer() extracts the model's reply from stdout.
    def triage_argv(self, model: str | None) -> list[str]: ...
    def triage_answer(self, stdout: str) -> str: ...
