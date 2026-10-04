"""Headless claude / codex behind one interface (docs/sandbox-design.md §6.4)."""

from .base import Event, Run, Runtime, SpawnContext
from .claude import ClaudeRuntime
from .codex import CodexRuntime

__all__ = ["ClaudeRuntime", "CodexRuntime", "Event", "Run", "Runtime", "SpawnContext"]
