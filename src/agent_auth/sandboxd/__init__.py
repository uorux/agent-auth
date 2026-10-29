"""sandboxd: the daemon inside an agent VM (docs/sandbox-design.md §6).

It holds the VM's agent identities (keys delivered by the broker, to it
alone), is the a2a dispatcher for all of them, runs claude/codex headless per
conversation in sandboxed systemd units as per-project users, parks idle
processes and resumes them, and serves the sandbox MCP (agents) and the
operator API (`avm`). Imports nothing server-side.
"""
