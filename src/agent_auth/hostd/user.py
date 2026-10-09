"""hostd-user: the part of hostd that lives in your desktop session.

It holds no secrets and decides nothing. It tells hostd (root) whether you
are at this desktop, shows the approval prompts hostd passes on, and sends
back which button you pressed. It talks to hostd over a unix socket that
only listens to the configured user.

Anything else running as you on this host can do the same: connect and
answer "allow". Which requests may be asked on a desktop at all is therefore
the broker's policy (`desktop:`), and an answer here never opens a shell or
satisfies a host's own TOTP/arming check.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

from .config import HostConfig

log = logging.getLogger(__name__)

PRESENCE_SECS = 10
DEFAULT_PROMPT = [
    "zenity", "--question", "--no-markup", "--width", "560",
    "--title", "{title}", "--text", "{text}", "--timeout", "{timeout}",
    "--ok-label", "Allow once", "--cancel-label", "Deny",
    "--extra-button", "Mute agent 1h", "--extra-button", "Send to Discord",
]
# What the dialog printed → the answer. zenity prints an extra button's
# label; sbx-prompt prints once | session | deny.
STDOUT_ANSWERS = {
    "mute agent 1h": "mute", "mute": "mute",
    "send to discord": "discord", "discord": "discord",
    "once": "allow", "session": "allow", "allow": "allow",
    "deny": "deny",
}
ZENITY_TIMEOUT = 5


def parse_answer(returncode: int, stdout: str) -> str:
    word = stdout.strip().lower()
    if word in STDOUT_ANSWERS:
        return STDOUT_ANSWERS[word]
    if returncode == 0:
        return "allow"
    if returncode == ZENITY_TIMEOUT:
        return "timeout"
    return "deny"


async def _output(*argv: str, timeout: float = 5) -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except (OSError, TimeoutError):
        return None
    return out.decode(errors="replace") if proc.returncode == 0 else None


async def _fullscreen() -> bool:
    """Hyprland: is the focused window fullscreen (not merely maximized)?"""
    if not os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return False
    out = await _output("hyprctl", "activewindow", "-j")
    try:
        value = json.loads(out or "{}").get("fullscreen", 0)
    except ValueError:
        return False
    return value is True or (isinstance(value, int) and value >= 2)


async def _logind() -> tuple[float | None, bool | None]:
    """(idle seconds, locked) from logind's hints for the user's display
    session — only meaningful where the desktop maintains them."""
    session = (await _output("loginctl", "show-user", str(os.getuid()), "-p", "Display", "--value") or "").strip()
    if not session:
        return None, None
    out = await _output(
        "loginctl", "show-session", session, "-p", "IdleHint", "-p", "IdleSinceHint", "-p", "LockedHint"
    )
    if out is None:
        return None, None
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    locked = {"yes": True, "no": False}.get(props.get("LockedHint", ""))
    if props.get("IdleHint") == "no":
        return 0.0, locked
    try:
        since = int(props.get("IdleSinceHint", "0")) / 1e6
    except ValueError:
        return None, locked
    return (max(0.0, time.time() - since) if since else None), locked


class UserHelper:
    def __init__(self, config: HostConfig):
        self.config = config
        self.fresh = True  # the first report after this process started
        self._dialog_lock = asyncio.Lock()
        self._current: tuple[str, asyncio.subprocess.Process] | None = None
        self._cancelled: set[str] = set()

    async def presence(self) -> dict[str, Any]:
        idle, locked = (None, None)
        if self.config.desktop.idle_source == "logind":
            idle, locked = await _logind()
        report = {
            "type": "presence",
            "idle_secs": idle,
            "locked": locked,
            "fullscreen": await _fullscreen(),
            "fresh": self.fresh,
        }
        self.fresh = False
        return report

    async def show(self, prompt: dict[str, Any]) -> str:
        """One dialog at a time; later ones wait their turn."""
        prompt_id = prompt["id"]
        async with self._dialog_lock:
            if prompt_id in self._cancelled:
                self._cancelled.discard(prompt_id)
                return "timeout"
            fields = {
                "title": str(prompt.get("title", "agent-auth")),
                "text": str(prompt.get("text", "")),
                "timeout": str(int(prompt.get("timeout", 90))),
            }
            template = self.config.desktop.prompt_command or DEFAULT_PROMPT
            # Substituted per argument: the text is never parsed by a shell.
            argv = [fields.get(arg[1:-1], arg) if arg.startswith("{") and arg.endswith("}") else arg for arg in template]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
                )
            except OSError as exc:
                log.error("could not show the prompt (%s): %s", argv[0], exc)
                return "timeout"
            self._current = (prompt_id, proc)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), int(fields["timeout"]) + 10)
            except TimeoutError:
                proc.kill()
                return "timeout"
            finally:
                self._current = None
            if prompt_id in self._cancelled:
                self._cancelled.discard(prompt_id)
                return "timeout"
            return parse_answer(proc.returncode or 0, out.decode(errors="replace"))

    def cancel(self, prompt_id: str) -> None:
        self._cancelled.add(prompt_id)
        if self._current and self._current[0] == prompt_id:
            try:
                self._current[1].terminate()
            except ProcessLookupError:
                pass

    async def session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async def send(msg: dict[str, Any]) -> None:
            writer.write(json.dumps(msg).encode() + b"\n")
            await writer.drain()

        async def report() -> None:
            while True:
                await send(await self.presence())
                await asyncio.sleep(PRESENCE_SECS)

        async def answer(prompt: dict[str, Any]) -> None:
            await send({"type": "answer", "id": prompt["id"], "answer": await self.show(prompt)})

        tasks = {asyncio.create_task(report())}
        try:
            while line := await reader.readline():
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("type") == "prompt" and isinstance(msg.get("id"), str):
                    task = asyncio.create_task(answer(msg))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                elif msg.get("type") == "cancel" and isinstance(msg.get("id"), str):
                    self.cancel(msg["id"])
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def run_user(config: HostConfig) -> None:
    helper = UserHelper(config)
    while True:
        try:
            reader, writer = await asyncio.open_unix_connection(str(config.user_socket))
        except OSError:
            await asyncio.sleep(5)
            continue
        log.info("connected to hostd")
        try:
            await helper.session(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
        await asyncio.sleep(2)
