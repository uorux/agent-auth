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
import html
import json
import logging
import os
import plistlib
import re
import time
from typing import Any

from .config import HostConfig, darwin

log = logging.getLogger(__name__)

PRESENCE_SECS = 10
DEFAULT_PROMPT = [
    # --default-cancel: a stray Enter (typing as the dialog appears) denies.
    "zenity", "--question", "--no-markup", "--default-cancel", "--width", "560",
    "--title", "{title}", "--text", "{text}", "--timeout", "{timeout}",
    "--ok-label", "Allow once", "--cancel-label", "Deny",
    "--extra-button", "Mute agent 1h", "--extra-button", "Send to Discord",
]
# What the dialog printed → the answer. zenity prints an extra button's
# label; sbx-prompt prints once | session | deny; the macOS dialog prints
# allow | discord | timeout (and fails on Deny).
STDOUT_ANSWERS = {
    "mute agent 1h": "mute", "mute": "mute",
    "send to discord": "discord", "discord": "discord",
    "once": "allow", "session": "allow", "allow": "allow",
    "deny": "deny",
    "timeout": "timeout",
}


def _osascript(lines: list[str], *args: str) -> list[str]:
    """AppleScript whose inputs are the run handler's arguments: an agent's
    text is never part of the script."""
    command = ["/usr/bin/osascript"]
    for line in lines:
        command += ["-e", line]
    return [*command, *args]


# macOS: AppleScript dialogs have at most three buttons, so there is no
# "Mute agent 1h" here. Deny is the default and the cancel button: a stray
# Enter denies, and so does Escape.
DARWIN_PROMPT = _osascript(
    [
        "on run argv",
        'set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Deny", '
        '"Send to Discord", "Allow once"} default button "Deny" cancel button "Deny" '
        "giving up after ((item 3 of argv) as integer) with icon caution",
        'if gave up of r then return "timeout"',
        'if button returned of r is "Allow once" then return "allow"',
        'if button returned of r is "Send to Discord" then return "discord"',
        'return "deny"',
        "end run",
    ],
    "{title}", "{text}", "{timeout}",
)
DARWIN_NOTIFY = _osascript(
    ["on run argv", "display notification (item 2 of argv) with title (item 1 of argv)", "end run"],
    "{title}", "{text}",
)


def default_prompt() -> list[str]:
    return DARWIN_PROMPT if darwin() else DEFAULT_PROMPT
ZENITY_TIMEOUT = 5


def _fill(template: list[str], fields: dict[str, str]) -> list[str]:
    """Placeholders are whole arguments: nothing here is parsed by a shell."""
    return [fields.get(arg[1:-1], arg) if arg.startswith("{") and arg.endswith("}") else arg for arg in template]


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


async def _busy(argv: list[str]) -> bool:
    """desktop.busy_command: exit 0 = don't show prompts now. A command that
    can't be run or doesn't answer counts as busy (unknown is away)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        return await asyncio.wait_for(proc.wait(), 5) == 0
    except (OSError, TimeoutError):
        return True


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


def parse_hid_idle(ioreg_text: str) -> float | None:
    """Seconds since the last keyboard/mouse input, from `ioreg -c IOHIDSystem`."""
    m = re.search(r'"HIDIdleTime" = (\d+)', ioreg_text)
    return int(m.group(1)) / 1e9 if m else None


def parse_console_locked(ioreg_plist: bytes, uid: int) -> bool | None:
    """Is `uid`'s console session locked (or switched away from)? From
    `ioreg -n Root -d 1 -a`; None when it can't be told."""
    try:
        root = plistlib.loads(ioreg_plist)
    except (ValueError, plistlib.InvalidFileException):
        return None
    if isinstance(root, list):
        root = root[0] if root else {}
    users = root.get("IOConsoleUsers") if isinstance(root, dict) else None
    for entry in users or []:
        if isinstance(entry, dict) and entry.get("kCGSSessionUserIDKey") == uid:
            return bool(entry.get("CGSSessionScreenIsLocked")) or not entry.get("kCGSSessionOnConsoleKey", True)
    return None


async def _macos() -> tuple[float | None, bool | None]:
    idle = parse_hid_idle(await _output("/usr/sbin/ioreg", "-c", "IOHIDSystem", "-d", "4") or "")
    tree = await _output("/usr/sbin/ioreg", "-n", "Root", "-d", "1", "-a")
    return idle, (parse_console_locked(tree.encode(), os.getuid()) if tree else None)


class UserHelper:
    def __init__(self, config: HostConfig):
        self.config = config
        self.fresh = True  # the first report after this process started
        self._dialog_lock = asyncio.Lock()
        self._current: tuple[str, asyncio.subprocess.Process] | None = None
        self._cancelled: set[str] = set()
        self._background: set[asyncio.Task] = set()

    async def presence(self) -> dict[str, Any]:
        idle, locked = (None, None)
        if self.config.desktop.idle_source == "logind":
            idle, locked = await _logind()
        elif self.config.desktop.idle_source == "macos":
            idle, locked = await _macos()
        report = {
            "type": "presence",
            "idle_secs": idle,
            "locked": locked,
            # "Not now", whatever the reason: the host's own check, or Hyprland's
            # focused window being fullscreen.
            "fullscreen": await (_busy(busy) if (busy := self.config.desktop.busy_command) else _fullscreen()),
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
            who, what, detail = (str(prompt.get(k) or "") for k in ("who", "what", "detail"))
            fields = {
                # {who} {what} {detail} are one line each (sbx-prompt's
                # arguments); {title} {text} are the same, laid out.
                "who": who,
                "what": what,
                "detail": detail,
                "title": f"agent-auth: {who}"[:120],
                "text": f"{who} asks to:\n    {what}" + (f"\n\n{detail}" if detail else ""),
                "timeout": str(int(prompt.get("timeout", 90))),
            }
            template = self.config.desktop.prompt_command or default_prompt()
            argv = _fill(template, fields)
            self.attention()
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

    def attention(self) -> None:
        """desktop.attention_command (a sound), not waited for."""
        if argv := self.config.desktop.attention_command:
            self._spawn(argv)

    def notify(self, msg: dict[str, Any]) -> None:
        """A notification, and the attention sound. The text may be an
        agent's: markup is escaped (notification daemons render it)."""
        self.attention()
        template, escape = self.config.desktop.notify_command, html.escape
        if not template and darwin():
            # macOS notifications show no markup: nothing to escape.
            template, escape = DARWIN_NOTIFY, str
        if template:
            urgency = msg.get("urgency") if msg.get("urgency") in ("low", "normal", "critical") else "normal"
            self._spawn(_fill(template, {
                "title": escape(str(msg.get("title") or "agent-auth")),
                "text": escape(str(msg.get("text") or "")),
                "urgency": urgency,
            }))

    def _spawn(self, argv: list[str]) -> None:
        async def run() -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await asyncio.wait_for(proc.wait(), 30)
            except (OSError, TimeoutError) as exc:
                log.warning("%s: %s", argv[0], exc)

        task = asyncio.create_task(run())
        self._background.add(task)
        task.add_done_callback(self._background.discard)

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
                elif msg.get("type") == "notify":
                    self.notify(msg)
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
