"""hostd's configuration and local policy: one JSON file written by its NixOS
module, so it lives in the nix store and only an audited config change can
loosen it (docs/sandbox-design.md §8.4). The broker has no say in any of it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

CONFIG_ENV = "AGENT_AUTH_HOSTD_CONFIG"
_DURATION_RE = re.compile(r"(\d+)([smhdw]?)")
_UNIT_SECS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def duration_secs(value: Any) -> int:
    """30, "30m", "8h" → seconds."""
    if isinstance(value, bool):
        raise ValueError("invalid duration")
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("duration must be positive")
        return value
    m = _DURATION_RE.fullmatch(str(value).strip().lower())
    if not m or int(m.group(1)) <= 0:
        raise ValueError(f"invalid duration {value!r}: use e.g. 30m, 8h, or seconds")
    return int(m.group(1)) * _UNIT_SECS[m.group(2)]


@dataclass
class TierConfig:
    enable: bool = False
    # The longest one arming may last.
    max_arm_secs: int = 3600
    # While armed: honour "approve all" windows, and approvals no human made
    # for this request (a saved rule, the LLM reviewer, a policy rule).
    accept_approve_all: bool = False
    accept_machine_approvals: bool = False
    shell_enable: bool = False
    shell_max_duration_secs: int = 1800

    @classmethod
    def load(cls, raw: dict[str, Any]) -> "TierConfig":
        shell = raw.get("shell") or {}
        return cls(
            enable=bool(raw.get("enable", False)),
            max_arm_secs=duration_secs(raw.get("max_arm", 3600)),
            accept_approve_all=bool(raw.get("accept_approve_all", False)),
            accept_machine_approvals=bool(raw.get("accept_machine_approvals", False)),
            shell_enable=bool(shell.get("enable", False)),
            shell_max_duration_secs=duration_secs(shell.get("max_duration", 1800)),
        )


@dataclass
class DesktopConfig:
    """Approval prompts on this host's desktop (hostd-user)."""

    enable: bool = False
    # Shown only while the session is unlocked and was used this recently.
    max_idle_secs: int = 300
    # The dialog: argv with {title} {text} {timeout} placeholders. It must
    # exit 0 for allow and 1 for deny, and may print "mute" or "discord" on
    # stdout for the two extra buttons. Default: zenity.
    prompt_command: list[str] = field(default_factory=list)
    prompt_timeout_secs: int = 90
    # Where "idle" and "locked" come from. "hooks": only what
    # `agent-auth-hostctl presence …` reports (hypridle, the lock screen).
    # "logind": the session's IdleHint/LockedHint, where the desktop keeps
    # them up to date (Hyprland does not).
    idle_source: str = "hooks"

    @classmethod
    def load(cls, raw: dict[str, Any]) -> "DesktopConfig":
        return cls(
            enable=bool(raw.get("enable", False)),
            max_idle_secs=duration_secs(raw.get("max_idle", 300)),
            prompt_command=list(raw.get("prompt_command") or []),
            prompt_timeout_secs=duration_secs(raw.get("prompt_timeout", 90)),
            idle_source="logind" if raw.get("idle_source") == "logind" else "hooks",
        )


@dataclass
class HostConfig:
    broker_url: str
    broker_public_key: str
    name: str
    state_dir: Path = Path("/var/lib/agent-auth-hostd")
    runtime_dir: Path = Path("/run/agent-auth-hostd")
    # The account the user tier runs commands as (and whose desktop is asked).
    user: str | None = None
    tiers: dict[str, TierConfig] = field(default_factory=lambda: {"user": TierConfig(), "root": TierConfig()})
    # argv patterns (see match_argv). auto: user-tier commands that run on any
    # approval, armed or not. deny: never run, whatever the approval.
    auto_commands: list[list[str]] = field(default_factory=list)
    deny_commands: list[list[str]] = field(default_factory=list)
    # name -> {"tier", "argv" (with {param} placeholders), "params": {name: regex}}
    templates: dict[str, dict[str, Any]] = field(default_factory=dict)
    env_allow: list[str] = field(default_factory=lambda: ["LANG", "LC_ALL", "TZ", "TERM"])
    # The agent VM's unit on this host: frozen on lockdown. None = no VM here.
    vm_unit: str | None = None
    job_path: str = "/run/wrappers/bin:/run/current-system/sw/bin"
    default_timeout_secs: int = 600
    max_timeout_secs: int = 3600
    systemd_run: str = "systemd-run"
    systemctl: str = "systemctl"
    setpriv: str = "setpriv"
    qrencode: str = "qrencode"
    desktop: DesktopConfig = field(default_factory=DesktopConfig)

    @property
    def totp_dir(self) -> Path:
        return self.state_dir / "totp"

    @property
    def ctl_socket(self) -> Path:
        return self.runtime_dir / "ctl.sock"

    @property
    def user_socket(self) -> Path:
        return self.runtime_dir / "user.sock"

    @property
    def privileged(self) -> bool:
        """Whether this hostd does anything that needs root."""
        return any(t.enable for t in self.tiers.values()) or self.vm_unit is not None

    @classmethod
    def load(cls, path: str | os.PathLike) -> "HostConfig":
        raw = json.loads(Path(path).read_text())
        tiers = {name: TierConfig.load((raw.get("tiers") or {}).get(name) or {}) for name in ("user", "root")}
        kwargs: dict[str, Any] = {
            "broker_url": raw["broker_url"],
            "broker_public_key": raw["broker_public_key"],
            "name": raw["name"],
            "tiers": tiers,
            "desktop": DesktopConfig.load(raw.get("desktop") or {}),
        }
        for key in ("state_dir", "runtime_dir"):
            if key in raw:
                kwargs[key] = Path(raw[key])
        for key in (
            "user", "auto_commands", "deny_commands", "templates", "env_allow", "vm_unit", "job_path",
            "systemd_run", "systemctl", "setpriv", "qrencode",
        ):
            if raw.get(key) is not None:
                kwargs[key] = raw[key]
        for key in ("default_timeout", "max_timeout"):
            if key in raw:
                kwargs[f"{key}_secs"] = duration_secs(raw[key])
        config = cls(**kwargs)
        config.check()
        return config

    def check(self) -> None:
        for pattern in [*self.auto_commands, *self.deny_commands]:
            if not isinstance(pattern, list) or not pattern or not all(isinstance(p, str) for p in pattern):
                raise ValueError(f"command pattern must be a non-empty list of strings: {pattern!r}")
        for name, tpl in self.templates.items():
            if tpl.get("tier") not in ("user", "root") or not isinstance(tpl.get("argv"), list) or not tpl["argv"]:
                raise ValueError(f"template {name!r} needs a tier and an argv")
            for regex in (tpl.get("params") or {}).values():
                re.compile(regex)
        if self.tiers["user"].enable and not self.user:
            raise ValueError("the user tier needs `user` (the account it runs commands as)")


def match_argv(pattern: list[str], argv: list[str], *, loose_program: bool = False) -> bool:
    """Does argv fit the pattern? Each element is a glob for one argument; a
    final "**" stands for any number of further arguments (none included).
    With loose_program, the first element also matches the program's basename,
    so denying "rm" covers /run/current-system/sw/bin/rm too."""
    rest = bool(pattern) and pattern[-1] == "**"
    fixed = pattern[:-1] if rest else pattern
    if len(argv) < len(fixed) or (not rest and len(argv) != len(fixed)):
        return False
    for i, (glob, arg) in enumerate(zip(fixed, argv)):
        if fnmatchcase(arg, glob):
            continue
        if i == 0 and loose_program and fnmatchcase(os.path.basename(arg), glob):
            continue
        return False
    return True
