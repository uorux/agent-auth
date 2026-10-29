"""What a host job is, shared by the broker (which proposes one) and hostd
(which decides whether to run it): the spec, its limits, and its digest.

A spec is plain JSON:

    {"kind": "run" | "tpl" | "shell",
     "host": "<host>", "tier": "user" | "root",
     "argv": [...],                  # run, and shell commands
     "template": "<name>", "params": {...},   # tpl (hostd expands its own template)
     "cwd": "/abs/path" | null, "env": {"K": "v"}, "timeout": <secs>,
     "stdin": "<text>" | null}

The digest names one exact spec. A TOTP approval is given for a digest, so
what runs is what the code was typed for — as far as the broker relays the
request honestly (docs/sandbox-design.md §8.5, residual risk).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

TIERS = ("user", "root")
KINDS = ("run", "tpl", "shell")
MAX_ARGS = 256
MAX_ARG_BYTES = 16 * 1024
MAX_ARGV_BYTES = 64 * 1024
MAX_STDIN_BYTES = 64 * 1024
MAX_ENV_VARS = 32
MAX_OUTPUT_BYTES = 1024 * 1024
OUTPUT_CHUNK_BYTES = 96 * 1024
DEFAULT_TIMEOUT_SECS = 600
ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class SpecError(ValueError):
    pass


def validate_argv(argv: Any) -> list[str]:
    if not isinstance(argv, list) or not argv:
        raise SpecError("argv must be a non-empty list of strings")
    if len(argv) > MAX_ARGS:
        raise SpecError(f"argv has more than {MAX_ARGS} arguments")
    total = 0
    for arg in argv:
        if not isinstance(arg, str) or "\x00" in arg:
            raise SpecError("argv must be a list of strings without NUL bytes")
        size = len(arg.encode())
        if size > MAX_ARG_BYTES:
            raise SpecError("an argument is too long")
        total += size
    if total > MAX_ARGV_BYTES:
        raise SpecError("argv is too long")
    if not argv[0]:
        raise SpecError("argv[0] is empty")
    return list(argv)


def validate_cwd(cwd: Any) -> str | None:
    if cwd in (None, ""):
        return None
    if not isinstance(cwd, str) or not cwd.startswith("/") or "\x00" in cwd or len(cwd) > 4096:
        raise SpecError("cwd must be an absolute path")
    return os.path.normpath(cwd)


def validate_env(env: Any) -> dict[str, str]:
    if env in (None, {}):
        return {}
    if not isinstance(env, dict) or len(env) > MAX_ENV_VARS:
        raise SpecError(f"env must be an object of at most {MAX_ENV_VARS} variables")
    out = {}
    for key, value in env.items():
        if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
            raise SpecError(f"invalid environment variable name {key!r}")
        if not isinstance(value, str) or "\x00" in value or "\n" in value or len(value) > 4096:
            raise SpecError(f"invalid value for environment variable {key}")
        out[key] = value
    return dict(sorted(out.items()))


def validate_timeout(timeout: Any, default: int = DEFAULT_TIMEOUT_SECS) -> int:
    if timeout is None:
        return default
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 24 * 3600:
        raise SpecError("timeout must be a number of seconds between 1 and 86400")
    return timeout


def validate_stdin(stdin: Any) -> str | None:
    if stdin is None:
        return None
    if not isinstance(stdin, str) or len(stdin.encode()) > MAX_STDIN_BYTES:
        raise SpecError(f"stdin must be text of at most {MAX_STDIN_BYTES} bytes")
    return stdin


def make_spec(
    *,
    kind: str,
    host: str,
    tier: Any,
    argv: Any = None,
    template: Any = None,
    params: Any = None,
    cwd: Any = None,
    env: Any = None,
    timeout: Any = None,
    stdin: Any = None,
) -> dict[str, Any]:
    """Validate the pieces and return the canonical spec."""
    if kind not in KINDS:
        raise SpecError(f"kind must be one of {', '.join(KINDS)}")
    if tier not in TIERS:
        raise SpecError("tier must be \"user\" or \"root\"")
    spec: dict[str, Any] = {"kind": kind, "host": host, "tier": tier}
    if kind == "tpl":
        if not isinstance(template, str) or not NAME_RE.fullmatch(template):
            raise SpecError("invalid template name")
        if not isinstance(params, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and "\x00" not in v and len(v) <= 4096
            for k, v in params.items()
        ):
            raise SpecError("template params must be an object of strings")
        spec["template"] = template
        spec["params"] = dict(sorted(params.items()))
    elif kind == "run" or argv is not None:
        spec["argv"] = validate_argv(argv)
    spec["cwd"] = validate_cwd(cwd)
    spec["env"] = validate_env(env)
    spec["timeout"] = validate_timeout(timeout)
    spec["stdin"] = validate_stdin(stdin)
    return spec


def shell_spec(host: str, tier: Any, duration_secs: Any) -> dict[str, Any]:
    """What opening a shell is approved for: a tier on a host, for so long."""
    if tier not in TIERS:
        raise SpecError("tier must be \"user\" or \"root\"")
    if isinstance(duration_secs, bool) or not isinstance(duration_secs, int) or duration_secs <= 0:
        raise SpecError("a shell needs a duration in seconds")
    return {"kind": "shell", "host": host, "tier": tier, "duration": duration_secs}


def digest(spec: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def expand_template(template: dict[str, Any], params: dict[str, str]) -> list[str]:
    """A template's argv with {name} placeholders filled from params, each
    checked against the template's regex for it. Whole-argument substitution
    only: a parameter can never add arguments or run through a shell."""
    patterns: dict[str, str] = template.get("params") or {}
    if set(params) != set(patterns):
        raise SpecError(
            f"template takes exactly these parameters: {', '.join(sorted(patterns)) or '(none)'}"
        )
    for name, value in params.items():
        if not re.fullmatch(patterns[name], value):
            raise SpecError(f"parameter {name!r} does not match the template's pattern")

    def fill(arg: str) -> str:
        return re.sub(r"\{([a-z0-9_]+)\}", lambda m: params.get(m.group(1), m.group(0)), arg)

    return [fill(arg) for arg in template["argv"]]


def describe(spec: dict[str, Any]) -> str:
    """One line for logs and prompts."""
    import shlex

    if spec.get("kind") == "tpl":
        what = f"template {spec.get('template')} {json.dumps(spec.get('params') or {})}"
    elif spec.get("argv"):
        what = shlex.join(spec["argv"])
    else:
        what = "shell"
    return f"[{spec.get('tier')}@{spec.get('host')}] {what}"
