#!/usr/bin/env python3
"""Dependency cooldown for the Rust workspace.

Every crates.io package in Cargo.lock must have been published at least
COOLDOWN_DAYS before today, and must not be yanked. Fresh releases are where
supply-chain compromises land; most are caught and yanked within days, so a
version that has been public for two weeks has had that time to be noticed.

    python3 -I scripts/cooldown.py check            # exit 1 on violations
    python3 -I scripts/cooldown.py fix              # walk violators back
    python3 -I scripts/cooldown.py latest NAME...   # newest version that passes

Exceptions (a security fix that cannot wait) go in cooldown-exceptions.toml:

    [[exception]]
    name = "some-crate"
    version = "1.2.3"
    reason = "RUSTSEC-2026-0001 fix; reviewed the diff"

Only the standard library is used, and crates.io answers are cached per run
under target/cooldown-cache.json (versions do not change once published,
except for yanks, so the cache is dropped after a day).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import time
import tomllib
import urllib.request

COOLDOWN_DAYS = 14
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# COOLDOWN_ROOT: another Cargo project to check (e.g. rust/fuzz, which has
# its own lockfile). Exceptions and the cache stay with the main workspace.
ROOT = os.path.abspath(os.environ.get("COOLDOWN_ROOT", HERE))
LOCK = os.path.join(ROOT, "Cargo.lock")
EXCEPTIONS = os.path.join(HERE, "cooldown-exceptions.toml")
CACHE = os.path.join(HERE, "target", "cooldown-cache.json")
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
USER_AGENT = "agent-auth-cooldown (jacob@otisroot.com)"


def cutoff() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=COOLDOWN_DAYS)


def load_cache() -> dict:
    try:
        if time.time() - os.path.getmtime(CACHE) > 86400:
            return {}
        with open(CACHE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    tmp = CACHE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, CACHE)


_last_request = 0.0


def versions(name: str, cache: dict) -> list[dict]:
    """[{num, created_at, yanked}], newest first."""
    global _last_request
    if name in cache:
        return cache[name]
    # crates.io asks crawlers for at most one request per second.
    wait = 1.0 - (time.monotonic() - _last_request)
    if wait > 0:
        time.sleep(wait)
    req = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/versions",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    _last_request = time.monotonic()
    out = [
        {"num": v["num"], "created_at": v["created_at"], "yanked": v["yanked"]}
        for v in data["versions"]
    ]
    cache[name] = out
    return out


def published(v: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(v["created_at"].replace("Z", "+00:00"))


def exceptions() -> set[tuple[str, str]]:
    try:
        with open(EXCEPTIONS, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return set()
    out = set()
    for e in data.get("exception", []):
        if not e.get("reason"):
            sys.exit(f"cooldown exception for {e.get('name')} has no reason")
        out.add((e["name"], e["version"]))
    return out


def locked() -> list[tuple[str, str]]:
    with open(LOCK, "rb") as f:
        lock = tomllib.load(f)
    return sorted(
        (p["name"], p["version"]) for p in lock.get("package", []) if p.get("source") == CRATES_IO
    )


def violations(cache: dict) -> list[tuple[str, str, str]]:
    allowed = exceptions()
    limit = cutoff()
    bad = []
    for name, version in locked():
        if (name, version) in allowed:
            continue
        info = next((v for v in versions(name, cache) if v["num"] == version), None)
        if info is None:
            bad.append((name, version, "not found on crates.io"))
        elif info["yanked"]:
            bad.append((name, version, "yanked"))
        elif published(info) > limit:
            bad.append((name, version, f"published {info['created_at'][:10]}, inside the cooldown"))
    return bad


def is_prerelease(num: str) -> bool:
    return "-" in num


def candidates(name: str, current: str, cache: dict) -> list[str]:
    """Older, cooled-down, unyanked releases, newest first, same major
    (or same minor for 0.x) as the current one."""
    limit = cutoff()

    def compat(num: str) -> tuple:
        parts = num.split("-")[0].split(".")
        return (parts[0],) if parts[0] != "0" else (parts[0], parts[1])

    return sorted(
        (
            v["num"]
            for v in versions(name, cache)
            if not v["yanked"]
            and published(v) <= limit
            and not is_prerelease(v["num"])
            and compat(v["num"]) == compat(current)
        ),
        key=semver_key,
        reverse=True,
    )


def semver_key(num: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in num.split("+")[0].split("-")[0].split("."))


def fix(cache: dict) -> int:
    for _ in range(20):
        bad = violations(cache)
        if not bad:
            return 0
        progressed = False
        for name, version, why in bad:
            for cand in candidates(name, version, cache):
                r = subprocess.run(
                    ["cargo", "update", "-p", f"{name}@{version}", "--precise", cand],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                if r.returncode == 0:
                    print(f"{name}: {version} -> {cand} (was: {why})")
                    progressed = True
                    break
            else:
                print(f"{name} {version}: {why}; no older compatible release resolves", file=sys.stderr)
        save_cache(cache)
        if not progressed:
            break
    bad = violations(cache)
    for name, version, why in bad:
        print(f"UNRESOLVED {name} {version}: {why}", file=sys.stderr)
    return 1 if bad else 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    cache = load_cache()
    try:
        if cmd == "check":
            bad = violations(cache)
            for name, version, why in bad:
                print(f"{name} {version}: {why}")
            print(f"{len(locked())} crates checked, {len(bad)} violations (cooldown {COOLDOWN_DAYS} days)")
            return 1 if bad else 0
        if cmd == "fix":
            return fix(cache)
        if cmd == "latest":
            limit = cutoff()
            for name in sys.argv[2:]:
                ok = sorted([
                    v for v in versions(name, cache)
                    if not v["yanked"] and not is_prerelease(v["num"]) and published(v) <= limit
                ], key=lambda v: semver_key(v["num"]), reverse=True)
                newest = versions(name, cache)[0]
                if ok:
                    print(f"{name} = \"{ok[0]['num']}\"  # {ok[0]['created_at'][:10]}; newest {newest['num']} {newest['created_at'][:10]}")
                else:
                    print(f"{name}: nothing passes the cooldown")
            return 0
        sys.exit(f"unknown command {cmd}")
    finally:
        save_cache(cache)


if __name__ == "__main__":
    sys.exit(main())
