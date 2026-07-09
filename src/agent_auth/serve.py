"""`agent-auth a2a serve` — resident, sessionless a2a dispatcher.

Reconciles the broker's pending thread-opens against a receiver by POSTing raw
thread facts as JSON to a configurable URL (an agent runtime's conversation-
start webhook). It is a DUMB DATA TRANSPORT: no prompts, no worker
instructions, no runtime-specific logic — the receiver's own template decides
what to do with the fields.

Level-triggered by design: /v1/a2a/events (sessionless) returns ALL currently
pending opens on every poll, and the only thing that stops redelivery is the
thread leaving pending_open (a worker accepted/rejected it, or it timed out).
A 2xx from the receiver means "run queued", NOT "worker accepted" — so the
local attempts map is a rate-limiter (cooldown), never a delivery ledger.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from .client import BrokerClient, BrokerError
from .crypto import sign_body

log = logging.getLogger(__name__)

_POST_TIMEOUT_SECS = 10
# Drop attempt records for threads no longer pending once this old — ~2x the
# broker's default open-timeout, so a re-used view never resurrects a cooldown.
_PRUNE_AGE_SECS = 1200.0

PostFn = Callable[[str, bytes, dict[str, str]], bool]


@dataclasses.dataclass
class Attempt:
    at: float
    failed: bool


@dataclasses.dataclass
class ServeConfig:
    on_open_url: str
    secret: str | None  # None → unsigned POSTs (--insecure-no-sign)
    wait: float = 60.0
    redeliver_interval: float = 60.0
    failure_backoff: float = 5.0
    include_activity: bool = False
    # Header carrying the signature — the FORMAT never changes (sha256=<hex
    # HMAC-SHA256 of the raw body>), so pointing this at a GitHub-style
    # verifier's fixed header (X-Hub-Signature-256) interops as-is.
    sig_header: str = "X-Agent-Auth-Signature"


@dataclasses.dataclass
class TickResult:
    cursor: str | None
    posted: int
    seen: int  # dispatchable items in view this tick (posted or in cooldown)


def default_state_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "agent-auth" / "a2a-serve.json"


def _body(event: str, thread: dict, payload: Any | None) -> dict:
    # Flat, stably-named fields for the receiver's {dot.notation} template.
    body = {
        "event": event,
        "thread_id": thread["thread_id"],
        "peer": thread.get("peer"),
        "topic": thread.get("topic"),
        "seq": thread.get("last_seq"),
    }
    if payload is not None:
        body["payload"] = payload
    return body


def _opening_payload(client: BrokerClient, thread_id: str) -> Any | None:
    """Best-effort seq-1 payload (the peer's ask — DATA, not instructions).
    Sessionless reads of a still-pending thread are allowed: the dispatcher is
    the responder agent and the thread isn't session-bound yet."""
    try:
        read = client.a2a_poll(thread_id, 0, 0)
        messages = read.get("messages") or []
        return messages[0].get("payload") if messages else None
    except Exception:
        log.warning("could not fetch opening payload for %s; omitting", thread_id)
        return None


def post_once(url: str, raw: bytes, headers: dict[str, str]) -> bool:
    try:
        resp = httpx.post(url, content=raw, headers=headers, timeout=_POST_TIMEOUT_SECS)
        if resp.status_code // 100 != 2:
            log.warning("dispatch POST %s -> %s", url, resp.status_code)
        return resp.status_code // 100 == 2
    except httpx.HTTPError as exc:
        log.warning("dispatch POST %s failed: %s", url, exc)
        return False


def run_serve_tick(
    client: BrokerClient,
    cursor: str | None,
    attempts: dict[str, Attempt],
    now: float,
    post_fn: PostFn,
    cfg: ServeConfig,
) -> TickResult:
    """One reconcile pass. Mutates `attempts` (every ATTEMPT is recorded,
    success or not); returns the advanced cursor and what happened."""
    snap = client.a2a_events(wait=cfg.wait, after=cursor)

    items: list[tuple[str, dict]] = [
        ("a2a_thread_open", t) for t in snap.get("pending_opens") or []
    ]
    if cfg.include_activity:
        opens = {t["thread_id"] for _, t in items}
        items += [
            ("a2a_thread_activity", t)
            for t in snap.get("activity") or []
            if t["thread_id"] not in opens
        ]

    posted = 0
    seen_ids: set[str] = set()
    for event, thread in items:
        tid = thread["thread_id"]
        seen_ids.add(tid)
        last = attempts.get(tid)
        cooldown = cfg.failure_backoff if (last and last.failed) else cfg.redeliver_interval
        if last is not None and now - last.at < cooldown:
            continue  # rate-limit only — pending state is what stops redelivery
        payload = (
            _opening_payload(client, tid) if event == "a2a_thread_open" else None
        )
        raw = json.dumps(_body(event, thread, payload)).encode()
        headers = {"Content-Type": "application/json"}
        if cfg.secret:
            headers[cfg.sig_header] = sign_body(cfg.secret, raw)
        ok = post_fn(cfg.on_open_url, raw, headers)
        attempts[tid] = Attempt(at=now, failed=not ok)
        posted += 1

    # Prune: no longer in view AND old enough that no cooldown could matter.
    for tid in [t for t in attempts if t not in seen_ids]:
        if now - attempts[tid].at > _PRUNE_AGE_SECS:
            del attempts[tid]

    return TickResult(cursor=snap.get("cursor") or cursor, posted=posted, seen=len(seen_ids))


# ------------------------------------------------------------------- state


def load_state(path: Path) -> tuple[str | None, dict[str, Attempt]]:
    try:
        data = json.loads(path.read_text())
        attempts = {
            tid: Attempt(at=float(a["at"]), failed=bool(a["failed"]))
            for tid, a in (data.get("attempts") or {}).items()
        }
        return data.get("cursor"), attempts
    except (OSError, ValueError, KeyError, TypeError):
        return None, {}


def save_state(path: Path, cursor: str | None, attempts: dict[str, Attempt]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(
            {
                "cursor": cursor,
                "attempts": {t: dataclasses.asdict(a) for t, a in attempts.items()},
            }
        )
    )
    os.replace(tmp, path)


# -------------------------------------------------------------------- loop


def serve_loop(
    client: BrokerClient,
    cfg: ServeConfig,
    state_path: Path,
    poll_interval: float = 5.0,
    post_fn: PostFn = post_once,
) -> None:
    """Run forever: park on the events long-poll when idle, paced ticks while
    threads linger pending (the endpoint returns instantly whenever anything
    is pending, so sleeping between no-op ticks is what prevents a busy loop).
    The long-poll doubles as the agent's liveness heartbeat."""
    # Sessionless is mandatory: only a sessionless caller sees pending_opens.
    client.session_id = ""
    cursor, attempts = load_state(state_path)
    log.info(
        "a2a dispatcher up (sessionless): POST %s, redeliver=%ss, state=%s",
        cfg.on_open_url,
        cfg.redeliver_interval,
        state_path,
    )

    # Raising (not flag-setting) matters: PEP 475 aborts a blocking syscall
    # when the handler raises, so SIGTERM interrupts a parked long-poll
    # immediately instead of waiting out --wait.
    def _stop(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop)
    try:
        while True:
            try:
                result = run_serve_tick(client, cursor, attempts, time.time(), post_fn, cfg)
                cursor = result.cursor
                save_state(state_path, cursor, attempts)
            except (BrokerError, httpx.HTTPError) as exc:
                log.warning("tick failed (%s); backing off", exc)
                time.sleep(min(poll_interval, 5.0))
                continue
            if result.seen and not result.posted:
                # Everything in view is inside its cooldown; the next events
                # call would return instantly — pace instead of spinning.
                time.sleep(poll_interval)
            elif result.posted:
                # Receiver queued work; give the worker a beat to accept
                # before the level-triggered view shows the thread again.
                time.sleep(poll_interval)
            # else: nothing pending — loop straight into an efficient park.
    except KeyboardInterrupt:
        pass
    save_state(state_path, cursor, attempts)
    log.info("a2a dispatcher stopped")
