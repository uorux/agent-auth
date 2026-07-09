"""`a2a serve` dispatcher tick: level-triggered redelivery, cooldown
rate-limiting, failure backoff, signing, and activity gating. No live loop,
no real sleeps — a stub client, a stub post_fn, and an injectable `now`."""

from __future__ import annotations

import hashlib
import hmac
import json

from agent_auth.crypto import sign_body
from agent_auth.serve import Attempt, ServeConfig, run_serve_tick


def _thread(tid: str, state: str = "pending_open", **extra) -> dict:
    return {
        "thread_id": tid,
        "peer": "claude-nixos-dots-x",
        "topic": None,
        "state": state,
        "last_seq": 1,
        **extra,
    }


class StubClient:
    """Programmable /v1/a2a/events view + opening-payload reads."""

    def __init__(self):
        self.pending: list[dict] = []
        self.activity: list[dict] = []
        self.cursor: str | None = "c1"
        self.poll_error = False

    def a2a_events(self, wait: float = 0, after: str | None = None) -> dict:
        return {
            "pending_opens": list(self.pending),
            "activity": list(self.activity),
            "cursor": self.cursor,
        }

    def a2a_poll(self, thread_id: str, after_seq: int = 0, wait: float = 0) -> dict:
        if self.poll_error:
            raise RuntimeError("broker unreachable")
        return {
            "thread": _thread(thread_id),
            "messages": [
                {"message_id": "m1", "seq": 1, "from": "claude-nixos-dots-x",
                 "payload": {"task": "deploy cactus"}}
            ],
        }


class StubPost:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls: list[tuple[str, bytes, dict]] = []

    def __call__(self, url: str, raw: bytes, headers: dict) -> bool:
        self.calls.append((url, raw, headers))
        return self.ok


def _cfg(**overrides) -> ServeConfig:
    kwargs: dict = dict(
        on_open_url="http://hermes.test/start",
        secret="hook-secret",
        redeliver_interval=60.0,
        failure_backoff=5.0,
    )
    kwargs.update(overrides)
    return ServeConfig(**kwargs)


def test_level_triggered_redelivery_with_cooldown():
    client, post, cfg = StubClient(), StubPost(), _cfg()
    client.pending = [_thread("t1")]
    attempts: dict[str, Attempt] = {}

    # tick 1: posts once
    r = run_serve_tick(client, None, attempts, now=0.0, post_fn=post, cfg=cfg)
    assert (r.posted, r.seen) == (1, 1)
    assert r.cursor == "c1"
    body = json.loads(post.calls[0][1])
    assert body == {
        "event": "a2a_thread_open",
        "thread_id": "t1",
        "peer": "claude-nixos-dots-x",
        "topic": None,
        "seq": 1,
        "payload": {"task": "deploy cactus"},
    }

    # tick 2, still pending, inside cooldown: suppressed — but still SEEN
    r = run_serve_tick(client, r.cursor, attempts, now=1.0, post_fn=post, cfg=cfg)
    assert (r.posted, r.seen) == (0, 1)
    assert len(post.calls) == 1

    # tick 3, past redeliver_interval, STILL pending: re-posts (a 2xx earlier
    # meant "run queued", not "accepted" — level-triggered)
    r = run_serve_tick(client, r.cursor, attempts, now=61.0, post_fn=post, cfg=cfg)
    assert r.posted == 1
    assert len(post.calls) == 2

    # thread leaves pending_open → dispatch stops, regardless of timers
    client.pending = []
    r = run_serve_tick(client, r.cursor, attempts, now=200.0, post_fn=post, cfg=cfg)
    assert (r.posted, r.seen) == (0, 0)
    assert len(post.calls) == 2


def test_failure_backoff_retries_sooner():
    client, post, cfg = StubClient(), StubPost(ok=False), _cfg()
    client.pending = [_thread("t1")]
    attempts: dict[str, Attempt] = {}

    run_serve_tick(client, None, attempts, now=0.0, post_fn=post, cfg=cfg)
    assert attempts["t1"].failed is True

    # not yet past failure_backoff (5s) → suppressed
    r = run_serve_tick(client, None, attempts, now=3.0, post_fn=post, cfg=cfg)
    assert r.posted == 0
    # past failure_backoff but well inside redeliver_interval → retried
    post.ok = True
    r = run_serve_tick(client, None, attempts, now=6.0, post_fn=post, cfg=cfg)
    assert r.posted == 1
    assert attempts["t1"].failed is False


def test_signature_matches_shared_contract():
    client, post, cfg = StubClient(), StubPost(), _cfg()
    client.pending = [_thread("t1")]
    run_serve_tick(client, None, {}, now=0.0, post_fn=post, cfg=cfg)
    _, raw, headers = post.calls[0]
    sig = headers["X-Agent-Auth-Signature"]
    assert sig == sign_body("hook-secret", raw)
    expected = "sha256=" + hmac.new(b"hook-secret", raw, hashlib.sha256).hexdigest()
    assert sig == expected  # wire format identical to the broker's pings

    # header name is configurable; bytes and signature value are unchanged
    post_gh = StubPost()
    run_serve_tick(
        client, None, {}, now=0.0, post_fn=post_gh,
        cfg=_cfg(sig_header="X-Hub-Signature-256"),
    )
    _, raw_gh, headers_gh = post_gh.calls[0]
    assert raw_gh == raw  # same body bytes
    assert "X-Agent-Auth-Signature" not in headers_gh
    assert headers_gh["X-Hub-Signature-256"] == sign_body("hook-secret", raw_gh) == sig

    # unsigned mode omits the header entirely (whatever its name)
    post2 = StubPost()
    run_serve_tick(
        client, None, {}, now=0.0, post_fn=post2,
        cfg=_cfg(secret=None, sig_header="X-Hub-Signature-256"),
    )
    assert "X-Agent-Auth-Signature" not in post2.calls[0][2]
    assert "X-Hub-Signature-256" not in post2.calls[0][2]


def test_include_activity_gating():
    client, post = StubClient(), StubPost()
    client.pending = [_thread("t1")]
    client.activity = [_thread("t1"), _thread("t2", state="open")]

    # default: opens only — t2 is ignored
    r = run_serve_tick(client, None, {}, now=0.0, post_fn=post, cfg=_cfg())
    assert r.posted == 1

    # enabled: t2 dispatched as activity (no payload fetch); t1 deduped
    post2 = StubPost()
    r = run_serve_tick(
        client, None, {}, now=0.0, post_fn=post2, cfg=_cfg(include_activity=True)
    )
    assert r.posted == 2
    events = {json.loads(raw)["thread_id"]: json.loads(raw)["event"] for _, raw, _ in post2.calls}
    assert events == {"t1": "a2a_thread_open", "t2": "a2a_thread_activity"}
    t2_body = next(json.loads(raw) for _, raw, _ in post2.calls if json.loads(raw)["thread_id"] == "t2")
    assert "payload" not in t2_body


def test_payload_fetch_failure_omits_payload():
    client, post, cfg = StubClient(), StubPost(), _cfg()
    client.pending = [_thread("t1")]
    client.poll_error = True
    r = run_serve_tick(client, None, {}, now=0.0, post_fn=post, cfg=cfg)
    assert r.posted == 1  # the open is still dispatched
    body = json.loads(post.calls[0][1])
    assert "payload" not in body


def test_attempts_pruned_only_when_gone_and_stale():
    client, post, cfg = StubClient(), StubPost(), _cfg()
    attempts = {"gone-old": Attempt(at=0.0, failed=False), "gone-new": Attempt(at=1990.0, failed=False)}
    client.pending = []
    run_serve_tick(client, None, attempts, now=2000.0, post_fn=post, cfg=cfg)
    assert "gone-old" not in attempts  # not in view and past the prune age
    assert "gone-new" in attempts  # not in view but recent — kept