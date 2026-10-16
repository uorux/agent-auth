"""Refusals the database doesn't keep: keys that didn't verify, admin
tokens that didn't, credentials not issued to a contained agent, a
containment lifted. Held in memory (the last few thousand), read by the
audit feed (api/audit_routes.py) and logged. A restart empties it: a
reader polling every minute or so loses at most what came in between.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("agent_auth.security")

MAX_ITEMS = 5000


class SecurityLog:
    def __init__(self, size: int = MAX_ITEMS):
        self.items: deque[dict[str, Any]] = deque(maxlen=size)
        self.seq = 0

    def record(self, kind: str, **fields: Any) -> None:
        self.seq += 1
        item = {
            "kind": f"security.{kind}",
            "id": f"s{self.seq}",
            "at": datetime.now(timezone.utc),
            **{k: (str(v)[:300] if v is not None else None) for k, v in fields.items()},
        }
        self.items.append(item)
        log.warning("%s %s", item["kind"], " ".join(f"{k}={v}" for k, v in fields.items() if v is not None))

    def since(self, when: datetime, limit: int) -> list[dict[str, Any]]:
        return [i for i in self.items if i["at"] >= when][:limit]


def client_of(request) -> str | None:
    """Who called, as the reverse proxy saw them (nginx on recusant sets
    X-Real-IP; anything else is only the proxy's address)."""
    return request.headers.get("X-Real-IP") or (request.client.host if request.client else None)


def record(request, kind: str, **fields: Any) -> None:
    found = getattr(request.app.state, "security_log", None)
    if found is not None:
        found.record(kind, client=client_of(request), path=request.url.path, **fields)
