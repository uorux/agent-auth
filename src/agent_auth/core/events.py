from __future__ import annotations

import asyncio
from collections import defaultdict


class KeyedEvents:
    """In-process wakeups for long-polling waiters, keyed by any string
    (request ids for decision polls, agent/session ids for a2a polls).

    Single-process by design; wait callers also re-check the DB on a short
    interval in the API layer, which is the seam for pg NOTIFY if this ever
    runs multi-process.
    """

    def __init__(self) -> None:
        self._conditions: dict[str, asyncio.Event] = defaultdict(asyncio.Event)

    def notify(self, key: str) -> None:
        ev = self._conditions[key]
        ev.set()
        # Re-arm so subsequent waits block until the next change.
        self._conditions[key] = asyncio.Event()

    async def wait(self, key: str, timeout: float) -> bool:
        """Returns True if notified before timeout."""
        ev = self._conditions[key]
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
            return True
        except TimeoutError:
            return False

    def discard(self, key: str) -> None:
        self._conditions.pop(key, None)
