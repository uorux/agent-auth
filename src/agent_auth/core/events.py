from __future__ import annotations

import asyncio
from collections import defaultdict


class DecisionEvents:
    """In-process wakeups for long-polling waiters.

    Single-process by design; wait_for_change also re-checks the DB on a short
    interval in the API layer, which is the seam for pg NOTIFY if this ever
    runs multi-process.
    """

    def __init__(self) -> None:
        self._conditions: dict[str, asyncio.Event] = defaultdict(asyncio.Event)

    def notify(self, request_id: str) -> None:
        ev = self._conditions[request_id]
        ev.set()
        # Re-arm so subsequent waits block until the next change.
        self._conditions[request_id] = asyncio.Event()

    async def wait(self, request_id: str, timeout: float) -> bool:
        """Returns True if notified before timeout."""
        ev = self._conditions[request_id]
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
            return True
        except TimeoutError:
            return False

    def discard(self, request_id: str) -> None:
        self._conditions.pop(request_id, None)
