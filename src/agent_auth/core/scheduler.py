from __future__ import annotations

import asyncio
import logging

from .service import RequestService

log = logging.getLogger(__name__)


class ExpiryScheduler:
    """Revokes grants past expires_at. The grants table IS the schedule, so the
    first tick after boot is the catch-up pass for anything that expired while
    the broker was down."""

    def __init__(self, service: RequestService, interval_secs: float = 30.0):
        self.service = service
        self.interval_secs = interval_secs
        self._stop = asyncio.Event()

    async def run(self) -> None:
        log.info("expiry scheduler started (interval %ss)", self.interval_secs)
        while not self._stop.is_set():
            try:
                expired = await self.service.expire_due_grants()
                if expired:
                    log.info("expired %d grant(s)", expired)
            except Exception:
                log.exception("scheduler tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_secs)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()
