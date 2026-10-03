from __future__ import annotations

import asyncio
import logging

from .a2a import A2AThreadService
from .service import RequestService

log = logging.getLogger(__name__)

# A grant still PROVISIONING after this long was interrupted: the longest
# legitimate provision (k8s control-plane failover, LLDAP create + password
# subprocess + group add) finishes well inside it.
STALE_PROVISIONING_SECS = 15 * 60


class ExpiryScheduler:
    """Revokes grants past expires_at and sweeps a2a lifecycle timeouts (idle
    sessions → peer_gone, open/idle thread timeouts, dead-grant threads). The
    tables ARE the schedule, so the first tick after boot is the catch-up pass
    for anything that lapsed while the broker was down."""

    def __init__(
        self,
        service: RequestService,
        a2a: A2AThreadService | None = None,
        interval_secs: float = 30.0,
    ):
        self.service = service
        self.a2a = a2a
        self.interval_secs = interval_secs
        self._stop = asyncio.Event()

    async def run(self) -> None:
        log.info("expiry scheduler started (interval %ss)", self.interval_secs)
        first_tick = True
        while not self._stop.is_set():
            # Interrupted provisions first: on the boot tick every PROVISIONING
            # row is an orphan (single process — nothing is in flight yet).
            try:
                reaped = await self.service.reap_stale_provisioning(
                    0 if first_tick else STALE_PROVISIONING_SECS
                )
                if reaped:
                    log.info("reaped %d interrupted provision(s)", reaped)
            except Exception:
                log.exception("stale-provisioning reap failed")
            first_tick = False
            # Grants next: the a2a sweep then closes their threads same-tick.
            try:
                expired = await self.service.expire_due_grants()
                if expired:
                    log.info("expired %d grant(s)", expired)
            except Exception:
                log.exception("scheduler tick failed")
            if self.a2a is not None:
                try:
                    counts = await self.a2a.sweep()
                    if any(counts.values()):
                        log.info("a2a sweep: %s", counts)
                except Exception:
                    log.exception("a2a sweep failed")
                try:
                    revoked = await self.service.revoke_delegated_for_closed_threads()
                    if revoked:
                        log.info("revoked %d delegated grant(s) for closed threads", revoked)
                except Exception:
                    log.exception("delegated-grant cascade failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_secs)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()
