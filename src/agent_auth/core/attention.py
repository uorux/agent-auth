"""An agent asking for the operator's attention, outside any request: a
message on Discord (a ping when it is urgent, or when nobody is at a desk)
and a notification with a sound on the desks they are at.

It grants nothing and needs no approval; it is rate-limited per agent, and
the text is the agent's own words, shown as such.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from ..models import Agent

PER_HOUR = 6
MAX_CHARS = 500


class AttentionLimit(Exception):
    pass


class AttentionService:
    def __init__(self, service, desktop=None):
        self.service = service
        self.desktop = desktop
        self._sent: dict[str, deque[float]] = defaultdict(deque)

    async def notify(self, agent: Agent, text: str, urgency: str = "normal") -> dict:
        text = " ".join(text.split())[:MAX_CHARS]
        if not text:
            raise ValueError("say what you need")
        if urgency not in ("normal", "high"):
            raise ValueError("urgency is normal or high")
        now = time.time()
        sent = self._sent[agent.id]
        while sent and sent[0] < now - 3600:
            sent.popleft()
        if len(sent) >= PER_HOUR:
            raise AttentionLimit(f"at most {PER_HOUR} notifications an hour; the operator has the earlier ones")
        sent.append(now)
        desks = await self.desktop.notify(agent, text, urgency) if self.desktop is not None else []
        await self.service.notifier.attention(agent, text, urgency, desks)
        return {"sent": True, "desktops": desks}
