"""Async calls to the broker's agent API, as one of the VM's agents."""

from __future__ import annotations

from typing import Any

import httpx


class BrokerCallError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(f"[{status}] {detail}")


class Broker:
    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None):
        # Long-polls hold a request open up to 300 s.
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), timeout=httpx.Timeout(330, connect=15), transport=transport
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call(
        self,
        api_key: str,
        method: str,
        path: str,
        *,
        session: str | None = None,
        **kwargs: Any,
    ) -> Any:
        headers = {"Authorization": f"Bearer {api_key}"}
        if session:
            headers["X-Agent-Session"] = session
        resp = await self._http.request(method, path, headers=headers, **kwargs)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            raise BrokerCallError(resp.status_code, str(detail)[:500])
        return resp.json() if resp.content else None

    # Thin wrappers for what sandboxd uses.

    async def me(self, key: str, session: str | None = None) -> dict:
        return await self.call(key, "GET", "/v1/me", session=session)

    async def create_session(self, key: str, label: str) -> str:
        return (await self.call(key, "POST", "/v1/sessions", json={"label": label}))["session_id"]

    async def close_session(self, key: str, session: str) -> None:
        await self.call(key, "POST", "/v1/sessions/close", session=session)

    async def events(self, key: str, *, wait: float, after: str | None, session: str | None = None) -> dict:
        params: dict[str, Any] = {"wait": wait}
        if after:
            params["after"] = after
        return await self.call(key, "GET", "/v1/a2a/events", session=session, params=params)

    async def accept(self, key: str, thread_id: str, session: str | None) -> dict:
        return await self.call(key, "POST", f"/v1/a2a/threads/{thread_id}/accept", session=session)

    async def reject(self, key: str, thread_id: str, reason: str) -> dict:
        return await self.call(key, "POST", f"/v1/a2a/threads/{thread_id}/reject", json={"reason": reason})

    async def messages(self, key: str, thread_id: str, after_seq: int, session: str | None = None) -> dict:
        return await self.call(
            key, "GET", f"/v1/a2a/threads/{thread_id}/messages", session=session,
            params={"after_seq": after_seq},
        )

    async def request_access(self, key: str, body: dict) -> dict:
        return await self.call(key, "POST", "/v1/requests", json=body)

    async def wait(self, key: str, request_id: str, timeout: float) -> dict:
        return await self.call(key, "GET", f"/v1/requests/{request_id}/wait", params={"timeout": timeout})
