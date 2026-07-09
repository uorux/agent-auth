from __future__ import annotations

import os
from typing import Any

import httpx


class BrokerError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


class BrokerClient:
    """Thin sync client over the broker HTTP API, shared by the CLI and MCP server."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        session_id: str | None = None,
    ):
        self.base_url = (base_url or os.environ.get("AGENT_AUTH_URL", "http://localhost:8400")).rstrip("/")
        self.api_key = api_key or os.environ.get("AGENT_AUTH_API_KEY", "")
        self.admin_token = os.environ.get("AGENT_AUTH_ADMIN_TOKEN", "")
        self.session_id = session_id or os.environ.get("AGENT_AUTH_SESSION", "")

    def _request(
        self,
        method: str,
        path: str,
        *,
        admin: bool = False,
        timeout: float = 30,
        **kwargs: Any,
    ) -> Any:
        token = self.admin_token if admin else self.api_key
        if not token:
            raise BrokerError(
                0,
                "AGENT_AUTH_ADMIN_TOKEN not set" if admin else "AGENT_AUTH_API_KEY not set",
            )
        headers = {"Authorization": f"Bearer {token}"}
        if self.session_id and not admin:
            headers["X-Agent-Session"] = self.session_id
        with httpx.Client(timeout=timeout) as client:
            resp = client.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                **kwargs,
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            raise BrokerError(resp.status_code, str(detail))
        return resp.json()

    # agent operations
    def me(self):
        return self._request("GET", "/v1/me")

    def catalog(self):
        return self._request("GET", "/v1/catalog")

    def request_access(
        self,
        platform: str,
        capability: str,
        resource: str,
        justification: str,
        duration: str,
        scope: dict | None = None,
        on_behalf_of_thread: str | None = None,
    ):
        return self._request(
            "POST",
            "/v1/requests",
            json={
                "platform": platform,
                "capability": capability,
                "resource": resource,
                "scope": scope or {},
                "justification": justification,
                "requested_duration": duration,
                "on_behalf_of_thread": on_behalf_of_thread,
            },
        )

    def get_request(self, request_id: str):
        return self._request("GET", f"/v1/requests/{request_id}")

    def wait(self, request_id: str, timeout: float = 60):
        return self._request(
            "GET",
            f"/v1/requests/{request_id}/wait",
            params={"timeout": timeout},
            timeout=timeout + 10,
        )

    def retry(self, request_id: str, justification: str):
        return self._request(
            "POST", f"/v1/requests/{request_id}/retry", json={"justification": justification}
        )

    def escalate(self, request_id: str):
        return self._request("POST", f"/v1/requests/{request_id}/escalate")

    def grants(self, status: str = "active"):
        return self._request("GET", "/v1/grants", params={"status": status})

    def credential(self, grant_id: str):
        return self._request("GET", f"/v1/grants/{grant_id}/credential")

    # sessions
    def create_session(self, label: str):
        out = self._request("POST", "/v1/sessions", json={"label": label})
        self.session_id = out["session_id"]
        return out

    def close_session(self):
        return self._request("POST", "/v1/sessions/close")

    # a2a threads
    def a2a_check(self, peer: str, direction: str = "out", topic: str | None = None):
        params: dict[str, Any] = {"peer": peer, "direction": direction}
        if topic:
            params["topic"] = topic
        return self._request("GET", "/v1/a2a/check", params=params)

    def a2a_open(self, to: str, payload: dict, topic: str | None = None):
        return self._request(
            "POST", "/v1/a2a/threads", json={"to": to, "topic": topic, "payload": payload}
        )

    def a2a_send(self, thread_id: str, payload: dict):
        return self._request(
            "POST", f"/v1/a2a/threads/{thread_id}/messages", json={"payload": payload}
        )

    def a2a_poll(self, thread_id: str, after_seq: int = 0, wait: float = 0):
        return self._request(
            "GET",
            f"/v1/a2a/threads/{thread_id}/messages",
            params={"after_seq": after_seq, "wait": wait},
            timeout=wait + 10,
        )

    def a2a_threads(self, state: str | None = None, role: str | None = None):
        params: dict[str, Any] = {}
        if state:
            params["state"] = state
        if role:
            params["role"] = role
        return self._request("GET", "/v1/a2a/threads", params=params)

    def a2a_thread(self, thread_id: str):
        return self._request("GET", f"/v1/a2a/threads/{thread_id}")

    def a2a_accept(self, thread_id: str):
        return self._request("POST", f"/v1/a2a/threads/{thread_id}/accept")

    def a2a_reject(self, thread_id: str, reason: str | None = None):
        return self._request(
            "POST", f"/v1/a2a/threads/{thread_id}/reject", json={"reason": reason}
        )

    def a2a_close(self, thread_id: str, reason: str | None = None):
        return self._request(
            "POST", f"/v1/a2a/threads/{thread_id}/close", json={"reason": reason}
        )

    def a2a_events(self, wait: float = 0, after: str | None = None):
        params: dict[str, Any] = {"wait": wait}
        if after:
            params["after"] = after
        return self._request("GET", "/v1/a2a/events", params=params, timeout=wait + 10)

    # admin operations
    def admin_create_agent(
        self,
        name: str,
        description: str = "",
        webhook_url: str | None = None,
        lldap_username: str | None = None,
        kind: str = "service",
    ):
        return self._request(
            "POST",
            "/admin/agents",
            admin=True,
            json={
                "name": name,
                "description": description,
                "kind": kind,
                "webhook_url": webhook_url,
                "lldap_username": lldap_username,
            },
        )

    def admin_rotate_webhook_secret(self, agent_id: str):
        return self._request(
            "POST", f"/admin/agents/{agent_id}/rotate-webhook-secret", admin=True
        )

    def admin_list_agents(self):
        return self._request("GET", "/admin/agents", admin=True)

    def admin_rotate_key(self, agent_id: str):
        return self._request("POST", f"/admin/agents/{agent_id}/rotate-key", admin=True)

    def admin_list_rules(self):
        return self._request("GET", "/admin/rules", admin=True)

    def admin_delete_rule(self, rule_id: str):
        return self._request("DELETE", f"/admin/rules/{rule_id}", admin=True)

    def admin_list_requests(self, limit: int = 100):
        return self._request("GET", "/admin/requests", admin=True, params={"limit": limit})

    def admin_decide(
        self,
        request_id: str,
        approve: bool,
        reason: str = "",
        duration: str | None = None,
    ):
        return self._request(
            "POST",
            f"/admin/requests/{request_id}/decide",
            admin=True,
            json={"approve": approve, "reason": reason, "duration": duration},
        )

    def admin_revoke_grant(self, grant_id: str, reason: str):
        return self._request(
            "POST", f"/admin/grants/{grant_id}/revoke", admin=True, params={"reason": reason}
        )
