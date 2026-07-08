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

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or os.environ.get("AGENT_AUTH_URL", "http://localhost:8400")).rstrip("/")
        self.api_key = api_key or os.environ.get("AGENT_AUTH_API_KEY", "")
        self.admin_token = os.environ.get("AGENT_AUTH_ADMIN_TOKEN", "")

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
        with httpx.Client(timeout=timeout) as client:
            resp = client.request(
                method,
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {token}"},
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

    def request_access(
        self,
        platform: str,
        capability: str,
        resource: str,
        justification: str,
        duration: str,
        scope: dict | None = None,
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

    def a2a_check(self, peer: str, direction: str = "out", topic: str | None = None):
        params: dict[str, Any] = {"peer": peer, "direction": direction}
        if topic:
            params["topic"] = topic
        return self._request("GET", "/v1/a2a/check", params=params)

    def a2a_send(self, to: str, payload: dict, topic: str | None = None):
        return self._request(
            "POST", "/v1/a2a/send", json={"to": to, "scope": topic, "payload": payload}
        )

    def a2a_inbox(self):
        return self._request("GET", "/v1/a2a/inbox")

    def a2a_ack(self, message_id: str):
        return self._request("POST", f"/v1/a2a/inbox/{message_id}/ack")

    # admin operations
    def admin_create_agent(self, name: str, description: str = "", webhook_url: str | None = None, lldap_username: str | None = None):
        return self._request(
            "POST",
            "/admin/agents",
            admin=True,
            json={
                "name": name,
                "description": description,
                "webhook_url": webhook_url,
                "lldap_username": lldap_username,
            },
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
