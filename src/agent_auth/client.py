from __future__ import annotations

import os
import time
from typing import Any

import httpx


class BrokerError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


# One long-poll request stays under what a reverse proxy in front of the broker
# allows (Cloudflare cuts a request at 100s); a longer wait is several of them.
POLL_SLICE = 60.0
WAITING = ("pending", "llm_evaluating", "awaiting_human", "approved", "provisioning")
JOB_ENDED = ("done", "refused", "lost")


def _poll(fetch, settled, total: float):
    """fetch(wait) repeatedly, each at most POLL_SLICE long, until settled(result)
    or `total` seconds have gone by. Returns the last result."""
    deadline = time.monotonic() + total
    while True:
        left = deadline - time.monotonic()
        out = fetch(max(0.0, min(left, POLL_SLICE)))
        if settled(out) or deadline - time.monotonic() <= 0:
            return out


class BrokerClient:
    """Thin sync client over the broker HTTP API, shared by the CLI and MCP server."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        session_id: str | None = None,
    ):
        self.base_url = (base_url or os.environ.get("AGENT_AUTH_URL", "https://agent-auth.rooty.dev")).rstrip("/")
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

    def attention(self, text: str, urgency: str = "normal"):
        return self._request("POST", "/v1/attention", json={"text": text, "urgency": urgency})

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
        return _poll(
            lambda t: self._request(
                "GET", f"/v1/requests/{request_id}/wait", params={"timeout": t}, timeout=t + 10
            ),
            lambda req: req.get("status") not in WAITING,
            timeout,
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
        return _poll(
            lambda t: self._request(
                "GET",
                f"/v1/a2a/threads/{thread_id}/messages",
                params={"after_seq": after_seq, "wait": t},
                timeout=t + 10,
            ),
            lambda out: bool(out.get("messages")) or out.get("thread", {}).get("state") == "closed",
            wait,
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
        return _poll(
            lambda t: self._request(
                "GET", "/v1/a2a/events", params={**params, "wait": t}, timeout=t + 10
            ),
            lambda out: bool(out.get("pending_opens") or out.get("activity")),
            wait,
        )

    # admin operations
    def admin_set_attributes(self, agent: str, **fields: str):
        return self._request("PATCH", f"/admin/agents/{agent}/attributes", admin=True, json=fields)

    def admin_create_agent(
        self,
        name: str,
        description: str = "",
        webhook_url: str | None = None,
        lldap_username: str | None = None,
        kind: str = "service",
        runtime: str | None = None,
        project: str | None = None,
        host: str | None = None,
    ):
        return self._request(
            "POST",
            "/admin/agents",
            admin=True,
            json={
                "name": name,
                "description": description,
                "kind": kind,
                "runtime": runtime,
                "project": project,
                "host": host,
                "webhook_url": webhook_url,
                "lldap_username": lldap_username,
            },
        )

    def admin_rotate_lldap_password(self, agent_id: str):
        return self._request(
            "POST", f"/admin/agents/{agent_id}/rotate-lldap-password", admin=True
        )

    def admin_rotate_webhook_secret(self, agent_id: str):
        return self._request(
            "POST", f"/admin/agents/{agent_id}/rotate-webhook-secret", admin=True
        )

    def admin_set_webhook(self, agent_id: str, webhook_url: str | None):
        return self._request(
            "POST",
            f"/admin/agents/{agent_id}/set-webhook",
            admin=True,
            json={"webhook_url": webhook_url},
        )

    def admin_set_kind(self, agent_id: str, kind: str):
        return self._request(
            "POST",
            f"/admin/agents/{agent_id}/set-kind",
            admin=True,
            json={"kind": kind},
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
        totp: str | None = None,
    ):
        return self._request(
            "POST",
            f"/admin/requests/{request_id}/decide",
            admin=True,
            json={"approve": approve, "reason": reason, "duration": duration, "totp": totp},
        )

    def admin_revoke_grant(self, grant_id: str, reason: str):
        return self._request(
            "POST", f"/admin/grants/{grant_id}/revoke", admin=True, params={"reason": reason}
        )

    # --- paired daemons -------------------------------------------------------

    def admin_create_pairing_code(self, role: str, name: str):
        return self._request(
            "POST", "/admin/daemons/pairing-codes", admin=True, json={"role": role, "name": name}
        )

    def admin_disable_agent(self, agent_id: str):
        return self._request("POST", f"/admin/agents/{agent_id}/disable", admin=True)

    def admin_list_daemons(self):
        return self._request("GET", "/admin/daemons", admin=True)

    def admin_unpair_daemon(self, daemon_id: str):
        return self._request("DELETE", f"/admin/daemons/{daemon_id}", admin=True)

    def admin_broker_key(self):
        return self._request("GET", "/admin/broker-key", admin=True)

    def admin_hosts(self):
        return self._request("GET", "/admin/hosts", admin=True)

    def admin_arm(self, host: str, tier: str, duration: str, totp: str):
        return self._request(
            "POST", f"/admin/hosts/{host}/arm", admin=True,
            json={"tier": tier, "duration": duration, "totp": totp},
        )

    def admin_disarm(self, host: str, tier: str | None = None):
        return self._request(
            "POST", f"/admin/hosts/{host}/disarm", admin=True, params={"tier": tier} if tier else None
        )

    def admin_lockdown(self, scope: str, host: str | None, kill_vm: bool):
        return self._request(
            "POST", "/admin/lockdown", admin=True, json={"scope": scope, "host": host, "kill_vm": kill_vm}
        )

    def admin_unlock(self, host: str | None, totp: str | None):
        return self._request("POST", "/admin/unlock", admin=True, json={"host": host, "totp": totp})

    # --- commands on hosts ------------------------------------------------------

    def host_job(self, job_id: str, wait: float = 0):
        return _poll(
            lambda t: self._request(
                "GET", f"/v1/hostexec/jobs/{job_id}", params={"wait": t}, timeout=t + 15
            ),
            lambda job: job.get("status") in JOB_ENDED,
            wait,
        )

    def host_shell_exec(self, grant_id: str, argv: list[str], cwd: str | None = None,
                        stdin: str | None = None, timeout: int | None = None, wait: float = 60):
        # The exec itself is one request (it must not be sent twice); the rest
        # of the wait is on the job it returns.
        first = min(wait, POLL_SLICE)
        job = self._request(
            "POST", f"/v1/hostexec/shells/{grant_id}/exec", timeout=first + 30,
            json={"argv": argv, "cwd": cwd, "stdin": stdin, "timeout": timeout, "wait": first},
        )
        if wait > first and job.get("id") and job.get("status") not in JOB_ENDED:
            return self.host_job(job["id"], wait - first)
        return job

    def host_shell_close(self, grant_id: str):
        return self._request("POST", f"/v1/hostexec/shells/{grant_id}/close")
