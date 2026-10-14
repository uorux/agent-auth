"""Platform "models": model calls through the homelab's LiteLLM gateway.

capability "use", resource = the gateway's name (platforms.models.name). A
grant is one LiteLLM virtual key for the agent: the key belongs to a
LiteLLM user named after the agent, so the gateway counts spend per agent
across keys, and carries the agent's fields (project, host, runtime) as
metadata. The key expires with the grant at the gateway itself
(`duration`), and revoking deletes it at once: LiteLLM moves a deleted key,
with its spend, to its deleted-keys table, so the live table holds only
current keys and nothing counted is lost. The broker keeps the key
encrypted to hand it out again; it is never in the data path.

The gateway holds the model providers' logins; agents hold only their own
key, so a VM no longer needs one. What the key can reach is
platforms.models.models (empty: every model the gateway has).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..crypto import SecretBox
from ..models import Agent, Grant, utcnow
from ..policy.schema import ModelsPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError

log = logging.getLogger(__name__)

_TIMEOUT = 20


class ModelsProvisioner:
    platform = Platform.MODELS

    def __init__(self, config: ModelsPlatformConfig, master_key: str, secret_box: SecretBox):
        self.config = config
        self.master_key = master_key
        self.box = secret_box
        self.admin = (config.admin_url or config.url).rstrip("/")

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability != "use":
            raise SpecValidationError('models capability must be "use"')
        if spec.resource != self.config.name:
            raise SpecValidationError(f"unknown model gateway {spec.resource!r} (this broker has {self.config.name!r})")
        if spec.scope:
            raise SpecValidationError("no scope for models grants: what a key may call is the gateway's policy")
        if self.config.by_runtime and spec.agent.runtime not in self.config.by_runtime:
            raise SpecValidationError(
                f"no models for runtime {spec.agent.runtime or '(none)'!r} at this gateway "
                f"(only {', '.join(sorted(self.config.by_runtime))})"
            )
        spec.notes.append(f"may call: {', '.join(self._models(spec.agent)) or 'every model the gateway serves'}")
        return spec

    def _models(self, agent: Agent) -> list[str]:
        if self.config.by_runtime:
            return list(self.config.by_runtime.get(agent.runtime or "", []))
        return list(self.config.models)

    async def _call(self, method: str, path: str, **kwargs) -> httpx.Response:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                return await client.request(
                    method, f"{self.admin}{path}", headers={"Authorization": f"Bearer {self.master_key}"}, **kwargs
                )
            except httpx.HTTPError as exc:
                raise ProvisionerError(f"model gateway: {exc}") from None

    async def _ensure_user(self, agent: Agent) -> None:
        """The LiteLLM user that counts this agent's spend across its keys."""
        resp = await self._call("GET", "/user/info", params={"user_id": agent.name})
        if resp.status_code == 200 and (resp.json().get("user_info") or {}).get("user_id") == agent.name:
            return
        made = await self._call(
            "POST",
            "/user/new",
            json={
                "user_id": agent.name,
                "user_alias": agent.name,
                "user_role": "internal_user_viewer",
                "auto_create_key": False,
                "metadata": _fields(agent),
            },
        )
        if made.status_code not in (200, 201) and "already exists" not in made.text:
            raise ProvisionerError(f"model gateway refused the user for {agent.name}: {made.status_code} {made.text[:200]}")

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        agent = await session.get(Agent, grant.agent_id)
        if agent is None:
            raise ProvisionerError("agent not found")
        await self._ensure_user(agent)
        secs = max(60, int((grant.expires_at - utcnow()).total_seconds()))
        body: dict[str, Any] = {
            "user_id": agent.name,
            "key_alias": f"{agent.name}/{grant.id[:8]}",
            # The gateway ends it too, whatever happens to the broker.
            "duration": f"{secs}s",
            "metadata": {**_fields(agent), "grant_id": grant.id, "issued_by": "agent-auth"},
        }
        models = self._models(agent)
        if self.config.by_runtime and not models:
            raise ProvisionerError(f"no models for runtime {agent.runtime!r}")
        if models:
            body["models"] = models
        if self.config.max_budget is not None:
            body["max_budget"] = self.config.max_budget
            body["budget_duration"] = self.config.budget_duration
        resp = await self._call("POST", "/key/generate", json=body)
        if resp.status_code != 200 or not resp.json().get("key"):
            raise ProvisionerError(f"model gateway refused the key: {resp.status_code} {resp.text[:200]}")
        out = resp.json()
        log.info("models: key %s for %s, %ss", body["key_alias"], agent.name, secs)
        return {
            "key_encrypted": self.box.encrypt(out["key"]),
            "key_alias": body["key_alias"],
            "user_id": agent.name,
        }

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        state = grant.provisioner_state or {}
        if not state.get("key_encrypted"):
            return
        key = self.box.decrypt(state["key_encrypted"])
        resp = await self._call("POST", "/key/delete", json={"keys": [key]})
        if resp.status_code == 404 or (resp.status_code == 400 and "not found" in resp.text.lower()):
            return  # already gone at the gateway
        if resp.status_code != 200:
            raise ProvisionerError(f"model gateway did not delete {state.get('key_alias')}: {resp.status_code} {resp.text[:200]}")

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
            raise ProvisionerError("grant is not active")
        state = grant.provisioner_state or {}
        if not state.get("key_encrypted"):
            raise ProvisionerError("no key was issued for this grant")
        base = self.config.url.rstrip("/")
        return CredentialOut(
            kind="model_gateway_key",
            value=self.box.decrypt(state["key_encrypted"]),
            url=base,
            expires_at=grant.expires_at,
            note=(
                f"Claude Code: ANTHROPIC_BASE_URL={base} and ANTHROPIC_AUTH_TOKEN=<this key>. "
                f"OpenAI-compatible clients (codex): base URL {base}/v1 with this key. "
                "The key is yours alone and ends with the grant."
            ),
        )

    async def usage(self) -> list[dict[str, Any]]:
        """Spend per agent: the gateway's users, as many pages as there are."""
        users: list[dict[str, Any]] = []
        for page in range(1, 51):
            resp = await self._call("GET", "/user/list", params={"page": page, "page_size": 100})
            if resp.status_code != 200:
                raise ProvisionerError(f"model gateway: {resp.status_code} {resp.text[:200]}")
            data = resp.json()
            batch = data.get("users") if isinstance(data, dict) else data
            users.extend(batch or [])
            if not batch or (isinstance(data, dict) and page >= int(data.get("total_pages") or 1)):
                break
        return users


def _fields(agent: Agent) -> dict[str, Any]:
    return {
        "agent": agent.name,
        "project": agent.project,
        "host": agent.host,
        "runtime": agent.runtime,
        "placement": agent.placement,
    }

