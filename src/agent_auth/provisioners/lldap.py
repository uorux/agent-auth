from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..crypto import SecretBox
from ..models import Agent, Grant, utcnow
from ..policy.schema import HomelabPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError

log = logging.getLogger(__name__)

_ADD_MUTATION = """
mutation AddUserToGroup($user: String!, $group: Int!) {
  addUserToGroup(userId: $user, groupId: $group) { ok }
}
"""
_REMOVE_MUTATION = """
mutation RemoveUserFromGroup($user: String!, $group: Int!) {
  removeUserFromGroup(userId: $user, groupId: $group) { ok }
}
"""
_CREATE_USER_MUTATION = """
mutation CreateUser($user: CreateUserInput!) {
  createUser(user: $user) { id }
}
"""
_GROUPS_QUERY = "query { groups { id displayName } }"
_USER_EXISTS_QUERY = """
query UserExists($user: String!) {
  user(userId: $user) { id }
}
"""
_USER_GROUPS_QUERY = """
query UserGroups($user: String!) {
  user(userId: $user) { groups { id } }
}
"""


class LldapProvisioner:
    """Homelab access via LLDAP group membership.

    Each agent has an LLDAP service account (agents.lldap_username) — either
    pre-created by hand, or a *managed account* the broker creates itself at
    the agent's first homelab grant (createUser + a generated password set via
    ``lldap_set_password``, stored Fernet-wrapped on the agent and returned by
    credential fetches). Authelia access rules are pre-configured per group.
    Grant = add the account to the group; revoke = remove it. The broker never
    edits Authelia config and never talks to downstream services (e.g. the
    agent mints its own Gitea tokens once it is in the right group).

    Convention: capability="group", resource=<lldap group name>, scope={}.
    """

    platform = Platform.HOMELAB

    def __init__(
        self,
        url: str,
        admin_user: str,
        admin_password: str,
        config: HomelabPlatformConfig,
        secret_box: SecretBox | None = None,
        set_password_bin: str = "lldap_set_password",
    ):
        self.url = url.rstrip("/")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.config = config
        # None → managed accounts unavailable (no ENCRYPTION_KEY); agents then
        # need a hand-registered lldap_username as before.
        self.secret_box = secret_box
        self.set_password_bin = set_password_bin
        self._jwt: str | None = None
        self._group_ids: dict[str, int] = {}
        # One account creation at a time: two grants racing on a fresh agent
        # must not both try to createUser.
        self._account_lock = asyncio.Lock()

    @property
    def manages_accounts(self) -> bool:
        return self.config.managed_accounts and self.secret_box is not None

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability != "group":
            raise SpecValidationError("homelab capability must be 'group'")
        group = spec.resource.strip()
        if self.config.allowed_groups and group not in self.config.allowed_groups:
            raise SpecValidationError(f"group {group!r} is not brokered (allowed_groups)")
        if not spec.agent.lldap_username and not self.manages_accounts:
            raise SpecValidationError(
                f"agent {spec.agent.name!r} has no LLDAP service account configured"
            )
        spec.resource = group
        spec.scope = {}
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        agent = await session.get(Agent, grant.agent_id)
        assert agent is not None
        if not agent.lldap_username:
            await self.ensure_account(session, agent)
        group_id = await self._group_id(grant.resource)
        await self._mutate(_ADD_MUTATION, agent.lldap_username, group_id, want_member=True)
        return {"lldap_user": agent.lldap_username, "group": grant.resource, "group_id": group_id}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        state = grant.provisioner_state or {}
        user = state.get("lldap_user")
        group_id = state.get("group_id")
        if not user or group_id is None:
            return
        # Membership is one (user, group) fact shared by every grant on the
        # group — only the LAST effective grant may remove it. expires_at is
        # checked too (not just ACTIVE) so that when several grants lapse in
        # the same scheduler tick, one of them still performs the removal.
        keeper = (
            await session.execute(
                select(Grant.id)
                .where(
                    Grant.id != grant.id,
                    Grant.agent_id == grant.agent_id,
                    Grant.platform == Platform.HOMELAB,
                    Grant.resource == grant.resource,
                    Grant.status == GrantStatus.ACTIVE,
                    Grant.expires_at > utcnow(),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if keeper is not None:
            log.info(
                "keeping %r in group %r: still backed by active grant %s",
                user,
                grant.resource,
                keeper,
            )
            return
        await self._mutate(_REMOVE_MUTATION, user, group_id, want_member=False)

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
            raise ProvisionerError("grant is not active")
        agent = await session.get(Agent, grant.agent_id)
        if agent is not None and agent.lldap_password_encrypted and self.secret_box is not None:
            # Managed account: the broker holds the password, so the credential
            # IS the account. Same value on every fetch until rotated.
            return CredentialOut(
                kind="lldap_account",
                username=agent.lldap_username,
                value=self.secret_box.decrypt(agent.lldap_password_encrypted),
                note=(
                    f"LLDAP service account {agent.lldap_username!r} is in group "
                    f"{grant.resource!r}; log in to Authelia-protected services "
                    "with this username/password"
                ),
            )
        return CredentialOut(
            kind="lldap_group",
            username=agent.lldap_username if agent else None,
            note=(
                f"your service account is now in group {grant.resource!r}; "
                "authenticate to Authelia-protected services with your own credentials"
            ),
        )

    # -- managed accounts -------------------------------------------------

    def managed_username(self, agent: Agent) -> str:
        # LLDAP user ids: lowercase, [a-z0-9_.-]; agent names are already
        # restricted to [A-Za-z0-9._-].
        return (self.config.managed_username_prefix + agent.name).lower()

    async def ensure_account(self, session: AsyncSession, agent: Agent) -> None:
        """Create the agent's managed LLDAP account if it has none.

        Idempotent across crashes: an account left behind by an earlier attempt
        (created, but the password step failed before the row was written) is
        adopted — it carries the managed name and no other agent can own it.
        """
        if agent.lldap_username:
            return
        if not self.manages_accounts:
            raise ProvisionerError(
                f"agent {agent.name!r} has no LLDAP service account and managed "
                "accounts are unavailable (ENCRYPTION_KEY unset or disabled in policy)"
            )
        async with self._account_lock:
            await session.refresh(agent)
            if agent.lldap_username:
                return
            username = self.managed_username(agent)
            if not re.fullmatch(r"[a-z0-9_.-]+", username):
                raise ProvisionerError(f"cannot derive an LLDAP user id from {agent.name!r}")
            if not await self._user_exists(username):
                await self._graphql(
                    _CREATE_USER_MUTATION,
                    {
                        "user": {
                            "id": username,
                            "email": f"{username}@{self.config.managed_email_domain}",
                            "displayName": f"{agent.name} (agent-auth managed)",
                        }
                    },
                )
                log.info("created LLDAP account %r for agent %r", username, agent.name)
            else:
                log.info("adopting existing LLDAP account %r for agent %r", username, agent.name)
            password = await self._set_new_password(username)
            agent.lldap_username = username
            agent.lldap_password_encrypted = self.secret_box.encrypt(password)
            await session.flush()

    async def rotate_password(self, session: AsyncSession, agent: Agent) -> None:
        """Replace a managed account's password; the next credential fetch
        returns the new one. Refused for hand-registered accounts."""
        if not agent.lldap_username or not agent.lldap_password_encrypted:
            raise ProvisionerError(
                f"agent {agent.name!r} has no broker-managed LLDAP account to rotate"
            )
        if self.secret_box is None:
            raise ProvisionerError("ENCRYPTION_KEY is unset; cannot store the new password")
        password = await self._set_new_password(agent.lldap_username)
        agent.lldap_password_encrypted = self.secret_box.encrypt(password)
        await session.flush()

    async def _set_new_password(self, username: str) -> str:
        password = secrets.token_urlsafe(32)
        await self._run_set_password(username, password)
        return password

    async def _run_set_password(self, username: str, password: str) -> None:
        # OPAQUE registration has no plain-JSON form, so drive LLDAP's own
        # client. A fresh JWT every time: the cached one may be a day old.
        token = await self._login()
        env = {**os.environ, "LLDAP_USER_PASSWORD": password}
        try:
            proc = await asyncio.create_subprocess_exec(
                self.set_password_bin,
                "--base-url",
                self.url,
                "--token",
                token,
                "--username",
                username,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            raise ProvisionerError(
                f"{self.set_password_bin!r} not found; install lldap's lldap_set_password "
                "or set LLDAP_SET_PASSWORD_BIN"
            ) from None
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            raise ProvisionerError("lldap_set_password timed out") from None
        if proc.returncode != 0:
            log.error(
                "lldap_set_password failed for %r (rc=%s): %s",
                username,
                proc.returncode,
                out.decode(errors="replace")[:300],
            )
            raise ProvisionerError("lldap_set_password failed (see broker logs)")

    async def _user_exists(self, username: str) -> bool:
        try:
            data = await self._graphql(
                _USER_EXISTS_QUERY, {"user": username}, log_errors=False
            )
        except ProvisionerError:
            # LLDAP answers an unknown user with a GraphQL error, not null.
            return False
        return bool((data.get("data") or {}).get("user"))

    async def _login(self) -> str:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self.url}/auth/simple/login",
                json={"username": self.admin_user, "password": self.admin_password},
            )
        if resp.status_code != 200:
            raise ProvisionerError(f"LLDAP login failed ({resp.status_code})")
        self._jwt = resp.json()["token"]
        return self._jwt

    async def _graphql(
        self, query: str, variables: dict | None = None, *, log_errors: bool = True
    ) -> dict:
        token = self._jwt or await self._login()
        for attempt in range(2):
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self.url}/api/graphql",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"query": query, "variables": variables or {}},
                )
            if resp.status_code == 401 and attempt == 0:
                token = await self._login()  # JWT expired (~1 day); re-login once
                continue
            break
        if resp.status_code != 200:
            log.error("LLDAP GraphQL error (%s): %s", resp.status_code, resp.text[:300])
            raise ProvisionerError(f"LLDAP GraphQL error ({resp.status_code})")
        data = resp.json()
        if data.get("errors"):
            msgs = "; ".join(e.get("message", "") for e in data["errors"])
            if log_errors:
                log.error("LLDAP GraphQL error: %s", msgs)
            raise ProvisionerError("LLDAP GraphQL error (see broker logs)")
        return data

    async def _group_id(self, name: str) -> int:
        if name not in self._group_ids:
            data = await self._graphql(_GROUPS_QUERY)
            self._group_ids = {
                g["displayName"]: g["id"] for g in data["data"]["groups"]
            }
        if name not in self._group_ids:
            raise ProvisionerError(f"LLDAP group {name!r} does not exist")
        return self._group_ids[name]

    async def _mutate(
        self, mutation: str, user: str, group_id: int, *, want_member: bool
    ) -> None:
        try:
            await self._graphql(mutation, {"user": user, "group": group_id})
        except ProvisionerError as exc:
            # LLDAP reports duplicate adds / absent removes as opaque database
            # errors, so verify the end state instead of parsing messages:
            # membership already where we wanted it is success.
            try:
                member = group_id in await self._user_group_ids(user)
            except ProvisionerError:
                raise exc from None
            if member != want_member:
                raise
            log.info(
                "LLDAP no-op: %r already %s group %s",
                user,
                "in" if want_member else "out of",
                group_id,
            )

    async def _user_group_ids(self, user: str) -> set[int]:
        data = await self._graphql(_USER_GROUPS_QUERY, {"user": user})
        return {g["id"] for g in data["data"]["user"]["groups"]}
