from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..models import Grant, utcnow
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
_GROUPS_QUERY = "query { groups { id displayName } }"
_USER_GROUPS_QUERY = """
query UserGroups($user: String!) {
  user(userId: $user) { groups { id } }
}
"""


class LldapProvisioner:
    """Homelab access via LLDAP group membership.

    Each agent has a pre-created LLDAP service account (agents.lldap_username);
    Authelia access rules are pre-configured per group. Grant = add the account
    to the group; revoke = remove it. The broker never edits Authelia config
    and never talks to downstream services (e.g. the agent mints its own Gitea
    tokens once it is in the right group).

    Convention: capability="group", resource=<lldap group name>, scope={}.
    """

    platform = Platform.HOMELAB

    def __init__(self, url: str, admin_user: str, admin_password: str, config: HomelabPlatformConfig):
        self.url = url.rstrip("/")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.config = config
        self._jwt: str | None = None
        self._group_ids: dict[str, int] = {}

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability != "group":
            raise SpecValidationError("homelab capability must be 'group'")
        group = spec.resource.strip()
        if self.config.allowed_groups and group not in self.config.allowed_groups:
            raise SpecValidationError(f"group {group!r} is not brokered (allowed_groups)")
        if not spec.agent.lldap_username:
            raise SpecValidationError(
                f"agent {spec.agent.name!r} has no LLDAP service account configured"
            )
        spec.resource = group
        spec.scope = {}
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        from ..models import Agent

        agent = await session.get(Agent, grant.agent_id)
        assert agent is not None and agent.lldap_username
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
        return CredentialOut(
            kind="lldap_group",
            note=(
                f"your service account is now in group {grant.resource!r}; "
                "authenticate to Authelia-protected services with your own credentials"
            ),
        )

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

    async def _graphql(self, query: str, variables: dict | None = None) -> dict:
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
