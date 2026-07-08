from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..models import Agent, Grant, utcnow
from ..policy.schema import KubernetesPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError

log = logging.getLogger(__name__)

_IN_CLUSTER_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_IN_CLUSTER_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
# TokenRequest rejects expirations under 10 minutes.
_MIN_TOKEN_SECS = 600
_MAX_TOKEN_SECS = 3600
_DNS1123 = re.compile(r"[^a-z0-9-]+")


def _sa_name(agent_name: str, grant_id: str) -> str:
    base = _DNS1123.sub("-", agent_name.lower()).strip("-")
    return f"aa-{base}-{grant_id[:8]}"[:63].rstrip("-")


class KubernetesProvisioner:
    """Namespace-scoped Kubernetes access via per-grant ServiceAccounts.

    provision  = create ServiceAccount + RoleBinding (to an allowlisted
                 ClusterRole) in the target namespace.
    credential = short-lived token from the TokenRequest API, capped at the
                 grant's remaining lifetime (>=10m, k8s minimum).
    revoke     = delete the RoleBinding and ServiceAccount — every token minted
                 for it dies immediately, so revocation is instant and total.

    Convention: capability="namespace", resource=<namespace>,
    scope={"role": <ClusterRole name>}.
    """

    platform = Platform.KUBERNETES

    def __init__(
        self,
        api_url: str,
        config: KubernetesPlatformConfig,
        token: str = "",
        token_file: str = "",
        ca_file: str = "",
        insecure_skip_verify: bool = False,
    ):
        if api_url == "in-cluster":
            host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            api_url = f"https://{host}:{port}"
            token_file = token_file or _IN_CLUSTER_TOKEN
            ca_file = ca_file or _IN_CLUSTER_CA
        self.api_url = api_url.rstrip("/")
        self.config = config
        self._token = token
        self._token_file = token_file
        self._verify: bool | str = False if insecure_skip_verify else (ca_file or True)

    # ------------------------------------------------------------ interface

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        # The capability IS the role (view / edit / traefik-patcher / ...), so
        # policy rules can auto-approve narrow roles and surface broad ones.
        role = spec.capability.strip()
        if role not in self.config.role_allowlist:
            raise SpecValidationError(
                f"role {role!r} is not grantable; allowed: {self.config.role_allowlist}"
            )
        namespace = spec.resource.strip().lower()
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", namespace):
            raise SpecValidationError(f"invalid namespace name {namespace!r}")
        if not any(fnmatch(namespace, p) for p in self.config.namespace_allowlist):
            raise SpecValidationError(f"namespace {namespace!r} is not brokered (allowlist)")

        spec.capability = role
        spec.resource = namespace
        spec.scope = {}
        spec.notes.append(f"binds role {role!r} in namespace {namespace!r} (namespace-scoped)")
        if role in ("edit", "admin"):
            spec.notes.append(
                f"{role} can run pods as any ServiceAccount in {namespace} — broad"
            )
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        agent = await session.get(Agent, grant.agent_id)
        assert agent is not None
        namespace = grant.resource
        role = grant.capability
        name = _sa_name(agent.name, grant.id)
        meta = {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "agent-auth"},
            "annotations": {
                "agent-auth/agent": agent.name,
                "agent-auth/grant-id": grant.id,
                "agent-auth/expires-at": grant.expires_at.isoformat(),
            },
        }
        await self._create(
            f"/api/v1/namespaces/{namespace}/serviceaccounts",
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta},
        )
        await self._create(
            f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings",
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": meta,
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": role,
                },
                "subjects": [
                    {"kind": "ServiceAccount", "name": name, "namespace": namespace}
                ],
            },
        )
        return {"namespace": namespace, "service_account": name, "role": role}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        state = grant.provisioner_state or {}
        namespace = state.get("namespace")
        name = state.get("service_account")
        if not namespace or not name:
            return
        await self._delete(
            f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings/{name}"
        )
        # Deleting the ServiceAccount invalidates every token minted for it.
        await self._delete(f"/api/v1/namespaces/{namespace}/serviceaccounts/{name}")

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
            raise ProvisionerError("grant is not active; refusing to mint a token")
        state = grant.provisioner_state or {}
        namespace, name = state.get("namespace"), state.get("service_account")
        if not namespace or not name:
            raise ProvisionerError("grant has no provisioned service account")

        remaining = int((grant.expires_at - utcnow()).total_seconds())
        expiration = max(_MIN_TOKEN_SECS, min(_MAX_TOKEN_SECS, remaining))
        resp = await self._request(
            "POST",
            f"/api/v1/namespaces/{namespace}/serviceaccounts/{name}/token",
            json={
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "spec": {"expirationSeconds": expiration},
            },
        )
        if resp.status_code not in (200, 201):
            log.error(
                "TokenRequest failed for %s/%s (%s): %s",
                namespace,
                name,
                resp.status_code,
                resp.text[:300],
            )
            raise ProvisionerError(f"TokenRequest failed ({resp.status_code})")
        status = resp.json().get("status", {})
        expires_at = None
        if status.get("expirationTimestamp"):
            expires_at = datetime.fromisoformat(
                status["expirationTimestamp"].replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        return CredentialOut(
            kind="kubernetes_token",
            value=status.get("token"),
            expires_at=expires_at,
            note=(
                f"bearer token for ServiceAccount {namespace}/{name} "
                f"({state.get('role')}) against {self.api_url}; "
                "re-fetch rather than caching — the account is deleted when the grant ends"
            ),
        )

    # -------------------------------------------------------------- helpers

    def _bearer(self) -> str:
        if self._token_file:
            try:
                # Re-read every call: kubelet-projected tokens rotate.
                return Path(self._token_file).read_text().strip()
            except OSError as exc:
                raise ProvisionerError(f"cannot read kubernetes token file: {exc}")
        if not self._token:
            raise ProvisionerError("no kubernetes credentials configured")
        return self._token

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=20, verify=self._verify) as client:
                return await client.request(
                    method,
                    f"{self.api_url}{path}",
                    headers={"Authorization": f"Bearer {self._bearer()}"},
                    **kwargs,
                )
        except httpx.HTTPError as exc:
            raise ProvisionerError(f"kubernetes API unreachable: {exc}")

    async def _create(self, path: str, body: dict) -> None:
        resp = await self._request("POST", path, json=body)
        if resp.status_code == 409:  # already exists → idempotent success
            return
        if resp.status_code not in (200, 201):
            log.error(
                "create %s at %s failed (%s): %s",
                body["kind"],
                path,
                resp.status_code,
                resp.text[:300],
            )
            raise ProvisionerError(
                f"create {body['kind']} failed ({resp.status_code})"
            )

    async def _delete(self, path: str) -> None:
        resp = await self._request("DELETE", path)
        if resp.status_code in (200, 202, 404):  # 404 → already gone
            return
        log.error("delete %s failed (%s): %s", path, resp.status_code, resp.text[:300])
        raise ProvisionerError(f"delete failed ({resp.status_code})")
