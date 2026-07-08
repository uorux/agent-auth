from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import Platform
from ..models import Agent, Grant
from ..schemas import CredentialOut


class ProvisionerError(Exception):
    """Provisioning/revocation failure (external system)."""


class SpecValidationError(Exception):
    """Request is structurally invalid or exceeds a hard ceiling → immediate deny."""


@dataclass
class RequestSpec:
    agent: Agent
    capability: str
    resource: str
    scope: dict[str, Any] = field(default_factory=dict)
    # Validator commentary surfaced to humans/LLM as risk context
    notes: list[str] = field(default_factory=list)


@runtime_checkable
class Provisioner(Protocol):
    platform: Platform

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        """Normalize the spec (canonical resource, sorted scope) or raise SpecValidationError."""
        ...

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        """Apply the grant externally. Idempotent. Returns provisioner_state."""
        ...

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        """Remove external access. Idempotent; raise ProvisionerError to retry later."""
        ...

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        """Return/mint a credential. MUST refuse unless the grant is ACTIVE."""
        ...


class ProvisionerRegistry:
    def __init__(self) -> None:
        self._by_platform: dict[Platform, Provisioner] = {}

    def register(self, provisioner: Provisioner) -> None:
        self._by_platform[provisioner.platform] = provisioner

    def get(self, platform: Platform) -> Provisioner:
        try:
            return self._by_platform[platform]
        except KeyError:
            raise SpecValidationError(
                f"platform {platform.value!r} is not enabled on this broker"
            ) from None

    def enabled(self, platform: Platform) -> bool:
        return platform in self._by_platform
