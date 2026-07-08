from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import Platform
from ..models import Grant
from ..schemas import CredentialOut
from .base import RequestSpec, SpecValidationError

_KNOWN_CAPABILITIES = {"calendar.read", "calendar.write", "gmail.read", "drive.read"}


class GoogleStubProvisioner:
    """Records Google Workspace decisions; credential minting is not implemented yet.

    Convention: capability in {calendar.read, calendar.write, gmail.read, drive.read},
    resource=<calendar id / label / folder, or '*'>.
    """

    platform = Platform.GOOGLE

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability not in _KNOWN_CAPABILITIES:
            raise SpecValidationError(
                f"unknown google capability {spec.capability!r}; "
                f"known: {sorted(_KNOWN_CAPABILITIES)}"
            )
        spec.notes.append("google provisioning is a stub: decision recorded, no credential minted")
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        return {"stub": True}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        return None

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        raise NotImplementedError("google workspace provisioning is not implemented")
