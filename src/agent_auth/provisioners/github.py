from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..crypto import SecretBox
from ..models import Credential, Grant, utcnow
from ..policy.schema import GithubPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError

log = logging.getLogger(__name__)

_PERM_LEVELS = {"read": 1, "write": 2, "admin": 3}
# Refresh the cached installation token when less than this much validity remains.
_MIN_TOKEN_VALIDITY = timedelta(minutes=5)
# GitHub's repository name charset; "." and ".." are reserved.
_REPO_NAME = re.compile(r"^[a-z0-9._-]{1,100}$")
_VISIBILITIES = ("private", "public")


def _fnmatch_any(name: str, patterns: list[str]) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(name, p) for p in patterns)


class GithubProvisioner:
    """Mints GitHub App installation tokens scoped to repos + permissions.

    Installation tokens live at most 1h, so the broker re-mints on demand for
    the life of the grant and hard-refuses once the grant is not ACTIVE. A
    token minted just before revocation can outlive it by up to ~55 minutes.

    The app may be installed on several accounts (personal + orgs); the
    installation for a repo is resolved via GET /repos/{owner}/{repo}/installation
    and cached. Setting installation_id pins a single installation instead;
    only repos owned by that installation's account are then mintable.

    Convention: capability="repo", resource="owner/repo",
    scope={"permissions": {"contents": "write", "secrets": "write", ...}}.

    capability="create", resource="org/name", scope={"visibility": "private"}
    creates the repo instead (organizations in `create_owners` only). The
    broker does the creating itself, with an Administration:write token it
    mints for that one call and revokes straight after — far broader than
    "create one repo" (it could delete or reconfigure any repo the
    installation covers), so it never leaves the broker. Access to the new
    repo is an ordinary "repo" grant afterwards. Nothing is undone at expiry:
    the broker never deletes repos.
    """

    platform = Platform.GITHUB

    def __init__(
        self,
        app_id: str,
        private_key_file: str,
        api_url: str,
        config: GithubPlatformConfig,
        secret_box: SecretBox,
        installation_id: str = "",
    ):
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key_file = private_key_file
        self.api_url = api_url.rstrip("/")
        self.config = config
        self.secret_box = secret_box
        self._installation_cache: dict[str, int] = {}
        # Account (owner login, lowercased) the pinned installation belongs to;
        # resolved once on first use.
        self._pinned_account: str | None = None

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability == "create":
            return self._validate_create(spec)
        if spec.capability != "repo":
            raise SpecValidationError("github capability must be 'repo' or 'create'")
        repo = spec.resource.strip().strip("/").lower()
        if repo.count("/") != 1:
            raise SpecValidationError("github resource must be 'owner/repo'")
        if _fnmatch_any(repo, self.config.repo_denylist):
            raise SpecValidationError(f"repo {repo!r} is never brokered (denylist)")
        if self.config.repo_allowlist and not _fnmatch_any(repo, self.config.repo_allowlist):
            raise SpecValidationError(f"repo {repo!r} is not in the allowlist")

        permissions = spec.scope.get("permissions")
        if not isinstance(permissions, dict) or not permissions:
            raise SpecValidationError(
                "scope.permissions is required, e.g. {\"contents\": \"write\"}"
            )
        normalized: dict[str, str] = {}
        for perm, level in sorted(permissions.items()):
            level = str(level).lower()
            if level not in _PERM_LEVELS:
                raise SpecValidationError(f"invalid permission level {level!r} for {perm!r}")
            ceiling = self.config.permission_ceiling.get(perm)
            if ceiling is None:
                raise SpecValidationError(f"permission {perm!r} is not grantable by policy")
            if _PERM_LEVELS[level] > _PERM_LEVELS[ceiling]:
                raise SpecValidationError(
                    f"permission {perm}:{level} exceeds policy ceiling {perm}:{ceiling}"
                )
            normalized[perm] = level
            if _PERM_LEVELS[level] >= _PERM_LEVELS["write"]:
                spec.notes.append(f"grants {perm}:{level} on {repo}")

        spec.resource = repo
        spec.scope = {"permissions": normalized}
        return spec

    def _validate_create(self, spec: RequestSpec) -> RequestSpec:
        repo = spec.resource.strip().strip("/").lower()
        if repo.count("/") != 1:
            raise SpecValidationError("github create resource must be 'org/name'")
        owner, name = repo.split("/")
        if owner not in {o.lower() for o in self.config.create_owners}:
            raise SpecValidationError(
                f"repos can't be created under {owner!r} (platforms.github.create_owners)"
            )
        if not _REPO_NAME.match(name) or name in (".", "..") or name.endswith(".git"):
            raise SpecValidationError(f"invalid repository name {name!r}")
        if _fnmatch_any(repo, self.config.repo_denylist):
            raise SpecValidationError(f"repo {repo!r} is never brokered (denylist)")
        if self.config.repo_allowlist and not _fnmatch_any(repo, self.config.repo_allowlist):
            raise SpecValidationError(f"repo {repo!r} is not in the allowlist")
        unknown = set(spec.scope) - {"visibility"}
        if unknown:
            raise SpecValidationError(f"unknown scope keys for create: {sorted(unknown)}")
        visibility = str(spec.scope.get("visibility", "private")).lower()
        if visibility not in _VISIBILITIES:
            raise SpecValidationError("scope.visibility must be 'private' or 'public'")
        spec.notes.append(f"creates a new {visibility} repo {repo}")
        if visibility == "public":
            spec.notes.append("PUBLIC: everything pushed to it is visible to anyone")
        spec.resource = repo
        spec.scope = {"visibility": visibility}
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        if grant.capability == "create":
            return await self._create(grant)
        # Minting a token scoped to the repo proves the installation covers it.
        token, expires_at = await self._mint(grant)
        await self._cache_token(session, grant, token, expires_at)
        return {"repo": grant.resource, "permissions": grant.scope["permissions"]}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        if grant.capability == "create":
            return  # nothing to undo: the broker never deletes repos
        cred = await self._cached(session, grant)
        if cred is not None:
            try:
                token = self.secret_box.decrypt(cred.value_encrypted)
                async with httpx.AsyncClient(timeout=15) as client:
                    await client.delete(
                        f"{self.api_url}/installation/token",
                        headers=self._token_headers(token),
                    )
            except Exception:
                # Best effort: enforcement is the refusal to re-mint below.
                log.warning("failed to revoke cached token for grant %s", grant.id)
        await session.execute(delete(Credential).where(Credential.grant_id == grant.id))

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
            raise ProvisionerError("grant is not active; refusing to mint a token")
        if grant.capability == "create":
            # No token: the repo exists now. Report what happened.
            state = grant.provisioner_state or {}
            note = (
                f"{'created' if state.get('created') else 'already existed'}: "
                f"{state.get('repo')} ({state.get('visibility')}). Request a 'repo' "
                "grant on it for access."
            )
            if not state.get("installation_covers", True):
                note += (
                    " The broker's GitHub App installation does not cover it yet, so repo "
                    "grants on it will fail until it is added to the installation."
                )
            return CredentialOut(kind="github_repo", value=state.get("html_url"), note=note)
        cred = await self._cached(session, grant)
        if cred is not None and cred.expires_at - utcnow() > _MIN_TOKEN_VALIDITY:
            token = self.secret_box.decrypt(cred.value_encrypted)
            return CredentialOut(
                kind="github_installation_token", value=token, expires_at=cred.expires_at
            )
        token, expires_at = await self._mint(grant)
        await self._cache_token(session, grant, token, expires_at)
        return CredentialOut(
            kind="github_installation_token", value=token, expires_at=expires_at
        )

    async def _cached(self, session: AsyncSession, grant: Grant) -> Credential | None:
        return (
            await session.execute(
                select(Credential)
                .where(Credential.grant_id == grant.id)
                .order_by(Credential.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def _cache_token(
        self, session: AsyncSession, grant: Grant, token: str, expires_at: datetime
    ) -> None:
        await session.execute(delete(Credential).where(Credential.grant_id == grant.id))
        session.add(
            Credential(
                grant_id=grant.id,
                kind="github_installation_token",
                value_encrypted=self.secret_box.encrypt(token),
                expires_at=expires_at,
            )
        )

    async def _installation_for(self, repo: str) -> str:
        """Resolve which installation covers this repo; the app may be
        installed on multiple accounts (personal + orgs)."""
        if self.installation_id:
            # The token endpoint takes BARE repo names resolved against the
            # installation's account, so the owner half of `resource` — the
            # half the allow/denylists were checked against — would otherwise
            # be silently discarded: "other-org/nixos-dots" would mint a token
            # for the pinned account's "nixos-dots". Refuse owner mismatches.
            owner = repo.split("/", 1)[0]
            account = await self._pinned_account_login()
            if owner != account:
                raise ProvisionerError(
                    f"repo {repo!r} is not covered by the pinned installation "
                    f"(GITHUB_INSTALLATION_ID belongs to {account!r}); unset it "
                    "to resolve installations per repo"
                )
            return self.installation_id
        if repo in self._installation_cache:
            return str(self._installation_cache[repo])
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_url}/repos/{repo}/installation",
                headers=self._app_headers(),
            )
        if resp.status_code == 404:
            raise ProvisionerError(
                f"the GitHub App is not installed on {repo!r} "
                "(install it on that account/repo, then retry)"
            )
        if resp.status_code != 200:
            raise ProvisionerError(
                f"installation lookup for {repo!r} failed ({resp.status_code})"
            )
        installation_id = resp.json()["id"]
        self._installation_cache[repo] = installation_id
        return str(installation_id)

    async def _pinned_account_login(self) -> str:
        if self._pinned_account is not None:
            return self._pinned_account
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_url}/app/installations/{self.installation_id}",
                headers=self._app_headers(),
            )
        if resp.status_code != 200:
            raise ProvisionerError(
                f"lookup of pinned installation {self.installation_id!r} failed "
                f"({resp.status_code})"
            )
        login = (resp.json().get("account") or {}).get("login")
        if not login:
            raise ProvisionerError(
                f"pinned installation {self.installation_id!r} has no account login"
            )
        self._pinned_account = str(login).lower()
        return self._pinned_account

    async def _create(self, grant: Grant) -> dict:
        org, name = grant.resource.split("/", 1)
        visibility = grant.scope["visibility"]
        installation_id = await self._org_installation(org)
        token = await self._admin_token(installation_id, org)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self.api_url}/orgs/{org}/repos",
                    headers=self._token_headers(token),
                    json={
                        "name": name,
                        "visibility": visibility,
                        "private": visibility == "private",
                    },
                )
                if resp.status_code == 201:
                    repo, created = resp.json(), True
                elif resp.status_code == 422:
                    # Most likely the name is taken. Idempotent for retries
                    # (an orchestrator re-running project setup, a re-provision
                    # after a crash): adopt it if it's visible to the app.
                    existing = await client.get(
                        f"{self.api_url}/repos/{org}/{name}",
                        headers=self._token_headers(token),
                    )
                    if existing.status_code != 200:
                        log.error("GitHub repo create for %s failed: %s", grant.resource, resp.text[:300])
                        raise ProvisionerError(f"GitHub repo create failed (422): {resp.text[:200]}")
                    repo, created = existing.json(), False
                else:
                    log.error(
                        "GitHub repo create for %s failed (%s): %s",
                        grant.resource,
                        resp.status_code,
                        resp.text[:300],
                    )
                    raise ProvisionerError(f"GitHub repo create failed ({resp.status_code})")
        finally:
            await self._revoke_token(token)
        covered = await self._installation_covers(grant.resource)
        if created:
            log.info("created GitHub repo %s (%s)", grant.resource, visibility)
        return {
            "action": "create",
            "repo": grant.resource,
            "html_url": repo.get("html_url"),
            "repo_id": repo.get("id"),
            "visibility": repo.get("visibility", visibility),
            "created": created,
            "installation_covers": covered,
        }

    async def _org_installation(self, org: str) -> str:
        if self.installation_id:
            account = await self._pinned_account_login()
            if account != org:
                raise ProvisionerError(
                    f"org {org!r} is not the pinned installation's account ({account!r})"
                )
            return self.installation_id
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.api_url}/orgs/{org}/installation", headers=self._app_headers()
            )
        if resp.status_code != 200:
            raise ProvisionerError(
                f"the GitHub App is not installed on org {org!r} ({resp.status_code})"
            )
        return str(resp.json()["id"])

    async def _admin_token(self, installation_id: str, org: str) -> str:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.api_url}/app/installations/{installation_id}/access_tokens",
                headers=self._app_headers(),
                json={"permissions": {"administration": "write", "metadata": "read"}},
            )
        if resp.status_code != 201:
            log.error("GitHub admin token mint for %s failed (%s): %s", org, resp.status_code, resp.text[:300])
            raise ProvisionerError(
                f"could not mint an Administration token for {org!r} ({resp.status_code}); "
                "does the GitHub App have Administration: write there?"
            )
        return resp.json()["token"]

    async def _revoke_token(self, token: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                await client.delete(
                    f"{self.api_url}/installation/token", headers=self._token_headers(token)
                )
        except Exception:
            # It expires within the hour regardless.
            log.warning("failed to revoke the Administration token after a repo create")

    async def _installation_covers(self, repo: str) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.api_url}/repos/{repo}/installation", headers=self._app_headers()
            )
        if resp.status_code == 200:
            self._installation_cache[repo] = resp.json()["id"]
            return True
        return False

    async def _mint(self, grant: Grant) -> tuple[str, datetime]:
        owner_repo = grant.resource.split("/", 1)[1]
        installation_id = await self._installation_for(grant.resource)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.api_url}/app/installations/{installation_id}/access_tokens",
                headers=self._app_headers(),
                json={
                    "repositories": [owner_repo],
                    "permissions": grant.scope["permissions"],
                },
            )
        if resp.status_code != 201:
            log.error(
                "GitHub token mint failed for %s (%s): %s",
                grant.resource,
                resp.status_code,
                resp.text[:300],
            )
            raise ProvisionerError(f"GitHub token mint failed ({resp.status_code})")
        data = resp.json()
        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        return data["token"], expires_at.astimezone(timezone.utc)

    def _app_headers(self) -> dict[str, str]:
        now = int(time.time())
        app_jwt = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self.app_id},
            Path(self.private_key_file).read_text(),
            algorithm="RS256",
        )
        return {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _token_headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
