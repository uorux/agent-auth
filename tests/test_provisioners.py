from __future__ import annotations

from datetime import timedelta

import pytest

from agent_auth.core.states import GrantStatus, Platform, RequestStatus
from agent_auth.models import Grant, utcnow
from agent_auth.provisioners.base import ProvisionerError, SpecValidationError, RequestSpec
from agent_auth.schemas import RequestCreate

from .conftest import GITHUB_API as GITHUB_API_URL, make_agent


def github_request(resource="jrt/cactus", permissions=None, duration="2h"):
    return RequestCreate(
        platform=Platform.GITHUB,
        capability="repo",
        resource=resource,
        scope={"permissions": permissions or {"contents": "write"}},
        justification="push deploy fix for the personal site",
        requested_duration=duration,
    )


async def test_github_validator_ceilings(db, registry, agent):
    a, _ = agent
    provisioner = registry.get(Platform.GITHUB)
    async with db.session() as session:
        # repo outside allowlist
        with pytest.raises(SpecValidationError, match="allowlist"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="repo", resource="evil/repo",
                            scope={"permissions": {"contents": "read"}}),
            )
        # denylisted repo is blocked even though jrt/* is allowlisted
        with pytest.raises(SpecValidationError, match="never brokered"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="repo", resource="jrt/NixOS-Dots",
                            scope={"permissions": {"contents": "read"}}),
            )
        # permission above ceiling (issues capped at read)
        with pytest.raises(SpecValidationError, match="exceeds policy ceiling"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="repo", resource="jrt/x",
                            scope={"permissions": {"issues": "write"}}),
            )
        # permission not grantable at all
        with pytest.raises(SpecValidationError, match="not grantable"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="repo", resource="jrt/x",
                            scope={"permissions": {"administration": "read"}}),
            )
        # missing permissions
        with pytest.raises(SpecValidationError, match="permissions is required"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="repo", resource="jrt/x", scope={}),
            )
        # normalization
        spec = await provisioner.validate_request(
            session,
            RequestSpec(agent=a, capability="repo", resource=" JRT/Cactus/ ",
                        scope={"permissions": {"contents": "WRITE"}}),
        )
        assert spec.resource == "jrt/cactus"
        assert spec.scope == {"permissions": {"contents": "write"}}


async def test_github_end_to_end_grant_and_credential(db, service, github_mock, agent):
    a, _ = agent
    async with db.session() as session:
        from agent_auth.models import Rule
        from agent_auth.core.states import RuleAction

        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern=a.name,
                platform=Platform.GITHUB,
                resource_pattern="jrt/*",
            )
        )

    req = await service.create_request(a.id, github_request())
    assert req.status == RequestStatus.GRANTED
    assert github_mock.called  # provisioning minted (and cached) a token

    async with db.session() as session:
        from sqlalchemy import select

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
        provisioner = service.registry.get(Platform.GITHUB)
        cred = await provisioner.get_credential(session, grant)
        assert cred.value == "ghs_testtoken123"
        assert cred.kind == "github_installation_token"
        # cached: no extra mint call
        calls_before = github_mock.call_count
        await provisioner.get_credential(session, grant)
        assert github_mock.call_count == calls_before

    # expire the grant → credential refusal
    async with db.session() as session:
        from sqlalchemy import update

        await session.execute(
            update(Grant)
            .where(Grant.id == grant.id)
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
    await service.expire_due_grants()
    async with db.session() as session:
        fresh = await session.get(Grant, grant.id)
        with pytest.raises(ProvisionerError, match="not active"):
            await provisioner.get_credential(session, fresh)


async def test_github_installation_resolution(db, registry, agent):
    """Unpinned provisioner resolves (and caches) the installation per repo;
    a repo the app isn't installed on fails with a clear error."""
    import respx

    a, _ = agent
    provisioner = registry.get(Platform.GITHUB)
    assert provisioner.installation_id == ""

    with respx.mock(assert_all_called=False) as mock:
        lookup = mock.get(f"{GITHUB_API_URL}/repos/jrt/cactus/installation").respond(
            200, json={"id": 4242}
        )
        assert await provisioner._installation_for("jrt/cactus") == "4242"
        assert await provisioner._installation_for("jrt/cactus") == "4242"
        assert lookup.call_count == 1  # cached after first resolution

        mock.get(f"{GITHUB_API_URL}/repos/jrt/ghost/installation").respond(404)
        with pytest.raises(ProvisionerError, match="not installed"):
            await provisioner._installation_for("jrt/ghost")

    # pinned mode short-circuits the lookup entirely
    provisioner.installation_id = "77"
    with respx.mock(assert_all_called=False):
        assert await provisioner._installation_for("jrt/anything") == "77"
    provisioner.installation_id = ""


async def test_lldap_grant_and_expiry_removes_group(db, service, lldap_mock):
    a, _ = await make_agent(db, "homelab-agent", lldap_username="svc-homelab-agent")
    req = await service.create_request(
        a.id,
        RequestCreate(
            platform=Platform.HOMELAB,
            capability="group",
            resource="svc-sonarr",
            justification="need sonarr api for the media pipeline task",
            requested_duration="30m",
        ),
    )
    assert req.status == RequestStatus.GRANTED  # auto-approve rule for svc-sonarr
    assert lldap_mock.mutations == [("add", {"user": "svc-homelab-agent", "group": 4})]

    async with db.session() as session:
        from sqlalchemy import select, update

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
        assert grant.provisioner_state["group"] == "svc-sonarr"
        await session.execute(
            update(Grant)
            .where(Grant.id == grant.id)
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )

    await service.expire_due_grants()
    assert lldap_mock.mutations[-1] == ("remove", {"user": "svc-homelab-agent", "group": 4})


async def test_lldap_validator(db, registry):
    provisioner = registry.get(Platform.HOMELAB)
    no_lldap, _ = await make_agent(db, "no-lldap-agent")
    async with db.session() as session:
        with pytest.raises(SpecValidationError, match="no LLDAP service account"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=no_lldap, capability="group", resource="svc-gitea"),
            )
    with_lldap, _ = await make_agent(db, "lldap-agent", lldap_username="svc-x")
    async with db.session() as session:
        with pytest.raises(SpecValidationError, match="not brokered"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=with_lldap, capability="group", resource="lldap_admin"),
            )


async def test_google_stub(db, service):
    a, _ = await make_agent(db, "cal-agent")
    req = await service.create_request(
        a.id,
        RequestCreate(
            platform=Platform.GOOGLE,
            capability="calendar.read",
            resource="primary",
            justification="check availability for scheduling a deploy window",
            requested_duration="1h",
        ),
    )
    assert req.status == RequestStatus.AWAITING_HUMAN  # default surface
    assert any("stub" in n for n in req.risk_notes)

    bad = await service.create_request(
        a.id,
        RequestCreate(
            platform=Platform.GOOGLE,
            capability="calendar.destroy",
            resource="primary",
            justification="x",
            requested_duration="1h",
        ),
    )
    assert bad.status == RequestStatus.DENIED
    assert "unknown google capability" in bad.decision_reason
