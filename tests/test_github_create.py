"""github capability "create": the broker creates org repos itself."""

from __future__ import annotations

import json

import pytest
import respx
from sqlalchemy import select

from agent_auth import authority
from agent_auth.core.states import Platform, RequestStatus, RuleAction
from agent_auth.models import Grant, Rule
from agent_auth.provisioners.base import RequestSpec, SpecValidationError
from agent_auth.schemas import RequestCreate

from .conftest import GITHUB_API

CREATE_PRIVATE = {"action": "create", "visibility": "private"}


def create_request(resource="jrt/newproj", visibility="private"):
    return RequestCreate(
        platform=Platform.GITHUB,
        capability="create",
        resource=resource,
        scope={"visibility": visibility},
        justification="bootstrap the larder project for the orchestrator",
        requested_duration="10m",
    )


async def _approve_rule(db, agent, auth=CREATE_PRIVATE):
    async with db.session() as session:
        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern=agent.name,
                platform=Platform.GITHUB,
                resource_pattern="jrt/*",
                authority=auth,
            )
        )


@pytest.fixture
def gh():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{GITHUB_API}/orgs/jrt/installation").respond(200, json={"id": 99})
        mint = mock.post(f"{GITHUB_API}/app/installations/99/access_tokens").respond(
            201, json={"token": "ghs_admin", "expires_at": "2099-01-01T00:00:00Z"}
        )
        revoke = mock.delete(f"{GITHUB_API}/installation/token").respond(204)
        covers = mock.get(url__regex=rf"{GITHUB_API}/repos/[^/]+/[^/]+/installation").respond(
            200, json={"id": 99}
        )
        create = mock.post(f"{GITHUB_API}/orgs/jrt/repos").respond(
            201,
            json={
                "id": 4242,
                "full_name": "jrt/newproj",
                "html_url": "https://github.com/jrt/newproj",
                "visibility": "private",
            },
        )
        yield {"mock": mock, "mint": mint, "revoke": revoke, "create": create, "covers": covers}


def test_create_is_its_own_authority():
    auth = authority.fold(Platform.GITHUB, "create", {"visibility": "private"})
    assert auth == CREATE_PRIVATE
    assert authority.split(Platform.GITHUB, auth) == ("create", {"visibility": "private"})
    assert authority.label(Platform.GITHUB, auth) == "create:private"
    # Never equal to any repo-access authority, so pinned rules can't cross over.
    assert auth != authority.fold(Platform.GITHUB, "repo", {"permissions": {}})


def test_public_create_is_sensitive(policy):
    platforms = policy.platforms
    assert authority.is_sensitive(
        Platform.GITHUB, {"action": "create", "visibility": "public"}, platforms
    )
    assert not authority.is_sensitive(Platform.GITHUB, CREATE_PRIVATE, platforms)


async def test_create_validator(db, registry, agent):
    a, _ = agent
    gh = registry.get(Platform.GITHUB)

    async def check(resource, scope=None):
        async with db.session() as session:
            return await gh.validate_request(
                session,
                RequestSpec(agent=a, capability="create", resource=resource, scope=scope or {}),
            )

    spec = await check(" JRT/NewProj/ ")
    assert spec.resource == "jrt/newproj" and spec.scope == {"visibility": "private"}
    assert any("creates a new private repo" in n for n in spec.notes)
    spec = await check("jrt/site", {"visibility": "PUBLIC"})
    assert spec.scope == {"visibility": "public"}
    assert any("PUBLIC" in n for n in spec.notes)

    with pytest.raises(SpecValidationError, match="create_owners"):
        await check("evil/thing")
    with pytest.raises(SpecValidationError, match="never brokered"):
        await check("jrt/nixos-dots")
    for bad in ("jrt/..", "jrt/x.git", "jrt/has space", "jrt/" + "a" * 101):
        with pytest.raises(SpecValidationError, match="invalid repository name"):
            await check(bad)
    with pytest.raises(SpecValidationError, match="visibility"):
        await check("jrt/x", {"visibility": "internal"})
    with pytest.raises(SpecValidationError, match="unknown scope keys"):
        await check("jrt/x", {"visibility": "private", "permissions": {"contents": "write"}})


async def test_private_create_end_to_end(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED, req.decision_reason

    # The admin token: all-repos (no `repositories`), administration only…
    body = json.loads(gh["mint"].calls.last.request.content)
    assert body == {"permissions": {"administration": "write", "metadata": "read"}}
    # …used for exactly the create call, then revoked.
    sent = json.loads(gh["create"].calls.last.request.content)
    assert sent == {"name": "newproj", "visibility": "private", "private": True}
    assert gh["create"].calls.last.request.headers["authorization"] == "token ghs_admin"
    assert gh["revoke"].called

    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        assert grant.provisioner_state["created"] is True
        cred = await service.registry.get(Platform.GITHUB).get_credential(session, grant)
    assert cred.kind == "github_repo"
    assert cred.value == "https://github.com/jrt/newproj"
    assert cred.note.startswith("created: jrt/newproj (private)")
    # Never a token: the admin token stays inside the broker.
    assert "ghs_admin" not in (cred.value or "") + (cred.note or "")


async def test_existing_repo_is_adopted_not_failed(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    gh["create"].respond(422, json={"message": "Repository creation failed.",
                                     "errors": [{"message": "name already exists on this account"}]})
    gh["mock"].get(f"{GITHUB_API}/repos/jrt/newproj").respond(
        200,
        json={"id": 7, "html_url": "https://github.com/jrt/newproj", "visibility": "private"},
    )
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        assert grant.provisioner_state["created"] is False
        cred = await service.registry.get(Platform.GITHUB).get_credential(session, grant)
    assert cred.note.startswith("already existed")
    assert gh["revoke"].called


async def test_failed_create_still_revokes_admin_token(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    gh["create"].respond(403, json={"message": "Resource not accessible by integration"})
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.PROVISION_FAILED
    assert gh["revoke"].called


async def test_uncovered_repo_is_reported(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    gh["covers"].respond(404)
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        cred = await service.registry.get(Platform.GITHUB).get_credential(session, grant)
    assert "does not cover it" in cred.note


async def test_public_create_reaches_a_human_despite_a_wildcard_rule(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a, auth=None)  # any github authority on jrt/*
    req = await service.create_request(a.id, create_request(visibility="public"))
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert not gh["create"].called


async def test_repo_rule_does_not_approve_create(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a, auth={"permissions": {"contents": "write"}})
    req = await service.create_request(a.id, create_request())
    assert req.status != RequestStatus.GRANTED
    assert not gh["create"].called


async def test_catalog_lists_create_owners(api, agent):
    _, key = agent
    resp = await api.get("/v1/catalog", headers={"Authorization": f"Bearer {key}"})
    gh = next(p for p in resp.json()["platforms"] if p["platform"] == "github")
    assert gh["create_owners"] == ["jrt"]
    assert gh["create_disposition"] in ("human review", "llm review", "auto-approve", "denied")
