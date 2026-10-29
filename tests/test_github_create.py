"""github capability "create": the broker creates org repos itself."""

from __future__ import annotations

import asyncio
import json
import logging

import httpx
import pytest
import respx
from sqlalchemy import select

from agent_auth import authority
from agent_auth.core.service import RequestService
from agent_auth.core.states import Platform, RequestStatus, RuleAction
from agent_auth.models import Grant, Rule, utcnow
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyRule
from agent_auth.provisioners.base import RequestSpec, SpecValidationError
from agent_auth.schemas import RequestCreate

from .conftest import GITHUB_API, make_agent

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


async def test_own_earlier_create_is_adopted_on_retry(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    first = await service.create_request(a.id, create_request())
    assert first.status == RequestStatus.GRANTED
    # Retry (e.g. the orchestrator re-runs project setup): the name is taken —
    # by the repo the broker itself created above (same GitHub id).
    gh["create"].respond(422, json={"message": "Repository creation failed.",
                                     "errors": [{"message": "name already exists on this account"}]})
    gh["mock"].get(f"{GITHUB_API}/repos/jrt/newproj").respond(
        200,
        json={"id": 4242, "html_url": "https://github.com/jrt/newproj", "visibility": "private"},
    )
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
        assert grant.provisioner_state["created"] is False
        cred = await service.registry.get(Platform.GITHUB).get_credential(session, grant)
    assert cred.note.startswith("already existed")
    assert gh["revoke"].call_count == 2


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
    # The test policy's github catch-all is "llm", but a create needs a rule
    # naming it, so the catalog must not advertise llm review.
    assert gh["create_disposition"] == "human review"


# ------------------------------------------------- only rules naming create

def _service_with_rules(db, policy, registry, events, rules):
    custom = policy.model_copy(update={"rules": [PolicyRule.model_validate(r) for r in rules]})
    return RequestService(db, PolicyEngine(custom), registry, events, llm=None, notifier=None)


async def test_repo_wildcard_yaml_rule_does_not_approve_create(db, policy, registry, events, gh, agent):
    a, _ = agent
    svc = _service_with_rules(
        db, policy, registry, events,
        [{"match": {"platform": "github", "resource": "jrt/*"}, "action": "approve"}],
    )
    req = await svc.create_request(a.id, create_request())
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert any("no rule names 'create'" in n for n in req.risk_notes)
    assert not gh["create"].called
    # The same rule still approves repo access, which is what it was written for.
    repo = await svc.create_request(
        a.id,
        RequestCreate(
            platform=Platform.GITHUB,
            capability="repo",
            resource="jrt/cactus",
            scope={"permissions": {"contents": "write"}},
            justification="push the fix",
            requested_duration="1h",
        ),
    )
    assert repo.status == RequestStatus.GRANTED, repo.decision_reason


async def test_llm_catch_all_does_not_route_create(db, service, gh, agent):
    a, _ = agent
    # TEST_POLICY routes {platform: github} to the LLM; a create must not go there.
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert not gh["create"].called


async def test_explicit_yaml_create_rule_approves(db, policy, registry, events, gh, agent):
    a, _ = agent
    svc = _service_with_rules(
        db, policy, registry, events,
        [{"match": {"platform": "github", "capability": "create", "resource": "jrt/*"},
          "action": "approve"}],
    )
    req = await svc.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    # Still sensitive when public: a YAML rule never clears that.
    pub = await svc.create_request(a.id, create_request("jrt/site", visibility="public"))
    assert pub.status == RequestStatus.AWAITING_HUMAN


async def test_globbed_capability_is_not_explicit(db, policy, registry, events, gh, agent):
    a, _ = agent
    svc = _service_with_rules(
        db, policy, registry, events,
        [{"match": {"platform": "github", "capability": "creat*"}, "action": "approve"}],
    )
    req = await svc.create_request(a.id, create_request())
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert not gh["create"].called


async def test_null_authority_db_rule_does_not_approve_private_create(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a, auth=None)  # e.g. Discord "approve:platform"
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.AWAITING_HUMAN
    assert not gh["create"].called


async def test_default_approve_does_not_approve_create(db, policy, registry, events, gh, agent):
    a, _ = agent
    custom = policy.model_copy(
        update={"rules": [], "defaults": policy.defaults.model_copy(update={"action": "approve"})}
    )
    svc = RequestService(db, PolicyEngine(custom), registry, events, llm=None, notifier=None)
    req = await svc.create_request(a.id, create_request())
    assert req.status == RequestStatus.AWAITING_HUMAN


# ------------------------------------------------- adopting existing repos

def _name_taken(gh, existing=None):
    gh["create"].respond(
        422,
        json={"message": "Repository creation failed.",
              "errors": [{"message": "name already exists on this account"}]},
    )
    return gh["mock"].get(f"{GITHUB_API}/repos/jrt/newproj").respond(
        200,
        json=existing
        or {"id": 4242, "html_url": "https://github.com/jrt/newproj", "visibility": "private"},
    )


async def test_existing_repo_not_created_by_broker_is_refused(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    lookup = _name_taken(gh)
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.PROVISION_FAILED
    assert "not created by the broker" in req.decision_reason
    # Neither GitHub's text nor the existing repo's details reach the agent,
    # and the admin token is never used to look the stranger's repo up.
    assert "already exists on this account" not in req.decision_reason
    assert not lookup.called
    assert gh["revoke"].called


async def test_adoption_requires_the_same_repo(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    assert (await service.create_request(a.id, create_request())).status == RequestStatus.GRANTED
    # Deleted and re-made by someone else since: same name, different id.
    _name_taken(gh, {"id": 9999, "html_url": "https://github.com/jrt/newproj",
                     "visibility": "private"})
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.PROVISION_FAILED
    assert "not created by the broker" in req.decision_reason


async def test_adoption_requires_the_same_visibility(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    assert (await service.create_request(a.id, create_request())).status == RequestStatus.GRANTED
    _name_taken(gh, {"id": 4242, "html_url": "https://github.com/jrt/newproj",
                     "visibility": "public"})
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.PROVISION_FAILED
    assert "exists as public" in req.decision_reason


async def test_adoption_requires_the_same_agent(db, service, gh, agent):
    a, _ = agent
    b, _ = await make_agent(db, "other-agent")
    await _approve_rule(db, a)
    await _approve_rule(db, b)
    assert (await service.create_request(a.id, create_request())).status == RequestStatus.GRANTED
    _name_taken(gh)
    req = await service.create_request(b.id, create_request())
    assert req.status == RequestStatus.PROVISION_FAILED
    assert "not created by the broker" in req.decision_reason


# ------------------------------------------------------ validator hardening

async def test_control_and_non_ascii_resources_are_refused(db, registry, agent):
    a, _ = agent
    gh = registry.get(Platform.GITHUB)

    async def check(capability, resource, scope):
        async with db.session() as session:
            return await gh.validate_request(
                session, RequestSpec(agent=a, capability=capability, resource=resource, scope=scope)
            )

    repo_scope = {"permissions": {"contents": "read"}}
    for bad in ("jrt/nixos-dots\n/", "jrt/nixos-dots\n", "jrt/x\t", "jrt/x\x7f", "jrt/nеwproj"):
        with pytest.raises(SpecValidationError, match="control or non-ASCII"):
            await check("create", bad, {})
        with pytest.raises(SpecValidationError, match="control or non-ASCII"):
            await check("repo", bad, repo_scope)
    # Whitespace between the name and a trailing slash can't dodge the denylist.
    with pytest.raises(SpecValidationError, match="never brokered"):
        await check("repo", "jrt/nixos-dots /", repo_scope)
    for bad in ("jrt/a b", "jrt/..", "jrt/x%0a", "jrt/x?y"):
        with pytest.raises(SpecValidationError, match="invalid github repository"):
            await check("repo", bad, repo_scope)


async def test_special_repo_names_are_refused(db, registry, agent):
    a, _ = agent
    gh = registry.get(Platform.GITHUB)

    async def check(resource):
        async with db.session() as session:
            return await gh.validate_request(
                session, RequestSpec(agent=a, capability="create", resource=resource, scope={})
            )

    for bad in (".github", ".github-private", ".hidden", "jrt.github.io", "...", "-", "_", "-._"):
        with pytest.raises(SpecValidationError, match="invalid repository name"):
            await check(f"jrt/{bad}")
    for ok in ("a.b", "x-1", "_x", "github.io-notes"):
        assert (await check(f"jrt/{ok}")).resource == f"jrt/{ok}"


# ------------------------------------------------------ admin token hygiene

async def test_admin_token_revoke_failure_is_logged(db, service, gh, agent, caplog):
    a, _ = agent
    await _approve_rule(db, a)
    gh["revoke"].respond(401)
    with caplog.at_level(logging.WARNING, logger="agent_auth.provisioners.github"):
        req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED
    assert any("returned 401" in r.getMessage() for r in caplog.records)


async def test_admin_token_revoked_when_create_is_cancelled(db, registry, gh, agent):
    a, _ = agent
    in_flight = asyncio.Event()

    async def hang(request):
        in_flight.set()
        await asyncio.Event().wait()

    gh["create"].side_effect = hang
    grant = Grant(
        agent_id=a.id,
        platform=Platform.GITHUB,
        capability="create",
        scope={"visibility": "private"},
        resource="jrt/newproj",
        expires_at=utcnow(),
    )
    async with db.session() as session:
        task = asyncio.create_task(registry.get(Platform.GITHUB).provision(session, grant))
        await in_flight.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    # The shielded revoke outlives the cancellation.
    for _ in range(50):
        if gh["revoke"].called:
            break
        await asyncio.sleep(0.01)
    assert gh["revoke"].called


async def test_coverage_lookup_error_does_not_fail_a_create(db, service, gh, agent):
    a, _ = agent
    await _approve_rule(db, a)
    gh["covers"].side_effect = httpx.ConnectError("boom")
    req = await service.create_request(a.id, create_request())
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    async with db.session() as session:
        grant = (await session.execute(select(Grant).where(Grant.request_id == req.id))).scalar_one()
    assert grant.provisioner_state["created"] is True
    assert grant.provisioner_state["installation_covers"] is False
