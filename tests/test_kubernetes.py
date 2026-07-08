from __future__ import annotations

from datetime import timedelta

import pytest

from agent_auth.core.states import GrantStatus, Platform, RequestStatus, RuleAction
from agent_auth.models import Grant, Rule, utcnow
from agent_auth.provisioners.base import ProvisionerError, RequestSpec, SpecValidationError
from agent_auth.provisioners.kubernetes import _sa_name
from agent_auth.schemas import RequestCreate

from .conftest import make_agent


def k8s_request(namespace="apps-cactus", role="edit", duration="2h"):
    return RequestCreate(
        platform=Platform.KUBERNETES,
        capability=role,  # capability IS the role
        resource=namespace,
        justification="deploy the cactus app: apply manifests and restart the deployment",
        requested_duration=duration,
    )


def test_sa_name_is_dns1123():
    name = _sa_name("Homelab.Agent_2", "123e4567-e89b-12d3-a456-426614174000")
    assert name == "aa-homelab-agent-2-123e4567"
    long = _sa_name("a" * 80, "123e4567-e89b-12d3-a456-426614174000")
    assert len(long) <= 63 and not long.endswith("-")


async def test_validator_ceilings(db, registry, agent):
    a, _ = agent
    provisioner = registry.get(Platform.KUBERNETES)
    async with db.session() as session:
        with pytest.raises(SpecValidationError, match="not brokered"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="view", resource="unlisted-ns"),
            )
        with pytest.raises(SpecValidationError, match="not grantable"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="cluster-admin", resource="apps-x"),
            )
        with pytest.raises(SpecValidationError, match="invalid namespace"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="view", resource="Bad_NS!"),
            )
        spec = await provisioner.validate_request(
            session,
            RequestSpec(agent=a, capability="edit", resource=" APPS-cactus "),
        )
        assert spec.resource == "apps-cactus"
        assert any("binds role 'edit'" in n for n in spec.notes)
        assert any("broad" in n for n in spec.notes)  # edit-role warning


async def test_grant_credential_revoke_cycle(db, service, k8s_mock):
    a, _ = await make_agent(db, "deploy-agent")
    async with db.session() as session:
        # An edit rule must pin the exact role: a wildcard/null-authority rule
        # would (correctly) no longer auto-approve a sensitive role like edit.
        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern="deploy-agent",
                platform=Platform.KUBERNETES,
                resource_pattern="apps-*",
                authority={"role": "edit"},
            )
        )

    req = await service.create_request(a.id, k8s_request())
    assert req.status == RequestStatus.GRANTED
    assert ("create", "ServiceAccount") in k8s_mock.calls
    assert ("create", "RoleBinding") in k8s_mock.calls

    async with db.session() as session:
        from sqlalchemy import select

        grant = (
            await session.execute(select(Grant).where(Grant.request_id == req.id))
        ).scalar_one()
        assert grant.provisioner_state["role"] == "edit"
        sa = grant.provisioner_state["service_account"]
        assert sa.startswith("aa-deploy-agent-")

        provisioner = service.registry.get(Platform.KUBERNETES)
        cred = await provisioner.get_credential(session, grant)
        assert cred.kind == "kubernetes_token"
        assert cred.value == "eyJhbGciOi.k8s-sa-token"
        assert ("token", sa) in k8s_mock.calls

    # expiry deletes the RoleBinding and ServiceAccount
    async with db.session() as session:
        from sqlalchemy import update

        await session.execute(
            update(Grant)
            .where(Grant.id == grant.id)
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
    assert await service.expire_due_grants() == 1
    deletes = [c for c in k8s_mock.calls if c[0] == "delete"]
    assert deletes == [("delete", sa), ("delete", sa)]  # rolebinding + serviceaccount

    async with db.session() as session:
        fresh = await session.get(Grant, grant.id)
        assert fresh.status == GrantStatus.EXPIRED
        with pytest.raises(ProvisionerError, match="not active"):
            await provisioner.get_credential(session, fresh)


async def test_provision_idempotent_on_conflict(db, service, k8s_mock):
    """A 409 AlreadyExists from a prior partial provision is treated as success."""
    a, _ = await make_agent(db, "deploy-agent-2")
    async with db.session() as session:
        # Null-authority rule: auto-approves any non-sensitive role in apps-*.
        session.add(
            Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern="deploy-agent-2",
                platform=Platform.KUBERNETES,
                resource_pattern="apps-*",
            )
        )
    k8s_mock.sa_exists = True  # simulate leftover SA from a crashed provision
    req = await service.create_request(a.id, k8s_request(role="view"))
    assert req.status == RequestStatus.GRANTED
    assert ("conflict", "ServiceAccount") in k8s_mock.calls
    assert ("create", "RoleBinding") in k8s_mock.calls


async def test_wildcard_allowlist(db, agent):
    """allowlist ['*'] brokers any namespace; containment is the role + review."""
    from agent_auth.policy.schema import KubernetesPlatformConfig
    from agent_auth.provisioners.kubernetes import KubernetesProvisioner

    a, _ = agent
    provisioner = KubernetesProvisioner(
        api_url="https://k8s.test",
        config=KubernetesPlatformConfig(
            namespace_allowlist=["*"],
            role_allowlist=["view", "edit", "admin"],
        ),
        token="t",
    )
    async with db.session() as session:
        for ns in ("brand-new-app", "kube-system", "monitoring"):
            spec = await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="admin", resource=ns),
            )
            assert spec.resource == ns
        # role ceiling still applies
        with pytest.raises(SpecValidationError, match="not grantable"):
            await provisioner.validate_request(
                session,
                RequestSpec(agent=a, capability="cluster-admin", resource="anything"),
            )


async def test_role_matched_routing(db, service, k8s_mock):
    """The capability-is-role change lets policy split friction by blast radius:
    a read-only role auto-approves; edit on the same namespace surfaces."""
    a, _ = await make_agent(db, "ops-agent", lldap_username=None)

    # view → auto-approved by the conftest rule, provisions a grant
    view_req = await service.create_request(a.id, k8s_request("personal-site", role="view"))
    assert view_req.status == RequestStatus.GRANTED
    assert view_req.decision_source.value == "policy"

    # edit on the very same namespace → surfaced to a human
    edit_req = await service.create_request(a.id, k8s_request("personal-site", role="edit"))
    assert edit_req.status == RequestStatus.AWAITING_HUMAN
