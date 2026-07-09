from __future__ import annotations

import os

import httpx
import pytest
import respx

from agent_auth.api.app import create_app
from agent_auth.config import Settings
from agent_auth.core.a2a import A2AThreadService
from agent_auth.core.events import KeyedEvents
from agent_auth.core.service import RequestService
from agent_auth.crypto import SecretBox, generate_api_key, generate_fernet_key
from agent_auth.db import Database
from agent_auth.models import Agent, Base
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.llm import LLMEvaluator
from agent_auth.policy.schema import PolicyFile
from agent_auth.provisioners.a2a import A2AProvisioner
from agent_auth.provisioners.base import ProvisionerRegistry
from agent_auth.provisioners.github import GithubProvisioner
from agent_auth.provisioners.google_stub import GoogleStubProvisioner
from agent_auth.provisioners.kubernetes import KubernetesProvisioner
from agent_auth.provisioners.lldap import LldapProvisioner

GITHUB_API = "https://github.test"
LLDAP_URL = "http://lldap.test"
K8S_API = "https://k8s.test"
OPENROUTER_URL = "https://openrouter.test/api/v1"

TEST_POLICY = {
    "defaults": {"action": "surface", "max_duration": "24h"},
    "llm": {"model": "test/judge", "retry_budget": 2, "timeout_secs": 5},
    "platforms": {
        "github": {
            "repo_allowlist": ["jrt/*"],
            "repo_denylist": ["jrt/nixos-dots"],
            "permission_ceiling": {"contents": "write", "secrets": "write", "issues": "read"},
        },
        "homelab": {"allowed_groups": ["svc-gitea", "svc-sonarr", "svc-k8s-gitops"]},
        "kubernetes": {
            "namespace_allowlist": ["apps-*", "personal-site"],
            "role_allowlist": ["view", "logs-reader", "edit"],
            "cluster_role_allowlist": ["view", "edit"],
            "cluster_grant_namespace": "agent-auth",
            "role_descriptions": {"view": "read-only in the namespace"},
        },
    },
    "rules": [
        {
            "match": {"agent": "denied-*"},
            "action": "deny",
            "reason": "agent is on the naughty list",
        },
        {
            "match": {"platform": "homelab", "resource": "svc-sonarr"},
            "action": "approve",
            "constraints": {"max_duration": "1h"},
        },
        {
            "match": {"platform": "github"},
            "action": "llm",
            "constraints": {"max_duration": "8h"},
        },
        {
            "match": {"platform": "a2a", "agent": "auto-*"},
            "action": "approve",
            "constraints": {"max_duration": "2h"},
        },
        # CLI agents (one identity per folder): frictionless a2a opens.
        {
            "match": {"platform": "a2a", "agent": "claude-*"},
            "action": "approve",
            "constraints": {"max_duration": "12h"},
        },
        # Delegated pair: hermes-* may join svc-gitea when a claude-* asked it
        # to (via an open a2a thread). Rules without `delegator` never
        # auto-approve delegated requests.
        {
            "match": {
                "platform": "homelab",
                "resource": "svc-gitea",
                "agent": "hermes-*",
                "delegator": "claude-*",
            },
            "action": "approve",
            "constraints": {"max_duration": "1h"},
        },
        # k8s: role-matched routing — read-only auto-approves, edit surfaces
        {
            "match": {"platform": "kubernetes", "capability": "view"},
            "action": "approve",
            "constraints": {"max_duration": "8h"},
        },
        {
            "match": {"platform": "kubernetes", "capability": "edit"},
            "action": "surface",
        },
    ],
}


@pytest.fixture
async def db(tmp_path):
    url = os.environ.get("TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    database = Database(url)
    async with database.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield database
    await database.dispose()


@pytest.fixture
def policy() -> PolicyFile:
    return PolicyFile.model_validate(TEST_POLICY)


@pytest.fixture
def secret_box() -> SecretBox:
    return SecretBox(generate_fernet_key())


@pytest.fixture
def registry(policy, secret_box, tmp_path) -> ProvisionerRegistry:
    # Throwaway RSA key so the GitHub provisioner can sign app JWTs in tests.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_path = tmp_path / "app.pem"
    pem_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    registry = ProvisionerRegistry()
    registry.register(A2AProvisioner())
    registry.register(GoogleStubProvisioner())
    registry.register(
        GithubProvisioner(
            app_id="1234",
            private_key_file=str(pem_path),
            api_url=GITHUB_API,
            config=policy.platforms.github,
            secret_box=secret_box,
            # unset → per-repo installation resolution (the default in prod)
        )
    )
    registry.register(
        LldapProvisioner(
            url=LLDAP_URL,
            admin_user="admin",
            admin_password="pw",
            config=policy.platforms.homelab,
        )
    )
    registry.register(
        KubernetesProvisioner(
            api_url=K8S_API,
            config=policy.platforms.kubernetes,
            token="k8s-test-token",
        )
    )
    return registry


@pytest.fixture
def events() -> KeyedEvents:
    return KeyedEvents()


@pytest.fixture
def llm_evaluator() -> LLMEvaluator:
    return LLMEvaluator("test-key", OPENROUTER_URL, timeout_secs=5)


@pytest.fixture
def service(db, policy, registry, events, llm_evaluator) -> RequestService:
    return RequestService(
        db, PolicyEngine(policy), registry, events, llm=llm_evaluator, notifier=None
    )


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        database_url="unused",
        admin_token="admin-secret",
        a2a_relay_enabled=True,
        _env_file=None,
    )


@pytest.fixture
def a2a_service(db, settings) -> A2AThreadService:
    return A2AThreadService(db, settings, KeyedEvents())


@pytest.fixture
def app(settings, db, service, registry, events, a2a_service):
    return create_app(settings, db, service, registry, events, a2a_service)


@pytest.fixture
async def api(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def make_agent(db, name: str, **kwargs) -> tuple[Agent, str]:
    """Create an agent directly in the DB; returns (agent, api_key)."""
    full_key, key_id, key_hash = generate_api_key()
    agent = Agent(name=name, key_id=key_id, api_key_hash=key_hash, **kwargs)
    async with db.session() as session:
        session.add(agent)
        await session.flush()
    return agent, full_key


@pytest.fixture
async def agent(db):
    return await make_agent(db, "test-agent", description="a test agent")


@pytest.fixture
def github_mock():
    """Mocks GitHub installation lookup + token mint; returns the mint route."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__regex=rf"{GITHUB_API}/repos/[^/]+/[^/]+/installation").respond(
            200, json={"id": 99}
        )
        mint = mock.post(f"{GITHUB_API}/app/installations/99/access_tokens").respond(
            201,
            json={
                "token": "ghs_testtoken123",
                "expires_at": "2099-01-01T00:00:00Z",
            },
        )
        mock.delete(f"{GITHUB_API}/installation/token").respond(204)
        yield mint


@pytest.fixture
def lldap_mock():
    """Mocks LLDAP login + GraphQL; records mutations in .calls."""

    class Recorder:
        def __init__(self):
            self.mutations: list[tuple[str, dict]] = []

    recorder = Recorder()

    def graphql_handler(request):
        import json as _json

        payload = _json.loads(request.content)
        query = payload.get("query", "")
        if "groups {" in query or "groups{" in query.replace(" ", ""):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "groups": [
                            {"id": 3, "displayName": "svc-gitea"},
                            {"id": 4, "displayName": "svc-sonarr"},
                            {"id": 5, "displayName": "svc-k8s-gitops"},
                        ]
                    }
                },
            )
        name = "add" if "addUserToGroup" in query else "remove"
        recorder.mutations.append((name, payload.get("variables", {})))
        return httpx.Response(200, json={"data": {f"{name}UserToGroup": {"ok": True}}})

    with respx.mock(assert_all_called=False) as mock:
        mock.post(f"{LLDAP_URL}/auth/simple/login").respond(200, json={"token": "jwt-test"})
        mock.post(f"{LLDAP_URL}/api/graphql").mock(side_effect=graphql_handler)
        yield recorder


@pytest.fixture
def k8s_mock():
    """Mocks the k8s API: SA/RoleBinding create+delete and TokenRequest.
    Records calls as (verb, kind_or_path) tuples."""
    import json as _json

    class Recorder:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []
            # None | "same" | "foreign": make the next ServiceAccount create
            # 409; the follow-up GET returns either the attempted body (a true
            # retry of this grant) or a foreign object (name squatting).
            self.sa_conflict: str | None = None
            self.last_sa_body: dict | None = None

    recorder = Recorder()

    def handler(request):
        path = request.url.path
        if request.method == "POST" and path.endswith("/token"):
            recorder.calls.append(("token", path.rsplit("/", 2)[-2]))
            body = _json.loads(request.content)
            assert body["spec"]["expirationSeconds"] >= 600
            return httpx.Response(
                201,
                json={
                    "status": {
                        "token": "eyJhbGciOi.k8s-sa-token",
                        "expirationTimestamp": "2099-01-01T00:00:00Z",
                    }
                },
            )
        if request.method == "POST":
            body = _json.loads(request.content)
            kind = body["kind"]
            if kind == "ServiceAccount" and recorder.sa_conflict:
                recorder.calls.append(("conflict", kind))
                recorder.last_sa_body = body
                return httpx.Response(409, json={"reason": "AlreadyExists"})
            recorder.calls.append(("create", kind))
            return httpx.Response(201, json=body)
        if request.method == "GET" and "/serviceaccounts/" in path:
            recorder.calls.append(("get", path.split("/")[-1]))
            if recorder.sa_conflict == "same" and recorder.last_sa_body:
                return httpx.Response(200, json=recorder.last_sa_body)
            if recorder.sa_conflict == "foreign" and recorder.last_sa_body:
                foreign = _json.loads(_json.dumps(recorder.last_sa_body))
                foreign["metadata"]["annotations"]["agent-auth/grant-id"] = "someone-else"
                return httpx.Response(200, json=foreign)
            return httpx.Response(404, json={})
        if request.method == "DELETE":
            recorder.calls.append(("delete", path.split("/")[-1]))
            return httpx.Response(200, json={})
        return httpx.Response(500)

    with respx.mock(assert_all_called=False) as mock:
        mock.route(host="k8s.test").mock(side_effect=handler)
        yield recorder


def openrouter_verdicts(*verdicts: dict):
    """respx context that returns scripted LLM verdicts in sequence."""
    import json as _json

    responses = [
        httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": _json.dumps(v)}}],
            },
        )
        for v in verdicts
    ]
    mock = respx.mock(assert_all_called=False)
    mock.post(f"{OPENROUTER_URL}/chat/completions").mock(side_effect=responses)
    return mock
