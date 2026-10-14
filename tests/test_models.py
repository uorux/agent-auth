"""The models platform: per-agent keys at the LiteLLM gateway, and the VM
daemon pointing its conversations at the gateway."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import httpx
import pytest
import respx

from agent_auth import authority
from agent_auth.config import Settings
from agent_auth.core.events import KeyedEvents
from agent_auth.core.service import RequestService
from agent_auth.core.states import GrantStatus, Platform, RequestStatus
from agent_auth.crypto import SecretBox, generate_fernet_key
from agent_auth.models import Grant
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import PolicyFile
from agent_auth.provisioners.base import ProvisionerRegistry
from agent_auth.provisioners.models import ModelsProvisioner
from agent_auth.sandboxd import daemon as sbx
from agent_auth.sandboxd.runtimes import ClaudeRuntime, CodexRuntime
from agent_auth.schemas import RequestCreate

from .conftest import make_agent

GW = "https://litellm.test"
POLICY = {
    "defaults": {"action": "surface"},
    "platforms": {"models": {"url": GW, "models": ["claude-*"], "max_budget": 50}},
    "rules": [
        {"match": {"agent": {"placement": "sandbox"}, "platform": "models", "capability": "use"}, "action": "approve", "max_duration": "24h"},
        # A catch-all written for something else never hands out model keys.
        {"match": {"agent": "trusted-*"}, "action": "approve"},
    ],
}


@pytest.fixture
def stack(db):
    from agent_auth.api.app import create_app
    from agent_auth.core.a2a import A2AThreadService

    settings = Settings(admin_token="t", encryption_key=generate_fernet_key(), _env_file=None)
    policy = PolicyFile.model_validate(POLICY)
    registry = ProvisionerRegistry()
    registry.register(ModelsProvisioner(policy.platforms.models, "master", SecretBox(settings.encryption_key)))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents())
    app = create_app(settings, db, service, registry, KeyedEvents(), A2AThreadService(db, settings, KeyedEvents()))
    return {"service": service, "registry": registry, "app": app}


def use(resource="litellm", capability="use", scope=None):
    return RequestCreate(
        platform=Platform.MODELS, capability=capability, resource=resource, scope=scope or {},
        justification="model calls", requested_duration="24h",
    )


class Gateway:
    """LiteLLM's admin API, as much of it as the broker uses."""

    def __init__(self):
        self.users: dict[str, dict] = {}
        self.keys: dict[str, dict] = {}
        self.deleted: list[str] = []

    def mock(self):
        def auth(request):
            assert request.headers["authorization"] == "Bearer master"

        def user_info(request):
            auth(request)
            uid = request.url.params["user_id"]
            if uid not in self.users:
                return httpx.Response(400, json={"error": "user not found"})
            return httpx.Response(200, json={"user_id": uid, "user_info": self.users[uid]})

        def user_new(request):
            auth(request)
            body = json.loads(request.content)
            self.users[body["user_id"]] = {"user_id": body["user_id"], "spend": 0.0, "max_budget": None, "metadata": body["metadata"]}
            return httpx.Response(200, json={"user_id": body["user_id"]})

        def key_generate(request):
            auth(request)
            body = json.loads(request.content)
            key = f"sk-{len(self.keys) + 1}"
            self.keys[key] = body
            return httpx.Response(200, json={"key": key, "key_alias": body["key_alias"]})

        def key_delete(request):
            auth(request)
            self.deleted.extend(json.loads(request.content)["keys"])
            return httpx.Response(200, json={})

        def user_list(request):
            auth(request)
            return httpx.Response(200, json={"users": list(self.users.values()), "total_pages": 1})

        respx.get(f"{GW}/user/info").mock(side_effect=user_info)
        respx.post(f"{GW}/user/new").mock(side_effect=user_new)
        respx.post(f"{GW}/key/generate").mock(side_effect=key_generate)
        respx.post(f"{GW}/key/delete").mock(side_effect=key_delete)
        respx.get(f"{GW}/user/list").mock(side_effect=user_list)
        return self


async def grant_of(db, request_id) -> Grant:
    from sqlalchemy import select

    async with db.session() as session:
        return (await session.execute(select(Grant).where(Grant.request_id == request_id))).scalar_one()


@respx.mock
async def test_a_grant_is_a_key_of_the_agents_own_that_ends_with_it(db, stack):
    gw = Gateway().mock()
    agent, _ = await make_agent(
        db, "claude-llm-bench-galaxy-sandbox", runtime="claude", project="llm-bench", host="galaxy", placement="sandbox"
    )
    req = await stack["service"].create_request(agent.id, use())
    assert req.status == RequestStatus.GRANTED, req.decision_reason
    grant = await grant_of(db, req.id)

    # One LiteLLM user per agent; the key is under it, with the agent's fields.
    assert gw.users["claude-llm-bench-galaxy-sandbox"]["metadata"]["project"] == "llm-bench"
    (key, body), = gw.keys.items()
    assert body["user_id"] == "claude-llm-bench-galaxy-sandbox"
    assert body["key_alias"] == f"claude-llm-bench-galaxy-sandbox/{grant.id[:8]}"
    assert body["models"] == ["claude-*"] and body["max_budget"] == 50
    assert body["metadata"]["grant_id"] == grant.id and body["metadata"]["host"] == "galaxy"
    # The gateway ends the key itself at the grant's end.
    assert 24 * 3600 - 120 <= int(body["duration"].rstrip("s")) <= 24 * 3600
    # Stored encrypted, not as is.
    assert key not in json.dumps(grant.provisioner_state)

    provisioner = stack["registry"].get(Platform.MODELS)
    async with db.session() as session:
        cred = await provisioner.get_credential(session, await session.get(Grant, grant.id))
    assert cred.kind == "model_gateway_key" and cred.value == key and cred.url == GW

    # A second grant reuses the user.
    req2 = await stack["service"].create_request(agent.id, use())
    assert req2.status == RequestStatus.GRANTED and len(gw.keys) == 2 and len(gw.users) == 1

    await stack["service"].revoke_grant(grant.id, "done", "test")
    assert gw.deleted == [key]
    async with db.session() as session:
        assert (await session.get(Grant, grant.id)).status == GrantStatus.REVOKED


@respx.mock
async def test_what_is_refused_and_what_a_rule_covers(db, stack):
    Gateway().mock()
    vm, _ = await make_agent(db, "codex-x-galaxy-sandbox", placement="sandbox")
    for body, why in (
        (use("openai"), "unknown model gateway"),
        (use(capability="admin"), 'must be "use"'),
        (use(scope={"models": ["gpt-5"]}), "no scope"),
    ):
        req = await stack["service"].create_request(vm.id, body)
        assert req.status == RequestStatus.DENIED and why in req.decision_reason
    # A catch-all rule for an agent does not reach model keys.
    trusted, _ = await make_agent(db, "trusted-hermes")
    assert (await stack["service"].create_request(trusted.id, use())).status == RequestStatus.AWAITING_HUMAN
    assert authority.split(Platform.MODELS, authority.fold(Platform.MODELS, "use", {})) == ("use", {})


@respx.mock
async def test_the_catalog_names_the_gateway_and_usage_is_per_agent(db, stack):
    gw = Gateway().mock()
    agent, key = await make_agent(db, "claude-a-galaxy-sandbox", project="a", host="galaxy", placement="sandbox")
    await stack["service"].create_request(agent.id, use())
    gw.users["claude-a-galaxy-sandbox"]["spend"] = 3.5
    gw.users["jrt"] = {"user_id": "jrt", "spend": 99.0}  # not an agent: not shown
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
        catalog = (await api.get("/v1/catalog", headers={"Authorization": f"Bearer {key}"})).json()
        models = next(p for p in catalog["platforms"] if p["platform"] == "models")
        assert models["gateway"] == {"name": "litellm", "url": GW, "models": ["claude-*"]}
        usage = (await api.get("/admin/models/usage", headers={"Authorization": "Bearer t"})).json()
    assert usage["enabled"] and [(r["agent"], r["spend"], r["project"]) for r in usage["agents"]] == [
        ("claude-a-galaxy-sandbox", 3.5, "a")
    ]


# --- the VM daemon ----------------------------------------------------------------------


class FakeBroker:
    def __init__(self, catalog, grants=(), request_status="granted"):
        self.catalog, self.grants, self.request_status = catalog, list(grants), request_status
        self.calls: list[tuple[str, str]] = []

    async def call(self, api_key, method, path, **kwargs):
        self.calls.append((method, path))
        if path == "/v1/catalog":
            return self.catalog
        if path == "/v1/grants":
            return self.grants
        if path == "/v1/requests":
            assert kwargs["json"]["platform"] == "models" and kwargs["json"]["resource"] == "litellm"
            return {"id": "r1", "status": self.request_status, "grant_id": "g1" if self.request_status == "granted" else None}
        if path.endswith("/credential"):
            return {"value": "sk-agent", "url": GW, "expires_at": "2099-01-01T00:00:00Z"}
        raise AssertionError(path)


def daemon_with(broker):
    return SimpleNamespace(broker=broker, config=SimpleNamespace(name="galaxy"), _gateway_keys={})


CATALOG = {"platforms": [{"platform": "models", "gateway": {"name": "litellm", "url": GW}}]}
REC = SimpleNamespace(name="claude-a-galaxy-sandbox", api_key="aa_x")


async def test_the_daemon_asks_once_and_points_both_runtimes_at_the_gateway():
    broker = FakeBroker(CATALOG)
    d = daemon_with(broker)
    held = await sbx.Sandboxd._gateway(d, REC)
    assert held["url"] == GW and held["key"] == "sk-agent"
    assert ("POST", "/v1/requests") in broker.calls
    broker.calls.clear()
    assert (await sbx.Sandboxd._gateway(d, REC)) is held and broker.calls == []  # reused

    env = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-x", "HOME": "/h"}
    sbx._gateway_env(env, held)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env
    assert env["ANTHROPIC_BASE_URL"] == GW and env["ANTHROPIC_AUTH_TOKEN"] == "sk-agent"
    assert env["AGENT_AUTH_MODELS_KEY"] == "sk-agent"

    codex = CodexRuntime("codex")
    argv = sbx._with_gateway(codex.triage_argv(None), codex, held)
    assert argv[0] == "codex" and argv[1:3] == ["-c", 'model_provider="agentauth"']
    assert f'model_providers.agentauth.base_url="{GW}/v1"' in argv
    assert 'model_providers.agentauth.env_key="AGENT_AUTH_MODELS_KEY"' in argv
    assert 'model_providers.agentauth.wire_api="responses"' in argv
    assert argv[-1] == "-"
    claude = ClaudeRuntime("claude")
    assert sbx._with_gateway(claude.triage_argv(None), claude, held) == claude.triage_argv(None)
    assert sbx._with_gateway(codex.triage_argv(None), codex, None) == codex.triage_argv(None)


async def test_the_daemon_reuses_a_grant_and_falls_back_only_without_a_gateway():
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 20 * 3600))
    broker = FakeBroker(CATALOG, grants=[{"id": "g9", "platform": "models", "resource": "litellm", "expires_at": later}])
    assert (await sbx.Sandboxd._gateway(daemon_with(broker), REC))["key"] == "sk-agent"
    assert ("POST", "/v1/requests") not in broker.calls and ("GET", "/v1/grants/g9/credential") in broker.calls

    # No gateway at the broker, or no broker: the VM's logins.
    assert await sbx.Sandboxd._gateway(daemon_with(FakeBroker({"platforms": []})), REC) is None

    class Waiting(FakeBroker):
        async def call(self, api_key, method, path, **kwargs):
            if path.endswith("/wait"):
                return {"id": "r1", "status": "awaiting_human"}
            return await super().call(api_key, method, path, **kwargs)

    class Down(FakeBroker):
        async def call(self, *a, **k):
            raise OSError("broker unreachable")

    assert await sbx.Sandboxd._gateway(daemon_with(Down(CATALOG)), REC) is None

    # A gateway but no key (a human must decide, refused, contained, the
    # agent's key refused): no start, rather than the VM's logins.
    with pytest.raises(sbx.NoModelKey, match="awaiting_human"):
        await sbx.Sandboxd._gateway(daemon_with(Waiting(CATALOG, request_status="awaiting_human")), REC)
    with pytest.raises(sbx.NoModelKey, match="denied"):
        await sbx.Sandboxd._gateway(daemon_with(FakeBroker(CATALOG, request_status="denied")), REC)

    class Refused(FakeBroker):
        async def call(self, *a, **k):
            raise sbx.BrokerCallError(401, "invalid API key")

    with pytest.raises(sbx.NoModelKey):
        await sbx.Sandboxd._gateway(daemon_with(Refused(CATALOG)), REC)


@respx.mock
async def test_by_runtime_keeps_each_subscription_to_its_own_tool(db):
    from agent_auth.api.app import create_app  # noqa: F401  (the stack, as above, with by_runtime)

    gw = Gateway().mock()
    policy = PolicyFile.model_validate(
        {
            **POLICY,
            "platforms": {"models": {"url": GW, "by_runtime": {"claude": ["claude-*"], "codex": ["gpt-*"]}}},
        }
    )
    registry = ProvisionerRegistry()
    registry.register(ModelsProvisioner(policy.platforms.models, "master", SecretBox(generate_fernet_key())))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents())
    claude, _ = await make_agent(db, "claude-a-galaxy-sandbox", runtime="claude", placement="sandbox")
    codex, _ = await make_agent(db, "codex-a-galaxy-sandbox", runtime="codex", placement="sandbox")
    hermes, _ = await make_agent(db, "hermes-x-sandbox", runtime="hermes", placement="sandbox")
    assert (await service.create_request(claude.id, use())).status == RequestStatus.GRANTED
    assert (await service.create_request(codex.id, use())).status == RequestStatus.GRANTED
    refused = await service.create_request(hermes.id, use())
    assert refused.status == RequestStatus.DENIED and "no models for runtime 'hermes'" in refused.decision_reason
    assert [b["models"] for b in gw.keys.values()] == [["claude-*"], ["gpt-*"]]


@respx.mock
async def test_by_runtime_star_covers_the_runtimes_not_named(db):
    gw = Gateway().mock()
    policy = PolicyFile.model_validate(
        {
            **POLICY,
            "rules": [{"match": {"platform": "models", "capability": "use"}, "action": "approve"}],
            "platforms": {"models": {"url": GW, "by_runtime": {"claude": ["claude-*", "gpt-*"], "*": ["gpt-*"]}}},
        }
    )
    registry = ProvisionerRegistry()
    registry.register(ModelsProvisioner(policy.platforms.models, "master", SecretBox(generate_fernet_key())))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents())
    claude, _ = await make_agent(db, "claude-a", runtime="claude")
    hermes, _ = await make_agent(db, "hermes-a", runtime="hermes")
    soc, _ = await make_agent(db, "soc-a")  # no runtime on record: "*" too
    for agent in (claude, hermes, soc):
        assert (await service.create_request(agent.id, use())).status == RequestStatus.GRANTED
    assert [b["models"] for b in gw.keys.values()] == [["claude-*", "gpt-*"], ["gpt-*"], ["gpt-*"]]
