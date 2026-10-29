"""The mcp platform: grants for catalogued MCP servers, whose credential is
a short-lived token the broker signs and the server's proxy verifies from
the published keys; and the verify endpoint a reverse proxy can call."""

from __future__ import annotations

import time

import httpx
import jwt
import pytest

from agent_auth import authority
from agent_auth.config import Settings
from agent_auth.core.events import KeyedEvents
from agent_auth.core.service import HumanDecision, RequestService
from agent_auth.core.states import Platform, RequestStatus
from agent_auth.core.tokens import TokenError, TokenIssuer
from agent_auth.crypto import generate_fernet_key
from agent_auth.daemon_common import crypto as dc
from agent_auth.models import AccessRequest, Grant
from agent_auth.policy.engine import PolicyEngine
from agent_auth.policy.schema import McpPlatformConfig, PolicyFile
from agent_auth.provisioners.base import ProvisionerRegistry
from agent_auth.provisioners.mcp import McpProvisioner
from agent_auth.schemas import RequestCreate

from .conftest import make_agent

ISSUER = "https://agent-auth.example"
URL = "https://mcp-browser.example/mcp"
POLICY = {
    "defaults": {"action": "surface"},
    "platforms": {
        "mcp": {
            "issuer": ISSUER,
            "token_ttl": "10m",
            "servers": {
                "browser": {"url": URL, "description": "a shared browser", "tools": ["navigate", "snapshot", "click"]},
                "search": {"url": "https://search.example/", "audience": "search"},
            },
        }
    },
    "rules": [
        {"match": {"agent": "trusted-*", "platform": "mcp", "capability": "use", "resource": "search"}, "action": "approve"},
    ],
}


@pytest.fixture
def stack(db):
    from agent_auth.api.app import create_app
    from agent_auth.core.a2a import A2AThreadService

    settings = Settings(admin_token="t", encryption_key=generate_fernet_key(), _env_file=None)
    policy = PolicyFile.model_validate(POLICY)
    registry = ProvisionerRegistry()
    tokens = TokenIssuer(dc.generate_private_key(), ISSUER)
    registry.register(McpProvisioner(policy.platforms.mcp, tokens))
    service = RequestService(db, PolicyEngine(policy), registry, KeyedEvents())
    app = create_app(settings, db, service, registry, KeyedEvents(), A2AThreadService(db, settings, KeyedEvents()))
    app.state.tokens = tokens
    return {"service": service, "tokens": tokens, "app": app, "registry": registry}


def use(server="browser", tools=None, duration="1h"):
    return RequestCreate(platform=Platform.MCP, capability="use", resource=server,
                         scope={"tools": tools} if tools else {}, justification="look something up",
                         requested_duration=duration)


async def grant_for(db, request_id):
    from sqlalchemy import select

    async with db.session() as session:
        return (await session.execute(select(Grant).where(Grant.request_id == request_id))).scalar_one()


async def test_a_grant_yields_a_token_the_server_can_verify_from_the_published_keys(db, stack):
    agent, _ = await make_agent(db, "claude-web")
    req = await stack["service"].create_request(agent.id, use(tools=["snapshot", "navigate", "navigate"]))
    assert req.status == RequestStatus.AWAITING_HUMAN and req.scope == {"tools": ["navigate", "snapshot"]}
    await stack["service"].decide(req.id, HumanDecision(approve=True, decided_by="jrt"))
    grant = await grant_for(db, req.id)
    async with db.session() as session:
        cred = await stack["registry"].get(Platform.MCP).get_credential(session, await session.get(Grant, grant.id))
    assert cred.kind == "mcp_token" and URL in cred.note

    # What ToolHive does: pick the key by kid from the JWKS, check iss, aud, exp.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
        jwks = (await api.get("/.well-known/jwks.json")).json()
        discovery = (await api.get("/.well-known/openid-configuration")).json()
    assert discovery["issuer"] == ISSUER and discovery["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    header = jwt.get_unverified_header(cred.value)
    assert header["alg"] == "ES256"
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    claims = jwt.decode(cred.value, jwt.PyJWK(key).key, algorithms=["ES256"], audience=URL, issuer=ISSUER)
    assert claims["sub"] == "agent:claude-web" and claims["tools"] == ["navigate", "snapshot"]
    assert claims["server"] == "browser" and claims["grant"] == grant.id
    assert 0 < claims["exp"] - time.time() <= 600  # token_ttl, not the grant's hour
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(cred.value, jwt.PyJWK(key).key, algorithms=["ES256"], audience="search", issuer=ISSUER)


async def test_what_is_refused_and_what_a_rule_covers(db, stack):
    agent, _ = await make_agent(db, "claude-web")
    for body, why in (
        (use("nope"), "no MCP server"),
        (use(tools=["navigate", "rm_rf"]), "no tool rm_rf"),
        (RequestCreate(platform=Platform.MCP, capability="admin", resource="browser", scope={},
                       justification="x", requested_duration="1h"), 'capability is "use"'),
    ):
        req = await stack["service"].create_request(agent.id, body)
        assert req.status == RequestStatus.DENIED and why in req.decision_reason
    # No tools listed for a server: any names; no scope: every tool.
    req = await stack["service"].create_request(agent.id, use("search"))
    assert req.scope == {"tools": ["*"]} and req.status == RequestStatus.AWAITING_HUMAN
    # A rule that names mcp approves; nothing else does (needs_explicit_rule).
    trusted, _ = await make_agent(db, "trusted-hermes")
    assert (await stack["service"].create_request(trusted.id, use("search"))).status == RequestStatus.GRANTED
    assert (await stack["service"].create_request(trusted.id, use("browser"))).status == RequestStatus.AWAITING_HUMAN
    # A saved rule for some tools covers fewer, never more.
    covers = lambda rule, want: authority.rule_covers(Platform.MCP, {"tools": rule}, {"tools": want})  # noqa: E731
    assert covers(["a", "b"], ["a"]) and covers(["*"], ["a"]) and covers(["*"], ["*"])
    assert not covers(["a"], ["a", "b"]) and not covers(["a"], ["*"])


async def test_verify_says_no_once_the_grant_has_ended(db, stack):
    agent, _ = await make_agent(db, "claude-web")
    req = await stack["service"].create_request(agent.id, use("search"))
    await stack["service"].decide(req.id, HumanDecision(approve=True, decided_by="jrt"))
    grant = await grant_for(db, req.id)
    async with db.session() as session:
        token = (await stack["registry"].get(Platform.MCP).get_credential(session, await session.get(Grant, grant.id))).value
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=stack["app"]), base_url="http://t") as api:
        ok = await api.get("/v1/tokens/verify", params={"server": "search"}, headers={"Authorization": f"Bearer {token}"})
        assert ok.status_code == 200 and ok.headers["x-agent-auth-agent"] == "claude-web"
        # Another server, no token, a token from another issuer.
        other = TokenIssuer(dc.generate_private_key(), ISSUER).mint(
            subject="agent:claude-web", audience="search", ttl_secs=60, claims={"server": "search", "grant": grant.id})[0]
        for params, headers in (
            ({"server": "browser"}, {"Authorization": f"Bearer {token}"}),
            ({"server": "search"}, {}),
            ({"server": "search"}, {"Authorization": f"Bearer {other}"}),
        ):
            assert (await api.get("/v1/tokens/verify", params=params, headers=headers)).status_code == 401
        await stack["service"].revoke_grant(grant.id, "done", "jrt")
        gone = await api.get("/v1/tokens/verify", params={"server": "search"}, headers={"Authorization": f"Bearer {token}"})
        assert gone.status_code == 401
    # The signature is still good until it expires: a proxy that doesn't ask keeps accepting it.
    assert stack["tokens"].verify(token, "search")["grant"] == grant.id
    async with db.session() as session:
        from agent_auth.provisioners.base import ProvisionerError

        with pytest.raises(ProvisionerError):
            await stack["registry"].get(Platform.MCP).get_credential(session, await session.get(Grant, grant.id))


def test_the_token_key_follows_the_broker_key_and_the_policy_needs_an_issuer():
    broker = dc.generate_private_key()
    a, b = TokenIssuer(broker, ISSUER), TokenIssuer(broker, ISSUER)
    assert a.kid == b.kid and b.verify(a.mint(subject="s", audience="x", ttl_secs=60, claims={})[0], "x")["sub"] == "s"
    other = TokenIssuer(dc.generate_private_key(), ISSUER)
    assert other.kid != a.kid
    with pytest.raises(TokenError):
        other.verify(a.mint(subject="s", audience="x", ttl_secs=60, claims={})[0], "x")
    with pytest.raises(ValueError, match="issuer"):
        McpPlatformConfig.model_validate({"servers": {"x": {"url": "https://x.example"}}})


async def test_the_bridge_adds_a_fresh_token_and_relays_json_and_event_streams(capsys):
    """agent-auth-mcp-bridge: stdio in, the server's HTTP endpoint out, with
    the agent's own token, refreshed when the server says it ran out."""
    import json
    from datetime import datetime, timedelta, timezone

    from agent_auth.mcp_bridge import Bridge, NoGrant

    issued, seen = [], []

    def broker(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer aa_key"
        if request.url.path == "/v1/catalog":
            return httpx.Response(200, json={"platforms": [{"platform": "mcp", "servers": [{"name": "browser", "url": URL}]}]})
        if request.url.path == "/v1/grants":
            return httpx.Response(200, json=[
                {"id": "g1", "platform": "mcp", "resource": "browser", "scope": {"tools": ["navigate"]}, "expires_at": "2099-01-01T00:00:00Z"},
                {"id": "g2", "platform": "mcp", "resource": "browser", "scope": {"tools": ["*"]}, "expires_at": "2098-01-01T00:00:00Z"},
                {"id": "g3", "platform": "github", "resource": "browser", "scope": {}, "expires_at": "2099-01-01T00:00:00Z"},
            ] if "none" not in request.headers.get("x-test", "") else [])
        assert request.url.path == "/v1/grants/g2/credential"  # the widest one
        issued.append(f"token-{len(issued) + 1}")
        return httpx.Response(200, json={"kind": "mcp_token", "value": issued[-1],
                                         "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()})

    def upstream(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        seen.append((request.headers["authorization"], request.headers.get("mcp-session-id"), message.get("method")))
        if request.headers["authorization"] == "Bearer token-1" and message.get("method") == "tools/call":
            return httpx.Response(401)
        if message.get("method") == "initialize":
            return httpx.Response(200, headers={"mcp-session-id": "s-1"},
                                  json={"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-06-18"}})
        if message.get("method") == "tools/call":
            body = 'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n' \
                   f'data: {{"jsonrpc":"2.0","id":{message["id"]},"result":{{"ok":true}}}}\n\n'
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)
        if message.get("method") == "tools/list":
            return httpx.Response(500, text="boom")
        return httpx.Response(202)

    def make(**headers):
        return Bridge(
            "browser", "http://broker", "aa_key",
            broker=httpx.AsyncClient(base_url="http://broker", transport=httpx.MockTransport(broker), headers=headers),
            upstream=httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        )

    bridge = make()
    for message in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "navigate"}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    ):
        await bridge.forward(message)
    out = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert out[0]["result"]["protocolVersion"] == "2025-06-18"
    assert out[1]["method"] == "notifications/progress" and out[2] == {"jsonrpc": "2.0", "id": 2, "result": {"ok": True}}
    assert out[3]["id"] == 3 and "answered 500" in out[3]["error"]["message"]  # a request always gets an answer
    # The 401 was retried once with a new token; the session id is kept.
    assert [(a, s) for a, s, m in seen if m == "tools/call"] == [("Bearer token-1", "s-1"), ("Bearer token-2", "s-1")]
    assert issued == ["token-1", "token-2"]

    with pytest.raises(NoGrant, match="request_access"):
        await make(**{"x-test": "none"}).token()
