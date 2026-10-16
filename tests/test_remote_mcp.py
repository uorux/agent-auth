"""Web UIs: the OAuth server (core/oauth.py, api/oauth_routes.py) and /mcp
(api/remote_mcp.py)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from agent_auth.api.app import enable_remote_mcp
from agent_auth.core.webui import UiAuth
from agent_auth.crypto import generate_fernet_key
from agent_auth.mcp_names import TOOL_NAMES
from agent_auth.policy.schema import PolicyFile, RemoteMcpConfig, UiConfig

BASE = "https://agent-auth.example"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
ADMIN = {"Authorization": "Bearer admin-secret"}


class Signin(UiAuth):
    """The panel's sign-in, with the provider stood in for: whoever comes
    back is `self.user`, carrying what begin() sealed."""

    user = "jrt"

    async def begin(self, redirect_uri=None, carry=None):
        assert redirect_uri == f"{BASE}/oauth/callback"
        return "https://idp.example/authorize?x=1", self.seal("login", {"state": "s", "carry": carry or {}})

    async def identify(self, login_cookie, code, state):
        attempt = self.unseal("login", login_cookie, 600)
        assert attempt is not None and code == "idp-code"
        return self.user, attempt["carry"]


@pytest.fixture
def remote(app, service, settings):
    policy = service.engine.policy
    policy.ui = UiConfig(enabled=False, base_url="https://panel.example", issuer="https://idp.example", client_id="agent-auth-admin")
    policy.remote_mcp = RemoteMcpConfig(enabled=True, base_url=BASE)
    settings.remote_mcp_loopback_url = "http://loopback.test"
    enable_remote_mcp(app, policy, settings, Signin(policy.ui, generate_fernet_key()))
    return app


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def connect(api, name="Claude", label=None) -> tuple[str, dict, str]:
    """Register, authorize, sign in, allow, exchange: (client_id, tokens, verifier)."""
    reg = await api.post("/oauth/register", json={"client_name": name, "redirect_uris": [CALLBACK]})
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    verifier, challenge = pkce()
    start = await api.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK, "state": "xyz",
        "code_challenge": challenge, "code_challenge_method": "S256"})
    assert start.status_code == 303 and start.headers["location"].startswith("https://idp.example/")
    page = await api.get("/oauth/callback", params={"code": "idp-code", "state": "s"},
                         cookies={"aa_oauth_login": start.cookies["aa_oauth_login"]})
    assert page.status_code == 200, page.text
    assert "claude.ai" in page.text and "form-action 'self' https://claude.ai" in page.headers["content-security-policy"]
    blob = re.search(r'name="consent" value="([^"]+)"', page.text).group(1)
    form = {"consent": blob, "action": "allow"}
    if label:
        form["name"] = label
    elif 'id="name"' in page.text:
        form["name"] = re.search(r'id="name" name="name" value="([^"]+)"', page.text).group(1)
    done = await api.post("/oauth/consent", data=form, cookies={"aa_oauth_consent": page.cookies["aa_oauth_consent"]})
    assert done.status_code == 303, done.text
    back = urlparse(done.headers["location"])
    query = parse_qs(back.query)
    assert f"{back.scheme}://{back.netloc}{back.path}" == CALLBACK and query["state"] == ["xyz"] and query["iss"] == [BASE]
    tokens = await api.post("/oauth/token", data={"grant_type": "authorization_code", "code": query["code"][0],
                                                   "redirect_uri": CALLBACK, "client_id": client_id, "code_verifier": verifier})
    assert tokens.status_code == 200, tokens.text
    return client_id, {**tokens.json(), "code": query["code"][0]}, verifier


def test_the_tool_names_are_the_servers():
    from agent_auth import mcp_server

    tools = {t.name for t in mcp_server.mcp._tool_manager.list_tools()}
    assert tools == set(TOOL_NAMES)


def test_policy_needs_a_sign_in_and_known_tools():
    with pytest.raises(ValueError, match="base_url"):
        PolicyFile.model_validate({"remote_mcp": {"enabled": True}})
    with pytest.raises(ValueError, match="no such tools"):
        PolicyFile.model_validate({
            "ui": {"issuer": "https://idp", "client_id": "c"},
            "remote_mcp": {"enabled": True, "base_url": BASE, "tools": ["whoami", "rm_rf"]},
        })
    ok = PolicyFile.model_validate({"ui": {"issuer": "https://idp"}, "remote_mcp": {"enabled": True, "base_url": BASE}})
    assert "get_credential" not in ok.remote_mcp.tools and "host_run" not in ok.remote_mcp.tools


async def test_discovery_and_registration_rules(api, remote):
    meta = (await api.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert meta == {"resource": f"{BASE}/mcp", "authorization_servers": [BASE], "bearer_methods_supported": ["header"],
                    "resource_name": "agent-auth"}
    server = (await api.get("/.well-known/oauth-authorization-server")).json()
    assert server["registration_endpoint"] == f"{BASE}/oauth/register" and server["code_challenge_methods_supported"] == ["S256"]
    refused = await api.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["https://evil.example/cb"]})
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_redirect_uri"
    plain = await api.post("/oauth/register", json={"redirect_uris": ["http://claude.ai/cb"]})
    assert plain.status_code == 400
    confidential = await api.post("/oauth/register", json={"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "client_secret_post"})
    assert confidential.status_code == 201 and confidential.json()["client_secret"]


async def test_no_pkce_no_authorization(api, remote):
    client_id = (await api.post("/oauth/register", json={"redirect_uris": [CALLBACK]})).json()["client_id"]
    plain = await api.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK,
                                                      "code_challenge": "x" * 43, "code_challenge_method": "plain"})
    assert plain.status_code == 400  # shown here, not sent to the redirect
    other = await api.get("/oauth/authorize", params={"response_type": "code", "client_id": client_id,
                                                      "redirect_uri": "https://claude.ai/other", "code_challenge": "x" * 43,
                                                      "code_challenge_method": "S256"})
    assert other.status_code == 400


async def test_a_connector_is_an_agent_of_its_own_and_its_tokens_rotate(api, remote, db):
    client_id, tokens, _ = await connect(api)
    me = await api.get("/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200 and me.json()["name"] == "web-claude"
    from sqlalchemy import select

    from agent_auth.models import Agent

    async with db.session() as session:
        agent = (await session.execute(select(Agent).where(Agent.name == "web-claude"))).scalar_one()
        assert agent.runtime == "web" and agent.kind == "ephemeral"

    # A code works once; using it again revokes what it gave.
    again = await api.post("/oauth/token", data={"grant_type": "authorization_code", "code": tokens["code"],
                                                  "redirect_uri": CALLBACK, "client_id": client_id, "code_verifier": "x" * 43})
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
    assert (await api.get("/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})).status_code == 401

    # A fresh authorization; refresh rotates, and a reused refresh token ends it.
    _, tokens, _ = await connect(api, name="Claude")
    fresh = await api.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                                  "client_id": client_id})
    # (connect registered a second client; this is that one's token)
    assert fresh.status_code == 400
    cid2 = (await api.get("/admin/connectors", headers=ADMIN)).json()[0]["client_id"]
    fresh = await api.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": cid2})
    assert fresh.status_code == 200, fresh.text
    new = fresh.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    reused = await api.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": cid2})
    assert reused.status_code == 400
    assert (await api.get("/v1/me", headers={"Authorization": f"Bearer {new['access_token']}"})).status_code == 401


async def test_a_wrong_verifier_gets_nothing(api, remote):
    reg = (await api.post("/oauth/register", json={"redirect_uris": [CALLBACK]})).json()
    _, challenge = pkce()
    start = await api.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CALLBACK,
                                                      "state": "s1", "code_challenge": challenge, "code_challenge_method": "S256"})
    page = await api.get("/oauth/callback", params={"code": "idp-code", "state": "s"}, cookies={"aa_oauth_login": start.cookies["aa_oauth_login"]})
    blob = re.search(r'name="consent" value="([^"]+)"', page.text).group(1)
    # Without the consent cookie of this browser, the blob alone is not enough.
    stolen = await api.post("/oauth/consent", data={"consent": blob, "action": "allow", "name": "web-x"})
    assert stolen.status_code == 400
    done = await api.post("/oauth/consent", data={"consent": blob, "action": "allow", "name": "web-x"},
                          cookies={"aa_oauth_consent": page.cookies["aa_oauth_consent"]})
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    bad = await api.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK,
                                                "client_id": reg["client_id"], "code_verifier": pkce()[0]})
    assert bad.status_code == 400 and "PKCE" in bad.json()["error_description"]


async def test_a_connector_can_not_be_named_as_another_agent(api, remote, db):
    from .conftest import make_agent

    await make_agent(db, "web-hermes", runtime="hermes")
    reg = (await api.post("/oauth/register", json={"client_name": "x", "redirect_uris": [CALLBACK]})).json()
    _, challenge = pkce()
    start = await api.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CALLBACK,
                                                      "code_challenge": challenge, "code_challenge_method": "S256"})
    page = await api.get("/oauth/callback", params={"code": "idp-code", "state": "s"}, cookies={"aa_oauth_login": start.cookies["aa_oauth_login"]})
    blob = re.search(r'name="consent" value="([^"]+)"', page.text).group(1)
    out = await api.post("/oauth/consent", data={"consent": blob, "action": "allow", "name": "hermes"},
                         cookies={"aa_oauth_consent": page.cookies["aa_oauth_consent"]})
    assert out.status_code == 400 and "not a web connector" in out.text


async def test_mcp_needs_a_token_and_then_is_that_agent(api, remote, monkeypatch):
    from agent_auth.api import remote_mcp


    bare = await api.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert bare.status_code == 401
    assert bare.headers["www-authenticate"] == f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"'

    _, tokens, _ = await connect(api)
    headers = {"Authorization": f"Bearer {tokens['access_token']}", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-06-18"}
    async with remote.state.remote_mcp_server.session_manager.run():
        listed = await api.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert listed.status_code == 200, listed.text
        names = {t["name"] for t in listed.json()["result"]["tools"]}
        assert "whoami" in names and "get_credential" not in names and "host_run" not in names
        with respx.mock(assert_all_called=True) as mock:
            # The tool calls the broker's own API, as the connector.
            me = mock.get("http://loopback.test/v1/me").mock(return_value=httpx.Response(200, json={"name": "web-claude"}))
            called = await api.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}})
        assert called.status_code == 200, called.text
        assert me.calls[0].request.headers["authorization"] == f"Bearer {tokens['access_token']}"
        assert json.loads(called.json()["result"]["content"][0]["text"]) == {"name": "web-claude"}
        # A wait longer than Cloudflare allows is cut short, and the model is told to call again.
        wait = next(t for t in listed.json()["result"]["tools"] if t["name"] == "wait_for_decision")
        assert "call it again" in wait["description"]
        monkeypatch.setattr(remote_mcp, "MAX_WAIT_SECS", 1)
        with respx.mock() as mock:
            got = mock.get("http://loopback.test/v1/requests/r1/wait").mock(
                return_value=httpx.Response(200, json={"id": "r1", "status": "awaiting_human"}))
            called = await api.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "wait_for_decision", "arguments": {"request_id": "r1"}}})
        assert all(float(c.request.url.params["timeout"]) <= 1 for c in got.calls)
        out = json.loads(called.json()["result"]["content"][0]["text"])
        assert out["status"] == "awaiting_human" and "call wait_for_decision again" in out["rerun"]


async def test_the_operator_lists_and_revokes_connectors(api, remote):
    client_id, tokens, _ = await connect(api)
    listed = (await api.get("/admin/connectors", headers=ADMIN)).json()
    assert listed[0]["client_id"] == client_id and listed[0]["agent"] == "web-claude" and listed[0]["live_authorizations"] == 1
    assert (await api.post(f"/admin/connectors/{client_id}/revoke", headers=ADMIN)).status_code == 200
    assert (await api.get("/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})).status_code == 401
    assert (await api.post("/oauth/register", json={"redirect_uris": [CALLBACK]})).status_code == 201


async def test_off_unless_enabled(api):
    assert (await api.get("/.well-known/oauth-authorization-server")).status_code == 404
    assert (await api.post("/oauth/register", json={"redirect_uris": [CALLBACK]})).status_code == 404
    assert (await api.post("/mcp", json={})).status_code in (404, 405)


async def test_a_connector_never_gets_a_rule_or_reviewer_decision(api, db, service, lldap_mock):
    """Whatever the rules say, a web connector's requests, and requests made
    on its behalf, wait for a person."""
    from agent_auth.core.service import HumanDecision
    from agent_auth.models import Rule
    from agent_auth.core.states import Platform, RuleAction
    from agent_auth.policy.schema import PolicyRule

    from .test_delegation import _delegated_body, _mk_agent, auth

    hermes = await _mk_agent(api, "hermes-homelab-x", lldap_username="svc-hermes")
    web = await _mk_agent(api, "web-claude", kind="ephemeral", runtime="web")
    policy = service.engine.policy
    policy.rules = [
        PolicyRule.model_validate({"match": {"agent": "web-*"}, "action": "approve"}),
        PolicyRule.model_validate({"match": {"platform": "homelab", "delegator": "web-*"}, "action": "approve"}),
        *policy.rules,
    ]
    async with db.session() as session:  # and a saved rule, pinned or not
        session.add(Rule(action=RuleAction.AUTO_APPROVE, agent_pattern="web-*", platform=Platform.A2A, resource_pattern="*"))

    sid = (await api.post("/v1/sessions", headers=auth(web["api_key"]), json={"label": "chat"})).json()["session_id"]
    talk = (await api.post("/v1/requests", headers=auth(web["api_key"], sid), json={
        "platform": "a2a", "capability": "talk", "resource": "hermes-homelab-x",
        "justification": "ask hermes about the cluster", "requested_duration": "30m"})).json()
    assert talk["status"] == "awaiting_human", talk
    await service.decide(talk["id"], HumanDecision(approve=True, decided_by="jrt", duration_secs=1800))

    tid = (await api.post("/v1/a2a/threads", headers=auth(web["api_key"], sid),
                          json={"to": "hermes-homelab-x", "payload": {"task": "look"}})).json()["thread_id"]
    await api.post(f"/v1/a2a/threads/{tid}/messages", headers=auth(hermes["api_key"]), json={"payload": {"ok": True}})
    delegated = (await api.post("/v1/requests", headers=auth(hermes["api_key"]), json=_delegated_body("svc-gitea", tid))).json()
    assert delegated["status"] == "awaiting_human", delegated
    assert delegated["delegator"] == "web-claude"
