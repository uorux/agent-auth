"""The admin panel: signing in at the OpenID provider, and what a session may do."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_auth.core import webui
from agent_auth.crypto import generate_fernet_key
from agent_auth.policy.schema import PolicyFile, UiConfig

from .conftest import make_agent

ISSUER = "https://auth.test"
BASE = "https://broker.test"
CLIENT = "agent-auth-admin"
GROUP = "agent-auth-admins"
ADMIN = {"Authorization": "Bearer admin-secret"}


class Provider:
    """An OpenID provider: discovery, keys, the token endpoint and userinfo."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        self.jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}
        self.user = "jrt"
        self.groups = [GROUP, "admin"]
        self.groups_in_id_token = True
        self.claims: dict = {}
        self.signing_key = self.key

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT, "sub": "sub-1", "iat": now, "exp": now + 300, "nonce": nonce}
        if self.groups_in_id_token:
            claims.update(groups=self.groups, preferred_username=self.user)
        claims.update(self.claims)
        return jwt.encode(claims, self.signing_key, algorithm="RS256", headers={"kid": "k1"})

    def mock(self):
        respx.get(f"{ISSUER}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "userinfo_endpoint": f"{ISSUER}/userinfo",
                    "jwks_uri": f"{ISSUER}/jwks.json",
                },
            )
        )
        respx.get(f"{ISSUER}/jwks.json").mock(return_value=httpx.Response(200, json=self.jwks))
        respx.get(f"{ISSUER}/userinfo").mock(
            return_value=httpx.Response(200, json={"sub": "sub-1", "groups": self.groups, "preferred_username": self.user})
        )
        self.token = respx.post(f"{ISSUER}/token")


@pytest.fixture
def provider():
    return Provider()


@pytest.fixture
def ui(app):
    config = UiConfig(enabled=True, base_url=BASE, issuer=ISSUER, client_id=CLIENT, admin_group=GROUP)
    app.state.ui_auth = webui.UiAuth(config, generate_fernet_key())
    return app.state.ui_auth


def cookies(**pairs: str) -> dict[str, str]:
    return {"Cookie": "; ".join(f"{k}={v}" for k, v in pairs.items())}


@pytest.fixture
async def api(app):
    """As the browser reaches the panel: at its own address."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
        yield client


def set_cookie(resp: httpx.Response, name: str) -> str:
    for header in resp.headers.get_list("set-cookie"):
        if header.startswith(name + "="):
            assert "HttpOnly" in header and "Secure" in header and "SameSite=lax" in header
            return header.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError(f"no {name} cookie set")


async def sign_in(api, provider: Provider, tamper=None) -> httpx.Response:
    """Through the whole flow; returns the callback's response."""
    provider.mock()
    start = await api.get("/ui/login")
    assert start.status_code == 303
    login_cookie = set_cookie(start, webui.LOGIN_COOKIE)
    query = parse_qs(urlparse(start.headers["location"]).query)
    assert query["client_id"] == [CLIENT] and query["redirect_uri"] == [f"{BASE}/ui/callback"]
    assert query["code_challenge_method"] == ["S256"] and "groups" in query["scope"][0]
    state, nonce = query["state"][0], query["nonce"][0]
    if tamper:
        state, nonce = tamper(state, nonce)
    provider.token.mock(
        return_value=httpx.Response(200, json={"id_token": provider.id_token(nonce), "access_token": "at"})
    )
    return await api.get(
        "/ui/callback", params={"code": "c0de", "state": state}, headers=cookies(**{webui.LOGIN_COOKIE: login_cookie})
    )


async def session_headers(api, provider: Provider) -> tuple[dict[str, str], str]:
    done = await sign_in(api, provider)
    assert done.status_code == 303 and done.headers["location"] == "/ui/", done.text
    headers = cookies(**{webui.SESSION_COOKIE: set_cookie(done, webui.SESSION_COOKIE)})
    info = (await api.get("/ui/session", headers=headers)).json()
    return headers, info["csrf"]


@respx.mock
async def test_signing_in_gives_a_session_that_sets_agents_up(api, db, ui, provider):
    await make_agent(db, "claude-x-galaxy", project="x")
    headers, csrf = await session_headers(api, provider)
    assert (await api.get("/ui/session", headers=headers)).json()["user"] == "jrt"
    # PKCE: the verifier sent to the token endpoint, and no client secret.
    sent = parse_qs(provider.token.calls[0].request.content.decode())
    assert sent["grant_type"] == ["authorization_code"] and len(sent["code_verifier"][0]) > 40
    assert "client_secret" not in sent

    page = await api.get("/ui/", headers=headers)
    assert page.status_code == 200 and "app.js" in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "script-src 'self'" in page.headers["content-security-policy"]

    assert [a["name"] for a in (await api.get("/admin/agents", headers=headers)).json()] == ["claude-x-galaxy"]
    made = await api.post(
        "/admin/agents",
        headers={**headers, webui.CSRF_HEADER: csrf},
        json={"name": "claude-y-galaxy", "kind": "ephemeral", "runtime": "claude", "project": "y", "host": "galaxy"},
    )
    assert made.status_code == 200 and made.json()["api_key"].startswith("aa_")
    projects = (await api.get("/admin/projects", headers=headers)).json()["projects"]
    assert projects["y"] == {"description": "", "repos": [], "in_policy": False, "agents": ["claude-y-galaxy"]}


@respx.mock
async def test_a_change_needs_the_csrf_token(api, db, ui, provider):
    headers, csrf = await session_headers(api, provider)
    body = {"name": "claude-y-galaxy"}
    assert (await api.post("/admin/agents", headers=headers, json=body)).status_code == 403
    assert (await api.post("/admin/agents", headers={**headers, webui.CSRF_HEADER: "guess"}, json=body)).status_code == 403
    assert (await api.post("/admin/agents", headers={**headers, webui.CSRF_HEADER: csrf}, json=body)).status_code == 200


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/admin/requests/some-id/decide"),
        ("POST", "/admin/hosts/recusant/arm"),
        ("POST", "/admin/hosts/recusant/disarm"),
        ("POST", "/admin/unlock"),
        ("POST", "/admin/lockdown"),
        ("POST", "/admin/agents/some-id/set-webhook"),
        ("POST", "/admin/agents/some-id/rotate-lldap-password"),
    ],
)
@respx.mock
async def test_a_session_is_not_the_admin_token(api, db, ui, provider, method, path):
    """Deciding requests, arming hosts and lifting a lockdown stay elsewhere."""
    headers, csrf = await session_headers(api, provider)
    resp = await api.request(method, path, headers={**headers, webui.CSRF_HEADER: csrf}, json={})
    assert resp.status_code == 403 and "admin panel" in resp.json()["detail"]
    # The admin token is as before, panel or no panel.
    assert (await api.request(method, path, headers=ADMIN, json={})).status_code != 403


def test_what_a_session_may_call_is_a_closed_list():
    assert webui.allowed("GET", "/admin/agents")
    assert webui.allowed("PATCH", "/admin/agents/abc/attributes")
    assert webui.allowed("DELETE", "/admin/rules/abc")
    assert not webui.allowed("DELETE", "/admin/agents")
    assert not webui.allowed("PATCH", "/admin/agents/a/b/attributes")
    assert not webui.allowed("POST", "/admin/agents/abc/attributes")
    assert not any("decide" in p or "arm" in p or "unlock" in p or "lockdown" in p for _, p in webui.ALLOWED)


@respx.mock
async def test_only_the_admin_group_gets_in(api, ui, provider):
    provider.groups = ["searxng-users", "admin"]
    done = await sign_in(api, provider)
    assert done.status_code == 403 and "is not in the group agent-auth-admins" in done.text
    assert not any(h.startswith(webui.SESSION_COOKIE) for h in done.headers.get_list("set-cookie"))


@respx.mock
async def test_groups_may_come_from_userinfo(api, ui, provider):
    provider.groups_in_id_token = False
    headers, _ = await session_headers(api, provider)
    assert (await api.get("/ui/session", headers=headers)).json()["user"] == "jrt"


@pytest.mark.parametrize(
    "break_it,expect",
    [
        (lambda p: p.claims.update(aud="another-client"), "did not check out"),
        (lambda p: p.claims.update(iss="https://evil.test"), "did not check out"),
        (lambda p: p.claims.update(exp=int(time.time()) - 60), "did not check out"),
        (lambda p: setattr(p, "signing_key", rsa.generate_private_key(public_exponent=65537, key_size=2048)), "did not check out"),
    ],
)
@respx.mock
async def test_an_id_token_that_does_not_check_out_is_refused(api, ui, provider, break_it, expect):
    break_it(provider)
    done = await sign_in(api, provider)
    assert done.status_code == 403 and expect in done.text


@respx.mock
async def test_the_return_must_answer_the_sign_in_that_was_started(api, ui, provider):
    wrong_state = await sign_in(api, provider, tamper=lambda state, nonce: ("another-state", nonce))
    assert wrong_state.status_code == 403 and "not started here" in wrong_state.text
    wrong_nonce = await sign_in(api, provider, tamper=lambda state, nonce: (state, "another-nonce"))
    assert wrong_nonce.status_code == 403 and "different sign-in" in wrong_nonce.text
    # No login cookie at all (a callback opened cold).
    assert (await api.get("/ui/callback", params={"code": "c", "state": "s"})).status_code == 403


@respx.mock
async def test_without_a_session(api, db, ui, provider):
    provider.mock()
    assert (await api.get("/ui/")).status_code == 303
    assert (await api.get("/ui/session")).status_code == 401
    assert (await api.get("/admin/agents")).status_code == 401
    # A header a proxy might add proves nothing: nobody is signed in by it.
    forged = {"Remote-User": "jrt", "Remote-Groups": GROUP, "X-Forwarded-User": "jrt"}
    assert (await api.get("/admin/agents", headers=forged)).status_code == 401
    # Nor does a cookie that this broker did not seal, or another broker's.
    other = webui.UiAuth(ui.config, generate_fernet_key())
    stolen = other._seal("session", {"user": "jrt", "csrf": "x", "exp": int(time.time()) + 600})
    assert (await api.get("/admin/agents", headers=cookies(**{webui.SESSION_COOKIE: stolen}))).status_code == 401
    assert (await api.get("/admin/agents", headers=cookies(**{webui.SESSION_COOKIE: "garbage"}))).status_code == 401
    # A login cookie is not a session.
    start = await api.get("/ui/login")
    login_cookie = set_cookie(start, webui.LOGIN_COOKIE)
    assert (await api.get("/admin/agents", headers=cookies(**{webui.SESSION_COOKIE: login_cookie}))).status_code == 401


async def test_a_session_ends(ui):
    live = ui._seal("session", {"user": "jrt", "csrf": "c", "exp": int(time.time()) + 60})
    assert ui.session(live).user == "jrt"
    assert ui.session(ui._seal("session", {"user": "jrt", "csrf": "c", "exp": int(time.time()) - 1})) is None


@respx.mock
async def test_signing_out(api, ui, provider):
    headers, csrf = await session_headers(api, provider)
    assert (await api.post("/ui/logout", headers=headers)).status_code == 403
    out = await api.post("/ui/logout", headers={**headers, webui.CSRF_HEADER: csrf})
    assert out.status_code == 204
    assert any(h.startswith(f"{webui.SESSION_COOKIE}=") and "Max-Age=0" in h for h in out.headers.get_list("set-cookie"))


async def test_no_panel_unless_enabled(api, db):
    assert (await api.get("/ui/")).status_code == 404
    assert (await api.get("/ui/login")).status_code == 404
    assert (await api.get("/ui/app.js")).status_code == 404
    assert (await api.get("/admin/agents", headers=ADMIN)).status_code == 200


async def test_the_pages_files(api, ui):
    js = await api.get("/ui/app.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    # Nothing an agent wrote is ever parsed as HTML.
    assert "innerHTML" not in js.text and "insertAdjacentHTML" not in js.text and "document.write" not in js.text
    assert (await api.get("/ui/app.css")).status_code == 200
    assert (await api.get("/ui/index.html")).status_code == 404
    assert (await api.get("/ui/..%2fmain.py")).status_code == 404


def test_policy_enables_the_panel_with_https_urls():
    on = PolicyFile.model_validate({"ui": {"enabled": True, "base_url": BASE, "issuer": ISSUER}})
    assert on.ui.client_id == "agent-auth-admin" and on.ui.admin_group == "agent-auth-admins"
    assert PolicyFile.model_validate({}).ui.enabled is False
    with pytest.raises(ValueError, match="https URL"):
        PolicyFile.model_validate({"ui": {"enabled": True, "base_url": "http://broker", "issuer": ISSUER}})


@respx.mock
async def test_the_panel_is_served_at_its_own_address_only(app, ui, provider):
    """Under the broker's other names (the public one agents use) there is no
    page, and a session cookie is not looked at."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as own:
        headers, _ = await session_headers(own, provider)
        assert (await own.get("/admin/agents", headers=headers)).status_code == 200
        # Forwarded by a proxy for another host.
        via = {**headers, "X-Forwarded-Host": "agent-auth.public.test"}
        assert (await own.get("/ui/", headers=via)).status_code == 404
        assert (await own.get("/admin/agents", headers=via)).status_code == 401
    async with httpx.AsyncClient(transport=transport, base_url="https://agent-auth.public.test") as public:
        assert (await public.get("/ui/")).status_code == 404
        assert (await public.get("/ui/login")).status_code == 404
        assert (await public.get("/admin/agents", headers=headers)).status_code == 401
        assert (await public.get("/admin/agents", headers=ADMIN)).status_code == 200
    # Behind a local proxy that does not pass the host on.
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8400") as local:
        assert (await local.get("/admin/agents", headers=headers)).status_code == 200
