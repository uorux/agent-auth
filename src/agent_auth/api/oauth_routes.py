"""The OAuth server for web UIs (core/oauth.py) and its discovery documents.

    GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728: /mcp is guarded by us
    GET  /.well-known/oauth-authorization-server       RFC 8414
    POST /oauth/register                               RFC 7591, open
    GET  /oauth/authorize                              PKCE; signs you in at the provider
    GET  /oauth/callback                               the provider's return: the consent page
    POST /oauth/consent                                Allow or Deny
    POST /oauth/token                                  authorization_code, refresh_token
    POST /oauth/revoke                                 RFC 7009

All of it answers 404 unless policy `remote_mcp` is enabled.
"""

from __future__ import annotations

import base64
import binascii
import html
import secrets
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..core import webui
from ..core.oauth import Authorization, OAuthError, agent_name
from .deps import require_admin

router = APIRouter()
admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

LOGIN_COOKIE = "aa_oauth_login"
CONSENT_COOKIE = "aa_oauth_consent"
CONSENT_TTL = 600
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _remote(request: Request):
    oauth = getattr(request.app.state, "oauth", None)
    if oauth is None:
        raise HTTPException(404, "Not Found")
    return oauth


def _base(request: Request) -> str:
    return _remote(request).config.base_url.rstrip("/")


def _json_error(exc: OAuthError) -> JSONResponse:
    return JSONResponse({"error": exc.error, "error_description": exc.description}, status_code=exc.status,
                        headers={"Cache-Control": "no-store"})


def _page(title: str, body: str, status: int = 200, send_to: str | None = None) -> HTMLResponse:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>
:root {{ color-scheme: light dark; --bg:#f6f5f2; --fg:#1d1d1b; --muted:#5f5e5a; --card:#fff; --line:#d9d7d0; --accent:#2a5bd7; --warn:#a4400a; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#161614; --fg:#ecebe6; --muted:#a3a19a; --card:#21211f; --line:#3a3936; --accent:#7ea2ff; --warn:#ff9b5e; }} }}
body {{ background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; margin:0; padding:16px; }}
main {{ max-width:34rem; margin:8vh auto; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }}
h1 {{ font-size:1.25rem; margin:0 0 12px; }} p {{ margin:8px 0; }} .muted {{ color:var(--muted); }}
.where {{ font-weight:600; color:var(--warn); word-break:break-all; }}
label {{ display:block; margin:16px 0 4px; font-weight:600; }}
input[type=text] {{ width:100%; box-sizing:border-box; padding:8px; border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg); font:inherit; }}
.row {{ display:flex; gap:8px; margin-top:20px; }} button {{ font:inherit; padding:8px 16px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; }}
button.allow {{ background:var(--accent); border-color:var(--accent); color:#fff; }}
code {{ font-family:ui-monospace, monospace; }}
</style></head><body><main>{body}</main></body></html>"""
    headers = dict(PAGE_HEADERS)
    if send_to:
        # Browsers hold the redirect after a form post to form-action too:
        # the connector's own origin, and no other.
        parsed = urlparse(send_to)
        headers["Content-Security-Policy"] = headers["Content-Security-Policy"].replace(
            "form-action 'self'", f"form-action 'self' {parsed.scheme}://{parsed.netloc}"
        )
    return HTMLResponse(doc, status_code=status, headers=headers)


def _message(text: str, status: int) -> HTMLResponse:
    return _page("agent-auth", f"<h1>Can't connect</h1><p>{html.escape(text)}</p>", status)


def _cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/oauth", secure=True, httponly=True, samesite="lax")


# ── discovery ─────────────────────────────────────────────────────────────────


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource(request: Request):
    base = _base(request)
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "resource_name": "agent-auth",
    }


def authorization_server_metadata(base: str) -> dict:
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "authorization_response_iss_parameter_supported": True,
        "scopes_supported": [],
    }


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server(request: Request):
    return authorization_server_metadata(_base(request))


# ── registration ──────────────────────────────────────────────────────────────


@router.post("/oauth/register")
async def register(request: Request):
    oauth = _remote(request)
    try:
        body = await request.json()
    except ValueError:
        return _json_error(OAuthError("invalid_client_metadata", "a JSON body"))
    if not isinstance(body, dict):
        return _json_error(OAuthError("invalid_client_metadata", "a JSON object"))
    try:
        return JSONResponse(await oauth.register(body), status_code=201, headers={"Cache-Control": "no-store"})
    except OAuthError as exc:
        return _json_error(exc)


# ── authorization ─────────────────────────────────────────────────────────────


def _ui(request: Request) -> webui.UiAuth:
    # The panel's sign-in (its provider, client and admin group), with our
    # own callback; set up even when the panel itself is off.
    auth = getattr(request.app.state, "oauth_signin", None)
    if auth is None:
        raise HTTPException(404, "Not Found")
    return auth


def _redirect(uri: str, params: dict) -> RedirectResponse:
    sep = "&" if urlparse(uri).query else "?"
    return RedirectResponse(f"{uri}{sep}{urlencode(params)}", status_code=303, headers={"Cache-Control": "no-store"})


@router.get("/oauth/authorize")
async def authorize(request: Request):
    oauth = _remote(request)
    try:
        auth = await oauth.check_authorize(dict(request.query_params))
    except OAuthError as exc:
        # Not sent back to the redirect: it isn't known good yet.
        return _message(exc.description, 400)
    carry = {"client_id": auth.client_id, "client_name": auth.client_name, "redirect_uri": auth.redirect_uri,
             "state": auth.state, "code_challenge": auth.code_challenge}
    try:
        url, cookie = await _ui(request).begin(redirect_uri=f"{_base(request)}/oauth/callback", carry=carry)
    except Exception:
        return _message("The sign-in provider could not be reached.", 502)
    response = RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})
    _cookie(response, LOGIN_COOKIE, cookie, webui.LOGIN_TTL)
    return response


@router.get("/oauth/callback")
async def callback(request: Request):
    oauth = _remote(request)
    ui = _ui(request)
    params = request.query_params
    if params.get("error"):
        return _message(f"The sign-in provider said: {params.get('error')}", 400)
    try:
        user, carry = await ui.identify(request.cookies.get(LOGIN_COOKIE), params.get("code", ""), params.get("state", ""))
    except webui.UiAuthError as exc:
        return _message(str(exc), 403)
    except Exception:
        return _message("The sign-in provider could not be reached.", 502)
    if not carry.get("client_id"):
        return _message("This sign-in didn't start at a connector's authorization.", 400)
    client = await oauth.client(carry["client_id"])
    if client is None:
        return _message("That connector is no longer registered.", 400)
    bound = await oauth.bound_agent(client.id)
    nonce = secrets.token_urlsafe(24)
    blob = ui.seal("consent", {**carry, "user": user, "nonce": nonce})
    host = urlparse(carry["redirect_uri"]).hostname or carry["redirect_uri"]
    name = html.escape(carry.get("client_name") or "An unnamed connector")
    if bound is not None:
        who = f"<p>It acts as <code>{html.escape(bound.name)}</code>, as it did before.</p>"
    else:
        default = html.escape(agent_name(carry.get("client_name") or "connector"))
        who = (
            '<label for="name">It will act as the agent</label>'
            f'<input type="text" id="name" name="name" value="{default}" maxlength="44" pattern="(web-)?[a-z0-9][a-z0-9-]*" required>'
            '<p class="muted">Everything it asks for goes through policy and your approvals as that agent.</p>'
        )
    body = f"""<h1>Connect {name} to agent-auth?</h1>
<p>Signed in as <strong>{html.escape(user)}</strong>.</p>
<p>After you allow it, the browser goes back to <span class="where">{html.escape(host)}</span>. If you didn't start this from there, deny it.</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="consent" value="{html.escape(blob)}">
{who}
<p class="muted">It can see what exists, ask for access, talk to agents in threads, and read the wiki. It gets no credentials.</p>
<div class="row"><button class="allow" type="submit" name="action" value="allow">Allow</button>
<button type="submit" name="action" value="deny">Deny</button></div>
</form>"""
    response = _page("Connect to agent-auth", body, send_to=carry["redirect_uri"])
    _cookie(response, CONSENT_COOKIE, nonce, CONSENT_TTL)
    response.delete_cookie(LOGIN_COOKIE, path="/oauth")
    return response


@router.post("/oauth/consent")
async def consent(request: Request):
    oauth = _remote(request)
    ui = _ui(request)
    form = await request.form()
    data = ui.unseal("consent", str(form.get("consent") or ""), CONSENT_TTL)
    cookie = request.cookies.get(CONSENT_COOKIE) or ""
    if data is None or not cookie or not secrets.compare_digest(cookie, data.get("nonce", "")):
        return _message("This approval expired or didn't start in this browser; start again from the app.", 400)
    auth = Authorization(data["client_id"], data.get("client_name") or "", data["redirect_uri"], data.get("state") or "",
                         data["code_challenge"])
    if form.get("action") != "allow":
        response = _redirect(auth.redirect_uri, {"error": "access_denied", "state": auth.state, "iss": _base(request)})
    else:
        try:
            code = await oauth.approve(auth, str(form.get("name") or auth.client_name or "connector"), data["user"])
        except OAuthError as exc:
            return _message(exc.description, 400)
        response = _redirect(auth.redirect_uri, {"code": code, "state": auth.state, "iss": _base(request)})
    response.delete_cookie(CONSENT_COOKIE, path="/oauth")
    return response


# ── tokens ────────────────────────────────────────────────────────────────────


def _basic(request: Request) -> tuple[str, str] | None:
    scheme, _, value = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        user, _, password = base64.b64decode(value).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return None
    from urllib.parse import unquote

    return unquote(user), unquote(password)


@router.post("/oauth/token")
async def token(request: Request):
    oauth = _remote(request)
    form = {k: str(v) for k, v in (await request.form()).items()}
    try:
        out = await oauth.exchange(form, _basic(request))
    except OAuthError as exc:
        return _json_error(exc)
    return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.post("/oauth/revoke")
async def revoke(request: Request):
    oauth = _remote(request)
    form = await request.form()
    await oauth.revoke(str(form.get("token") or ""))
    return JSONResponse({}, headers={"Cache-Control": "no-store"})


# ── the operator's ────────────────────────────────────────────────────────────


@admin.get("/connectors")
async def list_connectors(request: Request):
    return await _remote(request).clients()


@admin.post("/connectors/{client_id}/revoke")
async def revoke_connector(client_id: str, request: Request):
    if not await _remote(request).revoke_client(client_id):
        raise HTTPException(404, "no such connector")
    return {"revoked": client_id}
