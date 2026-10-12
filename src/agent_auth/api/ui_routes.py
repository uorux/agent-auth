"""The admin panel: its page, and signing in and out (core/webui.py). The
page's data comes from the admin API, which accepts the session on the
routes the panel may call (api/deps.require_admin)."""

from __future__ import annotations

from importlib import resources

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..core import webui

router = APIRouter(prefix="/ui")

# Nothing from anywhere else, no inline script or style, never in a frame.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
FILES = {"app.js": "text/javascript", "app.css": "text/css"}


def _auth(request: Request) -> webui.UiAuth:
    auth = getattr(request.app.state, "ui_auth", None)
    if auth is None or not auth.serves(request.headers):
        raise HTTPException(404)
    return auth


def _file(name: str) -> str:
    return resources.files("agent_auth.ui").joinpath(name).read_text()


def _cookie(response: Response, name: str, value: str, max_age: int) -> None:
    # Lax: the provider's redirect back is a cross-origin navigation.
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax")


def _message(text: str, status: int) -> HTMLResponse:
    page = _file("message.html").replace("{{message}}", _escape(text))
    return HTMLResponse(page, status_code=status, headers=HEADERS)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def page(request: Request):
    auth = _auth(request)
    if auth.session(request.cookies.get(webui.SESSION_COOKIE)) is None:
        return RedirectResponse("/ui/login", status_code=303, headers={"Cache-Control": "no-store"})
    return HTMLResponse(_file("index.html"), headers=HEADERS)


@router.get("/login", include_in_schema=False)
async def login(request: Request):
    auth = _auth(request)
    try:
        url, cookie = await auth.begin()
    except webui.UiAuthError as exc:
        return _message(str(exc), 502)
    except Exception:
        return _message("The sign-in provider could not be reached.", 502)
    response = RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})
    _cookie(response, webui.LOGIN_COOKIE, cookie, webui.LOGIN_TTL)
    return response


@router.get("/callback", include_in_schema=False)
async def callback(request: Request):
    auth = _auth(request)
    params = request.query_params
    if params.get("error"):
        return _message(f"The provider refused the sign-in ({params.get('error')}).", 403)
    try:
        cookie = await auth.finish(
            request.cookies.get(webui.LOGIN_COOKIE), params.get("code", ""), params.get("state", "")
        )
    except webui.UiAuthError as exc:
        return _message(str(exc), 403)
    except Exception:
        return _message("The sign-in provider could not be reached.", 502)
    response = RedirectResponse("/ui/", status_code=303, headers={"Cache-Control": "no-store"})
    _cookie(response, webui.SESSION_COOKIE, cookie, auth.ttl)
    response.delete_cookie(webui.LOGIN_COOKIE, path="/")
    return response


@router.get("/session", include_in_schema=False)
async def session(request: Request):
    """Who is signed in, the CSRF token the page sends back with every
    change, and what the panel may call."""
    auth = _auth(request)
    current = auth.session(request.cookies.get(webui.SESSION_COOKIE))
    if current is None:
        raise HTTPException(401, "not signed in")
    return JSONResponse(
        {"user": current.user, "csrf": current.csrf, "expires": current.expires},
        headers={"Cache-Control": "no-store"},
    )


@router.get("/{name}", include_in_schema=False)
async def asset(name: str, request: Request):
    _auth(request)
    if name not in FILES:
        raise HTTPException(404)
    return Response(_file(name), media_type=FILES[name], headers=HEADERS)


@router.post("/logout", include_in_schema=False)
async def logout(request: Request):
    auth = _auth(request)
    current = auth.session(request.cookies.get(webui.SESSION_COOKIE))
    if current is not None and request.headers.get(webui.CSRF_HEADER, "") != current.csrf:
        raise HTTPException(403, "missing or wrong CSRF token")
    response = Response(status_code=204)
    response.delete_cookie(webui.SESSION_COOKIE, path="/")
    return response
