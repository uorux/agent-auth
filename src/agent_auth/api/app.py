from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.routing import Route

from ..config import Settings
from ..core.a2a import A2AThreadService
from ..core.daemons import DaemonHub
from ..core.events import KeyedEvents
from ..core.service import RequestService
from ..db import Database
from ..provisioners.base import ProvisionerRegistry
from . import (
    a2a_routes,
    admin_log_routes,
    audit_routes,
    oauth_routes,
    chat_routes,
    containment_routes,
    admin_routes,
    agent_routes,
    daemon_routes,
    hostexec_routes,
    token_routes,
    ui_routes,
    wiki_routes,
)


def create_app(
    settings: Settings,
    db: Database,
    service: RequestService,
    registry: ProvisionerRegistry,
    events: KeyedEvents,
    a2a: A2AThreadService,
    daemons: DaemonHub | None = None,
    hostexec=None,
) -> FastAPI:
    # Docs/schema endpoints are disabled: they'd otherwise serve unauthenticated
    # on /docs, /redoc, /openapi.json. Agents discover capabilities via
    # GET /v1/catalog instead.
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # The remote MCP server's session manager (enable_remote_mcp), if any.
        server = getattr(app.state, "remote_mcp_server", None)
        if server is None:
            yield
            return
        async with server.session_manager.run():
            yield

    app = FastAPI(
        title="agent-auth",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db = db
    app.state.service = service
    app.state.registry = registry
    app.state.events = events
    app.state.a2a = a2a
    app.state.a2a_events = a2a.events
    app.state.daemons = daemons if daemons is not None else DaemonHub(db, settings)
    # core/hostexec.HostExecService; None = the daemon channel is off.
    app.state.hostexec = hostexec
    # core/wiki.WikiService; None = no wiki on this broker.
    app.state.wiki = None
    # core/webui.UiAuth; None = no admin panel.
    app.state.ui_auth = None
    # core/lockdown.ContainmentService: agents held wherever they run. The
    # agent VMs hear of it over the daemon channel, when there is one.
    from ..core.lockdown import ContainmentService

    app.state.containment = ContainmentService(
        db, service, a2a, app.state.daemons if app.state.daemons.enabled else None
    )
    if hostexec is not None:
        hostexec.containment = app.state.containment
    # core/security_log.py: refusals the database doesn't keep, for the audit feed.
    from ..core.security_log import SecurityLog

    app.state.security_log = SecurityLog()
    app.state.containment.security_log = app.state.security_log

    app.include_router(agent_routes.router)
    app.include_router(a2a_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(admin_log_routes.router)
    app.include_router(audit_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(oauth_routes.admin)
    app.include_router(chat_routes.router)
    app.include_router(containment_routes.admin)
    app.include_router(containment_routes.agents)
    app.include_router(daemon_routes.router)
    app.include_router(hostexec_routes.router)
    app.include_router(token_routes.router)
    app.include_router(wiki_routes.router)
    app.include_router(ui_routes.router)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    return app


def enable_remote_mcp(app: FastAPI, policy, settings: Settings, signin) -> None:
    """The broker as a remote MCP server for web UIs (policy remote_mcp):
    the OAuth server, its sign-in (`signin`: a core/webui.UiAuth), and /mcp.
    Call before the app starts (its lifespan runs the MCP session manager)."""
    from ..core.oauth import OAuthService
    from .remote_mcp import RemoteMcpApp, build_server

    config = policy.remote_mcp
    app.state.oauth = OAuthService(app.state.db, config)
    app.state.oauth_signin = signin
    server = build_server(config.tools)
    host = "127.0.0.1" if settings.listen_host in ("0.0.0.0", "::", "") else settings.listen_host
    loopback = settings.remote_mcp_loopback_url or f"http://{host}:{settings.listen_port}"
    asgi = RemoteMcpApp(server, app.state, config.base_url, loopback)
    app.state.remote_mcp_server = server
    for path in ("/mcp", "/mcp/"):
        app.router.routes.insert(0, Route(path, endpoint=asgi, methods=["GET", "POST", "DELETE"]))
