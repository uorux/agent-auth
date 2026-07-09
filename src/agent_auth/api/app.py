from __future__ import annotations

from fastapi import FastAPI

from ..config import Settings
from ..core.a2a import A2AThreadService
from ..core.events import KeyedEvents
from ..core.service import RequestService
from ..db import Database
from ..provisioners.base import ProvisionerRegistry
from . import a2a_routes, admin_routes, agent_routes


def create_app(
    settings: Settings,
    db: Database,
    service: RequestService,
    registry: ProvisionerRegistry,
    events: KeyedEvents,
    a2a: A2AThreadService,
) -> FastAPI:
    # Docs/schema endpoints are disabled: they'd otherwise serve unauthenticated
    # on /docs, /redoc, /openapi.json. Agents discover capabilities via
    # GET /v1/catalog instead.
    app = FastAPI(
        title="agent-auth",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.db = db
    app.state.service = service
    app.state.registry = registry
    app.state.events = events
    app.state.a2a = a2a
    app.state.a2a_events = a2a.events

    app.include_router(agent_routes.router)
    app.include_router(a2a_routes.router)
    app.include_router(admin_routes.router)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    return app
