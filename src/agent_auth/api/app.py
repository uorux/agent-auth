from __future__ import annotations

from fastapi import FastAPI

from ..config import Settings
from ..core.events import DecisionEvents
from ..core.service import RequestService
from ..db import Database
from ..provisioners.base import ProvisionerRegistry
from . import admin_routes, agent_routes


def create_app(
    settings: Settings,
    db: Database,
    service: RequestService,
    registry: ProvisionerRegistry,
    events: DecisionEvents,
) -> FastAPI:
    app = FastAPI(title="agent-auth", version="0.1.0")
    app.state.settings = settings
    app.state.db = db
    app.state.service = service
    app.state.registry = registry
    app.state.events = events

    app.include_router(agent_routes.router)
    app.include_router(admin_routes.router)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    return app
