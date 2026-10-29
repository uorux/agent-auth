"""Daemon-facing endpoints: pairing (authenticated by the one-time code's
proof, not a bearer token) and the signed WebSocket channel."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field

from ..core.daemons import DaemonsDisabled, PairingError

router = APIRouter(prefix="/v1/daemons")


class PairBody(BaseModel):
    role: str = Field(max_length=16)
    name: str = Field(max_length=128)
    public_key: str = Field(max_length=128)
    selector: str = Field(pattern=r"^[0-9a-f]{32}$")
    proof: str = Field(pattern=r"^[0-9a-f]{64}$")


@router.post("/pair")
async def pair(body: PairBody, request: Request):
    try:
        return await request.app.state.daemons.pair(
            body.role, body.name, body.public_key, body.selector, body.proof
        )
    except DaemonsDisabled as exc:
        raise HTTPException(503, str(exc)) from None
    except PairingError as exc:
        raise HTTPException(exc.status, exc.detail) from None


@router.websocket("/connect")
async def connect(ws: WebSocket):
    await ws.app.state.daemons.serve(ws)
