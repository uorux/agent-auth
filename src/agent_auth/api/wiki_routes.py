"""The agents' shared wiki (core/wiki.py). Any agent reads; who may write a
page is decided there, from the fields on the agent's record."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.lockdown import holding
from ..core.wiki import WikiError
from ..models import Agent
from .deps import get_agent

router = APIRouter(prefix="/v1/wiki")


def _wiki(request: Request):
    wiki = getattr(request.app.state, "wiki", None)
    if wiki is None:
        raise HTTPException(501, "this broker has no wiki")
    return wiki


async def _answer(call):
    try:
        return await call
    except WikiError as exc:
        raise HTTPException(exc.status, exc.detail) from None


async def _not_held(request: Request, agent: Agent) -> None:
    """A contained agent (core/lockdown.py) still reads, but writes nothing
    every other agent would read."""
    async with request.app.state.db.session() as db:
        held = await holding(db, agent)
    if held is not None:
        raise HTTPException(403, f"contained ({held['id']}): no wiki writes while you are held")


class PageWrite(BaseModel):
    path: str = Field(max_length=300)
    content: str
    summary: str = Field(min_length=1, max_length=500)
    base_sha: str | None = Field(default=None, max_length=64)


class PageDelete(BaseModel):
    path: str = Field(max_length=300)
    summary: str = Field(min_length=1, max_length=500)
    base_sha: str | None = Field(default=None, max_length=64)


@router.get("")
async def list_pages(request: Request, prefix: str = "", agent: Agent = Depends(get_agent)):
    return await _answer(_wiki(request).list(agent, prefix))


@router.get("/page")
async def read_page(request: Request, path: str, agent: Agent = Depends(get_agent)):
    return await _answer(_wiki(request).read(path))


@router.get("/search")
async def search(request: Request, q: str, limit: int = 8, agent: Agent = Depends(get_agent)):
    return await _answer(_wiki(request).search(q, limit))


@router.put("/page")
async def write_page(body: PageWrite, request: Request, agent: Agent = Depends(get_agent)):
    await _not_held(request, agent)
    return await _answer(_wiki(request).write(agent, body.path, body.content, body.summary, body.base_sha))


@router.post("/delete")
async def delete_page(body: PageDelete, request: Request, agent: Agent = Depends(get_agent)):
    await _not_held(request, agent)
    return await _answer(_wiki(request).delete(agent, body.path, body.summary, body.base_sha))
