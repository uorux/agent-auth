"""Agent-facing endpoints for commands on hosts: a job's result, and the
commands of an open shell. Asking for one is an ordinary request
(POST /v1/requests, platform "hostexec")."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.hostexec import HostExecError, job_out
from ..core.service import TransitionError
from ..core.states import Platform
from ..daemon_common.hostexec import SpecError
from ..models import Agent, Grant
from .deps import clamp_wait, get_agent

router = APIRouter(prefix="/v1/hostexec")


def _service(request: Request):
    hostexec = getattr(request.app.state, "hostexec", None)
    if hostexec is None:
        raise HTTPException(501, "hostexec is not enabled on this broker")
    return hostexec


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request, agent: Agent = Depends(get_agent), wait: float = 0):
    """A job's status and, once it has ended, its exit code and output.
    `wait` (≤300 s) holds the call open while it is still running."""
    job = await _service(request).get_job(job_id, agent.id, clamp_wait(wait, 0, 300))
    if job is None:
        raise HTTPException(404, "unknown job")
    return job_out(job)


class ShellExec(BaseModel):
    argv: list[str] = Field(min_length=1)
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    stdin: str | None = None
    timeout: int | None = None
    # Seconds to wait for the command to end before returning its job
    # (still running → poll GET /v1/hostexec/jobs/{id}?wait=…).
    wait: float = 60


@router.post("/shells/{grant_id}/exec")
async def shell_exec(grant_id: str, body: ShellExec, request: Request, agent: Agent = Depends(get_agent)):
    """Run one command in an open shell (a `hostexec` "shell" grant)."""
    hostexec = _service(request)
    payload: dict[str, Any] = body.model_dump(exclude={"wait"})
    try:
        job = await hostexec.shell_exec(grant_id, agent.id, payload)
    except LookupError:
        raise HTTPException(404, "unknown shell") from None
    except SpecError as exc:
        raise HTTPException(400, str(exc)) from None
    except HostExecError as exc:
        raise HTTPException(409, str(exc)) from None
    job = await hostexec.get_job(job.id, agent.id, clamp_wait(body.wait, 0, 300))
    return job_out(job)


@router.post("/shells/{grant_id}/close")
async def shell_close(grant_id: str, request: Request, agent: Agent = Depends(get_agent)):
    """End a shell early (it also ends at its expiry, or when the operator
    presses End shell)."""
    state = request.app.state
    async with state.db.session() as session:
        grant = await session.get(Grant, grant_id)
        if (
            grant is None
            or grant.agent_id != agent.id
            or grant.platform != Platform.HOSTEXEC
            or grant.capability != "shell"
        ):
            raise HTTPException(404, "unknown shell")
    try:
        await state.service.revoke_grant(grant_id, "closed by the agent")
    except TransitionError:
        pass  # already ended
    return {"closed": True}
