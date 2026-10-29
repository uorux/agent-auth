"""agent-auth-mcp-bridge <server>: a catalogued MCP server as a local stdio
MCP server, for clients that can't refresh a bearer token themselves.

It passes JSON-RPC messages between stdin/stdout and the server's
streamable-HTTP endpoint, adding `Authorization: Bearer <token>` from the
agent's own agent-auth grant and fetching a new token when the old one runs
out. It asks for nothing: without an active grant for the server it says so
and exits, and the agent requests one (request_access, platform "mcp").

It runs as the agent, with the agent's own key (AGENT_AUTH_URL,
AGENT_AUTH_API_KEY), and holds nothing the agent couldn't get itself. The
server's own proxy still decides what the token is good for.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from datetime import datetime

import httpx

REFRESH_BEFORE_SECS = 60
ACCEPT = "application/json, text/event-stream"


class NoGrant(Exception):
    pass


class Bridge:
    def __init__(self, server: str, broker_url: str, api_key: str, session: str | None = None,
                 broker: httpx.AsyncClient | None = None, upstream: httpx.AsyncClient | None = None):
        self.server = server
        headers = {"Authorization": f"Bearer {api_key}"}
        if session:
            headers["X-Agent-Session"] = session
        self.broker = broker or httpx.AsyncClient(base_url=broker_url.rstrip("/"), timeout=30)
        self.broker_headers = headers
        self.upstream = upstream or httpx.AsyncClient(timeout=httpx.Timeout(300, connect=15))
        self.url: str | None = None
        self._token: str | None = None
        self._token_expires = 0.0
        self._token_lock = asyncio.Lock()
        self._session_id: str | None = None
        self._protocol: str | None = None
        self._out_lock = asyncio.Lock()

    async def _broker(self, path: str, **params) -> object:
        resp = await self.broker.get(path, headers=self.broker_headers, params=params or None)
        resp.raise_for_status()
        return resp.json()

    async def token(self, fresh: bool = False) -> str:
        async with self._token_lock:
            if not fresh and self._token and time.time() < self._token_expires - REFRESH_BEFORE_SECS:
                return self._token
            if self.url is None:
                catalog = await self._broker("/v1/catalog")
                servers = [s for p in catalog["platforms"] if p["platform"] == "mcp" for s in p.get("servers") or []]
                entry = next((s for s in servers if s["name"] == self.server), None)
                if entry is None:
                    raise NoGrant(f"agent-auth has no MCP server {self.server!r} in its catalog")
                self.url = entry["url"]
            grants = [
                g for g in await self._broker("/v1/grants", status="active")
                if g["platform"] == "mcp" and g["resource"] == self.server
            ]
            if not grants:
                raise NoGrant(
                    f"no active agent-auth grant for MCP server {self.server!r}: ask with "
                    f'request_access(platform="mcp", capability="use", resource="{self.server}")'
                )
            # The widest grant, then the one that lasts longest.
            grants.sort(key=lambda g: ("*" in (g["scope"].get("tools") or ["*"]), g["expires_at"]), reverse=True)
            cred = await self._broker(f"/v1/grants/{grants[0]['id']}/credential")
            self._token = cred["value"]
            self._token_expires = datetime.fromisoformat(cred["expires_at"]).timestamp()
            return self._token

    async def _write(self, message: object) -> None:
        async with self._out_lock:
            sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    async def _headers(self, fresh: bool = False) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {await self.token(fresh)}", "Accept": ACCEPT,
                   "Content-Type": "application/json"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._protocol:
            headers["MCP-Protocol-Version"] = self._protocol
        return headers

    async def forward(self, message: dict) -> None:
        """One message from the client to the server; its answers (a JSON
        body, or an event stream) back to the client."""
        expects_reply = isinstance(message, dict) and "id" in message and "method" in message
        try:
            for attempt in (0, 1):
                async with self.upstream.stream(
                    "POST", self.url or await self._url(), headers=await self._headers(fresh=attempt == 1),
                    content=json.dumps(message),
                ) as resp:
                    if resp.status_code == 401 and attempt == 0:
                        continue  # the token ran out between the check and the call
                    if resp.status_code >= 400:
                        body = (await resp.aread()).decode(errors="replace")[:300]
                        raise RuntimeError(f"{self.server} answered {resp.status_code}: {body}")
                    if sid := resp.headers.get("mcp-session-id"):
                        self._session_id = sid
                    kind = resp.headers.get("content-type", "")
                    if kind.startswith("text/event-stream"):
                        async for event in _sse(resp):
                            await self._relay(message, event)
                    elif kind.startswith("application/json"):
                        await self._relay(message, json.loads(await resp.aread()))
                    return
        except Exception as exc:  # the client must get an answer to a request
            if expects_reply:
                await self._write({"jsonrpc": "2.0", "id": message["id"],
                                   "error": {"code": -32000, "message": f"agent-auth-mcp-bridge: {exc}"}})
            else:
                print(f"agent-auth-mcp-bridge: {exc}", file=sys.stderr)

    async def _url(self) -> str:
        await self.token()
        assert self.url is not None
        return self.url

    async def _relay(self, request: dict, answer: object) -> None:
        if isinstance(request, dict) and request.get("method") == "initialize" and isinstance(answer, dict):
            version = (answer.get("result") or {}).get("protocolVersion")
            if isinstance(version, str):
                self._protocol = version
        await self._write(answer)

    async def run(self, stdin: asyncio.StreamReader) -> None:
        tasks: set[asyncio.Task] = set()
        while line := await stdin.readline():
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("method") == "initialize":
                await self.forward(message)  # in order: the session id comes from it
                continue
            task = asyncio.create_task(self.forward(message))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        await asyncio.gather(*tasks, return_exceptions=True)


async def _sse(resp: httpx.Response):
    """The JSON messages of an event stream."""
    data: list[str] = []
    async for line in resp.aiter_lines():
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line and data:
            try:
                yield json.loads("\n".join(data))
            except ValueError:
                pass
            data = []
    if data:
        try:
            yield json.loads("\n".join(data))
        except ValueError:
            pass


async def _main(server: str) -> int:
    url, key = os.environ.get("AGENT_AUTH_URL"), os.environ.get("AGENT_AUTH_API_KEY")
    if not url or not key:
        print("agent-auth-mcp-bridge: AGENT_AUTH_URL and AGENT_AUTH_API_KEY must be set", file=sys.stderr)
        return 2
    bridge = Bridge(server, url, key, os.environ.get("AGENT_AUTH_SESSION") or None)
    try:
        await bridge.token()
    except NoGrant as exc:
        print(f"agent-auth-mcp-bridge: {exc}", file=sys.stderr)
        return 2
    except httpx.HTTPError as exc:
        print(f"agent-auth-mcp-bridge: cannot reach agent-auth: {exc}", file=sys.stderr)
        return 2
    reader = asyncio.StreamReader()
    await asyncio.get_running_loop().connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    await bridge.run(reader)
    return 0


def run() -> None:
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        print("usage: agent-auth-mcp-bridge <server>   (a server from agent-auth's mcp catalog)", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(_main(sys.argv[1])))
