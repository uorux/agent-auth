"""The agents' shared wiki: markdown pages in one git repo that only the
broker touches (README "Wiki").

Every agent reads and searches it through the broker, with no grant. An
agent writes under `projects/<its project>/` and nowhere else; the agents
policy names as editors (`wiki.editors`) write anywhere. The project is the
one on the agent's record, which an agent cannot change. Each write is one
commit in the repo, authored as the agent.

What this does not do: vouch for what a page says. A page is whatever some
agent wrote, so readers get its project and last author with it, and what
they read is information to weigh, not instructions.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ..policy.agents import agent_matches
from ..policy.schema import WikiConfig

log = logging.getLogger(__name__)

PROJECTS_DIR = "projects"
SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_PATH = 200
MAX_DEPTH = 6
MAX_SUMMARY = 200

# Refused in a page: the shapes of credentials an agent is likely to hold.
# A guard against pasting one by mistake, not a scanner.
SECRET_PATTERNS = [
    ("an agent-auth API key", re.compile(r"\baa_[A-Za-z0-9]{4,}_[A-Za-z0-9_-]{16,}")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("a JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("an API key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b")),
]


class WikiError(Exception):
    """A refusal the agent should read: (HTTP status, what to do)."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


class WikiConflict(Exception):
    """The page changed under the write."""


@dataclass
class Page:
    path: str
    sha: str
    text: str

    @property
    def title(self) -> str:
        for line in self.text.splitlines():
            if line.startswith("#"):
                return line.lstrip("#").strip() or self.path
            if line.strip():
                break
        return self.path


class WikiBackend(Protocol):
    async def snapshot(self, known: dict[str, bytes]) -> dict[str, tuple[str, bytes]]:
        """Every markdown file: path -> (blob sha, content). `known` maps the
        blob shas already held to their content, so only new ones are fetched."""

    async def put(self, path: str, content: bytes, message: str, author: str, sha: str | None) -> str:
        """Create (sha None) or replace (sha = the blob replaced). Returns the
        new blob sha; WikiConflict if the page is not at `sha` any more."""

    async def delete(self, path: str, message: str, author: str, sha: str) -> None: ...

    async def last_change(self, path: str) -> dict[str, Any] | None: ...


def check_path(path: str) -> str:
    if len(path) > MAX_PATH or not path.endswith(".md"):
        raise WikiError(400, f"a page's path ends in .md and is at most {MAX_PATH} characters")
    parts = path.split("/")
    if len(parts) > MAX_DEPTH or not all(SEGMENT_RE.fullmatch(p) for p in parts):
        raise WikiError(
            400,
            f"path {path!r}: at most {MAX_DEPTH} segments of letters, digits, dots, dashes and "
            "underscores, each starting with a letter or digit",
        )
    return path


def page_project(path: str) -> str | None:
    parts = path.split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == PROJECTS_DIR else None


class WikiService:
    def __init__(self, config: WikiConfig, backend: WikiBackend):
        self.config = config
        self.backend = backend
        self._pages: dict[str, Page] = {}
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()
        self._changes: dict[str, dict[str, Any] | None] = {}  # by blob sha

    # ── who may write what ────────────────────────────────────────────────

    def is_editor(self, agent) -> bool:
        return any(agent_matches(p, agent) for p in self.config.editors)

    def writable(self, agent) -> list[str]:
        """Where this agent may write, for a person or an agent to read."""
        if self.is_editor(agent):
            return ["(every page)"]
        return [f"{PROJECTS_DIR}/{agent.project}/"] if agent.project else []

    def _check_write(self, agent, path: str) -> None:
        if self.is_editor(agent):
            return
        if not agent.project:
            raise WikiError(
                403,
                "you have no project on record, so there is nowhere in the wiki you may write "
                "(the operator sets it: `agent-auth admin agent-set --project`)",
            )
        if page_project(path) != agent.project:
            raise WikiError(
                403,
                f"you may write under {PROJECTS_DIR}/{agent.project}/ only. For a page elsewhere, "
                "ask an agent of the project that owns it (shared pages: the homelab agents)",
            )

    # ── reading ───────────────────────────────────────────────────────────

    async def _load(self, force: bool = False) -> dict[str, Page]:
        async with self._lock:
            if not force and self._loaded_at and time.monotonic() - self._loaded_at < self.config.refresh_secs:
                return self._pages
            known = {p.sha: p.text.encode() for p in self._pages.values()}
            try:
                files = await self.backend.snapshot(known)
            except WikiError:
                raise
            except Exception as exc:
                # A stale copy is better than none while the repo is unreachable.
                log.warning("wiki: could not refresh from %s: %s", self.config.repo, exc)
                if self._loaded_at:
                    return self._pages
                raise WikiError(502, "the wiki's repo could not be read; try again later") from None
            self._pages = {
                path: Page(path, sha, data.decode("utf-8", "replace")) for path, (sha, data) in files.items()
            }
            self._loaded_at = time.monotonic()
            return self._pages

    async def list(self, agent, prefix: str = "") -> dict[str, Any]:
        pages = await self._load()
        return {
            "repo": self.config.repo,
            "you_may_write": self.writable(agent),
            "pages": [
                {"path": p.path, "title": p.title, "bytes": len(p.text.encode())}
                for p in sorted(pages.values(), key=lambda p: p.path)
                if p.path.startswith(prefix)
            ],
        }

    async def read(self, path: str) -> dict[str, Any]:
        check_path(path)
        page = (await self._load()).get(path)
        if page is None:
            raise WikiError(404, f"no page {path!r} (wiki_list shows what exists)")
        if page.sha not in self._changes:
            try:
                self._changes[page.sha] = await self.backend.last_change(path)
            except Exception:
                return self._out(page, None)
        return self._out(page, self._changes[page.sha])

    def _out(self, page: Page, change: dict[str, Any] | None) -> dict[str, Any]:
        return {
            "path": page.path,
            "sha": page.sha,
            # Whose page this is: a project's own, or shared (an editor's).
            "project": page_project(page.path),
            "last_change": change,
            "content": page.text,
        }

    async def search(self, query: str, limit: int = 8) -> dict[str, Any]:
        terms = [t for t in re.split(r"\s+", query.lower().strip()) if t]
        if not terms:
            raise WikiError(400, "an empty search")
        hits = []
        for page in (await self._load()).values():
            text = page.text.lower()
            head = f"{page.path} {page.title}".lower()
            if not all(t in text or t in head for t in terms):
                continue
            score = sum(text.count(t) + 5 * head.count(t) for t in terms)
            hits.append((score, page))
        hits.sort(key=lambda h: (-h[0], h[1].path))
        return {
            "query": query,
            "matches": len(hits),
            "results": [
                {
                    "path": p.path,
                    "title": p.title,
                    "project": page_project(p.path),
                    "lines": _matching_lines(p.text, terms),
                }
                for _, p in hits[: max(1, min(limit, 25))]
            ],
        }

    # ── writing ───────────────────────────────────────────────────────────

    async def write(self, agent, path: str, content: str, summary: str, base_sha: str | None) -> dict[str, Any]:
        check_path(path)
        self._check_write(agent, path)
        data = content.encode()
        if not content.strip():
            raise WikiError(400, "an empty page; to remove one, delete it")
        if len(data) > self.config.max_page_bytes:
            raise WikiError(
                413, f"a page is at most {self.config.max_page_bytes} bytes; split it into several"
            )
        for what, pattern in SECRET_PATTERNS:
            if pattern.search(content):
                raise WikiError(
                    400,
                    f"this looks like it contains {what}. The wiki holds no credentials: say where "
                    "one is kept, never its value",
                )
        current = (await self._load(force=True)).get(path)
        self._check_base(path, current, base_sha)
        if current is not None and current.text == content:
            return {"path": path, "sha": current.sha, "unchanged": True}
        try:
            sha = await self.backend.put(
                path, data, self._message(agent, summary), agent.name, current.sha if current else None
            )
        except WikiConflict:
            raise WikiError(409, f"{path!r} changed while you were writing; read it again") from None
        self._pages[path] = Page(path, sha, content)
        return {"path": path, "sha": sha, "created": current is None}

    async def delete(self, agent, path: str, summary: str, base_sha: str | None) -> dict[str, Any]:
        check_path(path)
        self._check_write(agent, path)
        current = (await self._load(force=True)).get(path)
        if current is None:
            raise WikiError(404, f"no page {path!r}")
        self._check_base(path, current, base_sha)
        try:
            await self.backend.delete(path, self._message(agent, summary), agent.name, current.sha)
        except WikiConflict:
            raise WikiError(409, f"{path!r} changed while you were deleting it; read it again") from None
        self._pages.pop(path, None)
        return {"path": path, "deleted": True}

    @staticmethod
    def _check_base(path: str, current: Page | None, base_sha: str | None) -> None:
        """A page that exists is replaced only by someone who has read the
        version being replaced: no blind overwrite of another agent's edit."""
        if current is None:
            if base_sha:
                raise WikiError(409, f"{path!r} no longer exists; leave base_sha out to create it")
            return
        if base_sha != current.sha:
            raise WikiError(
                409,
                f"{path!r} exists" + (" and has changed since you read it" if base_sha else "")
                + ": read it and pass its `sha` as base_sha",
            )

    @staticmethod
    def _message(agent, summary: str) -> str:
        line = " ".join(summary.split())[:MAX_SUMMARY]
        if not line:
            raise WikiError(400, "say in one line what changed (summary)")
        who = agent.name + (f" (project {agent.project})" if agent.project else "")
        return f"{line}\n\nAgent: {who}"


def _matching_lines(text: str, terms: list[str], limit: int = 3) -> list[str]:
    out = []
    for line in text.splitlines():
        low = line.lower()
        if any(t in low for t in terms):
            out.append(line.strip()[:200])
            if len(out) == limit:
                break
    return out


class GithubWikiBackend:
    """The repo through GitHub's API, as the broker's GitHub App: no clone,
    nothing on disk. The App must be installed on the repo with Contents:
    write."""

    def __init__(self, github, repo: str, branch: str):
        self.github = github  # provisioners.github.GithubProvisioner
        self.repo = repo
        self.branch = branch

    async def _headers(self) -> dict[str, str]:
        token = await self.github.own_token(self.repo, {"contents": "write", "metadata": "read"})
        return self.github._token_headers(token)

    def _url(self, rest: str) -> str:
        return f"{self.github.api_url}/repos/{self.repo}/{rest}"

    async def snapshot(self, known: dict[str, bytes]) -> dict[str, tuple[str, bytes]]:
        headers = await self._headers()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"git/trees/{self.branch}"), headers=headers, params={"recursive": "1"}
            )
            if resp.status_code in (404, 409):
                return {}  # no such branch yet, or an empty repo
            resp.raise_for_status()
            out: dict[str, tuple[str, bytes]] = {}
            for item in resp.json().get("tree", []):
                path = item.get("path", "")
                if item.get("type") != "blob" or not path.endswith(".md"):
                    continue
                try:
                    check_path(path)
                except WikiError:
                    continue  # put there by hand under a name agents can't address
                sha = item["sha"]
                if sha not in known:
                    blob = await client.get(self._url(f"git/blobs/{sha}"), headers=headers)
                    blob.raise_for_status()
                    known[sha] = base64.b64decode(blob.json()["content"])
                out[path] = (sha, known[sha])
            return out

    async def put(self, path: str, content: bytes, message: str, author: str, sha: str | None) -> str:
        body: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content).decode(),
            "branch": self.branch,
            "author": _author(author),
        }
        if sha:
            body["sha"] = sha
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.put(self._url(f"contents/{path}"), headers=await self._headers(), json=body)
        if resp.status_code in (409, 422):
            raise WikiConflict()
        if resp.status_code not in (200, 201):
            log.error("wiki: writing %s failed (%s): %s", path, resp.status_code, resp.text[:300])
            raise WikiError(502, f"the wiki's repo refused the write ({resp.status_code})")
        return resp.json()["content"]["sha"]

    async def delete(self, path: str, message: str, author: str, sha: str) -> None:
        body = {"message": message, "sha": sha, "branch": self.branch, "author": _author(author)}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(
                "DELETE", self._url(f"contents/{path}"), headers=await self._headers(), json=body
            )
        if resp.status_code in (409, 422):
            raise WikiConflict()
        if resp.status_code != 200:
            log.error("wiki: deleting %s failed (%s): %s", path, resp.status_code, resp.text[:300])
            raise WikiError(502, f"the wiki's repo refused the delete ({resp.status_code})")

    async def last_change(self, path: str) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                self._url("commits"),
                headers=await self._headers(),
                params={"path": path, "sha": self.branch, "per_page": "1"},
            )
        if resp.status_code != 200 or not resp.json():
            return None
        commit = resp.json()[0]["commit"]
        return {
            "author": commit["author"]["name"],
            "at": commit["author"]["date"],
            "summary": commit["message"].splitlines()[0],
        }


def _author(name: str) -> dict[str, str]:
    return {"name": name, "email": f"{name}@agents.invalid"}
