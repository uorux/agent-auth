"""The agents' wiki: everyone reads, an agent writes its own project's pages."""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
import respx

from agent_auth.core.states import Platform
from agent_auth.core.wiki import GithubWikiBackend, WikiConflict, WikiService
from agent_auth.policy.schema import PolicyFile, WikiConfig

from .conftest import GITHUB_API, make_agent

REPO = "jrt/agent-wiki"


class FakeBackend:
    """A repo in memory, with GitHub's rule that a write names the blob it replaces."""

    def __init__(self, files: dict[str, str] | None = None):
        self.files = {p: t.encode() for p, t in (files or {}).items()}
        self.commits: list[tuple[str, str, str]] = []  # (path, author, message)
        self.snapshots = 0

    @staticmethod
    def sha(data: bytes) -> str:
        return hashlib.sha1(data).hexdigest()

    async def snapshot(self, known):
        self.snapshots += 1
        return {p: (self.sha(d), d) for p, d in self.files.items()}

    async def put(self, path, content, message, author, sha):
        current = self.files.get(path)
        if (self.sha(current) if current is not None else None) != sha:
            raise WikiConflict()
        self.files[path] = content
        self.commits.append((path, author, message))
        return self.sha(content)

    async def delete(self, path, message, author, sha):
        if path not in self.files or self.sha(self.files[path]) != sha:
            raise WikiConflict()
        del self.files[path]
        self.commits.append((path, author, message))

    async def last_change(self, path):
        for p, author, message in reversed(self.commits):
            if p == path:
                return {"author": author, "at": "2026-10-12T00:00:00Z", "summary": message.splitlines()[0]}
        return None


@pytest.fixture
def backend():
    return FakeBackend({"shared/services.md": "# Services\n\nSearXNG is at search.rooty.dev.\n"})


@pytest.fixture
def wiki(app, backend):
    config = WikiConfig(repo=REPO, editors=[{"project": "homelab"}], refresh_secs=0)
    app.state.wiki = WikiService(config, backend)
    return app.state.wiki


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def test_an_agent_writes_its_own_projects_pages_and_everyone_reads_them(api, db, wiki, backend):
    _, tracker = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker", runtime="claude")
    _, other = await make_agent(db, "claude-food-tracker-excelsior", project="food-tracker", runtime="claude")

    resp = await api.put(
        "/v1/wiki/page",
        headers=auth(tracker),
        json={"path": "projects/task-tracker/deploy.md", "content": "# Deploy\n\nFlux applies it.\n", "summary": "how it deploys"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] is True
    assert backend.commits[-1][1] == "claude-task-tracker-galaxy"
    assert "Agent: claude-task-tracker-galaxy (project task-tracker)" in backend.commits[-1][2]

    page = (await api.get("/v1/wiki/page", headers=auth(other), params={"path": "projects/task-tracker/deploy.md"})).json()
    assert page["project"] == "task-tracker"
    assert page["content"].startswith("# Deploy")
    assert page["last_change"]["author"] == "claude-task-tracker-galaxy"

    found = (await api.get("/v1/wiki/search", headers=auth(other), params={"q": "flux deploy"})).json()
    assert [r["path"] for r in found["results"]] == ["projects/task-tracker/deploy.md"]
    assert found["results"][0]["lines"]

    listing = (await api.get("/v1/wiki", headers=auth(other))).json()
    assert {p["path"] for p in listing["pages"]} == {"shared/services.md", "projects/task-tracker/deploy.md"}
    assert listing["you_may_write"] == ["projects/food-tracker/"]


@pytest.mark.parametrize(
    "path",
    ["projects/food-tracker/notes.md", "shared/services.md", "README.md", "projects/task-tracker.md"],
)
async def test_an_agent_cannot_write_outside_its_project(api, db, wiki, backend, path):
    _, key = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker")
    resp = await api.put(
        "/v1/wiki/page", headers=auth(key), json={"path": path, "content": "# Mine now\n", "summary": "x"}
    )
    assert resp.status_code == 403, resp.text
    assert "projects/task-tracker/" in resp.json()["detail"]
    assert not backend.commits
    # ... nor delete there.
    resp = await api.post("/v1/wiki/delete", headers=auth(key), json={"path": "shared/services.md", "summary": "x"})
    assert resp.status_code == 403


async def test_an_agent_without_a_project_reads_and_cannot_write(api, db, wiki, backend):
    _, key = await make_agent(db, "claude-somewhere")
    assert (await api.get("/v1/wiki/page", headers=auth(key), params={"path": "shared/services.md"})).status_code == 200
    assert (await api.get("/v1/wiki", headers=auth(key))).json()["you_may_write"] == []
    resp = await api.put(
        "/v1/wiki/page", headers=auth(key), json={"path": "projects/x/a.md", "content": "# A\n", "summary": "x"}
    )
    assert resp.status_code == 403
    assert "no project on record" in resp.json()["detail"]


async def test_an_editor_writes_shared_pages(api, db, wiki, backend):
    _, key = await make_agent(db, "hermes-homelab-recusant", project="homelab", runtime="hermes")
    sha = (await api.get("/v1/wiki/page", headers=auth(key), params={"path": "shared/services.md"})).json()["sha"]
    resp = await api.put(
        "/v1/wiki/page",
        headers=auth(key),
        json={"path": "shared/services.md", "content": "# Services\n\nUpdated.\n", "summary": "update", "base_sha": sha},
    )
    assert resp.status_code == 200, resp.text
    assert backend.files["shared/services.md"] == b"# Services\n\nUpdated.\n"
    assert (await api.get("/v1/wiki", headers=auth(key))).json()["you_may_write"] == ["(every page)"]


async def test_a_page_that_exists_is_replaced_only_from_the_version_read(api, db, wiki, backend):
    _, key = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker")
    path = "projects/task-tracker/a.md"
    body = {"path": path, "content": "# One\n", "summary": "one"}
    first = (await api.put("/v1/wiki/page", headers=auth(key), json=body)).json()

    # No base_sha, and a stale one: refused, nothing written.
    blind = await api.put("/v1/wiki/page", headers=auth(key), json={**body, "content": "# Two\n"})
    assert blind.status_code == 409 and "base_sha" in blind.json()["detail"]
    backend.files[path] = b"# Edited on GitHub by hand\n"
    stale = await api.put(
        "/v1/wiki/page", headers=auth(key), json={**body, "content": "# Two\n", "base_sha": first["sha"]}
    )
    assert stale.status_code == 409 and "changed since you read it" in stale.json()["detail"]
    assert backend.files[path] == b"# Edited on GitHub by hand\n"

    # Read again, then it goes through; and the delete needs the same.
    sha = (await api.get("/v1/wiki/page", headers=auth(key), params={"path": path})).json()["sha"]
    ok = await api.put("/v1/wiki/page", headers=auth(key), json={**body, "content": "# Two\n", "base_sha": sha})
    assert ok.status_code == 200
    assert (await api.post("/v1/wiki/delete", headers=auth(key), json={"path": path, "summary": "gone"})).status_code == 409
    gone = await api.post(
        "/v1/wiki/delete", headers=auth(key), json={"path": path, "summary": "gone", "base_sha": ok.json()["sha"]}
    )
    assert gone.status_code == 200 and path not in backend.files


@pytest.mark.parametrize(
    "path",
    ["projects/task-tracker/../../shared/x.md", "projects/task-tracker/.hidden.md", "/etc/passwd.md",
     "projects/task-tracker/a.txt", "projects/task-tracker//a.md", "projects/task-tracker/a b.md",
     "projects/task-tracker/" + "/".join("d" * 3 for _ in range(6)) + "/a.md"],
)
async def test_a_path_is_plain_segments_ending_in_md(api, db, wiki, backend, path):
    _, key = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker")
    resp = await api.put("/v1/wiki/page", headers=auth(key), json={"path": path, "content": "# X\n", "summary": "x"})
    assert resp.status_code == 400, resp.text
    assert (await api.get("/v1/wiki/page", headers=auth(key), params={"path": path})).status_code == 400
    assert not backend.commits


@pytest.mark.parametrize(
    "secret",
    ["aa_0123456789ab_" + "x" * 43, "ghs_" + "A" * 36, "-----BEGIN OPENSSH PRIVATE KEY-----",
     "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJlLXZhbHVl"],
)
async def test_a_page_with_a_credential_in_it_is_refused(api, db, wiki, backend, secret):
    _, key = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker")
    resp = await api.put(
        "/v1/wiki/page",
        headers=auth(key),
        json={"path": "projects/task-tracker/a.md", "content": f"# Access\n\nUse {secret} to log in.\n", "summary": "x"},
    )
    assert resp.status_code == 400 and "where" in resp.json()["detail"]
    assert not backend.commits


async def test_size_empty_and_missing(api, db, wiki, backend):
    _, key = await make_agent(db, "claude-task-tracker-galaxy", project="task-tracker")
    put = lambda content: api.put(  # noqa: E731
        "/v1/wiki/page", headers=auth(key), json={"path": "projects/task-tracker/a.md", "content": content, "summary": "x"}
    )
    assert (await put("x" * (wiki.config.max_page_bytes + 1))).status_code == 413
    assert (await put("  \n")).status_code == 400
    assert (await api.get("/v1/wiki/page", headers=auth(key), params={"path": "nope.md"})).status_code == 404
    assert (await api.get("/v1/wiki/search", headers=auth(key), params={"q": " "})).status_code == 400


async def test_no_key_no_wiki_and_no_wiki_configured(api, app, db):
    _, key = await make_agent(db, "claude-x", project="x")
    assert (await api.get("/v1/wiki", headers=auth(key))).status_code == 501
    assert (await api.get("/v1/wiki")).status_code == 401


async def test_the_brokers_copy_is_kept_between_reads_and_survives_an_outage(db, backend):
    agent, _ = await make_agent(db, "claude-x", project="x")
    wiki = WikiService(WikiConfig(repo=REPO, refresh_secs=3600), backend)
    await wiki.list(agent)
    await wiki.search("searxng")
    await wiki.read("shared/services.md")
    assert backend.snapshots == 1

    async def down(known):
        raise httpx.ConnectError("no route")

    backend.snapshot = down
    wiki._loaded_at = 1.0  # long ago: the next read tries the repo again
    assert (await wiki.read("shared/services.md"))["content"].startswith("# Services")


def test_policy_names_the_wiki_and_its_editors():
    policy = PolicyFile.model_validate(
        {"projects": {"homelab": {}}, "wiki": {"repo": REPO, "editors": [{"project": "homelab"}]}}
    )
    assert policy.wiki.branch == "main"
    with pytest.raises(ValueError, match="not listed under `projects`"):
        PolicyFile.model_validate({"wiki": {"repo": REPO, "editors": [{"project": "nope"}]}})
    with pytest.raises(ValueError, match="owner/name"):
        PolicyFile.model_validate({"wiki": {"repo": "just-a-name"}})


# ── the repo itself, through GitHub's API ────────────────────────────────────


def _blob(text: str) -> dict:
    return {"content": base64.b64encode(text.encode()).decode(), "encoding": "base64"}


@respx.mock
async def test_github_backend_reads_and_writes_as_the_app(registry):
    github = registry.get(Platform.GITHUB)
    backend = GithubWikiBackend(github, REPO, "main")
    respx.get(f"{GITHUB_API}/repos/{REPO}/installation").mock(return_value=httpx.Response(200, json={"id": 7}))
    mint = respx.post(f"{GITHUB_API}/app/installations/7/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_wiki", "expires_at": "2099-01-01T00:00:00Z"})
    )
    respx.get(f"{GITHUB_API}/repos/{REPO}/git/trees/main").mock(
        return_value=httpx.Response(
            200,
            json={
                "tree": [
                    {"path": "shared", "type": "tree", "sha": "t1"},
                    {"path": "shared/services.md", "type": "blob", "sha": "b1"},
                    {"path": "shared/diagram.png", "type": "blob", "sha": "b2"},
                    {"path": ".github/notes.md", "type": "blob", "sha": "b3"},
                ]
            },
        )
    )
    blob = respx.get(f"{GITHUB_API}/repos/{REPO}/git/blobs/b1").mock(
        return_value=httpx.Response(200, json=_blob("# Services\n"))
    )

    known: dict[str, bytes] = {}
    assert await backend.snapshot(known) == {"shared/services.md": ("b1", b"# Services\n")}
    # A second look fetches no blob it already holds, and mints no second token.
    await backend.snapshot(known)
    assert blob.call_count == 1 and mint.call_count == 1
    assert json.loads(mint.calls[0].request.content) == {
        "repositories": ["agent-wiki"],
        "permissions": {"contents": "write", "metadata": "read"},
    }

    put = respx.put(f"{GITHUB_API}/repos/{REPO}/contents/projects/x/a.md").mock(
        return_value=httpx.Response(201, json={"content": {"sha": "b9"}})
    )
    assert await backend.put("projects/x/a.md", b"# A\n", "add a\n\nAgent: claude-x", "claude-x", None) == "b9"
    sent = json.loads(put.calls[0].request.content)
    assert sent["author"]["name"] == "claude-x" and sent["branch"] == "main" and "sha" not in sent
    assert put.calls[0].request.headers["Authorization"] == "token ghs_wiki"

    put.mock(return_value=httpx.Response(409, json={"message": "is at b9 but expected b1"}))
    with pytest.raises(WikiConflict):
        await backend.put("projects/x/a.md", b"# B\n", "m", "claude-x", "b1")

    respx.get(f"{GITHUB_API}/repos/{REPO}/commits").mock(
        return_value=httpx.Response(
            200,
            json=[{"commit": {"author": {"name": "claude-x", "date": "2026-10-12T01:00:00Z"}, "message": "add a\n\nAgent: claude-x"}}],
        )
    )
    assert await backend.last_change("projects/x/a.md") == {
        "author": "claude-x", "at": "2026-10-12T01:00:00Z", "summary": "add a",
    }


@respx.mock
async def test_an_empty_repo_is_an_empty_wiki(registry):
    backend = GithubWikiBackend(registry.get(Platform.GITHUB), REPO, "main")
    respx.get(f"{GITHUB_API}/repos/{REPO}/installation").mock(return_value=httpx.Response(200, json={"id": 7}))
    respx.post(f"{GITHUB_API}/app/installations/7/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_wiki", "expires_at": "2099-01-01T00:00:00Z"})
    )
    respx.get(f"{GITHUB_API}/repos/{REPO}/git/trees/main").mock(return_value=httpx.Response(409, json={"message": "Git Repository is empty."}))
    assert await backend.snapshot({}) == {}
