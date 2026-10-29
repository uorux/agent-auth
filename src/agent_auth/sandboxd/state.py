"""sandboxd's persistent state (SQLite under /var/lib/sandboxd, root 0600).

Holds the VM's agent keys — the only copy anywhere: the broker keeps hashes
— plus projects, conversations and which a2a threads each owns.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name TEXT PRIMARY KEY, agent_id TEXT NOT NULL, runtime TEXT, project TEXT,
    api_key TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    name TEXT PRIMARY KEY, uid INTEGER NOT NULL UNIQUE, sealed INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY, agent TEXT NOT NULL, runtime TEXT NOT NULL,
    runtime_session_id TEXT, broker_session_id TEXT, state TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'headless', title TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, last_activity REAL NOT NULL,
    turns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS threads (
    thread_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, peer TEXT,
    role TEXT, topic TEXT, cursor INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL,
    text TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS project_grants (
    grant_id TEXT PRIMARY KEY, project TEXT NOT NULL, target TEXT NOT NULL, access TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass
class AgentRecord:
    name: str
    agent_id: str
    runtime: str | None
    project: str | None
    api_key: str


@dataclass
class Conversation:
    id: str
    agent: str
    runtime: str
    runtime_session_id: str | None
    broker_session_id: str | None
    state: str  # running | parked | attached | closed
    mode: str  # headless | interactive
    title: str
    created_by: str
    created_at: float
    last_activity: float
    turns: int


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fresh = not path.exists()
        if fresh:
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- agents ----------------------------------------------------------------

    def put_agent(self, rec: AgentRecord) -> None:
        self._q(
            "INSERT INTO agents VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "agent_id=excluded.agent_id, runtime=excluded.runtime, project=excluded.project, "
            "api_key=excluded.api_key, updated_at=excluded.updated_at",
            (rec.name, rec.agent_id, rec.runtime, rec.project, rec.api_key, time.time()),
        )

    def agent(self, name: str) -> AgentRecord | None:
        rows = self._q("SELECT name, agent_id, runtime, project, api_key FROM agents WHERE name=?", (name,))
        return AgentRecord(**dict(rows[0])) if rows else None

    def agents(self) -> list[AgentRecord]:
        return [
            AgentRecord(**dict(r))
            for r in self._q("SELECT name, agent_id, runtime, project, api_key FROM agents ORDER BY name")
        ]

    # --- projects ----------------------------------------------------------------

    def project(self, name: str) -> dict[str, Any] | None:
        rows = self._q("SELECT * FROM projects WHERE name=?", (name,))
        return dict(rows[0]) if rows else None

    def projects(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._q("SELECT * FROM projects ORDER BY name")]

    def add_project(self, name: str, uid: int) -> None:
        self._q("INSERT INTO projects (name, uid, created_at) VALUES (?,?,?)", (name, uid, time.time()))

    def seal_project(self, name: str) -> None:
        self._q("UPDATE projects SET sealed=1 WHERE name=?", (name,))

    def used_uids(self) -> set[int]:
        return {r["uid"] for r in self._q("SELECT uid FROM projects")}

    # --- conversations -------------------------------------------------------------

    def new_conversation(
        self, agent: str, runtime: str, *, mode: str = "headless", title: str = "", created_by: str = ""
    ) -> Conversation:
        conv_id = uuid.uuid4().hex[:12]
        now = time.time()
        self._q(
            "INSERT INTO conversations (id, agent, runtime, state, mode, title, created_by, "
            "created_at, last_activity) VALUES (?,?,?,?,?,?,?,?,?)",
            (conv_id, agent, runtime, "parked", mode, title[:200], created_by, now, now),
        )
        return self.conversation(conv_id)

    def conversation(self, conv_id: str) -> Conversation | None:
        rows = self._q("SELECT * FROM conversations WHERE id=?", (conv_id,))
        return Conversation(**dict(rows[0])) if rows else None

    def conversations(self, agent: str | None = None, include_closed: bool = False) -> list[Conversation]:
        sql = "SELECT * FROM conversations WHERE 1=1"
        args: tuple = ()
        if agent:
            sql += " AND agent=?"
            args += (agent,)
        if not include_closed:
            sql += " AND state != 'closed'"
        return [Conversation(**dict(r)) for r in self._q(sql + " ORDER BY last_activity DESC", args)]

    def update_conversation(self, conv_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self._q(f"UPDATE conversations SET {cols} WHERE id=?", (*fields.values(), conv_id))

    def touch(self, conv_id: str) -> None:
        self._q("UPDATE conversations SET last_activity=? WHERE id=?", (time.time(), conv_id))

    # --- threads ---------------------------------------------------------------------

    def bind_thread(self, thread_id: str, conv_id: str, peer: str | None, role: str, topic: str | None) -> None:
        self._q(
            "INSERT INTO threads (thread_id, conversation_id, peer, role, topic) VALUES (?,?,?,?,?) "
            "ON CONFLICT(thread_id) DO UPDATE SET conversation_id=excluded.conversation_id",
            (thread_id, conv_id, peer, role, topic),
        )

    def thread(self, thread_id: str) -> dict[str, Any] | None:
        rows = self._q("SELECT * FROM threads WHERE thread_id=?", (thread_id,))
        return dict(rows[0]) if rows else None

    def threads_of(self, conv_id: str, open_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM threads WHERE conversation_id=?"
        if open_only:
            sql += " AND state != 'closed'"
        return [dict(r) for r in self._q(sql, (conv_id,))]

    def set_thread(self, thread_id: str, **fields: Any) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self._q(f"UPDATE threads SET {cols} WHERE thread_id=?", (*fields.values(), thread_id))

    # --- inbox -----------------------------------------------------------------------

    def queue(self, conv_id: str, text: str) -> None:
        self._q("INSERT INTO inbox (conversation_id, text, created_at) VALUES (?,?,?)", (conv_id, text, time.time()))

    def drain(self, conv_id: str) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, text FROM inbox WHERE conversation_id=? ORDER BY id", (conv_id,)
            ).fetchall()
            if rows:
                self._db.execute("DELETE FROM inbox WHERE id <= ? AND conversation_id=?", (rows[-1]["id"], conv_id))
        return [r["text"] for r in rows]

    def peek(self, conv_id: str) -> list[str]:
        return [r["text"] for r in self._q("SELECT text FROM inbox WHERE conversation_id=? ORDER BY id", (conv_id,))]

    # --- project grants ------------------------------------------------------------------

    def add_project_grant(self, grant_id: str, project: str, target: str, access: str) -> None:
        self._q("INSERT OR REPLACE INTO project_grants VALUES (?,?,?,?)", (grant_id, project, target, access))

    def pop_project_grant(self, grant_id: str) -> dict[str, Any] | None:
        rows = self._q("SELECT * FROM project_grants WHERE grant_id=?", (grant_id,))
        self._q("DELETE FROM project_grants WHERE grant_id=?", (grant_id,))
        return dict(rows[0]) if rows else None

    def project_grants(self, project: str | None = None, target: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM project_grants WHERE 1=1", ()
        if project:
            sql, args = sql + " AND project=?", args + (project,)
        if target:
            sql, args = sql + " AND target=?", args + (target,)
        return [dict(r) for r in self._q(sql, args)]

    # --- misc ------------------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        rows = self._q("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set(self, key: str, value: Any) -> None:
        self._q("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))
