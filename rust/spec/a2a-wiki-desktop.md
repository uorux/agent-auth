# Spec: a2a threads and sessions, operator chat, wiki, desktop prompts, attention

Behavioral spec for the Rust port (PostgreSQL only). The Python is the
reference; `file:line` refers to the Python tree under `src/agent_auth/`
unless it says otherwise. Where this spec and the Python disagree, the Python
wins, except for the items in §12 (suspected bugs), which the port should
decide on deliberately.

Sources: `core/a2a.py`, `api/a2a_routes.py`, `provisioners/a2a.py`,
`api/chat_routes.py`, `core/wiki.py`, `api/wiki_routes.py`, `core/desktop.py`,
`core/attention.py`, plus `api/deps.py` (auth, liveness bookkeeping),
`core/scheduler.py`, `core/events.py`, `crypto.py:40` (`sign_body`),
`core/service.py:374-435,849-866,1071-1098` (delegation),
`api/agent_routes.py:52-71,230-242`, `api/admin_routes.py:62-73,195-331`.

---

## 1. Data model

### 1.1 Tables

All timestamps are `timestamptz`, UTC. Python's `TZDateTime` refuses naive
datetimes on write (`models.py:40-56`). JSON output uses Python
`datetime.isoformat()`, e.g. `2026-10-25T12:34:56.123456+00:00`. The events
cursor is round-tripped by clients (§3.10), so the port's output must parse
back as an `after=` value, and a `+` in a query string must be URL-encoded
(an unencoded `+` decodes to a space and fails to parse with a 422).

**agents** (fields this subsystem uses; `models.py:101-153`)

| column | type | notes |
|---|---|---|
| id | varchar(36) PK | uuid4 string |
| name | varchar(128) unique | `^[a-zA-Z0-9._-]+$` at create/rename; `operator` is reserved (§5) |
| description | text | |
| kind | varchar(16) | `service` (default) \| `ephemeral` \| `operator` (only the operator row; §5) |
| disabled | bool | |
| webhook_url | varchar(512) null | service agents only, admin-set |
| webhook_secret | varchar(64) null | plaintext HMAC key; `secrets.token_urlsafe(32)` (43 chars) |
| last_seen_at | timestamptz null | any authenticated call (throttled, §3.12) |
| last_listen_at | timestamptz null | only the inbound a2a surfaces (§3.12) |
| runtime, project, host | varchar null | `project` drives wiki write rights (§7) |
| placement | varchar(16) | |

**agent_sessions** (`models.py:156-175`)

| column | type | notes |
|---|---|---|
| id | varchar(36) PK | uuid4; this is the value of the `X-Agent-Session` header |
| agent_id | FK agents | |
| name | varchar(160) | `"<label>-<4 hex>"`; unique per agent (`uq_agent_sessions_agent_name`) |
| created_at | timestamptz | |
| last_seen_at | timestamptz | default now |
| closed_at | timestamptz null | |
| close_reason | varchar(32) null | `idle` \| `closed` (`core/states.py:82-83`) |

Index `ix_agent_sessions_open (agent_id, closed_at)`.

**a2a_threads** (`models.py:178-217`)

| column | type | notes |
|---|---|---|
| id | varchar(36) PK | uuid4 |
| initiator_agent_id | FK agents, indexed | |
| initiator_session_id | FK agent_sessions null | the opener's session if it sent `X-Agent-Session` |
| responder_agent_id | FK agents, indexed | |
| responder_session_id | FK agent_sessions null | set when the responder accepts or first replies *with* a session |
| topic | varchar(256) null | |
| grant_id | FK grants null | the initiator's a2a grant; NULL only on operator threads |
| state | varchar(16), indexed | `pending_open` \| `open` \| `closed` |
| created_at | timestamptz | |
| accepted_at | timestamptz null | |
| closed_at | timestamptz null | |
| last_activity_at | timestamptz, indexed | |
| last_seq | int | 1 after the open (the opening message is seq 1) |
| closed_by | FK agents null | the agent that closed, or NULL for system closes |
| close_reason | varchar(32) null | `rejected`, `closed`, `open_timeout`, `idle_timeout`, `peer_gone`, `grant_revoked` (`core/states.py:67-80`) |
| close_note | text null | reject/close reason text, or `contained` |

**a2a_messages** (`models.py:361-384`)

| column | type | notes |
|---|---|---|
| id | varchar(36) PK | uuid4 |
| thread_id | FK a2a_threads null, indexed | NULL = legacy pre-thread rows: never returned by any API |
| seq | int null | unique with thread_id (`ix_a2a_messages_thread_seq`) |
| sender_agent_id | FK agents | |
| sender_session_id | FK agent_sessions null | |
| recipient_agent_id | FK agents | |
| grant_id | FK grants null | the thread's grant, for both directions |
| payload | json | a JSON **object**, stored and returned verbatim |
| created_at | timestamptz | |

Delegation columns on **access_requests** and **grants**:
`delegation_thread_id` (FK a2a_threads null) and `delegator_agent_id` (FK
agents null) (`models.py:232-239,300-307`).

### 1.2 In-memory state (single process)

The Python keeps all of this in process memory and loses it on restart. The
port may keep it in memory too, but should do so deliberately:

- `KeyedEvents` (`core/events.py`): wake-ups for long polls, keyed by agent id
  or session id. `notify(key)` sets the current event and replaces it with a
  fresh one. Every waiter also re-reads the DB at a fixed interval (2 s for
  agents, 5 s for the panel), so a missed notify only adds latency. For more
  than one process, use PG `LISTEN/NOTIFY`.
- Desktop: `dnd_until`, `_presence`, `_offers`, `_prompts`, per-host locks,
  rate deques, deny deques, `_paused_until` (`core/desktop.py:104-114`).
- Attention: per-agent send-time deques (`core/attention.py:28`).
- Wiki: the page cache, `_loaded_at`, and the `_changes` cache keyed by blob
  sha (`core/wiki.py:114-119`).

### 1.3 The wiki is NOT on disk

The wiki lives in a GitHub repo (`policy.wiki.repo`, branch
`policy.wiki.branch`, default `main`). The broker reads and writes it through
the GitHub REST API as its GitHub App, with no clone (§7.6). Pages are the
repo's `*.md` blobs whose paths pass `check_path` (§7.1). Other files, and
`.md` files with non-conforming paths (for example `.github/notes.md`), are
invisible.

### 1.4 Config

Environment settings (`config.py:67-82`; pydantic-settings, field name
upper-cased, no prefix):

| setting | default | meaning |
|---|---|---|
| `A2A_RELAY_ENABLED` | true | false → every `/v1/a2a/*` and `/admin/chat/*` route returns 404 `a2a is disabled on this broker`. `/v1/sessions*` is not gated. |
| `WEBHOOK_SIGNING_SECRET` | "" | fallback HMAC key for pings |
| `A2A_OPEN_TIMEOUT_SECS` | 600 | `pending_open` older than this (by `created_at`) → `closed/open_timeout` |
| `A2A_THREAD_IDLE_TIMEOUT_SECS` | 3600 | `open` with `last_activity_at` older than this → `closed/idle_timeout` |
| `SESSION_IDLE_TIMEOUT_SECS` | 900 | open session with `last_seen_at` older than this → closed `idle`; its threads → `peer_gone` |
| `LIVENESS_THRESHOLD_SECS` | 120 | `peer_alive` window |
| `A2A_LISTEN_THRESHOLD_SECS` | 300 | `reachable` window on `last_listen_at` |

Hard-coded constants: scheduler interval 30 s (`core/scheduler.py:28`); agent
long-poll cap 300 s (`api/a2a_routes.py:30`); panel long-poll cap 25 s
(`api/chat_routes.py:29`); last-seen/last-listen write throttle 20 s
(`api/deps.py:23`); webhook timeout 5 s (`core/a2a.py:33`); payload cap
16 KiB (`schemas.py:114`).

Policy sections: `wiki:` (`policy/schema.py:335-357`) and `desktop:`
(`policy/schema.py:304-332`). Both are described in §7 and §8.

---

## 2. Authentication context (`api/deps.py`)

- `Authorization: Bearer <api key>` (or an OAuth access token from a web UI
  connector). Any of these gives **401**: a missing token (`missing bearer
  token`), a malformed key (`malformed API key`), an unknown key, a disabled
  agent, an agent of kind `operator`, or a wrong secret (all `invalid API
  key`; OAuth: `invalid or expired access token`).
- `X-Agent-Session: <session id>` is optional. The session must exist, belong
  to the agent and not be closed, otherwise **401** `unknown or closed
  session`. The MCP client matches on this exact string to re-mint a session
  (`mcp_server.py:135`), so keep it verbatim.
- On every authenticated request, `agent.last_seen_at` is set to now, and so
  is the session's `last_seen_at` if a session was sent. Each is written only
  when the stored value is NULL or more than 20 s old (`deps.py:52-56,104-117`).

`Caller = (agent, session | None)`.

---

## 3. a2a: threads and sessions

### 3.1 Sessions

**POST /v1/sessions** `{label}`. `label` is 1-64 characters matching
`^[a-zA-Z0-9._-]+$`, otherwise 422. Any agent kind may call it.
`name = f"{label}-{secrets.token_hex(2)}"`; on a clash with one of the
agent's existing session names the broker tries again, at most 5 times, then
returns **500** `could not allocate a session name` (`a2a_routes.py:47-70`).
Response: `{session_id, name, created_at}`.

**POST /v1/sessions/close** (the session is the one in the header). Without
the header: **400** `no X-Agent-Session header`. Otherwise `end_session`
(`a2a.py:379-409`) sets `closed_at=now, close_reason="closed"` (if not
already closed) and then closes every non-closed thread with
`initiator_session_id == sid OR responder_session_id == sid`:
`close_reason=peer_gone`, `closed_by=agent.id`. Wakes and pings go to every
participant except the closing agent (excluded by **agent id**). Response:
`{"ok": true, "threads_closed": n}`. (The 404 `unknown session` inside
`end_session` cannot be reached over HTTP, because auth already rejected
unknown or closed sessions.)

A closed session never authenticates again (401, as in §2).

### 3.2 Reachability (pure function, `a2a.py:55-94`)

`reachability(agent, listen_threshold, now)` returns:
`{name, kind, last_seen_at (iso|null), last_listen_at (iso|null),
has_webhook, addressable, reachable, why}`.

1. `kind != "service"` (ephemeral **or operator**): addressable=false,
   reachable=false, why=`ephemeral`.
2. else if `webhook_url` is set: addressable=true, reachable=true,
   why=`webhook`.
3. else listening = `last_listen_at != null && now - last_listen_at <=
   threshold` (inclusive). addressable=true, reachable=listening,
   why=`polling` if listening, otherwise `idle`.

`unreachable_detail(reach)` (`a2a.py:97-111`). The strings are verbatim and
`{name!r}` is Python repr, i.e. `'name'`:
- ephemeral: `'X' is ephemeral (initiate-only) and cannot receive threads; it reaches out to you, not the other way around`
- otherwise: `'X' is registered but not listening for threads (no webhook, last polled <last_listen_at iso or "never">); opening one now would sit unanswered until it times out. Pick a peer that reports reachable, or retry once it is back — list_capabilities and the a2a check both report peer reachability.`

The same function serves the catalog (`api/catalog.py:182-211`; peers
exclude self, disabled agents, non-service agents and zone-apart agents, and
are sorted reachable first, then by name), `/v1/a2a/check`,
`/admin/chat/peers`, and `open_thread`.

### 3.3 Grant matching (`provisioners/a2a.py:62-98`)

`check_grant(sender_agent_id, recipient_name, topic, any_topic=False)` scans
grants with `platform=a2a`, `agent_id=sender`, `resource=recipient_name`,
`status=active` and `expires_at > now` (strict), in DB order. For each one,
`pattern = scope.get("topic", "*")`:
- `any_topic`: return the first grant found.
- `topic is None`: matches only `pattern == "*"` (unscoped), so omitting the
  topic never widens a topic-scoped grant.
- otherwise `fnmatch(topic, pattern)`. This is Python fnmatch: `*`, `?`,
  `[seq]` and `[!seq]`, case-sensitive on POSIX, and `*` matches `/`.

Request-time validation for a2a grants (`provisioners/a2a.py:32-47`):
capability must be `talk` (`a2a capability must be 'talk'`); the target must
exist and not be disabled (`unknown target agent 'X'`); it must not be
yourself (`agent cannot request a2a access to itself`); and it must be a
service agent (`a2a targets must be service agents; 'X' is ephemeral and can
only initiate threads itself`). Zones turn a zone-apart target into `unknown
target agent 'X'` before any rule is read (`core/zones.py:107-111`). Grants
are agent-level: every session of the agent shares them.

### 3.4 Thread state machine

```
            open_thread (msg seq 1)
                   │
                   ▼
            ┌─pending_open─┐
 accept /   │              │ reject ──────────────► closed(rejected, closed_by=responder, note=reason)
 responder  │              │ close (either side) ──► closed(closed, closed_by=closer, note=reason)
 reply      │              │ sweep: created_at < now-open_timeout ─► closed(open_timeout)
            ▼              │ session death / end_session ─► closed(peer_gone)
           open            │ backing grant dead ─► closed(grant_revoked)
            │              │ responder demoted / containment ─► closed(peer_gone | closed[note=contained])
            ├─ close (either side) ─────────────► closed(closed)
            ├─ sweep: last_activity_at < now-idle_timeout ─► closed(idle_timeout)
            ├─ bound session idles out / is closed ─► closed(peer_gone)
            ├─ backing grant revoked/expired (send-time or sweep) ─► closed(grant_revoked)
            ├─ responder reclassified ephemeral ─► closed(peer_gone)
            └─ either side contained ─► closed(closed, note="contained")
closed: terminal. Nothing transitions out of it.
```

`_close` (`a2a.py:766-781`) sets `state=closed`, `closed_at=now`,
`close_reason`, `closed_by`, `close_note` (overwritten, NULL if not given)
and `last_activity_at=now`. Setting `last_activity_at` is what makes events
cursors see the close.

Every close path (`reject`, `close`, `end_session`, `orphan_inbound_threads`,
`close_all_for`, sweep, and the dead-grant branch of send) then:
- wakes `_closure_notices`: for each participant not excluded,
  `side_session_id or side_agent_id` (`a2a.py:783-791`);
- pings `_closure_pings`: one `a2a_thread_closed` ping per non-excluded
  participant (§4).

Exclusion happens only for agent-initiated closes (`reject`, `close`,
`end_session`), and only the acting agent is excluded.

Notable non-transitions:
- `pending_open` threads are never idle-swept, only open-timed-out.
- Operator threads (`grant_id NULL`) are never `grant_revoked`
  (`test_chat.py:100`).
- Disabling an agent does not close its threads directly (§12, B7).

### 3.5 Access check `_own_thread` (`a2a.py:716-738`). Every per-thread operation uses it.

1. The thread does not exist, or the caller agent is neither initiator nor
   responder: **404** `unknown thread`. This applies to existence too: a
   non-participant cannot tell a thread exists.
2. If the caller is the **initiator** (checked first): `_require_session`,
   i.e. an ephemeral caller with no session gets **400** `ephemeral agents
   must open a session before using a2a (POST /v1/sessions, then send
   X-Agent-Session)`. `bound = initiator_session_id`.
3. Otherwise (responder): `bound = responder_session_id`. No session is
   required.
4. If `bound` is set and the caller's session is missing or different:
   **403** `thread is bound to a different session of this agent`.

So an unbound side may be used by any session of that agent, or by none. A
bound side may be used only by its own session.

### 3.6 Open: **POST /v1/a2a/threads** `{to, topic?, payload}` (`a2a.py:137-215`)

Body validation (422, `schemas.py:138-153`): `to` is 1-128 characters;
`topic` is at most 256 characters and must not match `[\x00-\x1f\x7f]`
(`topic must not contain control characters or newlines`); `payload` is a
JSON object (default `{}`) whose `len(json.dumps(payload)) <= 16384`. That
length is measured on Python's default `json.dumps` output: `", "` and `": "`
separators, and `ensure_ascii`, so a non-ASCII character counts as 6 (or 12
for an astral one). Error: `payload exceeds 16384 bytes`.

Checks, in this order (the order is observable):
1. Responder is looked up by exact name. If missing or disabled: **404**
   `unknown agent 'X'`.
2. Containment, `_refuse_if_held(caller, responder)`: skipped if either one
   is kind `operator`. Otherwise, for the caller first and then the
   responder, if `holding()` returns an entry: **403** `<name> is contained
   (<entry id>): no a2a while it is held`.
3. Not addressable (responder kind != service): **403** with the ephemeral
   detail. This happens before the permission check (`test_a2a.py:788`).
4. `_require_session(caller)` → 400 (as in §3.5).
5. Permission: an operator caller needs no grant. Anyone else needs
   `check_grant(caller.id, responder.name, topic)`, else **403**:
   `no active a2a grant to talk to 'X'; request one via POST /v1/requests {"platform": "a2a", "capability": "talk", "resource": "X"} — topic-scoped grants also require an explicit matching topic on the open`.
6. Not reachable: **409** with the idle detail. "Permission first, liveness
   last."
7. Insert the thread: `state=pending_open`, `last_activity_at=now`,
   `last_seq=1`, `initiator_session_id=caller.session?.id`,
   `grant_id=grant?.id`. Insert message seq 1 with
   `sender_session_id=caller.session?.id`, `recipient=responder`, the
   thread's `grant_id` and the payload.
8. Commit, then `notify(responder.id)` (always the agent id), then the
   `a2a_thread_open` ping to the responder.

Response: `thread_out` from the initiator's view (§3.11).

There is no zone check here and no `responder != caller` check (§12, B5).

### 3.7 Send: **POST /v1/a2a/threads/{id}/messages** `{payload}` (`a2a.py:217-298`)

Payload validated as in §3.6. Order:
1. `_own_thread`.
2. Thread closed: **409** `thread is closed (<close_reason or "closed">)`.
3. `_refuse_if_held(caller, peer)` → 403.
4. If `thread.grant_id` is set and that grant is missing, not `active`, or
   `expires_at <= now`: close the thread with `grant_revoked` and
   `closed_by=NULL` (no exclusion), **commit**, wake both sides, ping both
   sides, then **403** `backing grant is no longer active; thread closed`. No
   message is stored. The close is committed even though the call errors.
5. Initiator on a `pending_open` thread: **409** `thread is pending_open:
   your opening message already rides the open; wait for the responder to
   accept or reply`.
6. Responder on a `pending_open` thread: **implicit accept**. Sets
   `state=open` and `accepted_at=now`, and if the caller has a session,
   `responder_session_id=session.id`. This claims the thread.
7. `seq = atomic(UPDATE a2a_threads SET last_seq=last_seq+1,
   last_activity_at=now WHERE id=? RETURNING last_seq)`. Insert the message
   with `recipient` = the other side.
8. Commit. Wake the peer's key: if the sender is the initiator, wake
   `responder_session_id or responder_agent_id`, otherwise
   `initiator_session_id or initiator_agent_id`. Then send the
   `a2a_message` ping to the recipient.

Response: `{"message_id", "seq", "thread_state"}`, where `thread_state` is
the state after this send (`open`).

**Port requirement:** load the thread with `SELECT … FOR UPDATE` for steps
2-7 (§12, B4).

### 3.8 Accept / reject / close / get

**POST …/{id}/accept** (`a2a.py:300-318`, route `a2a_routes.py:123-133`):
`_own_thread` → caller not the responder: **403** `only the thread responder
may do this` → state not pending: **409** `thread is not pending_open (state
<state>)` → `_refuse_if_held(caller, initiator)` → set `state=open`,
`accepted_at=now`, `last_activity_at=now`, and with a session,
`responder_session_id`. Commit, then wake the initiator's key. Accept sends
**no webhook ping**. After success the route calls `mark_listening` (§3.12).
Response: `thread_out`.

**POST …/{id}/reject** `{reason?}` (`reason` at most 2000 characters; the
body is required, `{}` is fine): `_own_thread` → responder only (403) →
pending only (409) → close `rejected`, `closed_by=caller`, `close_note=reason`.
Wake and ping the initiator only. No containment check. Response:
`thread_out`.

**POST …/{id}/close** `{reason?}`: `_own_thread` → not closed (409) → close
`closed`, `closed_by=caller`, note. Allowed from either side and in
`pending_open`. No containment check. Response: `thread_out`.

**GET /v1/a2a/threads/{id}**: `_own_thread` → `thread_out`. Closed threads
stay readable.

### 3.9 List and read

**GET /v1/a2a/threads?state=&role=** (`a2a.py:420-450`): `_require_session`
first (ephemeral without a session → 400). Predicates:
- initiator side: `initiator_agent_id = me` [AND `initiator_session_id = my
  session` if the caller sent a session].
- responder side: `responder_agent_id = me` [AND `responder_session_id = my
  session` if the caller sent a session].
- `role=initiator` → initiator side only; `role=responder` → responder side
  only; anything else → either side.
- `state` filters on exact equality (any string).
- `ORDER BY last_activity_at DESC LIMIT 200`.

A **sessionless** caller (service agents only, since ephemeral callers got a
400) therefore sees every thread of the agent, including threads bound to its
sessions (metadata only; §12, B8).

**GET /v1/a2a/threads/{id}/messages?after_seq=0&wait=0**
(`a2a_routes.py:188-224`, `a2a.py:452-481`):
- `wait = clamp_wait(wait, 0, 300)`: NaN → 0, ±inf clamped
  (`deps.py:26-37`).
- First read: `_own_thread`, then messages with `thread_id=id AND seq >
  after_seq ORDER BY seq`, joined to the sender's agent name. The response
  is `{"thread": thread_out, "messages": [{message_id, seq, from:
  sender_name, payload, created_at}]}`.
- Return immediately if there are messages, or `wait <= 0`, or the thread is
  `closed`.
- Otherwise loop until the deadline: wait on `wake_key` (= the caller's
  session id if it sent one, else its agent id) for at most
  `min(remaining, 2.0)` s; `_touch_caller` (write `agent.last_seen_at` and
  the open session's `last_seen_at`, **unthrottled**, `a2a_routes.py:315-326`);
  `mark_listening` (§12, B2); re-read (any A2AError aborts with its status).
  Return when there are messages or the state differs from the first read's
  state. At the deadline, return the last read.
- Payloads must come back byte-for-byte as stored. FastAPI's encoder would
  drop keys starting with `_sa`, so Python returns a raw `JSONResponse`
  (`a2a_routes.py:180-185`, `test_a2a.py:1100`). The Rust port just
  serializes the stored JSON.

### 3.10 Events feed: **GET /v1/a2a/events?wait=0&after=<iso>** (`a2a_routes.py:227-259`, `a2a.py:483-536`)

- A naive `after` is treated as UTC. `wait` is clamped to [0, 300].
- `mark_listening(caller)` runs once, before the first snapshot. This call is
  the thing that makes an agent reachable.
- Snapshot (`_require_session` first; an ephemeral caller without a session
  gets 400):
  - `pending_opens`: **only for sessionless callers**, every thread with
    `responder_agent_id = me AND state = pending_open`. No cursor filter and
    no ORDER BY (the port should order by `created_at`). Pending opens keep
    appearing on every poll until they are resolved (`test_a2a.py:589`).
  - `activity`: the side predicates of §3.9 (session-filtered when a session
    is sent). With `after`: `last_activity_at > after` (strict). Without
    `after`: `state != closed`. Then `ORDER BY last_activity_at ASC LIMIT
    200`.
  - `cursor`: the maximum `last_activity_at` among the returned activity, or
    `after` echoed back if there is none (null if both are absent). The
    output uses isoformat.
- Return at once if `pending_opens` or `activity` is non-empty. Otherwise
  wait on `wake_key`, at most `min(remaining, 2.0)` s per round, calling
  `_touch_caller` after each wait, and re-snapshot until the deadline. At the
  deadline, return the last (empty) snapshot.
- Activity items are `thread_out` objects. The feed carries **no messages**;
  callers read them with the cursor read.

### 3.11 `thread_out` (`a2a.py:823-860`)

```
{thread_id, peer (peer agent name|null), role ("initiator"|"responder"),
 topic, state, close_reason, close_note, grant_id, last_seq,
 created_at, accepted_at|null, closed_at|null, last_activity_at,
 peer_last_seen_at|null, peer_alive}
```

`role` is `initiator` iff the viewer's agent id is the initiator. Peer
liveness: if the peer's side is session-bound and that session row exists,
use the **session's** `last_seen_at` (even if the session is closed);
otherwise use the peer agent's `last_seen_at`. `peer_alive = last_seen !=
null && now - last_seen <= LIVENESS_THRESHOLD_SECS`.

### 3.12 Liveness bookkeeping

- `last_seen_at` (agent and session): every authenticated request (throttled
  to 20 s), plus `_touch_caller` on every round of a long-poll loop
  (unthrottled).
- `last_listen_at` (agent only; `mark_listening`, `deps.py:120-145`, throttled
  to 20 s): the events poll (once per request), a successful accept, and, in
  Python, every round of the message long-poll (§12, B2).
  `set-kind → ephemeral` clears it.

### 3.13 Check: **GET /v1/a2a/check?peer=&direction=out&topic=** (`a2a_routes.py:262-312`)

No session requirement. The peer is looked up by name; if it is missing, or
`Zones.apart(caller, peer)`, the response is `{"allowed": false, "reason":
"unknown agent 'X'"}` with no `peer`. Disabled peers are **not** filtered
(§12, B6). `peer` is `PeerEntry{description|null, ...reachability}`.
- `direction=out`: `check_grant(caller.id, peer.name, topic,
  any_topic=(topic is None))`.
- `direction=in`: `check_grant(peer.id, caller.name, topic, any_topic=(topic
  is None))`.
- anything else: **400** `direction must be 'out' or 'in'`.

No grant: `{allowed: false, reason: "no active a2a grant", peer}`. Grant:
`{allowed: true, grant_id, expires_at, reason, peer}`, where `reason` is
`unreachable_detail` only when `direction=out` and the peer is not reachable,
otherwise null.

### 3.14 Scheduler and sweep

`ExpiryScheduler.run` (`core/scheduler.py:39-81`) runs every 30 s. The first
tick runs right after boot and is the catch-up pass. Each step has its own
try/except:
1. reap stale provisioning (0 s threshold on the boot tick, 15 min after);
2. `expire_due_grants`;
3. **a2a sweep** (below);
4. `revoke_delegated_for_closed_threads` (§6);
5. sandbox lease sweep.

`A2AThreadService.sweep()` (`a2a.py:595-692`) runs as one transaction with
`now` fixed at its start, in this order:
1. Sessions with `closed_at IS NULL AND last_seen_at < now -
   SESSION_IDLE_TIMEOUT_SECS` get `closed_at=now, close_reason="idle"`. Every
   non-closed thread with `initiator_session_id` or `responder_session_id` in
   those sessions → `peer_gone`.
2. `state=pending_open AND created_at < now - A2A_OPEN_TIMEOUT_SECS` →
   `open_timeout`.
3. `state=open AND last_activity_at < now - A2A_THREAD_IDLE_TIMEOUT_SECS` →
   `idle_timeout`.
4. Non-closed threads joined to a grant where `status != active OR
   expires_at <= now` → `grant_revoked`. The inner join excludes operator
   threads.

All of these have `closed_by=NULL` and no exclusion. Threads closed by an
earlier step are not re-selected (the ORM flushes before each query; in the
port, either filter on `state != closed` after updates or use one statement
per step). After commit: wake everyone and deliver the pings. Returns
`{sessions_idled, open_timeout, idle_timeout, grant_revoked}`.
`sessions_idled` counts sessions; threads closed `peer_gone` are not
counted.

### 3.15 Admin-triggered closes

- `orphan_inbound_threads(agent_id)` (`a2a.py:541-568`): every non-closed
  thread where the agent is the **responder** → `peer_gone`, `closed_by=NULL`.
  Called from `set-kind` demotion to ephemeral (`admin_routes.py:240-281`),
  which also clears `webhook_url`, `webhook_secret` and `last_listen_at`, and
  then revokes every active a2a grant whose `resource` is that agent's name
  (reason `target 'X' reclassified ephemeral`, by `admin`). It is also called
  from `core/hostexec.py:617`.
- `close_all_for(agent_id, note)` (`a2a.py:570-591`): every non-closed thread
  on either side → `closed`, `closed_by=NULL`, `close_note=note`. Containment
  calls it with `note="contained"` (`core/lockdown.py:174-176`).

### 3.16 Wake routing summary

| event | key(s) notified |
|---|---|
| open | `responder.agent_id` |
| send | the peer side's `session_id or agent_id` |
| accept | the initiator side's `session_id or agent_id` |
| any close | each non-excluded side's `session_id or agent_id` |

Waiters wait on `caller.session_id or caller.agent_id`. If the waiter's
session does not match the key the sender woke (for example an unbound side
polling with a session header), it is not woken and sees the change on its
next 2 s re-read. The port may notify both the agent key and the session key.

---

## 4. Webhook pings

### 4.1 Configuration (admin only)

- `webhook_url`: accepted only if `urlparse(v).scheme in {http, https}` and
  the netloc is non-empty, otherwise 422 `webhook_url must be an http(s) URL
  with a host`. At most 512 characters (`schemas.py:198-206`). There is no
  private-IP/SSRF filtering, because only the admin sets it.
- Create (`POST /admin/agents` with `webhook_url`), `POST
  /admin/agents/{id}/set-webhook` (null clears the URL and the secret) and
  `POST /admin/agents/{id}/rotate-webhook-secret` each mint
  `webhook_secret = token_urlsafe(32)` and return it **once**, in that
  response. `/v1/me`, `/admin/agents` and every other read omit it
  (`test_a2a.py:1052-1063`). The operator row refuses all of these with 409
  (`admin_routes.py:62-67`).

### 4.2 Who gets pinged (`a2a.py:864-877`)

The target must be a `kind == "service"` agent with a `webhook_url`. The
secret is `agent.webhook_secret`, or else `WEBHOOK_SIGNING_SECRET`. If both
are empty, the ping is **skipped** (a warning is logged) and never sent
unsigned (`test_a2a.py:988`). The ping's ingredients (url, secret, event) are
captured inside the transaction and delivered after commit.

### 4.3 Payloads (JSON object; key order as listed)

- `{"type": "a2a_thread_open", "thread_id", "from": <initiator name>, "topic", "seq": 1}`, sent to the responder on open.
- `{"type": "a2a_message", "thread_id", "message_id", "from": <sender name>, "topic", "seq"}`, sent to the recipient on send.
- `{"type": "a2a_thread_closed", "thread_id", "topic", "close_reason"}`, sent to each non-excluded participant on close.

Pings are notify-only and **never carry the message payload**
(`test_a2a.py:943`). Accept sends no ping.

### 4.4 Wire

`raw = json.dumps(event).encode()` (Python default separators; the exact
spacing does not matter because the signature covers the bytes actually
sent). The request is `POST <webhook_url>` with headers
`Content-Type: application/json` and
`X-Agent-Auth-Signature: sha256=<lowercase hex HMAC-SHA256(key=secret UTF-8 bytes, msg=raw)>`
(`crypto.py:40-44`). Receivers verify with a constant-time compare.

Delivery: a fresh HTTP client per ping, 5 s total timeout, redirects not
followed, response status ignored, **no retries**. Pings are delivered
sequentially and awaited inline in the API request (or sweep) that caused
them. A transport error (`httpx.HTTPError`) is logged and swallowed, and the
API call still succeeds (`test_a2a.py:948-956`). The cursor read stays
authoritative. Port: do not let ping failures fail the request; consider
delivering in a background task (§12, B9).

The same `sign_body` contract is used by `agent-auth a2a serve` (the
client-side dispatcher, `cli.py:249`), which can also emit it under
`X-Hub-Signature-256`.

---

## 5. Operator chat from the admin panel (`api/chat_routes.py`)

### 5.1 The operator row

`A2AThreadService.operator()` (`a2a.py:357-377`) returns the single agent
with `kind="operator"`, creating it on first use: `name="operator"`,
`description="the operator, writing from the admin panel"`,
`key_id=token_hex(8)`, `api_key_hash="!"*64` (matches no key). If another
agent is already named `operator`: **409** `an agent is already named
'operator'; rename it to chat from the panel`.

Protections:
- `get_caller` refuses kind `operator` (401) even when the key is valid
  (`test_chat.py:147`).
- Admin routes that would give the operator a key, name, kind, webhook or
  attributes return 409 `the operator's identity belongs to the admin
  panel's chat`.
- Creating an agent named `operator`, or renaming one to it, returns 409
  `'operator' is the admin panel's name for the operator`.
- Reachability puts the operator row in the `ephemeral` case, so it is never
  addressable.
- `holding()` never holds it, and `_refuse_if_held` is skipped when either
  side is the operator.
- `Zones.apart` is false whenever either side is the operator.

### 5.2 Routes (all need `require_admin`; `/admin/chat` prefix)

Admin auth is either the `ADMIN_TOKEN` bearer (`admin_user = "admin
token"`), or a UI session cookie on the panel host, limited to the allowlisted
routes (`core/webui.py:56-66` lists these six) and requiring the CSRF header
on non-GET requests (403 `missing or wrong CSRF token`). `admin_user` is then
the signed-in user. Every route except `/peers` calls `_operator()` first:
it creates or looks up the row (A2AError → its status), returns **409**
`the operator's identity is disabled` if disabled, and sets
`operator.last_seen_at = now` (unthrottled), so agents see their operator
peer as alive while the panel is open.

- **GET /peers**: every `kind=service AND NOT disabled` agent, ordered by
  name: `{...reachability, runtime, project, host, placement, description}`.
  No zone filter.
- **GET /threads?limit=100** (clamped to [1, 500]): threads with
  `initiator_agent_id = operator`, ordered by `last_activity_at DESC`. Each
  item is `{id, to, topic, state, close_reason, opened, last, last_seq,
  preview, last_from_operator}`. `preview` comes from the message with
  `seq == thread.last_seq`: its `text`, else `summary`, else `type`, else
  `""`, cut to 200 characters. `last_from_operator` is true iff that
  message's `sender_agent_id` is the operator.
- **POST /threads** `{to: 1..128, topic?: ≤256, text: 1..20000}`:
  `open_thread(operator, None, to, topic, {"type": "message", "text": text,
  "operator": admin_user})`. No grant is needed; every other open check of
  §3.6 applies (404, 403 ephemeral, 409 not listening). A log line records
  who opened it.
- **GET /threads/{id}?after_seq=0&wait=0** (wait clamped to [0, 25]): 404
  `unknown conversation` unless `thread.initiator_agent_id == operator.id`.
  Returns `{thread: thread_out(operator view), messages: [...], requests:
  [...]}`.
  - Each message is `{seq, at, from, type, text, status, summary, payload,
    operator}`. `text`, `status`, `summary` and `operator` are taken from the
    payload only when they are strings. `payload` is null when `text` is a
    string, otherwise the raw payload.
  - `requests` are the access requests with `delegation_thread_id == id`,
    ordered by `created_at`: `{id, platform, what, resource, status,
    source}`.
  - Long-poll: return if there are messages, the state differs from the first
    read, the first state was `closed`, or the deadline has passed. Otherwise
    wait on `operator.id` for at most `min(remaining, 5.0)` s and re-read.
- **POST /threads/{id}/messages** `{text: 1..20000}`: `send_message(operator,
  None, id, payload)`. The thread is looked up by `_own_thread`, so the
  operator must be a participant, which it always is as initiator. An
  operator thread has no grant, so step 4 of §3.7 is skipped.
- **POST /threads/{id}/close** `{reason?: ≤2000}`: `close(operator, None, id,
  reason)`.

Agents see operator threads as ordinary threads: `peer == "operator"` and
`from == "operator"`. By convention they answer with `{"type": "message",
"text": ...}` or `{"type": "result", "status", "summary"}`.

---

## 6. Delegation, as seen from a2a

A request body's `on_behalf_of_thread` (at most 36 characters) anchors the
request to a thread (`core/service.py:202-213,374-435`). On failure the
request is stored as `DENIED`, source `POLICY`, with reason
`"delegation: " + <one of>`:
- platform is a2a: `a2a access cannot be requested on behalf of another agent`
- thread missing, or caller not a participant: `unknown thread (you must be a participant of the thread you cite)`
- `state != open`: `thread is <state>; delegation requires an OPEN thread (the other side must have accepted)`
- caller is not the **responder**: `you opened this thread; only the responder may act on a thread's behalf (the delegator must be the side that asked)`
- `responder_session_id` is set and differs from the request's session (a
  sessionless request counts as different): `thread belongs to a different session of this agent`
- the initiator is missing or disabled: `delegator agent is disabled`

On success: `delegation_thread_id = thread.id` and `delegator_agent_id =
thread.initiator_agent_id`. The delegator is derived from the thread, never
taken from the client. A risk note is appended: `on behalf of <delegator>
(a2a thread topic <json.dumps(topic) or "(none)">)`. The containment check
runs before delegation resolution.

Lifecycle tied to the thread:
- At provision time (`service.py:849-866`): the thread must be `open` **and**
  its backing grant must exist, be active and be unexpired, otherwise
  `PROVISION_FAILED` with `… | provisioning failed: delegation thread is no
  longer open`. The grant's `expires_at` is
  `min(requested, backing.expires_at)`.
- Credential fetch (`agent_routes.py:230-242`): if the thread is missing or
  not `open`: **403** `delegation thread is closed; credential no longer
  issuable`.
- Scheduler step 4: every `active` grant whose delegation thread is `closed`
  is revoked with reason `delegation thread closed (<close_reason or
  'closed'>)` by `scheduler`. A `TransitionError` (raced) is ignored.

Operator threads have no backing grant, so delegated requests on them can
never provision (§12, B1).

---

## 7. Wiki (`core/wiki.py`, `api/wiki_routes.py`)

### 7.1 Paths (`check_path`, `wiki.py:92-102`)

- `len(path) <= 200` and `path.endswith(".md")`, else **400** `a page's path
  ends in .md and is at most 200 characters`.
- Split on `/`: at most 6 segments, each matching the full regex
  `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, else **400** `path '<path>': at most 6
  segments of letters, digits, dots, dashes and underscores, each starting
  with a letter or digit`.
- This rejects `..`, `.hidden`, an empty segment (`//`), a leading `/`,
  spaces, and paths deeper than 6 segments (`test_wiki.py:171-182`).
  `a..b.md` is allowed (it does not traverse, because paths are only ever
  API paths in GitHub).
- `page_project(path)`: `parts[1]` if `len(parts) >= 3 and parts[0] ==
  "projects"`, else None. So `projects/x.md` belongs to no project.

### 7.2 Write permission (`wiki.py:123-151`)

`_check_write(agent, path)`, in order:
1. Zones: if the agent is a member of any restricted zone whose `wiki` flag
   is false: **403** `you don't write the shared wiki`.
2. `is_editor`: any `wiki.editors` pattern matches the agent (a string is an
   fnmatch on the name; a mapping matches fields such as `{project:
   homelab}`). Editors may write anything.
3. The agent has no `project`: **403** `you have no project on record, so
   there is nowhere in the wiki you may write (the operator sets it:
   `agent-auth admin agent-set --project`)`.
4. `page_project(path) != agent.project`: **403** `you may write under
   projects/<project>/ only. For a page elsewhere, ask an agent of the
   project that owns it (shared pages: the homelab agents)`.

`writable(agent)` is used by list's `you_may_write`: `[]` if the zone rule
forbids, `["(every page)"]` for editors, `["projects/<p>/"]` if the agent has
a project, else `[]`.

Before any of this, the route checks containment for writes and deletes: a
held agent gets **403** `contained (<id>): no wiki writes while you are held`
(`wiki_routes.py:31-37`). Reads are never refused for containment or zones.

### 7.3 Routes (agent auth; `/v1/wiki`)

No wiki configured (`policy.wiki.repo` empty): **501** `this broker has no
wiki`. Unauthenticated: 401.

| route | body/query | result |
|---|---|---|
| `GET /v1/wiki?prefix=` | | `{repo, you_may_write, pages: [{path, title, bytes}]}`, sorted by path, filtered by `path.startswith(prefix)` (prefix not validated) |
| `GET /v1/wiki/page?path=` | | `check_path` (400) → 404 `no page '<p>' (wiki_list shows what exists)` → `{path, sha, project, last_change, content}` |
| `GET /v1/wiki/search?q=&limit=8` | | §7.4 |
| `PUT /v1/wiki/page` | `{path ≤300, content, summary 1..500, base_sha? ≤64}` | §7.5 |
| `POST /v1/wiki/delete` | `{path ≤300, summary 1..500, base_sha? ≤64}` | §7.5 |

`bytes` is `len(text.encode())` of the cached, UTF-8-decoded text (decoded
with `errors="replace"`). `title` (`wiki.py:68-75`) scans lines in order: the
first line starting with `#` gives the title (leading `#`s stripped, then
whitespace stripped, or the path if that leaves nothing); a non-blank,
non-heading line before any heading means the title is the path.
`last_change` is `{author, at, summary}` from the newest commit touching the
path, cached by **blob sha** (§12, B12), or null on error.

### 7.4 Search (`wiki.py:210-235`)

`terms = whitespace-split(lower(strip(q)))`. Empty: **400** `an empty
search`. A page matches iff **every** term is a substring of the lowercased
text, or of the lowercased `"<path> <title>"`. Score is
`Σ(text.count(t) + 5 * head.count(t))`. Sort by score descending, then path
ascending. `limit` is clamped to [1, 25]. Result: `{query, matches: <total
hit count>, results: [{path, title, project, lines}]}`, where `lines` holds
up to 3 lines of the page text that contain any term (case-insensitive),
each stripped and cut to 200 characters.

### 7.5 Write and delete (`wiki.py:239-304`)

Write, in order:
1. `check_path` (400), then `_check_write` (403).
2. `content.strip()` is empty: **400** `an empty page; to remove one, delete it`.
3. `len(content.encode("utf-8")) > max_page_bytes` (default 65536): **413**
   `a page is at most <n> bytes; split it into several`.
4. Secret patterns, checked against **content only**. A match gives **400**
   `this looks like it contains <what>. The wiki holds no credentials: say
   where one is kept, never its value`:
   - an agent-auth API key `\baa_[A-Za-z0-9]{4,}_[A-Za-z0-9_-]{16,}`
   - a GitHub token `\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`
   - a private key `-----BEGIN [A-Z ]*PRIVATE KEY-----`
   - a JWT `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
   - an API key `\b(?:sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b`
   Python `re` `\b` is Unicode-aware, so use the Unicode-aware word boundary
   in Rust `regex` (its default).
5. Force-reload the snapshot (§7.6), then get `current` (by path).
6. `_check_base`:
   - current absent and `base_sha` given: **409** `'<p>' no longer exists; leave base_sha out to create it`.
   - current present and `base_sha != current.sha` (including a missing
     `base_sha`): **409** `'<p>' exists: read it and pass its `sha` as
     base_sha` when `base_sha` is missing, or `'<p>' exists and has changed
     since you read it: read it and pass its `sha` as base_sha` when it is
     stale.
7. If `current.text == content`, return `{path, sha, unchanged: true}` with
   no commit.
8. Commit message (`_message`): `summary` with whitespace collapsed
   (`" ".join(summary.split())`) and cut to 200 characters. If that is
   empty: **400** `say in one line what changed (summary)`. Then
   `"<line>\n\nAgent: <name>[ (project <p>)]"`.
9. `backend.put(path, bytes, message, author=agent.name, sha=current?.sha)`.
   A conflict gives **409** `'<p>' changed while you were writing; read it
   again`. Update the cache entry. Return `{path, sha: <new blob sha>,
   created: current is None}`.

Delete: `check_path`, `_check_write`, force reload, absent page → **404**
`no page '<p>'`, `_check_base`, commit with `_message`, `backend.delete`
(conflict → **409** `'<p>' changed while you were deleting it; read it
again`), drop it from the cache, and return `{path, deleted: true}`.

### 7.6 Cache and GitHub backend

`_load(force)`, under an async mutex: if not forced and the last load is
younger than `refresh_secs` (default 30), use the cache. Otherwise call
`snapshot(known = {sha: bytes})`. A `WikiError` propagates. Any other error
keeps the stale cache if one exists, or else gives **502** `the wiki's repo
could not be read; try again later` (`test_wiki.py:218-231`).

`GithubWikiBackend` (`wiki.py:318-409`). The token is
`github.own_token(repo, {"contents": "write", "metadata": "read"})` (an App
installation token, cached until 5 min before expiry, never given to
agents). The header is `Authorization: token <t>`.
- snapshot: `GET /repos/{repo}/git/trees/{branch}?recursive=1` with a 30 s
  timeout. 404 or 409 → empty wiki. Other errors raise. Take `type == "blob"`
  entries whose path ends in `.md` and passes `check_path`. Fetch each blob
  sha not already in `known` with `GET /repos/{repo}/git/blobs/{sha}` and
  base64-decode it. `truncated` is ignored (§12, B15).
- put: `PUT /repos/{repo}/contents/{path}` with `{message, content: b64,
  branch, author: {name, email: "<name>@agents.invalid"}, sha?}`. 409 or 422
  → conflict. Any status other than 200/201 → **502** `the wiki's repo
  refused the write (<status>)`. Returns `json.content.sha`.
- delete: `DELETE /repos/{repo}/contents/{path}` with a JSON body
  `{message, sha, branch, author}`. 409 or 422 → conflict. Any status other
  than 200 → **502** `the wiki's repo refused the delete (<status>)`.
- last_change: `GET /repos/{repo}/commits?path=&sha=<branch>&per_page=1`
  with a 15 s timeout. A non-200 status or an empty list gives None.
  Otherwise `{author: commit.author.name, at: commit.author.date, summary:
  first line of commit.message}`.

Policy validation: `wiki.repo` must be empty or match
`[A-Za-z0-9._-]+/[A-Za-z0-9._-]+` (`owner/name`). Editors' `project` values
must be listed under `projects` (`test_wiki.py:234-242`). Unknown keys are
forbidden.

---

## 8. Desktop prompts (`core/desktop.py`)

These run only when `policy.desktop.enabled` is true and the daemon hub is
on. Config: `enabled`, `agents` (patterns), `platforms` (empty means all),
`sensitive` (default false), `timeout` (default `90s`), `per_agent_per_hour`
(6), `per_hour` (20), `deny_cooldown` (`10m`), `mute` (`1h`). Constants:
`BURST=2` within `BURST_WINDOW_SECS=120`, `QUEUE_SECS=30`,
`DENIES_TO_MUTE=3`.

### 8.1 Wiring

`FanoutNotifier` (`desktop.py:381-407`):
- `surface(request, agent)`: send to Discord first, then
  `desktop.offer(...)` (fire-and-forget).
- `update_outcome`: `desktop.cancel(request.id)`, then Discord.
- `watch_alert`: Discord, then `desktop.alert("agent-auth: look at <host>",
  "<shlex argv>[:200] — <text>")`.
- Everything else delegates to Discord.

### 8.2 Presence (`desktop.py:120-139`)

A host is present iff its `Daemon(role="host")` row exists, the hub holds a
live connection for it, and either:
- its last heartbeat `last_status.desktop.present === true`; or
- the newest `presence` message from that host (`{"type": "presence",
  "present": bool}`) has a receipt time `>= row.last_seen_at`, in which case
  that message's value overrides the heartbeat.

The result is sorted by host name.

### 8.3 Eligibility, `refusal(request, agent)` (`desktop.py:151-179`)

The first match wins. These strings are internal (log/test only):
`desktop prompts are off`; `agent not listed under desktop.agents`;
`platform not listed under desktop.platforms`; `never asked on a desktop`
(`authority.human_only(platform, authority)`, i.e. shells); `sensitive
(desktop.sensitive is off)` (only for non-hostexec requests, when
`!config.sensitive && engine.is_sensitive(request)`); `do-not-disturb`
(`dnd_until > now`); `this agent's desktop prompts are paused`; `desktop
rate-limited (agent)` (the agent has ≥ `per_agent_per_hour` prompts in the
last hour, or ≥ 2 in the last 120 s); `desktop rate-limited` (≥ `per_hour`
prompts overall in the last hour).

`offer()` runs `refusal` synchronously and, if it passes, spawns `_ask`.

### 8.4 `_ask(request_id)` (`desktop.py:209-267`)

1. Reload the request. Stop unless it is `AWAITING_HUMAN`. Load the agent,
   the delegator, and (for hostexec) the target `Daemon` row.
2. `hosts = present_hosts()`.
3. Hostexec whose resource is one of the present hosts (and hostexec is
   configured): `spec = hostexec.final_spec(request, agent,
   HumanDecision(approve=True, decided_by="desktop"))`; on any exception,
   stop silently. Then `hosts = [resource]` and `job = {job_id: request.id,
   spec}`. That host's hostd decides whether Allow at its own desk is enough.
4. Hostexec elsewhere: stop unless the target's
   `last_status.tiers[scope.tier].armed_until` is truthy and the request is
   not too sensitive.
5. No hosts: stop.
6. Record one prompt in the agent's deque and in the global deque (counted
   once per offer, not per host).
7. Payload: `{request_id, who, what, detail, timeout: <secs>, job?}`, where
   `prompt_fields` (`desktop.py:72-94`) gives:
   - `who = agent.name + " (for <delegator>)"`.
   - `what` for hostexec: `run on <host> as <ROOT|your user>: <shlex.join(argv)>`,
     or `template <name> <params>`.
   - `what` otherwise: `<platform> / <capability> on <resource>[ <str(scope)[:200]>], for <format_duration>`.
   - `detail` = up to 2 risk notes (each ≤200 characters) and `The agent
     says (unverified): <justification[:400]>`, joined by `" · "`.
8. For each host, `_show` acquires that host's lock, waiting at most 30 s
   (one dialog per host; if the lock times out, skip that host). It then
   sends `{"type": "prompt", "prompt_id": uuid4, ...payload}` via
   `hub.call(..., timeout=10)`. A `DaemonCallError` drops this host. On
   success it holds the lock until it is cancelled.
9. Wait for the first answer for at most `timeout + 30` s; past that, the
   answer is `timeout`. Then cancel the shows, and for every prompt still
   registered send `{"type": "prompt.cancel", "prompt_id"}` (`hub.send`,
   best-effort).
10. `_apply`:
    - `mute`: pause the agent for `mute`.
    - `allow`/`deny`: `deny` first calls `_note_deny` (the pause is `mute` if
      there are ≥ 3 denies in the last hour, else `deny_cooldown`). Then
      `service.decide(request_id, HumanDecision(approve=answer=="allow",
      decided_by="desktop:<host>", reason="" | "denied at the desk"))`. A
      `TransitionError` is logged and ignored, leaving the request with
      Discord.
    - `discord`/`timeout`: nothing.

### 8.5 Answers, `prompt.answer` (`desktop.py:298-311`)

An answer `{prompt_id, answer}` is accepted only if all of these hold: the
connection's role is `host`; the prompt id is still registered; it was sent
to **this** host (`offer.prompts[prompt_id] == live.name`); and `answer ∈
{allow, deny, mute, discord, timeout}`. `timeout` only unregisters that one
prompt (other desks may still answer). Otherwise the answer resolves the
offer once (first answer wins). `cancel(request_id)` (a decision made
elsewhere) resolves the offer with `(None, "discord")`.

### 8.6 DND, notify and alert

- `set_dnd(seconds)`: `dnd_until = now + seconds` (0 turns it off). Send
  `{"type": "dnd", "duration": seconds | null}` to every host row
  (best-effort). Triggered from Discord `/dnd`.
- `notify(agent, text, urgency)` (attention): returns `[]` unless the
  desktop is enabled, the agent matches `desktop.agents`, DND is off and the
  agent is not paused. It is **not** counted against the prompt rate limits.
  For each present host, in sequence: `hub.call({"type": "notify", "title":
  "agent-auth: <agent>", "text": text, "urgency": "critical" if
  urgency=="high" else "normal"}, timeout=10)`. Returns the hosts that
  acknowledged. The text is sent raw; hostd escapes it (HTML) and plays the
  attention sound (`hostd/user.py:256-265`, `test_desktop.py:220-236`).
- `alert(title, text)`: `notify` to every present host with urgency
  `critical`, ignoring eligibility.

---

## 9. Operator attention (`core/attention.py`, `api/agent_routes.py:52-71`)

**POST /v1/attention** `{text: 1..2000, urgency: "normal"}`. If the service
is not configured: **501** `not available on this broker`.

`AttentionService.notify`, in order:
1. `text = " ".join(text.split())[:500]`. If empty: **400** `say what you need`.
2. `urgency ∉ {normal, high}`: **400** `urgency is normal or high`.
3. Rate limit: a per-**agent-id** deque of send times, pruned to the last
   3600 s. If it holds ≥ 6: **429** `at most 6 notifications an hour; the
   operator has the earlier ones`. Otherwise record now. The send is counted
   before delivery, so a failed delivery still counts.
4. `desks = desktop.notify(agent, text, urgency)` (§8.6), or `[]`.
5. `notifier.attention(agent, text, urgency, desks)`. In Discord
   (`discord_bot/bot.py:167-186`): `ping = bool(owner_id) and (urgency ==
   "high" or not desks)`. The message is `"<@owner> " if ping` +
   `🔔 **<agent name>** wants your attention[ (shown on h1, h2)]:\n> <text
   with markdown, then mentions, escaped>`, cut to 2000 characters. Allowed
   mentions: only that owner user when pinging; never everyone or roles.
   Errors are logged and swallowed. The non-Discord notifier only logs it.
6. Response: `{"sent": true, "desktops": desks}`.

There is no containment check: a held agent can still reach the operator.

---

## 10. Security invariants

- **INV-1** A thread's messages and metadata are returned by `/v1/a2a/*`
  only to its two participant agents. To any other agent every per-thread
  route returns 404 `unknown thread`, the same as for a nonexistent id. Admin
  routes (`/admin/chat/*` for operator-initiated threads; `/admin/a2a/*`
  logs) are the only other readers.
- **INV-2** If `initiator_session_id = S`, the initiator agent can read,
  poll, send on and close the thread only with `X-Agent-Session: S`.
  Sessionless and other-session calls get 403. The same holds for
  `responder_session_id` on the responder side. Once set, a binding is
  never cleared or changed (Python lacks the lock that guarantees this; see
  B4).
- **INV-3** An ephemeral agent never uses a per-thread route, list or events
  without a session (400), so sessionless access cannot widen an ephemeral
  agent's view.
- **INV-4** A thread is never opened to an agent whose kind is not
  `service`, and never to a missing or disabled agent. An a2a grant whose
  resource is a non-service agent cannot be created, and demoting an agent
  to ephemeral revokes the existing ones and closes its inbound threads.
- **INV-5** A non-operator thread is created only if, at open time, the
  initiator holds an `active` a2a grant with `expires_at > now` for
  `resource = responder.name` whose topic glob matches. A topic-less open
  matches only unscoped grants.
- **INV-6** No message is stored on a grant-backed thread unless its backing
  grant is active and unexpired at that moment. A send that finds the grant
  dead stores nothing and leaves the thread `closed/grant_revoked`.
- **INV-7** No message is ever stored on a `closed` thread, and `closed` is
  terminal.
- **INV-8** While a thread is `pending_open`, the initiator cannot add
  messages: the thread holds exactly one message. Only the responder can
  move it out of `pending_open` (accept, reply, reject), or a close or sweep
  can.
- **INV-9** Per thread, `seq` values are unique, contiguous from 1, and
  equal to `last_seq` after each send.
- **INV-10** The `from` of every message, ping and panel row is the broker's
  name for `sender_agent_id`. No payload field ever sets it. Only an
  admin-authenticated request can create a message whose sender is the
  operator row. The operator row never authenticates with an API key.
- **INV-11** No open, accept or send happens while either participant is
  held, unless one side is the operator. Containment closes every
  non-closed thread of a held agent.
- **INV-12** Webhook pings are sent only to `service` agents with a
  `webhook_url`, are always signed (`sha256=` HMAC over the exact body),
  are never sent unsigned, and never contain a message payload.
  `webhook_secret` appears only in the create, set-webhook and rotate
  responses.
- **INV-13** A delegated request is anchored only by the thread's
  **responder**, only on an `open` thread, and only from the bound session
  if the responder side is bound. The delegator is always
  `thread.initiator_agent_id`. a2a is never delegable. A delegated grant
  never expires after its backing grant. No credential is issued for it
  unless the thread is `open`, and the scheduler revokes it within one tick
  after the thread closes.
- **INV-14** A non-editor agent writes or deletes a wiki page only when the
  path is `projects/<agent.project>/…` with at least 3 segments. An agent
  with no project, a member of a zone without `wiki: true`, or a held agent
  writes nothing.
- **INV-15** Every wiki path the broker reads, writes or deletes passes
  `check_path`: plain segments, no `.`/`..` segments, no empty segment, at
  most 6 segments and 200 characters, ending in `.md`.
- **INV-16** An existing wiki page is replaced or deleted only when
  `base_sha` equals its current blob sha, re-fetched just before the write;
  GitHub's sha precondition backs this up.
- **INV-17** Wiki content larger than `max_page_bytes`, blank, or matching a
  credential pattern is never committed.
- **INV-18** A desktop answer counts only if it comes from a `host`
  connection, for a prompt id the broker sent to **that** host, while the
  offer is open. It acts only through `service.decide` (so the normal gates
  apply), recorded as `desktop:<host>`. Shell and human-only requests are
  never offered.
- **INV-19** An agent produces at most 6 attention notifications per rolling
  hour. The text is single-line and at most 500 characters, and on Discord
  it can mention nobody but the configured owner.
- **INV-20** Every long-poll wait is clamped: NaN → 0, agent routes at most
  300 s, the panel at most 25 s.
- **INV-21** `reachable` for a service agent without a webhook means its
  `last_listen_at` is within `A2A_LISTEN_THRESHOLD_SECS`. An open to an
  unreachable service agent fails with 409 and creates nothing.

---

## 11. Tests worth porting

From `tests/test_a2a.py`:
- `test_session_lifecycle`: sessions authenticate; a bogus, closed or other
  agent's session gets 401.
- `test_explicit_accept_and_close`: only the responder accepts; a double
  accept gets 409; follow-ups get seq 2; no send after close (409).
- `test_reject`: reject sets `close_reason=rejected` and `close_note`, and
  the initiator sees it.
- `test_initiator_cannot_send_on_pending_open`: 409.
- `test_non_participant_gets_404`: read and send by a third agent get 404.
- `test_responder_session_binding`: dispatcher sees the pending open and the
  worker does not; accept with a session binds; other sessions and
  sessionless get 403; wakes route to the worker.
- `test_implicit_accept_binds_replying_session`: a sessioned reply binds; a
  sessionless accept leaves the thread unbound.
- `test_responder_session_death_closes_thread`: `peer_alive` follows the
  worker session; idle or closed session → `peer_gone`.
- `test_grants_shared_across_sessions`: the grant is agent-level; threads
  are session-scoped; ephemeral open without a session gets 400.
- `test_thread_access_bound_to_session`: session B cannot read, poll, close
  or send on A's thread; sessionless ephemeral gets 400.
- `test_ephemeral_cannot_receive`: the validator denies, and a manufactured
  grant still gets 403.
- `test_topic_glob_enforced_at_open`: topic glob; a missing topic does not
  match a scoped grant; check `any_topic`.
- `test_message_longpoll_wakes_on_reply` and
  `test_events_longpoll_and_cursor`: wake-ups, cursor advance, pending opens
  repeat.
- `test_open_timeout_sweep`, `test_idle_thread_sweep`,
  `test_idle_session_sweep_closes_threads_peer_gone`,
  `test_grant_revocation_closes_thread` (lazy and sweep paths).
- `test_peer_liveness_fields`, `test_requesting_access_does_not_make_a_peer_reachable`,
  `test_listening_ages_out`, `test_ephemeral_peer_is_403_not_409`.
- `test_set_kind_demotes_and_orphans_inbound_threads`,
  `test_set_kind_promotes_back_to_service`,
  `test_set_kind_demotion_revokes_grants_targeting_it`,
  `test_set_kind_rejects_garbage`.
- `test_webhook_ping_shape_and_signature`,
  `test_webhook_global_secret_fallback`, `test_unsigned_pings_never_sent`,
  `test_set_webhook_on_existing_agent`, `test_rotate_webhook_secret`.
- `test_legacy_null_thread_messages_invisible`,
  `test_payload_keys_survive_verbatim` (`_sandbox` and `_sample` keys
  intact).

From `tests/test_chat.py`:
- `test_the_operator_writes_and_an_agent_answers`: the payload shape,
  `from=operator`, preview, `last_from_operator`, a result shown as its
  summary, and close then 409.
- `test_a_reply_wakes_the_waiting_panel`.
- `test_no_grant_backs_it_and_the_sweep_leaves_it_open`.
- `test_only_service_agents_that_listen`: peers list; 403 for ephemeral; 409
  for asleep.
- `test_the_operator_row_speaks_only_through_the_panel`: 409 on every admin
  mutation, name reserved, and an operator-kind key gets 401.
- `test_an_agent_named_operator_blocks_the_chat_until_renamed`.
- `test_from_the_panel_the_signed_in_user_is_recorded`: CSRF is required and
  the `operator` field equals the user.

From `tests/test_wiki.py`:
- `test_an_agent_writes_its_own_projects_pages_and_everyone_reads_them`.
- `test_an_agent_cannot_write_outside_its_project` (parametrized, write and
  delete).
- `test_an_agent_without_a_project_reads_and_cannot_write`.
- `test_an_editor_writes_shared_pages`.
- `test_a_page_that_exists_is_replaced_only_from_the_version_read`.
- `test_a_path_is_plain_segments_ending_in_md` (parametrized).
- `test_a_page_with_a_credential_in_it_is_refused` (parametrized).
- `test_size_empty_and_missing`.
- `test_no_key_no_wiki_and_no_wiki_configured`.
- `test_the_brokers_copy_is_kept_between_reads_and_survives_an_outage`.
- `test_policy_names_the_wiki_and_its_editors`.
- `test_github_backend_reads_and_writes_as_the_app`: tree filter, blob
  cache, token permissions, author, conflict mapping, last_change.
- `test_an_empty_repo_is_an_empty_wiki`.
- `test_a_held_agent_reads_but_writes_nothing`.

From `tests/test_desktop.py` (these need a hostd fake):
- `test_a_request_is_asked_at_the_desk_and_the_answer_decides`.
- `test_a_deny_at_the_desk_denies_and_pauses_that_agent`.
- `test_mute_decides_nothing_and_silences_the_agent`.
- `test_who_is_never_asked_at_a_desk`.
- `test_an_agent_can_ask_for_attention`: also covers the attention rate
  limit.
- `test_away_locked_or_do_not_disturb_means_discord_only`.
- `test_an_answer_counts_only_for_a_prompt_sent_to_that_host`.
- `test_rates_keep_an_agent_from_flooding_the_desk`.
- The own-desk hostexec tests
  (`test_allow_at_its_own_desk_approves_exactly_that_command`,
  `test_root_at_its_own_desk_takes_the_password_too`) belong to the hostd
  spec.

From `tests/test_delegation.py` (a2a side):
- `test_delegation_validation`.
- `test_delegation_respects_responder_session_binding`.
- `test_thread_close_cascades_revocation`.
- `test_provision_recheck_after_thread_closed`.

From `tests/test_review_fixes.py`:
- the `wait=nan` long-poll test.
- `test_thread_topic_rejects_newlines`.
- the initiator-cannot-delegate test (around line 59).

From `tests/test_mcp_sessions.py` (only if the MCP client is ported; it is
client-side): the `STALE_SESSION` re-mint
(`test_a_minted_session_the_broker_closed_is_replaced`), and an explicit
`session_key` that is never replaced.

---

## 12. Suspected bugs / questionable behavior in the Python

**B1. Delegation on operator threads can never be provisioned.** The README
("Admin panel → Chat") says that what an agent asks for on the operator's
behalf is a delegated request with `operator` as delegator, decided by
reviewer or Discord. `_resolve_delegation` accepts operator threads, but the
provision-time re-check at `core/service.py:855-866` requires a backing grant
(`backing is None → PROVISION_FAILED "delegation thread is no longer
open"`), and operator threads have `grant_id NULL`. So every approved
operator-delegated request fails at provisioning, with a misleading reason.
No test covers it. For the port: skip the backing-grant clause when
`thread.grant_id IS NULL` and the initiator is the operator, and cap the
expiry some other way (or refuse operator delegation up front with a clear
reason).

**B2. The message long-poll marks the caller as listening.**
`a2a_routes.py:215` calls `mark_listening` in the `read_messages` wait loop.
That contradicts the design in `core/a2a.py:55-69` and `deps.py:120-127`:
"only the a2a inbound surfaces record it". A service agent that never reads
inbound threads, but long-polls replies on threads it opened, is advertised
as reachable (`why: polling`). That is exactly the mis-registered-service
case reachability exists to catch. The port should drop it, or else document
it.

**B3. The events cursor can skip activity.** `last_activity_at` comes from
the application clock (`utcnow()` in `_next_seq` and `_close`) before the
transaction commits. Under concurrency, a transaction that commits later can
carry an *earlier* timestamp than one already returned, so the cursor has
already moved past it and `last_activity_at > after` never returns it
(`a2a.py:516,528-531`). Equal timestamps at the 200-row limit boundary are
also dropped by the strict `>`. Python tolerated this under SQLite's single
writer; it is real on PostgreSQL. Options: a commit-ordered sequence column
(for example a per-row `activity_seq BIGINT` from a sequence, assigned in
the same UPDATE, with clients that tolerate gaps), or a cursor that re-reads
a small overlap window. Pending opens are unaffected because they are never
cursor-filtered.

**B4. No row locking on thread transitions.** accept, reply-accept, reject,
close and send each read the thread, check its state, then write, with no
`FOR UPDATE` (`a2a.py:226-276,304-314`). On PostgreSQL:
- two worker sessions can both accept or reply to the same `pending_open`
  thread, and both succeed; the last write wins `responder_session_id`, and
  the first worker is then locked out with 403;
- a send can insert a message onto a thread that a concurrent close has just
  committed (breaks INV-7);
- a double accept may both return 200.
`models.py:212-213` notes the reliance on SQLite serialization. The port must
`SELECT … FOR UPDATE` the thread row (or use conditional `UPDATE … WHERE
state = 'pending_open'`).

**B5. Zones are not enforced on open or send.** Zones are applied when the
grant is requested (`core/zones.py:107-111`), in `/a2a/check`, and in the
catalog. `open_thread` (`a2a.py:137-172`) and `send_message` do not check
them. A grant issued before a zone was declared, or before a policy change
put the agents on opposite sides, still opens and uses threads across the
zone edge. Also, for a zone-apart peer, `open` reveals that it exists
(`no active a2a grant to talk to 'X'`) while `check` says `unknown agent
'X'`. Separately, `open_thread` has no `responder != initiator` check
(defense in depth; the validator forbids self-grants).

**B6. `/a2a/check` ignores `disabled`** (`a2a_routes.py:282`). For a
disabled peer it returns full reachability data and possibly `allowed:
true`, while open returns 404 `unknown agent`. This leaks the disabled
agent's description and timestamps and contradicts the open path.

**B7. Disabling an agent leaves the threads it responds to open.**
`disable_agent_tree` (`core/sandboxes.py:54-82`) only expires the disabled
agent's *own* grants. Threads where it is the **responder** are backed by the
initiator's grant, so they stay `open`. The initiator can keep sending, and
messages pile up for an agent that can no longer authenticate, until
`idle_timeout` (1 h). Operator threads to a disabled agent behave the same
way. The port should close them `peer_gone` on disable, as the ephemeral
demotion already does.

**B8. Sessionless callers see session-bound threads in list and events.**
For a sessionless caller the side predicates are not session-filtered
(`a2a.py:430-446,505-518`). A service agent's dispatcher therefore lists, and
gets activity wake-ups (via the 2 s re-read) for, threads claimed by its
workers. It can see their topic, peer and state, but every read returns 403.
The code comment ("unclaimed responder-side threads are the sessionless
dispatcher's view") and the README ("the sessionless dispatcher lose[s]
access") imply that bound threads should be excluded (`responder_session_id
IS NULL` for the sessionless responder side). A dispatcher that acts on
`activity` will also spin on 403s.

**B9. Webhook delivery is inline, sequential and unretried.** Each ping is
awaited in the request path after commit, with a 5 s timeout per ping
(`a2a.py:879-892`). One blackholed webhook adds 5 s to every open, send or
close that touches that agent. In `close_all_for` (containment) and in the
sweep, N affected threads cost up to N×5 s. Only `httpx.HTTPError` is caught:
any other exception (for example `httpx.InvalidURL`, or a non-ASCII host
error) surfaces as a 500 *after* the state change has committed. The port
should deliver from a background task and catch everything. The README
describes the ping fields as `{type, thread_id, seq, from, topic}`, but the
real shapes differ (§4.3): closed pings carry no `from` or `seq`, and message
pings add `message_id`. Accept sends no ping at all, so a webhook-only
initiator learns of an accept only from the next message.

**B10. `_touch_caller` writes on every long-poll round** (every ≤2 s per
parked poller, unthrottled, `a2a_routes.py:315-326`). This is write
amplification on PostgreSQL, unlike the 20 s throttle in `deps.py`. Throttle
it the same way: the 900 s idle timeout leaves plenty of room.

**B11. Operator-row edge cases.** `operator()` uses `scalar_one_or_none()` on
`kind == "operator"` (`a2a.py:360-362`). A second operator-kind row (possible
only through the DB) makes every chat call fail with a 500. Two concurrent
first uses race on the unique name, and the loser gets a 500. The port
should use `INSERT … ON CONFLICT DO NOTHING` and then select.

**B12. Wiki `last_change` is cached by blob sha, not by path**
(`wiki.py:193-198`). Git blob shas are content-addressed, so two pages with
identical content, or a page deleted and re-created with the same text,
share a cache entry. `wiki_read` then shows the *other* page's (or an older)
author and summary. That undermines the module's stated purpose: "readers get
its project and last author with it". Also, `last_change` returns `None` on
any non-200 response and that `None` **is cached**, so a transient GitHub
error hides the author until the page's content changes (only exceptions
skip the cache). The port should key by `(path, sha)` and not cache `None`.

**B13. The credential scan skips the summary.** Only `content` is checked
against `SECRET_PATTERNS` (`wiki.py:249-255`). `summary` goes verbatim
(collapsed, ≤200 characters) into the commit message (`wiki.py:299-304`), so
a token pasted there lands in git history, which is permanent and readable
by everyone. Scan the summary too.

**B14. Wiki writes do a full tree fetch each time, and the cache is
process-local.** Each write or delete forces `snapshot()` (one tree call,
plus blob calls for new shas) under the global lock, which serializes all
wiki writes behind GitHub latency. This is acceptable, but the port should
know about it. Reads with `refresh_secs=0` (used in tests) refetch on every
call.

**B15. The GitHub tree `truncated` flag is ignored** (`wiki.py:345`). On a
repo large enough for GitHub to truncate the recursive tree, pages silently
disappear from list, search and read, and a write to a page outside the
truncated listing is treated as a *create* (no sha), which GitHub then
rejects with 409/422 → "changed while you were writing". This is unlikely at
wiki scale. The port should log it at least.

**B16. Desktop rate limits can be bypassed by simultaneous requests.**
`refusal()` runs synchronously in `offer()` (`desktop.py:195-201`), but the
counters are only appended later in `_ask` (`desktop.py:250-251`), after
DB and presence awaits. Several requests surfaced together all pass the
burst and hourly checks before any of them is counted. The per-host lock
still shows them one at a time, but each one queued (up to 30 s) is asked.
The port should reserve the slot at refusal time, or re-check inside `_ask`.
The counters are also incremented even when every `hub.call` then fails.

**B17. A chat topic may contain newlines.** `ChatOpen.topic`
(`chat_routes.py:35`) lacks the control-character validator that
`ThreadOpenBody` has (`schemas.py:147-153`). The operator's topic is later
rendered through `json.dumps` in delegation risk notes, so this is not
injectable there, but "topics are single-line" is not universal. Apply the
same validator.

**B18. The panel trusts the payload's `operator` field from any sender.**
`_message` (`chat_routes.py:87`) shows `payload.operator` for every message,
including the agent's replies. An agent can put `"operator": "jrt"` in its
reply, and the panel shows it with that attribution next to the agent's
`from`. Show `operator` only when `sender_agent_id == operator.id`.

**B19. Process-local limits reset on restart.** These limits are kept in
memory: attention (6 per hour), the desktop rates, the deny pause and mute,
and DND. A restart, or more than one process, resets or splits them. That
may be acceptable, but it should be documented, or the state persisted (for
example a small PG table) if the port runs more than one replica.
