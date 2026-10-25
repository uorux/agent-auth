# HTTP API: behavioral specification

Scope: the broker's HTTP surface as built by `src/agent_auth/api/app.py`. This
document covers the agent API (`/v1/*`), the admin API (`/admin/*`), the
audit, containment, wiki and token-issuer routes, the catalog, serialization,
and middleware. Several areas have their own specs: OAuth, the web UI
(`/ui`), remote MCP (`/mcp`), operator chat (`/admin/chat/*`), daemon pairing
and channel (`/v1/daemons/*`) and hostexec (`/v1/hostexec/*`). They appear in
the inventory (§1) with one line each.

All `file:line` citations are relative to `src/agent_auth/` unless stated.
Python versions this was checked against: FastAPI 0.139, pydantic 2.13,
Starlette 1.3, uvicorn 0.50. Several statements below were checked against a
live in-process app, not only read from the code. Those are marked
"(observed)".

Notation: `detail` strings are verbatim. `{x!r}` means Python `repr`, a
single-quoted string such as `'foo'`. Rust must reproduce that quoting: wrap
in single quotes, and if the value contains a `'` but no `"`, Python uses
double quotes instead.

---

## 1. Route inventory

Auth legend:
- **agent**: `Authorization: Bearer <api key | oauth access token>`, plus an optional `X-Agent-Session` (§3.1).
- **admin**: the admin token or an admin-panel cookie session (§3.3).
- **none**: unauthenticated.
- **daemon-proof**: authenticated by the pairing proof in the body.
- **oauth**: the remote-MCP OAuth bearer.
- **cookie**: the UI's own sign-in cookie flow.

| Method | Path | Auth | Handler | Notes |
|---|---|---|---|---|
| GET | `/healthz` | none | api/app.py:108 | `{"ok": true}` |
| GET | `/v1/me` | agent | api/agent_routes.py:31 | |
| POST | `/v1/attention` | agent | api/agent_routes.py:57 | |
| GET | `/v1/catalog` | agent | api/agent_routes.py:74 | |
| POST | `/v1/requests` | agent | api/agent_routes.py:106 | |
| GET | `/v1/requests/{request_id}` | agent | api/agent_routes.py:123 | |
| GET | `/v1/requests/{request_id}/wait` | agent | api/agent_routes.py:133 | long-poll |
| POST | `/v1/requests/{request_id}/retry` | agent | api/agent_routes.py:160 | |
| POST | `/v1/requests/{request_id}/escalate` | agent | api/agent_routes.py:173 | |
| GET | `/v1/grants` | agent | api/agent_routes.py:186 | |
| GET | `/v1/grants/{grant_id}/credential` | agent | api/agent_routes.py:217 | |
| POST | `/v1/sessions` | agent | api/a2a_routes.py:47 | |
| POST | `/v1/sessions/close` | agent (+session) | api/a2a_routes.py:73 | |
| POST | `/v1/a2a/threads` | agent | api/a2a_routes.py:89 | gated by `a2a_relay_enabled` |
| GET | `/v1/a2a/threads` | agent | api/a2a_routes.py:100 | gated |
| GET | `/v1/a2a/threads/{thread_id}` | agent | api/a2a_routes.py:114 | gated |
| POST | `/v1/a2a/threads/{thread_id}/accept` | agent | api/a2a_routes.py:123 | gated |
| POST | `/v1/a2a/threads/{thread_id}/reject` | agent | api/a2a_routes.py:136 | gated |
| POST | `/v1/a2a/threads/{thread_id}/close` | agent | api/a2a_routes.py:150 | gated |
| POST | `/v1/a2a/threads/{thread_id}/messages` | agent | api/a2a_routes.py:164 | gated |
| GET | `/v1/a2a/threads/{thread_id}/messages` | agent | api/a2a_routes.py:188 | gated, long-poll |
| GET | `/v1/a2a/events` | agent | api/a2a_routes.py:227 | gated, long-poll |
| GET | `/v1/a2a/check` | agent | api/a2a_routes.py:262 | gated |
| GET | `/v1/audit/events` | agent and policy `audit.readers` | api/audit_routes.py:61 | 404 to non-readers |
| POST | `/v1/containment` | agent and policy `containment.agents` | api/containment_routes.py:73 | 404 to others |
| GET | `/v1/containment` | agent and policy `containment.agents` | api/containment_routes.py:94 | 404 to others |
| GET | `/v1/wiki` | agent | api/wiki_routes.py:53 | |
| GET | `/v1/wiki/page` | agent | api/wiki_routes.py:58 | |
| GET | `/v1/wiki/search` | agent | api/wiki_routes.py:63 | |
| PUT | `/v1/wiki/page` | agent | api/wiki_routes.py:68 | |
| POST | `/v1/wiki/delete` | agent | api/wiki_routes.py:74 | |
| GET | `/.well-known/jwks.json` | none | api/token_routes.py:25 | |
| GET | `/.well-known/openid-configuration` | none | api/token_routes.py:30 | merged with OAuth AS metadata |
| GET | `/v1/tokens/verify` | none (bearer is the subject) | api/token_routes.py:52 | forwardAuth |
| POST | `/admin/agents` | admin | api/admin_routes.py:75 | panel-allowed |
| PATCH | `/admin/agents/{agent_id}/attributes` | admin | api/admin_routes.py:107 | panel-allowed |
| POST | `/admin/agents/{agent_id}/rename` | admin | api/admin_routes.py:127 | panel-allowed |
| GET | `/admin/agents` | admin | api/admin_routes.py:176 | panel-allowed |
| POST | `/admin/agents/{agent_id}/rotate-key` | admin | api/admin_routes.py:183 | panel-allowed |
| POST | `/admin/agents/{agent_id}/rotate-webhook-secret` | admin | api/admin_routes.py:196 | |
| POST | `/admin/agents/{agent_id}/rotate-lldap-password` | admin | api/admin_routes.py:213 | |
| POST | `/admin/agents/{agent_id}/set-kind` | admin | api/admin_routes.py:241 | |
| POST | `/admin/agents/{agent_id}/set-webhook` | admin | api/admin_routes.py:316 | |
| POST | `/admin/agents/{agent_id}/disable` | admin | api/admin_routes.py:495 | panel-allowed |
| GET | `/admin/rules` | admin | api/admin_routes.py:334 | panel-allowed |
| DELETE | `/admin/rules/{rule_id}` | admin | api/admin_routes.py:359 | panel-allowed |
| GET | `/admin/requests` | admin | api/admin_routes.py:369 | |
| POST | `/admin/requests/{request_id}/decide` | admin | api/admin_routes.py:393 | |
| POST | `/admin/grants/{grant_id}/revoke` | admin | api/admin_routes.py:421 | |
| GET | `/admin/projects` | admin | api/admin_routes.py:430 | panel-allowed |
| POST | `/admin/daemons/pairing-codes` | admin | api/admin_routes.py:457 | panel-allowed; semantics in the daemon spec |
| GET | `/admin/daemons` | admin | api/admin_routes.py:475 | panel-allowed; daemon spec |
| DELETE | `/admin/daemons/{daemon_id}` | admin | api/admin_routes.py:480 | panel-allowed; daemon spec |
| GET | `/admin/broker-key` | admin | api/admin_routes.py:487 | panel-allowed |
| GET | `/admin/hosts` | admin | api/admin_routes.py:516 | panel-allowed; hostexec spec |
| POST | `/admin/hosts/{name}/arm` | admin | api/admin_routes.py:529 | hostexec spec |
| POST | `/admin/hosts/{name}/disarm` | admin | api/admin_routes.py:541 | hostexec spec |
| POST | `/admin/lockdown` | admin | api/admin_routes.py:557 | hostexec spec |
| POST | `/admin/unlock` | admin | api/admin_routes.py:572 | hostexec spec |
| GET | `/admin/log/decisions` | admin | api/admin_log_routes.py:32 | panel-allowed |
| GET | `/admin/log/commands` | admin | api/admin_log_routes.py:95 | panel-allowed |
| GET | `/admin/log/commands/{job_id}` | admin | api/admin_log_routes.py:107 | panel-allowed |
| GET | `/admin/a2a/graph` | admin | api/admin_log_routes.py:127 | panel-allowed |
| GET | `/admin/a2a/threads/{thread_id}` | admin | api/admin_log_routes.py:220 | panel-allowed |
| GET | `/admin/models/usage` | admin | api/admin_log_routes.py:281 | panel-allowed |
| GET | `/admin/containment` | admin | api/containment_routes.py:44 | not panel-allowed |
| POST | `/admin/containment` | admin | api/containment_routes.py:49 | not panel-allowed |
| POST | `/admin/containment/lift` | admin | api/containment_routes.py:59 | not panel-allowed |
| GET | `/admin/connectors` | admin | api/oauth_routes.py:295 | **delegated (OAuth)**; panel-allowed |
| POST | `/admin/connectors/{client_id}/revoke` | admin | api/oauth_routes.py:300 | **delegated (OAuth)**; panel-allowed |
| GET | `/admin/chat/peers` | admin | api/chat_routes.py:98 | **delegated (chat)** |
| GET | `/admin/chat/threads` | admin | api/chat_routes.py:123 | **delegated (chat)** |
| POST | `/admin/chat/threads` | admin | api/chat_routes.py:173 | **delegated (chat)** |
| GET | `/admin/chat/threads/{thread_id}` | admin | api/chat_routes.py:185 | **delegated (chat)** |
| POST | `/admin/chat/threads/{thread_id}/messages` | admin | api/chat_routes.py:245 | **delegated (chat)** |
| POST | `/admin/chat/threads/{thread_id}/close` | admin | api/chat_routes.py:255 | **delegated (chat)** |
| GET | `/.well-known/oauth-protected-resource` | none | api/oauth_routes.py:98 | **delegated (OAuth)** |
| GET | `/.well-known/oauth-protected-resource/mcp` | none | api/oauth_routes.py:99 | **delegated (OAuth)** |
| GET | `/.well-known/oauth-authorization-server` | none | api/oauth_routes.py:127 | **delegated (OAuth)** |
| POST | `/oauth/register` | none | api/oauth_routes.py:135 | **delegated (OAuth)**: dynamic client registration |
| GET | `/oauth/authorize` | none | api/oauth_routes.py:167 | **delegated (OAuth)** |
| GET | `/oauth/callback` | cookie | api/oauth_routes.py:186 | **delegated (OAuth)** |
| POST | `/oauth/consent` | cookie | api/oauth_routes.py:234 | **delegated (OAuth)** |
| POST | `/oauth/token` | client | api/oauth_routes.py:273 | **delegated (OAuth)** |
| POST | `/oauth/revoke` | none/token | api/oauth_routes.py:284 | **delegated (OAuth)** |
| GET, POST, DELETE | `/mcp`, `/mcp/` | oauth | api/app.py:130 (`RemoteMcpApp`, api/remote_mcp.py) | **delegated (remote MCP)**; inserted at route index 0, only when `remote_mcp.enabled` |
| GET | `/ui`, `/ui/` | cookie | api/ui_routes.py:55-56 | **delegated (web UI)** |
| GET | `/ui/login` | none | api/ui_routes.py:64 | **delegated (web UI)** |
| GET | `/ui/callback` | none (OIDC) | api/ui_routes.py:78 | **delegated (web UI)** |
| GET | `/ui/session` | cookie | api/ui_routes.py:98 | **delegated (web UI)** |
| GET | `/ui/{name}` | cookie | api/ui_routes.py:112 | **delegated (web UI)**: static assets |
| POST | `/ui/logout` | cookie | api/ui_routes.py:120 | **delegated (web UI)** |
| POST | `/v1/daemons/pair` | daemon-proof | api/daemon_routes.py:22 | **delegated (daemons)** |
| WS | `/v1/daemons/connect` | signed hello | api/daemon_routes.py:34 | **delegated (daemons)**; ws max message 1 MiB (main.py:224) |
| GET | `/v1/hostexec/jobs/{job_id}` | agent | api/hostexec_routes.py:29 | **delegated (hostexec)**; `wait` clamped 0..300 |
| POST | `/v1/hostexec/shells/{grant_id}/exec` | agent | api/hostexec_routes.py:50 | **delegated (hostexec)** |
| POST | `/v1/hostexec/shells/{grant_id}/close` | agent | api/hostexec_routes.py:67 | **delegated (hostexec)** |

Not routed: `/docs`, `/redoc` and `/openapi.json` are disabled and return 404
(app.py:55-62, observed). The legacy `/v1/a2a/send` and `/v1/a2a/inbox`
routes are gone and must stay gone: 404/405 (tests/test_api.py:228-231).

---

## 2. Per-route behavior

Defaults that apply to every route below:
- Auth failures come from §3. On `/v1` routes, authentication runs before
  handler logic and before body or query validation. One exception: a body
  that is not valid JSON is rejected with 422 before auth (§6.4).
- A validation failure is 422 with FastAPI's list-shaped `detail` (§6.4)
  unless stated otherwise.
- "detail" means the JSON body `{"detail": "<string>"}`.

### 2.1 Agent core: api/agent_routes.py

#### GET /v1/me
Returns:
```
{ id, name, description, kind, webhook_url, lldap_username,
  runtime, project, host, placement,          # policy/agents.py:attributes()
  session?: {id, name} }                       # only when X-Agent-Session was sent and valid
```
- All keys are present even when their value is null. `session` is omitted
  entirely without a session.
- `webhook_secret` must never appear here (agent_routes.py:34-36; test
  test_a2a.py:1063). Neither do `disabled`, `api_key`, `parent`, `sandbox` or
  `last_seen_at`.

#### POST /v1/attention
Body:
```
{ text: str, 1..2000 chars (required),
  urgency: str = "normal" }
```
- 501 `not available on this broker` if `app.state.attention` is unset.
- The service collapses whitespace and truncates `text` to 500 chars
  (core/attention.py:31).
- 400 `say what you need` if the text is empty after that.
- 400 `urgency is normal or high` for any other urgency.
- Rate limit: 6 per agent per rolling 3600 s, in memory. Over it: 429
  `at most 6 notifications an hour; the operator has the earlier ones`.
- 200 `{"sent": true, "desktops": [...]}`.
- Side effects: a desktop notification (if configured) and the notifier's
  `attention(agent, text, urgency, desks)` (Discord). An exception from the
  notifier propagates and returns 500.

#### GET /v1/catalog
See §4. Response model `CatalogOut` with exclude_none (only top-level
`PlatformCatalog` fields that are None are dropped; §5.4).

#### POST /v1/requests
Body `RequestCreate` (schemas.py:37):

| field | type | rule |
|---|---|---|
| `platform` | enum | `github`, `homelab`, `kubernetes`, `a2a`, `google`, `agents`, `sandbox`, `hostexec`, `mcp`, `models` (core/states.py:6) |
| `capability` | str | 1..128 |
| `resource` | str | 1..512 |
| `scope` | object | default `{}`; any JSON object; **no size cap** |
| `justification` | str | 1..4000 |
| `requested_duration` | str or int | required; `parse_duration` (schemas.py:15) |
| `on_behalf_of_thread` | str or null | max 36 |

Extra fields are ignored.

`parse_duration`:
- An int must be > 0, else `duration must be positive`.
- A str is stripped and lowercased.
  - All digits: parsed as an int, with the same positivity rule.
  - Otherwise it must match `^(\d+)([smhdw])$`, else
    `invalid duration '<v>': use e.g. '30m', '8h', '2d', or seconds`.
  - Units: s=1, m=60, h=3600, d=86400, w=604800.
- Errors surface as 422 (`msg: "Value error, <text>"`).
- Python quirks (observed): JSON `true` is accepted as 1 s, `1.0` as 1, and
  there is no upper bound. See §8.

Flow: `RequestService.create_request(agent_id, body, session_id)`. The
decision engine is another spec. At the HTTP layer:
- A disabled platform (`registry.get`) raises `SpecValidationError`, which
  becomes 400 `platform '<p>' is not enabled on this broker` (observed).
- Every other refusal (containment, a delegation problem, validator, zones,
  policy deny) is not an HTTP error. It is a 200 with `status: "denied"`,
  `decision_source: "policy"` and a `decision_reason` such as
  `contained (<id>): <reason>`, `delegation: ...` or `validator: ...`
  (core/service.py:193-246).
- Response: `RequestOut` (§5.2), `agent` = the caller's name.

#### GET /v1/requests/{request_id}
- 404 `unknown request` if the request is missing or not the caller's.
- 200 `RequestOut`.

#### GET /v1/requests/{request_id}/wait?timeout=<float, default 60>
Long-poll.
1. `timeout = clamp_wait(timeout, 1, 300)`. NaN becomes 1 (the lower
   bound); ±inf clamps normally (deps.py:27-38). The query parameter is
   named `timeout`, not `wait`.
2. `deadline = now_monotonic + timeout`.
3. Loop:
   - Read the row: 404 `unknown request` if missing or foreign.
   - If `status ∉ WAITING_STATUSES` (pending, llm_evaluating,
     awaiting_human, approved, provisioning: core/states.py:91), return it.
   - If the deadline has passed, re-read and return the current row (still
     waiting; guidance explains).
   - Otherwise wait on in-process `events` key `request_id` for
     `min(remaining, 2.0)` s, then repeat.
4. The 2 s cap is the fallback recheck interval. Wakeups come from
   `RequestService` calling `events.notify(request_id)`.

Note that `awaiting_human` holds the poll until a human decides or the
timeout ends.

#### POST /v1/requests/{request_id}/retry
- Body: `{justification: str 1..4000}`.
- `service.retry`. `TransitionError` becomes 409 with these details
  (core/service.py:544-565):
  - `unknown request` (missing or foreign; note: 409, not 404)
  - `cannot retry from status <status>` (only `llm_denied` may retry)
  - `contained (<id>): <reason or 'by the operator'>`
  - `retry budget exhausted; use escalate`
  - `request was decided concurrently`
- On success: status `llm_evaluating`, `attempt += 1`, the justification is
  replaced, and an LLM eval is spawned.
- 200 `RequestOut`.

#### POST /v1/requests/{request_id}/escalate
- No body.
- 409 with: `unknown request`, `cannot escalate from status <s>`,
  `contained (...)`, `request was decided concurrently`.
- On success: status `awaiting_human`, a risk note is appended, and the
  request is surfaced to the human.
- 200 `RequestOut`.

#### GET /v1/grants?status=<active|all|provisioning|expired|revoked|provision_failed>
- Default `active`. Any other value: 400 `invalid status '<v>'`.
- Returns the caller's grants, `granted_at` descending, as `GrantOut[]`.
- `delegator` is resolved to a name, or null if that agent is unknown (no
  `"?"` here, unlike `request_out`).
- `active` is a pure status filter. A grant past `expires_at` that the
  scheduler has not yet swept is still listed.

#### GET /v1/grants/{grant_id}/credential
Checks run in this order (agent_routes.py:217-249):
1. 404 `unknown grant` if the grant is missing or not the caller's.
2. Containment: if `lockdown.holding(agent)`, record the security_log event
   `credential_refused` (agent, grant, containment) and return 403
   `contained (<entry id>): credentials are not issued`.
3. Delegated grant (`delegation_thread_id` set): if the thread is missing or
   its state is not `open`, 403
   `delegation thread is closed; credential no longer issuable`.
4. `registry.get(grant.platform).get_credential(session, grant)`:
   - `ProvisionerError`: 403 with `str(exc)`. For github and kubernetes,
     e.g. `grant is not active; refusing to mint a token`.
   - `NotImplementedError`: 501 with `str(exc)`.
   - A disabled platform raises an uncaught `SpecValidationError`: 500
     (§8).
5. 200 `CredentialOut`: `{kind, value, username, url, expires_at, note}`,
   all keys present (nulls included; no exclude_none). For a2a:
   `{"kind":"a2a_grant","note":"a2a grants are check-based; open a thread via POST /v1/a2a/threads", ...nulls}`.

Active/expiry checking is done per provisioner, not here: github, k8s,
lldap, mcp and models check status and expiry; hostexec checks status only;
a2a, google, agents and sandbox check nothing. **Rust should check
`status == active && expires_at > now` centrally before calling the
provisioner**, keeping the provisioner's own checks as well.

### 2.2 Sessions and a2a: api/a2a_routes.py

The a2a service internals (thread state machine, sweeps, webhooks) are in
core/a2a.py and its own spec. Below is the HTTP contract.

Gating: every `/v1/a2a/*` route first calls `_a2a()`. If
`settings.a2a_relay_enabled` is false, it returns 404
`a2a is disabled on this broker` (after auth). The `/v1/sessions*` routes
are **not** gated.

`A2AError(status, detail)` maps to `HTTPException(status, detail)`.

#### POST /v1/sessions
- Body `{label: str 1..64, ^[a-zA-Z0-9._-]+$}`.
- Generates `name = f"{label}-{4 lowercase hex}"`, retrying up to 5 times
  if (agent_id, name) already exists. After 5 failures: 500
  `could not allocate a session name`.
- Inserts an `AgentSession` row.
- 200 `{session_id, name, created_at}`.
- Any agent kind may create one. Ephemeral agents need one for any a2a
  operation.

#### POST /v1/sessions/close
- Requires a valid `X-Agent-Session`, else 400 `no X-Agent-Session header`.
  An invalid or closed session already got 401 in auth.
- `a2a.end_session`: sets `closed_at` and `close_reason="closed"`, and
  closes every non-closed thread bound to the session with `peer_gone`
  (notices and pings go to the peers). It can raise 404 `unknown session`.
- 200 `{"ok": true, "threads_closed": <int>}`.
- Any later use of that session id gets 401.

#### POST /v1/a2a/threads (open)
Body `ThreadOpenBody`:
- `to`: str 1..128.
- `topic`: str or null, max 256. It must not match `[\x00-\x1f\x7f]`, else
  422 `topic must not contain control characters or newlines`.
- `payload`: object, default `{}`. Size cap below.

Payload size cap (schemas.py:117): `len(json.dumps(payload)) > 16384` gives
422 `payload exceeds 16384 bytes`. **Python's default `json.dumps`
formatting is the measure**: separators `", "` and `": "`, `ensure_ascii=True`
(each non-ASCII BMP char counts 6, each astral char 12). Rust must
reproduce that serializer to give identical accept/reject decisions at the
boundary.

Checks run in this order (core/a2a.py:137-176):
1. 404 `unknown agent '<to>'` if the responder is missing or disabled.
2. Containment, skipped if either side is the operator: 403
   `<name> is contained (<id>): no a2a while it is held`, checking the
   caller first, then the peer.
3. Not addressable (kind is not `service`, including the operator row): 403
   with `unreachable_detail`. The ephemeral text:
   `'<name>' is ephemeral (initiate-only) and cannot receive threads; it reaches out to you, not the other way around`.
4. An ephemeral caller without a session: 400
   `ephemeral agents must open a session before using a2a (POST /v1/sessions, then send X-Agent-Session)`.
5. No matching grant (`check_grant`, strict topic): 403
   `no active a2a grant to talk to '<to>'; request one via POST /v1/requests {"platform": "a2a", "capability": "talk", "resource": "<to>"} — topic-scoped grants also require an explicit matching topic on the open`.
6. Not reachable (no webhook, `last_listen_at` older than
   `a2a_listen_threshold_secs`, default 300): 409
   `'<name>' is registered but not listening for threads (no webhook, last polled <iso|never>); opening one now would sit unanswered until it times out. Pick a peer that reports reachable, or retry once it is back — list_capabilities and the a2a check both report peer reachability.`

Success:
- Creates the thread (`pending_open`, `last_seq=1`) and message seq 1.
- Notifies the responder's agent-id wake key and sends a webhook ping (no
  payload).
- 200 `thread_out` (below), with `role: "initiator"`.

`thread_out` (core/a2a.py:823): `{thread_id, peer, role, topic, state, close_reason, close_note, grant_id, last_seq, created_at, accepted_at, closed_at, last_activity_at, peer_last_seen_at, peer_alive}`.
- Timestamps are Python `isoformat()` strings (`+00:00`).
- `peer_alive` means the peer was seen within `liveness_threshold_secs`
  (default 120). The peer's *session* `last_seen_at` is used when that side
  is session-bound.

#### GET /v1/a2a/threads?state=&role=
- Ephemeral without a session: 400 (as in open, step 4).
- `role=initiator|responder` filters; any other value (or absent) means
  both. `state` is an exact filter on any string.
- A sessioned caller sees only threads bound to its session.
- Ordered by `last_activity_at` descending, at most 200.
- 200 `[thread_out]`.

#### GET /v1/a2a/threads/{id}
- `_own_thread`:
  - 404 `unknown thread` if the caller is not a participant.
  - If the caller is the initiator: an ephemeral caller without a session
    gets 400.
  - If that side is bound to a session and the caller's session differs or
    is absent: 403 `thread is bound to a different session of this agent`.
- 200 `thread_out`.

#### POST /v1/a2a/threads/{id}/accept
- `_own_thread`.
- 403 `only the thread responder may do this`.
- 409 `thread is not pending_open (state <s>)`.
- Containment check against the initiator.
- Sets the state to `open`. If the call has a session, the thread is bound
  to it (`responder_session_id`).
- Notifies the initiator's wake key.
- After success, `mark_listening` (§3.4).
- 200 `thread_out`.

#### POST /v1/a2a/threads/{id}/reject
- Body `{reason: str|null ≤2000}`. Send `{}` at least: the body is
  required, so a missing body is 422.
- `_own_thread`, responder-only (403), pending-only (409).
- Closes with `rejected` and `close_note=reason`.
- 200 `thread_out`.

#### POST /v1/a2a/threads/{id}/close
- Body as in reject.
- `_own_thread`. 409 `thread is closed (<close_reason or 'closed'>)` if
  already closed.
- Closes with `closed`; either participant may close.
- 200 `thread_out`.

#### POST /v1/a2a/threads/{id}/messages
- Body `{payload: object, same 16 KiB cap}`.
- `_own_thread`, then the not-closed check (409).
- Containment check against the other side.
- If the backing grant (when `grant_id` is set) is not active or has
  expired: the thread is closed `grant_revoked`, the transaction commits,
  and only then 403 `backing grant is no longer active; thread closed`.
- Initiator on a `pending_open` thread: 409
  `thread is pending_open: your opening message already rides the open; wait for the responder to accept or reply`.
- Responder on a `pending_open` thread: implicit accept, with session
  binding if the call has a session.
- `seq` comes from an atomic `UPDATE last_seq = last_seq + 1` that also
  bumps `last_activity_at`.
- 200 `{message_id, seq, thread_state}`.

#### GET /v1/a2a/threads/{id}/messages?after_seq=<int=0>&wait=<float=0>
Long-poll (a2a_routes.py:188-224):
1. `wait = clamp_wait(wait, 0, 300)`. Wake key = the session id if the call
   has one, else the agent id.
2. First read (with all `_own_thread` errors). Return immediately if there
   are messages, `wait <= 0`, or the thread state is `closed`.
3. Loop:
   - If the deadline has passed, return the last snapshot.
   - Otherwise wait on `a2a_events` (the a2a service's own `KeyedEvents`,
     not the request one) for `min(remaining, 2)` s.
   - Then `_touch_caller`: unconditionally set `last_seen_at` on the agent
     and the session, with no 20 s throttle.
   - Then `mark_listening`.
   - Re-read; return if there are messages or the state differs from the
     *initial* state.
4. Response body: `{thread: thread_out, messages: [{message_id, seq, from, payload, created_at}]}`.
   - It is sent as a raw `JSONResponse`, so payload keys survive verbatim.
     FastAPI's encoder would drop keys starting with `_sa` (a2a_routes.py:180;
     test test_a2a.py:1100).
   - Rust: serialize payloads verbatim, with no key filtering.

#### GET /v1/a2a/events?wait=<float=0>&after=<datetime>
1. A naive `after` is treated as UTC. An unparseable one is 422 (pydantic
   datetime parsing).
2. `wait` is clamped to 0..300.
3. `mark_listening` is called **once, before** the session check. An
   ephemeral caller without a session still gets its `last_listen_at`
   touched, then 400.
4. Loop:
   - Snapshot. Return if `pending_opens` or `activity` is non-empty.
   - If the deadline has passed, return the (empty) snapshot.
   - Otherwise wait `min(remaining, 2)` s, then `_touch_caller` (not
     `mark_listening`).

Snapshot `{pending_opens: [thread_out], activity: [thread_out], cursor: iso|null}`:
- `pending_opens`: only for a sessionless caller, the agent's threads in
  `pending_open` as responder.
- `activity`: the caller's own (session-filtered) threads. With `after`,
  those with `last_activity_at > after`; without it, all non-closed. Ordered
  by `last_activity_at` ascending, limit 200.
- `cursor`: the max of `after` and the activity timestamps.

**The cursor must round-trip at full microsecond precision**, because the
comparison is a strict `>`.

#### GET /v1/a2a/check?peer=<name>&direction=out|in&topic=
Returns `A2ACheckOut` `{allowed, grant_id, expires_at, reason, peer}`:
pydantic, all keys present, timestamps with `Z`.
1. Unknown peer, or zones say the two are apart (core/zones.py): 200
   `{allowed:false, reason:"unknown agent '<peer>'", peer:null}`.
   **Disabled peers are not filtered here** (§8).
2. `peer` = `PeerEntry(description or null, **reachability(peer))` (§4.2).
3. Grant: `direction=out` means the caller to the peer; `in` means the peer
   to the caller. `topic` absent means any grant at all (`any_topic=True`);
   a given topic is glob-matched strictly.
4. Any other direction: 400 `direction must be 'out' or 'in'`. This is
   evaluated after the peer lookup, so an unknown peer with a bad direction
   still gets the 200 "unknown agent" answer (observed).
5. No grant: `{allowed:false, reason:"no active a2a grant", peer}`.
6. Grant found: `{allowed:true, grant_id, expires_at, reason, peer}`.
   `reason` is `unreachable_detail` when `direction=out` and the peer is not
   reachable, else null.

### 2.3 Audit: api/audit_routes.py

`GET /v1/audit/events?since=<ISO>&limit=<int=500>`
- Auth: agent.
- Then `_allowed`: if no pattern in `policy.audit.readers` matches the
  agent, 404 `Not Found`, identical to an unknown route.
  - Python leaks the route's existence through query validation: `limit=x`
    gives 422 to a non-reader (observed; §8). Rust should check membership
    before any parameter validation.
- `limit` is clamped to 1..2000.
- `since`:
  - `Z` is replaced by `+00:00`, then `datetime.fromisoformat`. A naive
    value is treated as UTC.
  - Invalid: 422 `since: an ISO 8601 time` (string detail).
  - Absent: now − 1 h.
- Collection: each list is queried with `col >= start ORDER BY col LIMIT limit`.
  - Requests by `updated_at`.
  - Grants by `granted_at` and by `revoked_at`, deduped by id.
  - Host jobs by `created_at` and by `finished_at`, deduped.
  - Threads by `created_at` and by `closed_at`, deduped.
  - Agents by `created_at`.
  - Containment entries (all, filtered by parsed `at >= start`).
  - `security_log.since(start, limit)`.
- Items. Every one has `kind`, `id`, `at`, `status`.
  - `request`:
    - `{id, at=updated_at, created_at, agent, for, platform, what=authority.label, resource, status, source, by=decided_by, reason, justification, risk_notes, duration_secs}`
    - `reason` and `justification` are cut to 2000 chars plus `…`.
    - `duration_secs = approved_duration_secs or requested_duration_secs`.
  - `grant.issued`:
    - `{at=granted_at, status:"active", expires_at, id, agent, platform, what, resource, request_id}`
    - Emitted if `granted_at >= start`.
  - `grant.ended`:
    - `{at=revoked_at, status=<grant status>, reason=cut(revoke_reason), ...base}`
    - Emitted if `revoked_at >= start`.
  - `host_job`:
    - Started: `status:"started"`, `at=created_at`.
    - Finished: `status=job.status, exit_code, error`, `at=finished_at`.
    - Base: `{id, created_at, agent, host, tier, shell:bool, command=cut(_command(spec)), cwd, via}`.
    - `_command`:
      - Template jobs: `"[<template>] k=v k=v"`, stripped.
      - Otherwise: the argv joined with spaces.
  - `a2a.opened`:
    - `{at=created_at, status:"open", id, from, to, topic, operator: grant_id is None}`
  - `a2a.closed`: `status:"closed"`, `reason=close_reason`. Messages are
    never included.
  - `agent.created`: `{id, at, status:"created", agent=name, agent_kind, runtime, project, host, placement, parent=<name|null>}`.
  - `containment`: `{id, at, status:"standing", match, reason, by, source}`. Only entries still standing appear.
  - `security.<kind>`: `{kind, id:"s<seq>", at, client, path, ...fields}`, with every field stringified and cut to 300 chars.
- Sort by `at` ascending and cut to `limit`.
- Returns `{events, next: (last.at if any else start).isoformat(), truncated: len(events)==limit}`.
  - `since` is inclusive: clients pass `next` back and drop items whose
    `(kind, id, status)` they have already seen.
  - Unknown agent ids resolve to `"?"`.

### 2.4 Containment: api/containment_routes.py

Service semantics (revoking grants, denying pending requests, closing
threads, telling sandboxes, the Discord ping) are in core/lockdown.py. The
HTTP layer:

- `_service`: if `app.state.containment` is None, 503
  `containment is not set up on this broker`. Python always sets it.
- Body `ContainBody`:
  - `match`: object (an AgentMatch: `name` glob plus `runtime`, `project`,
    `host`, `placement`, `kind` values; extra keys are forbidden).
  - `reason`: str 1..500.
  - `evidence`: str ≤4000, default "".

**Admin `GET /admin/containment`**
- Returns the list of entries `{id (8 hex), match, reason, evidence, by, source, at (ISO, seconds precision)}`.

**Admin `POST /admin/containment`**
- `contain(match, reason, by=request.state.admin_user, evidence, source="operator")`.
  - `admin_user` is `"admin token"` for the token, or the panel user's name.
- An invalid AgentMatch gives 422 `not an agent match: <pydantic error text>`.
- 200 with `{...entry, agents:[names], grants_revoked, requests_denied, threads_closed, daemons:{...}}`.

**Admin `POST /admin/containment/lift`**
- Body `{id: str|null}`. **null or absent lifts every entry** (§8).
- An unknown id gives 404 `no containment '<id>'`.
- 200 `{"lifted": [entries]}`.
- Records a security_log `containment_lifted` event per entry.

**Agent `POST /v1/containment`**
1. `_allowed`: 404 `Not Found` if no `policy.containment.agents` pattern
   matches. This happens **before the body is read**: a malformed body from
   a non-member must also get 404 (test_containment.py:147).
2. Body: `ContainBody.model_validate(await request.json())`.
   - Bad JSON or schema errors give 422 with a **string** detail
     (`str(exc)` of JSONDecodeError or ValidationError), not FastAPI's
     list.
3. `match == {}` and not `policy.containment.allow_all`: 403
   `containing every agent at once is the operator's`.
4. `contain(..., by=agent.name, source="agent")`.
   - An invalid match gives 422 `not an agent match: ...`.
   - 200 as for the admin route.
5. Agents can never lift.

**Agent `GET /v1/containment`**
- `_allowed` (404), then the list. Allowed agents see full entries,
  including `evidence`.

### 2.5 Wiki: api/wiki_routes.py

`_wiki`: if `app.state.wiki` is None, 501 `this broker has no wiki`. The
check runs after auth, so an unauthenticated caller gets 401 first
(test_wiki.py:212). `WikiError(status, detail)` becomes
`HTTPException(status, detail)`.

| Route | Params / body | Service call |
|---|---|---|
| `GET /v1/wiki?prefix=` | prefix str default "" | `list(agent, prefix)` returns `{repo, you_may_write:[...], pages:[{path,title,bytes}]}` sorted by path, filtered by `startswith(prefix)` |
| `GET /v1/wiki/page?path=` | path required | `read(path)` returns `{path, sha, project, last_change:{author,at,summary}|null, content}` |
| `GET /v1/wiki/search?q=&limit=8` | q required | `search(q, limit)` returns `{query, matches, results:[{path,title,project,lines}]}`; results cut to `clamp(limit,1,25)` |
| `PUT /v1/wiki/page` | `{path ≤300, content (no cap), summary 1..500, base_sha ≤64|null}` | containment gate, then `write` returns `{path, sha, created}` or `{path, sha, unchanged:true}` |
| `POST /v1/wiki/delete` | `{path ≤300, summary 1..500, base_sha ≤64|null}` | containment gate, then `delete` returns `{path, deleted:true}` |

The containment gate (`_not_held`) applies to writes only: 403
`contained (<id>): no wiki writes while you are held`. Reads remain allowed.

Service errors (core/wiki.py). Rust can treat these as the wiki spec's, but
the HTTP mapping is:
- 400 path: `a page's path ends in .md and is at most 200 characters`.
- 400 path: `path '<p>': at most 6 segments of letters, digits, dots, dashes and underscores, each starting with a letter or digit`.
- 400 `an empty search`.
- 400 `an empty page; to remove one, delete it`.
- 400 secret patterns: `this looks like it contains <what>. The wiki holds no credentials: say where one is kept, never its value`.
- 400 `say in one line what changed (summary)`.
- 403 `you don't write the shared wiki` (zones).
- 403 no project: `you have no project on record, so there is nowhere in the wiki you may write (the operator sets it: \`agent-auth admin agent-set --project\`)`.
- 403 wrong project: `you may write under projects/<p>/ only. For a page elsewhere, ask an agent of the project that owns it (shared pages: the homelab agents)`.
- 404 `no page '<p>' (wiki_list shows what exists)` (read) and `no page '<p>'` (delete).
- 409 base mismatch: `'<p>' exists[ and has changed since you read it]: read it and pass its \`sha\` as base_sha`.
- 409 `'<p>' no longer exists; leave base_sha out to create it`.
- 409 `'<p>' changed while you were writing; read it again` and the
  `...deleting it...` variant.
- 413 `a page is at most <max_page_bytes> bytes; split it into several`
  (default 65536).
- 502 `the wiki's repo could not be read; try again later`.
- 502 `the wiki's repo refused the write (<code>)` and the delete variant.

Order of checks in `write`:
1. path
2. permission
3. empty
4. size
5. secrets
6. load (forced)
7. base_sha
8. unchanged short-circuit
9. put

### 2.6 Token issuer: api/token_routes.py

These routes are unauthenticated on purpose.
- `_tokens`: 404 (`{"detail":"Not Found"}`) when `app.state.tokens` is unset
  (no MCP servers, or no `BROKER_SIGNING_KEY`).
- `GET /.well-known/jwks.json` returns `tokens.jwks()`.
- `GET /.well-known/openid-configuration`:
  - Starts from `tokens.discovery()` if tokens are set.
  - If OAuth is enabled and there was no discovery document, or its
    `issuer` (with the trailing `/` stripped) equals
    `oauth.config.base_url` (stripped), the OAuth authorization-server
    metadata is merged over it.
  - If neither applies: 404.
- `GET /v1/tokens/verify?server=<name>`. `server` is required: missing is
  422.
  - 404 if tokens are unset.
  - Every negative answer is **401 with an empty body** and the header
    `WWW-Authenticate: Bearer error="invalid_token", error_description="<why>"`:
    - Unknown server, or a missing or non-Bearer Authorization header (the
      scheme compare is case-insensitive):
      `a bearer token for a known server is required`.
    - `TokenError`, or `claims.server != server`:
      `not a valid token for this server`.
    - Grant missing, agent missing or disabled, platform ≠ mcp, resource ≠
      server, status ≠ active, or `expires_at <= now`:
      `the grant behind this token has ended`.
  - 200 with an empty body and headers `X-Agent-Auth-Agent: <name>` and
    `X-Agent-Auth-Tools: <comma-joined claims.tools>`.

### 2.7 Admin: api/admin_routes.py, api/admin_log_routes.py

Every route has `require_admin` as a router dependency (§3.3).

`AgentOut` fields:
`{id, name, description, kind, webhook_url, lldap_username, lldap_managed, disabled, last_seen_at, parent, sandbox, runtime, project, host, placement, lease_expires_at, api_key, webhook_secret}`.
- `lldap_managed` is `lldap_password_encrypted IS NOT NULL`.
- `parent` and `sandbox` are the ids `parent_agent_id` and `sandbox_id`.

Whether nulls are dropped varies by route (exclude_none):
- **Dropped** for: create, rotate-webhook-secret, rotate-lldap-password,
  set-kind, set-webhook.
- **Kept** for: list, rotate-key, attributes, rename.

Tests depend on this: test_a2a.py:827 (`webhook_url` absent after a demote)
and test_api.py:49 (`api_key` null in listings).

`{agent_id}` lookup:
- `attributes` and `rename` accept an id or a name: the id is tried first,
  then the name.
- Every other route takes the id only.
- Unknown: 404 `unknown agent`. `disable` uses `agent not found`.

Operator guards:
- `_not_operator`: 409 `the operator's identity belongs to the admin panel's chat`.
- `_not_operator_name`: 409 `'operator' is the admin panel's name for the operator`.

#### POST /admin/agents
Body `AgentCreate`:
- `name`: 1..128, `^[a-zA-Z0-9._-]+$`.
- `description`: ≤2000, default "".
- `kind`: `^(service|ephemeral)$`, default service.
- `webhook_url`: ≤512 or null, http(s) with a host. Otherwise a 422 value
  error `webhook_url must be an http(s) URL with a host`.
- `lldap_username`: ≤128 or null.
- `runtime`: ≤16; `project`, `host`: ≤64. Each `^[a-z0-9][a-z0-9._-]*$` or
  null.

Behavior:
1. Name check `_not_operator_name`.
2. 409 `agent '<name>' already exists`.
3. Generate a key: `aa_<12 hex>_<token_urlsafe(32)>`. Store `key_id` and
   the sha256 hex of the secret.
4. `webhook_secret = token_urlsafe(32)` iff `webhook_url` is set.
5. `placement="host"`.
6. Response: exclude_none, with `api_key` (and `webhook_secret`) shown this
   once.

#### PATCH /admin/agents/{id-or-name}/attributes
- Body `{runtime?, project?, host?}`. Same patterns but empty allowed
  (`^([a-z0-9][a-z0-9._-]*)?$`).
- Only the fields present in the body are applied. `""` or null clears the
  field.
- Refuses:
  - The operator (409).
  - A VM-minted agent (`sandbox_id` set): 409
    `<name> was minted in an agent VM; its fields are the broker's`.

#### POST /admin/agents/{id-or-name}/rename
- Body `{name}`, same rule as create.
- Refuses:
  - The operator.
  - A VM-minted agent: 409 `<name> was minted in an agent VM; its name is the broker's`.
  - The new name `operator`.
- Same name: 200 with `rules:0, grants:0`, no writes.
- Name taken: 409 `agent '<new>' already exists`.
- Updates:
  - Rules with `agent_pattern == old`, with `delegator_pattern == old`, and
    a2a rules with `resource_pattern == old`.
  - **Active** a2a grants with `resource == old`.
- Returns `{agent: AgentOut, previous_name, rules: <sum of rowcounts>, grants: <rowcount>}`.

#### GET /admin/agents
- Ordered by name; includes the operator row (kind `operator`).
- `api_key` and `webhook_secret` are always null.

#### POST /admin/agents/{id}/rotate-key
- Refuses the operator. VM-minted agents are not refused (§8).
- Replaces `key_id` and the hash. The old key fails at once.
- Returns `AgentOut` (all keys), with `api_key` set.

#### POST /admin/agents/{id}/rotate-webhook-secret
- Refuses the operator.
- New secret; returned once (exclude_none).

#### POST /admin/agents/{id}/rotate-lldap-password
- The homelab provisioner must be registered, else 501
  `platform 'homelab' is not enabled on this broker`.
- Refuses the operator.
- `provisioner.rotate_password`. A `ProvisionerError` gives 409 with the
  message.
- Returns `AgentOut` (exclude_none). The password is never returned.

#### POST /admin/agents/{id}/set-kind
- Body `{kind: ^(service|ephemeral)$}`: anything else is 422 (test
  test_a2a.py:901). Unknown id: 404.
- Refuses the operator.
- Sets `kind`.
- If the new kind is not `service`: clears `webhook_url`, `webhook_secret`
  and `last_listen_at`.
- After commit, if the agent went service to ephemeral:
  - `a2a.orphan_inbound_threads(agent_id)` closes every non-closed thread
    where it is the responder with `peer_gone`.
  - Then every active a2a grant whose `resource == name` is revoked through
    `service.revoke_grant(id, "target '<name>' reclassified ephemeral", "admin")`.
    A `TransitionError` (already ended) is skipped.
- Returns `AgentOut` (exclude_none), as built before those side effects.

#### POST /admin/agents/{id}/set-webhook
- Body `{webhook_url: str|null ≤512}`, validated as on create.
- Refuses the operator.
- Sets the URL. Secret = a fresh `token_urlsafe(32)` if a URL is set, else
  null (both cleared).
- Returns exclude_none with the new secret.

#### POST /admin/agents/{id}/disable
- 404 `agent not found`.
- `disable_agent_tree`: disables the agent and its minted descendants
  (walking `parent_agent_id` transitively).
  - Sets `expires_at = now` on their active grants, so the scheduler
    revokes them.
  - Deletes their `PendingKeyDelivery` rows.
- Returns `{"disabled": [names]}`. There is no operator guard (§8).

#### GET /admin/rules
- Ordered by `created_at` descending.
- `RuleOut {id, action (auto_approve|auto_deny), agent_pattern, delegator_pattern, platform, capability_pattern, resource_pattern, authority, max_duration_secs, enabled, created_by, notes}`.
- `capability_pattern = authority.label(platform, authority)` if
  `authority` is set, else `"*"`.

#### DELETE /admin/rules/{rule_id}
- 404 `unknown rule`. Hard delete. Returns `{"ok": true}`.

#### GET /admin/requests?limit=100
- `created_at` descending, `LIMIT min(limit, 500)`. No lower bound (§8).
- `RequestOut[]`. `agent` is the name, or `"?"` if missing.

#### POST /admin/requests/{id}/decide
Body `DecideBody`:
`{approve: bool (required), reason: str = "", duration: str|int|null, resource_override: str|null, scope_override: object|null, totp: str|null}`.
- `duration` is parsed with `parse_duration`. Failure gives 422 with a
  **string** detail, e.g.
  `invalid duration 'x': use e.g. '30m', '8h', '2d', or seconds`
  (observed).
- `service.decide(..., HumanDecision(decided_by="admin-api", ...))`.
  `TransitionError` gives 409. Details:
  - `unknown request`
  - `request already resolved (status <s>)`
  - `request changed state concurrently`
  - `edited approval rejected by validator: <e>`
  - hostexec gate: `rejected by validator: <e>`
  - `a shell is approved with a TOTP code only (Approve with TOTP)`
- Returns `RequestOut`.

#### POST /admin/grants/{grant_id}/revoke?reason=revoked%20by%20admin
- `reason` is a **query** param.
- `service.revoke_grant(id, reason, "admin")`. 409
  `grant is not active` if missing or not active.
- Returns `{"ok": true, "grant_id", "status": "revoked"}`.

#### GET /admin/projects
- Returns `{projects: {name: {description, repos, in_policy, agents:[names of non-disabled agents with that project]}}, wiki: policy.wiki.repo or null}`.
- Projects that agents carry but policy does not declare appear with
  `in_policy:false`, `description:""` and `repos:[]`.

#### Daemon and host routes (envelope only; semantics in other specs)

**Daemons**
- `POST /admin/daemons/pairing-codes`:
  - Body `{role: str, name: str}`.
  - 503 `BROKER_SIGNING_KEY not configured` (DaemonsDisabled).
  - 400 for `ValueError`: `role must be one of ...`, or
    `name must be a lowercase hostname label ([a-z0-9-], ≤63)`.
  - 200 `{role, name, code, expires_at, broker_public_key}`.
- `GET /admin/daemons` returns `hub.list_daemons()`.
- `DELETE /admin/daemons/{id}`: 404 `daemon not found`, else
  `{"ok": true}`.
- `GET /admin/broker-key` returns `{"broker_public_key": ...}`, or 503
  `BROKER_SIGNING_KEY not configured`.

**Hosts**
- `_hostexec`: 503 `the daemon channel is disabled (BROKER_SIGNING_KEY)` if
  hostexec is None.
- `GET /admin/hosts` returns `{lockdown, hosts}`.
- `POST /admin/hosts/{name}/arm`:
  - Body `{tier="user", duration: str|int = "1h", totp: str (required)}`.
  - `HostExecError` gives 409.
- `POST /admin/hosts/{name}/disarm?tier=`: `HostExecError` gives 409.
- `POST /admin/lockdown`:
  - Body `{scope="sandboxes", host=null, kill_vm=false}`.
  - `ValueError` gives 422 (string detail).
  - Called with `by="admin-api"`.
- `POST /admin/unlock`:
  - Body `{host=null, totp=null}`.
  - `HostExecError` gives 409.

#### Admin logs: api/admin_log_routes.py

Read-only. `limit` is clamped to 1..1000.

**`GET /admin/log/decisions?limit=200&source=&agent=`**
- `created_at` descending.
- `source` filters `decision_source` with an exact compare. On Postgres a
  value that is not an enum member errors (§8).
- `agent` is a name. An unknown name matches nothing.
- Items:
  `{id, at=created_at, decided_at, agent, for, platform, what=label(authority), resource, status, source, by=decided_by, reason, justification, duration_secs}`.
  - These are *not* cut, unlike audit.

**`GET /admin/log/commands?limit=200&host=`**
- `created_at` descending.
- Items: `{id, at, agent, host, tier, shell, command, cwd, status, via, exit_code, error, duration_ms, output_bytes, request_id}`.

**`GET /admin/log/commands/{job_id}`**
- 404 `unknown command`.
- The item plus `{justification, decided_by}` from the originating request
  (null if none), `output` (the last 20000 chars),
  `output_cut = len(output) > 20000 or job.truncated`, and `output_sha256`.

**`GET /admin/a2a/graph?hours=24`**
- `hours` is clamped to 1..720.
- Threads with `last_activity_at >= now - hours`, newest first. Threads
  whose initiator or responder is disabled or missing are skipped.
- `alive` means `last_seen_at` within `liveness_threshold_secs`.
- Returns
  `{hours, now, nodes:[{name, runtime, project, host, placement, kind, alive}], edges:[{from, to, threads, open, messages, requests, last}], threads:[{id, from, to, topic, state, close_reason, messages, requests, opened, last}]}`.
  - Nodes: non-disabled agents that appear in a thread or are alive.
  - Edge `open` counts threads in `open` or `pending_open`.
  - `requests` counts AccessRequests with that `delegation_thread_id`.

**`GET /admin/a2a/threads/{thread_id}`**
- 404 `unknown thread`.
- Returns
  `{id, from, to, topic, state, close_reason, opened, messages:[{seq, at, from, type, text, cut}], requests:[{platform, what, resource, status, source}]}`.
  - `text` is `payload["text"]` if that is a str; otherwise
    `json.dumps(payload, indent=1, default=str)`. It is cut to 4000 chars,
    with `cut` true when it was longer.
  - `type` is `payload.get("type")`.
  - The admin can read operator-unrelated agent payloads here. This is
    deliberate.

**`GET /admin/models/usage`**
- If models are not enabled: `{"enabled": false, "agents": []}`.
- `gateway.usage(sorted names of agents that ever held a models grant)`.
  - A `ProvisionerError` gives 200
    `{"enabled": true, "gateway": url, "error": str, "agents": []}`.
- Rows `{agent, runtime, project, host, placement, spend: float, max_budget}`.
  Gateway users that are not agents are skipped. Rows are sorted by spend,
  descending.
- Returns `{"enabled": true, "gateway": url, "agents": rows}`.

---

## 3. Authentication and authorization

### 3.1 Agent auth: `get_caller` (api/deps.py:58)

1. Bearer extraction follows FastAPI `HTTPBearer(auto_error=False)`:
   - Split the header at the first space; the scheme compare is
     case-insensitive (`bearer x` works, observed); strip the credentials.
   - Missing header, empty scheme or credentials, or a non-Bearer scheme:
     401 `missing bearer token`.
2. OAuth path: taken only if `app.state.oauth` is set **and** the token
   starts with `aat_`.
   - `oauth.agent_for_access`: the token row must be found and unexpired
     (core/oauth.py) and the client not revoked.
   - Agent missing or disabled: record security_log
     `bad_key(agent=<name|None>, reason="oauth token")` and return 401
     `invalid or expired access token`.
   - Otherwise continue to step 5.
   - If OAuth is off, an `aat_` token falls through to API-key parsing and
     gets `malformed API key`.
3. API key: `parse_api_key` does `split("_", 2)`. It must give exactly 3
   parts, the first being `aa`.
   - Otherwise record security_log `bad_key(reason="malformed")` and return
     401 `malformed API key`.
4. Look up the agent by `key_id` (part 2). Refuse if:
   - the agent is missing (`unknown key`),
   - disabled (`disabled`),
   - its kind is `operator` (`operator`; the operator row never speaks by
     key),
   - or `hmac.compare_digest(sha256_hex(secret), api_key_hash)` is false
     (`wrong secret`).

   On refusal, record `bad_key(key_id, agent, reason)` and return 401
   `invalid API key`. The `reason` is chosen in that order.
5. Session (`_with_session`, deps.py:102): if `X-Agent-Session` is present
   and **non-empty** (an empty header counts as absent, observed):
   - The row must exist, belong to this agent, and have `closed_at IS NULL`.
   - Otherwise 401 `unknown or closed session` (no security_log). A 401 and
     not a 404, because the client should mint a new session.
6. Bookkeeping (`_touch`, deps.py:51):
   - Set `last_seen_at = now` on the session (if any) and on the agent, but
     only if the stored value is null or older than 20 s.
   - It is written in the same DB transaction, committed at the end of
     `get_caller`'s session block.
   - On the 401 paths the transaction rolls back, so nothing is written.
7. The caller is `{agent, session|null}`. The ORM rows are detached copies;
   handlers re-read the rows they mutate.

### 3.2 Liveness bookkeeping

- `last_seen_at`: any successful agent auth (throttled to 20 s), plus
  `_touch_caller` inside the a2a long-poll loops (unthrottled, every ≤2 s;
  agent and open session).
- `last_listen_at`: **only** `mark_listening` (deps.py:122), throttled to
  20 s. It is called by:
  - `GET /v1/a2a/events`, once per call at the start;
  - `POST /v1/a2a/threads/{id}/accept`, after success;
  - each wake iteration of `GET /v1/a2a/threads/{id}/messages` with
    `wait > 0`.

  Requesting access, `/v1/me`, `/v1/grants` and the rest never set it
  (test_a2a.py:727). Reachability keys on it.
- AgentSession `last_seen_at` defaults to its creation time.

### 3.3 Admin auth: `require_admin` (api/deps.py:146)

1. **Panel session path.** Taken only if all of these hold:
   - `app.state.ui_auth` is set;
   - there is **no** bearer credential (`creds is None` in HTTPBearer's
     sense);
   - `ui.serves(headers)`: for each of `Host` and `X-Forwarded-Host` (first
     comma element, stripped, lowercased), the value is empty, or equals
     the netloc of `policy.ui.base_url`, or its host part is one of
     `127.0.0.1`, `localhost` or `[::1]`.

   Then decrypt the `aa_ui` cookie (Fernet with an HKDF-derived key, ttl
   `ui.session_ttl`, `k == "session"`, `exp > now`).

   If the session is valid:
   - `webui.allowed(method, path)` must be true, else 403
     `not available from the admin panel`. The allowlist is in
     core/webui.py:46-75; `{}` matches one path segment `[^/]+`; the method
     must match exactly.
   - For a method other than GET: the `X-CSRF-Token` header must equal
     `session.csrf` (constant-time), else 403
     `missing or wrong CSRF token`. Then log at info:
     `admin panel: <user> <METHOD> <path>`.
   - Set `request.state.admin_user = session.user` and allow.

   If the session is invalid or absent, fall through to step 2.
2. **Token path.**
   - If `settings.admin_token` is empty: 503
     `admin API disabled: ADMIN_TOKEN not configured`. This happens even
     for unauthenticated callers.
   - Otherwise the credential must equal the token
     (`hmac.compare_digest`). If not:
     - When a credential was presented: record security_log
       `bad_admin_token`.
     - Return 401 `invalid admin token`. A missing header gives the same
       401, without a log entry.
   - Set `admin_user = "admin token"`.

Panel allowlist (verbatim, core/webui.py:46):
- `GET`: `/admin/agents`, `/admin/rules`, `/admin/daemons`, `/admin/hosts`,
  `/admin/broker-key`, `/admin/projects`, `/admin/log/decisions`,
  `/admin/log/commands`, `/admin/log/commands/{}`, `/admin/a2a/graph`,
  `/admin/a2a/threads/{}`, `/admin/models/usage`, `/admin/connectors`,
  `/admin/chat/peers`, `/admin/chat/threads`, `/admin/chat/threads/{}`.
- `POST`: `/admin/connectors/{}/revoke`, `/admin/chat/threads`,
  `/admin/chat/threads/{}/messages`, `/admin/chat/threads/{}/close`,
  `/admin/agents`, `/admin/agents/{}/rename`, `/admin/agents/{}/rotate-key`,
  `/admin/agents/{}/disable`, `/admin/daemons/pairing-codes`.
- `PATCH`: `/admin/agents/{}/attributes`.
- `DELETE`: `/admin/rules/{}`, `/admin/daemons/{}`.

Everything else under `/admin` is token-only: decide, revoke, set-kind,
set-webhook, rotate-webhook-secret, rotate-lldap-password, containment,
arm, disarm, lockdown, unlock, `/admin/requests`.

### 3.4 Policy-gated agent routes
- Audit: `policy.audit.readers`. Containment:
  `policy.containment.agents`.
- Each entry is a name glob (str) or an `AgentMatch`, matched with
  `agent_matches` (policy/agents.py:63).
- A non-member gets 404 `{"detail":"Not Found"}`, indistinguishable from a
  missing route.

### 3.5 Security log (core/security_log.py)

- In memory, a deque of 5000 items, emptied on restart. Each `record`:
  - appends `{kind:"security.<k>", id:"s<n>", at:now, client, path, **fields}`;
  - stringifies non-null field values and cuts them to 300 chars;
  - logs a WARNING on logger `agent_auth.security`.
- `client` is the `X-Real-IP` header if present, else the peer address.
- Kinds emitted:
  - `bad_key`: reasons `malformed`, `unknown key`, `disabled`, `operator`,
    `wrong secret`, `oauth token`.
  - `bad_admin_token`.
  - `credential_refused`.
  - `containment_lifted`, from core/lockdown.py, including hostexec unlock's
    `lift_where`.
- `since(when, limit)` returns the **oldest** `limit` items with
  `at >= when`.

### 3.6 Security invariants

- **INV-1**: Every `/v1/*` route except `/v1/tokens/verify` and
  `/v1/daemons/pair` (and the daemon WebSocket) authenticates the caller as
  an enabled, non-operator agent before any state is read or changed.
- **INV-2**: Every `/admin/*` route requires either the configured admin
  token (constant-time compared) or a valid admin-panel session. A panel
  session may call only allowlisted (method, path) pairs, and must present
  a matching `X-CSRF-Token` for every non-GET.
- **INV-3**: No route that changes state accepts an unauthenticated caller.
  The only unauthenticated routes are `/healthz`, the token-issuer
  `.well-known` documents, `/v1/tokens/verify` (read-only),
  `/v1/daemons/pair` (one-time code proof) and the delegated OAuth/UI
  flows.
- **INV-4**: An agent with `kind == "operator"` can never authenticate with
  an API key. No admin route will give the operator row a key, a webhook,
  a kind change, attributes or a new name. No agent may be created or
  renamed to `operator`.
- **INV-5**: An agent can read or act only on its own requests and grants.
  A foreign or unknown id answers exactly like a missing one (`404 unknown
  request` / `404 unknown grant`; retry/escalate `409 unknown request`).
- **INV-6**: A credential is issued only if all of these hold:
  - the grant is the caller's;
  - the caller is not contained;
  - a delegated grant's thread is `open`;
  - (provisioner-checked today, to be centralized in Rust) the grant is
    `active` and `expires_at > now`.
- **INV-7**: `api_key` appears only in the responses of
  `POST /admin/agents` and `POST /admin/agents/{id}/rotate-key`.
  `webhook_secret` appears only in the create, rotate-webhook-secret and
  set-webhook responses. Neither appears in `/v1/me` or any listing.
  Stored keys are sha256 hashes only.
- **INV-8**: Every client-supplied long-poll duration is clamped to its
  range before use, and NaN maps to the lower bound. No non-finite value
  reaches a timer.
- **INV-9**: A policy-gated route (audit, agent containment) gives a
  non-member the same 404 as a nonexistent route. Its request body is not
  parsed before membership is established. (Rust: query parameters too; see
  §8.)
- **INV-10**: When a non-empty `X-Agent-Session` is sent, it must name an
  open session of the same agent, or the request is 401. A thread bound to
  a session is invisible and unusable to every other session and to the
  sessionless caller of the same agent (403).
- **INV-11**: `last_listen_at` changes only through the a2a inbound
  surfaces (events, accept, the message long-poll). No other authenticated
  call makes an agent reachable.
- **INV-12**: A contained agent:
  - gets no new grant (requests are recorded denied);
  - cannot retry or escalate (409);
  - gets no credential (403);
  - cannot write or delete wiki pages (403);
  - cannot open, accept or send on threads with non-operator peers, and
    cannot be opened to (403).
- **INV-13**: An agent can never lift a containment. An agent can contain
  "every agent" (`{}`) only when `containment.allow_all` is set. (Rust:
  enforce on the *meaning* of the match, not its syntax; see §8.)
- **INV-14**: The responses of `/v1/a2a/threads/{id}/messages` reproduce
  stored payload objects exactly.
- **INV-15**: `/v1/tokens/verify` returns 200 only when all of these hold:
  - the token verifies for the server's audience;
  - `claims.server == server`;
  - the referenced grant is mcp, has `resource == server`, is `active`, and
    is unexpired;
  - its agent is not disabled.

  Otherwise it returns 401 with no body.
- **INV-16**: Failed agent-key and admin-token authentications (with a
  presented credential) are recorded in the security log with the client
  address and path. The raw secret is never logged; only `key_id`.
- **INV-17**: OpenAPI and docs endpoints are never served.
- **INV-18**: An agent payload, topic or webhook URL is validated at the
  edge:
  - payload ≤16384 (Python `json.dumps` length);
  - topic has no control characters and is ≤256;
  - webhook_url is http(s) with a host.

---

## 4. Catalog (`GET /v1/catalog`)

Built by `build_catalog` (api/catalog.py:55). Output is
`{"platforms": [PlatformCatalog...]}` in this fixed order, each only if its
condition holds:

| # | platform | condition | fields |
|---|---|---|---|
| 1 | github | registry has GITHUB | `capability_hint:"repo"`, `resource_hint:"owner/repo"`, `repo_allowlist: gh.repo_allowlist or ["<any>"]`, `permission_ceiling: gh.permission_ceiling`, `create_owners: list or omitted`, `create_disposition: disposition(github,"create") if create_owners else omitted`. The denylist is never shown. |
| 2 | agents | `agent.sandbox_id` and registry has AGENTS | `capability_hint:"mint"`, `resource_hint:"<runtime>-<project>-<this host>-sandbox"`, `capabilities: list(policy.platforms.agents.runtimes)` |
| 3 | sandbox | `agent.sandbox_id` and `agent.project` and registry has SANDBOX | `capability_hint:"project.read \| project.write (write: always a human)"`, `resource_hint:"<another project in this agent VM>"`, `capabilities:["project.read","project.write"]` |
| 4 | hostexec | registry has HOSTEXEC and the hosts list is non-empty | `capability_hint:'run \| tpl.<template> \| shell (root and every shell: always a human)'`, `resource_hint:"<host>"`, `capabilities:["run","shell", "tpl.<name>" for each policy hostexec template]`, `hosts` (below) |
| 5 | mcp | registry has MCP | `capability_hint:'use (scope {"tools": [...]}; omit for every tool)'`, `resource_hint:"<server>"`, `capabilities:["use"]`, `servers:[{name,url,description,tools or null}]` sorted by name |
| 6 | models | registry has MODELS | `capability_hint:"use"`, `resource_hint: gw.name`, `capabilities:["use"]`, `gateway:{name,url,models or null}` |
| 7 | homelab | registry has HOMELAB | `capability_hint:"group"`, `resource_hint:"<lldap group>"`, `groups:[{name, description?}]` for each allowed group, in policy order |
| 8 | kubernetes | registry has KUBERNETES | `capability_hint:"<role name>"`, `resource_hint:'<namespace>, or "*" for cluster-wide'`, `namespace_allowlist` (always present, may be `[]`), `roles:[{name, description?, typical_disposition}]` for each role in `role_allowlist` order, `cluster_roles: list or omitted` |
| 9 | a2a | registry has A2A | `capability_hint:"talk"`, `resource_hint:"<agent name>"`, `peers` (below) |
| 10 | google | registry has GOOGLE | `capability_hint:"<calendar.read \| gmail.read \| ...>"`, `resource_hint:"<calendar id / label / folder>"`, `capabilities: sorted(google_stub._KNOWN_CAPABILITIES)` |

(The `\|` in the table is a literal `|` in the strings.)

### 4.1 Typical disposition (api/catalog.py:24)

1. Build a transient `AccessRequest` probe: `{agent_id, platform, capability, resource:"*", scope:{}, justification:"", requested_duration_secs:0}`, with `authority = fold(platform, capability, {})`.
2. Run `engine.evaluate(session, agent, probe)`.
3. If the action is APPROVE or LLM, `decision.explicit` is false, and
   `engine.needs_explicit_rule(probe)` is true (github `create`), the
   result is `"human review"`.
4. Otherwise map the action: APPROVE→`auto-approve`, SURFACE→`human review`,
   LLM→`llm review`, DENY→`denied`. Anything else falls back to the action's
   value.

The probe is not persisted. It does not apply the sensitive-capability gate,
zones or `human_only`. It is best-effort and errs toward the catch-all,
because resource-specific rules don't match `"*"`.

### 4.2 Peers (a2a)

- All agents except the caller with `disabled = false` and `kind = 'service'`
  (so ephemeral and operator rows are excluded), and not
  `Zones(policy).apart(caller, peer)`.
- Each peer is `PeerEntry` built from `reachability(peer, a2a_listen_threshold_secs)`:
  - `name`, `description` (null if empty), `kind`.
  - `addressable`, `reachable`, `why`.
  - `last_seen_at` and `last_listen_at`, as isoformat strings.
  - `has_webhook`.
- Reachability:
  - Kind ≠ service: `addressable:false, reachable:false, why:"ephemeral"`.
  - Has a webhook: `true, true, "webhook"`.
  - Else `true`, with `reachable = last_listen_at is not null and now - last_listen_at <= threshold`, `why = "polling" | "idle"`.
- Sort key `(not reachable, name)`: reachable peers first, then
  alphabetical.

### 4.3 Hosts (hostexec)

From `hostexec.hosts()`, computed whenever `app.state.hostexec` is set.
Each host is
`{name, online, lockdown, tiers: {tier: {armed: bool(armed_until), shell: bool(shell)} for enabled tiers only}, templates}`.
`vm` and `desktop` are omitted for agents.

---

## 5. Serialization

### 5.1 Timestamps

Every datetime is timezone-aware UTC (`TZDateTime`, models.py:40). Writing a
naive datetime is an error. There are two encodings on the wire:

- **pydantic response models** use `Z` and print fractional seconds only
  when non-zero, at 6 digits: `2026-01-01T00:00:00Z`,
  `2026-01-01T00:00:00.000005Z` (observed). Used by: `RequestOut`,
  `GrantOut`, `CredentialOut`, `SessionOut`, `AgentOut`, `A2ACheckOut`,
  `RuleOut` (no datetime fields), `CatalogOut`.
- **Plain dicts** (routes without a response model, or `.isoformat()` in
  core) use `+00:00`, with the same fractional rule: Python `isoformat()`
  omits `.ffffff` when microseconds are 0. Used by: the whole a2a thread,
  message and events surface, `PeerEntry.last_seen_at` and
  `last_listen_at` (str fields), audit, admin logs, graph, pairing-code
  `expires_at`, containment `at` (`timespec="seconds"`), wiki
  `last_change.at` (GitHub's string, passed through).

Rust: any RFC 3339 output with an offset is acceptable to the existing
clients (the Python client and MCP server parse with `fromisoformat`).
**Cursors (`/v1/a2a/events` `cursor`, audit `next`) must keep microsecond
precision.** Clients must URL-encode a `+00:00` cursor in a query string.

### 5.2 RequestOut (schemas.py:60; built in api/serialize.py:41)

Fields, all always present (no exclude_none):
- `id`
- `agent`: the requester's name, or `"?"` if missing
- `platform`
- `capability`, `scope`: from `authority.split(platform, authority)`
- `resource`
- `justification`
- `requested_duration_secs`
- `status`
- `attempt`
- `decision_source`
- `decision_reason`
- `approved_duration_secs`
- `approved_scope`: `split(platform, approved_authority)[1]`, or null if no
  approved authority
- `approved_resource`
- `grant_id`: the grant whose `request_id` is this request
- `delegator`: the name, `"?"` if missing, null if not delegated
- `delegation_thread_id`
- `created_at`
- `guidance`

`guidance` (serialize.py:12-38) is a template keyed by status, with `{id}`
replaced by the request id and `{grant_id}` by the grant id or `"?"`. It is
null for `pending`, `approved` and `provisioning`. The texts:
- `llm_denied`:
  `Denied by LLM review — see decision_reason. Retry with a revised justification that answers it (retry_request / POST /v1/requests/{id}/retry), or ask for human review (escalate_request / POST /v1/requests/{id}/escalate).`
- `awaiting_human`:
  `Waiting for a human decision on Discord; this can take a while. Keep waiting (wait_for_decision / GET /v1/requests/{id}/wait).`
- `llm_evaluating`:
  `Under LLM review. Keep waiting (wait_for_decision / GET /v1/requests/{id}/wait).`
- `granted`:
  `Granted. If the grant carries a credential (a token, an account, a created repo's URL), fetch it with get_credential("{grant_id}") / GET /v1/grants/{grant_id}/credential — and re-fetch rather than caching it.`
- `denied`:
  `Denied — see decision_reason. Final: don't resubmit it unchanged. A narrower request, or one with a materially better justification, is a new request.`
- `provision_failed`:
  `Approved, but setting it up failed (see decision_reason). Not your request's fault; tell the user, or try again later as a new request.`

**Hidden from agents** (never on RequestOut):
- `authority` and `approved_authority` (raw)
- `risk_notes`
- `decided_by`, `decided_at`
- `session_id`
- `updated_at`
- the Discord ids
- `delegator_agent_id` (only the name is shown)
- LLM evaluation rows

### 5.3 GrantOut and the authority split

GrantOut fields: `{id, request_id, agent, platform, capability, resource, scope, granted_at, expires_at, status, delegator, delegation_thread_id}`.

Hidden: `authority` (raw), `revoked_at`, `revoke_reason`,
`delegator_agent_id`, and provisioner state or secrets.

`authority` is the single stored truth (authority.py). Requests take
(capability, scope), which `fold` turns into authority. Responses carry
`split(authority)`. Per platform:

| platform | fold(capability, scope) | split(authority) |
|---|---|---|
| github | `create`: `{action:"create", visibility: scope.visibility or "private"}`; else `{permissions: scope.permissions or {}}` | `("create", {visibility})` or `("repo", {permissions})` |
| kubernetes | `{role: capability}`, plus `cluster:true` if `scope.cluster` is truthy | `(role or "", {cluster:true} or {})` |
| a2a | `dict(scope)` | `("talk", dict(authority))` |
| google | `{action: capability}` | `(action or "", {})` |
| agents | `{action: capability, runtime: scope.runtime}` | `(action or "mint", {runtime})` |
| sandbox | `{access: capability}` | `(access or "", {})` |
| hostexec | shell: `{action:"shell", tier}`; `tpl.<t>`: `{action:"tpl", template:t, params, tier, cwd, env, timeout, stdin}`; else `{action:"run", argv, tier, cwd, env, timeout, stdin}` | shell or window: `("shell"\|"run", {tier})`; tpl: `("tpl.<t>", {non-empty of tier,cwd,env,timeout,stdin} + params)`; run: `("run", {non-empty ...} + argv)`. Empty means `None`, `{}` or `""`. |
| mcp | `{tools: ["*"] if "*" in set else sorted(set(str(t)))}`, where the set defaults to `["*"]` | `("use", {tools})` |
| models | `{action:"use"}` | `("use", {})` |
| homelab | `{}` | `("group", {})` |

`label()`, used in admin and audit `what`:
- github: `create:<vis>`, or `k:v+k:v` sorted, or `repo`.
- k8s: `role`, or `role (cluster-wide)`; `*` if there is no role.
- agents: `mint:<runtime|?>`.
- mcp: `all tools`, or the tools comma-joined.
- hostexec: `approve-all:<tier>`, `tpl.<t>:<tier>`, or `<action|*>:<tier>`.
- Other platforms: `split()[0]`, or `*`.

### 5.4 Enums and exclude_none

- Enums serialize as their lowercase `.value`:
  - platform;
  - RequestStatus: `pending llm_evaluating llm_denied awaiting_human approved provisioning granted provision_failed denied`;
  - DecisionSource: `policy rule llm human`;
  - GrantStatus: `provisioning active expired revoked provision_failed`;
  - RuleAction: `auto_approve auto_deny`.
- Agent kind and thread state are plain strings.
- `response_model_exclude_none=True` drops only None-valued **model** fields.
  It does not descend into `dict[str, Any]` values (observed). So
  `servers[].tools: null` and `gateway.models: null` are emitted as null,
  while a None `PlatformCatalog.roles` is omitted. In `CatalogEntry`, a None
  `description` or `typical_disposition` is omitted (nested models).
- Datetimes from SQLite are naive, and the column type re-tags them as UTC.
  With Postgres `timestamptz` they are already aware. Rust/PG: always
  `timestamptz`.

---

## 6. Middleware and transport

1. **No CORS**: no CORS middleware. `OPTIONS` gets 405 (observed), and no
   `Access-Control-*` headers are sent. Rust must not add permissive CORS:
   the admin panel is same-origin.
2. **No body size limit**: uvicorn has no default limit, and the app adds
   none. The only caps are field-level (§2) and the 1 MiB WebSocket
   message cap. Rust should add a global limit (suggested 1 MiB; the wiki
   page cap is 64 KiB and the a2a payload 16 KiB, but `scope` is
   uncapped).
3. **Docs disabled**: `docs_url`, `redoc_url` and `openapi_url` are all
   None, so 404.
4. **Error shapes**:
   - `HTTPException(status, "text")` gives `{"detail": "text"}`, with
     content-type `application/json`.
   - `HTTPException(404)` with no detail gives `{"detail": "Not Found"}`
     (Starlette's phrase).
   - Unknown route: 404 `{"detail":"Not Found"}`. Wrong method: 405
     `{"detail":"Method Not Allowed"}` with an `Allow` header. `HEAD` on a
     GET route is 405 (observed).
   - Request validation gives 422
     `{"detail":[{"type","loc":[...],"msg","input","ctx"?}]}`. For example,
     `{"type":"missing","loc":["body","capability"],"msg":"Field required","input":{...}}`.
     Invalid JSON gives `{"type":"json_invalid","loc":["body",<pos>],"msg":"JSON decode error","input":{},"ctx":{"error":"..."}}`.
     Agents don't parse these lists; matching the status code and the
     top-level `detail` key is enough.
   - Some handlers raise 422 with a **string** detail:
     - decide: bad duration;
     - audit: bad `since`;
     - containment: bad body or match;
     - lockdown: ValueError.
   - An unhandled exception gives 500 with a `text/plain` body
     `Internal Server Error` (Starlette ServerErrorMiddleware).
   - Order of checks (observed):
     - A body that is not valid JSON gives 422 **before** authentication.
     - Schema-invalid bodies and bad query params give 401 first when
       unauthenticated.
     - Once authenticated, query and body validation run before the
       handler. That ordering is the audit 404 leak.
     - Rust should authenticate first.
5. **Trailing slash**: Starlette redirects `/v1/me/` to `/v1/me` with a 307
   (observed). Not required for clients.
6. **Request logging**:
   - uvicorn's access log at `info`: method, path and query string, status,
     client. No secrets travel in query strings.
   - `admin panel: <user> <METHOD> <path>` (info) for panel writes.
   - security_log WARNINGs.
   - set-kind and rename info lines.
   - Nothing logs request bodies or bearer tokens.
7. **Proxying**: uvicorn defaults (`proxy_headers=True`,
   `forwarded_allow_ips=127.0.0.1`), so `request.client` honors
   `X-Forwarded-For` from localhost. The security log prefers `X-Real-IP`
   unconditionally.
8. **Lifespan**: when remote MCP is enabled, its session manager runs for
   the app's lifetime (app.py:45-53).
9. **In-process events**: `KeyedEvents` (core/events.py) is single-process.
   - `notify(key)` sets and replaces the key's Event.
   - Long-polls also recheck every ≤2 s, so a missed wake costs at most 2 s.
   - Two separate instances: request decisions (`app.state.events`) and
     a2a (`app.state.a2a_events`).
   - A Rust port on Postgres may use LISTEN/NOTIFY or an in-process
     broadcast, but must keep the ≤2 s recheck.

---

## 7. Tests worth porting

From tests/test_api.py:
- `test_auth_rejections`: no header, `aa_bogus_key` and `garbage` all give
  401; a valid key gives 200 with the name.
- `test_admin_auth`: no token or a wrong token gives 401; the right one
  gives 200.
- `test_admin_create_agent_shows_key_once`: create returns `api_key`
  starting `aa_`; a duplicate name is 409; listings show `api_key: null`;
  the key authenticates.
- `test_request_flow_via_api`: an a2a request is `awaiting_human` with
  guidance mentioning "Discord". `/wait` returns `granted` after a
  concurrent decide (duration 600, `grant_id` set). `/v1/grants` lists it.
  The credential `kind == "a2a_grant"`.
- `test_request_isolation_between_agents`: another agent's request is 404.
- `test_a2a_thread_smoke`: check before a grant gives allowed false; open
  gives 403. After an auto-grant, check is allowed but unreachable (`idle`),
  so open is 409. One events poll makes the peer `polling`. Check
  direction=in works. A fast-open is `pending_open`. The pending open is
  listed in events. A reply is an implicit accept with seq 2. A cursor read
  works. Close gives `closed/closed`. The legacy routes give 404/405.
- `test_admin_rules_and_revoke`: revoking makes check allowed false, and
  `/admin/requests` lists the request.
- `test_admin_decide_endpoint`: decide with `duration:"10m"` gives granted
  with 600 s; a second decide is 409.
- `test_catalog`:
  - k8s roles carry descriptions and dispositions (view auto-approve, edit
    human review);
  - github allowlist and ceiling;
  - peers exclude self and ephemeral agents; an idle peer is `idle`;
  - a webhook peer is `webhook`/reachable and sorts first;
  - None fields are omitted.
- `test_catalog_requires_auth`: 401.
- `test_webhook_url_validated`: `ftp://` gives 422; https gives 200.
- `test_field_size_caps`: a 5000-char justification is 422; a 20000-char
  payload is 422.
- `test_invalid_duration_rejected`: `"sometime"` gives 422.

From tests/test_a2a.py (API parts):
- `test_session_lifecycle`: a session's `name` has the label prefix and
  `/v1/me` shows it. A bogus session, a closed session and another agent's
  session all give 401.
- `test_explicit_accept_and_close`: only the responder may accept (403); a
  second accept is 409; after accept the initiator sends seq 2; after close,
  a send is 409.
- `test_reject`: gives `closed/rejected` with `close_note`, and the
  initiator sees it.
- `test_initiator_cannot_send_on_pending_open`: 409.
- `test_non_participant_gets_404`: get and send both 404.
- `test_responder_session_binding`:
  - pending opens are visible only sessionless;
  - a sessioned accept binds the thread, and the dispatcher and other
    sessions get 403;
  - the list is session-filtered;
  - the worker's events poll wakes on the initiator's message.
- `test_implicit_accept_binds_replying_session`: a sessioned reply binds;
  a sessionless accept does not.
- `test_responder_session_death_closes_thread`: `peer_alive` follows the
  bound session's last_seen.
- `test_grants_shared_across_sessions`: one grant serves all sessions; an
  ephemeral agent opening without a session gets 400.
- `test_thread_access_bound_to_session`: session B gets 403 on A's thread
  for get, read, close and send, and B's list and events are empty. An
  ephemeral agent without a session gets 400 on get, read, list and events.
- `test_ephemeral_cannot_receive`: the request is denied ("service
  agents"); a manufactured grant still gives open 403 "ephemeral".
- `test_topic_glob_enforced_at_open`: a grant for `deploy/*` allows
  `deploy/cactus` and refuses `gossip` and topic-less opens. Check without
  a topic is allowed; check with a mismatched topic is not.
- `test_message_longpoll_wakes_on_reply`: wakes in under 5 s; an empty
  wait returns `[]`.
- `test_events_longpoll_and_cursor`: wakes on open; the cursor advances;
  pending opens persist across cursors.
- `test_grant_revocation_closes_thread`: a send after revoke is 403 and the
  thread is `grant_revoked`; the responder's send is then 409.
- `test_peer_liveness_fields`: `peer_alive` true, then false after aging.
- `test_requesting_access_does_not_make_a_peer_reachable`: `/v1/me` and
  `/v1/grants` don't set `last_listen_at`. Check gives allowed with
  unreachable `idle` and a reason containing "not listening"; open is 409.
  After an events poll, open is 200.
- `test_listening_ages_out`: 409 after `last_listen_at` is older than the
  threshold.
- `test_ephemeral_peer_is_403_not_409`: 403 "initiate-only"; check shows
  `addressable:false`, `why:"ephemeral"`.
- `test_set_kind_demotes_and_orphans_inbound_threads`: the response has
  kind ephemeral and no `webhook_url` key; the key still works; the thread
  is `peer_gone`; the agent leaves the catalog; open is 403; the secret is
  cleared.
- `test_set_kind_promotes_back_to_service`: the open is 409 until it
  listens.
- `test_set_kind_demotion_revokes_grants_targeting_it`: the grant is
  revoked with "ephemeral" in the reason; it does not come back after
  re-promotion ("no active a2a grant").
- `test_set_kind_rejects_garbage`: 422 for a bad kind, 404 for an unknown
  id.
- `test_set_webhook_on_existing_agent`: set returns a secret; `ftp` is 422;
  `{}` clears the URL and secret.
- `test_rotate_webhook_secret`: a new secret; never in `/v1/me` or
  listings.
- `test_legacy_null_thread_messages_invisible`: thread-less messages appear
  nowhere.
- `test_payload_keys_survive_verbatim`: `_sandbox` and `_sample` keys
  round-trip.
- Webhook tests (`test_webhook_ping_shape_and_signature`,
  `_global_secret_fallback`, `test_unsigned_pings_never_sent`): port with
  the a2a spec. At the HTTP level they check that a webhook failure never
  fails the API call.

From tests/test_wiki.py (API parts):
- `test_an_agent_writes_its_own_projects_pages_and_everyone_reads_them`:
  PUT gives `created:true`, and the commit author and message trailer are
  set. Other agents read, search and list; `you_may_write` is
  `["projects/<p>/"]`.
- `test_an_agent_cannot_write_outside_its_project` (4 paths): 403 with
  `projects/task-tracker/` in the detail; delete is 403 too.
- `test_an_agent_without_a_project_reads_and_cannot_write`: 403 "no project
  on record"; `you_may_write` is `[]`.
- `test_an_editor_writes_shared_pages`: with base_sha it works;
  `you_may_write` is `["(every page)"]`.
- `test_a_page_that_exists_is_replaced_only_from_the_version_read`: a blind
  write is 409 mentioning `base_sha`; a stale one is 409 "changed since you
  read it"; a delete needs base_sha.
- `test_a_path_is_plain_segments_ending_in_md` (7 paths): PUT and GET both
  400.
- `test_a_page_with_a_credential_in_it_is_refused` (4 secrets): 400 with
  "where" in the detail.
- `test_size_empty_and_missing`: 413 over max, 400 for blank, 404 for a
  missing page, 400 for a blank search.
- `test_no_key_no_wiki_and_no_wiki_configured`: 501 with a key, 401 without.
- `test_a_held_agent_reads_but_writes_nothing`: PUT and delete 403
  "contained"; reads are 200.

From tests/test_containment.py (API parts):
- `test_a_held_agent_loses_its_grants_and_gets_nothing_new_until_lifted`:
  admin contain returns `agents` and `grants_revoked`. The credential is
  403. The list and lift by id work.
- `test_containing_denies_pending_requests_and_takes_the_agent_out_of_a2a`:
  `requests_denied:1`; an open to the held agent is 403 "contained"; after
  lift it is 409 "not listening".
- `test_an_allowed_agent_may_contain_but_not_everyone_and_not_lift`:
  - a non-member gets 404, even with a garbled body;
  - a member gets 200 with `by` and `source:"agent"`;
  - `{}` is 403;
  - a bogus key is 422;
  - the admin lift with an agent key is 401;
  - `allow_all` makes `{}` 200.

New tests the Rust port should add for the §8 items it fixes:
- non-ASCII admin bearer gives 401;
- audit non-reader with `limit=x` gives 404;
- `{"name":"*"}` contain without `allow_all` gives 403;
- `requested_duration` over the cap gives 422;
- a NaN `wait`/`timeout` returns promptly.

---

## 8. Suspected bugs and questionable behavior in the Python

1. **Non-ASCII admin bearer: 500.** `hmac.compare_digest(str, str)` raises
   `TypeError` for non-ASCII strings. A header such as `Bearer \xe9` (bytes
   are latin-1-decoded) crashes `require_admin` (deps.py:171, observed),
   and no security_log entry is written. The CSRF compare (deps.py:161) has
   the same flaw. Rust: compare bytes in constant time, and answer
   401/403.
2. **Agent containment can contain everyone without `allow_all`.** Only the
   literal `match == {}` is refused (containment_routes.py:84). `AgentMatch`
   defaults `name` to `"*"`, so `{"name": "*"}`,
   `{"kind": ["service","ephemeral"]}` or
   `{"placement": ["host","sandbox"]}` match every agent and pass. Rust
   should refuse any match equivalent to "everyone". At minimum:
   - all field filters absent, with `name` being `*`;
   - or, better, a match that would hold all current non-operator agents.
3. **The audit route leaks its existence.** FastAPI validates `limit: int`
   before the handler runs `_allowed`, so an authenticated non-reader
   sending `?limit=x` gets 422, not 404 (audit_routes.py:62, observed).
   The module docstring promises "404, before the query is read".
4. **Unbounded durations.**
   - `requested_duration` has no maximum, and `requested_duration_secs` is
     an `Integer` column. On Postgres (int4), anything over 2147483647 s
     (e.g. `"3551w"`) fails the INSERT, giving 500. (On SQLite it was
     stored as 6.0e16, observed.)
   - JSON `true` is accepted as 1 s and `1.0` as 1, because Python bool is
     an int and pydantic coerces integral floats.
   - Rust: reject bool and float; cap at, say, the int4 range or a policy
     maximum, returning 422.
   - `DecideBody.duration` likewise.
5. **Query params that reach Postgres unchecked.**
   - `/admin/requests?limit=-1` gives `LIMIT -1`: PG raises (500), while
     SQLite treats it as unlimited (observed 200).
   - `/admin/log/decisions?source=bogus` compares a native PG enum with an
     invalid label: 500 on PG, `[]` on SQLite.
   - Rust: clamp `limit` to ≥1, and validate `source` against the
     DecisionSource enum (unknown: 422, or empty result).
6. **The credential route doesn't check grant status or expiry itself**
   (agent_routes.py:217-249). The check relies on each provisioner:
   - hostexec checks status but not expiry;
   - a2a, google, agents and sandbox check nothing.

   Harmless today (those return no secrets), but fragile. Also, if a
   platform is disabled after a grant exists, `registry.get` raises an
   uncaught `SpecValidationError`, giving 500.
7. **Retry/escalate return 409 `unknown request` for a foreign or missing
   id**, while GET returns 404 (core/service.py:1162). Inconsistent, though
   it leaks nothing. Keep 409 for client compatibility, or document the
   change.
8. **No request-body size limit anywhere.** `RequestCreate.scope`,
   `DecideBody.scope_override`, `PageWrite.content` (checked against
   `max_page_bytes` only after the full parse) and `ContainBody.match` are
   all uncapped. `scope` is stored and rendered to Discord and the LLM.
9. **`last_listen_at` is not refreshed inside the events long-poll.**
   `GET /v1/a2a/events` calls `mark_listening` once per call
   (a2a_routes.py:245); the loop only calls `_touch_caller`. A dispatcher
   polling with `wait` near 300 s (the cap), against the default 300 s
   listen threshold and the 20 s write throttle, can have a
   `last_listen_at` older than the threshold mid-poll. Opens to it then
   fail 409 "not listening" although it is parked on the poll. The default
   `a2a serve` wait of 60 s avoids it. Rust: call `mark_listening` in the
   loop as the messages poll does.
10. **`_touch_caller` writes every ≤2 s per parked long-poll, unthrottled**
    (a2a_routes.py:315). This is write amplification proportional to the
    number of pollers. The 20 s throttle used elsewhere would suffice.
11. **`/v1/a2a/check` doesn't exclude disabled peers**
    (a2a_routes.py:279-284). It can answer `allowed:true` with reachability
    for an agent that `open` would answer 404 `unknown agent`. It also
    reports the operator row (if named) as `why:"ephemeral"`.
12. **security_log trusts `X-Real-IP` from any caller** (security_log.py:43).
    If the broker is reachable other than through nginx, a caller can forge
    the `client` field of its own failed-auth records.
13. **Missing operator and VM guards.** `/admin/agents/{id}/disable` has no
    `_not_operator`, so disabling the operator row is allowed.
    `rotate-key`, `rotate-webhook-secret`, `set-kind` and `set-webhook` do
    not refuse VM-minted agents (`sandbox_id`), unlike `attributes` and
    `rename`. Rotating a minted agent's key breaks the sandbox daemon's
    copy.
14. **Create mints a webhook secret for an ephemeral agent** when
    `webhook_url` is given (admin_routes.py:86). `set-kind` to ephemeral
    clears both. `set-webhook` also accepts ephemeral agents. A webhook on
    an ephemeral agent is meaningless (reachability says `ephemeral` first)
    and leaves a stray signing secret.
15. **`POST /admin/containment/lift` with `{}` lifts every containment**
    (`id` defaults to None; containment_routes.py:33). A one-character
    mistake undoes all holds. Consider requiring an explicit
    `{"all": true}`.
16. **Audit pagination edge cases.**
    - `truncated` is `len(events) == limit`, which is true at an exact
      boundary.
    - If more than `limit` items share one `at` value, `next` doesn't
      advance and the reader loops forever.
    - `security_log.since` returns the oldest `limit` items, which is
      consistent, but its items vanish on restart.
17. **`KeyedEvents` never forgets keys** (core/events.py). `notify`
    re-arms a fresh Event for every request id or agent id ever notified,
    and `wait` creates entries. `discard` is never called from the API, so
    the dict grows for the process lifetime.
18. **`/v1/attention` spends a rate-limit slot before delivery.** If the
    Discord notifier raises, the caller gets 500 and has lost one of its 6
    hourly slots (core/attention.py:42-44).
19. **Mixed timestamp formats.** `Z` comes from pydantic and `+00:00` from
    dicts (§5.1). Not a bug, but a client that string-compares or naively
    builds query strings (an unencoded `+`) breaks. Rust should pick one
    format and keep microseconds.
20. **Invalid JSON is rejected before authentication** (§6.4, observed).
    An unauthenticated client learns nothing useful, but it is
    inconsistent with "auth first".
