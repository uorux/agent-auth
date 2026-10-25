# Deliberate differences from the Python

Each entry: where (spec section), what the Python did, what the Rust does,
and why. Keep entries short. Group by area.

## Core

- **Globs** (core-lifecycle-policy §5.1). A reversed range like `[z-a]`
  matches nothing; CPython merges neighbouring chunks of the set (and can
  raise on some inputs; `[z-?!]` even becomes "any character"). Ordinary
  patterns behave identically: a differential test against CPython's
  `fnmatchcase` on 30 000 generated pattern/text pairs agrees on all of
  them except patterns with a reversed range (`glob::tests::agrees_with_cpython`).
- **Authority scopes are strict** (§6.1). Unknown scope keys are refused at
  request time on every platform. The Python ignored them on most platforms
  and stored an a2a scope verbatim (any keys) as the authority.
- **Stored authorities are canonical** (§6). A stored authority that this
  version would not have written (extra keys, wrong types) is an error
  rather than being read loosely.
- **Database**: Postgres only; a new schema (no migration from the Python's).

- **Ids parse only in canonical form**, from text and from JSON alike
  (lowercase, hyphenated).

## Policy

- **Unknown keys are errors everywhere** (§5.2, bug B-1). Every section of
  the policy file (rules, `match`, `constraints`, `defaults`, `llm`, each
  platform, desktop, notify, containment, audit…) refuses keys it does not
  know. The Python ignored them outside six sections, so `match: {agnet: x}`
  loaded as a match-everything rule and a rule-level `max_duration` was
  silently dropped. A policy with such a typo now fails to load.
- **YAML strictness** (§5.2). Duplicate keys are an error (PyYAML kept the
  last); unknown tags are refused; a file is at most 1 MiB, and alias
  expansion, nesting depth, node and scalar counts are bounded (alias
  bombs fail to load). Booleans must be YAML booleans and integers
  integers: pydantic's lax coercions (`"3"` for an int, `"yes"` for a bool)
  are gone. `llm.retry_budget` and other counts are unsigned.
- **Hostexec template mirrors are compiled at load** (§5.2). The policy's
  `platforms.hostexec.templates` must have a valid template name, a tier, a
  non-empty argv and parameter patterns that compile (the Python checked
  only the tier and argv).
- **The default never clears a delegated request** (§5.3, bug B-7). With
  `defaults.action: approve|llm`, a delegated request that no rule matched
  surfaces to a human, as a rule written without a delegator would. Deny and
  surface defaults are unchanged.
- **A gone delegator matches no delegator pattern** (§5.3, bug B-18). The
  Python's stand-in agent was named `?` and matched delegator globs `*` and
  `?`; it still keeps rules without a delegator from granting.
- **`explicit` needs the rule's platform and a literal** (§5.3, bug B-16).
  A policy-file rule names a privilege (clearing github create, agents,
  hostexec, mcp, models) only when its `match.platform` is set and
  `match.capability` is a literal pattern (no `*`, `?` or set) equal to the
  capability. `{match: {capability: use}}` written for MCP no longer clears
  model keys, and `capability: "tpl.*"` (string-equal to nothing real, but a
  pattern) never names `tpl.x`.
- **Pinned resources are glob-escaped** (§4.6). A saved rule made from an
  "approve exact" decision stores its resource through `glob::escape`
  (`*`, `?`, `[` as `[*]`, `[?]`, `[[]`), so it matches that resource only;
  the Python stored the resource verbatim as a glob.
- **Saved rules are ordered totally** (§5.3, bug B-22): newest first, the
  rule id breaking ties (`policy::sort_saved_rules`).
- **Containment "everyone" is semantic** (§8.5, bug B-2).
  `AgentPattern::matches_everyone()` is true when the pattern holds every
  possible agent: its name glob matches every name over `[A-Za-z0-9._-]`
  (exactly: `*`, `?*`, `[!/]*`… all count) and no field narrows it
  (`runtime`/`project`/`host` absent, `placement`/`kind` absent or listing
  every value). The containment route must refuse such a match without
  `allow_all`, where the Python only refused a literal `{}`.
- **Durations** (§9.4, bug B-14). Zero is refused on every path (`"0m"`
  parsed to 0), anything over 365 days is refused ("duration must be at
  most 365 days"), and only ASCII digits are digits (Python's `isdigit`
  accepted e.g. Arabic-Indic digits). One type for the wire, the policy and
  the store (see Wire, Durations).
- **Displayed text is display-safe** (job `describe`, risk notes, pattern
  text). Control characters (`\n`, `\r`, ESC…), bidi overrides/isolates
  and zero-width/invisible characters never reach what an approver reads:
  a job argument holding one is shown in bash ANSI-C quoting (`$'a\nb'`,
  `$'\u202e…'`, still the same argument as shell), other text with Python
  escapes (`repr`, `pyfmt::escape_unprintable`). Python's `shlex.join`
  passed them through inside quotes, so an argv could show a harmless fake
  second line.
- **No `make_spec(kind="shell")`** (daemons-hostd §6.2). The Python
  accepted it but nothing used it; a shell is a `ShellSpec`
  (`{"kind","host","tier","duration"}`), and shell commands are `run` specs.
  `JobSpec::from_json` (hostd's view of a raw spec) also refuses unknown
  keys and keys of the other kind (`argv` on a `tpl` job).
- **Template parameter patterns are Rust `regex`** (daemons-hostd §6.4),
  matched in full (`\A(?:…)\z`, after checking the pattern compiles on its
  own). No backreferences, lookaround, `\Z`, possessive or atomic groups:
  such a pattern fails at load instead of at match time. Matching is
  linear-time. `\d`, `\w`, `\s` are Unicode-aware as in Python, with small
  differences at the edges of `\w`/`\s`.

## Credentials

- **One issuance check for every platform** (provisioners §1.5). The
  credential route builds an `IssuableGrant` (own grant, `active`,
  unexpired, agent not held, delegation thread open) before any provisioner
  runs; the Python left status/expiry to each provisioner and several
  checked nothing. Consequence: an expired hostexec run grant no longer
  returns its job summary here; `GET /v1/hostexec/jobs/{id}` still does.
## Store (schema and kernel)

- **Requests keep what was asked** (core §2.3). New columns
  `requested_capability` / `requested_scope` (as submitted), and
  `authority` is NULL only for a request refused before its capability and
  scope parsed (a CHECK allows that only in PENDING/DENIED). The Python
  stored whatever `fold` produced; a strict `Authority` has no value for
  input that does not parse. Elsewhere authorities are NOT NULL (B-21).
- **Status machines in the database** (§3). Triggers refuse request,
  grant, host-job and thread status changes the machines do not allow
  (and inserts in any but the initial status); CHECKs tie decision fields
  to statuses (APPROVED and later need source/decider/duration/time).
  Identity columns (agent, platform, delegation, thread parties) are
  immutable; a grant's expiry only moves earlier.
- **Grant status writes are compare-and-swap** (B-9): activate,
  provision-failed, revoke and expire are `UPDATE ... WHERE status = ...`.
- **Containment entries are rows** (§8.5, B-8): `containment_entries`
  instead of a JSON list in `broker_flags`. `record`/`lift` take an
  exclusive advisory lock; `lockdown::check` takes it shared and holds it
  (and a share lock on the agent row) until its transaction ends, so a
  containment recorded while something is being provisioned or issued
  waits for it, and its sweep then sees the result.
- **Held includes disabled and lapsed** (B-15): `lockdown::check` treats a
  disabled agent, or one whose lease has passed, as held, so nothing is
  provisioned or issued for it; `grants::begin` also refuses when the
  delegator has been disabled.
- **Credentials are checked centrally** (http-api §GET credential): the
  grant must be ACTIVE and unexpired for every platform (the Python left it
  to some provisioners). Text: `grant is not active; refusing to mint a
  token` for github/kubernetes, `grant is not active` otherwise. A delegated
  grant also needs its thread's backing grant live (not only the thread
  open).
- **One operator row** (a2a B11): a unique partial index; creation is
  `INSERT ... ON CONFLICT DO NOTHING`, then select.
- **a2a writes are conditional updates** (a2a B4): accept only from
  `pending_open` (one of two racing accepts wins), messages only on `open`
  threads with `seq` from the same `last_seq` bump, closes only from a
  non-closed state. A bound responder session never changes (trigger). A
  thread's initiator and responder differ (B5), its grant is the
  initiator's (composite FK), and sessions belong to their side's agent.
- **a2a payloads are `json`, returned as text**, so they come back byte for
  byte (jsonb would reorder keys).
- **Key acks name the key** (sandboxd B-6): `pending_key_deliveries.key_id`;
  an ack deletes only the delivery of that key.
- **Lease renewal does not clear a disable** (sandboxd B-1):
  `agents::set_lease` only moves the lease; re-enabling is explicit, and
  `agents.disabled_reason` (`operator` | `lease` | `unpaired`, migration
  0013) records why an agent was disabled; an `operator` reason is never
  replaced by a later one.
- **OAuth one-time use is one UPDATE** (Bug-C2): `oauth::consume` marks a
  code/refresh token used with `used_at IS NULL` in the WHERE; a replay
  revokes the family in the same transaction.
- **Pairing**: at most one unused code per daemon (partial unique index).
- **Rules order** (B-22): `ORDER BY created_at DESC, seq DESC`.
- **Watcher context** (daemons bug 10): earlier shell commands are those
  created strictly before the job, not every other one.
- **Durations** (B-14): integer columns with `> 0` CHECKs; values that do
  not fit are refused (`StoreError::OutOfRange`), never truncated.
## Wire (crates/wire)

- **One timestamp format** (http-api §5.1, §8.19). Every timestamp is RFC
  3339 UTC with exactly six fractional digits and `Z`
  (`2026-01-01T00:00:00.000000Z`). The Python mixed pydantic's `Z` (no
  fraction when zero) with `isoformat()`'s `+00:00`, and containment `at`
  had seconds only. Parsing still takes any offset. Why: one sortable form,
  no `+` to URL-encode in a cursor, microseconds kept for the events
  cursor and audit `next`.
- **Durations** (http-api §2.1 `parse_duration`, §8.4). JSON `true` and
  floats are refused (Python: `true` = 1 s, `1.0` = 1); `"0m"` is refused
  like `0` (Python returned 0); at most 365 days, else 422 `duration
  must be at most 365 days` (Python: no bound, a 500 on Postgres). Same
  for `DecideBody.duration`. Only ASCII digits count (Python's
  `\d`/`isdigit` took other Unicode digits). The wire type *is*
  `core::durations::DurationSecs`, so a request, a decision and the policy
  file accept exactly the same durations.
- **Host durations are bounded** (`ArmBody.duration`, `dnd`; daemons-hostd
  §6.6). `HostDuration` is checked with hostd's own rules
  (`host_duration_secs`: bare digits are seconds) and refused over 365
  days (`MAX_HOST_DURATION_SECS`); hostd's config durations have the same
  bound. The Python passed any value through and parsed it unbounded on the
  host. hostd still caps arming per tier (`max_arm`).
- **Unknown fields in request bodies are refused** (http-api §2.1 "Extra
  fields are ignored"): every agent and admin body is
  `deny_unknown_fields`, so a misspelt field is a 422 instead of silently
  dropped.
- **Size caps** (http-api §6.2, §8.8). `scope`/`scope_override` at most
  512 KiB of compact JSON and 16 levels deep; a containment `match` 4 KiB
  and 8 levels; wiki `content` 1 MiB; decide `reason` 4000; `/v1/attention`
  `urgency` 32 characters; shell `exec` bodies at most 1024 arguments of
  64 KiB, 256 env entries, 256 KiB of stdin (core's spec rules, tighter,
  still answer 400). Daemon messages: specs 512 KiB, status and reply data
  64 KiB, texts bounded. The Python had no caps on these.
- **Lifting every containment is explicit** (http-api §8.15).
  `POST /admin/containment/lift` takes `{"id": "<id>"}` or `{"all": true}`;
  `{}` and `{"id": null}` (which lifted everything) are refused.
- **Catalog peers keep null keys** (http-api §5.4). A peer's `description`,
  `last_seen_at`, `last_listen_at` are `null` when unset in the catalog too
  (Python omitted them there, via exclude_none on nested models, but sent
  them in `/v1/a2a/check`). Additive only.
- **Audit `host_job` items** (http-api §2.3) always carry `exit_code` and
  `error` (`null` on the `started` item; Python omitted the keys there).
- **`job.output` chunk index is `chunk`** (daemon spec §5.2). The Python
  sent it as `seq`, which sealing overwrote with the envelope's own `seq`
  (so the broker never saw a chunk index). Envelope keys are stripped
  before a message is parsed, and no message field uses one.
- **Channel messages are strict** (daemon spec §5, sandboxd spec §3). A
  known message type with an extra or out-of-bounds field is malformed
  (logged and dropped, as a Python handler exception was); unknown types
  are still ignored.
- **Typed admin inputs**: `ArmBody.tier` must be `user`/`root` (422; the
  Python passed any string to the host, which refused it with a 409), and
  lockdown/unlock `host` must be a daemon name. The admin chat `topic`
  follows the agents' rule (no control characters; Python only capped it).
- **Query values** (http-api §8.5): `wire::query` validates the decisions
  log `source` (Python: a Postgres enum error, 500) and clamps limits to at
  least 1 (Python: `LIMIT -1`, 500).
- **OAuth registration** (surfaces §C.3): at most 16 redirect URIs of 2048
  characters; a non-string `client_name` is kept as its JSON text (Python:
  `str()` of it).
- **Python `repr` in messages** (`invalid duration 'x'`): reproduced,
  except that unassigned code points print as themselves (Python escapes
  them; needs the Unicode database).

## Crypto (`agent-auth-crypto`)

- **API keys parse strictly** (core-lifecycle-policy §10.1). Only the shape
  ever issued parses: `aa_` + 12 lowercase hex + `_` + 43 URL-safe base64
  characters. The Python split on `_` and accepted any parts (`aa__x`),
  which then failed the lookup as "invalid API key"; such keys are now
  "malformed API key".
- **Encryption at rest is ChaCha20-Poly1305, not Fernet** (§10.2). Format
  (`secretbox.rs`): base64url(`0x01` ‖ 96-bit random nonce ‖ ciphertext ‖
  tag), with associated data binding the value to its table, column and row,
  so a ciphertext copied to another row does not open. `ENCRYPTION_KEY` keeps
  its shape (32 bytes, base64), so an existing Fernet key still parses; old
  ciphertexts do not open (the database is new).
- **Envelope sealing refuses what the Python let through** (daemons-hostd
  §4.3, §17 item 14): a payload using a reserved key (`id iss aud seq iat
  exp`) is an error instead of being overwritten, and a ttl outside
  (0, 3600] s is an error instead of producing an envelope the peer refuses.
- **Envelope bodies are read strictly** (§4.3): `iat`/`exp` must be JSON
  numbers (Python's `float()` also took numeric strings and booleans), and a
  `seq` above 2^64 − 1 is "malformed envelope body".
- **Hello nonces must be 32 bytes of URL-safe base64** (§4.2). The Python
  broker accepted any string as the daemon's nonce; every Python daemon
  sends this shape.
- **Base64 is decoded strictly** (§2.1): URL-safe alphabet only, padding
  optional, non-zero trailing bits refused. Python skipped stray characters.
- **Pairing proofs cover the canonical public key text** (§3.1). The Python
  broker MACed the key text as received; the Rust re-encodes the parsed key,
  so a peer sending a padded or otherwise non-canonical text fails the
  proof. Honest peers send the canonical form.
- **Key file opened with `O_NOFOLLOW | O_NONBLOCK`** (§2.3): the flags
  are defined per OS/architecture without libc; the checks (regular file,
  owner, mode) are made on the opened file, and a FIFO swapped in is
  refused instead of hanging the open. A symlinked key is reported as "is
  not a regular file" (the Python surfaced the OS's ELOOP error). The
  effective uid comes from `/proc/self/status` on Linux (other systems:
  the owner of a probe file created next to the key).
- **TOTP secrets must be at least 16 bytes** (daemons-hostd §7). The
  Python accepted any base32, including an empty secret, which gives
  predictable codes; such a secret is now refused with "TOTP secret is N
  bytes; at least 16 are required". Generated secrets are 20 bytes.
- **Broker JWT verification** (§10.4) takes the time as an argument and
  reports PyJWT's messages; `iat`/`nbf`/`exp` must be JSON numbers (PyJWT's
  `int()` also took numeric strings). Tokens and the JWKS (`kid`, `x`, `y`)
  are the Python's for the same `BROKER_SIGNING_KEY`. ES256 signatures are
  minted with low `s` and a high-`s` signature is refused (the Python
  accepted both forms of a malleated signature). A token's identity is its
  `jti`; nothing may key on token text.
- **Note, not a change: ES256 key derivation uses a deprecated ring helper.** ring has no
  "P-256 scalar → key pair" constructor and its PKCS#8 parser needs the
  public key, so `jwt::TokenIssuer` feeds the derived scalar to ring's own
  key generation through `ring::test::rand::FixedSliceRandom` (deprecated,
  "will be removed"). Correct on ring 0.17.14 (checked against the Python's
  `kid`/JWKS); a ring upgrade may need another route (the `p256` crate, or
  storing the derived key as PKCS#8 once).
- **Spec correction, not a change** (daemons-hostd §6.3): Python's
  `ensure_ascii` escapes DEL (0x7f) as `\u007f`; the spec said raw. The Rust
  canonical JSON (`core::canonical_json`) matches the Python, checked
  against a vector from Python's `json.dumps`.
- **Approvals carry proofs** (security review). Routing clearances
  (`AutoClearance` for `approve`, `LlmClearance` for `llm`, distinct types)
  name the request and the authority they were computed for; only
  `Policy::route`/`evaluate_and_route` make them, from a sealed decision (a
  decision whose fields were edited, or that was evaluated for another
  authority or resource, clears nothing). A human approval is a
  `HumanApproval` attested by an authenticated human surface (grep audit in
  `scripts/check.sh`). The store's `Approval` is built only from one of the
  three, and `transition` refuses one for another request, authority or
  starting state (auto: PENDING/AWAITING_HUMAN; LLM: LLM_EVALUATING; human:
  AWAITING_HUMAN). Entering LLM review needs the `LlmClearance`, so a retry
  re-routes with current facts (B-4).
- **Provisioning carries a proof**: `ProvisioningGrant` (from `begin` or
  `load_provisioning`, `FOR UPDATE`) is consumed by `activate` /
  `fail_provisioning`. A grant row can only be inserted for a PROVISIONING
  request (trigger), and a request's spec (authority, resource, what was
  asked) is immutable once stored (trigger).
- **One lock order** (store `lib.rs`): requests → containment advisory lock
  → agents → grants → threads. Disabling takes the containment lock
  exclusively, so it waits for in-flight checks rather than deadlocking
  with a provisioning (reproduced with psql and in a test).

## Admin panel, OAuth server, remote MCP (broker `webui`, `oauth`, `remote_mcp`)

- **Cookies are sealed with ChaCha20-Poly1305, not Fernet** (surfaces §B.2).
  `SecretBox` under an HKDF-derived key (same info string), with the kind
  bound into the associated data and the issue time inside; the age is
  checked as Fernet's TTL was. The panel's cookies are `__Host-aa_ui` and
  `__Host-aa_ui_login` (Path=/), the OAuth ones `__Secure-aa_oauth_login`
  and `__Secure-aa_oauth_consent` (Path=/oauth), so a browser refuses them
  unless Secure and (for `__Host-`) host-only. Python-issued cookies are not
  read (they expire within 8 h).
- **Default ports in `Host`** (Bug-B2): `Host: panel.example:443` is the
  panel's own address; any other port still is not. Without a `Host`
  header the request target's authority (HTTP/2 `:authority`) stands in;
  with neither, or an empty one, the request is not the panel's (the
  Python served it).
- **CSRF compares bytes** (Bug-B3): a non-ASCII `X-CSRF-Token` is a 403,
  not a 500.
- **The session cookie is looked at only without an `Authorization`
  header** (§B.6). The Python also took it with a non-Bearer
  `Authorization` header.
- **An ID token signed with a key the provider does not publish** is
  "the provider's ID token did not check out", as the spec says (the Python
  actually showed "...signed with a key the provider does not publish").
  The key's type must fit the token's `alg`, and a key naming an `alg`
  must name the token's.
- **Provider replies are bounded** (1 MiB) and a user name is cut at 128
  characters.
- **Registration refuses redirect URIs over 512 characters** (Bug-C7:
  400 `invalid_redirect_uri`, "redirect_uris: at most 512 characters each";
  the Python stored them and Postgres answered 500), and `/oauth/authorize`
  refuses a `state` over 1024 characters (a page: "state: at most 1024
  characters"; it is sealed into a cookie, which browsers drop past ~4 KiB).
- **Registration cannot lock connectors out** (Bug-C6). Registrations
  nobody authorized have their own cap of 20: a new one evicts the oldest
  (store `oauth::evict_unbound_clients`), they expire after an hour
  ("unknown client"), and `max_clients` counts only authorized (bound)
  clients (`oauth::count_live_bound_clients`). One client address may
  register 20 times an hour, then 429 `invalid_client_metadata` "too many
  registrations from this address; try again later" (the address is the
  peer, or `X-Real-IP` with `TRUST_PROXY_HEADERS`; behind an untrusting
  proxy every caller shares one allowance).
- **Redirect URIs are exact** (policy `remote_mcp.redirect_uris` replaces
  `redirect_hosts`; a policy still naming `redirect_hosts` no longer
  loads). The default is Claude's and ChatGPT's callbacks
  (`https://claude.ai/api/mcp/auth_callback`,
  `https://claude.com/api/mcp/auth_callback`,
  `https://chatgpt.com/connector_platform_oauth_redirect`); each entry must
  be https without a fragment. The Python accepted any https URI on a
  listed host, so any page there could receive a code. The error reads
  "this broker sends the browser back only to <the list>".
- **Codes and refresh tokens are consumed atomically** (Bug-C2,
  `store::oauth::consume`): of concurrent exchanges of one code exactly one
  succeeds; the others see a replay and revoke the family (including what
  the winner got), durably.
- **A code exchange checks the agent is enabled** too ("the connector's
  agent is disabled"; the Python checked only at refresh).
- **`get_credential` is never served on `/mcp`**, even if listed in
  `remote_mcp.tools` (a warning at startup).
- **A connector's token reaches only its tools' routes** (Bug-C1). The
  `AgentCaller` extractor admits an OAuth access token only on the `/v1`
  routes the served tools call (`wire::mcp_tools::api_routes`, a table
  next to the tool table; tested: each tool calls nothing else), and
  answers 403 "not available to a web UI connector" elsewhere, so a route
  added later is closed by default and trimming `remote_mcp.tools` trims
  the token's reach. The Python accepted it on every `/v1` route.
- **A connector's agent stays `web`** (§C.7, INV-C8). "Always a human"
  keys on `runtime == "web"`; migration 0006 ties that to the
  `oauth_clients` binding: a bound agent's runtime cannot change (trigger;
  the admin PATCH answers 409 "<agent> is a web UI connector's agent; its
  runtime stays web"), a client binds only to a `web` agent, and a binding
  never changes. So every agent bound to a client is a web agent. The
  Python let `PATCH /admin/agents/{}/attributes` (on the panel's list)
  clear it.
- **Tools call the agent API in process** (the `/v1` router through
  `tower::oneshot`) with the connector's own token, instead of over HTTP on
  `REMOTE_MCP_LOOPBACK_URL` (no longer read). `create_session` and
  `close_session` act as the connector (Bug-C3).
- **Remote sessions are kept per OAuth family** (Bug-C4), not per access
  token: a refresh keeps the conversation's session and its threads. Kept
  sessions are touched every 240 s while the connector has called within
  one `access_ttl`; at most 1000 are kept (least recently used dropped, not
  all cleared). A stale-session retry happens only for a session minted
  here, never one the caller named.
- **Only real waits are capped at 50 s**: `timeout_secs` of
  `wait_for_decision`, `wait` of `a2a_poll`/`a2a_events`, `wait_secs` of
  the host tools. The Python also capped `host_run`'s `timeout_secs` (the
  command's own timeout) to 50 and always added the rerun note there.
- **The OAuth pages' CSP allows their one style block by hash**
  (`style-src 'sha256-…'`) instead of any inline style.
- **Tool results** are pretty-printed by serde (non-ASCII is not escaped)
  and a broker error with an empty body reports the status's reason phrase.
- **`/mcp` answers on the SDK's terms**: rmcp in stateless JSON mode; a
  request needs a `Host` header (every HTTP/1.1 client sends one).
## Discord (broker/src/discord)

- **No twilight-http or twilight-gateway** (dependency policy). twilight-http
  always enables HTTP/2 (h2, banned) and both bring their own TLS roots
  (twilight-gateway's connector cannot be replaced). Only twilight-model
  (types) is used. REST goes over `agent-auth-tls::reqwest_builder`
  (HTTP/1.1, no compression, the shared root store, 15 s per attempt, 429
  `retry_after` and the global flag honoured, at most 3 retries and 30 s per
  wait). The gateway is our own client over tokio-tungstenite (feature
  `__rustls-tls`, the shared rustls config): JSON, no compression, intents
  0, heartbeat with jitter, zombie detection, resume via
  `resume_gateway_url` (followed only if `wss://`), identify again after a
  non-resumable invalid session, 1 s→60 s backoff, 1 MiB frame/message cap.
  The protocol is a pure state machine (`gateway::Machine`), property-tested.
- **All agent- and model-chosen text is escaped** (surfaces A.5, Bug-A1,
  INV-A5): justification, resource, agent and delegator names, agent
  attributes, risk notes, decided-by, decision and revoke reasons, job
  errors, attention desks. The escape is stricter than discord.py's: a
  backslash before every markup character (backslash, `*`, `_`, `~`, `|`,
  backtick, `>`, `<`, `#`, `-`, `[`, `]`, `(`, `)`, `:`) and a zero-width space after every `@`; trimming never splits an escape.
  Code spans/blocks (scope JSON, commands, thread topics, resources in
  backticks) replace backticks with `ˋ`. Privilege labels (made from a parsed
  authority) and the broker's own words are not escaped.
- **Every message names who it may ping** (Bug-A3): `allowed_mentions` with
  `parse: []` and at most the owner. The approval card's `<@owner>` is
  omitted when no owner is configured (Python wrote `<@0>`).
- **A card decided before its ids were stored is updated** (Bug-A4):
  `surface` re-reads the request after storing the message ids and applies
  the outcome if it is already final. `update_outcome`, `job_finished` and
  the shell thread read the ids fresh from the database.
- **Edit refuses what it cannot hold whole** (Bug-A2): a resource over 512
  characters or scope JSON over 4000 gets "This request is too long to edit
  here (...): approve or deny it as it is." instead of a truncated prefill.
- **`/release` answers ephemerally** (Bug-A5), after a deferral.
- **Stateless components.** The decision modal's custom id says what it
  decides: `aa:decision:approve:{rid}` / `aa:decision:deny:{rid}` (Python:
  `aa:decision:{rid}`, with approve/deny held in memory, so a submission
  after a restart failed). The rules browser's select and buttons carry the
  page and rule id (`aa:rules:sel|page|toggle|del:...`) instead of a
  600-second in-memory view, and redraw from the database after the owner
  check. Custom ids parse strictly (canonical ids and numbers only).
- **Modal inputs are `Label` components** around text inputs (Discord's
  current form; the input's own `label` is deprecated). Same labels, limits
  and placeholders.
- **Autocomplete from anyone but the owner gets no choices** (Python listed
  containment ids to any user).
- **`DISCORD_API_URL` and `DISCORD_GATEWAY_URL`** (new, optional): where
  the REST API and the gateway are; default Discord's
  (`https://discord.com/api/v10`, `wss://gateway.discord.gg`). The e2e
  suite points them at a fake Discord.
- **`/release` lifts everything only with `all:True`** (decided; matches
  the admin API's explicit `{"all": true}`). With neither an entry nor
  `all`, it answers with the standing entries and how to release one or
  all (Python: an empty `/release` lifted every containment).
- **Host commands are shown display-safe** (daemons-hostd §10, review
  2026-10): the card's command, `env` values (shell-quoted), `cwd` and
  `stdin`, and the shell mirror's text, go through core's display-safe
  quoting (`$'..'` for arguments, `\r`/`\u202e`-style escapes, line breaks
  of stdin kept), so a carriage return, bidi override or zero-width
  character cannot hide or fake part of what runs. Long commands keep head
  and tail; the mirror attaches the whole text as a file when long.
- **hostexec commands** (`/arm`, `/disarm`, `/lockdown`, `/unlock`,
  `/dnd`, `/hosts`, "Approve all…", "Kill VMs") as the Python, with
  daemon-supplied text (lockdown reports, versions) escaped. "Kill VMs"
  carries its scope and host in its custom id (stateless; the Python view
  lived an hour) and greys itself out after use. `/arm` parses the
  duration first (`Invalid duration: …`) instead of letting the host
  refuse it.

## a2a (broker::a2a)

- **Row locks on every transition** (a2a B4). Accept, reply-accept, send,
  reject and close load the thread `FOR UPDATE` after both participants
  passed `lockdown::check_pair`, and re-check participant, binding and
  state on the locked row (store lock order: agents, the backing grant,
  then the thread). Two racing accepts: one 200, the other 409 (or 403
  once the winner's session is bound); a send racing a close lands before
  it or gets 409.
- **The backing grant is checked where the message is written** (a2a
  INV-5/6): `store::a2a::open` share-locks the grant and requires the
  initiator's own live a2a grant for that responder name; `append`
  share-locks the backing grant before bumping the thread. A revoke
  either waits for the send or is seen by it; the Python checked the
  grant before writing, without a lock.
- **Events cursor is exact** (a2a B3). Instead of an overlap window (which
  a timestamp-only cursor cannot dedupe without the client spinning on
  repeats), every write of `last_activity_at` takes a stamp from an
  in-process monotonic clock and holds it until commit; the events reader
  only returns activity strictly below the oldest stamp still in flight
  (`a2a::clock`). A late commit is held back for milliseconds instead of
  being skipped; nothing is returned twice. A page of 200 never ends in
  the middle of a run of equal timestamps. Like the wake-ups, this assumes
  one broker process.
- **The message long-poll does not mark the caller listening** (a2a B2):
  only the events poll and accept set `last_listen_at`.
- **Zones hold on open and send** (a2a B5): a zone-apart responder is
  `404 unknown agent 'X'` on open (as in the check); a send across a zone
  edge is 403 `a restricted zone separates you from this peer: no a2a
  across a zone's edge`. Opening a thread to yourself is 403 `an agent
  cannot open a thread to itself`.
- **`/v1/a2a/check` treats a disabled peer as unknown** (a2a B6).
- **Disabling an agent closes its threads** (a2a B7): the disable paths
  must call `a2a::on_agent_disabled`, which closes every non-closed thread
  on either side `peer_gone`.
- **Held agents**: a disabled or lease-lapsed participant (core B-15) is
  refused like a contained one: 403 `<name> is disabled: no a2a while it
  is held` (containment keeps the Python text).
- **Webhooks** (a2a B9, spec §4): delivered from a background task after
  commit, failures logged (never a 500 after the state changed). URLs must
  be `https` with a host; plain `http` only to hosts listed in
  `A2A_WEBHOOK_HTTP_HOSTS` (Python: any http(s)). The admin routes that
  set a URL must call `a2a::webhook::check_url` (422 `webhook_url must be
  an https URL with a host (plain http only to the hosts in
  A2A_WEBHOOK_HTTP_HOSTS)`); delivery re-checks. No redirects, no proxy,
  5 s timeout, one shared client.
- **Webhook pings are signed with a timestamp** (upstream review 2026-10,
  flagged there). `X-Agent-Auth-Timestamp: <unix seconds>`, and the
  signature (same header and `sha256=<hex>` form) is the HMAC of
  `"<timestamp>." + body`, so a receiver can refuse replays
  (`crypto::webhook::verify_timestamped`, 5 minutes by default). The Python
  signed the body alone; receivers must change their check (README
  "Verifying webhook pings"). `a2a serve`'s POSTs to a local runtime keep
  the body-only GitHub-style form those runtimes verify.
- **No broker-wide webhook key** (flagged upstream). `WEBHOOK_SIGNING_SECRET`
  is ignored (a warning at startup): every receiver holding a shared key
  could forge pings to every other. An agent is pinged only with its own
  `webhook_secret`, which the admin routes always set with the webhook
  (create, set-webhook; rotate-webhook-secret replaces it), so only rows
  made outside those routes lack one; they get no pings (as before when
  neither key existed), never unsigned ones.
- **Long-poll rounds touch liveness throttled** (a2a B10), at 20 s like the
  extractor. Waiters with a session wake on their session key or their
  agent key; senders wake the peer's session (if bound) and agent.
- **Payloads**: keys come back sorted (the workspace's serde_json has no
  `preserve_order`; the stored text is the re-serialized object). An
  integer literal outside `-2^63..=2^64-1` is 422 `payload integers must
  be between -2^63 and 2^64-1` (Python kept it; serde_json would round it
  to a float). The 16 KiB cap is checked by `Payload`'s deserializer with
  `core::canonical_json::python_dumps_len`.
- **Panel attribution** (a2a B18): a chat message's `operator` field is
  shown only on the operator's own messages.
- **Operator-thread delegation** (not a change: the Python's later fix, a2a
  B1, "operator threads need no backing grant"). A request may cite an open
  admin-panel chat thread; the delegator is the operator. With no backing
  grant, the open thread is the whole test (`store::grants::begin`,
  `issuable`: initiator of kind operator and no grant), the grant is capped
  only by its own duration, and it ends when the thread closes.
- **Legacy thread-less messages** do not exist (`a2a_messages.thread_id` is
  NOT NULL), so `test_legacy_null_thread_messages_invisible` is not ported.
- **Resource caps** (security review #2; the Python had none):
  `A2A_MAX_SESSIONS_PER_AGENT` (64) open sessions per agent, then 409
  `too many open sessions for this agent (at most N); …` (counted under a
  lock on the agent row); `A2A_MAX_MESSAGES_PER_THREAD` (1000), then 409
  `thread has reached its limit of N messages; close it and open a new
  one`; `A2A_MAX_LONG_POLLS_PER_AGENT` (8) concurrently parked message
  reads and events polls per agent, then 429 `too many concurrent a2a
  long-polls for this agent (at most N); wait for one to return` (a read
  that does not wait needs no slot).
- **Long-polls sleep on wake-ups**, re-reading the database at least every
  15 s (the panel 10 s; Python: every 2 s and 5 s), or every 100 ms while
  a writer the events cursor waits for is in flight. At every re-read the
  caller is re-checked (agent enabled, API key not rotated or OAuth token
  still live, session still open): a caller that is no longer valid gets
  the extractor's 401 mid-wait instead of further data.
- **The dispatcher's events skip claimed threads** (not a change: the
  Python's later fix, a2a B8). A sessionless `/v1/a2a/events` caller gets
  activity only for threads no session has claimed on its side (each read
  of a claimed one is 403). `/v1/a2a/threads` still lists them (metadata
  only), as in the Python.
## Agent-side programs (client, `agent-auth` CLI, stdio MCP, bridge)

- **One MCP tool table** (surfaces §D.5): names, descriptions, parameters
  and schemas live in `wire::mcp_tools`, used by the stdio server and the
  broker's remote endpoint (which keeps its differences there as data:
  `REMOTE_NEVER_SERVED`, `REMOTE_MAX_WAIT_SECS`, `wait_param`, its
  instructions). A number parameter's default is advertised as the Python
  wrote it (`120`, not `120.0`), checked against a golden copy of the
  Python server's `tools/list` (`crates/mcp/tests/golden/tools.json`).
- **The broker URL must be `https://`** unless it is a loopback address
  (§D.1). Otherwise every call fails with `[0] AGENT_AUTH_URL must be an
  https:// URL ...` before sending the key. The Python sent keys over any
  scheme.
- **Request bodies are checked before sending** with the wire types the
  broker parses them into: a body the broker would refuse fails here with
  `[422] <the same message>` and no request. Durations go out as seconds.
- **Ids are one path segment**: percent-encoded (`/` too); `""`, `.` and
  `..` are refused (`[0] not an id: ...`). The Python interpolated them into
  the path.
- **`host_shell_exec` keeps waiting on the job** after the first slice (the
  Python looked for `job["id"]`, which jobs never have, so it never did).
- **Waits**: the first slice is exactly `min(wait, 60)`; a total that is NaN
  or negative is no wait and at most a day is waited (the Python looped
  forever on NaN and had no bound).
- **Printed JSON** is Python's `json.dumps(..., indent=2)` (ASCII-escaped,
  floats as `repr`), keys in the wire types' order (the Python models'); keys
  inside free-form objects (scopes, payloads) come sorted rather than in the
  broker's order. Answers are typed: a field a newer broker adds is not
  printed until the wire type has it.
- **`create_session`/`close_session` use the caller's credentials** (Bug-C3):
  the tools run for a `Caller`; neither builds a client from the
  environment.
- **`get_credential(to_file=True)` writes every kind not known to be
  harmless** (`to_file::NOT_SECRET_KINDS`: github_repo, lldap_group,
  a2a_grant, agent_identity, project_access, hostexec_shell, hostexec_job);
  a new kind is a secret by default. The Python listed the secret kinds and
  missed `model_gateway_key`, whose LiteLLM key went into the conversation.
- **`get_credential(to_file=True)`** (Bug-D1): an existing symlink at the
  file's name is refused; the value goes to a new `O_CREAT|O_EXCL` 0600 file
  that is renamed into place; the directory must be a real directory (not a
  link) owned by the user and is set to 0700 if it exists; `git_helper`
  shell-quotes the path (unchanged for ordinary paths). The file name keeps
  ASCII alphanumerics and `-` (Python: Unicode alphanumerics).
- **MCP argument errors** read `Error executing tool <t>: 1 validation error
  for <t>Arguments\n<param>: <problem>` (pydantic's text was longer).
  Arguments are not coerced from strings.
- **CLI**: bad JSON in `--scope`/`--payload` (Bug-D3) or a non-object is a
  usage error (exit 2), not a traceback. `BadParameter` cases are clap usage
  errors (`error: Invalid value: ...`, exit 2). An answer that does not parse
  prints `could not read the broker's answer: ...`, exit 1. The default
  session label keeps ASCII `[A-Za-z0-9._-]` only. `admin contain-lift`
  without an id sends `{"all": true}` (wire change). `admin gen-key` prints a
  `SecretBox` key (same shape as a Fernet key).
- **Bridge** (Bug-D2): a credential without `expires_at` is not cached (a
  new token per message) instead of crashing. Broker errors at startup are
  reported as `cannot reach agent-auth: [status] detail`.

## Provisioners (`broker/src/provisioners`)

- **Agent-visible errors carry no upstream bodies** (provisioners B13,
  INV-6). Models errors were `"{status} {text[:200]}"`; now only the status
  (`model gateway refused the key: 500`, `... refused the user for x: 500`,
  `... did not delete <alias>: 503`, usage `model gateway: 500`); bodies go
  to the broker log. Transport failures carry no client or upstream text
  (host names, addresses): `GitHub API unreachable (see broker logs)`,
  `LLDAP unreachable (see broker logs)`, `model gateway unreachable (see
  broker logs)`, `kubernetes API unreachable (see broker logs)`, `cannot
  read kubernetes token file (see broker logs)`; the detail is logged.
- **Case-folded resources are matched by lowercased globs** (review): the
  policy loader lowercases `platforms.github.repo_allowlist`/`repo_denylist`,
  `platforms.kubernetes.namespace_allowlist`/`sensitive_namespaces`/
  `cluster_grant_namespace`, and every restricted zone's `kubernetes` and
  `github` globs (the GitHub provisioner lowercases its lists again). The
  Python compared lowercased repos to the globs as written, so `JRT/x` in
  a denylist never matched: it failed open.
- **MCP servers need distinct audiences** (review): a policy where two
  servers share an `audience` (or url) does not load (`platforms.mcp.servers:
  a and b have the same audience '...'`); each would accept the other's
  tokens.
- **GitHub owner `.`/`..` refused** (B6): `invalid github repository`.
- **GitHub ceiling values are checked at startup** (B7): a
  `permission_ceiling` value other than read/write/admin (any case) stops
  the broker (the Python raised `KeyError`, a 500, at request time).
- **GitHub repo grants re-check policy at every mint** (B7): after a policy
  tightening (and restart), a grant whose repo is now denylisted / outside
  the allowlist, or whose permission exceeds the ceiling, gets `policy no
  longer allows this grant (<reason>); refusing to mint a token`.
- **GitHub provisioning does not cache its proof token** (store review:
  `credentials::replace` needs an `IssuableGrant`). Provision still mints a
  repo token (proving the installation covers the repo) and revokes it at
  once; the first credential fetch mints and caches. One more mint per
  grant; no unused token lives on (B8).
- **GitHub installation cache entries are dropped when a mint fails** (B9),
  so a reinstalled app is found again without a restart.
- **LLDAP administration groups are never brokered** (B1): `lldap_admin`,
  `lldap_password_manager`, `lldap_strict_readonly` (any case) are refused
  at validation (`group '<g>' is never brokered (it administers LLDAP
  itself)`) and at provision, whatever `allowed_groups` says, and are left
  out of the catalog. The meaning of an empty `allowed_groups` is unchanged
  (see Open questions).
- **LLDAP managed accounts are never taken over** (B2, INV-L5). Adoption of
  an existing LLDAP user requires that no other agent row holds that user
  id (case-insensitively: `LLDAP account '<u>' belongs to another agent;
  refusing to adopt it`) and that the user's display name is the broker's
  `"<agent> (agent-auth managed)"` (`LLDAP user '<u>' exists and was not
  created by the broker for this agent; refusing to adopt it`). Migration
  `0003` adds a unique index on `lower(agents.lldap_username)`: two agents
  can no longer share an LLDAP account (an admin setting one that another
  agent has now fails).
- **LLDAP memberships are serialized per agent and group** (review: write
  skew). Provision and revoke take a transaction-scoped advisory lock on
  (agent, group) (`store::lldap::lock_membership`) before reading the
  sibling grants, so of two concurrent revokes of an agent's last two
  grants on a group, the second sees the first one's outcome and removes
  the membership (the Python, and the first port, could keep it forever).
- **LLDAP account creation holds the agent row** (B3): `ensure_account`
  locks the agent row `FOR UPDATE` in the provisioning transaction, so a
  concurrent provision for the same fresh agent waits for the commit (or,
  if both already hold the containment check's share lock, Postgres aborts
  one as a deadlock: that grant fails and can be requested again). The
  Python's in-process mutex released before the commit.
- **LLDAP passwords are set over LDAP, not `lldap_set_password`** (B4).
  `lldap_set_password` takes the admin JWT only on its command line (no
  env/stdin option), where `/proc/<pid>/cmdline` shows it to every local
  user. The broker now binds to LLDAP's LDAP interface as the admin and
  uses the Password Modify extended operation (RFC 3062), which LLDAP
  supports; new settings `LLDAP_LDAP_URL` (`ldap://host:3890` or
  `ldaps://host:6360`) and `LLDAP_BASE_DN` (`dc=example,dc=com`); plain
  `ldap://` only to a loopback host or with `LLDAP_LDAP_ALLOW_PLAINTEXT=1`.
  `LLDAP_SET_PASSWORD_BIN` is ignored (a warning). Managed accounts need
  `ENCRYPTION_KEY` **and** `LLDAP_LDAP_URL`/`LLDAP_BASE_DN`; without them
  they are off as before (hand-registered accounts and existing managed
  accounts keep working; rotation fails). The failure text is `setting the
  LLDAP password failed (see broker logs)` (was `lldap_set_password failed
  (see broker logs)`), and the unavailable text names the new settings.
- **LLDAP group ids are looked up for every add** (B5), never cached.
- **LLDAP revoke treats a deleted user as not a member** (B17): a grant no
  longer stays ACTIVE forever when its account was deleted out of band.
- **LLDAP `UserExists` also reads `displayName`** (for the B2 check).
- **Kubernetes ServiceAccounts live in a namespace of their own**
  (review). The Python put a namespaced grant's ServiceAccount in the
  target namespace (and a cluster grant's in `cluster_grant_namespace`,
  `default`), where anyone allowed to create pods there could run one as
  that ServiceAccount and inherit its role. Every grant's ServiceAccount is
  now created in `platforms.kubernetes.grant_namespace` (new setting,
  default `agent-auth-grants`; the operator creates it and lets the broker
  manage ServiceAccounts there); the RoleBinding stays in the target
  namespace, its subject naming the ServiceAccount in the grant namespace.
  A request for the grant namespace is refused whatever the allowlist says
  (`namespace 'agent-auth-grants' holds the grants' ServiceAccounts and is
  never brokered`), and a zone-avoiding cluster grant never binds there.
  State gains `binding_namespace`; the credential note reads `bearer token
  for ServiceAccount agent-auth-grants/<name> (<role> in namespace <ns>)`
  (or `(<role> cluster-wide)`). A cluster-wide ClusterRoleBinding still
  covers the grant namespace too (cluster-wide grants are always a human's
  decision).
- **Kubernetes half-made provisions clean up** (B10): when a binding (or
  the namespace listing of the zone branch) fails after the ServiceAccount
  was made, the SA (and any bindings made) is deleted before the error is
  returned. A revoke with no recorded state (the reaper) derives the names
  from the grant (`aa-<agent>-<grant id>` in its namespace; cluster-wide:
  the ClusterRoleBinding, and per-namespace RoleBindings when the agent has
  zone exclusions) and deletes them (404 is fine).
- **Models reuses only its own gateway user** (B12): an existing LiteLLM
  user named like the agent is reused only if its `user_role` is
  `internal_user_viewer` and `metadata.agent` is the agent's name;
  otherwise `the model gateway has a user <name> the broker did not create;
  refusing to issue a key under it`, and no key is generated. A runtime
  with no models (`by_runtime`) is refused before any gateway call.
- **`/v1/tokens/verify` checks what the credential route checks** (B20):
  the grant must be issuable (`grants::issuable`: active, unexpired, agent
  not held, delegation thread open), not only active and unexpired.
- **Credentials carry `crypto::Secret`** (`Credential.value`); the MCP
  credential of a deleted agent is a refusal, not a 500 (B18).
- **Missing `server` on `/v1/tokens/verify`** is 422 `{"detail": "query
  parameter 'server' is required"}` (FastAPI's 422 had a list detail).
- **Secrets at rest bind to their row**: GitHub token cache
  (`credentials.value_encrypted`, row = credential id), LLDAP passwords
  (`agents.lldap_password_encrypted`, row = agent id), gateway keys
  (`grants.provisioner_state.key_encrypted`, row = grant id).

- **Google tokens are minted per (account, scopes) lock** (flagged
  upstream): the Python held one lock across every mint, so a slow Google
  for one account stalled all of them. Each cached token has its own lock
  (concurrent fetches of one token still make one call).
- **Google token endpoint texts** (provisioners, `_explain`): Google's
  free-text `error_description` is logged, not shown; the agent-visible text
  names only the OAuth error code (`invalid_grant`, `unauthorized_client`,
  ...), and the refresh-token and delegation texts keep the Python's advice.
  A transport failure is `google token endpoint unreachable (see broker
  logs)`; an unreadable login file names what is wrong (`no such file`,
  `not JSON`, `no client_id`), not the Python exception's repr.
- **A login file's `token_uri` must be Google's token endpoint**
  (`https://oauth2.googleapis.com/token` or the legacy
  `https://accounts.google.com/o/oauth2/token`), in the broker and in
  `admin google-consent` (security review #4): `google account <a>: its
  token_uri is not Google's token endpoint`. The Python posted the refresh
  token or the signed assertion to whatever the file named. Tests' fake
  endpoints are allowed only by the test constructor
  (`GoogleTokens::with_http`) and the CLI's own unit tests.
- **`admin google-consent --out` is a new file** (security review #4):
  created `O_CREAT|O_EXCL`, mode 0600 from creation; anything already at the
  name (an empty file, a link, a dangling link) is refused (`<path> already
  exists; remove it first`; the Python replaced an empty file). A client
  JSON that does not parse is a clean error (the Python raised).
- **Stub-era Google grants never become tokens** (security review #4). A
  grant approved while google was a stub recorded a decision only
  (`{"stub": true}`); once accounts are configured its credential is
  refused (`this grant was approved while google had no account configured
  (nothing was issued then); request it again`: the credential needs the
  real provisioner's state, `account` equal to the resource), and at
  startup every such active grant is revoked with that reason, besides the
  warning about saved google rules. The Python would have minted real,
  account-wide tokens for them.
- **A token answer without `scope` is not handed out** (security review
  #4): the Python counted it as exactly the scopes asked for. An agent's
  token needs Google to say what it carries (`Google's answer did not say
  which scopes the token carries; not handed out`); the broker's own use
  (the mail gateway's Gmail backend) still takes it.
- **Delegated accounts name whom they act as** (security review #4): the
  request note and the credential note read `<address> (acting as
  <subject>, by domain-wide delegation)`, since the subject may be someone
  else than the account's address.
- **Pool items made sensitive after approval** (security review #4, not a
  change): provisioning re-reads the pool's configuration, and "any" and
  "previous" choose only among items that are not sensitive then (tested),
  so an item marked sensitive between approval and provisioning is never
  taken by them.
- **Google texts**: a scope on a google request is refused with core's
  `no scope for google grants: the capability is the scope (unknown scope
  keys: ...)`; the stub's 501 reads `no google account is configured on this
  broker` (the Python's).
- **Pools** (upstream `provisioners/pool.py`, 2026-10 snapshot):
  - Items are tried in name order (the policy is read as JSON, whose
    objects keep no order; the Python tried them in file order), the item
    the agent held last first.
  - Provisions of one pool are serialized by a transaction advisory lock
    (`store::pool::lock_pool`) and a lease is inserted `ON CONFLICT DO
    NOTHING` (a lost race reads again and moves on, at most 8 times) instead
    of a savepoint per attempt; both caps stay unique constraints
    (`(pool, item, slot)`, `(pool, agent_id, agent_slot)`). A trigger refuses
    a lease unless its grant is a `pool` grant on that pool being
    provisioned, and lease rows never change. Leases whose grant has ended
    without its revoke are cleared at that pool's next provision.
  - Scope problems are refused before the pool is looked up (core parses
    the scope first): unknown keys, two of `item`/`previous`/`match`, a
    non-string item or malformed `match` give the Python's texts even for an
    unknown pool. `previous` must be a boolean (the Python took any truthy
    value); `match` holds at most 32 keys, strings at most 256 characters.
  - The catalog's `frees_at` is in the one wire timestamp format; the
    refusal ("the first frees at ...") and the credential note keep the
    Python's `isoformat(timespec="minutes")` (`2026-10-25T14:30+00:00`).
  - `CredentialOut` gains `properties` (upstream's addition), so it has
    seven keys, all always present (`null` unless set).
- **`release_grant`** (`POST /v1/grants/{id}/release`): an agent ends its
  own grant: 404 `unknown grant` for anyone else's (or a malformed id),
  `{"released": true}`, or `{"released": false, "status": ...}` for one
  already ended (the status is read after the attempt). Allowed while
  contained.

## Wiki (`broker/src/wiki`)

- **`last_change` is cached per (path, blob sha), and a failed lookup is
  remembered for 30 s only** (a2a B12): two pages with the same content no
  longer share an author, and a transient GitHub error no longer hides it
  until the page changes.
- **Writes re-read the repo only when `base_sha` disagrees with the
  broker's copy** (a2a B14): the Python fetched the whole tree on every
  write and delete. GitHub's own sha precondition still refuses a write
  over a version the copy missed (409 `... changed while you were
  writing`).
- **The commit summary is checked for credentials too** (a2a B13), on
  write and delete, with the same 400 text as for the content.
- **A truncated tree listing is logged** (a2a B15).
- A write or delete GitHub could not be reached for answers 502 `the wiki's
  repo refused the <write|delete> (unreachable)` (the Python raised a 500).
- Query parameters missing on `/v1/wiki/page` (`path`) or `/search` (`q`)
  are 422 `{"detail": "query parameter '<p>' is required"}`.

## Request lifecycle, routes and startup (broker `service`, `http`, `containment`, `scheduler`, `server`)

- **LLM evaluations survive a restart** (core B-3). The scheduler's first
  tick re-runs every LLM_EVALUATING request (or, with no reviewer, sends it
  to a human with `llm evaluator unavailable after a restart`); later ticks
  do the same for one untouched for 15 minutes.
- **An LLM approval re-runs the policy** (core B-4). The approve path routes
  the request again with today's rules, zones and gates and needs
  `Route::Llm` (its `LlmClearance`); anything else goes to a human with the
  note `LLM approved, but the policy no longer routes this to the LLM: …`.
  A retry likewise needs the policy still to route to the LLM, else 409
  `the policy no longer routes this request to LLM review; use escalate`.
- **Human edits are zone-checked** (core B-5): an edited (or unedited)
  approval is refused with `edited approval rejected by validator: <the
  platform's not-brokered text>` when a restricted zone now hides it.
- **A window rule passes every gate** (core B-6): `apply_rule_to_pending`
  routes each waiting request again and approves it only when the new rule
  decides it and the route is still `approve` (so a web connector's, a
  shell's or a zone's request keeps waiting); an expired rule applies to
  nothing.
- **Disabled is held** (core B-15): a request of an agent disabled or past
  its lease since it authenticated is recorded denied (`agent is
  disabled`), and nothing is provisioned for it.
- **Saved-rule pinning for resource-driven sensitivity** (not a change: the
  Python's `engine.sensitive_by_resource` / `pinned_here`). A saved rule
  pinned to an authority clears a request sensitive only because of its
  resource (a sensitive Kubernetes namespace, a pool's sensitive item) when
  the rule names exactly that resource; otherwise the request surfaces with
  the sensitive note. Core's evaluation and gates carry it
  (`RuleStrength::names_resource`, `GateFacts::sensitive_by_resource`),
  proven with the other gates. "Exactly" is the resource as a literal glob,
  since exact rules store it escaped.
- **"Exact" rules from a decision take the resource literally**: the
  resource pattern is the resource glob-escaped (`team*` → `team[*]`).
  A rule's duration cap from a decision is at most 365 days.
- **LLM suggestions**: a non-positive or non-integer
  `suggested_duration_secs` is ignored (core B-14), a `reasoning` that is
  not a string is an error (human).
- **The reviewer's prompt** follows the Python's later B-13 fix rather than
  the spec §7 text: the resource and scope are JSON-quoted and labelled
  agent-chosen, and each context note is one JSON string on its own line;
  the system prompt says so. Scope keys are in sorted order (no insertion
  order in serde_json).
- **Credentials are not issued to web UI connectors** (surfaces Bug-C1):
  a caller authenticated by an OAuth access token, or any agent whose
  runtime is `web`, gets 403 `credentials are not issued to a web UI
  connector`. A platform disabled since its grant was made answers 403
  `platform 'x' is not enabled on this broker` (was a 500).
- **A request whose capability/scope does not parse** for its platform is
  recorded denied with `validator: <why>` (the Python stored whatever
  `fold` made of it).
- **Admin agents**: a webhook is refused on an ephemeral agent (create 422,
  set-webhook 409; http-api §8.14), and must pass the a2a webhook URL rules
  (https, or http to `A2A_WEBHOOK_HTTP_HOSTS`); rotate-webhook-secret of a
  non-service agent is 409; disable refuses the operator's row (§8.13).
  Admin-token decisions are `decided_by: admin-api`, a panel user's are
  their name.
- **Agent containment of "everyone"** (core B-2, http-api §8.2): refused
  without `allow_all` when the match means everyone
  (`AgentMatch::matches_everyone`: `{}`, `{"name": "*"}`, every placement
  or kind…) or holds every enabled agent today. Discord's contain applies
  the same check unless its "everyone" option is chosen.
- **Audit**: membership in `audit.readers` is checked before any query
  parameter (http-api §8.3); `limit=x` from a reader is 422.
- **Transport**: a 2 MiB body limit, a 330 s request timeout (longer than
  any long-poll), and `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store` and a deny-all CSP on every
  response that does not set its own. 404/405 answer `{"detail": ...}`.
- **Containment acts durably** (review #2): the transaction that records
  an entry also moves every active grant of the held agents to expire now,
  so the scheduler revokes them even if nothing else runs; the rest
  (denials, reverting PROVISIONING grants, revocations, threads, agent
  VMs) runs as a tracked task each of whose steps runs even if an earlier
  one failed. Each scheduler tick also revokes any active grant of a held
  agent.
- **Provisioning outlives its caller**: phase two runs in a tracked task
  the handler awaits, so a dropped connection does not strand it.
- **Host approvals fail closed**: approving a hostexec request needs the
  hostexec approval gate (409 without it), and a shell needs a TOTP code in
  the decision (`a shell is approved with a TOTP code only (Approve with
  TOTP)`), whatever the gate does.
- **Per-agent limits** (new): at most `REQUESTS_PER_AGENT_PER_HOUR` (60)
  new access requests an hour and `MAX_WAITS_PER_AGENT` (16) concurrent
  decision long-polls, else 429. The long-poll re-reads the database every
  10 s (wake-ups do the rest); the Python polled every 2 s.
- **Provisioner transport errors** reach the agent as `the platform could
  not be reached; try again later` (the detail is logged); other
  provisioner texts are cut to 300 characters.
- **The reviewer's history** quotes earlier reasoning as a JSON string
  labelled model output, and the system prompt says not to follow it.
- **Security log**: failed authentications have a ring of their own, so a
  flood of them cannot evict the other events.
- **The boot tick** (reaper catch-up, stalled LLM work) completes before
  the HTTP listener and the Discord bot start.
- **Startup**: a missing `POLICY_FILE` stops the broker (core B-12);
  `DATABASE_URL` must be a postgres URL; one broker per database (a session
  advisory lock; a second one exits — B-19, ARCHITECTURE.md "Deployment").
  `./.env` is read without changing the process environment (no `set_var`);
  every part reads its settings through that lookup (`config::Env`). The
  Discord bot and the a2a settings read only the process environment at
  first, so `DISCORD_TOKEN` in `./.env`, as the README's quick start puts
  it, left the bot off (found by the e2e suite).
- **Shutdown drains for at most 10 s** (found by the e2e suite). On SIGTERM
  the Python's uvicorn waited for every open request, so one agent's
  long-poll (`wait`, a2a `poll`/`events`: up to 300 s) held the shutdown
  past Kubernetes' 30 s grace and the pod was killed. Now open requests get
  10 s (`server::DRAIN`), then the broker stops the scheduler, settles LLM
  evaluations (10 s), releases its lock and exits; a cut-off long-poll
  sees its connection close and polls again.

## Daemons, hostd and hostexec (`crates/daemon`, `crates/hostd`, broker `daemons`, `hostexec`, `desktop`, `attention`)

- **TOTP lockout escalates and ends in a hard lock** (daemons-hostd §7, bug
  6). Five wrong codes in a row lock a secret for 5 min, then 10, 20, …
  (doubling up to ~21 h) until a code is accepted; 20 wrong codes within 30
  days hard-lock it until root on the host runs `agent-auth-hostctl
  totp-unlock NAME` (new, root only). Accepted codes reset the escalation,
  not the 30-day count. Python: 5 per 300 s forever (≈79 %/year for whoever
  relays codes). A state file that exists but does not read hard-locks its
  secret (Python: read as empty, which forgot the last used step); clearing
  it then refuses the current window. Lock state shows as
  `tiers.<t>.totp_locked` in the heartbeat status. Logic in
  `core::hostd::totp`, model-checked (replay, lock).
- **Durable state files** (bug 7): TOTP state, the lockdown flag, the spool
  and `paired.json` are written to a temp file, fsynced, renamed, and the
  directory fsynced. A lockdown flag whose existence cannot be checked
  counts as locked.
- **Remote `arm` checks the tier and the lockdown before the code** (bug 8):
  a valid arm code is no longer burned on a locked host.
- **`truncated` is exact** (bug 1): true iff the job wrote more than the
  1 MiB kept (`core::hostd::output::OutputTail`, property-tested). `bytes`
  is still the kept size.
- **No answer to `job.start` is not a refusal** (bug 2): on a call timeout
  the job row stays `starting` (its result is stored if it comes, else it
  becomes `lost`), the host is told to kill it, and provisioning fails
  with `… did not answer within 20s; the host was told to stop the job in
  case it started`. An explicit refusal or an offline host is `refused`
  as before. Same for `shell.exec`.
- **`lost` is produced** (bug 3): a job running when hostd stopped is
  reported with `lost: true` (an additive field of `job.done`, omitted when
  false) and stored as `lost` with the restart message; the scheduler step
  marks jobs still `starting`/`running` one hour past their timeout `lost`
  (`no result from the host; its outcome is unknown`).
- **Orphaned job units are tracked** (bug 4): at startup hostd lists its
  running `aa-job-*` units; `job.kill` and lockdown stop them, and their
  ids never start again.
- **A kill that arrives before the job's process exists still stops it**:
  each running job has a kill signal its executor watches (the Python's
  `systemctl stop` could miss a unit not created yet).
- **Approval prompts show the whole command or say they don't** (bug 5,
  review finding 6): the desk prompt and the polkit message render the
  argv with control/bidi/zero-width characters escaped (`$'…'`), show stdin
  (escaped) with cwd and env, and when that exceeds the field, show its
  head plus `… [cut: N of M characters shown; the approval covers all of
  it, sha256 <digest prefix>…]`. Whitespace is no longer collapsed in what
  hostd builds (only in broker-supplied text). Helpers for the Discord
  follow-up: `core::hostd::display`.
- **Linux root jobs get `HOME=/root`, `USER`, `LOGNAME`** (bug 21).
- **The watcher sees templates** (bug 10): `template:<name>` and its
  parameters instead of `[]`.
- **Desk rate slots are taken when the offer is accepted** (a2a-wiki-desktop
  B16), so simultaneous requests can't all pass the burst/hour checks.
- **A desk answer is its own principal**: `auth::DeskAnswer`
  (`decided_by` `desktop:<host>`), made only by `desktop`, converted into a
  `HumanDecider`; the request service attests the approval as for any
  human surface.
- **A shell command checks containment** (`lockdown::check`) besides the
  grant being live; Python relied on the grant having been revoked.
- **hostd config is strict**: unknown keys are refused, values must have
  their JSON types, `desktop.approve` needs `desktop.enable`, the desktop
  needs `user`, `vm_unit` must look like a unit (Python: lenient
  `bool()`/defaults; the nix module asserted some of these).
- **Malformed broker messages are answered**: a known type that does not
  parse (wire types are strict) gets `{"ok": false, "error": "malformed
  <type> message"}` when it carries a `call_id` (Python raised inside the
  handler, with the same effect for most shapes).
- **macOS user tier without libc** (`docs/hostd-macos.md`): the `asuser`
  step (`agent-auth-hostd asuser <json>`, still behind `launchctl asuser`)
  drops privileges with `CommandExt::gid`/`uid` and execs; supplementary
  groups are dropped rather than set with `initgroups`, and the "root can
  be regained" probe is gone (setuid as root sets the real, effective and
  saved uid; there is no safe `setuid(0)` to try). The account (uid, gid,
  home, shell) comes from `dscl` on macOS and `getent`/`/etc/passwd` on
  Linux. Process groups are signalled with `kill(1)`.
- **Lockdown kills in parallel** (bug 17, partly): every job and orphan of
  a host is stopped concurrently; handlers are still inline per connection.
- **Daemon reconnect backoff resets after a session** (bug 15), and the
  daemon drops a broker that stays silent for two ping intervals (40 s).
- **Daemon-supplied status is re-validated on the broker** (review finding
  3): `hosts()`/`/admin/hosts` and the desktop keep only plausible times,
  valid template names and version strings, and escape and bound free text.
- **hostctl prints times in UTC** (no local time zone without libc).
- **Job rows are written in the grant's provisioning transaction** (it holds
  the grant row; a separate transaction deadlocked on the foreign key). A
  `job.done` that arrives before that commits (or is still seen as
  starting/running) is retried in the background for up to 30 s, without
  holding up the channel, before being treated as another host's.

Upstream fixes of review 2026-10, adopted:
- **systemd-run argv `$` escaping** (HIGH): every `$` goes to systemd as
  `$$`, so `$VAR`/`${VAR}` are not expanded and what runs is what was
  approved; a proptest checks any argv round-trips through systemd's
  documented `$` rules.
- **Desk dialog shows everything or isn't asked** (HIGH): arguments in
  `$'..'` escapes, env values and stdin content shown; a command or its
  details longer than the dialog limits is refused at the desk ("too long
  to show in full at a desk") and stays on Discord, instead of being shown
  cut with a digest. A prompt id already up is refused ("that prompt is
  already up").
- **Lockdown order**: the containment entry is recorded first, then the
  affected agents' waiting requests are denied (`requests_denied` in
  `LockdownResult`, new field), then grants are revoked. On a host, the
  in-memory lock is set before the lockdown file is written; a write
  failure doesn't stop disarming or kills. A job whose kill or lockdown
  lands before it is spawned never runs ("killed before it started" /
  "locked down before it started"). A desk root Allow is decided and
  recorded under the state lock, so a lockdown during the polkit dialog
  either is seen or clears the approval.
- **hostd-user stalls**: messages to the desktop helper go through a
  bounded queue (32) with `try_send`; a full queue drops the helper, and a
  socket write that takes over 5 s ends its connection. Neither can block
  the broker channel.
- **No host TOTP code spent on a contained or disabled agent**: the
  spine's gate runner skips the approval gate when the agent's lockdown or
  containment check fails, so provisioning fails without a code relayed.
- **auto/deny globs and paths**: `auto_commands` match path globs segment
  by segment (`*` never crosses `/`) and never match an argv with a `..`
  path segment; `deny_commands` match as before and again with path
  arguments lexically normalized (`/usr/../bin/rm`).
- **Templates may pin `cwd`, `env` and `stdin`** (validated as a
  request's would be); a template request carrying any of them is refused
  on the host ("template 'x' takes no cwd/environment/stdin"). The broker
  still validates the request shape; the host is authoritative.
- **Handshake slots**: at most 32 unauthenticated handshakes overall, and
  4 per address only when the address is believed (a trusted proxy's
  `X-Real-IP`; behind an untrusted proxy every daemon would share one
  address); the hello timeout is 5 s (was 10 s).
- **Every TOTP refusal is logged as a warning** besides its audit record;
  lockouts escalate as before.

Security review 2026-10 (hostd/hostexec), fixed:
- **1 (HIGH) A desk click no longer forges a human approval.** hostd asks
  at its desk only about commands of a tier its desk approves
  (`desktop.approve.<tier>`): no prompt, so no click to relay, on a tier
  that is merely armed. The broker applies a desk Allow for a host command
  only from that host's own desk and only when hostd reports
  `authorized: true` (its own recorded desk approval, polkit-confirmed for
  root); otherwise it is ignored and logged. Desk evidence is marked
  (`decided_by` `desktop:<host>` reads as source `desk` on the host) and
  arming never covers it. An answer counts only from the helper connection
  the prompt was shown on, keyed by a nonce hostd makes (the broker's
  prompt id never reaches the helper). Host commands are no longer asked
  at other hosts' desks (no desk approves another host's tier). A Kani
  harness (`hostd_desk_click_never_admits`) and property tests check that
  desk evidence admits nothing without the host's own approval.
- **1e/6 Local peers inside a job are refused**: ctl.sock and the desktop
  helper's registration on user.sock refuse a process whose
  `/proc/<pid>/cgroup` is in an `aa-job-*` unit, read on hostd's side and
  failing closed. Gaps: macOS has no equivalent (launchd marks nothing a
  peer can see), and a user-tier job that reaches the user's service
  manager (`systemd-run --user`) can start a process outside its unit;
  the check also reads the pid after connect (a pid reused in between is
  possible, narrowly).
- **2 A kill before the unit exists is not lost** (Linux): after a kill,
  `systemctl stop` repeats every 250 ms until `systemd-run` exits.
  Lockdown also stops every `aa-job-*` unit `running_jobs()` lists, and
  hostd, starting locked down, stops leftover units before anything else.
- **3 Local sockets are bounded**: the caller is admitted (uid, and the
  job check) before anything is read; at most 8 connections per uid and
  64 overall; a request line must arrive within 60 s; ctl.sock lines are at
  most 4 KiB. The NixOS hostd unit gets `LimitNOFILE=65536`.
- **4 A TOTP code is bound to what it was typed for.** New optional
  secrets `user-shell`, `root-shell`, `root-unlock` (`agent-auth-hostd
  totp-enroll --add <name>`). A shell is opened with its tier's shell code
  when that secret is enrolled (a direct code then opens no shell, and a
  shell code admits no job); a root shell needs `root-shell` (a direct
  code never opens one). Unlocking from the broker takes `root-unlock`
  (a root-arm code no longer unlocks, so a code typed to unlock can't arm);
  without it, unlock locally with hostctl. Arm durations were already
  capped by hostd's own `max_arm`. `hostexec.authorize` carries
  `shell: true` for shells.
- **5** Arming reads the lock under the state lock a lockdown disarms
  under. A prompt id is shown at most once (kept for the last 4096). A
  TOTP failure that can't be written to disk locks that secret in memory
  until root clears it. polkit is asked about the helper process as it
  was when it connected (pid and start time read then). Linux jobs stop
  reading output 5 s after `systemd-run` exits, so a process outside the
  unit holding the pipe doesn't keep the job open (macOS already did).
- **6** Ed25519 public keys that are small-order points (the identity
  among them, either sign, canonical or not) are refused when parsed. A
  daemon session shorter than 30 s backs off like a failure (no 1 Hz
  reconnect loop against a broker that welcomes and drops).

## Mail (`crates/mail`, broker `mail`, `discord/mail.rs`; upstream snapshot 2026-10-25)

Ported from the snapshot with every fix its review log lists (judge reads
exactly what is delivered; compare-and-set release/discard; mailbox mode
trusts the From, DMARC only for `header.from=` the From's domain; only
`<msg-id>` tokens in replies, a failed send marks the item failed; zero /
sub-pixel font sizes only; verdicts carry a constraints fingerprint; the
worse of judge and hints; create domains resolve; no counts while
searching; backend errors are agent-safe errors, not 500s; escaped Discord
cards with unbreakable fences; release re-checks containment, thread,
grant and the draft; unconstrained `create` is sensitive; one-line
subjects; no mail to the person's own alias domains; one denial text for
unknown aliases; case-insensitive tag breaking and Unicode tag
characters stripped; `mail_attachment` never served remotely). Beyond it:

- **No Python mail stack.** MIME through `mail-parser` (no `full_encoding`:
  CJK multi-byte charsets such as Shift_JIS, GBK, Big5, EUC-KR,
  ISO-2022-JP decode lossily); HTML through our own tokenizer (HTML5 tag,
  attribute, comment and raw-text rules as Python 3.14's `html.parser`;
  references decoded with the full HTML5 entity table generated from
  Python's `html.entities.html5`). Attachments are every attachment part,
  nested ones included (Python's `iter_attachments` saw only the top
  level's). IMAP and SMTP are our own minimal clients.
- **TLS only, our roots.** IMAP is implicit TLS; SMTP on 465 is implicit
  TLS and on any other port STARTTLS, which must be offered (no plaintext
  fallback; bytes the server sent ahead of the handshake are refused).
  Certificates are checked against the shared root store (Mozilla minus
  the distrusted roots), not the system store; `MAIL_CA_FILE` (new,
  optional) adds a CA for private mail servers (and SimpleLogin, Gmail).
  SMTP authenticates with PLAIN or LOGIN only (smtplib also tried
  CRAM-MD5); the EHLO name is our address literal.
- **Bounded parsing.** A message is cut at 25 MiB (as the Python); IMAP
  lines at 8 MiB, literals at 64 MiB (kept up to 25 MiB), SEARCH at 10^6
  UIDs, SMTP replies at 8 KiB × 256 lines; HTML nesting past 4096 makes the
  rest of the document hidden text (never shown as visible), and end tags
  find their element through an index (the Python was quadratic on deep
  nesting).
- **Agent-visible errors carry no server text** (as the provisioners):
  `imap <host>: login refused`, `gmail: GET /messages answered 500`,
  `simplelogin unreachable (see broker logs)`; details go to the log. The
  Python put imaplib/smtplib exception text and API bodies into them.
- **Timestamps** in mail summaries are the one wire format (RFC 3339 `Z`,
  microseconds); the judge's JSON keys come sorted (no insertion order).
- **`since`** is `YYYY-MM-DD` only (Python's `date.fromisoformat` also took
  `20260101` and ISO week dates). Correspondent globs are at most 320
  characters.
- **Policy is checked at load** (B-1 style): unknown keys refused;
  mailbox `folders` are 1–255 characters without control characters;
  `imap_host`/`smtp_host` are host names; `simplelogin.api_url` must be
  `https` (plain `http` only to a loopback host: the tests' fake);
  `create_domains` must be domains; `max_body_chars` at least 1. Globs
  (`aliases`, restriction `address`/`correspondents`) are lowercased at
  load. `platforms.mail` is its own section; a gmail mailbox's
  `google_account` must exist.
- **The store enforces the item machine** (migration 0014): inbound items
  may be judged again until released or discarded; held → released |
  discarded (in), held → sending | discarded and sending → sent | failed
  (out); a decided item is never re-judged; a draft exists only while held
  or sending, sealed with `SecretBox` bound to its row. A mail grant's
  resource is immutable except the one move `create` makes (domain → the
  alias on it), while provisioning.
- **The mail validator may call SimpleLogin** (to tell an alias that
  exists from one that does not, as the Python did; cached an hour). The
  provisioner contract otherwise keeps validators off the network.
- **Discord**: Release/Discard answer in a deferred ephemeral message and
  rebuild the card from the item (with its outcome line) instead of
  editing the old embed; custom ids `aa:mlrel:<id>` / `aa:mldis:<id>` as
  the Python's. Without a notifier, a held item is logged.
- **Web connectors**: a `runtime: web` agent reaches a mail route only for
  tools in `remote_mcp.tools` (`not available to a web UI connector
  (<tool> is not in remote_mcp.tools)`); an OAuth connector token reaches
  only `mail_list`/`mail_read`/`mail_send`'s routes (`api_routes`);
  `mail_attachment` is in `REMOTE_NEVER_SERVED` (the Python served it and
  answered an error).
- **`GMAIL_API_URL`** (new, optional): where the Gmail API is (the e2e
  suite's fake). Gmail logins are the google part's `GoogleTokens`.
- **CLI `mail-send`** reads the body from `--body-file` or stdin, as the
  Python; `mail-list --limit` is an integer (clap usage error otherwise).

### Mail: security review #4

"(upstream)" marks what the Python does too: upstream should know.

- **Verified senders only** (upstream). A mailbox grant counts a
  correspondent only when the mailbox provider's own Authentication-Results
  (its authserv-id: `mx.google.com` for Gmail, `authserv_id` for IMAP,
  unset = nothing verified) shows DMARC pass for the From's domain or a
  DKIM pass signed by it; a message "from" the mailbox counts as its own
  only so verified or filed as sent (Gmail's `SENT` label, IMAP
  `sent_folders`, default `Sent`, `Sent Items`, `Sent Messages`,
  `[Gmail]/Sent Mail`). An alias trusts `X-SimpleLogin-Envelope-To` and
  `-Original-From` only on a message the provider saw DKIM-signed by
  `simplelogin.dkim_domains` (default `simplelogin.co`) or the alias's own
  domain. A message that would belong if its claims were true but is not
  verified is held ("the sender could not be verified..."), never
  delivered or dropped; the judge does not see it. New policy keys:
  `mailboxes.*.authserv_id`, `mailboxes.*.sent_folders`,
  `simplelogin.dkim_domains`.
- **Authentication-Results are parsed** (RFC 8601; upstream used regexes
  over the text): comments removed, results split on `;`, `method=result`
  anchored at each result's start, `header.from`/`header.d` read from that
  same result, and the header counts only from the provider's authserv-id.
- **Attachments**: a content type is kept only in `type/subtype` token
  syntax, else `application/octet-stream` (upstream passed what the
  sender wrote); attachment names are scanned for injection hints
  (upstream did not).
- **Held items are released only after their whole text was shown**
  (upstream showed 1,500 characters, Discord 900, of up to 50,000). Held
  items keep their whole text sealed (inbound too: what the agent would
  read plus the hidden text; migration 0015); `GET /admin/mail/items/{id}`
  and `/admin/mail/held` return it in `text`, the Discord card attaches it
  as a file when it does not fit, and each records `shown_at`; a release
  before that is 409.
- **IMAP answers are bounded per command**: 48 MiB held, 8 literals per
  response, 120 s for a whole command (and for the greeting); a
  per-read timeout alone let one login hold 400 MiB.
- **No paging oracle while searching** (upstream): a search's pages are
  filled from messages the agent may read only (up to 5 backend pages per
  call), behind a sealed cursor (`page is not a cursor of this search`,
  400, for anything else). Held and unscreened messages are not listed
  while searching. The time a search takes still grows with what it
  skipped.
- **Hidden text** (upstream): every Unicode Default_Ignorable code point
  and U+FFF9..FFFB are stripped, U+2028/2029 are line breaks; CSS is read
  after removing comments and decoding escapes, declaration by
  declaration; also hiding: `opacity` ≤ 0.05 (`.0`, `0%`),
  `visibility:collapse`, `mso-hide:all`, font sizes under 2 px in any
  unit, zero width with overflow hidden, transparent `rgb`/`hsl` alpha,
  `scale(0)`, empty clips, far off-screen positions and indents;
  `<style>` rules that hide hide every element with a class or id they
  name (over-approximated); closed `<details>`, `<iframe>`, `<noembed>`,
  `<noframes>` content is hidden. Not detected: text coloured like its
  background, SVG text, `<select>` options.
- **The first From, Subject and Date** count when a header repeats (as the
  Python's `msg.get`; mail-parser reads the last).
- **The judge's hints sit inside the quoted `<email>` block**
  (`heuristic_hints`), not after it (upstream).
- **Defence in depth**: `imap::quote`, IMAP command arguments and
  `compose` refuse CR, LF and NUL themselves.

## Agent VMs (`crates/sandboxd`, broker `sandboxes`)

Broker side:
- **Only the VM's orchestrator mints** (B-14): `agents:mint` from any
  other agent is refused (`only an agent VM's orchestrator can mint
  identities`), and the catalog lists `agents` to the orchestrator only.
  The Python let any VM agent ask and left it to policy.
- **Re-minting never undoes an operator's disable** (B-1, B-8). Renewing a
  live agent extends its lease only (as before). A lease-expired agent is
  re-enabled with a NEW key queued for its sandbox (the daemon restarts its
  dispatcher on it; the old key stays dead). An agent the operator
  disabled is refused at validation and at provisioning: `<name> was
  disabled by the operator; minting it again does not re-enable it`. The
  Python re-enabled any disabled agent with its old key. Re-pairing still
  re-enables the orchestrator (an operator act, with a new key).
- **Key acks name the key** (B-6): `key` carries `key_id`, and `key.ack`
  must name it (one without is malformed and ignored); an ack for a key
  since replaced deletes nothing.
- **Unpairing a sandbox disables its agents** (B-10), with their
  descendants (reason `unpaired`): their keys stop working at once. The
  Python left them enabled until their leases (the orchestrator: never).
- **`rotate-key` refuses a VM agent** (409 `<name> was minted in an agent
  VM; its key is its sandbox's (disable it and mint it again)`), as rename
  and attributes do: it would have stranded the daemon's copy.
- **A connecting sandbox is told the lock state either way** (B-3):
  `unlock` when the broker is not locked for it, `lockdown` when it is,
  then its held list, then pending keys, all from one hook in that order.
  A VM that missed an unlock no longer stays locked forever.
- **Lockdown and unlock tell sandboxes their held lists.** The Python did
  this from `containment.record`/`lift_where`; without it a VM stayed
  fully contained after an unlock. An unlock of one host while `*` remains
  no longer unlocks that host's VM.
- **A timed-out `project.grant` is followed by a best-effort
  `project.revoke`** (B-7, broker half): the daemon may have applied it.

sandboxd:
- **State is a few JSON documents, not SQLite** (spec §4.3; the workspace
  bans SQLite). Each change is written whole to a new 0600 file, fsynced,
  renamed over the old one and the directory fsynced, under the
  document's lock; memory changes only once the disk has. A document that
  does not read, is not a regular file or is readable by others stops the
  daemon at startup. A change that only lifts holds is not applied unless
  it is written (fail closed); one that adds holds applies in memory even
  if the write fails.
- **Broker messages are handled off the read loop, holds first** (B-7).
  A hold (`lockdown`, `unlock`, `agents.contained`) takes effect in memory
  and on disk before the next message is read; its freezing and thawing
  run in order on a worker, and deliveries after a release run in tasks of
  their own. Project grants run in tasks (serialized per project pair). A
  grant is recorded before its ACL is applied and undone if applying
  fails, so a revoke after a failure or a broker timeout cleans up.
- **Held means held on every path** (B-2, upstream review 2026-10): a unit
  is thawed, and its queue delivered, only when nothing holds its agent
  any more (lifting the lockdown keeps contained agents frozen; lifting a
  containment during a lockdown thaws nothing). `core::sandbox`, with Kani
  harnesses. A held run is not parked (frozen processes are kept), and a
  turn that ends while held does not get its queue.
- **Process limits are enforced** (B-4): a slot is held for as long as a
  process runs (headless, TUI and triage alike), at most `max_processes`
  in the VM and `max_processes_per_project` per project (the orchestrator
  is its own). A delivery waits up to 120 s for a slot; then the text
  waits in the conversation's queue and is retried. The Python's
  semaphore counted starts only, and the per-project limit was unused.
- **Idle TUIs are ended** (B-5): a TUI with no client attached and no
  activity for `interactive_idle_secs` is stopped, and its conversation
  goes back to headless.
- **Queued deliveries are retried** (B-17): a thread that was accepted
  is never rejected because its process then failed to start (no model
  key, no slot, a broken runtime); the text waits and is retried (30 s,
  doubling to 15 min) and with the next message.
- **A refused key is asked for once, then waited for** (B-8): a dispatcher
  or watcher that gets a 401 sends `key.rotate` (at most once per 5 minutes
  per agent) and waits for a new key instead of ending (dispatcher) or
  repeating every 5 s forever (watcher). A 401 while routing an open does
  the same.
- **Sessionless conversations get a new session** (B-9): when the broker
  ends a conversation's session, the conversation gets a new one the next
  time it is used (a claim, a process start); a claim that meets a dead
  session retries with a new one, and a process still holding the dead
  session is stopped. The Python claimed threads without a session and
  never heard from them again.
- **Root never follows a path an agent controls** (B-11, B-12, B-13).
  Directories are opened `O_PATH|O_NOFOLLOW` one component at a time from
  sandboxd's own roots, through `/proc/self/fd/<parent>/<name>` (std has no
  `openat`); every entry of a tree is opened without following and acted
  on through `/proc/self/fd/<n>`. Files are created `O_EXCL|O_NOFOLLOW`
  under a random name and renamed in the same directory (a planted FIFO
  or symlink only fails the write); reads take regular files of bounded
  size only. Ownership changes use `chown(2)` on those magic links (no
  `chown -R`), only for entries owned by an expected previous owner (seal:
  the orchestrator's; the write-revoke hand-back: the grantee's; a codex
  home: root's), never symlinks or multiply-linked files. ACLs still go
  through `setfacl` (no xattr calls in std, no `unsafe`), but only on
  `/proc/<sandboxd>/fd/<n>` paths of verified inodes, passed on stdin in
  batches; only regular files and directories, and a grant only on
  entries the target project owns with one link. The codex socket is
  found by reading its symlink (never following it), opening each
  directory of a `/tmp/<plain names>` target without following, and
  connecting to the socket's `O_PATH` descriptor. Residual risk: a
  project can hard-link into its tree a file it can already write
  elsewhere (`protected_hardlinks`); removing an ACL entry is applied to
  every entry; `setfacl` is a separate root process trusted with its
  stdin; `X` is evaluated when it runs.
- **The shared codex login is written back by one designated project
  only** (upstream review 2026-10, flagged). New config key
  `codex_auth_owner` (a project; default none). Every other project gets
  the shared login copied in whenever its copy differs, and its own
  changes never go back. The owner keeps its copy (and its refreshes go
  back after it parks) unless the operator replaced the shared login since
  the last sync. Contents are compared, not mtimes (B-11b).
- **Grants of one pair combine**: adding a read grant keeps an existing
  write grant's `rwX`, and a revoke restores the widest remaining grant
  (the Python re-applied each in turn, the last one winning). Revoking the
  last write grant hands what the grantee created back to the target
  (upstream).
- **codex turns**: the running turn and the queued inputs share one lock;
  a steer refused because the turn just ended starts the next turn
  instead of queueing behind one that never comes; the next queued turn is
  started off the reader task (the Python awaited it inside the reader and
  stalled for the call's 120 s timeout).
- **Unit commands and env files**: every `$` in a unit's argv goes to
  systemd as `$$` (as hostd's fix); env-file values are double-quoted with
  `\`, `"`, `` ` `` and `$` escaped (the Python's `shlex.quote` single
  quotes were not systemd's syntax for a value with a `'`) (B-18).
- **Strict config and local API.** Unknown config keys and runtimes other
  than `claude`/`codex` are refused; new keys `codex_auth_owner` and
  `refuse_vm_logins_when_unreachable`; an agent VM's `name` has no `-`. Local API parameters must have their JSON types
  (the Python called `str()` on anything), unknown parameters are
  refused, and strings are bounded; a missing one still answers
  `internal error: '<name>'`. Projects list `sealed` as a boolean (the
  Python's SQLite gave 0/1).
- **Closed conversations' tokens stop working** and a TUI that ended by
  itself has its env file removed (B-18).
- **The gateway request waits for any undecided status** (up to 20 s;
  the Python waited only for approved/provisioning/pending).
- **sandboxctl prints log times in UTC** (no local time zone without libc).

Security review #5 (sandboxd), fixed. "Python" marks what the port
inherited from the Python; "port" what the port introduced.
- **No environment of sandboxd's reaches its children** (Python): every
  command sandboxd runs gets PATH and LANG only, and the tmux client
  commands (`new-session`, `has-session`, `capture-pane`, the idle check)
  run in a transient unit of their own (the project's uid, the agent
  units' protections, its tmp at `/tmp`, PATH/LANG/HOME only), never as
  the project's uid outside a unit, where its processes could read their
  environment. The `setpriv` config key is gone.
- **The operator's attach and shell run on a pty of their own** (Python):
  `sandboxctl attach|new|shell` run `systemd-run --pty --uid=… -p
  NoNewPrivileges=yes -p ProtectProc=invisible …` with TERM/LANG/PATH/HOME
  only; root relays the new pty, so no process of the project's uid holds
  an fd of the operator's root tty (no `/proc/<pid>/fd/0` grab, no
  TIOCSTI after a detach). The operator API's attach and shell answers
  carry `workdir` and `systemd_run` (additive).
- **A revoked write grant leaves the grantee nothing** (port): when the
  last write grant of a pair ends, everything the grantee owns in the
  target is reclaimed: directories become the target's, each regular file
  is replaced by a target-owned copy (a hard link elsewhere keeps its
  file), symlinks/FIFOs/sockets it owns are removed. Every tree walk
  (grants, revokes, seals, reclaims) fails with an error at the depth cap
  (128) instead of skipping what lies below. A revoke that fails keeps the
  grant recorded (it is retried, never forgotten with its ACL in place).
- **Freezes are verified** (Python ignored the result): `systemctl show -p
  FreezerState` must say `frozen`; three tries, then the unit is stopped
  and the error logged (a held agent's process never keeps running). A run
  or TUI that started while its agent was being held is frozen the same
  way, and a triage running when a hold arrives is stopped. The Kani
  harnesses (`proofs_sandbox.rs`) model freeze and thaw as succeeding;
  this fallback is what makes that assumption safe.
- **Keys only for this VM's agents** (Python): a `key` is stored only for
  `orchestrator-<host>-sandbox` or exactly `<runtime>-<project>-<host>-sandbox`
  of a project that exists in the VM; an agent without a project has none
  to run in (it no longer maps to the orchestrator's uid and home).
- **The orchestrator is its name, VM and lack of a parent** (port; the
  Python's bootstrap keyed on the runtime): minting and the `agents`
  catalog entry need `name == orchestrator-<daemon>-sandbox`, `sandbox_id ==
  the daemon` and no parent. Policy refuses `orchestrator` (and any name
  with `-` or other than lowercase letters and digits) in
  `platforms.agents.runtimes`.
- **Agent VM names have no `-`** (Python): pairing a sandbox daemon whose
  name has one is refused (and sandboxd's config refuses it), so
  `<runtime>-<project>-<host>-sandbox` reads one way only.
- **`/run/sandboxd` is created 0711** (`env/` 0700, the agent socket's
  directory 0755), modes set through a handle on each before any socket
  is bound, and a symlink in its place is refused. sandboxd refuses to run
  unless `fs.protected_hardlinks` is 1 (Python: the module's 0755, no
  check).
- **`POST /admin/agents/{id}/enable`** (new, admin only; `agent-auth admin
  agent-enable <agent>`): re-enables that agent (not what it minted) and
  clears its disable reason; a VM agent gets a new key for its sandbox in
  the same transaction (answer `{"enabled", "key_rotated"}`).
- **`key.rotate` is rate-limited per agent** on the broker (bursts of 2,
  then one per 5 minutes; Python: none).
- **A closed conversation's broker session is closed** and forgotten once
  the broker has it closed; a failure is retried by the reaper.
- **Keys reach a VM only after its greeting**: lock state, held list and
  live grants are sent on every connect before any key, and keys pushed
  by heartbeats, the tick or a mint wait until that connection has been
  greeted (a heartbeat push could overtake it before).
- **Project grants under races** (Python, B-7): a grant is recorded
  before waiting for its pair's lock; a revoke of an unknown id leaves a
  tombstone and a late grant with that id is refused; on every connect the
  broker sends `project.grants` (new message: the grant ids active or
  provisioning for the VM) and the VM revokes any other grant it holds.
- **Operator output is terminal-safe** (Python): `sandboxctl logs` and
  `ls` show C0/C1 controls (but newline and tab), DEL and bidi controls as
  `\u{..}`; a conversation title's peer must be an agent name.
- **codex logins** (Python): a project's copy of the shared login is
  deleted when its process uses the gateway and when its agent is
  contained; the owner's write-back must have codex's shape (`tokens` with
  a `refresh_token`) and the shared login's `account_id`; codex triage gets
  a fresh `CODEX_HOME` with only the login. Exposure, stated: a codex
  project not on the gateway holds a refresh token of the shared account
  in its `~/.codex/auth.json`, readable by every process of that project's
  uid, and can use (or leak) it for as long as the account allows.
- **Triage listing** (Python): only conversations that already talk to the
  peer are candidates (a matching topic alone no longer is), and peer and
  topic are inert in the listing.
- **Bounded inbox** (Python): at most 1000 queued messages and 8 MiB per
  conversation; a new message beyond is refused, and a thread whose
  message no longer fits is closed with `sandbox: the inbox of
  conversation … is full`.
- **No silent fallback to the VM's logins** (Python): with
  `refuse_vm_logins_when_unreachable` (default true) a broker that cannot
  be reached starts no process; a reachable broker without a gateway still
  means the VM's logins.
- **A thread's cursor moves past a message only once it is recorded**
  (Python moved it first: at most once): sent, or queued even if its
  process then failed to start. A message whose text could not be recorded
  is read again (at least once; deliveries happen under the thread's
  lock, so the claim and the watcher don't both deliver it).

## Packaging (`flake.nix`, `nix/`, `deploy/k8s`)

- **Modules keep the Python's names and options** (`services.agent-auth`,
  `-hostd`, `-sandboxd`, `darwinModules.hostd`). The broker module adds
  `database.createLocally` (PostgreSQL on the host, peer authentication on
  the socket; the Python's SQLite state directory is gone) and asserts that
  `environmentFiles` holds no Nix path literal (upstream review 2026-10)
  and that `settings` holds no secret.
- **Stricter units.** Broker: W^X memory (no cffi), `PrivateUsers`,
  `ProcSubset=pid`, `~@resources`, `LimitNOFILE=65536`, no state
  directory, working directory `/var/empty` (it reads `./.env`). hostd: W^X
  memory, and `ProcSubset=pid` when unprivileged.
- **Unprivileged hostd sees other users' processes** (no
  `ProtectProc=invisible`, which the Python unit had): hostd reads a local
  peer's `/proc/<pid>/cgroup` to refuse callers inside a job's unit
  (security review 2026-10, finding 1e/6) and refuses a peer it cannot
  place, so with the Python setting every hostctl and desktop-helper
  connection to a connect-only hostd would have been refused.
- **The desktop helper's unit has util-linux on its PATH**: hostd-user ends
  a withdrawn dialog with `kill`, which coreutils on NixOS does not ship.
- **sandboxd's runtime directories are created 0700** by the unit (the
  Python module's 0755; upstream review 2026-10, B-18) and sandboxd sets
  their modes itself (Agent VMs above).
- **sandboxd module**: `orchestratorRuntime` is `claude` or `codex` and
  must be in `runtimes` (assertions); `hostName` has no `-`; new options
  `max_processes_per_project`, `interactive_idle_secs`, `codex_auth_owner`,
  `refuse_vm_logins_when_unreachable`, `extraConfig`;
  `fs.protected_hardlinks` defaults to 1.
- **Image**: no shell and no CA bundle (the broker never reads the system
  store), uid 65532, no `HEALTHCHECK` (nothing to run it with; probe
  `/healthz`).
- **Kubernetes RBAC is scoped and fenced** (upstream review 2026-10): grant
  ServiceAccounts and their tokens only in `agent-auth-grants` (a Role);
  RoleBindings per namespace or cluster-wide by component;
  ClusterRoleBindings only with `components/cluster-grants`; a
  ValidatingAdmissionPolicy holds the broker's ServiceAccount to `aa-*`
  names, bindings of a ClusterRole to exactly the grant's own
  ServiceAccount, the cluster allowlist for ClusterRoleBindings, and no
  updates. A quota of zero pods in the grant namespace. Python's
  `deploy/k8s.yaml` gave a ClusterRole with unrestricted token creation.

## Open questions

(for Jacob; nothing here is implemented until decided)

- **Shells "one at a time"** (daemons bug 11): neither side enforces it
  (as in the Python); enforce on hostd (refuse a command while another of
  the same shell runs)?
- **Re-locking after a local unlock** (daemons bug 9): a host unlocked
  locally (or with its code) while the broker's flag is `*` is locked again
  at its next reconnect. Kept; intended?
- **Run grants kill their job at expiry** (bug 22) and **the window probe
  passes on an auto pattern** (bug 13): kept as in the Python.
- **TOTP hard-lock thresholds** (20 wrong codes in 30 days) are a guess at
  the right balance between typos and relayed guessing; tune?
- **Root shells now need a `root-shell` secret** (security review
  2026-10, finding 4): with only the four original secrets a root shell is
  refused. The review also allowed a polkit desk approval instead; that
  path isn't built (shells are approved on Discord only). Build it, or keep
  root shells TOTP-only? Likewise remote unlock now needs `root-unlock`.
- **A user-tier job can reach the user's service manager** and start a
  process outside its unit, past the `aa-job-*` peer check (and so arm
  the user tier via hostctl, or act as the desk helper). Close it by
  denying job units the user bus (`InaccessiblePaths=/run/user/<uid>/bus`
  and `.../systemd`, which breaks `systemctl --user` in jobs), or accept?

- **The CNPG CA on Kubernetes** (packaging): the broker verifies Postgres
  against a copy of CNPG's CA in a ConfigMap, which must be refreshed when
  CNPG renews its self-made CA. A cert-manager CA for the cluster
  (`spec.certificates`) with trust distribution would remove the manual
  step; that is a homelab change.
- **Where the broker runs**: on Kubernetes the gitops repo and the image
  registry decide its policy and RBAC (the reason the Python ran on
  recusant). The manifests are ready; whether to move is Jacob's call.

- **Panel logout is client-side only** (Bug-B1, unchanged): a copied
  session cookie stays valid until its `exp` (8 h). A server-side session
  table or a per-user generation would allow "sign out everywhere".
- **Consent can merge identities** (Bug-C5, unchanged): a new connector
  whose name normalizes to an existing `web-*` agent binds to it silently.
- **Does an empty `platforms.homelab.allowed_groups` mean "nothing"?**
  (provisioners B1). The Python (and the port, for now) reads it as "every
  group"; Kubernetes reads an empty `namespace_allowlist` as nothing, and
  the homelab catalog then lists no groups although all are grantable.
  The LLDAP administration groups are refused either way.
- **LLDAP over LDAP needs two new settings** (B4 fix): `LLDAP_LDAP_URL` and
  `LLDAP_BASE_DN` for managed accounts. Plain `ldap://` (the admin password
  in the clear) is refused at startup unless the host is loopback or
  `LLDAP_LDAP_ALLOW_PLAINTEXT=1` is set (then a warning is logged); use
  `ldaps://`.
- **Kubernetes `grant_namespace`** must exist before the first grant, with
  the broker allowed to manage ServiceAccounts (and request their tokens)
  there; existing grants made by the Python keep their ServiceAccounts
  where they are until they end.
- **Models user ids**: the port refuses a pre-existing gateway user it did
  not create (B12) instead of prefixing user ids; prefixing would change
  existing gateways' accounting.
- **B19**: should the credential route refuse web-UI OAuth callers? (The
  spine's route.)

- **Remote MCP redirect URIs.** The allowlist is now exact callback URIs
  (`remote_mcp.redirect_uris`, replacing `redirect_hosts`; a policy with the
  old key does not load). Defaults: `https://claude.ai/api/mcp/auth_callback`
  (from the Python tests), `https://claude.com/api/mcp/auth_callback` and
  `https://chatgpt.com/connector_platform_oauth_redirect` (not verified
  against the live services). Confirm or correct them.

- **Mail**: Gmail's search cannot see `X-SimpleLogin-Envelope-To`, so mail
  where an alias was only Bcc'd is not found (IMAP finds it). The judge's
  model provider reads every message and draft. Both by upstream's design;
  flagged there.

- **The shared codex login** (sandboxd B-11b, upstream flag): with
  `codex_auth_owner` unset nobody writes it back, so a refresh in any
  project may invalidate the shared refresh token for the others. Is a
  shared refreshable login still wanted, or one login per project?
- **codex triage keeps its read-only tools** (B-16): `codex exec -s
  read-only` still has its read-only shell tools while reading untrusted
  text (now with a fresh CODEX_HOME), and uses the runtime's normal model
  when `triage_model` is unset.
- **Conversations are never closed automatically** (B-18): a closed one's
  broker session is now closed (and retried), but open conversations keep
  theirs. Close idle conversations after some time?
- **Triage picks the candidate whose id appears in the answer** (B-18):
  kept (exactly one must match).

## To do (engineering, tracked here until done)

- Local unix-socket protocols (hostctl, hostd-user, sandboxd local API) are
  typed in the daemon crate, not wire.
- A missing `POLICY_FILE` (B-12): the broker refuses to start.
- ES256 MCP token key: derived from `BROKER_SIGNING_KEY` via ring's
  deprecated `test::rand::FixedSliceRandom` (ring has no scalar-to-key
  constructor). Pinned by known-answer tests against the Python; revisit
  (a dedicated PKCS#8 key) in review.
- Store lock-order doc vs. the finish phase (grant before request row):
  verify in the next review that no path locks request then grant.
- At shutdown, end long-polls early with their current state instead of
  cutting them off after the 10 s drain ("could not reach the broker").
