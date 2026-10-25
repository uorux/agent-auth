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
  `agents::set_lease` only moves the lease; re-enabling is explicit.
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
  panel's own address; any other port still is not.
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
- **Clients nobody authorized expire** (Bug-C6): an unbound client is
  "unknown client" one hour after registering, and such clients (with no
  tokens) are deleted at the next registration, so they no longer fill
  `max_clients` for good. No rate limit yet.
- **Codes and refresh tokens are consumed atomically** (Bug-C2,
  `store::oauth::consume`): of concurrent exchanges of one code exactly one
  succeeds; the others see a replay and revoke the family (including what
  the winner got), durably.
- **A code exchange checks the agent is enabled** too ("the connector's
  agent is disabled"; the Python checked only at refresh).
- **`get_credential` is never served on `/mcp`**, even if listed in
  `remote_mcp.tools` (a warning at startup). The agent API must also refuse
  a connector's token on the credential route (spine; Bug-C1).
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
- **Not yet ported** (hostexec Discord UI, a follow-up): "Approve all…"
  (window rules) is not offered on run/template cards; /arm, /disarm,
  /lockdown, /unlock, /dnd and /hosts are not registered. "Approve with
  TOTP" and "End shell" work through the generic decision/revoke
  interfaces.

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
- **Operator-thread delegation is refused up front** (a2a B1, open
  question below): `a2a::delegation::resolve` answers `a thread with the
  operator cannot back a delegated request (not supported yet); request
  the access on your own behalf`.
- **Legacy thread-less messages** do not exist (`a2a_messages.thread_id` is
  NOT NULL), so `test_legacy_null_thread_messages_invisible` is not ported.
- **Not changed**: a sessionless caller still lists, and gets activity for,
  its agent's session-bound threads (a2a B8, metadata only; every read is
  403).
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
  to the broker log. Transport failures say `GitHub API unreachable (...)`,
  `LLDAP unreachable (...)`, `model gateway: ...` without URLs (the
  Python's uncaught httpx text could include them).
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
  `ldaps://host:6360`) and `LLDAP_BASE_DN` (`dc=example,dc=com`).
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

## Wiki (`broker/src/wiki`)

- **`last_change` is cached per (path, blob sha), and a failed lookup is
  not cached** (a2a B12): two pages with the same content no longer share
  an author, and a transient GitHub error no longer hides it until the page
  changes.
- **The commit summary is checked for credentials too** (a2a B13), on
  write and delete, with the same 400 text as for the content.
- **A truncated tree listing is logged** (a2a B15).
- A write or delete GitHub could not be reached for answers 502 `the wiki's
  repo refused the <write|delete> (unreachable)` (the Python raised a 500).
- Query parameters missing on `/v1/wiki/page` (`path`) or `/search` (`q`)
  are 422 `{"detail": "query parameter '<p>' is required"}`.

## Open questions

(for Jacob; nothing here is implemented until decided)

- **Operator-thread delegation** (a2a B1). The README says an agent can
  request access on the operator's behalf from an admin-panel chat thread,
  but the Python refuses it at provisioning (such a thread has no backing
  grant, and provisioning requires one), so it never worked. The port keeps
  that refusal (it now fails up front with a clear reason). Allowing it
  would mean a delegated grant capped only by its own duration and revoked
  when the chat thread closes.

- **Panel logout is client-side only** (Bug-B1, unchanged): a copied
  session cookie stays valid until its `exp` (8 h). A server-side session
  table or a per-user generation would allow "sign out everywhere".
- **Consent can merge identities** (Bug-C5, unchanged): a new connector
  whose name normalizes to an existing `web-*` agent binds to it silently.
- **`/release` with no entry lifts every containment** (Discord, as the
  Python; its option says so). The admin API now needs an explicit
  `{"all": true}`. Should Discord ask for confirmation, or require an entry?
- **Does an empty `platforms.homelab.allowed_groups` mean "nothing"?**
  (provisioners B1). The Python (and the port, for now) reads it as "every
  group"; Kubernetes reads an empty `namespace_allowlist` as nothing, and
  the homelab catalog then lists no groups although all are grantable.
  The LLDAP administration groups are refused either way.
- **LLDAP over LDAP needs two new settings** (B4 fix): `LLDAP_LDAP_URL` and
  `LLDAP_BASE_DN` for managed accounts. Plain `ldap://` sends the admin
  password like the existing HTTP login to `LLDAP_URL` does; prefer
  `ldaps://` when LLDAP is not on a trusted network.
- **Models user ids**: the port refuses a pre-existing gateway user it did
  not create (B12) instead of prefixing user ids; prefixing would change
  existing gateways' accounting.
- **B19**: should the credential route refuse web-UI OAuth callers? (The
  spine's route.)

## To do (engineering, tracked here until done)

- Local unix-socket protocols (hostctl, hostd-user, sandboxd local API) are
  typed in the daemon crate, not wire.
- A missing `POLICY_FILE` (B-12): the broker refuses to start.
- ES256 MCP token key: derived from `BROKER_SIGNING_KEY` via ring's
  deprecated `test::rand::FixedSliceRandom` (ring has no scalar-to-key
  constructor). Pinned by known-answer tests against the Python; revisit
  (a dedicated PKCS#8 key) in review.
