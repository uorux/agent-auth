# Deliberate differences from the Python

Each entry: where (spec section), what the Python did, what the Rust does,
and why. Keep entries short. Group by area.

## Core

- **Globs** (core-lifecycle-policy §5.1). A reversed range like `[z-a]`
  matches nothing; CPython merges neighbouring chunks of the set (and can
  raise on some inputs). Ordinary patterns behave identically.
- **Authority scopes are strict** (§6.1). Unknown scope keys are refused at
  request time on every platform. The Python ignored them on most platforms
  and stored an a2a scope verbatim (any keys) as the authority.
- **Stored authorities are canonical** (§6). A stored authority that this
  version would not have written (extra keys, wrong types) is an error
  rather than being read loosely.
- **Database**: Postgres only; a new schema (no migration from the Python's).

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

## Open questions

(for Jacob; nothing here is implemented until decided)

- **Operator-thread delegation** (a2a B1): `grants::begin` keeps the
  Python behavior (a thread without a backing grant cannot carry a
  delegated grant: provision fails "delegation thread is no longer
  open"). Allow it with some other expiry cap, or refuse it up front?
- **Events cursor** (a2a B3): `last_activity_at` from the application clock
  can commit out of order. Not addressed in the schema yet; options are a
  commit-ordered sequence or an overlap window in the reader.
