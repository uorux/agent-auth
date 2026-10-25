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
- **`explicit` needs the rule's platform** (§5.3, bug B-16). A policy-file
  rule names a privilege (clearing github create, agents, hostexec, mcp,
  models) only when its `match.platform` is set and `match.capability` is
  literally the capability. `{match: {capability: use}}` written for MCP no
  longer clears model keys.
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
  accepted e.g. Arabic-Indic digits).
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

## Open questions

(for Jacob; nothing here is implemented until decided)

- **A missing base policy file** (bug B-12). `Policy::load` takes the
  file's text, so whether a missing `POLICY_FILE` is an error is the
  broker's call; the spec recommends refusing to start.
- **Spec erratum, daemons-hostd §6.3**: Python's `json.dumps(...,
  ensure_ascii=True)` escapes DEL (0x7f) as `\u007f`; the spec says it is
  emitted raw. The canonical-JSON digest must escape it to stay compatible.
- **Operator-thread delegation** (a2a B1): `grants::begin` keeps the
  Python behavior (a thread without a backing grant cannot carry a
  delegated grant: provision fails "delegation thread is no longer
  open"). Allow it with some other expiry cap, or refuse it up front?
- **Events cursor** (a2a B3): `last_activity_at` from the application clock
  can commit out of order. Not addressed in the schema yet; options are a
  commit-ordered sequence or an overlap window in the reader.
