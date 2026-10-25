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
  like `0` (Python returned 0); at most 2147483647 s, else 422 `duration
  must be at most 2147483647 seconds` (Python: no bound, a 500 on
  Postgres). Same for `DecideBody.duration`. Only ASCII digits count
  (Python's `\d`/`isdigit` took other Unicode digits).
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

## Open questions

(for Jacob; nothing here is implemented until decided)

- **a2a payload cap measure** (wire): the 16384 cap is measured with
  Python's `json.dumps` length, whose encoder is core's
  (`core::canonical_json`, not merged when wire was written).
  `wire::payload::Payload::sized` takes that function as an argument; once
  it lands, the check can move into `Payload`'s deserializer.
- **Core ids accept any UUID spelling when deserialized** (wire): the id
  types' `FromStr` takes only the canonical lowercase hyphenated form, but
  their serde `Deserialize` is `transparent` over `Uuid`, which also takes
  upper case, simple, braced and URN forms (they re-serialize canonically).
  Should core's `Deserialize` use the canonical parser?
- **Not modelled in wire**: the local unix-socket protocols (hostctl,
  hostd-user, sandboxd's local API, JSON lines) belong to the daemon crate;
  the containment `match` stays bounded JSON until policy's `AgentMatch`
  type exists.
- **Python client bug** (for the client port): `host_shell_exec` continues
  waiting only if `job.get("id")`, but a job carries `job_id`, so a long
  `wait` stops after the first slice.
