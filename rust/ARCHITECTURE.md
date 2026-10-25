# agent-auth in Rust: architecture and rules

This is the contract every part of the port follows. The behavior to
reproduce is in `spec/*.md` (written from the Python in `../src`, which you
can and should read). Where the Python is wrong, we fix it and record the
change in `DEVIATIONS.md`.

## Goals, in order

1. **Secure.** No `unsafe` anywhere (`#![forbid(unsafe_code)]` in every
   crate root, checked by `scripts/check.sh`). If something truly seems to
   need it, stop and report it — do not work around the lint.
2. **Invalid states unrepresentable.** Authentication, authorization,
   containment and state-machine transitions are enforced by types, so the
   compiler rejects a handler that acts for an unauthenticated caller or a
   transition the state machine does not allow (patterns below).
3. **Verified where it matters.** Pure security logic lives in
   `agent-auth-core`, is exhaustively tested or property-tested, and has
   Kani harnesses (`#[cfg(kani)]`). Every parser of untrusted input has a
   fuzz target (`rust/fuzz`).
4. **Same interface.** Agents and the operator should not notice the
   switch: same routes, JSON shapes, MCP tool names/descriptions/parameters,
   CLI commands, Discord cards, error strings (verbatim from the spec),
   policy YAML. No data or wire compatibility with the Python is required
   (the database is new, Postgres only), but where a wire protocol is
   sound, keep it (daemon channel, pairing) — it makes a mixed rollout
   possible.

## Crates (`rust/crates/*`)

| crate | what | may depend on |
|---|---|---|
| `agent-auth-core` | pure domain: ids, `Platform`, request/grant state machines (typestate), `Authority`, globs, routing gates, policy file schema + evaluation, zones logic, hostexec job specs, durations, validated names. **No I/O, no async, no time source** (time is passed in). | serde, serde_json, thiserror, time, uuid, regex (policy patterns) |
| `agent-auth-crypto` | `ring`-based: API keys, at-rest `SecretBox` (AEAD), webhook HMAC, daemon pairing/hello/envelopes, TOTP, canonical JSON + digests, `Secret<T>`. | ring, base64, hex, zeroize, serde_json |
| `agent-auth-tls` | the one rustls client config (ring, TLS 1.2/1.3, Mozilla roots minus distrusted ones, optional extra CA) and a reqwest builder with no proxy/redirects/compression. Every outbound connection uses it. | rustls, webpki-roots, reqwest |
| `agent-auth-wire` | serde types of every JSON body on the wire: agent API, admin API, daemon channel messages, credential shapes. Shared by broker, client, CLI, MCP, daemons. | core |
| `agent-auth-store` | Postgres: migrations (`crates/store/migrations`), row types, **all SQL**, and the state-transition kernel (guarded transitions, `IssuableGrant`, containment checks inside the transaction). | core, sqlx |
| `agent-auth-mail` | reading untrusted mail (MIME via mail-parser, HTML, injection hints), composing what is sent, minimal IMAP and SMTP clients over TLS (tokio-rustls with the shared config); test doubles behind feature `testing`. | core, mail-parser, rustls, tokio-rustls |
| `agent-auth-broker` | the server binary `agent-auth-server`: config, HTTP API (axum), auth extractors, request service, LLM review, provisioners, a2a, wiki, desktop, Discord bot, admin panel, OAuth + remote MCP, daemon hub, hostexec, sandboxes, scheduler. | everything above |
| `agent-auth-client` | the agents' HTTP client library. | wire |
| `agent-auth-cli` | binary `agent-auth` (agent and admin commands). | client |
| `agent-auth-mcp` | binaries `agent-auth-mcp` (stdio) and `agent-auth-mcp-bridge`. | client, rmcp |
| `agent-auth-daemon` | what hostd and sandboxd share: the broker channel client, local unix-socket server with peer-credential checks, key files. | crypto, wire |
| `agent-auth-hostd` | binaries `agent-auth-hostd`, `agent-auth-hostctl`. | daemon, core |
| `agent-auth-sandboxd` | binaries `agent-auth-sandboxd`, `agent-auth-sandboxctl`, `agent-auth-sandbox-mcp`; its state is local to the VM (atomic JSON documents, no SQLite). | daemon, client, mcp, core |

All SQL lives in `agent-auth-store`, one module per domain
(`store/src/requests.rs`, `a2a.rs`, `hostexec.rs`, ...), so feature work in
parallel touches different files.

## Type patterns (mandatory)

**Principals.** Every authenticated caller is a value only the auth module
can build (private fields, no `Default`, no `Deserialize`):
`AgentCaller` (agent + optional session; built by verifying an API key or an
OAuth access token), `AdminCaller` (admin token or a signed-in panel session
with CSRF checked), `DaemonPeer` (a paired daemon whose hello verified),
`DiscordOwner` (an interaction from the configured owner id). They are axum
extractors. A handler that changes or reveals anything takes one; the few
unauthenticated routes are listed in one place (`broker::http::public`). A
service function acting for an agent takes `&AgentCaller`, never an id.

**Containment.** "Is this agent held?" is answered inside the transaction
that acts on it: `store::lockdown::check(&mut tx, agent) -> Result<NotHeld<'tx>, Held>`,
and the operations that grant anything (begin/finish provisioning, issuing a
credential, opening a thread) require a `NotHeld<'tx>` borrowed from the
same transaction, so the check cannot be skipped or done in another one.

**State transitions.** `core::lifecycle` implements `CanMoveTo<To>` only for
allowed edges. `store::requests::transition::<From, To>(tx, Request<From>)`
does the compare-and-swap (`UPDATE ... WHERE id = $1 AND status = From::STATUS`)
and returns `Request<To>`, or `Lost` when someone else moved it first.
Loading a request yields `AnyRequest` (an enum over states) to match on.

**Clearances.** An automatic approval takes a `core::routing::AutoClearance`,
which only `core::routing::route` makes (after every gate). A human approval
takes a `HumanApproval`, which only an authenticated human surface makes
(`DiscordOwner`, `AdminCaller`). The LLM-approve path re-runs `route` with
the current facts and requires `Route::Llm`.

**Issuing credentials.** Provisioners' `credential` takes an `IssuableGrant`,
which `store::grants::issuable(tx, agent_id, grant_id, now)` builds only
for the caller's own grant that is `active`, unexpired, whose agent is not
held, and (if delegated) whose thread is open and backing grant active.
(The store cannot name `AgentCaller`, a broker type; the agent id it
takes comes from the caller in the one place that issues credentials,
the broker's credential route, which takes an `AgentCaller`.)
This replaces the Python's per-provisioner checks.

**Secrets.** Tokens, keys, passwords and TOTP seeds are `crypto::Secret<T>`:
no `Debug`/`Display`/`Serialize` that reveals them, zeroized on drop,
`expose()` to read. Logs never contain them.

**Parse, don't validate.** Names (`AgentName`, `HostName`, `GroupName`,
`RepoName`...) are newtypes whose only constructor validates. Wire bodies
deserialize with `#[serde(deny_unknown_fields)]` and explicit limits.

**hostd admission.** A job runs only as an `AdmittedJob`, which only the
admission function makes; a TOTP code yields a `TotpApproval { tier, digest }`
and admission requires the job's own tier and digest (the Python fix in
e6640af: a code approves a job of its own tier only).

## Errors and robustness

- No `unwrap`/`expect`/`panic!`/indexing in non-test code (clippy denies
  them under `scripts/check.sh`); arithmetic is checked or saturating.
- HTTP errors keep the Python shape `{"detail": "..."}` and status codes.
- Every request body has a size limit; every list/map/string from the wire
  has a bound; every long-poll clamps its wait (NaN → no wait).
- Outbound HTTP: `agent-auth-tls::reqwest_builder` (rustls + ring, the
  shared root store: webpki-roots minus the distrusted eMudhra roots), timeouts on every call, redirects off unless needed, no
  compression, no proxy from the environment.
- Constant-time comparison for every secret comparison.

## Time

`time::OffsetDateTime`, always UTC. Core functions take `now` as an
argument. Postgres `timestamptz`. On the wire: RFC 3339 with microseconds
and `Z` (one format everywhere; the Python mixed `Z` and `+00:00`).

## Dependencies

Only `[workspace.dependencies]`, default features off, minimal features on.
Adding one: justify it (well known, maintained, little or no unsafe), add it
to the workspace with minimal features, run `python3 -I scripts/cooldown.py
fix` then `cargo deny check`. No compression codecs, no OpenSSL/native-tls,
no aws-lc, no HTTP/2. Prefer writing 50 lines over adding a crate.

## Testing

- Unit tests next to the code; property tests (proptest) for parsers and
  predicates; Kani harnesses for pure security logic.
- Kani: `scripts/kani.sh` runs every harness (`#[kani::proof]`) in every
  crate that has one, inside the `kani` dev shell (`nix develop .#kani`,
  Kani 0.68.0 from `nix/kani.nix`: the release bundle patched for NixOS,
  plus the exact nightly it was built against). Extra arguments go to
  `cargo kani`, e.g. `scripts/kani.sh --harness status_machine`. A harness
  that loops needs `#[kani::unwind(N)]`; Kani's unwinding assertions fail
  the proof when N is too small, so a bound can never pass silently.
- Database tests: `#[sqlx::test(migrations = "../store/migrations")]`
  (a fresh database per test) against `scripts/pg.sh start`.
- HTTP tests drive the axum `Router` with `tower::ServiceExt::oneshot`.
- External services (GitHub, LLDAP, Kubernetes, LiteLLM, OpenRouter, Discord)
  are faked with small local axum servers in tests; nothing in the test
  suite talks to the network.
- Port the tests listed in the spec's "tests worth porting" section.

## Deployment

Exactly one broker per database: long-poll wake-ups, the a2a activity
stamps, the security log, background LLM evaluations and the daemon hub
live in the process, and the boot-time reaper fails every PROVISIONING
grant. The broker takes a session-level advisory lock
(`store::instance::try_lock`) on a connection it holds for its whole life;
a second broker on the same database logs why and exits. On Kubernetes:
`replicas: 1`, `strategy: Recreate` (a rolling update would start the new
pod while the old one holds the lock).

## Working on a part (subagents)

1. Work in your own worktree:
   `git -C /home/jrt/Documents/agent-auth worktree add /home/jrt/Documents/agent-auth/.claude/worktrees/rust-<part> -b rust-<part> rust-port`
   and do everything there (never in another checkout).
2. Toolchain: prefix commands with `nix develop /home/jrt/Documents/agent-auth/.claude/worktrees/rust-<part>/rust#default -c` (or `#nightly` for miri/fuzz).
3. Database: `scripts/pg.sh start` prints a `DATABASE_URL` (one server per worktree).
4. Before finishing: `scripts/check.sh` must pass (or say exactly what fails
   and why). Commit on your branch with a message saying what and why, ending with
   `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
5. Record every deliberate behavior change in `DEVIATIONS.md` (spec section,
   old behavior, new behavior, reason) and anything you could not decide
   under "Open questions" there.
