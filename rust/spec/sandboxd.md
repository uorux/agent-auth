# sandboxd and the broker side of agent VMs: behavioral spec

Scope: the daemon inside an agent VM (`src/agent_auth/sandboxd/*`), and the broker
code that serves agent VMs: `core/sandboxes.py` (orchestrator bootstrap, key
custody and delivery, minting, leases), `provisioners/agents.py` (platform
`agents`), `provisioners/sandbox.py` (platform `sandbox`), and the sandbox parts
of `authority.py`, `core/zones.py`, `api/catalog.py`, `core/hostexec.py` and
`core/lockdown.py`.

Out of scope, specified elsewhere: the daemon channel (pairing, ed25519 identity
key, signed envelopes, heartbeats, `hub.call`/`reply` correlation, reconnect) is in
`rust/spec/daemons-hostd.md`. This document covers only the message types
specific to role `sandbox`. The a2a API, sessions, the model gateway and the MCP
bridge are referenced by the endpoints sandboxd calls, not specified here.

Storage: the broker side is PostgreSQL. sandboxd's own state is local to the VM
(SQLite in Python, `state.py`). The port must keep it local to the VM (embedded
SQLite or similar). It must not go into the broker's Postgres, because the agent
keys must exist only inside the VM (INV-1).

Citations are `file:line` relative to `src/agent_auth/` unless they start with
`tests/`, `docs/` or `flake.nix`.

---

## 1. Concepts and names

| thing | value | source |
|---|---|---|
| daemon role | `"sandbox"` | `sandboxd/daemon.py:44`, `core/sandboxes.py:37` |
| daemon name | the **physical** host name (`Config.name`); NixOS option `hostName` matches `[a-z0-9][a-z0-9-]{0,62}` | `flake.nix:1013` |
| orchestrator agent | `orchestrator-<host>-sandbox`, runtime `"orchestrator"` in the broker | `core/sandboxes.py:38,48` |
| minted agent | `<runtime>-<project>-<host>-sandbox` | `core/sandboxes.py:52` |
| project name regex (both sides) | `[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?`, a full match of 1 to 30 chars | `core/sandboxes.py:41`, `sandboxd/daemon.py:45` |
| project unix user | `p-<project>` (user name and group name; gid = uid) | `sandboxd/host.py:38` |
| orchestrator unix user | `sbx-orchestrator`, uid = `uid_base` (40000) | `sandboxd/host.py:34`, `daemon.py:411-413` |
| orchestrator dir name | `_orchestrator` (its home and tmp); its workspace is `<sandbox_root>/orchestrator` | `host.py:35`, `daemon.py:405-409` |
| conversation id | `uuid4().hex[:12]` (12 lowercase hex) | `state.py:134` |
| unit names | `sbx-conv-<conv>`, `sbx-tui-<conv>`, `sbx-triage-<12 hex>` | `daemon.py:618-622,589` |
| MCP server name (catalog bridge) | must fully match `[a-z0-9][a-z0-9-]{0,62}` | `daemon.py:46,805` |

Names are **never parsed for trust** on the broker. Runtime, project, host,
sandbox_id and parent are stored as columns. The mint validator derives
`(runtime, project)` from the name only to check that the name equals
`agent_name(runtime, project, daemon.name)` for the requester's own daemon
(`provisioners/agents.py:43-66`).

---

## 2. Broker side

### 2.1 Schema (Postgres)

`agents`, sandbox-related columns (`models.py:133-153`):
- `parent_agent_id` (FK agents.id, nullable, indexed): the agent whose mint created
  this one.
- `sandbox_id` (FK daemons.id, `ON DELETE SET NULL`, nullable, indexed): the daemon
  that holds the key and dispatches a2a.
- `runtime` (≤16), `project` (≤64), `host` (≤64), nullable.
- `placement` (`"host"` default | `"sandbox"`).
- `lease_expires_at` (timestamptz, nullable; null = no lease).

`pending_key_deliveries` (`models.py:429-443`, migration
`migrations/versions/e1f2a3b4c5d6_sandbox_agents.py`):
- `id` (uuid string PK)
- `agent_id` (FK agents.id, **UNIQUE**: at most one pending key per agent)
- `sandbox_id` (FK daemons.id, `ON DELETE CASCADE`, indexed)
- `key_encrypted` (text: Fernet token of the full API key, under `ENCRYPTION_KEY`)
- `created_at`

Enum `platform` gains `agents` and `sandbox`.

### 2.2 SandboxService wiring (`core/sandboxes.py:88-97`)

Constructed with `(db, hub, secret_box | None)`. It registers:
- `hub.on_paired(_paired)`
- `hub.on_connect(_push_keys)` and `hub.on_heartbeat(_push_keys)`: on every
  connect and on **every heartbeat** of a sandbox, all of its pending keys are
  pushed again.
- `hub.handle("key.ack", _key_ack)` and `hub.handle("key.rotate", _key_rotate)`.

Hooks and handlers must not raise. Errors are logged and swallowed by the hub.

### 2.3 Orchestrator bootstrap on (re-)pairing (`core/sandboxes.py:199-235`)

On a successful pairing of `(role="sandbox", name, daemon_id)`. Re-pairing an
existing (role, name) keeps the same `daemons.id` (`core/daemons.py:331-341`).
1. Look up the agent named `orchestrator-<name>-sandbox`.
2. If it is absent, create it: `kind="service"`, `runtime="orchestrator"`,
   `host=name`, `placement="sandbox"`, `sandbox_id=daemon_id`, no parent, no
   lease, `last_seen_at=now`, and a description. Generate a key and queue its
   delivery. Done.
3. If it exists with `sandbox_id ∉ {NULL, daemon_id}` or `runtime != "orchestrator"`,
   log an error and **do nothing**: no takeover of a same-named agent.
4. Otherwise set `sandbox_id=daemon_id`, `host=name`, `placement="sandbox"`,
   `disabled=False`, and **rotate**: generate a new key, which replaces `key_id`
   and `api_key_hash` (the old key stops authenticating at once), and queue it.
   Covered by `tests/test_sandboxes.py::test_repairing_rotates_the_orchestrator_key`.

If `ENCRYPTION_KEY` is unset, `_wrap` raises `SandboxError("ENCRYPTION_KEY is
required to hand keys to a sandbox")`. The hook fails and the transaction rolls
back (`core/sandboxes.py:101-104`).

### 2.4 Key queueing and delivery

- `_queue_delivery(agent, full_key)`: delete any existing row for `agent.id`, then
  insert `{agent_id, sandbox_id: agent.sandbox_id, key_encrypted: Fernet(full_key)}`
  (`:113-121`).
- `_queue_key(agent)`: generate a new key (`aa_<key_id 12 hex>_<secret>`; the hash
  is sha256 of the secret; `crypto.py:12-21`), set `agent.key_id` and
  `api_key_hash`, then `_queue_delivery` (`:106-111`).
- `_push(role, name, daemon_id)` (`:143-166`): select the rows joined to agents
  `WHERE pending.sandbox_id = daemon_id`. For each row, send (fire-and-forget
  `hub.send`, no call_id):
  ```json
  {"type": "key", "agent_id": "<uuid>", "name": "<agent name>",
   "runtime": "<runtime|orchestrator>", "project": "<project|null>",
   "api_key": "<plaintext full key>"}
  ```
  Without a secret box it returns silently.
- `nudge(daemon_id, delay=0.5)`: after 0.5 s (so that the caller's transaction has
  committed), `push_keys_to(daemon_id)`, which pushes only if that daemon is online
  (`:123-137`). Heartbeats retry anyway.
- `_key_ack(live, {"agent_id"})` (`:168-179`): if `agent_id` is a string, delete
  rows with `agent_id = msg.agent_id AND sandbox_id = live.daemon_id`. An ack from
  any other daemon deletes nothing.
- `_key_rotate(live, {"name"})` (`:181-195`): only when `live.role == "sandbox"`
  and `name` is a string. Look the agent up by name. Refuse (log a warning, no
  reply) unless `agent.sandbox_id == live.daemon_id` and `not agent.disabled`.
  Otherwise `_queue_key` (a new key; the old one dies at once) and `_push` to this
  daemon right away. This also applies to the orchestrator. There is no rate
  limit.

The broker stores only key hashes. The pending row is the only place where a
plaintext key can be recovered, and it is deleted on ack, on
`disable_agent_tree`, by the replacement in `_queue_delivery`, and by cascade
when the daemon row is deleted.

### 2.5 Minting: platform `agents` (`provisioners/agents.py`, `core/sandboxes.py:239-284`)

Request: `platform="agents"`, `capability="mint"`, `resource="<runtime>-<project>-<host>-sandbox"`,
`scope={"runtime": <rt>}` (optional).

`validate_request` (`provisioners/agents.py:31-66`), in this order:
1. `capability != "mint"` → `SpecValidationError("agents capability must be 'mint'")`.
2. `config.runtimes` is empty → "minting is disabled (platforms.agents.runtimes is empty)".
3. The requester's `sandbox_id` must name a daemon whose role is `sandbox`;
   otherwise "only agents running in an agent VM can mint identities". **Any**
   agent in a VM passes this check, minted project agents included, not only the
   orchestrator. Restricting minting to the orchestrator is policy's job.
4. If `HostExecService.locked(session, daemon.name)` (the broker lockdown flag has
   `"*"` or this host) → "locked down: no identities are minted until it is lifted".
5. `name = resource.strip().lower()`, `suffix = "-<daemon.name>-sandbox"`. `runtime`
   = the first configured runtime `r` such that the name starts with `r + "-"`
   and ends with the suffix; none → "resource must be '<runtime>-<project><suffix>'
   with runtime one of …". The runtime set is hyphen-free by convention, so the
   first-match rule is unambiguous.
6. `project = name[len(runtime)+1 : -len(suffix)]` must match PROJECT_RE; otherwise
   "invalid project name … (lowercase letters, digits and '-', ≤30)".
7. `scope.runtime ∉ {None, runtime}`, or a scope key other than `runtime` → "scope
   may only repeat the name's runtime".
8. Normalize: `resource = name`, `scope = {"runtime": runtime}`, and add the note
   `"mints <name> (<rt> on project <p>) in the agent VM on <host>"`.

Authority (`authority.py:46-49,96-97,131-132`): `fold` = `{"action": "mint",
"runtime": rt}`, `split` → `("mint", {"runtime": rt})`, label `mint:<rt>`.
`needs_explicit_rule(AGENTS) = True` (`authority.py:157-160`): only a rule that
names `mint` can approve it or route it to the LLM. Catch-alls cannot
(`tests/test_sandboxes.py::test_a_catchall_rule_does_not_clear_a_mint` →
AWAITING_HUMAN). Zones (`core/zones.py:130-148`): if the would-be agent (name,
runtime, derived project, host, placement sandbox, kind service) belongs to any
restricted zone, the result is `("human", "mints an agent inside restricted zone …:
always a human")`.

`provision` (`provisioners/agents.py:68-89`):
- Load the parent (`grant.agent_id`) and its daemon. If either is missing →
  ProvisionerError "the requesting agent is no longer in an agent VM".
- `project = grant.resource[len(runtime)+1 : -len("-<daemon.name>-sandbox")]`.
- Call `SandboxService.mint(session, parent, runtime, project, lease_secs)`:
  - The parent's daemon must exist with role sandbox, else SandboxError "only agents
    in an agent VM can mint".
  - Existing agent with that name:
    - If `sandbox_id != daemon.id`, `runtime != runtime` or `project != project` →
      SandboxError "<name> exists and doesn't belong to this sandbox".
    - Otherwise **renew**: set `lease_expires_at = now + lease_secs` and
      `disabled = False`. The key is **not** rotated and nothing is queued. Return
      `created=False`. The parent is not compared.
  - New agent: `kind="service"`, `parent_agent_id=parent.id`,
    `sandbox_id=daemon.id`, `runtime`, `project`, `host=daemon.name` (always the
    daemon's, whatever was asked), `placement="sandbox"`, `lease_expires_at=now+lease`,
    `last_seen_at=now`, and a description. Flush, then `_queue_delivery` with a
    newly generated key. Return `created=True`.
- SandboxError → ProvisionerError(str).
- `nudge(daemon.id)`.
- provisioner_state: `{"agent_id", "name", "created": bool, "lease_expires_at": iso}`.

`revoke`: does nothing. The identity lives by its lease, not by the mint grant.

`get_credential` → `CredentialOut(kind="agent_identity", value=<name>, note=
"minted|renewed; lease until <iso>. Its key went to the sandbox daemon, which runs
it — you never hold it.")`. **Never the key.**

Config `platforms.agents` (`policy/schema.py:169-186`): `runtimes: list[str] =
["claude","codex"]` (empty disables minting), `lease: str|int = "30d"` (a duration,
validated; `lease_secs`).

Catalog (`api/catalog.py:86-104`): the `agents` platform appears only if
`agent.sandbox_id` is set and the platform is enabled (`capability_hint "mint"`,
`resource_hint "<runtime>-<project>-<this host>-sandbox"`, `capabilities =
runtimes`). The `sandbox` platform appears only if `sandbox_id` and `project` are
both set.

### 2.6 Leases and the disable cascade

`disable_agent_tree(session, agent_id) -> [names]` (`core/sandboxes.py:56-84`):
an iterative DFS over `parent_agent_id` children with a `seen` set. For each agent:
`disabled=True`; every ACTIVE grant of that agent gets `expires_at=now` (the
scheduler's next expiry pass revokes them through their provisioners); delete its
`pending_key_deliveries` row. Returns the names. Used by:
- `POST /admin/agents/{id}/disable` (`api/admin_routes.py:495-503`; 404 if the
  agent is unknown; returns `{"disabled": [names]}`).
- `sweep_leases()` (`core/sandboxes.py:288-305`): select agents with
  `lease_expires_at IS NOT NULL AND lease_expires_at <= now AND NOT disabled`,
  run `disable_agent_tree` on each, and return the total count of disabled names.
  The scheduler runs it every tick, after grant expiry and the a2a sweep
  (`core/scheduler.py:71-77`), so the next tick's expiry pass ends the grants.

A disabled agent's key fails auth with 401 "invalid API key" (`api/deps.py:84-97`).
sandboxd is **not** told about a disable or a lease expiry.

Admin restrictions: `PATCH /admin/agents/{id}/attributes` and
`POST /admin/agents/{id}/rename` → 409 for agents with `sandbox_id` set
(`api/admin_routes.py:120,143`). `POST /admin/agents/{id}/rotate-key` is **not**
restricted: it returns the new key to the admin, and the VM's copy dies (see
§7, B-10).

### 2.7 Platform `sandbox`: cross-project access (`provisioners/sandbox.py`)

Request: `capability ∈ {"project.read","project.write"}`, `resource = target
project`, `scope = {}`.

`validate_request` (`:31-49`), in this order: capability not in ACCESS → error; the
requester has no `sandbox_id` or no `project` → "only a project's agent in an agent
VM can ask for this" (so the orchestrator, whose project is null, cannot ask);
`target = resource.strip().lower()` must match PROJECT_RE; `target ==
agent.project` → "that's your own project"; a non-empty scope → "no scope for
sandbox grants". Normalize the resource and add the note `"reads|WRITES project
<target> from project <own>"`. The broker does **not** check that the target
exists; the daemon does at provision time.

Authority: `{"access": capability}`. `is_sensitive` is true for `project.write`
(always a human; `authority.py:217-219`). Zones (`core/zones.py:113-129`): deny if
any agent of the target project in the same VM, or any would-be
`<rt>-<target>-<host>-sandbox` for each configured runtime, is in a zone the
requester is not in. This is one-way: a zone member may read outward.

`provision` (`:58-74`): `hub.call(daemon.role, daemon.name, {...}, timeout=30 default)`:
```json
{"type": "project.grant", "grant_id": "<grant uuid>", "project": "<requester's project>",
 "target": "<target>", "access": "project.read|project.write", "call_id": "<hex>"}
```
`DaemonCallError` (offline, timeout, or `ok:false`) → ProvisionerError
`"sandbox <host>: <error>"`, so the request ends PROVISION_FAILED. State is
`{"project","target","access"}`.

`revoke` (`:76-91`): `hub.call` with `{"type":"project.revoke","grant_id","project","target"}`.
DaemonCallError → ProvisionerError (the scheduler retries until it is answered).

`get_credential` → `kind="project_access"`, no value, and a note naming
`/var/lib/sandbox/projects/<target>`.

### 2.8 Lockdown and containment messages sent to sandboxes (broker side)

- Lockdown (`core/hostexec.py:537-627`): with scope `sandboxes` or `all`, every
  daemon is a target; with scope `host`, only the daemons of that name. Sandboxes
  are called **first** with `{"type":"lockdown","kill_vm":<bool>}`, timeout
  `SANDBOX_LOCKDOWN_TIMEOUT=5.0` s, before the hosts (timeout 20 s). A sandbox's
  `reply` carries no `data`.
- Unlock (`core/hostexec.py:629-662`): `hub.send` (not a call) of `{"type":"unlock"}`
  to each sandbox (all of them, or the one of that host). It is not queued if the
  sandbox is offline.
- On (re)connect of a sandbox (`core/hostexec.py:666-690`): if the broker is locked
  for this host, send `{"type":"lockdown","kill_vm":false}`. **Always** send
  `{"type":"agents.contained","agents":[...]}`, the full list of this VM's agents
  held by any containment entry (`core/lockdown.py:92-96`).
- Whenever containment changes, `tell_sandboxes()` (`core/lockdown.py:98-115`) sends
  every sandbox its full held list.

---

## 3. Sandbox-specific channel messages (exact)

Broker → sandboxd (the payload inside the signed envelope; see daemons-hostd.md):

| type | fields | expects reply | sandboxd action |
|---|---|---|---|
| `key` | `agent_id` str, `name` str, `runtime` str\|null, `project` str\|null, `api_key` str | no; it answers with `key.ack` | upsert the agent record (persist) → send `key.ack` → (re)start that agent's dispatcher (`daemon.py:275-287`) |
| `project.grant` | `grant_id`, `project`, `target`, `access`, `call_id` | `reply` | `apply_project_grant` |
| `project.revoke` | `grant_id`, `project`, `target`, `call_id` | `reply` | `remove_project_grant(grant_id)` (only the id is used) |
| `lockdown` | `kill_vm` bool (ignored), `call_id` (when sent by call) | `reply` if `call_id` | `lockdown()` |
| `unlock` | (`call_id` optional) | `reply` if `call_id` | `unlock()` |
| `agents.contained` | `agents`: list of names (the complete held set for this VM), `call_id` optional | `reply` if `call_id` | `set_contained(list)` |

sandboxd → broker:

| type | fields | when |
|---|---|---|
| `key.ack` | `agent_id` | right after the key is persisted (only when the channel object exists) |
| `key.rotate` | `name` | an agent's key was refused with 401 (`_key_lost`, `daemon.py:398-401`) |
| `reply` | `call_id` (echoed, may be null), `ok` bool, `error` str (when `ok` is false) | for `project.grant` and `project.revoke`: `{"type":"reply","call_id":…,"ok":true}` or `{…,"ok":false,"error":str(exc)}` (`daemon.py:288-298`). For `lockdown`, `unlock` and `agents.contained`, only `{"ok":true}`, sent only when `call_id` is truthy |
| `heartbeat` | `status` = §4.10 | channel-generic |

Unknown types are ignored. A handler exception (for example a `KeyError` on a
`key` message with missing fields) is logged by the channel loop and dropped
(`daemon_common/channel.py:287-291`). **Handlers run inline in the channel read
loop.** A slow handler (setfacl on a large tree, or delivering a backlog on unlock)
delays every later broker message (see B-7).

---

## 4. sandboxd

### 4.1 Processes, entry points, files

Binaries (`pyproject.toml:32-34`):
- `agent-auth-sandboxd run|pair`
- `agent-auth-sandboxctl`, the operator CLI (`avm` runs it in the guest over vsock SSH)
- `agent-auth-sandbox-mcp`: a stdio MCP server, or with argv[1]=="hook" the claude
  hook.

`agent-auth-sandboxd run` (`main.py:36-62`): load the config; create `Sandboxd(cfg,
LinuxHost(cfg))`; serve the **agent socket** at `cfg.agent_socket` with mode
**0666**, and the **operator socket** at `cfg.runtime_dir/operator.sock` with mode
**0600**; run `sbx.run()`; SIGTERM or SIGINT cancels it. `serve_unix` creates the
parent dir, unlinks a stale socket, binds, then chmods
(`daemon_common/localsock.py:93-100`).

`agent-auth-sandboxd pair [-]` (`main.py:65-93`): a positional code is refused (exit
2). Read the code from stdin (`-`), else from env `AGENT_AUTH_SANDBOXD_PAIRING_CODE`,
else from a hidden prompt; strip it. Pair the daemon identity (role `sandbox`,
name = cfg.name, key = `state_dir/key`). On PairingFailed or HTTP error, exit 1.
On success, print the principal, both fingerprints, and "Restart
agent-auth-sandboxd; …".

`Sandboxd.run()` (`daemon.py:229-238`): `startup()`, then create the DaemonChannel
(identity, version, `status`, `on_message`), start the `_reaper` task, and await
`channel.run()`. Finally `shutdown()`: cancel all tasks, `stop()` every live run,
and close the HTTP client. Units are left running for the next startup to stop.

`startup()` (`daemon.py:207-227`):
1. mkdir `sandbox_root/{projects,homes,tmp}` with mode 0711.
2. `ensure_user("sbx-orchestrator", uid_base, homes/_orchestrator)`.
3. `make_dirs(uid_base, sandbox_root/orchestrator, homes/_orchestrator, tmp/_orchestrator)`.
4. mkdir `state_dir/logs` with mode 0700.
5. For each non-closed conversation: stop `sbx-conv-<id>` and `sbx-tui-<id>`, set
   state `parked`, and start its watcher.
6. For each agent record: start its dispatcher.

File layout and permissions:

| path | owner/mode | contents |
|---|---|---|
| `/var/lib/sandboxd/` (state_dir) | root 0700 (StateDirectoryMode, `flake.nix:1106-1107`) | |
| `state_dir/key` | root **0400**, created atomically with O_EXCL+link; refused if not a regular file, not owned by us, or readable by others (`daemon_common/crypto.py:146-…`) | the daemon's ed25519 identity |
| `state_dir/state.db` | root **0600**, pre-created with O_CREAT 0600 before sqlite opens it; WAL mode (`state.py:76-84`) | **every agent API key in plaintext**, projects, conversations, threads, inbox, project grants, kv |
| `state_dir/secrets/claude-oauth-token` | root 0600 (via `write_file`) | the subscription token, stripped |
| `state_dir/secrets/codex-auth.json` | root 0600 | the shared codex login (not stripped) |
| `state_dir/logs/<conv>.log` | root (dir 0700) | JSONL `{"t": epoch_float, "dir": "in"\|"out"\|"error", "text": …}` (`daemon.py:1207-1212`) |
| `runtime_dir` = `/run/sandboxd` | RuntimeDirectory, **0755** (`flake.nix:1108-1109`) | |
| `/run/sandboxd/operator.sock` | root 0600 | the operator API |
| `/run/sandboxd/env/<unit>.env` | root **0600** | the unit's whole environment, secrets included; deleted on `stop_unit` |
| `/run/sandboxd-agent/agent.sock` | **0666** (dir 0755) | the agent API |
| `/var/lib/sandbox/{projects,homes,tmp}` | root **0711** (tmpfiles + startup) | |
| `/var/lib/sandbox/{projects,homes,tmp}/<p>/` | `p-<p>`:`p-<p>` **0700** (`host.py:100-104`) | the project, `$HOME`, and the dir bound to /tmp |
| `/var/lib/sandbox/orchestrator`, `homes/_orchestrator`, `tmp/_orchestrator` | uid_base 0700 | |
| `/var/lib/userdb/<name>.user`, `<name>.group`, plus symlinks `<uid>.user`, `<uid>.group` | 0644 (written tmp+rename) | userdb records: `{"userName","uid","gid"=uid,"realName":"agent sandbox user <name>","homeDirectory","shell":"/run/current-system/sw/bin/bash","disposition":"regular","locked":true}` and `{"groupName","gid"}` (`host.py:76-98`) |

The service runs as root with `UMask=0077` (`flake.nix:1092-1115`).

### 4.2 Configuration (`sandboxd/config.py`)

A JSON file. The path comes from `--config`, else env `AGENT_AUTH_SANDBOXD_CONFIG`,
else `/etc/agent-auth/sandboxd.json`. Unknown keys are a TypeError (dataclass
kwargs). Path-typed keys are converted.

| key | type | default | notes |
|---|---|---|---|
| `broker_url` | str | required | the nix module requires `https://…`, or http only on localhost (`flake.nix:1003-1006`) |
| `broker_public_key` | str | required | `ed25519:<43 b64url>` |
| `name` | str | required | the physical host |
| `state_dir` | path | `/var/lib/sandboxd` | `secrets_dir` = `state_dir/secrets` |
| `sandbox_root` | path | `/var/lib/sandbox` | |
| `userdb_dir` | path | `/var/lib/userdb` | |
| `runtime_dir` | path | `/run/sandboxd` | |
| `agent_socket` | path | `/run/sandboxd-agent/agent.sock` | |
| `runtimes` | `{name: {"command": str, "model": str\|null}}` | `{}` | only the keys `claude` and `codex` are instantiated; any other name is ignored (`daemon.py:175-178`) |
| `agent_path` | str | `/run/current-system/sw/bin` | PATH inside units |
| `agent_auth_mcp` | str | `agent-auth-mcp` | |
| `sandbox_mcp` | str | `agent-auth-sandbox-mcp` | |
| `mcp_bridge` | str | `agent-auth-mcp-bridge` | |
| `tmux`, `systemd_run`, `systemctl`, `setfacl` | str | bare names | absolute store paths in nix |
| `orchestrator_runtime` | str | `claude` | |
| `uid_base` / `uid_max` | int | 40000 / 49999 | orchestrator = uid_base; projects get the lowest free uid in (base, max] |
| `park_grace_secs` | float | 30 | |
| `triage` | bool | true | |
| `triage_runtime` | str\|null | null → orchestrator_runtime | |
| `triage_model` | str\|null | null → claude `haiku`; codex: the runtime's configured model | |
| `triage_timeout_secs` | float | 60 | |
| `interactive_idle_secs` | float | 1800 | **unused** |
| `max_processes` | int | 16 | a semaphore around process **starts** only (B-4) |
| `max_processes_per_project` | int | 4 | **unused** |
| `unit_memory_max` | str | `8G` | |
| `unit_tasks_max` | int | 4096 | |

The nix module writes only: broker_url, broker_public_key, name, agent_path
(`<agentPackages env>/bin:<pkg>/bin`), the three MCP binaries, tmux,
systemd_run, systemctl, setfacl, orchestrator_runtime, runtimes
(`command = <pkg>/bin/<binary>`, model), park_grace_secs, max_processes and
unit_memory_max (`flake.nix:973-991`).

Other environment variables:
- Daemon: `LOG_LEVEL` (default INFO), `AGENT_AUTH_SANDBOXD_PAIRING_CODE`.
- Clients: `AGENT_AUTH_SANDBOX_SOCKET` (default `/run/sandboxd-agent/agent.sock`),
  `AGENT_AUTH_SANDBOX_TOKEN`, and `AGENT_AUTH_SANDBOXD_OPERATOR` (operator socket
  override, default `/run/sandboxd/operator.sock`) (`sandboxd/client.py`).

### 4.3 Local state (`state.py`): tables and semantics

- `agents(name PK, agent_id, runtime, project, api_key, updated_at)`. `put_agent`
  is an upsert on name that replaces every field.
- `projects(name PK, uid UNIQUE, sealed 0/1, created_at)`.
- `conversations(id PK, agent, runtime, runtime_session_id, broker_session_id,
  state ∈ running|parked|attached|closed, mode default 'headless', title ≤200
  chars, created_by, created_at, last_activity, turns)`. New conversations start
  `parked`. `conversations()` excludes closed ones by default and orders by
  last_activity DESC.
- `threads(thread_id PK, conversation_id, peer, role, topic, cursor default 0,
  state default 'open')`. `bind_thread` is an upsert that changes only
  `conversation_id` on conflict.
- `inbox(id autoinc, conversation_id, text, created_at)`. `drain` reads all rows
  in id order, then deletes `id <= last`, under the lock. `peek` does not delete.
- `project_grants(grant_id PK, project, target, access)`. Add is INSERT OR REPLACE.
  `pop` is select-then-delete.
- `kv(key PK, value JSON)`. Keys used: `locked` (bool) and `contained` (sorted list
  of names).

Lockdown and containment are **persisted**: they survive a daemon restart.

### 4.4 HTTP calls to the broker, as an agent (`sandboxd/broker.py`)

Header `Authorization: Bearer <agent api_key>`, plus `X-Agent-Session: <sid>` when
a session is given. Timeout 330 s (15 s connect), because long-polls hold up to
300 s. Status ≥ 400 → `BrokerCallError(status, detail)`, where detail = JSON
`detail` or the body text, truncated to 500 chars. An empty body → None.

| use | request |
|---|---|
| create a conversation's session | `POST /v1/sessions {"label":"conv-<conv id>"}` → `session_id` |
| close it | `POST /v1/sessions/close` (with the session header) |
| events long-poll | `GET /v1/a2a/events?wait=60[&after=<cursor>]` (sessionless: `pending_opens`; with a session: `activity`) |
| claim | `POST /v1/a2a/threads/{tid}/accept` (with the conversation's session) |
| refuse | `POST /v1/a2a/threads/{tid}/reject {"reason": "sandbox: <exc>"[:500]}` (sessionless) |
| read | `GET /v1/a2a/threads/{tid}/messages?after_seq=<n>` |
| mint (as the orchestrator) | `POST /v1/requests {...}`, then `GET /v1/requests/{id}/wait?timeout=<s>` |
| MCP servers | `GET /v1/grants?status=active` (`platform=="mcp"` → resource names) |
| model gateway | `GET /v1/catalog`, `GET /v1/grants?status=active`, `POST /v1/requests`, `GET /v1/requests/{id}/wait?timeout=20`, `GET /v1/grants/{id}/credential` |

Thread objects consumed: `thread_id`, `peer`, `topic`, `role`, `last_seq`, `state`,
`close_reason`. Messages: `seq`, `from`, `payload`. Events: `cursor`,
`pending_opens[]`, `activity[]`.

### 4.5 Agent identities in the VM

- Keys arrive only through `key` messages (§3). There is no other path in. On
  receipt the key is persisted, acked, and the dispatcher is **restarted** (the old
  task is cancelled).
- **Dispatcher** (one per agent, sessionless; `daemon.py:473-510`): loop: re-read
  the record (stop if it is gone); `events(key, wait=60, after=cursor)`; set
  `cursor = snap.cursor or cursor`; `route_open` each `pending_opens` entry. A
  `LookupError`, `RuntimeError` or `ValueError` from routing →
  `reject(thread, "sandbox: <exc>")` (truncated to 500). `BrokerCallError` 401 →
  `key.rotate` and **return** (it is restarted only by a new `key` message). Any
  other error → log and sleep 5 s.
- `_runtime_of(rec)` (`daemon.py:629-635`): the orchestrator →
  `orchestrator_runtime`; otherwise `rec.runtime` if it is configured. Not
  configured → `RuntimeError("no runtime configured for …")`.

### 4.6 Projects (`daemon.py:405-469`, `host.py`)

- `create_project(name)`: PROJECT_RE, else ValueError. It must not exist. The uid
  is the lowest free value in `(uid_base, uid_max]`, else RuntimeError.
  `ensure_user(p-<name>, uid, homes/<name>)`, then `make_dirs(uid, projects/<n>,
  homes/<n>, tmp/<n>)` (mkdir, chown uid:uid, chmod 0700), then insert the record
  (sealed=0). Returns `{"project","path"(workdir),"uid"}`.
- `open_project_for_setup(name)`: it must exist unsealed, else ValueError "not open
  for setup". `grant_acl(workdir, uid_base, write=True)`.
- `seal_project(name)`: LookupError if it is missing. A no-op if already sealed.
  Otherwise `revoke_acl(workdir, uid_base)`, `chown -R --no-dereference uid:uid
  workdir`, then mark it sealed. `_ensure_running` seals the agent's project
  automatically before the first start (`daemon.py:920-921`). There is **no**
  timed auto-seal, despite docs §6.2.
- ACLs (`host.py:119-128`): grant = `setfacl -R -m u:<uid>:<rX|rwX> <path>` then
  `setfacl -R -d -m u:<uid>:<perms> <path>`. Revoke = `setfacl -R -x u:<uid>` and
  `-R -d -x u:<uid>`. A non-zero exit → RuntimeError(first 300 chars).
- `apply_project_grant(grant_id, project, target, access)`: access must be
  `project.read|write`, else ValueError. `uid = project_uid(project)`, which raises
  LookupError if the project is missing; `project_uid(target)` must also exist.
  `grant_acl(workdir(target), uid, write = access=="project.write")`, then record
  it.
- `remove_project_grant(grant_id)`: pop it; if it is unknown, return (idempotent).
  `revoke_acl(target workdir, uid)`, then **re-grant** for every remaining grant of
  the same (project, target) pair, because revoke removes all of that uid's entries.

### 4.7 Conversations, routing, delivery

`new_conversation(agent, created_by, title, mode)`: the agent record must exist,
else LookupError "no key for agent … in this VM". Insert (state parked).
`POST /v1/sessions {"label":"conv-<id>"}`. Store `broker_session_id`. Start the
watcher.

`route_open(rec, thread)` (`daemon.py:512-530`):
1. If the thread is already bound locally, return.
2. Fetch `messages(after_seq=0)`. Hint = `msgs[0].payload._sandbox.conversation`
   if the payload is an object and the hint is a string.
3. Use the hinted conversation if it exists, belongs to this agent, and is not
   closed.
4. Otherwise run `triage(...)`. If that gives None, create a new conversation:
   `created_by="a2a:<peer>"`, `title="<peer>: <topic or tid[:8]>"`.
5. `claim(conv, thread)`: `accept` with the conversation's session, then
   `bind_thread(tid, conv, peer, role or "responder", topic)`, then `_read_thread`.

Triage (`daemon.py:532-614`):
- It returns None at once if the VM is locked or the agent is contained. No model
  runs for a held agent.
- Candidates: only when `config.triage` is true. They are the agent's open
  conversations that have any thread (open or closed) whose peer equals the new
  peer, or whose topic equals the new topic (when the topic is set). Each
  conversation pairs with its last related thread. Sort by last_activity desc and
  keep at most 8. No candidates, or no triage runtime → None.
- Prompt: `TRIAGE_PROMPT` (`daemon.py:86-102`). Each candidate is a line `- id: … ·
  peer: … · topic: … · title: <inert(title[:120])> · turns: N · last active M min
  ago`. The request body is the payload (a string, or JSON indent 2) truncated to
  4000 chars. `_inert` replaces every `</` with `<\/`. The topic is inert and has
  `"` replaced by `'`. The peer is inert.
- Unit `sbx-triage-<hex12>`, run as the agent's project uid, workdir = **home**
  (not the project). Env: HOME, PATH, `LANG=C.UTF-8`, `CODEX_HOME=<home>/.codex`,
  plus the OAuth token file if present, plus the gateway env (below). The
  agent-auth key is **not** included. `NoModelKey` → None.
- Inside `_spawn_slots`: `start_piped` (systemd-run --pipe --wait), write the prompt
  to stdin, wait with a timeout of `triage_timeout_secs`, and always `stop_unit`.
  A timeout, OSError or RuntimeError → None.
- Answer: claude parses stdout JSON `.result` (a string); codex takes the last
  non-empty line. Select the candidates whose id is a **substring** of the answer.
  Exactly one → that conversation. Otherwise None.
- Claude triage argv: `<claude> -p --model <triage_model|haiku> --output-format json
  --tools "" --strict-mcp-config --setting-sources "" --no-session-persistence`.
  Codex: `<codex> exec --skip-git-repo-check --ephemeral -s read-only [-m <model>] -`.
  The gateway argv is inserted after argv[0] (codex only).

Watcher (one per conversation, with its session; `daemon.py:665-700`): loop.
Return if the conversation is gone or closed, or has no agent record or no
`broker_session_id`. Run `events(wait=60, after=cursor, session=sid)`. For each
`activity` thread not bound locally, **adopt** it (bind it with the thread's own
role; the agent opened it from this conversation), then `_read_thread`. A 401 whose
detail contains "session" → set `broker_session_id=NULL` and return. Any other 401
→ `key.rotate`, sleep 5 s, continue (it repeats every 5 s). Other errors → sleep
5 s.

`_read_thread(conv, rec, thread)` (`daemon.py:702-729`), under a per-thread asyncio
lock:
- `cursor = bound.cursor or 0`. If `thread.last_seq > cursor`, fetch
  `messages(after_seq=cursor, session)` and keep those with `seq > cursor`. Advance
  the stored cursor to the max seq **before** delivering (at-most-once).
- If the thread is now closed and the local copy is not, mark it closed locally.
- Outside the lock: deliver each fresh message whose `from != rec.name` as
  `format_a2a`. On closing, deliver
  `"[a2a] thread <tid> with <peer> is closed (<close_reason or 'closed'>). Nothing more will arrive on it."`.

`format_a2a` (exact, `daemon.py:112-120`):
```
[a2a] thread <tid> · from <from>[ · topic <topic>] · seq <seq>
<payload if string, else json.dumps(payload, indent=2)>
(reply: a2a_send(thread_id="<tid>", payload={...}))
```

`deliver(conv_id, text)` (`daemon.py:935-978`):
1. The conversation is missing or closed → return.
2. Log `in`, then touch last_activity.
3. Locked or contained → `queue` and return.
4. A TUI is attached and the runtime is not `shares_live_process` (claude) → queue
   and return.
5. Under the conversation lock: a run exists, is busy, and the runtime has
   `doorbell` (claude) → queue and return (the PostToolUse hook collects it, or
   `_flush_queue` sends it at turn end).
6. Cancel the park timer. `pending = drain()`. `_ensure_running`. On **any**
   exception, re-queue `pending + [text]` and re-raise.
7. Re-check locked or contained. If held, freeze `sbx-conv-<id>`, re-queue
   everything, and return without sending.
8. Send each pending item as its own turn, then `text`.

`_ensure_running` (`daemon.py:916-933`): return the existing run if there is one.
Seal the project if needed. Under `_spawn_slots`: build the context, add the
catalog MCP servers, then `_use_gateway`. If there is no gateway and the runtime is
codex, run `_sync_codex_auth(into_project=True)`. Then `runtime.start`. Store the
run and ctx. If the runtime's session id changed, persist it. Set state `running`
and start the `_pump`.

`_pump`: on `text` events, log `out`. On `turn_done` or `error` (an error also
logs `error`), increment turns; if not busy and `_flush_queue` sent nothing,
schedule a park. On `exit`, clear `lv.run` if it is still this run, set state
`parked` if it was running, and stop.

`_flush_queue`: if a TUI is attached → False. Under the lock, and only if this run
is still current: drain the queue and, if it is non-empty, send it as **one** turn
joined by `"\n\n"`.

Park: after `park_grace_secs`, `park(expected=run)`. Under the lock: skip if there
is no run, the run is a different one, or it is busy. Otherwise stop it. For codex,
`_sync_codex_auth(into_project=False)`. State becomes `parked` (unless closed).

`close(conv)`: stop the TUI, stop the run, state `closed`,
`POST /v1/sessions/close` (a BrokerCallError is logged; the broker ends the
session's threads with peer_gone and revokes delegated grants), cancel the watcher.
Conversations are never closed automatically.

`spawn(agent, prompt, created_by, title)`: `new_conversation(title = title or
prompt[:80])`, then `deliver(prompt)`.

### 4.8 Runtimes and units

**Unit** (`host.py:156-203`), the argv is exactly:
`systemd-run --unit=<name> --uid=<uid> --gid=<uid> --quiet --collect [--pipe --wait]`,
then `-p` for each of:
`Description=…`, `WorkingDirectory=<workdir>`, `EnvironmentFile=<runtime_dir>/env/<name>.env`,
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`, `NoNewPrivileges=yes`,
`ProtectProc=invisible`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
`ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`,
`ProtectHostname=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
`RestrictRealtime=yes`, `KeyringMode=private`, `UMask=0077`,
`InaccessiblePaths=<runtime_dir>`, `InaccessiblePaths=-/run/systemd/transient`,
`InaccessiblePaths=<state_dir>`, `ReadWritePaths=<sandbox_root>/projects`,
`ReadWritePaths=<home>`, `BindPaths=<tmp>:/tmp`, `MemoryMax=<unit_memory_max>`,
`TasksMax=<unit_tasks_max>`, `KillMode=control-group`, plus `ReadWritePaths=` for
each extra path; then `-- <argv…>`.

The env file has one line per variable, `KEY=<shell-quoted value>`. A value
containing `\n` or NUL → ValueError. Secrets go **only** in the env file, never in
argv (argv is visible through `systemctl show`). `stop_unit` = `systemctl stop
<name>.service` (the exit code is ignored), then unlink the env file. `freeze_unit`
= `systemctl freeze|thaw` (cgroup freezer). `unit_active` = `systemctl is-active
--quiet`. `run_as(uid, argv)` = `setpriv --reuid=uid --regid=uid --clear-groups --
argv` (outside any unit).

**Unit environment** (`daemon.py:733-792`): HOME, USER and LOGNAME
(`p-<project>` or `sbx-orchestrator`), PATH=agent_path, `LANG=C.UTF-8`,
`TERM=xterm-256color`, `AGENT_AUTH_URL`, `AGENT_AUTH_API_KEY` (the agent's key),
`AGENT_AUTH_SESSION` (the conversation's broker session, or ""),
`AGENT_AUTH_SANDBOX_SOCKET`, `AGENT_AUTH_SANDBOX_TOKEN` (the Live token, below),
`CODEX_HOME=<home>/.codex`, and `CLAUDE_CODE_OAUTH_TOKEN` if
`secrets/claude-oauth-token` exists. The env is built from scratch and never
inherits the daemon's.

With a gateway (`daemon.py:156-161,812-890`): remove `CLAUDE_CODE_OAUTH_TOKEN`; set
`ANTHROPIC_BASE_URL=<gw url>`, `ANTHROPIC_AUTH_TOKEN=<key>` and
`AGENT_AUTH_MODELS_KEY=<key>`; set `ctx.model_gateway=url`. `_gateway(rec)`:
- Return the cached `{url,key,expires}` if it is more than 2 h from expiry.
- `GET /v1/catalog`. A BrokerCallError → NoModelKey. Any other error (unreachable)
  → None (use the VM's logins).
- No `models` platform, or no gateway url → None.
- Otherwise find an active `models` grant on `gateway.name` that expires more than
  2 h out. If there is none, request one with `{"platform":"models","capability":"use",
  "resource":name,"justification":…,"requested_duration":"24h"}`; if its status is
  approved, provisioning or pending, wait up to 20 s; if it is not `granted` with a
  `grant_id` → NoModelKey.
- `GET /v1/grants/{id}/credential`. It needs `value` and `url`; `expires` comes from
  `expires_at`, else now+3600.

`_use_gateway`: a contained agent → NoModelKey (the process must not start). The
system prompt is `SYSTEM_PROMPT` plus `ORCHESTRATOR_EXTRA` for the orchestrator
(`daemon.py:57-83`).

**MCP servers in ctx**: `agent-auth` → `{command: agent_auth_mcp, env_vars:
[AGENT_AUTH_URL, AGENT_AUTH_API_KEY, AGENT_AUTH_SESSION]}`. `sandbox` →
`{command: sandbox_mcp, env_vars: [AGENT_AUTH_SANDBOX_SOCKET, AGENT_AUTH_SANDBOX_TOKEN]}`.
Then one `{command: mcp_bridge, args: [<name>], env_vars: [URL, KEY, SESSION]}` for
each active `mcp` grant resource that matches NAME_OK and is not already present
(read at each process start). Hooks: `{"PostToolUse": "<sandbox_mcp> hook"}`, plus
`UserPromptSubmit` for a TUI.

**Claude** (`runtimes/claude.py`): `shares_live_process=False`, `doorbell=True`.
- Headless argv: `<cmd> -p --input-format stream-json --output-format stream-json
  --verbose --append-system-prompt <prompt> --mcp-config <json> --permission-mode
  bypassPermissions [--model <ctx.model or cfg model>] [--settings <hooks json>]`,
  then `--resume <sid>` if a session id is known, else `--session-id <new uuid4>`.
- `--mcp-config` = `{"mcpServers": {name: {"command", "args": [] default}}}`. It
  holds no env, because stdio servers inherit claude's environment.
- `--settings` = `{"hooks": {event: [{"hooks": [{"type":"command","command":cmd}]}]}}`.
- It is started with `start_piped`. `send` writes
  `{"type":"user","message":{"role":"user","content":text}}\n` and increments
  `pending_turns`. `busy` = pending_turns > 0.
- Reader: `system` with session_id → update it. `assistant` → join the text items
  into a `text` event. `result` → decrement pending_turns (floor 0) and emit
  `error` if `is_error`, else `turn_done`. At EOF emit `exit`.
- `stop`: if the process is alive, `stop_unit`, wait 15 s, else kill.
- TUI argv: `<cmd> <common…> [--resume <sid>]`. On attach with no session id, a
  new uuid is persisted and `--resume` is replaced with `--session-id`.

**Codex** (`runtimes/codex.py`): `shares_live_process=True`, `doorbell=False`.
- argv: `<cmd> [gateway -c …] app-server --listen unix:///tmp/codex-<conv>.sock`,
  plus for each MCP server `-c mcp_servers.<n>.command=<json str>`,
  `[-c mcp_servers.<n>.args=<json list>]`, `[-c mcp_servers.<n>.env_vars=<json list>]`.
  It is started detached. A stale `<tmp>/codex-<conv>.sock` is removed first.
- Gateway argv: `-c model_provider="agentauth"`, `-c model_providers.agentauth.name="model gateway"`,
  `-c model_providers.agentauth.base_url=<json(url.rstrip('/') + '/v1')>`,
  `-c model_providers.agentauth.env_key="AGENT_AUTH_MODELS_KEY"`,
  `-c model_providers.agentauth.wire_api="responses"`.
- Connect: poll for up to 30 s (100 ms steps) for the socket. `socket_on_host` follows
  one symlink whose absolute target is under `/tmp/` with no `..`, re-rooted at the
  project's tmp dir; any other target leaves the path as is. Timeout → stop the
  unit and raise RuntimeError. Connect through `/proc/self/fd/<O_PATH dirfd>/<name>`
  (paths over 108 bytes). WebSocket URI `ws://localhost/`.
- JSON-RPC: `initialize {"clientInfo":{"name":"sandboxd","version":"1"}}`, then
  `thread/resume {base…, threadId}` or `thread/start base`, where base =
  `{cwd, approvalPolicy:"never", sandbox:"danger-full-access", developerInstructions:
  <prompt>, [model]}`. Take the thread id from `result.thread.id`. For a new thread,
  `thread/name/set {threadId, name:"conversation <conv>"}`, whose failure is only a
  warning. Each call has a 120 s timeout. An `error` member → RuntimeError.
- `send`: with no active turn, `turn/start {threadId, input:[{type:"text",text}]}`;
  otherwise `turn/steer {threadId, expectedTurnId, input}`. On a failed steer, the
  text goes to the local `_queued` list and starts the next turn when
  `turn/completed` arrives.
- Notifications for another threadId are ignored. `turn/started` → set the turn id.
  `item/completed` with `agentMessage` text → `text`. `turn/completed` → clear the
  turn, emit `error` (turn.error JSON) or `turn_done`, and start the next queued
  turn. `error` without `willRetry` → `error`. When the socket closes, fail pending
  calls and emit `exit`. `busy` = there is a turn, or `_queued` is non-empty.
- TUI argv: `<cmd> [gateway] --remote unix:///tmp/codex-<conv>.sock resume [<thread id>]`
  (a second client of the live server).
- Codex auth sync (no gateway only; `daemon.py:892-914`): before a start
  (`into_project`), mkdir `~/.codex` 0700 and copy the shared file in if it is newer
  or the local copy is missing (`write_file` uid 0600), then `chown -R` `~/.codex`.
  After a park, copy the project's copy back to the shared file if it is newer.
  Skip with a warning if `~/.codex` or `auth.json` is a symlink.

`write_file(path, content, uid, mode)`: mkdir the parent; open `.<name>.tmp` with
`O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW` at the mode; write; chown if a uid is given;
chmod; rename over the target.

### 4.9 Interactive (TUI) attach (`daemon.py:1074-1200`)

- `attach(conv, now)`:
  - Errors: the conversation is missing or closed → LookupError; locked →
    RuntimeError "locked down"; contained → RuntimeError "<agent> is contained".
  - If a TUI is already running, return the attach info.
  - Under the lock, cancel the park timer.
  - Codex: `_ensure_running` (the TUI joins it).
  - Claude: if a run exists, wait up to 600 s (0 with `now`) for it to stop being
    busy, then stop it.
  - Build a TUI context (UserPromptSubmit hook), add the MCP servers and the
    gateway, then `_start_tui`. Set `lv.tui=True` and state `attached`.
- `_start_tui`:
  - Host socket `<tmp>/tmux-<conv>.sock`; inside the unit it is
    `/tmp/tmux-<conv>.sock`.
  - Start unit `sbx-tui-<conv>` detached, running `tmux -D -S <unit sock> -f /dev/null`.
  - Wait up to 10 s for the socket.
  - Then, as the uid via `run_as`: `tmux -S <host sock> new-session -d -s conv -c
    <workdir> /bin/sh -c "<cmd>"`. The command records start time t0, runs the TUI,
    and if rc≠0 or it ran under 5 s, prints `"\n[the TUI exited with status <rc>]\n"`
    and sleeps 600; then it runs `tmux kill-server`.
  - Sleep 1.5 s. Then `has-session` and `capture-pane -p`. If the session is dead
    or the pane contains the failure marker, stop the unit and raise RuntimeError
    with the pane's last 1500 non-blank chars (or a journalctl hint).
- Attach info: `{"conversation": id, "uid": <project uid>, "argv": [tmux, "-S",
  <host sock>, "attach", "-t", "conv"]}`. The operator CLI `exec`s it through
  `setpriv` as that uid.
- `stop_tui`: if a TUI is attached, stop the unit, then `_tui_ended`.
- `_tui_ended`: clear the flag; set state `running` or `parked`; schedule a park if
  the run is idle; drain the queue and deliver it headless.
- `_reaper`: every 10 s, for each Live with a TUI whose unit is inactive, run
  `_tui_ended`. There is **no** idle reaping of attached TUIs (B-5).

### 4.10 Status (heartbeat payload, `daemon.py:256-269`)

`{"version", "role":"sandbox", "host", "agents": <count>, "projects": <count>,
"conversations": {<state>: count} (non-closed only), "lockdown": bool,
"processes": <live runs>}`.

### 4.11 Lockdown and containment in the VM (`daemon.py:315-396`)

- `lockdown()`: persist `locked=true`. Freeze every live run's unit and every TUI
  unit. While locked: `deliver` queues; `triage` returns None; `mint` and `attach`
  raise RuntimeError "locked down"; `_ensure_running` callers freeze a run that
  started meanwhile.
- `unlock()`: no-op if not locked. Persist `locked=false`, thaw **every** live and
  TUI unit (contained agents too; B-2), and for each non-TUI conversation drain the
  queue and deliver it as one text.
- `set_contained(list)`: `contain(new - old)` and `release(old - new)`.
- `contain(agents)`: persist the union, drop the cached gateway keys, and freeze
  the units of those agents' conversations.
- `release(agents)`: persist the difference. For each agent that was held: thaw its
  units (even when the VM is locked; B-2); if not locked, deliver its queued items.

### 4.12 Local API: JSON lines over unix sockets (`daemon_common/localsock.py`, `sandboxd/localapi.py`)

Framing: one JSON object per line, at most 1 MiB per line.
Request: `{"method": str, "params": object (default {}), "token": str|null}`.
Reply: `{"ok": true, "result": …}` or `{"ok": false, "error": str}`.
`ApiError`, `LookupError`, `ValueError` and `RuntimeError` give their message.
Other exceptions give `"internal error: <exc>"`. A non-object request or a
non-string method → "bad request". Non-object params → "params must be an object".
The caller's uid comes from `SO_PEERCRED`, read once per connection. A connection
may carry several requests. The client side uses a timeout of 600 s.

**Agent socket** (mode 0666), `AgentApi.__call__` (`localapi.py:263-311`):
1. A missing or empty token, or a token that matches no Live → "unknown
   conversation token". The lookup is a constant-time compare over all Live
   entries. Tokens are `token_urlsafe(24)` and live in memory only: they are new
   after a daemon restart, and they stay valid for closed conversations whose Live
   remains.
2. `uid` must equal the uid of the conversation's agent: uid_base for the
   orchestrator, otherwise its project's uid. Else "this token belongs to another
   user's conversation".
3. Methods:

| method | who | params | result |
|---|---|---|---|
| `whoami` | any | – | `{"agent","conversation","project"(null for orch),"host","orchestrator":bool}` |
| `project_list` | any | – | list of `{"name","uid","sealed","created_at"}` (all projects) |
| `conversations` | any | – | the caller's agent's non-closed conversations, as dicts without `broker_session_id` |
| `inbox` | any | `drain` bool | `drain` → drain the list; else peek |
| `project_create` | orch | `name` | `create_project`, then `open_project_for_setup` → `{"project","path","uid"}` |
| `project_seal` | orch | `name` | `{"sealed": name}` |
| `agent_mint` | orch | `runtime`, `project`, `why`? | `mint(...)` → §4.13 |
| `agent_spawn` | orch | `agent`, `prompt` | conversation dict (`created_by="spawn:<orch>"`) |
| other | | | "unknown method '<m>'" |

A non-orchestrator calling an orchestrator method → "<method> is for the
orchestrator". Missing params → KeyError, which becomes "internal error: …".

**Operator socket** (mode 0600; `uid != 0` → "operators only"), `OperatorApi`
(`localapi.py:314-379`):

| method | params | result |
|---|---|---|
| `status` | – | §4.10 |
| `agents` | – | `[{"name","runtime","project"}]` (never keys) |
| `projects` | – | project list |
| `conversations` | `all`?, `project`? | conversation dicts (filtered by the agents of that project) |
| `project_create` | `name`, `sealed` (default true) | create, then seal (default) or open for setup |
| `mint` | `runtime`, `project`, `why`? (default "operator request") | §4.13 |
| `new` | `agent`, `prompt`?, `title`?, `attach` (default true) | LookupError if there is no key. `new_conversation(created_by="operator")`; deliver the prompt; → `{"conversation": …, "attach": <attach info>}` or `{"conversation"}` |
| `attach` | `conversation`, `now`? | attach info |
| `send` | `conversation`, `text` | `{"sent": true}` |
| `stop` | `conversation` | stop_tui + park → `{"parked": id}` |
| `close` | `conversation` | `{"closed": id}` |
| `log_path` | `conversation` | the path string |
| `shell` | `project` | `{"uid","workdir"}` |
| `secret_set` | `name` ∈ {`claude-oauth-token`,`codex-auth.json`}, `value` | write `secrets/<name>` as root 0600 → `{"stored": name}`. Any other name → "secrets: claude-oauth-token, codex-auth.json" |

### 4.13 Mint from inside the VM (`daemon.py:1222-1252`)

There must be an orchestrator record (else RuntimeError "this VM has no
orchestrator key yet (is it paired?)"). Not locked. The project must exist locally
(else LookupError "create project … first"). Then, as the orchestrator,
`POST /v1/requests {"platform":"agents","capability":"mint","resource":"<rt>-<p>-<host>-sandbox",
"scope":{"runtime":rt},"justification": why or "run <rt> on project <p>","requested_duration":"1h"}`.
If the status is not granted, denied or provision_failed, `wait(timeout=wait_secs=120)`.
Result: `{"agent","request_id","status","reason"(decision_reason)}`. When the
request is granted, poll local state every 100 ms for up to 120 s for the key, and
add `"key_received": bool`.

### 4.14 sandbox MCP (`sandboxd/mcp.py`)

A FastMCP server named `sandbox` with fixed INSTRUCTIONS. Every tool returns a
**string**: the result as JSON indent 2, or `{"error": "<msg>"}`, or
`{"error":"sandboxd unreachable: …"}`. Tools: `sandbox_whoami()`,
`project_list()`, `conversations()`, `inbox()` (always `drain:false`),
`project_create(name)`, `project_seal(name)`,
`agent_mint(runtime, project, why="")`, `agent_spawn(agent, prompt)`. Each calls the
agent API method of the same name (`sandbox_whoami` → `whoami`) with the env's
socket and token.

`agent-auth-sandbox-mcp hook`: read the JSON on stdin and take `hook_event_name`.
Anything other than PostToolUse or UserPromptSubmit becomes UserPromptSubmit.
Call `inbox {"drain": true}`; any exception → []. If the result is non-empty, print
exactly `{"hookSpecificOutput":{"hookEventName":<event>,"additionalContext":"Messages
that arrived for this conversation while you were working:\n\n" + join("\n\n")}}`.
If it is empty, print **nothing**.

### 4.15 sandboxctl (`sandboxd/ctl.py`), the root CLI over the operator socket

`status`, `agents` and `projects` print JSON. `ls [-p project] [-a]` prints
`<id>  <state:9> <agent:44> <age:6>s ago  <title>`. `project-create <name> [--open]`
sends `sealed = not --open`. `mint <project> [-r claude]`.
`new <project> [-r claude] [--prompt] [-d]`: find the agent with that
project+runtime; if there is none, call `mint` (why "operator opened a <rt> session
on <p>"); still none → exit 1. Then call `new`; with `-d`, print the conversation;
otherwise exec the attach. `attach <conv> [--now]` runs
`setpriv --reuid --regid --clear-groups -- tmux …`. `send <conv> <text>`.
`logs <conv> [-f]` reads the JSONL and prints `--- HH:MM:SS <dir>\n<text>`, polling
every 1 s with `-f`. `stop`, `close`. `shell <project>` chdirs to the workdir and
execs `$SHELL -l` (default bash) as the uid. `secret-set <name>` reads the value
from **stdin** (never argv); it is stripped unless the name ends with `.json`.
Errors print in red and exit 1.

---

## 5. Security invariants

INV-1. A minted or orchestrator agent's plaintext API key is sent by the broker
only in a `key` message, over the signed channel, to the connected daemon whose
`daemons.id == pending_key_deliveries.sandbox_id == agents.sandbox_id`. It never
appears in an HTTP response to the requesting agent, in a grant credential, in
provisioner_state, in logs, or in an admin listing. (The one exception is the
explicit admin `rotate-key`, which hands a new key to the admin.)

INV-2. Outside the pending delivery row, the broker stores only `key_id` and
`sha256(secret)`. The pending row holds the key Fernet-encrypted under
`ENCRYPTION_KEY`. Without that key, nothing is minted or bootstrapped (an error,
not a plaintext fallback).

INV-3. A pending delivery row is deleted only by a `key.ack` from the daemon whose
id equals the row's `sandbox_id`, by `disable_agent_tree`, by a newer queueing for
the same agent, or by cascade when the daemon is deleted. A `key.ack` from any
other daemon deletes nothing.

INV-4. `key.rotate` issues a new key only for an agent with `sandbox_id ==
requesting daemon id` and `disabled == false`. The new key goes only to that
daemon, and the previous key stops authenticating in the same transaction.

INV-5. Only an agent whose `sandbox_id` references a daemon of role `sandbox` can
obtain an `agents:mint` grant. The minted agent's `sandbox_id`, `host` and
`placement` always come from the **parent's daemon**, never from the request. A
mint resource whose suffix is not `-<parent daemon name>-sandbox` is denied.

INV-6. `runtime`, `project`, `host`, `placement`, `sandbox_id` and
`parent_agent_id` of a minted agent are set only by the broker at mint time. The
admin attribute and rename endpoints refuse (409) any agent with `sandbox_id` set.

INV-7. An `agents:mint` request is never approved by a rule that doesn't name
`mint` (needs_explicit_rule). A mint into a restricted zone always goes to a human.
`sandbox:project.write` always goes to a human.

INV-8. No identity is minted while the broker is locked down for the parent's host
(or globally).

INV-9. Disabling an agent (admin, or lease expiry) disables every transitive
descendant by `parent_agent_id`, sets `expires_at=now` on all their ACTIVE grants,
and deletes their pending key deliveries. A disabled agent's key gets 401 on every
agent endpoint.

INV-10. Re-pairing a sandbox rotates the orchestrator's key: the pre-re-pair key
gets 401 afterwards. A sandbox never takes over an agent named
`orchestrator-<host>-sandbox` that belongs to another daemon or has another
runtime.

INV-11. In the VM, agent keys exist only in `state.db` (root 0600 inside a 0700
dir) and in the per-unit env file `/run/sandboxd/env/<unit>.env` (root 0600). Every
unit has `InaccessiblePaths` for `runtime_dir`, `state_dir` and
`/run/systemd/transient`. No secret (API key, OAuth token, gateway key) ever
appears in a `systemd-run` argv or in the `--mcp-config` or `--settings` JSON.

INV-12. A process runs with the uid of its agent's project (uid_base for the
orchestrator), never as root. It sees only `/var/lib/sandbox/projects` (read-write
but per-project 0700), its own home, and its own tmp bound at /tmp. It cannot see
other uids' processes (`ProtectProc=invisible`).

INV-13. Agents of one project share a uid, and therefore can read each other's
keys (`/proc/<pid>/environ`). The project is the trust boundary. No agent of
project A can read the files of project B without an active `sandbox` grant
applied as an ACL for A's uid on B's workdir.

INV-14. The agent socket answers a call only when the token matches a live
conversation **and** the peer's SO_PEERCRED uid equals that conversation's project
uid. Orchestrator methods (`project_create`, `project_seal`, `agent_mint`,
`agent_spawn`) additionally require the conversation's agent to be the VM's
orchestrator. The token alone is never enough.

INV-15. The operator socket is mode 0600 and also refuses any peer uid ≠ 0. No
operator method returns an agent key. `secret_set` writes only the two fixed names
under `secrets/`.

INV-16. The agent socket never returns API keys, broker session ids or env
contents: conversation dicts drop `broker_session_id`, and agents are returned by
name only.

INV-17. While the VM is locked down, or an agent is contained: no model process
(headless, TUI or triage) is started or sent input for the affected agents;
running ones are frozen (cgroup freezer, not killed); inbound text is queued in
the inbox; `attach` and `mint` (lockdown) raise. A run that finished starting
after the hold began is frozen and receives nothing. Both flags persist across a
daemon restart.

INV-18. A contained agent never falls back to the VM's subscription logins:
`_use_gateway` raises NoModelKey for it. A broker that answers with an error
(as opposed to an unreachable one) also yields NoModelKey, and the process does
not start.

INV-19. A thread is claimed (accepted) with the session of the conversation that
will answer it. Messages on a thread are delivered to exactly one conversation, at
most once (the cursor advances before delivery). The agent's own messages are never
echoed to it.

INV-20. Untrusted a2a text reaches the triage model only inside
`<conversations>`/`<request>` with every `</` neutralized. The claude triage call
has no tools, no MCP, no settings and no session persistence. Only an answer that
names exactly one candidate id routes the thread there.

INV-21. A `_sandbox.conversation` hint routes into a conversation only if that
conversation belongs to the thread's target agent and is not closed.

INV-22. `project.grant` from the broker grants only `rX` (read) or `rwX`
(write) to the requester project's uid on the target's workdir. Revocation removes
that uid's entries and restores only those still justified by another recorded
grant for the same (project, target) pair. Revoking an unknown grant id succeeds
(idempotent).

INV-23. The orchestrator gets write access to a project only between
`project_create` (agent API) and its seal. Sealing removes the ACL and chowns the
tree (no-dereference) to the project user. A project is sealed before any of its
agents' processes first start.

INV-24. `pair` never accepts the pairing code as an argv argument (only stdin, env
or a hidden prompt).

---

## 6. Tests worth porting

Broker (`tests/test_sandboxes.py`):
- Pairing creates `orchestrator-<host>-sandbox` (runtime orchestrator, service,
  enabled); its delivered key authenticates; the pending row is gone after the ack.
- Re-pairing delivers a new orchestrator key and the old one gets 401.
- A mint creates the child with parent, sandbox, runtime, project, host, placement
  and a lease of about 30 d; the credential holds the name, not the key; the
  sandbox receives the key with its project.
- Minting again renews the lease and re-enables, sends no new key, and the old key
  still works.
- Mint validation: another host's suffix, an unknown runtime, a bad project
  (uppercase/underscore, empty, 31 chars) → DENIED with the right reason.
- A hand-registered agent cannot mint ("agent VM").
- A catch-all approve rule leaves a mint AWAITING_HUMAN.
- `key.rotate` rotates the sandbox's own orchestrator, but not a hand-registered
  agent.
- `disable_agent_tree` covers parent and child, and their grants expire on the next
  pass.
- The lease sweep disables only the expired child, not the parent.
- `POST /admin/agents/{id}/disable` returns the names; the listing shows disabled.
- A `project.read` grant sends `project.grant` with (project, target, access);
  revoke sends `project.revoke`.
- `project.write` → AWAITING_HUMAN; the agent's own project → DENIED "own project".
- A daemon `ok:false` reply → PROVISION_FAILED with the daemon's error.
- The catalog shows `agents`/`sandbox` only to VM agents.

sandboxd (`tests/test_sandboxd.py`, with a FakeHost and a fake runtime):
- An a2a open is routed to a new conversation, answered, parked after the grace
  period, and resumed on the next message with the same runtime session.
- A `_sandbox.conversation` hint routes a second thread into the same conversation.
- Orchestrator via the agent API: whoami, project_create (user plus setup ACL),
  agent_mint (granted, key_received), agent_spawn (seals: chown plus ACL revoke;
  the process cwd is the project).
- The agent API refuses a wrong uid ("another user"), a forged token ("unknown
  conversation"), and orchestrator methods from a project agent.
- A broker project grant gives an ACL with the right uid and write flag; revoke
  removes it.
- Operator API: non-root refused; status; project_create; mint; new; send;
  log_path has in/out; close; `secret_set` with a path-traversal name is refused.
- Attach (claude): the headless run stops, the TUI resumes the same session, a2a
  queues while attached, and stop_tui delivers the queue headless.
- An open that can't be served (no runtime) is rejected and the thread closes with
  a note containing "sandbox:".
- A TUI that exits at once raises with its output, and the unit is inactive.
- Triage: the named candidate is chosen; "new" or a non-candidate id gives a new
  conversation; `</request>` in the payload is neutralized; a stranger peer is
  never triaged.
- Busy claude: a mid-turn message waits in the inbox, the hook drain takes it (no
  double delivery), and leftovers become one joined next turn.
- Hook output names the calling event; an empty inbox prints nothing.
- Lockdown over the channel freezes the units, queues messages, refuses mint and
  attach; unlock thaws and delivers the queue.
- `agents.contained` freezes and queues; an empty list releases, thaws and
  delivers.
- A conversation contained while starting is frozen and sent nothing; attach and
  triage refuse.
- `socket_on_host` re-roots a `/tmp/...` symlink and ignores other targets
  (`..`, outside /tmp, relative).
- `connect_unix` reaches a socket path longer than 108 bytes.

Add these (they are missing from Python; each pins a B-item below): unlock while an
agent is contained keeps it frozen (B-2); release during lockdown keeps it frozen
(B-2); a key.ack for a superseded key does not delete the newer pending key (B-6);
a renewal after admin disable does not re-enable it with the old key (B-1).

---

## 7. Suspected bugs / questionable behavior in the Python

B-1. **A renewal undoes an admin disable, with the same key.** In `mint()`, an
existing agent gets `disabled=False` with its key unchanged
(`core/sandboxes.py:255-261`). The test explicitly expects a disabled agent to come
back with its old key working (`tests/test_sandboxes.py:260-283`). An admin who
disables a compromised minted agent can see it re-enabled by the VM's orchestrator
under an auto-approve `mint` rule, with the compromised key. The renewal also
re-enables only that one agent, not its descendants. Re-pairing likewise sets the
orchestrator's `disabled=False` (`:233`), though it does rotate the key. Suggestion
for the port: the renewal should not clear an admin disable (record the disable
reason), or it should rotate the key.

B-2. **Unlock and release thaw agents that are still held.** `unlock()` thaws
every live unit with no containment check (`daemon.py:336-340`). `release()` calls
`_freeze_agent(agent, False)` **before** checking `self.locked`
(`daemon.py:389-391`), so releasing a containment during a VM lockdown thaws that
agent's processes. Both contradict "held means held on every path". The fix is to
thaw a unit only if it is neither locked nor contained.

B-3. **A sandbox that was offline at unlock stays locked forever.** The broker's
unlock is a `hub.send` that is not queued (`core/hostexec.py:648-650`). On
reconnect, the broker sends `lockdown` when locked but never `unlock` when not
(`core/hostexec.py:680-681`). sandboxd persists `locked=true` (`daemon.py:323`).
The VM keeps queuing and refusing until someone issues another unlock. The broker
should send the current lock state (lock or unlock) on every connect.

B-4. **`max_processes` limits concurrent starts, not processes.** `_spawn_slots` is
held only around `runtime.start` (`daemon.py:922-927`) and triage. The number of
running processes is unbounded. `max_processes_per_project` and
`interactive_idle_secs` are defined but never read (`config.py:51,53`). The docs
promise both limits and the 30-min TUI idle park (docs §6.3, §6.8).

B-5. **Attached TUIs are never idle-reaped.** As in B-4, `_reaper` only notices
exited TUIs.

B-6. **A `key.ack` carries only `agent_id`, and that races with rotation.** If a
key is pushed, then rotated (a `key.rotate` or a re-pair queues a new row), and the
ack for the **old** key arrives afterwards, `_key_ack` deletes the **new** pending
row (`core/sandboxes.py:173-179`). The VM holds a dead key and the new key is lost.
It self-heals only through a 401 → `key.rotate` round. The fix: include
`key_id`/delivery id in `key` and `key.ack`, and delete only a matching row.

B-7. **Broker messages are handled inline in the channel read loop**
(`daemon_common/channel.py:287-291`). `unlock`/`release` deliver backlogs (each
`_ensure_running` can take 30 s for a codex connect), and `project.grant` runs
recursive setfacl. Meanwhile a following `lockdown` is not read. A `project.grant`
that takes longer than the hub's 30 s call timeout is applied in the VM (ACL and
record) while the broker marks the grant PROVISION_FAILED. No revoke is ever sent,
so the ACL stays forever. A setfacl that fails between the `-m` and `-d -m` steps
leaves a partial ACL with no local record. Handlers should be spawned as tasks, and
lockdown should take priority.

B-8. **After lease expiry and renewal, the agent's dispatcher stays dead.** A
disabled key gets 401. The dispatcher sends `key.rotate` (refused, because the
agent is disabled) and **returns** (`daemon.py:501-503`). A renewal does not rotate
the key, so no `key` message comes and `_dispatch` is never called again until the
daemon restarts. New threads to that agent are never routed. Meanwhile every
watcher of a disabled agent sends `key.rotate` every 5 s forever
(`daemon.py:693-695`), which is channel and log spam.

B-9. **Sessionless conversations still accept threads, and their messages are lost.**
When the broker ends a conversation's session, the watcher sets
`broker_session_id=NULL` and exits (`daemon.py:687-692`). The conversation stays
`parked`, so a hint or triage can still choose it (`route_open`,
`_triage_candidates`). `claim` then accepts **without a session**
(`broker.accept(..., None)`), and no watcher exists for it, so only the messages
present at claim time are ever delivered. The process env also gets
`AGENT_AUTH_SESSION=""`. Such conversations should be treated as closed, or given
a new session.

B-10. **Unpairing a sandbox leaves its agents enabled with valid keys.** Deleting the
daemon sets `agents.sandbox_id=NULL` (FK SET NULL) and cascades the pending rows,
but disables nothing (`core/daemons.py:366-385`). The old VM's keys keep working
against the HTTP API until each lease expires (orchestrator: never). After a
re-pair, the orchestrator is adopted (its sandbox_id is NULL) and rotated. Minted
children cannot be renewed ("doesn't belong to this sandbox") or rotated
(`sandbox_id != daemon`), so they die at lease end. Also, the admin `rotate-key` on
a VM agent returns the key to the admin and silently breaks the VM's copy (it
recovers only through 401 → key.rotate, which issues yet another key).

B-11. **Codex auth sync: TOCTOU and cross-project poisoning, run as root on
project-controlled paths** (`daemon.py:892-914`).
(a) `is_symlink()` is checked, then later `mkdir`, `write_file` and `read_text`
run on the same paths. A project user can swap `~/.codex` for a symlink in between
and make root write `auth.json` (chowned to the project) into another directory, or
read an arbitrary root-readable text file (for example
`/var/lib/sandboxd/secrets/claude-oauth-token`) into the shared
`codex-auth.json`, which is then copied into every codex project.
(b) Even without a race, the newest mtime wins, and a project controls its file's
mtime (`touch -d` into the future). Any one project can replace the login that all
other projects' codex processes use (for example with its own account). This is a
cross-project influence/leak channel.
(c) `write_file` opens `.<name>.tmp` without `O_EXCL`. If a project has created
`~/.codex/.auth.json.tmp` as a FIFO, the synchronous `os.open(O_WRONLY)` blocks the
whole daemon event loop: a VM-wide DoS (`host.py:136`).
The port should do these with dirfd-relative `openat(O_NOFOLLOW)`, refuse
non-regular files, and avoid trusting the project's mtime.

B-12. **Root runs `setfacl -R` over trees that agents control.** `grant_acl` and
`revoke_acl` walk the target project by path (`host.py:119-128`), and the target's
uid can race symlink swaps during the walk. setfacl skips symlinks it encounters,
but not atomically. This could put an ACL for the requester on files outside the
project (for example `state.db`). The port should walk with `openat`/`O_NOFOLLOW`
and set ACLs through fds (`fsetxattr`).

B-13. **The codex socket path is project-controlled.** `socket_on_host` follows the
project's symlink, and `connect_unix` opens its parent with `O_PATH` (following
symlinks). Root sandboxd can be made to connect to any socket in the VM (for
example `/run/sandboxd/operator.sock`) and speak WebSocket to it. This is
low-impact (the operator API rejects non-JSON lines), but it is a confused deputy.
The port should resolve the path under the tmp dir with no symlink components.

B-14. **Any VM agent may request `agents:mint`, not only the orchestrator**
(`provisioners/agents.py:36-38`). The renewal path doesn't check the parent either
(`core/sandboxes.py:255-261`). With a permissive `mint` rule, a project agent of
project A can mint `<rt>-B-<host>-sandbox` and then (with an a2a talk grant) have
code run as project B's uid. That crosses the project boundary without a
`sandbox:project.*` grant. Only policy prevents it. Consider requiring
`runtime == "orchestrator"` for the parent.

B-15. **README contradicts the gateway fallback.** The README says "the gateway is
never a reason a conversation does not start" and that the VM logins are used when
a request "is not granted at once". The code raises NoModelKey and refuses to start
on any broker error, refusal or pending request (`daemon.py:824-872`). Port the code
behavior (INV-18), not the README.

B-16. **Codex triage is not tool-less.** `codex exec -s read-only` keeps codex's
shell tools (read-only sandbox). The prompt carries untrusted peer text
(`runtimes/codex.py:510-516`). The codex triage also uses the runtime's normal
model, not a cheap one, when `triage_model` is unset. Docs §6.3 marks it as
unverified.

B-17. **A conversation chosen during an open that fails to start is still accepted,
then rejected.** `route_open` → `claim` (accept) → `_read_thread` → `deliver` raises
(NoModelKey is a RuntimeError, or the project is missing → LookupError). The
dispatcher then calls `reject` on a thread it already accepted
(`daemon.py:494-499`). The reject most likely fails on the broker side and the loop
sleeps. The message is queued and nothing retries until the next message arrives.

B-18. **Smaller items.**
- Sessions and conversations are never garbage-collected: the watcher's long-poll
  keeps every broker session alive forever.
- Live tokens of closed conversations stay valid in `self.live`.
- `_tui_ended` from the reaper does not delete the TUI's env file (it stays in
  `/run/sandboxd/env`, which is root-only tmpfs).
- `/run/sandboxd` is 0755 although the config comment says "root only" (the files
  in it are 0600).
- Triage selects a candidate by substring match of its id in the answer.
- The docs describe a `key.available`/fetch flow and an `AGENT_AUTH_SESSION_ID`
  env var. The code pushes `key` directly and uses `AGENT_AUTH_SESSION`.
- Env file values use `shlex.quote` single-quote escaping (`'"'"'`), which
  systemd's EnvironmentFile parser may not concatenate. Values with `'` would be
  mangled. Today's values (keys, tokens, URLs) contain none.
