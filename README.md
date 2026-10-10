# agent-auth

A credential/access broker for AI agents (Hermes instances), with Discord as the
human-approval surface. Agents submit structured, time-bounded access requests; a
policy engine decides per request — **deny**, **auto-approve**, **LLM-review**
(OpenRouter), or **surface to a human on Discord** with Approve / Deny / Edit
buttons. Approved grants are actually provisioned (GitHub App tokens, LLDAP group
membership, a2a permissions) and revoked when they expire.

```
agent ──HTTP/MCP/CLI──▶ broker ──policy──▶ deny | approve | llm | surface ──▶ Discord ping
                          │                                                    Approve/Deny/Edit
                          └─▶ provisioners: GitHub App tokens · LLDAP groups · a2a grants · google (stub)
                              └─ expiry scheduler revokes at expires_at
```

## Platforms

| platform  | capability    | resource            | grant means                                                                 |
|-----------|---------------|---------------------|-----------------------------------------------------------------------------|
| `github`  | `repo`        | `owner/repo`        | broker mints GitHub App installation tokens (≤1h, re-minted on demand) scoped to the repo + `scope.permissions` |
| `github`  | `create`      | `org/name`          | broker **creates** the repo in an org listed in `create_owners` (`scope.visibility`: `private`, or `public` = always human-reviewed), using an Administration token it mints, uses once and revokes — the agent never sees it. Already exists → fails, unless the broker itself created it earlier (a retried create is adopted). Access afterwards is a normal `repo` grant; nothing is deleted at expiry |
| `homelab` | `group`       | LLDAP group name    | agent's LLDAP service account is added to the group (Authelia rules are per-group); removed at expiry. Agents without a hand-registered account get a broker-managed one (`svc-<name>`, generated password) at their first grant; the credential fetch returns username + password |
| `kubernetes` | role name (`view`, `edit`, `traefik-patcher`, …) | namespace name (or `*` for cluster-wide) | per-grant ServiceAccount + RoleBinding to the named (Cluster)Role — a ClusterRoleBinding when the namespace is `*`; tokens minted on demand via TokenRequest; SA deleted at expiry → all tokens die instantly. The capability *is* the role, so policy rules auto-approve narrow roles and surface broad ones |
| `a2a`     | `talk`        | target agent name   | authorizes OPENING conversation threads to that (service) agent — see [a2a threads](#a2a-threads); no credential is minted |
| `hostexec` | `run`, `tpl.<name>`, `shell` | host name | one command (or a time-boxed shell) **on a host**, run by that host's daemon — see [Commands on hosts](#commands-on-hosts-hostexec). The host decides, with its own TOTP secrets and policy; root and shells always reach a human |
| `google`  | `calendar.*`… | calendar id / label | stub: decisions recorded, no credential minted (501)                        |

Note the Gitea flow: the broker grants the homelab agent the `svc-gitea` LLDAP
group; the agent then authenticates to Gitea itself and mints its own tokens.
The broker never talks to Gitea.

## Quick start (dev)

State lives in a local SQLite file by default (WAL mode; the broker is a single
process, so SQLite is the recommended production database too). Set
`DATABASE_URL=postgresql+asyncpg://...` if you'd rather use Postgres —
`docker-compose.yml` provides one.

```bash
cp policy.example.yaml policy.yaml
cat > .env <<EOF
ADMIN_TOKEN=$(openssl rand -hex 24)
ENCRYPTION_KEY=$(uv run agent-auth admin gen-key)
DISCORD_TOKEN=...            # bot token; needs no privileged intents
DISCORD_CHANNEL_ID=...       # channel for approval requests
DISCORD_OWNER_ID=...         # your discord user id (gets pinged, may click buttons)
OPENROUTER_API_KEY=...       # optional; without it, 'llm' rules escalate to human
EOF
uv run agent-auth-server               # migrates, then serves :8400 + bot + scheduler
```

Register an agent and make a request:

```bash
export AGENT_AUTH_URL=http://localhost:8400 AGENT_AUTH_ADMIN_TOKEN=<ADMIN_TOKEN>
uv run agent-auth admin agent-create hermes-sde --description "sde agent"
# → prints the API key ONCE

export AGENT_AUTH_API_KEY=aa_...
uv run agent-auth request a2a talk other-agent --why "coordinate deploy" -d 2h --wait
```

On NixOS, run inside `nix develop` (sets `LD_LIBRARY_PATH` for manylinux wheels).

## Exposing to Hermes instances

Each Hermes instance gets its own agent identity + API key. Three equivalent
interfaces, all wrapping the same HTTP API:

- **HTTP**: `Authorization: Bearer aa_...` against `/v1/...` (interactive docs
  are disabled; discover the surface with `GET /v1/catalog`).
- **MCP** (recommended for agents): stdio server with tool docs written for LLMs —
  ```json
  {"mcpServers": {"agent-auth": {
      "command": "agent-auth-mcp",
      "env": {"AGENT_AUTH_URL": "https://agent-auth.rooty.dev", "AGENT_AUTH_API_KEY": "aa_..."}}}}
  ```
  The server sends orientation instructions on connect (clients that defer
  MCP tools show agents only tool names until loaded, so the workflow lives
  there). Tools: `whoami`, `list_capabilities`, `request_access`, `wait_for_decision`,
  `retry_request`, `escalate_request`, `get_credential`, `list_grants`,
  `create_session`, `close_session`, `check_a2a`, `a2a_open`, `a2a_send`,
  `a2a_poll`, `a2a_threads`, `a2a_accept`, `a2a_reject`, `a2a_close`,
  `a2a_events`. Runtimes that share ONE MCP process across conversations
  (Hermes): each conversation calls `create_session` once and passes the
  returned id as `session_key` on every a2a/`request_access` call — explicit
  keys never touch shared state, so concurrent conversations can't clobber
  each other. Ephemeral CLI agents (own MCP process per session) keep the
  automatic cwd-labeled session and never need `session_key`.
- **CLI**: `agent-auth ...` (same env vars), plus `agent-auth admin ...` with
  `AGENT_AUTH_ADMIN_TOKEN`.

### Agent protocol

0. `list_capabilities()` (`GET /v1/catalog`) — discover what's requestable:
   enabled platforms and their roles/groups/repos/permissions, each with a
   description and its typical routing (auto-approve / human review). Pick the
   narrowest capability that does the job.
1. `request_access(...)` with a **specific** justification and a duration.
2. `wait_for_decision(id)` — blocks through LLM review / human review.
3. On `llm_denied`: read `decision_reason`, `retry_request` with a revised
   justification (limited attempts), or `escalate_request` to a human.
4. On `granted`: `get_credential(grant_id)` when a token is needed (GitHub);
   re-fetch rather than caching — minting stops the moment the grant ends.

## a2a threads

Agent-to-agent messaging is TCP-like conversations through the broker, not a
mailbox. An a2a grant (platform `a2a`, capability `talk`, resource = target
agent, optional `scope={"topic": "deploy/*"}`) authorizes **opening threads**;
everything after that is thread lifecycle:

```
open (carries first message) ─▶ pending_open ─▶ accept / first reply ─▶ open ─▶ close
                                     └▶ reject / open_timeout ─▶ closed
```

- **Fast-open**: `POST /v1/a2a/threads {to, topic?, payload}` — the first
  message rides the open. The responder `accept`s, `reject`s, or just replies
  (implicit accept). Unanswered opens close after `A2A_OPEN_TIMEOUT_SECS`.
- **Cursor reads, no acks**: messages carry a per-thread `seq`.
  `GET /v1/a2a/threads/{id}/messages?after_seq=N&wait=60` long-polls for the
  reply — this is how a CLI agent waits in-session. `GET /v1/a2a/events?wait=`
  is the service-agent loop: pending opens awaiting you + threads with new
  activity since your cursor.
- **Liveness**: any authenticated call (long-polls included) refreshes
  last-seen; thread status reports `peer_alive`/`peer_last_seen_at`. Threads
  close automatically: `open_timeout`, `idle_timeout`, `peer_gone` (the peer's
  session ended), `grant_revoked` (the backing grant was revoked/expired —
  either side's next send also detects this immediately).
- **Reachability** (is anyone home?) is a *separate* signal from liveness, and
  the one consulted before a thread exists. Last-seen tracks **outbound**
  activity, so an agent busy requesting access looks alive even when nothing on
  its side ever reads an inbound thread — the classic Claude-Code-registered-as-
  `service` case. Reachability instead keys on `last_listen_at`, touched only by
  the inbound surfaces (`GET /v1/a2a/events`, thread accept), within
  `a2a_listen_threshold_secs` (300s; deliberately coarser than the 120s liveness
  threshold, so a dispatcher between polls still counts). A peer is reachable if
  it hosts a `webhook_url` (wake-able on demand, `why: "webhook"`) or has
  listened recently (`why: "polling"`); otherwise `why: "idle"`.
  `GET /v1/catalog` returns a2a `peers` as objects carrying these fields
  (reachable ones sorted first), `GET /v1/a2a/check` returns the same under
  `peer` alongside the permission answer, and an open to an idle peer fails fast
  with **409** instead of parking the caller until the `open_timeout` sweep.
  Structural vs transient stays distinguishable: unaddressable (ephemeral) is
  **403** and never worth retrying; 409 is.
- **Agent kinds & sessions**: `service` agents (Hermes) are always-on and may
  register a `webhook_url` — but note that registering as `service` does not by
  itself make an agent answerable: it must either host a webhook or keep the
  `/v1/a2a/events` loop running, or peers are told it is idle. `agent-create`
  warns when a `service` agent is registered with neither, since that shape is
  almost always an `ephemeral` agent left on the default `--kind`;
  `ephemeral` agents (Claude Code, Codex) must mint a
  session (`POST /v1/sessions {label}`, then send `X-Agent-Session`; the MCP
  server does this automatically, labeled by cwd) and are **initiate-only** —
  nobody can open a thread to them. Multiple concurrent instances work: threads
  bind to the opening session and replies route only to it; a later session of
  the same identity cannot read or act on another session's threads.
- **Responder sessions** (service-agent workers): sessions are uniform
  machinery — a service agent's per-conversation worker may accept (or first
  reply to) a thread **with its own session**, binding the thread to that
  worker: wakes route only to it, other sessions and the sessionless
  dispatcher lose access, the initiator's `peer_alive` reflects the *worker's*
  liveness (not the daemon's), and the thread ends `peer_gone` when the worker
  session dies. The intended Hermes shape: a sessionless dispatcher loops on
  `/v1/a2a/events` (which shows pending opens + unbound activity), spawns one
  conversation per thread, and each worker claims its thread by accepting with
  a fresh session. Sessionless accept keeps today's agent-level behavior. No
  handoff: if a worker dies, its thread closes `peer_gone` and the initiator
  reopens. Hermes→hermes chains compose: a worker opens downstream threads
  from its session, so teardown cascades link by link (and revokes any
  delegated grants along the way).
- **One agent identity per folder**: register CLI agents per workspace using
  the `<agent-type>-<folder>-<host>` naming scheme shared with the Hermes
  fleet — e.g. `claude-nixos-dots-uorux` alongside `hermes-homelab-recusant`
  (`kind=ephemeral`) — with the key in that folder's
  env (direnv/.env). The key is the permission boundary — folder-level policy
  is plain agent-name matching (your homelab folder's claude can hold
  kubernetes grants; your kernel folder's claude can't even ask as that
  identity). Grants — a2a included — are agent-level, so all sessions of a
  folder share them; the responder replies under the initiator's grant, no
  reverse grant needed.
- **Webhook pings** (service agents only): notify-only —
  `{type: a2a_thread_open|a2a_message|a2a_thread_closed, thread_id, seq, from,
  topic}` with **no payload**; fetch via the cursor read. Signed
  `X-Agent-Auth-Signature: sha256=<hmac>` with the agent's `webhook_secret`
  (shown ONCE at admin create / `rotate-webhook-secret` — record it then; it
  is not readable afterwards, by design), falling back to the global
  `WEBHOOK_SIGNING_SECRET`. Delivery is best-effort; the poll is authoritative.

Retrofit: `agent-auth admin agents` lists `kind` and `last_seen_at`; anything
`service` that has never been seen (or is never seen polling) is the shape to
reclassify with `admin set-kind`. Demotion to `ephemeral` drops the webhook,
closes the threads it was responding to (`peer_gone`), and revokes every a2a
grant that targets it — a talk grant to a peer that cannot receive threads is
never allowed to exist, whether requested after or before the reclassification.

CLI: `agent-auth session create|close`, `agent-auth a2a
open|send|poll|threads|show|accept|reject|close|events|check`, plus
`agent-auth a2a serve --on-open-url <url>` — a resident sessionless dispatcher
that POSTs each pending thread-open (signed, level-triggered redelivery until
accepted) to an agent runtime's conversation-start webhook;
`--sig-header X-Hub-Signature-256` emits the same `sha256=<hex>` signature
under a GitHub-style header for receivers that verify a fixed name.

For wiring a Discord-based Hermes instance into all of this — dispatcher loop
vs webhook+cron, the conversation lifecycle, and final-message routing — see
[docs/hermes-setup.md](docs/hermes-setup.md).

### Delegated auth (on behalf of)

A request may be anchored to an **OPEN a2a thread the requester is
responding to** (`on_behalf_of_thread` in the request body / MCP tool /
`--on-behalf-of-thread` CLI flag) — pass only the thread whose conversation
asked for the work. The broker derives the delegator (the thread's
**initiator**, i.e. the side that asked; never client-asserted), so "hermes
acting for claude" is backed by a real, mutually consented conversation, not a
justification string. Direction is enforced: a thread you opened yourself is
never delegation proof — otherwise "acting for X" could be manufactured by
opening a thread to X and waiting for X's dispatcher to accept it.

- **Policy authorizes the pair**: rules gain a `delegator:` glob. Rules without
  one still deny/surface delegated requests but never auto-approve or
  LLM-clear them — pre-delegation rules can't be laundered through. Approving
  a delegated request on Discord with Edit→rule pins the delegator, so the
  saved rule only re-applies to the same pair.
- **The grant lives and dies with the thread**: expiry is capped at the
  thread's backing a2a grant; when the thread closes (close, reject,
  `peer_gone`, `idle_timeout`, grant revocation), credentials stop being
  issuable immediately and the scheduler revokes the grant within a tick.
  Hanging up is revocation.
- **Depth 1 only**: a2a access itself cannot be delegated (no re-delegation
  chains), and platform validator ceilings apply unchanged — delegation can
  select rules, never widen them.
- The Discord embed and LLM review both show "on behalf of `<delegator>`
  (thread topic)" so the reviewer sees the pair, not just the delegate.

## Policy

See `policy.example.yaml`. Evaluation order: platform validator (hard ceilings) →
saved rules from Discord's **Edit** modal (newest first) → YAML rules (first match)
→ default. Approved duration is always `min(requested, rule cap, default cap)`;
a human editing an approval may exceed policy caps deliberately but is bounded at
1 year (catches fat-fingered values).

The Discord **Edit** button opens a modal to adjust duration/resource/scope before
approving, and its *Rule* field persists a rule for future identical requests:
`approve`, `approve:capability` (any resource), `approve:platform`, or `deny:*`
variants. **Edited approvals are re-validated against the platform ceilings before
provisioning** — an override can't push a grant past the repo allowlist, permission
ceiling, or namespace/role allowlist. Auto-approve rules are **scope-pinned**: a
rule created for `contents:write` won't rubber-stamp a later `secrets:write` on the
same repo. Manage saved rules with `agent-auth admin rules` / `rule-delete`.

LLM review calls OpenRouter with a structured verdict schema; the model is set
per-rule (`constraints.llm_model`) or globally (`llm.model`). Evaluator errors
always escalate to a human — never auto-approve. **Sensitive scopes always reach a
human**: `platforms.github.sensitive_permissions` (default `secrets`,
`administration`) and `platforms.kubernetes.sensitive_roles` (default `edit`,
`admin`) force a request to `surface` even if a YAML rule or the LLM would clear it,
so attacker-controlled justification text can't talk the model into a broad grant.
A human's own scope-pinned auto-approve rule still applies.

## GitHub App setup (one-time)

1. Create a GitHub App (Settings → Developer settings → GitHub Apps): no webhook,
   permissions = the *ceiling* you ever want brokered (e.g. contents rw, secrets rw,
   pull requests rw). Note the **App ID**.
2. Generate and download a **private key** (PEM).
3. Install the app on each account whose repos you broker (personal and/or
   orgs), selecting the repos. The broker resolves the right installation per
   repo automatically — `GITHUB_INSTALLATION_ID` is optional and only pins a
   single installation; with it set, only repos owned by that installation's
   account are mintable (the token endpoint takes bare repo names, so the
   broker refuses any other owner rather than silently re-targeting).
4. Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY_FILE`, and mirror the
   ceiling in `platforms.github.permission_ceiling`.
5. **Repo creation** (optional): give the app the **Administration: write**
   repository permission, accept it on each org installation you list in
   `platforms.github.create_owners`, and keep those orgs inside
   `repo_allowlist`. Organizations only — an installation token can't create
   repos under a personal account. Check whether a newly created repo joins
   a *selected-repositories* installation; if it doesn't, the create grant's
   credential says so, and `repo` grants on it fail until you add it (or
   install the app on all repositories of that org).
6. Note the app is its own principal: installation tokens carry the *app's*
   permissions as approved at install time — they never inherit or act with
   any user's org role.

Uploading Actions secrets (libsodium sealed box) is the *agent's* job with its
minted token; the broker only grants `secrets: write`. A minted token can outlive
revocation by up to ~55 min (GitHub tokens are not remotely revocable by the
broker beyond best effort); enforcement is refusal to re-mint.

## LLDAP setup

- Create per-capability groups (`svc-gitea`, `svc-sonarr`, …) and point Authelia
  access rules at them; list them in `platforms.homelab.allowed_groups`.
- The broker's LLDAP account must be in `lldap_admin` — LLDAP has no finer role
  that can change group membership (or create users). Its JWT is cached and
  refreshed on 401 (~1 day expiry).
- **Managed accounts (default):** register agents without `--lldap-username`.
  At the agent's first homelab grant the broker creates
  `<managed_username_prefix><agent name>` (default `svc-<name>`) via GraphQL
  `createUser`, sets a random 43-char password with LLDAP's own
  `lldap_set_password` tool (OPAQUE registration has no plain-JSON form), and
  stores it Fernet-wrapped on the agent row. The agent reads username and
  password from `GET /v1/grants/{id}/credential` (`kind: lldap_account`) —
  same value on every fetch until `agent-auth admin rotate-lldap-password
  <agent-id>`, which is never printed, only delivered through the next fetch.
  Requires `ENCRYPTION_KEY` and `lldap_set_password` on the broker's PATH (or
  `LLDAP_SET_PASSWORD_BIN`); the nixpkgs `lldap` package ships the binary.
  Set `platforms.homelab.managed_accounts: false` to turn it off.
- **Hand-registered accounts:** pass `--lldap-username` at registration to use
  an account you created yourself. The broker only manages its group
  membership, never learns its password, and the credential fetch stays the
  informational `lldap_group` note.

## Kubernetes setup

Set `KUBERNETES_API_URL=in-cluster` (or an API server URL plus
`KUBERNETES_TOKEN`/`KUBERNETES_TOKEN_FILE` and `KUBERNETES_CA_FILE` for
out-of-cluster). For an HA control plane, give a comma-separated list of
apiserver URLs (e.g. `https://cp1:6443,https://cp2:6443,https://cp3:6443`) and
the broker fails over to the next when one is unreachable. The broker needs
RBAC to create/delete ServiceAccounts and
RoleBindings, create `serviceaccounts/token`, and `bind` the allowlisted
ClusterRoles — see the `agent-auth-provisioner` ClusterRole in `deploy/k8s.yaml`
(bind it per brokered namespace, or cluster-wide if your allowlist is broad). If
you enable cluster-wide grants (below), it also needs create/delete on
`clusterrolebindings`.

Ceilings: `namespace_allowlist: ["*"]` is fine — containment comes from narrow
roles and human review, not from walling namespaces off (an agent with gitops
access reaches them anyway). Keep `role_allowlist` enumerated and prefer
purpose-built roles over `edit`/`admin`: it must match the ClusterRoles/Roles
the broker holds `bind` on, so a tight role means a tight grant *and* a tight
broker credential.

**Cluster-wide grants.** An agent requests cluster scope by asking for the
namespace `"*"`; the broker binds the role via a `ClusterRoleBinding` (the
backing ServiceAccount lives in `cluster_grant_namespace`, default `default`)
instead of a namespaced RoleBinding. This is gated by a *separate*
`cluster_role_allowlist` — empty by default, so cluster-wide is off until you opt
a role in — and **every** cluster-wide grant is forced to human review, whatever
the role and whatever any rule says. Keep the list tiny (read-only roles at
most); a cluster-wide `edit` is close to `cluster-admin`.

**Narrow capability library.** The capability an agent requests *is* the role
name, so a single approval grants exactly one capability rather than a tier.
`deploy/k8s.yaml` ships a library of these, friction scaled to blast radius:
auto-approved (`traefik-patcher` — `get`+`patch` on the one named `traefik`
deployment; `logs-reader` — read pods + logs; `workload-manager` — restart and
scale Deployments/StatefulSets), LLM-reviewed (`cm-editor`, `port-forwarder`,
`job-runner`), and human-only via `sensitive_roles` (`pod-exec`,
`secret-reader`, `edit`, `admin`). To add your own:

1. Define a `ClusterRole` with the minimal rules in `deploy/k8s.yaml`.
2. Append its name to the provisioner's `bind` `resourceNames` (so the broker
   can hand it out) **and** to policy `role_allowlist`.
3. Optionally add a policy rule to auto-approve it; agents request it as the
   capability (`agent-auth request kubernetes <role> <namespace> ...`).

Caveat: RBAC `resourceNames` scopes `get`/`patch`/`delete` on named objects but
is ignored by `create` and disables `list`/`watch` — so a name-scoped role acts
on an object directly but can't enumerate the collection. `get`+`patch` (what
`kubectl edit` does) works; `kubectl get <type>` without a name won't.

Agents use the credential as a bearer token:
`kubectl --server=... --token=$(agent-auth cred <grant-id> | jq -r .value) -n <ns> ...`
Tokens are short-lived (≤1h, capped at the grant's remaining life) and every
token dies the moment the grant expires or is revoked, because the
ServiceAccount itself is deleted.

## Paired daemons (hostd)

Hosts run `agent-auth-hostd`, a daemon that dials out to the broker over a
signed WebSocket (`/v1/daemons/connect`); see
[docs/sandbox-design.md](docs/sandbox-design.md). With no tier enabled it only
pairs, connects and reports heartbeats, as the unprivileged `agent-auth-hostd`
user. Enabling a tier makes it run approved commands
([Commands on hosts](#commands-on-hosts-hostexec)), as root.

- **Broker key**: `agent-auth admin gen-signing-key --out FILE` writes
  `BROKER_SIGNING_KEY` to a new 0600 file (move it into the broker's env
  secret, never into `settings`) and prints the public key. Without `--out`
  it prints the seed only to a terminal (or with `--stdout`). Every daemon
  **pins** that public key in its own config, so the broker is verified
  against the host's config, not against whatever answers on the network.
  Without `BROKER_SIGNING_KEY`, the daemon endpoints are disabled (503).
- **Pairing**: `agent-auth admin daemon-pair <hostname>` issues a one-time
  code (10 min, single use, burned after 5 wrong proofs). On the host, run
  `sudo agent-auth-hostd pair` and enter the code at the (hidden) prompt, or
  pipe it to `agent-auth-hostd pair -`, or set
  `AGENT_AUTH_HOSTD_PAIRING_CODE`. It is never taken as an argument, where it
  would land in shell history and process listings. Both sides prove
  knowledge of the code over the exact keys exchanged, and both print key
  fingerprints to compare.
  Re-pairing replaces the key and drops the old connection.
- **Connections**: mutual challenge–response on every connect, then every
  message is an ed25519-signed envelope naming its sender and recipient, with
  a short expiry and replay protection.
- **Fleet health**: `agent-auth admin daemons` / Discord `/hosts` list paired
  daemons with online state, version and last heartbeat;
  `agent-auth admin daemon-unpair <id>` forgets one.

```nix
imports = [ inputs.agent-auth.nixosModules.hostd ];
services.agent-auth-hostd = {
  enable = true;
  brokerUrl = "https://agent-auth.recusant.rooty.dev";
  brokerPublicKey = "ed25519:…";   # agent-auth admin broker-key
};
# impermanence: persist /var/lib/agent-auth-hostd (the host's identity key,
# its TOTP secrets and lockdown flag), mode 0700. Owner: agent-auth-hostd while
# no tier is enabled, root once one is (the module's tmpfiles rule moves it).
```

## Commands on hosts (hostexec)

An agent can ask to run one exact command on a host, as your user or as root:
platform `hostexec`, capability `run`, resource = the host,
`scope {"tier": "user"|"root", "argv": [...], "cwd"?, "env"?, "timeout"?, "stdin"?}`
(MCP tool `host_run`). The request goes through policy and Discord like any
other. **Whether it runs is decided on the host**, by hostd, in this order:

1. locked down → no;
2. tier disabled, a `denyCommands` match, an env var outside `envAllow` → no;
3. a valid **direct TOTP code** came with the approval → run, armed or not;
4. an `autoCommands` match (user tier) → run;
5. the tier is **armed** → run if a human approved it; a rule's, the LLM's or
   policy's approval only with `acceptMachineApprovals`; an "approve all"
   window only with `acceptApproveAll`;
6. otherwise → refused (`not_armed`), and the approval is not accepted: the
   request stays open on Discord.

```nix
services.agent-auth-hostd = {
  enable = true; brokerUrl = "…"; brokerPublicKey = "ed25519:…";
  user = "jrt";                       # the user tier runs as this account
  tiers.user = { enable = true; maxArm = "8h"; shell.enable = true; };
  tiers.root = { enable = true; maxArm = "1h"; };   # no windows, no machine approvals
  autoCommands = [ [ "systemctl" "--user" "status" "*" ] ];
  denyCommands = [ ];
  templates.nixos-rebuild = {
    tier = "root";
    argv = [ "nixos-rebuild" "switch" "--flake" "{flake}" ];
    params.flake = "git\\+https://git\\.example/me/[a-z0-9-]+#[a-z0-9-]+";
  };
  vm.unit = "agent-vm.service";       # frozen on lockdown; null without a VM
};
users.users.jrt.linger = true;        # headless hosts: the user tier needs the user's manager
```

- **TOTP.** `sudo agent-auth-hostd totp-enroll` on each host creates four
  secrets and shows each once as a QR code: `<tier>-arm` and `<tier>-direct`
  for `user` and `root`. They are generated on the host and never leave it.
  Codes are single use; five wrong ones lock a secret for five minutes.
- **Arming.** `/arm host tier duration code` (an arm code), or on the host
  `agent-auth-hostctl arm 2h` (your user for the user tier; `sudo … --tier
  root`). Held in memory: a restart disarms. `/disarm` needs no code.
- **Discord.** Approve (needs the tier armed) · Approve all… (a time-boxed
  rule for that agent, host and tier; armed, and the host must accept
  windows) · Approve with TOTP (a direct code, works disarmed) · Deny · Edit.
  The message gets the exit code, duration and the end of the output; the
  agent gets all of it (the last 1 MiB) from `host_job`. With
  `OPENROUTER_API_KEY`, each request carries an advisory risk line from a
  model (`platforms.hostexec.risk_model`); it decides nothing.
- **Templates** (`tpl.<name>`): the host expands its own copy, with each
  parameter checked against its regex and substituted as one whole argument.
  `platforms.hostexec.templates` in the broker's policy mirrors them so the
  Discord message can show the expanded command.
- **Shells** (`shell`, `scope {"tier"}`): a time-boxed window in which the
  agent runs commands one at a time (`host_shell_exec`; no terminal). Opened
  with a TOTP code only — arming, windows and rules never open one. The
  request is loud (optionally in `DISCORD_LOUD_CHANNEL_ID`), every command is
  posted to a thread on it **before** it is sent to the host (if it can't be
  posted, it doesn't run), and **End shell** kills it. The host keeps the
  expiry itself.
- **Kill switch.** `/lockdown [sandboxes|all|host]` or `agent-auth admin
  lockdown`: revokes the grants of agent-VM agents (of every agent with
  `all`), refuses new identities and host commands, and each host disarms,
  kills its jobs and shells, and freezes its agent VM from outside (`kill_vm`
  stops it). `/unlock` lifts the broker's side; **each host stays locked**
  until `/unlock host:<h> code:<root-arm code>` or `sudo agent-auth-hostctl
  unlock` there.
- **Audit.** Every decision hostd makes is in its journal
  (`journalctl -u agent-auth-hostd`), with the evidence it was made on.

What this does **not** protect against: codes pass through Discord and the
broker, so a compromised broker can attach a direct code you typed to a
different command (once per code); and while a tier is armed it can run
anything in that tier. Disarmed and without codes it can run only the
`autoCommands`. `denyCommands` guards against mistakes, not against `sh -c`.

Not yet run on a real host: the systemd-run paths (the user tier's in
particular). The tests drive the real daemon with a fake executor.

## Desktop prompts

With `desktop.enabled` in the policy and `services.agent-auth-hostd.desktop.enable`
on a host, a request that needs you is also shown as a dialog on **every
desktop you are at**, next to the Discord message; the first answer decides
and the others are taken down. No answer in 90 s leaves it to Discord.

```yaml
desktop:
  enabled: true
  agents: ["claude-*", "codex-*", "*-sandbox"]   # who may be asked at a desk
  # platforms: [github, a2a]    # empty = any
  # sensitive: false            # root commands etc. stay on Discord
```

- **Present** means: hostd's helper in your session (`agent-auth-hostd user`,
  a user service) is connected, the session is unlocked and was used within
  `desktop.maxIdle`, nothing is fullscreen (or `desktop.busyCommand` says not
  now), and do-not-disturb is off. Unknown counts as away. Hyprland keeps no idle or lock hints, so report them:

  ```
  # hypridle.conf
  listener { timeout = 300; on-timeout = agent-auth-hostctl presence idle; on-resume = agent-auth-hostctl presence active }
  # around your lock screen
  agent-auth-hostctl presence locked; hyprlock; agent-auth-hostctl presence unlocked
  ```
- **Buttons**: Allow once · Deny · Mute agent 1h · Send to Discord. Deny is the
  default, so a stray Enter denies. The dialog
  is `desktop.promptCommand` (zenity by default; any command that exits 0 for
  allow works, including `sbx-prompt`).
- **Limits**: one dialog per desktop at a time, 2 in a burst and 6 an hour per
  agent, 20 an hour overall, a 10-minute pause after a Deny (an hour after
  three), optional `quiet_hours`, `agent-auth-hostctl dnd 2h` / `/dnd`.
- An answer at a desk counts like a click on Discord: a host command still
  needs its host armed, and shells are never asked there.

What this does **not** protect against: anything running as you on one of
those desktops, or a compromised host, can answer its prompts. `desktop.agents`
and `desktop.platforms` are the limit on what that can approve.

Not yet run on a desktop: the zenity dialog, the Hyprland fullscreen check and
the user service. The tests drive the real helper with a script as the dialog.

## Agent VMs (sandboxd)

An agent VM is one per host. It runs orchestrated, headless Claude/Codex
agents, each project under its own unix user. See
[docs/sandbox-design.md](docs/sandbox-design.md); nixos-dots'
`modules.agentVm` builds the VM, and `nixosModules.sandboxd` goes into its
guest.

- **Identities.** Pairing the VM's daemon (`agent-auth admin daemon-pair
  --role sandbox <host>`, then `avm pair` on the host) bootstraps
  `orchestrator-<host>-sandbox`. Its policy may mint
  `<runtime>-<project>-<host>-sandbox` (platform `agents`, capability `mint`;
  only a rule naming `mint` clears it). A minted agent's key goes to the
  VM's daemon alone, never to the agent that asked. Each minted agent has a
  lease (`platforms.agents.lease`, 30d; minting again renews it), and
  `admin agent-disable` disables an agent and everything it minted.
- **Conversations.** An a2a open to a VM agent becomes a conversation: a
  claude (`-p` stream-json) or codex (app-server) process in a sandboxed
  systemd unit. It parks when idle and resumes on the next message, with the
  same transcript and scratchpad. `{"_sandbox": {"conversation": id}}` in an
  opening payload continues an existing conversation.
- **Projects.** Each project gets `/var/lib/sandbox/projects/<p>`, a home
  and a `/tmp` of its own, and a userdb user. Another project's files are a
  grant (platform `sandbox`, `project.read`, or `project.write`, which is
  always a human's call), applied by the daemon as ACLs.
- **Operators.** On the host, `avm`: `avm claude <project>` opens a
  conversation in the Claude TUI, minting the agent if needed. Other commands
  are `avm ls`, `attach`, `logs -f`, `send`, `stop`, `close`, `shell`,
  `project-create`, and `secret-set claude-oauth-token < file`.

## Deploy (recommended: native NixOS service)

Why not on the k8s cluster: the homelab agent will eventually hold gitops-repo
access, and the gitops repo is what would configure the broker there (policy
ConfigMap, RBAC) — a trivial privilege-escalation loop. On a NixOS host, the
policy file lives in the **nix store** (immutable at runtime; every change is a
commit to the host's config repo plus a rebuild) and the package builds from
source with no registry pull an agent could poison. Keep that host's config
repo out of reach of every brokered agent — that's the property the whole move
buys.

```nix
# flake input
inputs.agent-auth.url = "git+https://git.rooty.dev/jrt/agent-auth";

# host configuration
imports = [ inputs.agent-auth.nixosModules.default ];

# secrets via sops-nix (agenix works identically — any root-readable path)
sops.secrets."agent-auth/env" = {
  format = "dotenv";                          # KEY=value lines, see below
  sopsFile = ./secrets/agent-auth.env;
  restartUnits = [ "agent-auth.service" ];    # bounce the broker on rotation
};
sops.secrets."agent-auth/github-app-pem" = {
  format = "binary";
  sopsFile = ./secrets/github-app.pem;
  restartUnits = [ "agent-auth.service" ];
};
sops.secrets."agent-auth/k8s-token" = {
  format = "binary";
  sopsFile = ./secrets/k8s-token;
  restartUnits = [ "agent-auth.service" ];
};

services.agent-auth = {
  enable = true;
  policyFile = ./agent-auth-policy.yaml;      # → nix store, immutable
  listenHost = "127.0.0.1";                   # front with your reverse proxy
  environmentFiles = [ config.sops.secrets."agent-auth/env".path ];
  loadCredentials = [
    "github-pem:${config.sops.secrets."agent-auth/github-app-pem".path}"
    "k8s-token:${config.sops.secrets."agent-auth/k8s-token".path}"
  ];
  settings = {
    GITHUB_APP_PRIVATE_KEY_FILE = "/run/credentials/agent-auth.service/github-pem";
    KUBERNETES_API_URL = "https://<k8s-api>:6443";   # out-of-cluster
    KUBERNETES_TOKEN_FILE = "/run/credentials/agent-auth.service/k8s-token";
    KUBERNETES_CA_FILE = "/etc/agent-auth/k8s-ca.crt";
  };
};
```

The dotenv secret holds the flat key/value config
(`sops secrets/agent-auth.env` to edit):

```dotenv
ADMIN_TOKEN=...
ENCRYPTION_KEY=...           # agent-auth admin gen-key
DISCORD_TOKEN=...
DISCORD_CHANNEL_ID=...
DISCORD_OWNER_ID=...
OPENROUTER_API_KEY=...
GITHUB_APP_ID=...
GITHUB_INSTALLATION_ID=...
LLDAP_URL=http://lldap:17170
LLDAP_ADMIN_USER=agent-auth-svc
LLDAP_ADMIN_PASSWORD=...
#LLDAP_SET_PASSWORD_BIN=lldap_set_password   # for managed accounts; needs ENCRYPTION_KEY
WEBHOOK_SIGNING_SECRET=...    # optional; fallback HMAC key for a2a webhook pings
# a2a thread lifecycle knobs (defaults shown)
#A2A_OPEN_TIMEOUT_SECS=600
#A2A_THREAD_IDLE_TIMEOUT_SECS=3600
#SESSION_IDLE_TIMEOUT_SECS=900
#LIVENESS_THRESHOLD_SECS=120
```

`webhook_url` on a registered agent must be an `http(s)` URL (admin-set; the
broker POSTs to it verbatim, so keep it that way — self-service URLs would be
an SSRF vector). Webhook POSTs are notify-only pings (no message payload — pull
via the cursor read) signed with the agent's own `webhook_secret` when set,
else `WEBHOOK_SIGNING_SECRET`: `X-Agent-Auth-Signature: sha256=<hmac>` over the
raw body. If neither secret exists the ping is skipped entirely — unsigned
pings are never sent, and polling remains authoritative.

The unit runs as a `DynamicUser` with systemd hardening, stores SQLite state in
`/var/lib/agent-auth/`, and self-migrates on start. Secret files may stay
root-owned 0400 (sops-nix's default): systemd reads `EnvironmentFile` and
`LoadCredential` sources before dropping to the service user, so no
`owner`/`group` overrides on the secrets are needed. For the kubernetes
provisioner from outside the cluster, keep the `agent-auth-provisioner`
ServiceAccount + RBAC from `deploy/k8s.yaml` in the cluster and mint it a
long-lived token Secret for `KUBERNETES_TOKEN_FILE`.

### Alternative: container on k8s

`nix build .#dockerImage` → layered image running `agent-auth-server`; CI in
`.gitea/workflows/build.yml`, manifests in `deploy/k8s.yaml` (point
`DATABASE_URL` at a Postgres or mount a PVC for SQLite). Only appropriate if no
brokered agent can write to the gitops repo or the image registry. Keep **one
replica** either way — long-poll events and the scheduler are in-process.

## Development

```bash
uv run pytest                                  # sqlite-backed suite
TEST_DATABASE_URL=postgresql+asyncpg://... uv run pytest   # same suite on postgres
uv run python scripts/e2e.py                   # interactive walkthrough (live Discord)
```

SQLite runs in WAL mode with `busy_timeout` and foreign keys enforced (see
`db.py`); back up by copying `/var/lib/agent-auth/` (or `sqlite3 ... ".backup"`).

Architecture notes: all lifecycle logic is in `core/service.py` (state machine with
optimistic-concurrency transitions); Discord views, API routes, scheduler, and CLI
are thin callers. `grants.expires_at` is the persisted schedule — the expiry loop's
first tick after boot is the catch-up pass.
