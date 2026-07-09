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
| `homelab` | `group`       | LLDAP group name    | agent's LLDAP service account is added to the group (Authelia rules are per-group); removed at expiry |
| `kubernetes` | role name (`view`, `edit`, `traefik-patcher`, …) | namespace name | per-grant ServiceAccount + RoleBinding to the named (Cluster)Role; tokens minted on demand via TokenRequest; SA deleted at expiry → all tokens die instantly. The capability *is* the role, so policy rules auto-approve narrow roles and surface broad ones |
| `a2a`     | `talk`        | target agent name   | authorizes OPENING conversation threads to that (service) agent — see [a2a threads](#a2a-threads); no credential is minted |
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
      "env": {"AGENT_AUTH_URL": "https://auth.rooty.dev", "AGENT_AUTH_API_KEY": "aa_..."}}}}
  ```
  Tools: `list_capabilities`, `request_access`, `wait_for_decision`,
  `retry_request`, `escalate_request`, `get_credential`, `list_grants`,
  `check_a2a`, `a2a_open`, `a2a_send`, `a2a_poll`, `a2a_threads`, `a2a_accept`,
  `a2a_reject`, `a2a_close`, `a2a_events`.
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
- **Agent kinds & sessions**: `service` agents (Hermes) are always-on and may
  register a `webhook_url`; `ephemeral` agents (Claude Code, Codex) must mint a
  session (`POST /v1/sessions {label}`, then send `X-Agent-Session`; the MCP
  server does this automatically, labeled by cwd) and are **initiate-only** —
  nobody can open a thread to them. Multiple concurrent instances work: threads
  bind to the opening session and replies route only to it; a later session of
  the same identity cannot read or act on another session's threads.
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

CLI: `agent-auth session create|close`, `agent-auth a2a
open|send|poll|threads|show|accept|reject|close|events|check`.

### Delegated auth (on behalf of)

A request may be anchored to an **OPEN a2a thread** the requester participates
in (`on_behalf_of_thread` in the request body / MCP tool / `--on-behalf-of-thread`
CLI flag) — pass only the thread whose conversation asked for the work. The
broker derives the delegator (the thread's other participant; never
client-asserted), so "hermes acting for claude" is backed by a real, mutually
consented conversation, not a justification string.

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
   single installation.
4. Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY_FILE`, and mirror the
   ceiling in `platforms.github.permission_ceiling`.
5. Note the app is its own principal: installation tokens carry the *app's*
   permissions as approved at install time — they never inherit or act with
   any user's org role.

Uploading Actions secrets (libsodium sealed box) is the *agent's* job with its
minted token; the broker only grants `secrets: write`. A minted token can outlive
revocation by up to ~55 min (GitHub tokens are not remotely revocable by the
broker beyond best effort); enforcement is refusal to re-mint.

## LLDAP setup

- Create a service account per agent in LLDAP (e.g. `svc-homelab-agent`) and set
  it as the agent's `lldap_username` at registration.
- Create per-capability groups (`svc-gitea`, `svc-sonarr`, …) and point Authelia
  access rules at them; list them in `platforms.homelab.allowed_groups`.
- The broker's LLDAP admin account needs group-management rights; its JWT is
  cached and refreshed on 401 (~1 day expiry).

## Kubernetes setup

Set `KUBERNETES_API_URL=in-cluster` (or an API server URL plus
`KUBERNETES_TOKEN`/`KUBERNETES_TOKEN_FILE` and `KUBERNETES_CA_FILE` for
out-of-cluster). The broker needs RBAC to create/delete ServiceAccounts and
RoleBindings, create `serviceaccounts/token`, and `bind` the allowlisted
ClusterRoles — see the `agent-auth-provisioner` ClusterRole in `deploy/k8s.yaml`
(bind it per brokered namespace, or cluster-wide if your allowlist is broad).

Ceilings: `namespace_allowlist: ["*"]` is fine — containment comes from narrow
roles and human review, not from walling namespaces off (an agent with gitops
access reaches them anyway). Keep `role_allowlist` enumerated and prefer
purpose-built roles over `edit`/`admin`: it must match the ClusterRoles/Roles
the broker holds `bind` on, so a tight role means a tight grant *and* a tight
broker credential.

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
