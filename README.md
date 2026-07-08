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
| `a2a`     | `talk`        | target agent name   | check-based: `GET /v1/a2a/check`, plus optional relay `POST /v1/a2a/send` → webhook or inbox |
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

- **HTTP**: `Authorization: Bearer aa_...` against `/v1/...` (OpenAPI at `/docs`).
- **MCP** (recommended for agents): stdio server with tool docs written for LLMs —
  ```json
  {"mcpServers": {"agent-auth": {
      "command": "agent-auth-mcp",
      "env": {"AGENT_AUTH_URL": "https://auth.rooty.dev", "AGENT_AUTH_API_KEY": "aa_..."}}}}
  ```
  Tools: `list_capabilities`, `request_access`, `wait_for_decision`,
  `retry_request`, `escalate_request`, `get_credential`, `list_grants`,
  `check_a2a`, `a2a_send`, `a2a_inbox`, `a2a_ack`.
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

## Policy

See `policy.example.yaml`. Evaluation order: platform validator (hard ceilings) →
saved rules from Discord's **Edit** modal (newest first) → YAML rules (first match)
→ default. Approved duration is always `min(requested, rule cap, default cap)`.

The Discord **Edit** button opens a modal to adjust duration/resource/scope before
approving, and its *Rule* field persists a rule for future identical requests:
`approve`, `approve:capability` (any resource), `approve:platform`, or `deny:*`
variants. Manage saved rules with `agent-auth admin rules` / `rule-delete`.

LLM review calls OpenRouter with a structured verdict schema; the model is set
per-rule (`constraints.llm_model`) or globally (`llm.model`). Evaluator errors
always escalate to a human — never auto-approve.

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
`deploy/k8s.yaml` ships two examples — `traefik-patcher` (`get`+`patch` on the
one named `traefik` deployment) and `logs-reader` (read pods + logs) — and the
policy auto-approves them while surfacing `edit`/`admin`. To add your own:

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
```

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
