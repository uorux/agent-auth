# agent-auth in Rust: operator's guide

The Rust port of agent-auth: the same broker, daemons and agent-side
programs as the Python in `../src`, with the same routes, MCP tools, CLI
commands, Discord cards and policy file, on PostgreSQL only. What it does is
in the top-level [README](../README.md); this file is how to build, configure,
run and deploy the Rust version, and how to move a Python deployment to it.

- [ARCHITECTURE.md](ARCHITECTURE.md): how the code is organised and the rules it follows.
- [DEVIATIONS.md](DEVIATIONS.md): every deliberate difference from the Python (read its
  Policy section before moving a policy file over).
- [UPSTREAM.md](UPSTREAM.md): which Python commit this tracks.

| binary | crate | what |
|---|---|---|
| `agent-auth-server` | broker | the broker: HTTP API, Discord bot, admin panel, OAuth server and remote MCP, daemon hub, scheduler |
| `agent-auth` | cli | agent and admin CLI |
| `agent-auth-mcp`, `agent-auth-mcp-bridge` | mcp | stdio MCP server for agents; bridge to an MCP server in the broker's catalog |
| `agent-auth-hostd`, `agent-auth-hostctl` | hostd | per-host daemon (hostexec, desktop prompts, lockdown) and its local control |
| `agent-auth-sandboxd`, `agent-auth-sandboxctl`, `agent-auth-sandbox-mcp` | sandboxd | the agent-VM daemon, its operator CLI, the MCP server agents in the VM use |

## Build

### With Nix (what ships)

`rust/flake.nix` is a flake of its own (the Python flake at the top level is
unchanged). From the repository root:

```sh
nix build ./rust#broker      # bin/agent-auth-server
nix build ./rust#hostd       # agent-auth-hostd, agent-auth-hostctl
nix build ./rust#sandboxd    # sandboxd, sandboxctl, sandbox-mcp and the client programs
nix build ./rust#client      # agent-auth, agent-auth-mcp, agent-auth-mcp-bridge
nix build ./rust#default     # all of the above
nix build ./rust#image       # the broker as an OCI image: docker load < result
```

Packages are built with [crane](https://github.com/ipetkov/crane) from
`Cargo.lock` (every crate fetched by its checksum, nothing resolved at build
time), with the pinned stable toolchain (Rust 1.99.0 from rust-overlay), the
release profile of `Cargo.toml` (overflow checks on, thin LTO) and
`SQLX_OFFLINE=true` (queries are checked against the committed `.sqlx`, no
database at build time). One dependency build is shared by every package
and check.

Systems: `x86_64-linux` and `aarch64-linux` get every package;
`aarch64-darwin` gets `hostd` and `client` (for a Mac running hostd). Only
x86_64-linux is built in CI; the others evaluate.

Checks (`nix flake check ./rust`, or one at a time with
`nix build ./rust#checks.x86_64-linux.<name>`):

| check | what |
|---|---|
| `rust-audit` | `scripts/audit.sh`: no `unsafe` anywhere, every crate root forbids it, human approvals only from human surfaces |
| `rust-fmt` | `cargo fmt --check` |
| `rust-clippy` | clippy on every target with the workspace's lints as errors (`-D warnings`) |
| `rust-tests` | every test, database tests and the e2e suite included, against a throwaway PostgreSQL started inside the build sandbox (but two sandboxd tests that need a NixOS host's `/run/current-system`); the nextest log is in the output |
| `module-eval` | evaluates a NixOS system with the three modules, checks the units' settings that matter and the assertions, and has the binaries parse the `hostd.json` / `sandboxd.json` the modules write |
| `module-darwin-eval` | the nix-darwin module against stub options, its `hostd.json` parsed too |
| `broker-vm` | a NixOS VM: PostgreSQL, the broker from the module, an agent made with the admin CLI taking a pool lease through to its credential, the single-instance lock, a restart, `systemd-analyze security` (1.1 OK). Runs without KVM too (QEMU TCG, a few minutes) |

`cargo deny` and the crates.io cooldown check need the network and stay in
`scripts/check.sh`.

### With cargo (development)

```sh
cd rust
nix develop                      # the pinned toolchain, sqlx-cli, postgres, nextest
cargo build --release --locked   # target/release/*
scripts/check.sh                 # everything a change must pass (needs the network for deny/cooldown)
```

## Configure

### The broker (`agent-auth-server`)

Environment variables (names case-insensitive; the process environment wins
over a `./.env` in the working directory, which the NixOS module and the
image make an empty or root-owned place). Unknown variables are ignored. A
value that does not parse stops the broker with the variable's name.

**Core**

| variable | default | |
|---|---|---|
| `DATABASE_URL` | (required) | `postgres://` or `postgresql://` only. TLS: `?sslmode=verify-full&sslrootcert=/path/ca.crt`; unix socket: `postgres://user@localhost/db?host=/run/postgresql`. The broker runs its migrations at start |
| `POLICY_FILE` | `policy.yaml` | the policy; missing or invalid stops the broker (the Python ran on defaults) |
| `POLICY_OVERLAYS` | (none) | comma-separated policy files merged over it in order (restricted zones' private policy); a missing one stops the broker |
| `LISTEN_HOST` | `0.0.0.0` | |
| `LISTEN_PORT` | `8400` | |
| `LOG_LEVEL` | `INFO` | a tracing filter: `info`, `debug`, `agent_auth_broker=debug,info` |
| `TRUST_PROXY_HEADERS` | `false` | believe `X-Real-IP` (a reverse proxy that sets it is in front): the security log, registration and handshake limits see the client |
| `REQUESTS_PER_AGENT_PER_HOUR` | `60` | new access requests per agent per hour (`0`: unlimited) |
| `MAX_WAITS_PER_AGENT` | `16` | concurrent decision long-polls per agent (`0`: unlimited) |

**Secrets and keys**

| variable | default | |
|---|---|---|
| `ADMIN_TOKEN` | (none: admin API answers 503) | bearer token of the admin API and `agent-auth admin` |
| `ENCRYPTION_KEY` | (none) | 32 bytes, base64 (`agent-auth admin gen-key`). Encrypts secrets at rest (ChaCha20-Poly1305, not Fernet: a Python key still parses, Python ciphertexts don't open). Needed by GitHub token caching, models, the panel, remote MCP, managed LLDAP accounts, VM key delivery, held mail |
| `BROKER_SIGNING_KEY` | (none: no daemons, no signed tokens) | the broker's ed25519 seed (`agent-auth admin gen-signing-key --out FILE`). Turns on the daemon channel (hostd, sandboxd) and the MCP token signer; `agent-auth admin broker-key` prints the public key the daemons pin. Keep the Python's to keep the daemons' pinned key and the JWKS `kid` |

**LLM reviewer**

| variable | default | |
|---|---|---|
| `OPENROUTER_API_KEY` | (none: `llm` routes go to a human) | |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | |

**Discord**

| variable | default | |
|---|---|---|
| `DISCORD_TOKEN` | (none: no bot, a warning) | |
| `DISCORD_CHANNEL_ID` | `0` | approvals |
| `DISCORD_OWNER_ID` | `0` | the one user whose clicks count |
| `DISCORD_LOUD_CHANNEL_ID` | the approvals channel | shell requests |
| `DISCORD_ACTIVITY_CHANNEL_ID` | the approvals channel | what needs no one |
| `DISCORD_API_URL` | `https://discord.com/api/v10` | new; tests point it at a fake |
| `DISCORD_GATEWAY_URL` | `wss://gateway.discord.gg` | new; likewise |

**GitHub**

| variable | default | |
|---|---|---|
| `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID` | (none: platform off) | |
| `GITHUB_APP_PRIVATE_KEY_FILE` | (none) | the App's PEM (a `LoadCredential` path or a mounted Secret) |
| `GITHUB_API_URL` | `https://api.github.com` | |

**LLDAP (`homelab`)**

| variable | default | |
|---|---|---|
| `LLDAP_URL` | (none: platform off) | the GraphQL API, `http(s)://host:17170` |
| `LLDAP_ADMIN_USER`, `LLDAP_ADMIN_PASSWORD` | (none) | |
| `LLDAP_LDAP_URL` | (none) | **new**: LDAP interface for setting managed accounts' passwords (`ldaps://host:6360`, or `ldap://host:3890`). Replaces `lldap_set_password`, whose command line exposed the admin token |
| `LLDAP_BASE_DN` | (none) | **new**: `dc=example,dc=com` |
| `LLDAP_LDAP_ALLOW_PLAINTEXT` | `false` | **new**: allow `ldap://` to a non-loopback host (the admin password crosses in the clear) |
| `LLDAP_SET_PASSWORD_BIN` | | **ignored** (a warning) |

Managed accounts need `ENCRYPTION_KEY`, `LLDAP_LDAP_URL` and `LLDAP_BASE_DN`.

**Kubernetes**

| variable | default | |
|---|---|---|
| `KUBERNETES_API_URL` | (none: platform off) | `in-cluster`, or comma-separated API servers (tried in turn) |
| `KUBERNETES_TOKEN_FILE` | in-cluster: the pod's token | read at every call (rotation is picked up) |
| `KUBERNETES_TOKEN` | (none) | a fixed token; the file wins |
| `KUBERNETES_CA_FILE` | in-cluster: the pod's CA | otherwise the shared root store |
| `KUBERNETES_INSECURE_SKIP_VERIFY` | `false` | a warning at start |
| `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT` | `kubernetes.default.svc`, `443` | in-cluster only (the kubelet sets them) |

Every grant's ServiceAccount is made in the policy's
`platforms.kubernetes.grant_namespace` (default `agent-auth-grants`), which
must exist; see [Kubernetes](#kubernetes) for the RBAC.

**Model gateway, mail, a2a, daemons**

| variable | default | |
|---|---|---|
| `LITELLM_MASTER_KEY` | (none: `models` off) | |
| `MAIL_CA_FILE` | (none) | **new**: an extra CA (PEM) for private IMAP/SMTP servers; mail trusts the shared root store, not the system's |
| `GMAIL_API_URL` | Google's | **new**; tests point it at a fake |
| `A2A_RELAY_ENABLED` | `true` | |
| `A2A_OPEN_TIMEOUT_SECS` | `600` | |
| `A2A_THREAD_IDLE_TIMEOUT_SECS` | `3600` | |
| `SESSION_IDLE_TIMEOUT_SECS` | `900` | |
| `LIVENESS_THRESHOLD_SECS` | `120` | |
| `A2A_LISTEN_THRESHOLD_SECS` | `300` | |
| `A2A_MAX_SESSIONS_PER_AGENT` | `64` | **new** |
| `A2A_MAX_MESSAGES_PER_THREAD` | `1000` | **new** |
| `A2A_MAX_LONG_POLLS_PER_AGENT` | `8` | **new** |
| `A2A_WEBHOOK_HTTP_HOSTS` | (none) | **new**: hosts webhooks may reach over plain `http` (otherwise https only) |
| `WEBHOOK_SIGNING_SECRET` | | **ignored** (a warning): each agent's own webhook secret signs its pings, with a timestamp |
| `DAEMON_HEARTBEAT_SECS` | `30` | |
| `DAEMON_PAIRING_CODE_TTL_SECS` | `600` | |
| `DAEMON_PAIRING_MAX_ATTEMPTS` | `5` | |
| `REMOTE_MCP_LOOPBACK_URL` | | **no longer read**: remote MCP tools call the API in process |

Everything else (GitHub ceilings, Google accounts, mailboxes, pools, MCP
servers, the panel's sign-in, remote MCP) is in the policy file; secrets
the policy points at are files (`secret_file`, `client_secret_file`,
`password_file`, ...), passed with `LoadCredential` or mounted Secrets.

TLS: every outbound connection (HTTP, Discord's gateway, IMAP/SMTP, LDAP,
Postgres) trusts Mozilla's roots minus the distrusted ones, built in; the
system's CA bundle is never read. A private CA goes in `KUBERNETES_CA_FILE`,
`MAIL_CA_FILE` or the Postgres URL's `sslrootcert`.

### Policy

The policy file is the Python's format, read more strictly. The changes that
can stop an existing policy from loading (DEVIATIONS.md, Policy, Provisioners,
Admin panel):

- unknown keys are errors everywhere (a typo used to be ignored); duplicate
  YAML keys, unknown tags, lax types (`"3"` for a number, `yes` for a
  boolean) are refused;
- `remote_mcp.redirect_hosts` is gone: `remote_mcp.redirect_uris` lists exact
  callback URIs (defaults: Claude's and ChatGPT's);
- hostexec template parameter patterns are Rust regexes (no backreferences
  or lookaround) and must compile; durations are at most 365 days, never 0;
- GitHub `permission_ceiling` values must be read/write/admin; two MCP
  servers may not share an audience.

And what changes in meaning: `platforms.kubernetes.grant_namespace` (new,
default `agent-auth-grants`) holds every grant's ServiceAccount; LLDAP
administration groups are never brokered; the default never clears a
delegated request; mail and pool sections are checked at load.

### hostd (`agent-auth-hostd`)

One JSON file, written by the NixOS or nix-darwin module
(`/etc/agent-auth/hostd.json`, `AGENT_AUTH_HOSTD_CONFIG`). Unknown keys and
wrong types are refused (the Python was lenient). Keys:
`broker_url`, `broker_public_key`, `name`, `state_dir`, `runtime_dir`,
`user`, `tiers.{user,root}.{enable,max_arm,accept_approve_all,accept_machine_approvals,shell.{enable,max_duration}}`,
`auto_commands`, `deny_commands`, `templates.<name>.{tier,argv,params,description,cwd,env,stdin}`,
`env_allow`, `vm_unit`, `job_path`, `default_timeout`, `max_timeout`,
`systemd_run`, `systemctl`, `qrencode`, `pkcheck`, and `desktop.*`.
Environment: `LOG_LEVEL` (default `info`); without a config file,
`AGENT_AUTH_HOSTD_BROKER_URL`, `AGENT_AUTH_HOSTD_BROKER_KEY`,
`AGENT_AUTH_HOSTD_NAME`, `AGENT_AUTH_HOSTD_STATE_DIR` make a connect-only
config; `AGENT_AUTH_HOSTD_PAIRING_CODE` for `pair`; `AGENT_AUTH_HOSTD_CTL`
(hostctl's socket).

TOTP secrets: `totp-enroll` makes the four of the Python (`user-arm`,
`user-direct`, `root-arm`, `root-direct`). Three optional ones are new
(`totp-enroll --add <name>`): `root-shell` (a root shell needs it),
`root-unlock` (unlocking from the broker needs it; otherwise unlock locally
with hostctl), `user-shell` (if enrolled, user shells take it instead of
the direct code). Five wrong codes lock a secret for escalating periods; 20
in 30 days lock it until `sudo agent-auth-hostctl totp-unlock NAME`.

### sandboxd (`agent-auth-sandboxd`)

One JSON file from the NixOS module (`/etc/agent-auth/sandboxd.json`,
`AGENT_AUTH_SANDBOXD_CONFIG`), strict as hostd's. New keys:
`refuse_vm_logins_when_unreachable` (default true: no agent process on the
VM's own logins while the broker can't be reached), `codex_auth_owner`
(the one project whose codex login is written back),
`max_processes_per_project` (now enforced), `interactive_idle_secs`; see
`crates/sandboxd/src/config.rs` for the rest (`triage*`, `unit_tasks_max`,
`uid_base`/`uid_max`). The VM's `name` has no `-`, and sandboxd refuses
to run unless `fs.protected_hardlinks` is 1. State is JSON documents in `/var/lib/sandboxd` (no
SQLite). Environment: `LOG_LEVEL`, `AGENT_AUTH_SANDBOXD_PAIRING_CODE`,
`AGENT_AUTH_SANDBOXD_OPERATOR` (sandboxctl's socket); agents' units get
`AGENT_AUTH_SANDBOX_SOCKET` and `AGENT_AUTH_SANDBOX_TOKEN`.

### Agent-side programs

`AGENT_AUTH_URL` (must be `https://` unless loopback: the key is never sent
over plain http), `AGENT_AUTH_API_KEY`, `AGENT_AUTH_SESSION`,
`AGENT_AUTH_ADMIN_TOKEN` (admin commands), `AGENT_AUTH_WEBHOOK_SECRET`
(`a2a serve`). Same as the Python.

## Run

```sh
# The broker
DATABASE_URL=postgres://... POLICY_FILE=policy.yaml ADMIN_TOKEN=... ENCRYPTION_KEY=... \
  agent-auth-server
curl -s localhost:8400/healthz          # {"ok":true}: unauthenticated, says nothing else

# Agents and the operator
agent-auth admin agent-create my-agent --kind ephemeral   # prints the API key once
AGENT_AUTH_API_KEY=... agent-auth request github repo me/repo --why "..." --wait

# A host
agent-auth admin daemon-pair myhost                       # on the operator's side
sudo agent-auth-hostd pair                                # on the host (prompts for the code)
sudo agent-auth-hostd totp-enroll                         # once (QR codes, shown once)
sudo agent-auth-hostd totp-enroll --add root-shell        # optional secrets
agent-auth-hostd run                                      # the service
agent-auth-hostctl status | presence idle | dnd 2h | totp-unlock NAME

# An agent VM
agent-auth admin daemon-pair --role sandbox myhost
agent-auth-sandboxd pair                                  # in the guest
agent-auth-sandboxd run
```

Exactly one broker per database: it holds a session-level advisory lock for
its whole life, and a second broker on the same database logs why and
exits. On SIGTERM open requests get 10 s, LLM evaluations 10 s more, then it
exits. Anything that restarts it must stop the old one first (systemd does;
on Kubernetes, `strategy: Recreate`).

## Deploy

### NixOS

```nix
inputs.agent-auth-rs.url = "github:uorux/agent-auth?dir=rust";   # or git+https://...?dir=rust

imports = [
  inputs.agent-auth-rs.nixosModules.broker     # = .default
  inputs.agent-auth-rs.nixosModules.hostd
];
# inside an agent VM's guest: inputs.agent-auth-rs.nixosModules.sandboxd
# on a Mac (nix-darwin):      inputs.agent-auth-rs.darwinModules.hostd
```

The modules keep the Python modules' service and option names
(`services.agent-auth`, `services.agent-auth-hostd`,
`services.agent-auth-sandboxd`, same options), so a host switches by
importing these instead of the Python flake's (never both). What differs:

- **broker**: `database.createLocally` (new, default `true`) runs PostgreSQL
  on the host with a database and role `agent-auth`, reached over the unix
  socket with peer authentication (no password); set it `false` and put
  `DATABASE_URL` in an environment file to use another server. No state
  directory (the Python's `/var/lib/private/agent-auth` SQLite is not
  read; persist `/var/lib/postgresql` instead on impermanence hosts). An
  assertion refuses Nix path literals in `environmentFiles` (they would be
  copied into the world-readable store) and secrets in `settings`. The
  sandbox is stricter than the Python unit's: W^X memory, a private user
  namespace, `ProcSubset=pid`, `~@resources`, `LimitNOFILE=65536`.
- **hostd**: templates take `description`, `cwd`, `env`, `stdin` (pinned:
  a request for the template may not set them). The unprivileged unit no
  longer sets `ProtectProc=invisible`: hostd reads a local peer's
  `/proc/<pid>/cgroup` to refuse callers inside a job's unit and refuses
  peers it cannot place, so other users' processes must be visible to it.
  `LimitNOFILE=65536`, W^X memory. The desktop helper's unit gets
  util-linux (`kill`) on its PATH.
- **sandboxd**: `/run/sandboxd` and `/run/sandboxd-agent` are created
  root-only (the Python module made them `0755`) and sandboxd sets their
  modes itself (`0711` with `env/`, the conversations' broker tokens,
  `0700`; the agents' socket directory `0755`). `hostName` has no `-`.
  New options `max_processes_per_project`, `interactive_idle_secs`,
  `codex_auth_owner`, `refuse_vm_logins_when_unreachable`, `extraConfig`
  (any other config key); `orchestratorRuntime` must be `claude` or
  `codex` and present in `runtimes`; `fs.protected_hardlinks = 1`.

```nix
services.agent-auth = {
  enable = true;
  policyFile = ./agent-auth-policy.yaml;                       # → the nix store, immutable
  policyOverlays = [ config.sops.secrets."agent-auth/policy-private".path ];
  environmentFiles = [ config.sops.secrets."agent-auth/env".path ];   # a string path
  loadCredentials = [ "github-pem:${config.sops.secrets."agent-auth/github-pem".path}" ];
  settings = {
    GITHUB_APP_PRIVATE_KEY_FILE = "/run/credentials/agent-auth.service/github-pem";
    LLDAP_LDAP_URL = "ldaps://lldap.example:6360";
    LLDAP_BASE_DN = "dc=example,dc=com";
  };
};
```

### Container image

`nix build ./rust#image` makes `agent-auth:<version>`: the broker binary and
its runtime closure (glibc, libgcc) only: no shell, no package manager, no CA
bundle (not read). It runs as uid/gid 65532, works with a read-only root
filesystem (mount an emptyDir at `/tmp`), listens on 8400, and reads
`POLICY_FILE=/etc/agent-auth/policy.yaml` unless told otherwise. There is no
`HEALTHCHECK` (nothing in the image could run one); probe `GET /healthz`
over HTTP.

### Kubernetes

`rust/deploy/k8s/` is a kustomization laid out like the homelab repo's apps
(copy it to `apps/infra/agent-auth/`, replacing what is there). Before the
first sync:

1. **Database.** Add the role to the CNPG Cluster's managed roles
   (`apps/infra/postgres/cluster.yaml`; the snippet is in `postgres.yaml`),
   and create the 1Password item `agent-auth-postgres` (`username`
   `agent-auth`, a URL-safe `password`). `postgres.yaml` makes the Database
   and the Secret in both namespaces.
2. **The CNPG CA**, as ConfigMap `cnpg-ca` in `agent-auth` (public data; the
   broker connects with `sslmode=verify-full` to
   `postgres-rw.cnpg.svc.cluster.local`):
   `kubectl -n cnpg get secret postgres-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt && kubectl -n agent-auth create configmap cnpg-ca --from-file=ca.crt`.
   CNPG renews its self-made CA; when it does, refresh this ConfigMap (or
   give the Cluster a cert-manager CA through `spec.certificates` and copy
   that CA's certificate instead).
3. **Secrets**: the 1Password items in `secrets.yaml` (`agent-auth-env`
   with one field per variable above, `agent-auth-github-key` with
   `app.pem`, `agent-auth-policy-private` with `policy-private.yaml`).
4. **Policy**: replace `policy.yaml` (a ConfigMap whose name changes with
   its content, so a change rolls the pod). Keep
   `platforms.kubernetes.grant_namespace: agent-auth-grants`, and the
   role lists in step with `rbac.yaml`, `components/cluster-grants` and the
   `clusterRoles` of `admission-policy.yaml`.
5. **Image**: `nix build ./rust#image`, push it, and set `images:` in
   `kustomization.yaml` (pin a digest).
6. Kubernetes 1.30 or later (ValidatingAdmissionPolicy), and Cilium for
   `networkpolicy-cilium.yaml` (the API server's entity; without Cilium
   replace it with an ipBlock rule).

What is in it:

- `deployment.yaml`: one replica, `strategy: Recreate` (the advisory lock),
  non-root (65532), read-only root filesystem, all capabilities dropped,
  seccomp `RuntimeDefault`, resource requests and limits, startup /
  readiness / liveness probes on `/healthz`, a 40 s grace period.
  `DATABASE_URL` is assembled from the CNPG role's Secret.
- `rbac.yaml`, `roles.yaml`, `components/`: the broker's ServiceAccount.
  ServiceAccounts and their tokens only in `agent-auth-grants` (a Role, not
  a ClusterRole); RoleBindings, with `bind` on exactly the allowlisted
  roles, in the namespaces a component grants: `components/namespaces` (one
  RoleBinding per namespace), `components/all-namespaces` (`*`, and the
  namespace list restricted zones need), `components/cluster-grants`
  (ClusterRoleBindings of the cluster allowlist). The homelab's policy today
  needs the last two. `roles.yaml` is the narrow role library the broker
  hands out.
- `admission-policy.yaml`: a ValidatingAdmissionPolicy on the broker's own
  requests (upstream review 2026-10): every object it creates or deletes and
  every token it requests is named `aa-*`; ServiceAccounts only in the grant
  namespace; a binding binds a ClusterRole to exactly the grant's own
  ServiceAccount there; a ClusterRoleBinding only a cluster-allowlisted
  role; no updates. So even its own credential cannot mint a token for
  another ServiceAccount or bind an allowlisted role to anything else.
- `namespace.yaml`: `agent-auth` and `agent-auth-grants` (restricted pod
  security; a quota of zero pods in the grant namespace, so nobody can run
  a pod as a grant's ServiceAccount).
- `networkpolicy.yaml`: in from Traefik only; out to DNS, the CNPG cluster,
  LLDAP, Traefik (services reached by their public names) and the public
  internet on 443/993/465/587 (no private ranges).
- `service.yaml`, `ingress.yaml` (Traefik IngressRoute, the wildcard cert).

These were checked with `kubectl kustomize` and `kubeconform -strict`
(CRDs from the datree catalog), and the RBAC and admission policy against a
real kube-apiserver: by impersonation, and with the broker's own
provisioner making, using and releasing a namespaced and a cluster-wide
grant.

Where the broker runs is a security decision, not only an operational one:
on Kubernetes, whoever can write the gitops repo (or push the image) decides
the broker's policy and RBAC. Give no brokered agent write access to those,
or to the Flux objects (`flux-reconciler` only asks Flux to reconcile).
The broker can also stay on a NixOS host and broker the cluster from
outside: apply the same RBAC and admission policy (the ServiceAccount's
long-lived token as `KUBERNETES_TOKEN_FILE`).

## Migrating from the Python deployment

Nothing carries over in the database: the Rust broker starts on a new,
empty PostgreSQL database (its own schema; it never reads the Python's
SQLite or Postgres tables). Plan a short cutover:

1. **Drain the Python broker.** Let active grants end or revoke them
   (`agent-auth admin revoke <grant>`): what it provisioned (Kubernetes
   ServiceAccounts and bindings labelled `app.kubernetes.io/managed-by:
   agent-auth`, LiteLLM keys, LLDAP memberships) is unknown to the new
   broker and would otherwise stay. Check with
   `kubectl get sa,rolebinding,clusterrolebinding -A -l app.kubernetes.io/managed-by=agent-auth`.
   Then stop it.
2. **Keep the keys.** Reuse `BROKER_SIGNING_KEY` (the daemons' pinned
   `brokerPublicKey`, the JWKS and its `kid` stay the same) and
   `ADMIN_TOKEN`; `ENCRYPTION_KEY` may stay (same shape), though nothing
   encrypted by the Python is read.
3. **Fix the policy** for the stricter loader (above; DEVIATIONS.md).
   Start the Rust broker once against it: it refuses a policy it cannot
   load, naming the key.
4. **Start the Rust broker** on the new database (NixOS: import the Rust
   modules, `database.createLocally`; Kubernetes: the steps above).
5. **Re-register agents**: `agent-auth admin agent-create <name>` for each
   (with `--lldap-username` for hand-registered LLDAP accounts,
   `--webhook-url` for service agents), and give each its new API key.
   Broker-managed LLDAP accounts (`svc-<name>`, display name
   `<agent> (agent-auth managed)`) are adopted again at the agent's next
   homelab grant. Webhook receivers must check the new timestamped
   signature (top-level README, "Verifying webhook pings").
6. **Re-pair the daemons**: the new database knows no daemon. On each host,
   switch its module to the Rust one, then `agent-auth admin daemon-pair
   <host>` and `sudo agent-auth-hostd pair`. hostd's state directory carries
   over as is (the identity key, the TOTP secrets and their state are in
   the Python's formats), so the authenticator entries stay valid; enroll
   the new optional secrets if wanted (`sudo agent-auth-hostd totp-enroll
   --add root-shell`: root shells now need it; `--add root-unlock`: remote
   unlock now needs it). Agent VMs: `daemon-pair --role sandbox <host>`,
   then `agent-auth-sandboxd pair` in the guest; sandboxd's state is new
   (JSON documents instead of SQLite), so the VM's agents are minted again
   by its orchestrator.
7. **Reconnect web UIs**: remote MCP connectors (claude.ai, ChatGPT) and
   panel sessions start over; the connector is authorized again from its
   settings.
8. Saved rules ("approve all like this") and the audit history stay in
   the old database; recreate the rules you want.
