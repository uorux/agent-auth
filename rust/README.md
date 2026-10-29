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
| `DATABASE_URL` | (required) | `postgres://` or `postgresql://` only. A server other than this machine needs `?sslmode=verify-full` (with `&sslrootcert=/path/ca.crt` for a private CA); a unix socket (`postgres://user@localhost/db?host=/run/postgresql`) or localhost needs nothing. The broker runs its migrations at start |
| `DATABASE_ALLOW_INSECURE` | `false` | development only: allow a remote database without verified TLS (a loud warning) |
| `POLICY_FILE` | `policy.yaml` | the policy; missing or invalid stops the broker (the Python ran on defaults) |
| `POLICY_OVERLAYS` | (none) | comma-separated policy files merged over it in order (restricted zones' private policy); a missing one stops the broker |
| `LISTEN_HOST` | `0.0.0.0` | |
| `LISTEN_PORT` | `8400` | |
| `LOG_LEVEL` | `INFO` | a tracing filter: `info`, `debug`, `agent_auth_broker=debug,info` |
| `TRUST_PROXY_HEADERS` | `false` | believe `X-Real-IP` (a reverse proxy that sets it is in front): the security log, registration and handshake limits see the client |
| `REQUESTS_PER_AGENT_PER_HOUR` | `600` | new access requests per agent per hour (`0`: unlimited) |
| `MAX_WAITS_PER_AGENT` | `16` | concurrent decision long-polls per agent (`0`: unlimited) |

**Secrets and keys**

| variable | default | |
|---|---|---|
| `ADMIN_TOKEN` | (none: admin API answers 503) | bearer token of the admin API and `agent-auth admin`; at least 32 characters |
| `PLAINTEXT_HTTP_HOSTS` | (empty) | comma-separated exact host names that outbound URL settings may reach over plain `http://`/`ws://`/`ldap://` (an in-cluster service without TLS); each is logged at start. Every other outbound URL must be `https://`/`wss://`/`ldaps://`, or plain text to localhost |
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
| `LLDAP_URL` | (none: platform off) | the GraphQL API: `https://host:17170`, or `http://host:17170` with the host listed in `PLAINTEXT_HTTP_HOSTS` |
| `LLDAP_ADMIN_USER`, `LLDAP_ADMIN_PASSWORD` | (none) | |
| `LLDAP_LDAP_URL` | (none) | **new**: LDAP interface for setting managed accounts' passwords (`ldaps://host:6360`, or `ldap://host:3890`). Replaces `lldap_set_password`, whose command line exposed the admin token |
| `LLDAP_BASE_DN` | (none) | **new**: `dc=example,dc=com` |
| `LLDAP_LDAP_ALLOW_PLAINTEXT` | `false` | **new**: allow `ldap://` to a non-loopback host (the admin password crosses in the clear); the host must also be in `PLAINTEXT_HTTP_HOSTS` |
| `LLDAP_SET_PASSWORD_BIN` | | **ignored** (a warning) |

Managed accounts need `ENCRYPTION_KEY`, `LLDAP_LDAP_URL` and `LLDAP_BASE_DN`.

**Kubernetes**

| variable | default | |
|---|---|---|
| `KUBERNETES_API_URL` | (none: platform off) | `in-cluster`, or comma-separated API servers (tried in turn) |
| `KUBERNETES_TOKEN_FILE` | in-cluster: the pod's token | read at every call (rotation is picked up) |
| `KUBERNETES_TOKEN` | (none) | a fixed token; the file wins |
| `KUBERNETES_CA_FILE` | in-cluster: the pod's CA | the only CA trusted for the API server (the public roots are not); unset outside the cluster: the shared root store |
| `KUBERNETES_INSECURE_SKIP_VERIFY` | `false` | only for an API on localhost (refused otherwise) |
| `KUBERNETES_AGENT_API_URL` | the API URLs above | comma-separated `https://` API servers as agents reach them (in-cluster, the broker's own are not) |
| `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT` | `kubernetes.default.svc`, `443` | in-cluster only (the kubelet sets them) |

A `kubernetes_token` credential carries what a client needs to verify the
API server: `url` (the preferred server), and in `properties` every server
(`servers`), the grant's `namespace`, `tls` (`ca`, `public_roots` or
`insecure`) and, with a CA, `certificate_authority_pem` and
`certificate_authority_data` (base64, as kubeconfig takes it). An insecure
broker has no CA to give and says so. The CA is not secret. With
`to_file=True` the MCP server writes a whole kubeconfig (0600: servers, CA,
namespace, token) and answers with its path and
`KUBECONFIG=<file> kubectl …`, so the token stays off command lines.

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
system's CA bundle is never read. A private CA goes in `KUBERNETES_CA_FILE`
(it then replaces the public roots for the API server), `MAIL_CA_FILE`
(added to them: mail also reaches Gmail and SimpleLogin) or the Postgres
URL's `sslrootcert` (sqlx adds it to its own public roots).

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
(`totp-enroll --add <name>`): `user-shell`, `root-shell` (if enrolled,
that tier's shells take it instead of the tier's arm code; a direct code
never opens a shell), `root-unlock` (unlocking from the broker needs it;
otherwise unlock locally with hostctl). A shell can also be approved at its
own host's desk (`desktop.approve` for its tier), with the user's password
through polkit whatever the tier. Five wrong codes lock a secret for
escalating periods; 20 in 30 days lock it until
`sudo agent-auth-hostctl totp-unlock NAME`.

### Shell modes

A shell request's scope may name a `mode` (the agent picks it; the approval
card shows it under "Checks", and approving approves that mode; every mode
still needs your TOTP code to open the shell on the host, and every command
is still shown in the shell's thread before it runs):

| mode | before a command runs | after it starts |
|---|---|---|
| `watched` (default) | shown to you | the watcher alerts on danger or off-purpose work (with `platforms.hostexec.watch`) |
| `general` | shown to you | the watcher alerts on danger only: for catch-all shells |
| `guarded` | a guard model checks it against the justification and refuses what doesn't serve it | — |
| `umbrella` | the agent opens scoped shells (`host_shell_scope`), each purpose checked against the justification (the umbrella's concept); commands run only in a scope, guarded against its purpose | — |

The guard and the scope check use `platforms.hostexec.risk_model` (default
`llm.model`) through OpenRouter: without `OPENROUTER_API_KEY` a guarded or
umbrella shell is refused at request time, and when the model can't be
reached a command (or scope) is refused, never let through. Refusals are
posted in the shell's thread (an alarming one pings you, and your desk).
An alarming refusal, or five refusals in all, ends the shell: the agent has
to ask you for a new one. A guarded shell's commands may set only LANG,
LC_*, TZ and TERM in their environment. hostd knows
nothing of modes: an umbrella is one host shell, and its scopes live in the
broker.

### Evals

Every decision a model makes for the broker is recorded: the request
reviewer, the risk line, the mail judge (both ways), the shell guard, the
scope check and the shell watchers. Each record keeps what the prompt was
built from (the facts), the exact system and user messages, the model's
answer, the decision class it means, and what it was about. Label the ones
you have an opinion on, then replay them with another model, system prompt
or context setting and compare:

```sh
agent-auth admin evals kinds                     # classes, context settings, current prompts
agent-auth admin evals calls --kind shell_guard --unlabeled
agent-auth admin evals show <call-id>            # facts, prompts, answer
agent-auth admin evals label <call-id> odd --note "curl isn't part of a rebuild"
agent-auth admin evals replay --kind shell_guard --labeled \
    --model deepseek/deepseek-v4.1-flash-1017 --system-file guard.txt \
    --context '{"history_items": 10}' --wait
agent-auth admin evals runs
```

A replay reports, over the labelled calls, how many it got right next to
how many the original calls did, a confusion table, and every case whose
class changed. Labels are a class of the kind (`approve`, `odd`,
`in_scope/none`, ...; `*` for any part between `/`, e.g. `in_scope/*`).
Some labels come by themselves (source `outcome`): when you decide a
request the reviewer saw, your decision labels its last review; when you
release a held outgoing mail, its review is labelled `send`. Yours always
win over those.

From Discord: a message that reports a model's decision (a guard's
refusal, a watcher's alert, a scoped shell opened or refused, the LLM
reviewer's approval in the activity channel) has a **Wrong call** button.
It asks what the decision should have been (prefilled with the other side:
`fine` for a refusal or an alert) and an optional note, and labels the
record; **Undo** takes it back. `/review` lists the latest decisions that
went against an agent or pinged you and that you haven't labelled (an LLM
denial goes to the agent, not to Discord: find it there), each with its
own button; `kind:` narrows it, `everything:True` adds the ones that let
things through. A label never changes what was decided. Mail decisions
show no reason there (their records are sealed).

Replays only read records and write their own results: no request, grant,
command or mail is touched. They call the model gateway (cost: one call per
replayed decision). Policy:

```yaml
evals:
  record: true            # default
  retention: 90d          # unlabelled calls and replays older than this are forgotten
  replay_concurrency: 4
  max_replay: 500         # calls one replay takes at most
```

Records hold what the models saw: agents' justifications and commands
(with their stdin and env), mail an outsider sent, drafts. Mail's records
are sealed with `ENCRYPTION_KEY`, like the held mail itself (without the
key, mail decisions are not recorded); the rest sits in the database next
to the same data (`host_jobs`, requests). Calls you labelled are kept until
you unlabel them; everything else goes after `retention`. Set
`record: false` to keep none. One replay runs at a time.

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
sudo agent-auth-hostd totp-enroll --add root-unlock       # optional secrets
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
  copied into the world-readable store) and secrets in `settings`
  (names compared case-insensitively, as the broker reads them; anything
  named `*_TOKEN`, `*_KEY`, `*_PASSWORD`, `*_SECRET`; a `DATABASE_URL` with
  a password), and `settings` names must be upper-case. The
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

### Releasing an image

Built by GitHub Actions from a signed version tag, and pinned only after a
second, local build agrees (`.github/workflows/image.yml`):

1. Set `workspace.package.version` in `rust/Cargo.toml` (the image's own
   `agent-auth:<version>`), commit, and tag that commit with a **signed**
   annotated tag: `git tag -s v<version> -m v<version>`, then
   `git push origin v<version>`. Anyone who can push could push a tag; only
   a signature by an operator key gets an image pinned.
2. The workflow builds `./rust#image` on a GitHub-hosted runner,
   substituting from cache.nixos.org only, pushes
   `ghcr.io/uorux/agent-auth:v<version>`, attests its build provenance,
   and lists the manifest and config digests in the run's summary.
3. In the deploying repository, `scripts/verify-image.sh` checks the tag's
   signature against its allowed signers, rebuilds the tagged commit
   locally (cache.nixos.org only), compares the config digest with the
   registry's, and prints `ghcr.io/uorux/agent-auth:v<version>@sha256:…`
   to pin. The image is reproducible: two builds of a commit have the same
   config digest (the manifest digest can differ by layer compression, so
   the config is what's compared).
4. Pin that digest in a signed commit there. The first push leaves the
   package private on ghcr.io: make it public once (package settings) so
   nodes pull it without a token.

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
5. **Image**: a released, verified image ("Releasing an image"), its
   digest pinned in `images:` in `kustomization.yaml`.
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

The Rust broker runs on a new PostgreSQL database (its own schema; it never
reads the Python's SQLite or Postgres tables). `agent-auth-server
import-python` carries over the host pairings and the agents with their API
keys; nothing else. Plan a short cutover:

1. **Drain the Python broker.** Let active grants end or revoke them
   (`agent-auth admin revoke <grant>`): what it provisioned (Kubernetes
   ServiceAccounts and bindings labelled `app.kubernetes.io/managed-by:
   agent-auth`, LiteLLM keys, LLDAP memberships) is unknown to the new
   broker and would otherwise stay. Check with
   `kubectl get sa,rolebinding,clusterrolebinding -A -l app.kubernetes.io/managed-by=agent-auth`.
   Then stop it.
2. **Keep the keys.** Reuse `BROKER_SIGNING_KEY`: the daemons pin its
   public key (`brokerPublicKey`), so with another one every daemon fails
   at the welcome; the JWKS and its `kid` stay the same too. Reuse
   `ADMIN_TOKEN`; `ENCRYPTION_KEY` may stay (same shape), though nothing
   encrypted by the Python is read.
3. **Fix the policy** for the stricter loader (above; DEVIATIONS.md), and
   **start the Rust broker** on the new database (NixOS: import the Rust
   modules, `database.createLocally`; Kubernetes: the steps above). It
   refuses a policy it cannot load, naming the key. Register no agent and
   pair no daemon yet: the import wants an empty database.
4. **Export** on the old host, as root, the Python broker stopped. The
   file holds API key hashes and webhook secrets: keep it on tmpfs, copy it
   over ssh, delete it after the import (both copies).

   ```sh
   umask 077; d=$(mktemp -d /dev/shm/agent-auth.XXXXXX)
   cp /var/lib/private/agent-auth/agent-auth.db* "$d"/   # with any -wal: the live file is not touched
   nix shell nixpkgs#sqlite -c sqlite3 "$d/agent-auth.db" > /dev/shm/agent-auth-export.json <<'SQL'
   SELECT json_object('format', 'agent-auth-python-export/1',
     'agents', json((SELECT json_group_array(json_object(
       'id', id, 'name', name, 'description', description, 'key_id', key_id,
       'api_key_hash', api_key_hash, 'webhook_url', webhook_url,
       'webhook_secret', webhook_secret, 'lldap_username', lldap_username,
       'lldap_managed', lldap_password_encrypted IS NOT NULL, 'disabled', disabled,
       'kind', kind, 'last_seen_at', last_seen_at, 'last_listen_at', last_listen_at,
       'parent_agent_id', parent_agent_id, 'sandbox_id', sandbox_id,
       'runtime', runtime, 'project', project, 'host', host, 'placement', placement,
       'lease_expires_at', lease_expires_at, 'created_at', created_at)) FROM agents)),
     'daemons', json((SELECT json_group_array(json_object(
       'id', id, 'role', role, 'name', name, 'public_key', public_key,
       'paired_at', paired_at, 'last_seen_at', last_seen_at,
       'created_at', created_at)) FROM daemons)));
   SQL
   rm -r "$d"
   ```

   (The path is the Python module's default, `DynamicUser` +
   `StateDirectory`; the LLDAP password ciphertexts are not exported, only
   whether there is one.)
5. **Import**, with the broker's own `DATABASE_URL`, first with
   `--dry-run` (checks every row and prints what would be carried, what
   stays behind and why, and warnings; never opens the database), then
   without. One transaction: a bad row aborts it all, naming the row. The
   export is read from a file or from stdin (`-`):

   ```sh
   # Kubernetes (the image has no shell; the pod has DATABASE_URL):
   kubectl -n agent-auth exec -i deploy/agent-auth -- /bin/agent-auth-server import-python --dry-run - < agent-auth-export.json
   # NixOS, database.createLocally (peer auth as the service's user, while it runs):
   sudo -u agent-auth env DATABASE_URL='postgres://agent-auth@localhost/agent-auth?host=/run/postgresql' \
     "$(readlink /proc/$(systemctl show -P MainPID agent-auth)/exe)" import-python --dry-run - < agent-auth-export.json
   ```

   Carried: host daemons (id, name, public key), and agents registered by
   hand, with their API keys (key id and hash: the old keys keep working),
   kind, attributes, webhook URL and secret, hand-registered LLDAP
   username, and disabled state. Not carried: agent VMs (sandbox daemons),
   every agent minted in or for one, or by another agent, and the
   orchestrators (step 7); web UI connectors' agents (step 8); the
   Python's operator stand-in (the broker makes its own); LLDAP passwords
   (Fernet): a broker-managed account (`svc-<name>`, display name
   `<agent> (agent-auth managed)`) is adopted again at the agent's next
   homelab grant, with a new password. The warnings name service agents
   whose webhook has no secret of their own (they get no pings until
   `agent-auth admin rotate-webhook-secret`), `http` webhooks to hosts not
   in `A2A_WEBHOOK_HTTP_HOSTS`, and the managed accounts to be adopted.
   Webhook receivers must check the new timestamped signature (top-level
   README, "Verifying webhook pings").
6. **Switch the hosts**: on each, import the Rust hostd module instead of
   the Python's. hostd's state directory carries over as is (the identity
   key, the TOTP secrets and their state are in the Python's formats): it
   reconnects without pairing, and the authenticator entries stay valid.
   Shells now open with the tier's arm code (a direct code no longer does),
   or at the host's own desk with the password; `sudo agent-auth-hostd
   totp-enroll --add root-unlock` if remote unlock is wanted (it now needs
   it), `--add user-shell` / `--add root-shell` for a shell code of its own.
7. **Re-pair the agent VMs**: `agent-auth admin daemon-pair --role sandbox
   <host>`, then `agent-auth-sandboxd pair` in the guest; sandboxd's state
   is new (JSON documents instead of SQLite), the broker makes the VM's
   orchestrator again, and the orchestrator mints the VM's agents again.
8. **Reconnect web UIs**: remote MCP connectors (claude.ai, ChatGPT) and
   panel sessions start over; the connector is authorized again from its
   settings.
9. Saved rules ("approve all like this"), grants and the audit history
   stay in the old database; recreate the rules you want.
