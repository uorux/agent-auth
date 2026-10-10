# Agent VMs, host daemons, and remote execution — design

Status: **draft, revision 3** (2026-10-03). Nothing here is implemented yet.
Revision 2 incorporated review answers and a survey of the existing sandbox
tier in nixos-dots (branch `vm-sandbox`). Revision 3 adds:
- interactive sessions in the agent VM (§6.8);
- direct desktop prompts with anti-spam policy (§8.10);
- the agent network allowlist (§6.6);
- which hosts run what (§3.4).

This extends agent-auth from a credential broker into the control plane for
agents running in per-host **agent VMs**. It covers:
- minting the agents' identities;
- spawning and routing their conversations;
- attaching MCP servers;
- through a paired daemon on every host, running human-approved commands and
  mounting folders *outside* the VM.

Markers: **[decided]** = settled in review; **[proposed]** = my default, change
it if you disagree; **[verify]** = depends on tool behavior not yet confirmed
against the pinned versions; **[open]** = needs your call (collected in §16).

---

## Status (2026-10-09)

| phase | state |
|---|---|
| 1. Daemon channel + hostd skeleton | built, tested; deployed |
| 2. Agent VM (nixos-dots) | built; being brought up on excelsior |
| 3. sandboxd | built, including routing triage and the claude mid-turn doorbell; tested against a real broker with a fake runtime. `avm --host` is in nixos-dots (not run) |
| 4. hostexec `run` + kill switch | built, tested against the real hostd with a fake executor; **the systemd-run paths have not run on a host** |
| 5. Shells | built, same caveat |
| 6. MCP catalog + proxy | not started |
| 7. Mounts | not started |
| 8. Content-bound desktop approval of hostexec | not started |
| 9. Desktop prompts on every active host | built, tested with the real helper and a script for the dialog; **not run on a desktop** |

Where the build departed from this document is noted in place as **[built: …]**.

## 0. Decisions on record

- One agent VM per physical host, NixOS guest under crosvm.
- Headless claude/codex, driven by a daemon in the VM.
- Projects are isolated inside the VM, and cross-project access is a grant.
  Claude and Codex agents in the same project share a uid.
- Claude's scratchpad must survive.
- Subscription OAuth for both runtimes.
- The orchestrator is spawned per request, and its runtime is configurable
  (not tied to Claude).
- Minted agents get grants through normal policy, with parent lineage.
- No idle processes.
- There is no handoff after a mint: the requester opens its own thread to the
  new agent.
- The MCP catalog is mostly web MCPs, with secrets held by agent-auth through
  a broker proxy.
- Host execution:
  - Two modes, exact argv and time-boxed shells.
  - Shells get a louder prompt and a Discord thread showing every command.
    They only accept per-request TOTP.
  - "Approve all" is a time-boxed window.
  - Root has two TOTP secrets: one opens an arming window, the other approves
    a single request.
  - "Approve with TOTP" works without arming.
- TOTP secrets are per host.
- hostd's local policy lives in the nix store.
- All hosts are NixOS, desktops run Hyprland, and integrating the existing
  prompting system is the last phase.
- Extras accepted: kill switch, command output to Discord, LLM risk summary,
  mounts as grants, fleet health. No pre-mutation snapshots.
- Deferred: remote-host mounts and egress control.
- Revision 3 additions:
  - The shared VM pieces are extracted into `lib/vm/core` first.
  - Agent VMs run on excelsior, galaxy and recusant. hostd runs on every
    host, including the k3s nodes.
  - TOTP secrets are generated on the host.
  - Root desktop approval = a zenity prompt, *then* your polkit password.
  - Agents may prompt the desktop directly, under an anti-spam policy.
  - Agent network = internet + broker + attic + the gateways + the k8s
    nodes on 6443/443/80 (§6.6).
  - Interactive CLI sessions in the agent VM are required, and a web UI comes
    later.
  - The existing `claude`/`codex` launchers keep working unchanged.

---

## 1. Shape

```
                              ┌──────── broker (agent-auth on recusant, tailnet-only) ────────┐
 Hermes / any agent ──a2a───▶ │ policy · Discord · grants · a2a · daemon channel (WS)           │
                              │ platforms: agents · sandbox · mcp · hostexec · mount            │
                              └────▲─────────────────────────────────────────────▲──────────────┘
                                   │ signed WS over tailnet                      │ signed WS (via passt)
  ┌────────────────────────────────┴─────────────────────────────────────────────┴────────────┐
  │ physical host <host>                                                                       │
  │  hostd-root (trust anchor: TOTP, arm state, local policy, runs jobs, controls agent VM)    │
  │  hostd-user (desktop hosts only: prompts via sbx-prompt / polkit)                          │
  │                                                                                            │
  │  agent-vm units (system services, NOT the desktop session):                               │
  │   VMM · passt (-net, cgroup egress filter) · fs shares · grants fs device (as jrt)        │
  │   ┌──────────────────────── agent VM guest (own NixOS config) ─────────────────────────┐  │
  │   │ sandboxd (root): dispatcher, router, runtime adapters, project users + units       │  │
  │   │ nix-daemon (overlay store) · /var/lib/sandbox on persistent virtio-blk             │  │
  │   │ orchestrator-<host>-sandbox · claude-<proj>-<host>-sandbox · codex-…               │  │
  │   └────────────────────────────────────────────────────────────────────────────────────┘  │
  │  app sandboxes (unchanged): sbx-broker, per-app VMs/containers, zenity prompts             │
  └────────────────────────────────────────────────────────────────────────────────────────────┘
```

### End-to-end example

"Hermes asks for a Claude agent on project `larder` with the Linear MCP":

1. Hermes (on recusant) opens an a2a thread to `orchestrator-excelsior-sandbox`.
   This needs an `a2a talk` grant; policy auto-approves `hermes-*` →
   `*-sandbox`.
2. sandboxd, the dispatcher for every agent in its VM, gets the pending open
   over its daemon channel and routes it (§6.3) to a new orchestrator
   conversation. It spawns the orchestrator headless with its own broker
   session, and the conversation accepts the thread with that session.
3. The orchestrator calls `project_create("larder", repo="otisdog8/larder")`.
   sandboxd creates the project user and directory and gives the orchestrator
   temporary write access. The orchestrator requests a GitHub grant
   (delegated, on behalf of Hermes's thread) and clones the repo.
4. The orchestrator calls `agent_mint(runtime="claude", project="larder")`.
   This is an `agents:mint` request; policy auto-approves it. The broker
   creates `claude-larder-excelsior-sandbox` with parent = orchestrator and
   delivers its key **to sandboxd only**.
5. `request_access(mcp, linear, claude-larder-excelsior-sandbox)` is surfaced
   on Discord and approved.
6. The orchestrator calls `project_seal("larder")`, `a2a_send`s Hermes a
   result naming the new agent, and closes the thread. Hermes opens its own
   thread to the project agent **[decided: no handoff]**, and sandboxd routes
   that to a new project-agent conversation.

---

## 2. What already exists in nixos-dots, and what this reuses

The `vm-sandbox` branch already has a general sandbox tier. Most of it was
built for desktop apps, and most VM-side pieces are build-verified only
(HANDOFF §4).

| existing piece | what it does today | used here? |
|---|---|---|
| `lib/vm/instance.nix` | one crosvm microVM per app / per cwd / per group. Units `sandbox-vm-<n>[-prep\|-net\|-relay\|-grants\|…]`; launcher = SSH-over-vsock with per-boot keys, started via polkit by `jrt` | **reuse its building blocks**, not the instance itself (§3) |
| patched crosvm (`lib/vm/crosvm-fs.nix`) | virtio-fs with `--allowlist-socket-path`; `uidmap` for the single guest user | yes |
| passt + `lib/netpolicy.nix` | guest egress through a `-net` unit with cgroup `IPAddressAllow/Deny`; VM default `internet` (no LAN/tailnet) | yes, with a small allowlist (broker, attic, gateways, k8s nodes on 6443/443/80) plus new `allowPorts` (§6.6) |
| `lib/vm/vsock-relay.py` | guest unix socket → host service, authenticated by peer CID only | yes, for host↔VM local services |
| `lib/vm/grants.py` + guest `sbx-grantd` | live folder grants: the allowlist adds a `$HOME` subtree, and the guest bind-mounts it at the same path. No revoke; `ro` is enforced only in the guest | **yes, as the mount mechanism**, extended with revoke and per-project mapping (§11) |
| `sbx-broker` (user service, `graphical-session.target`) | per-sandbox socket; ops `exec` (user, or root via `run0`), `grant-net`, `grant-path`, `camera`, `fido`, `authenticate`. Prompts with zenity; root is never session-cached; rules per sandbox name | **not** used by the agent VM. It stays the app-sandbox broker. hostd is the agent-side counterpart (§8.1) |
| `sbx-prompt` (`lib/broker/prompt.nix`) | `sbx-prompt [--timeout N] [--no-session] -- REQUESTER SUMMARY DETAIL` → `once\|session\|deny` | **yes**, as the desktop prompt for hostd (phases 8 and 9, §8.6, §8.10) |
| polkit `authenticate` path (`pkcheck` → hyprpolkitagent) | a password check bound to a fixed action message | **yes**, as the second step of root desktop approval (phase 8, §8.6) |
| `modules.sandbox.agents` group | ONE persistent VM/container holding claude, codex, gemini, gsd and opencode, all sharing credentials (`agent-peers` collapses the wall on purpose). Projects shared rw at their real paths | kept for interactive desktop use; the agent VM is separate (§3.3) |
| agent-auth on recusant | broker; Hermes `hermes-homelab-recusant` + its a2a dispatcher (`agent-auth a2a serve`); `agent-auth-client` on every host | yes. Hermes is the first orchestrator client |

---

## 3. Separating the agent VM from app sandboxes **[decided]**

You suspected they should be separate. Having read the tier, I agree: the agent
VM should be its own module with its own guest, built from the same low-level
pieces. The coupling points that make sharing the *instance* layer wrong:

1. **The app tier runs inside the desktop session.**
   - `-relay`, `-bus` and `-grants` run as `jrt` against `/run/user/1001`.
   - `sbx-broker` is part of `graphical-session.target`.
   - The polkit rule hardcodes `jrt`.
   - Lifecycle is a launcher in your shell.

   recusant, arquitens, carrack and munificent are headless, so none of that
   exists there. An agent VM has to run as an always-on system service.
2. **One guest config for every VM.**
   - Anything added to `modules.sandbox.vm.guestModules` lands in every game
     and browser VM.
   - The agent guest needs a different system: sandboxd, a nix daemon,
     userdb users, and persistent disk. The app guest has none of these:
     its `/` is tmpfs, `nix.enable = false`, and it has a single user.
3. **One principal per VM.** The app tier's uid mapping makes guest user =
   host `jrt` (instance.nix:1973-1985). Per-project users inside the guest
   break that assumption everywhere the shares are uid-mapped.
4. **Different trust and approval channels.** App escapes are answered at the
   desk via zenity, and the socket is the identity. Agent escapes are
   answered by Discord, TOTP, and arming, with paired crypto. Mixing the two
   in one broker means either the app tier carries agent-auth's dependencies,
   or the agent tier inherits "any `jrt` process may connect".
5. **Churn isolation.** The app tier changes constantly (virtio-nvgpu, capture,
   GPU tuning). The agent VM uses none of it and shouldn't be rebuilt or
   broken by it.

### 3.1 What to share and what to fork

| layer | shared | agent VM |
|---|---|---|
| crosvm package (patched fs) | ✓ | |
| passt `-net` unit + `netpolicy.lower` | ✓ | own policy |
| vsock relay | ✓ | own service map |
| CID allocation | ✓ (one allocator; the agent VM gets a reserved CID so nothing collides) | |
| grants fs device + hub protocol | ✓ (extended: revoke, per-target mapping) | driven by hostd, not sbx-broker |
| storage tier conventions (`/persist`, `/large`, `/cache`) | ✓ | disk image on `/large` (§6.1) |
| instance.nix (launcher, display, audio, bus, capture, camera, fido) | | ✗ none of it |
| guest NixOS (`lib/vm/guest.nix`) | | ✗ own `agent-guest.nix` |
| broker / prompts | | hostd (+ `sbx-prompt`/polkit only for hostd-user) |

Concretely, in nixos-dots: extract the VMM/fs/net/relay/CID pieces that
`instance.nix` inlines into `lib/vm/core/*.nix` (no behavior change for apps).
Then add `nixos/modules/system/agent-vm.nix` (`modules.agentVm.*`) built on
them, with the guest config coming from agent-auth's `nixosModules.sandboxd`.

**[decided]** Extract first. The extraction must not change behavior for app
VMs. Check it by diffing the generated unit files and guest spec JSON for
every app VM on all eight hosts, before and after.

### 3.2 Host-side units of the agent VM

All are system services (`wantedBy = multi-user.target`); none needs a desktop
session:

- **`agent-vm`**: the VMM. Runs as `sbx-agentvm` with group `kvm`, hardened
  like app VMMs. Memory, vcpus and disk size are options.
- **`agent-vm-net`**: passt with the agent policy (§6.6).
- **`agent-vm-relay`**: a vsock relay with services `hostd` (sandboxd → local
  hostd, for mount and VM-control coordination) and nothing else.
- **`agent-vm-grants`**: the grants fs device, run as **`jrt`** because it
  shares jrt's `$HOME`. It is a plain system unit with `User=jrt`, so it works
  on headless hosts. Its allowlist socket is owned by hostd-root, not by a
  user hub.
- Rebuilds never restart a running VM (`restartIfChanged = false`, as in the
  app tier). hostd-root can freeze, stop and start the VM (kill switch, §9).

### 3.3 The existing launchers and the `agents` group **[decided: unchanged]**

`claude`, `codex` and the others keep working exactly as today: the nixpak
container by default, the `-container`/`-vm` variants, the `agents` group, and
`claude-gpu`/`claude-nesbox`. Nothing in this design changes their storage,
credentials or launchers. The agent VM never sees `/persist/sandbox/claude-code`.

Interactive work **inside** the agent VM is a separate, additional entry point,
`avm` (§6.8). The name avoids colliding with the app tier's generated
`claude-vm`/`codex-vm` variant commands.

### 3.4 Which hosts run what **[decided]**

| host | role | hostd-root | hostd-user | agent VM |
|---|---|---|---|---|
| excelsior | desktop | ✓ | ✓ | ✓ |
| galaxy | desktop | ✓ | ✓ | ✓ |
| constitution | laptop | ✓ | ✓ | — |
| recusant | server (broker, Hermes) | ✓ | — | ✓ |
| arquitens, carrack, munificent | k3s nodes | ✓ | — | — |
| liveusb | — | — | — | — |

- On the k3s nodes and recusant, hostd is the only broker-facing daemon, so
  agents can still run approved commands there.
- Headless hosts have no desktop prompts: Discord, TOTP and arming only.
- The user tier needs `jrt`'s user manager running, so those hosts set
  `users.users.jrt.linger = true`, or disable `tiers.user`.
- Desktop prompts reach whichever desktop host you're active on (§8.10).

---

## 4. Identities

### 4.1 Naming **[decided]**

`<runtime>-<project>-<host>-sandbox`, e.g. `claude-larder-excelsior-sandbox`,
`codex-agent-auth-recusant-sandbox`. The orchestrator is
`orchestrator-<host>-sandbox`. `<host>` is the **physical** hostname (one VM
each).

Names are never parsed for security decisions:
- The agent row stores `runtime`, `project`, `sandbox_id` as columns.
- The mint validator checks
  `name == f"{runtime}-{project}-{sandbox.host}-sandbox"`.
- `runtime` comes from a fixed hyphen-free set, so project names may contain
  hyphens.
- Policy rules keep matching on name globs (`*-sandbox`,
  `claude-*-excelsior-sandbox`).

### 4.2 Agent model changes

New columns on `agents`:

| column | meaning |
|---|---|
| `parent_agent_id` | the agent whose mint request created this one (null = hand-registered) |
| `sandbox_id` | the sandbox that holds this agent's key and dispatches its a2a |
| `runtime`, `project` | structured name parts (sandbox agents only) |

Minted agents are `kind=service` (they *can* receive threads), with sandboxd as
their dispatcher. sandboxd's event subscription touches `last_listen_at` for
all its children, so reachability works unchanged while the sandbox is
connected, and children go `idle` when it is not.

Grants for minted agents go through normal policy **[decided]**. Lineage
cascades: disabling an agent disables its descendants and revokes their
grants, and expiry of the mint lease does the same.

### 4.3 The sandbox principal

There is a `daemons` row per sandboxd (role `sandbox`), holding `host`, an
ed25519 public key, `paired_at`, `last_heartbeat_at` and `lockdown`.
sandboxd authenticates over the daemon channel (§7) with its key, and for
calls *as a child agent* it uses that child's API key.

**Blast radius of a VM-root compromise:**
- The attacker holds every child key in that VM.
- It can mint more children (bounded by `agents` policy).
- It can read the children's a2a threads and anything mounted into the VM.
- It cannot touch other VMs or hosts (hostd requires arming or TOTP), or
  hand-registered agents.
- An unrevoked crosvm allowlist entry stays readable by VM root until
  revocation is fixed (§11).

---

## 5. New broker platforms

All are ordinary requests that go request → policy → (rule | LLM | Discord) →
grant → provisioner. Expiry, revocation, rules, delegation and the Discord
surface come for free. Authority folding (`authority.py`):

| platform | capability | resource | authority (pinned by rules) | provisioned by |
|---|---|---|---|---|
| `agents` | `mint` | full agent name | `{runtime}` | broker (creates the agent row; key queued for sandboxd) |
| `sandbox` | `project.read` \| `project.write` | target project (same sandbox) | `{access}` | sandboxd (ACLs) |
| `mcp` | catalog server name | agent that will use it | `{tools?}` | broker (proxy grant) + sandboxd (config) |
| `hostexec` | `run` \| `shell` \| `tpl.<name>` | host | run: `{tier, argv, cwd, env}`; shell: `{tier}`; tpl: `{tier, template, params}` | hostd |
| `mount` | `ro` \| `rw` | `<host>:<abs path>` | `{mode, project}` | hostd (allowlist) + sandboxd (bind) |

Sensitive, always human (`is_sensitive`): every `hostexec` with `tier=root`,
every `shell`, `mount rw`, and `sandbox project.write`. Shells get no liberal
approval modes at all (§8.4).

Validators:

- **`agents:mint`**
  - The requester must have a `sandbox_id`, and `runtime` must be in the
    sandbox's allowed set.
  - The name must match §4.1 for the *requester's* sandbox.
  - Minting an existing child of the same sandbox renews its lease.
  - Grant duration = identity lease (policy default 30d, renewable by rule).
- **`sandbox:project.*`**: requester and target are in the same sandbox, and
  the target is not the requester's own project.
- **`mcp`**: the server is in `platforms.mcp.catalog`; the requester is the
  resource agent or its parent; `tools` ⊆ the entry's tools.
- **`hostexec`**
  - The host's hostd must be paired and online; otherwise fail fast with a
    409.
  - argv is a non-empty list of strings.
  - `tpl.*` params are validated against the template's regexes and expanded
    broker-side; the authority keeps both.
- **`mount`**: the target host is the VM's own host for now (remote mounts are
  deferred); the path is absolute and normalized, with no `..`. hostd
  re-checks it against its local policy.

---

## 6. The agent VM guest and sandboxd

agent-auth ships `nixosModules.sandboxd`, the guest-side module (sandboxd plus
the system shape below). nixos-dots' `agent-vm.nix` boots a guest built from it.
sandboxd is Python, in this repo, entry point `agent-auth-sandboxd`, and runs
as root in the guest. Its state lives in SQLite under `/var/lib/sandboxd`.

### 6.1 Guest system **[proposed]**

- **Disk** **[decided, built]**: `/` is a tmpfs rebuilt from Nix on every
  boot, as on the hosts. A **btrfs** data disk is mounted at `/persist`
  (virtio-blk, formatted on first boot) and holds `/var/lib` (projects, homes,
  per-project `/tmp`, sandboxd and userdb state), `/nix/var`, `/var/log`, and
  the store overlay's writable layer, all bound in place in the initrd.
  - Why tmpfs root: whatever a compromised guest root writes anywhere else is
    gone at the next boot.
  - Why btrfs: compression and checksums inside the image, a subvolume per
    project for cheap snapshots and reflink copies, and `discard=async`, which
    returns freed blocks to a sparse image.
  - Why a block device rather than a virtio-fs folder: many guest uids,
    ACLs, and an overlay writable layer all need a real local filesystem.
    Mapping guest uid ranges through virtio-fs would mean a root-run,
    guest-facing parser on the host.
  - Where the disk lives on the host: a sparse image in `/large`, marked
    nodatacow (`chattr +C`) before it is created, so btrfs hosts don't
    fragment it. Or a dedicated block device (`disk.type = "block"`: an LVM
    thin LV, a partition or a zvol), which is better where one exists.
- **Nix**: the host's `/nix/store` (a virtio-fs share, as today) is the
  lower layer of an overlayfs `/nix/store`, with the upper layer on the
  disk. A guest `nix-daemon` lets agents `nix develop`/`build`. Substituters:
  cache.nixos.org plus attic on recusant.
  - **[verify]** registration of the host's store paths in the guest
    database. microvm.nix's `writableStoreOverlay` is the reference
    implementation of this pattern.
- **Users**: systemd-userdb records written by sandboxd
  (`/var/lib/userdb` → `/etc/userdb`), so the guest NixOS config keeps
  `mutableUsers = false`.
- **No display, audio, D-Bus relay, or SSH launcher.** One SSH-on-vsock
  endpoint for *you* (root/debug, key from the host's `-prep`) is optional.

### 6.2 Projects and isolation **[decided]**

```
/var/lib/sandbox/projects/<p>/   0700 p-<p>   the checkout(s)
/var/lib/sandbox/homes/<p>/      0700 p-<p>   $HOME: ~/.claude, ~/.codex, gitconfig
/var/lib/sandbox/tmp/<p>/        0700 p-<p>   bound to /tmp in every unit of the project
```

- **One unix user per project (`p-<project>`).** The project is the trust
  boundary: `claude-x` and `codex-x` share a uid **[decided]**.
- **Every process runs in a transient systemd unit** with:
  - `User=p-<p>`
  - `ProtectSystem=strict`
  - `ReadWritePaths=/var/lib/sandbox/projects /var/lib/sandbox/homes/<p>`
  - `BindPaths=/var/lib/sandbox/tmp/<p>:/tmp`
  - `ProtectProc=invisible`, so other projects' `/proc/*/environ` is hidden
  - `NoNewPrivileges`, `PrivateDevices`, `ProtectKernel*`
  - `MemoryMax`, `TasksMax`, `CPUWeight`
- **Isolation is by file permissions, not mount namespaces**, so grants apply
  to running units:
  - `sandbox:project.read` → `setfacl -R -m u:p-a:rX` plus a default ACL;
  - `project.write` → `rwX`;
  - revoke removes them.
  - gitconfig sets `safe.directory=*`.
- **Scratchpad persists** **[decided]**. Claude's scratchpad lives under
  `/tmp/claude-<uid>/<cwd-slug>/<session-id>/`. `/tmp` is the persistent
  per-project directory, so a resumed session finds its scratchpad after
  process exits and VM reboots.
- **Orchestrator setup access**: `project_create` grants the orchestrator user
  a temporary `rwX` ACL. `project_seal` chowns everything to `p-<p>` and drops
  the ACL. Unsealed projects auto-seal after a timeout.

### 6.3 Conversations and routing

A **conversation** is the logical unit; a **process** is transient.

```
Conversation {id, agent, runtime, runtime_session_id, broker_session_id,
              threads[], state: running | parked | closed, created_by}
```

- **No idle processes** **[decided]**. A process exits when its turn
  finishes and nothing is queued. The grace period is configurable (default
  30s, 0 allowed). The conversation then goes `parked`. The next message for
  it **resumes** the runtime session in a fresh process, with the same
  transcript, the same scratchpad, and the current MCP config.
- **The broker session outlives the process.** sandboxd keeps it alive while
  the conversation has open threads, so a parked conversation is still
  `peer_alive` (it *will* answer, by resuming). Closing the conversation
  closes the session, which cascades `peer_gone` and revokes delegated
  grants as today. A new `AGENT_AUTH_SESSION_ID` env var pins the MCP server
  to the conversation's session.
- **Routing an inbound event**:
  1. A message on a bound thread goes to its conversation (resumed if
     parked).
  2. A new open with a hint (`payload._sandbox.conversation` or
     `continue_thread`) goes to that conversation, if it belongs to the
     target agent.
  3. A new open where the target agent has conversations with the same peer
     or a matching topic → **triage**: a one-shot cheap-model call
     (`claude -p --model haiku` or the codex equivalent, in a throwaway unit)
     picks `{conversation_id | "new"}`. Any failure → new.
     **[built]** Candidates are the agent's open conversations that already
     have a thread with the same peer or the same topic (at most 8). The
     call has no tools, no MCP and no settings, gets the prompt on stdin,
     and runs in a throwaway unit as the project's user. Only an answer
     naming exactly one candidate routes there. The claude call
     (`--model haiku --tools "" --strict-mcp-config --setting-sources ""`)
     is checked against the fake runtime only; the codex one (`codex exec -`)
     is unverified.
  4. Otherwise → a new conversation.

  **[built]** The hint is `{"_sandbox": {"conversation": "<id>"}}` in the
  opening payload. Building it surfaced a broker bug, now fixed: FastAPI's
  encoder dropped payload keys starting with `_sa`, as if they were
  SQLAlchemy state.

  The chosen conversation claims the thread by accepting with its own session.
- **Delivery format**: `[a2a] thread <id> · from <peer> · topic <t> · seq <n>`,
  then the payload, plus a footer saying to reply with `a2a_send`. The sink
  rule from `hermes-setup.md` applies.
- **Limits**: maximum concurrent processes per project and per VM; excess work
  queues.

### 6.4 Runtime adapters (headless) **[decided]**

```python
class Runtime(Protocol):
    async def start(self, conv: Conversation, resume: bool) -> RunHandle: ...
    async def send(self, h: RunHandle, text: str) -> None   # queued as next user turn
    async def interrupt(self, h: RunHandle) -> None
    def events(self, h: RunHandle) -> AsyncIterator[Event]  # text, tool use, turn_done, exit
    async def stop(self, h: RunHandle) -> None
```

Prototyped on 2026-10-03 against Claude Code 2.1.280 and codex-cli 0.156.1.
"Verified" below means observed, not assumed.

- **Claude** (verified with a live model)
  - Invocation: `claude -p --input-format stream-json --output-format
    stream-json --verbose`, with `--session-id <uuid>` on the first start and
    `--resume <uuid>` after.
    - The chosen id is honored.
    - Resume **continues the same id and the same transcript file**
      (`~/.claude/projects/<cwd-slug>/<id>.jsonl`); it does not fork.
  - **One process takes many turns**: writing another `{"type":"user",…}`
    line to stdin after a `result` starts the next turn. Lines written while
    a turn is running queue up, and **each becomes its own turn with its own
    `result`**. That is exactly the `send()` contract.
  - Also passed: `--mcp-config <generated>` and `--append-system-prompt
    <sandbox context>`. Permissions are bypassed because the unit is the
    sandbox.
  - **Spawn with a clean environment.** A `CLAUDE_CODE_CHILD_SESSION` marker
    inherited from a parent Claude process turns transcript saving off in
    the TUI ("restart with CLAUDE_CODE_FORCE_SESSION_PERSISTENCE=1"). That
    would silently break resume. sandboxd builds each unit's env from
    scratch, never from its own.
- **Codex** (protocol verified; live turns not run, since there is no auth in
  the test environment)
  - `codex app-server` JSON-RPC methods exist as assumed: `initialize`,
    `thread/start`, `thread/resume`, `turn/start`, `turn/interrupt`, plus
    `turn/steer` (`{threadId, expectedTurnId, input}`) and
    `thread/inject_items`. Notifications include `turn/started`,
    `turn/completed`, `item/started|completed`, `item/agentMessage/delta`,
    `thread/status/changed` and `error`.
  - `--listen unix://PATH` serves **WebSocket over a unix socket**. Long
    paths are symlinked to `/tmp/codex-daemon-<uid>/<hash>`, which lands in
    the project's persistent `/tmp`. **Several clients can share one
    server**: after `thread/resume`, every client receives every event of the
    thread, and any client can start turns. sandboxd uses this for
    interactive attach (§6.8).
  - The session file (`$CODEX_HOME/sessions/YYYY/MM/DD/rollout-…-<id>.jsonl`)
    is written at the **first turn**. `thread/resume` of a thread with no
    turns fails with "no rollout found", so sandboxd never parks a codex
    conversation before its first turn.
  - `CODEX_HOME` must not be under `/tmp`, because codex refuses to create
    its helper binaries there. Project homes live in
    `/var/lib/sandbox/homes/<p>`, which is fine.
  - Codex's own sandbox is set to full access inside the unit.
- **Mid-turn delivery**
  - Codex: `turn/steer` adds input to the running turn, which is better than
    the turn-boundary baseline assumed in revision 2. sandboxd steers a2a
    messages into an active turn, and starts a turn otherwise.
  - Claude: queued stdin lines become the next turns (verified).
    **[built]** A `PostToolUse` hook is the doorbell: a message for a busy
    process waits in the conversation's inbox, the hook
    (`agent-auth-sandbox-mcp hook`) hands it to the model as added context
    after its next tool call, and whatever is still queued when the turn
    ends becomes the next turn. Verified against Claude Code 2.1.292 in `-p`
    mode: the hook's `additionalContext` reaches the model. For an attached
    TUI, the same hook on `UserPromptSubmit` adds queued messages to your
    next prompt.
- **Auth: subscription OAuth** **[decided]**
  - Claude: one long-lived `claude setup-token` token, root-only on the VM
    disk, injected as `CLAUDE_CODE_OAUTH_TOKEN`.
  - Codex: one `auth.json` in a `sandbox-auth` group directory, linked into
    each project's `CODEX_HOME`. **[verify]** whether concurrent refresh is
    safe; if not, sandboxd serializes it.
  - Both are separate from your interactive credentials in
    `/persist/sandbox/*`. Agents can read the subscription credentials,
    which is unavoidable.

### 6.5 Local API and the sandbox MCP

sandboxd serves a unix socket. It identifies callers by `SO_PEERCRED` uid →
project, plus a per-conversation token in the unit env. Agents reach it
through a stdio shim (`agent-auth-sandbox-mcp`):

| tool | who | does |
|---|---|---|
| `project_create(name, repo?)` / `project_seal` / `project_list` | orchestrator | §6.2 |
| `agent_mint(runtime, project)` | orchestrator | `agents:mint` *as the orchestrator*; the key goes to sandboxd |
| `agent_spawn(agent, prompt)` | orchestrator | new conversation with a seed prompt |
| `conversations()` | any | own agent's conversations (for routing hints) |
| `inbox()` | any | queued, undelivered a2a for this conversation |

Every instance also gets the regular `agent-auth-mcp` (its own key and the
conversation's session) and its granted catalog MCPs.

### 6.6 Network **[decided set; per-project egress deferred]**

passt plus `netpolicy`, mode `internet` (no LAN or tailnet), with
exceptions:

| destination | how it's allowed | why |
|---|---|---|
| broker `agent-auth.recusant.rooty.dev` (100.110.239.45) | IP | daemon channel, a2a, MCP proxy |
| attic on recusant | IP | nix substituter |
| `gateway.rooty.dev`, `ion-1.rooty.dev`, `ovh-1.rooty.dev` | `allowNames` (`sbx-dnsallow`) | homelab gateway |
| k3s nodes arquitens / carrack / munificent (100.126.30.73, 100.103.225.29, 100.65.16.13) | IP **+ ports 6443, 443, 80 only** | Kubernetes API (so `kubernetes` grants are usable from the VM) and the cluster's ingress |

**Port limit for the k3s nodes.** cgroup `IPAddressAllow` can't filter by
port, and arquitens has its firewall off, so allowing the node IPs would open
every service on them.

**[decided, built]** The shared `lib/vm/core` net piece has `portFilter`: the
agent VM's passt runs as its own uid (`sbx-agentvm-net`), and host iptables
rules matched on that uid (`-m owner --uid-owner`) accept only the listed
`ip:port` pairs. The addresses are also in the unit's `IPAddressAllow`, since
the cgroup filter and the firewall must both pass a packet. This is host-side,
so a compromised VM can't remove it.
- A cgroup match was the first idea, but iptables and nft resolve the cgroup
  path when the rule loads, before the unit's cgroup exists.
- The hosts run the iptables firewall, not nftables.
- App VMs can't use the filter while their passt runs as the desktop user,
  because an owner match would filter that user's own traffic.

**[verify]** whether the gateway names and `agent-auth.recusant.rooty.dev`
resolve through the guest's public resolvers. `allowNames` forwards DNS to the
host's resolved either way. `allowNames` additions persist until reboot, and a
lookup by anyone on the host counts (the existing `sbx-dnsallow` semantics).

Other tailnet services (llama-swap on galaxy, Gitea, …) are reached through
grants: a future `net` platform lowered to `set-property IPAddressAllow`, as
sbx-broker's `grant-net` does. Deferred, along with per-project egress
(in-guest nftables `meta skuid`).

### 6.7 Key custody

**[built]**
- **Orchestrator bootstrap:** pairing a sandbox daemon bootstraps
  `orchestrator-<host>-sandbox`, and re-pairing rotates its key.
- **Delivery:** keys are pushed as `key` messages on connect, on every
  heartbeat, and right after a mint, until acknowledged.
- **Leases:** the identity lease (`platforms.agents.lease`, 30d) is separate
  from the mint grant's duration, which recusant's 24h default would cap.
  Minting again renews the lease. A sweep disables expired agents, and
  `admin agent-disable` disables an agent and everything it minted.
- **Explicit rules:** minting is cleared only by a rule that names `mint`.

`agents:mint` provisioning generates the key, stores it Fernet-wrapped in
`pending_key_deliveries`, and pushes `key.available`. sandboxd fetches it once
over the daemon channel, and the row is deleted on ack. A lost key → `admin
rotate-key`, or a sandbox-initiated rotate for its own children. The grant
credential for `agents` returns only `{agent_id, name}`.

### 6.8 Interactive sessions **[decided: CLI required, web UI later]**

An interactive session is just a conversation whose process is the runtime's
TUI instead of its headless mode. It uses the same identity, broker session,
project unit, scratchpad and MCP config. So you can start one interactively,
leave it to run headless, and take over a headless one, all on the same
transcript.

**Host CLI `avm`** (on the agent VM's host; `--host <h>` reaches another host
over tailnet SSH, which `jrt` already has). **[built: avm runs
`agent-auth-sandboxctl` in the guest over vsock SSH; `avm claude|codex
<project>` stands in for `avm new`; `--host` runs the other host's `avm` over SSH]**

| command | does |
|---|---|
| `avm ls [--project p]` | conversations: agent, state (running/parked/attached), threads, last activity |
| `avm new <project> [--runtime claude\|codex] [--project-create --repo …]` | new interactive conversation as `<runtime>-<project>-<host>-sandbox`. Mints the identity if missing (via the orchestrator's `agents:mint`, so policy still applies); creates the project only with `--project-create` |
| `avm attach <conv>` | take over a conversation in its TUI |
| `avm logs -f <conv>` | read-only live transcript of a headless conversation (stream-json / app-server events rendered) |
| `avm send <conv> "text"` | inject a user turn without attaching |
| `avm stop <conv>` / `avm close <conv>` | park / close (close ends its threads) |
| `avm shell <project>` | a plain shell as `p-<project>` in a project unit (no runtime) |

**Mechanics**

- **Transport**
  - `avm` SSHes over vsock into the guest, using the same pattern as app
    VMs: a per-boot client key from the host's `-prep` unit, readable by
    group `agent-vm-users` (`jrt`).
  - In the guest it talks to sandboxd's local API as an *operator* client.
    That is a separate socket, root-owned, reachable only from the SSH
    login user `operator`, never from project uids.
- **TUI processes**
  - Interactive processes run in the project's unit inside a per-conversation
    tmux session (`tmux -L conv-<id>`), so a dropped SSH connection detaches
    instead of killing the process.
  - `avm attach` = `ssh -t … tmux attach`.
- **Claude: hand the session over, one writer at a time** (verified)
  - `attach` waits for the headless process to reach a turn boundary (or
    interrupts it with `--now`), stops it, and starts
    `claude --resume <session-id>` in the TUI, with the same `--mcp-config`
    and appended system prompt.
  - Prototype result: a session created by `claude -p` stream-json opened in
    the TUI with its full history. A turn taken in the TUI was then visible
    to the next headless `--resume`, still on the same id and file.
  - Detaching from tmux leaves the TUI running; that is the `attached` state.
  - Exiting the TUI, or `avm stop`, returns the conversation to `parked`,
    after which inbound messages resume it headless again.
- **Codex: share the live process, no handover** (protocol verified)
  - sandboxd runs codex conversations under
    `codex app-server --listen unix://…/conv-<id>.sock` and stays connected
    as a client.
  - `avm attach` starts `codex --remote unix://…/conv-<id>.sock resume
    <thread-id>` in tmux, a second client of the same live server. The TUI
    connected and reached its login screen in the test (no auth there).
  - Both clients see every event, so you and sandboxd are on one live thread
    with no stop/resume.
  - **[verify] with auth**: the TUI's rendering of turns started by the
    other client.
- **Inbound a2a while attached**
  - Codex: sandboxd `turn/steer`s the message into your active turn, or
    starts a turn when the thread is idle. You see it arrive in the TUI.
  - Claude: messages queue in sandboxd. A `UserPromptSubmit` hook prepends
    them to your next prompt as context, and a status line (`a2a: 2 queued`)
    shows them. **[verify]** the hook and status-line contracts.
- **No idle processes, with one exception**: an attached TUI is never
  reaped while a client is attached. With no client attached, it is parked
  after `interactiveIdle` (default 30 min) of no input.
- **Desktop shortcuts** (nixos-dots, desktop hosts):
  - `avm-claude` / `avm-codex <project>` = `avm new` or attach to the most
    recent conversation for that project, in your terminal.
  - Optional launcher entries "Claude (agent VM)" and "Codex (agent VM)".

**Web UI (later)**: the same operator API, exposed over the daemon channel
(`conv.list|send|stream|attach`). It would be served by the broker behind
Authelia OIDC, like the Hermes dashboard, rendering transcripts and a chat
box, with a web terminal (xterm.js over the WS) for full TUI attach. Nothing
in the CLI design blocks this. The operator API is the contract both use.

---

## 7. Daemon channel and pairing (shared by hostd and sandboxd)

### 7.1 Keys

- **Broker signing key**: ed25519, new secret `BROKER_SIGNING_KEY` in
  recusant's `agent-auth/env` sops dotenv; `agent-auth admin
  gen-signing-key` prints the seed and pubkey. Daemons **pin the broker
  pubkey from nix config** (`brokerPublicKey`), set by an audited
  nixos-dots commit.
- **Daemon keys**: each daemon generates its own ed25519 key on first start.
  - hostd: `/var/lib/agent-auth-hostd/key`, persisted via impermanence.
  - sandboxd: the VM disk.
  - Mode 0400 in both cases.

### 7.2 Pairing

```
admin:   agent-auth admin daemon-pair --role host excelsior   → one-time code (10 min)
host:    sudo agent-auth-hostd pair            (prompts for the code; never on argv)
           → POST /v1/daemons/pair {role, name, pubkey,
                selector = HMAC(code, "pair-selector"), proof = HMAC(code, role‖name‖pubkey)}
broker:  matches selector, verifies proof, stores pubkey,
           replies proof' = HMAC(code, role‖name‖pubkey‖broker_pubkey)
host:    verifies proof' and broker_pubkey == pinned; prints both fingerprints
```

The selector lets the broker refuse attempts from anyone without the code
before they spend one of the code's 5 attempts, so the unauthenticated pair
endpoint can't be used to burn a pending code (or to learn whether one is
pending: every refusal reads the same). Attempts are spent atomically before
the proof is checked. Unpairing also burns any unused code for that daemon.

sandboxd pairs the same way (`--role sandbox`), with the code entered
through the VM's debug SSH endpoint or passed in by hostd over the relay.
Re-pairing replaces the key; `admin daemons` lists them, and
`daemon-unpair` revokes one.

### 7.3 Transport

- **Connection**: an outbound WebSocket to `/v1/daemons/connect` through
  recusant's nginx, tailnet-only. hostd connects over the host's tailnet;
  sandboxd connects via passt (§6.6). There are no inbound ports anywhere.
- **Handshake**: a mutual challenge in which each side signs
  `"agent-auth/v1/hello" ‖ speaker ‖ role ‖ name ‖ both nonces ‖ params`
  (`params`: the daemon's version, the broker's heartbeat interval). A
  hello verified against a key that is re-paired or unpaired before the
  connection registers is refused.
- **Envelopes**: `{"p": b64(json), "s": b64(sig over "agent-auth/v1/msg" ‖ sid ‖ p)}`
  carrying `type`, `id`, `seq`, `iat`, `exp` (60s for jobs), where `sid`
  hashes role, name and both hello nonces. An envelope verifies only on the
  connection it was sent on; `seq` must strictly increase per direction, so
  nothing is replayed or reordered; stale messages are rejected. Ids that
  must survive reconnects (job ids) are deduplicated by the job layer.
- **Liveness**: the broker drops a connection that sends nothing for three
  heartbeat intervals.
- **Confidentiality** is TLS's: envelopes are signed, not encrypted, so
  daemons refuse a non-https broker URL (plain http only for localhost).
- **Reliability**: reconnect with backoff; in-flight jobs are reconciled by
  id. nginx `proxy_read_timeout` must exceed the heartbeat interval (it is
  330s today; the heartbeat is 30s).
- **Message types**:
  - `heartbeat`
  - `job.offer|accepted|rejected|output|done`
  - `arm|disarm|arm.state`
  - `control` (sandbox/mount/mcp provision steps, `lockdown`, `unlock`,
    `vm.freeze|thaw|stop`) and `control.ack`
  - sandboxes only: `key` (broker → daemon, an agent's key) and `key.ack`,
    `key.rotate` (daemon → broker), and `project.grant|revoke` answered by
    `reply` through `DaemonHub.call()`.

  **[built]** a2a doesn't travel over the channel. sandboxd runs one
  sessionless `/v1/a2a/events` long-poll per agent, which is also what keeps
  each agent reachable, plus one session-scoped long-poll per open
  conversation, which keeps its session alive while parked. That's simpler
  than fanning events out over the channel, and fine at homelab scale; it
  can move onto the channel later without changing sandboxd's logic.

  Daemon-side provisioners wait for an ack. A timeout or nack becomes
  `provision_failed`, and revocations retry until acked.

---

## 8. hostd — execution outside the VM

agent-auth ships `nixosModules.hostd`, imported by nixos-dots on **every**
host. Headless servers run hostd-root only.

### 8.1 Relationship to sbx-broker

sbx-broker already does `exec` as user or root behind a zenity prompt, but it is
built for a different trust model:
- the socket is the identity;
- any `jrt` process may connect;
- it lives inside the graphical session;
- it keeps no persistent audit log.

hostd is the agent-tier equivalent: paired crypto, Discord/TOTP/arming, local
policy in the nix store, the journal as the audit log, and it works headless.
Both run side by side and share no sockets. Phase 8 reuses sbx-broker's
*prompt pieces* (`sbx-prompt`, the polkit `authenticate` pattern), not its
broker.

### 8.2 Two processes, one trust anchor **[proposed]**

- **hostd-root** (system service) is the only daemon that pairs with the
  broker. It holds the TOTP secrets, arm state and local policy, and runs
  every job:
  - root jobs directly;
  - user jobs via `systemd-run --user --machine=jrt@.host`, so they land in
    your user manager.

  It also controls the local agent VM (freeze, stop, start) and its grants
  allowlist socket.
- **hostd-user** (user service, desktop hosts) is a prompt helper that talks
  to hostd-root over a root-owned unix socket.

**[built]** One root daemon, `agent-auth-hostd run`, started as root only
when a tier or `vm.unit` is configured (otherwise it stays the unprivileged
connect-only service). User jobs do not use `--machine=jrt@.host`: that
transport can't carry the job's stdio. hostd drops to the user (`setpriv`)
and runs `systemd-run --user` against `/run/user/<uid>/bus`. hostd-user is
`agent-auth-hostd user`, a user service; it is used for desktop prompts
(phase 9) and holds nothing.

Why the user instance doesn't pair or verify on its own: an approved user
command runs as `jrt`. If the user-tier daemon also ran as `jrt`, that command
could read its TOTP secrets, ptrace it, or arm it, so one approval would mean
permanent access. Keeping secrets and arm state in root makes user-tier
approvals expire.

### 8.3 TOTP secrets **[decided: per host, generated on the host]**

There are four secrets per host: `user-arm`, `user-direct`, `root-arm`,
`root-direct`.

**[decided]** Generate them on the host, not in sops:
- `sudo agent-auth-hostd totp-enroll` creates the four secrets in
  `/var/lib/agent-auth-hostd/totp/` (root 0400, persisted).
- It prints each one once as a QR code in the terminal for your
  authenticator.
- The secrets never leave the host and never pass through git or sops.
- This also avoids adding sops recipients for arquitens, carrack and
  munificent, which have none today.
- `totp-enroll --rotate <name>` replaces one secret.

### 8.4 Local policy (nix store) **[decided]**

```nix
services.agent-auth-hostd = {
  enable = true;
  brokerUrl = "https://agent-auth.recusant.rooty.dev";
  brokerPublicKey = "ed25519:...";
  user = "jrt";
  tiers.user = {
    enable = true;
    maxArm = "8h";
    acceptApproveAll = true;           # approve-all windows honored while armed
    acceptMachineApprovals = true;     # rule / LLM approvals honored while armed
    shell = { enable = true; maxDuration = "1h"; };
  };
  tiers.root = {
    enable = true;
    maxArm = "1h";
    acceptApproveAll = false;
    acceptMachineApprovals = false;    # armed root still needs a human click
    shell = { enable = true; maxDuration = "30m"; };
  };
  autoCommands = [ [ "systemctl" "--user" "status" "*" ] ];  # user tier, no arming needed
  denyCommands = [ ];                                         # never run, whatever the approval
  templates.nixos-rebuild = {
    tier = "root";
    argv = [ "nixos-rebuild" "switch" "--flake" "{flake}" ];
    params.flake = "^git\\+https://git\\.rooty\\.dev/jrt/[a-z0-9-]+(\\?ref=[a-z0-9/._-]+)?#[a-z0-9-]+$";
  };
  mounts = {
    allow = [ "/home/jrt/Documents/*" "/home/jrt/src/*" ];
    deny  = [ "/home/jrt/.ssh" "/home/jrt/.gnupg" "/home/jrt/Documents/nixos-dots" ];
    autoRo = [ ];                      # ro mounts that need no arming
  };
  vm.unit = "agent-vm.service";        # null on hosts without an agent VM
};
```

The default `mounts.deny` includes nixos-dots, matching agent-auth's GitHub
repo denylist (`*/nixos-dots`): no brokered agent should reach the repo that
configures the broker's host.

### 8.5 What hostd accepts

Each `job.offer` carries evidence:
`{request_id, decided_by, source: human|rule|llm|policy, window_id?, totp?}`.
hostd checks it in this order:

1. Lockdown → reject (except `unlock`, §9).
2. A `denyCommands` match, a disabled tier, or a mount outside `allow` /
   inside `deny` → reject.
3. `totp` present → validate against the tier's **direct** secret (±1 step,
   single use, last used step persisted). Valid → run, armed or not.
4. Command matches `autoCommands` (user tier) → run.
5. Tier **armed** → run if `source=human`; `rule`/`llm` only if
   `acceptMachineApprovals`; windows only if `acceptApproveAll`.
6. Otherwise → reject `not_armed`; the agent and Discord are told "TOTP or
   arm".

Shells accept only step 3. Every decision goes to the journal with its
evidence, as a local audit log the broker can't edit.

**[built]** Three messages instead of one offer, so a refusal can leave the
request open on Discord instead of failing it:

- `hostexec.precheck {spec, source, window}`: would this be admitted now?
  Consumes nothing. Asked before a human approval is recorded.
- `hostexec.authorize {job_id, digest, tier, totp}`: verify and spend a
  direct TOTP code for one request. The digest is over the whole spec
  (host, tier, argv or template+params, cwd, env, timeout, stdin), and the
  job that follows must have that digest.
- `job.start {job_id, spec, evidence}`: run it, if an authorization with
  that digest is waiting, or the steps above admit it.

Codes also lock: five wrong ones lock a secret for five minutes, so whoever
relays codes can't search them.

**Residual risk** (accepted): TOTP codes pass through Discord and the broker.
A compromised broker can't *produce* codes, but it could hold back your
request and attach your code to its own command, once per code. Only an
approval UI rendered by hostd itself (§8.6) binds the approval to the
content.

### 8.6 Approval modes and Discord UX **[decided]**

| mode | how | needs | allowed for |
|---|---|---|---|
| **Approve** | button | tier armed | `run`, `tpl.*` |
| **Approve all…** | button → modal (duration, default 30m) | armed + `acceptApproveAll` | `run`, `tpl.*` |
| **Approve with TOTP** | button → modal with code (direct secret) | — (works disarmed) | `run`, `tpl.*`, **`shell`** |
| Deny / Edit | as today; Edit may change argv/cwd, and still needs TOTP if disarmed | | all |

- **Approve all** = an **expiring saved rule** **[decided: time-boxed]**:
  - Scope: this exact agent, platform `hostexec`, capability `run`, resource
    = this host, authority `{tier}` (any argv), with `expires_at` (a new
    column on `rules`).
  - It also approves matching pending requests.
  - It never matches `shell`.
- **Arming** **[built]**
  - Discord: `/arm host:<h> tier:<user|root> duration:<d> code:<arm TOTP>`,
    and `/disarm`.
  - Locally: `agent-auth-hostctl arm 2h` (user tier: local presence; root:
    sudo).
  - Capped at `maxArm`, held in memory only (a restart disarms).
  - Embeds show live arm state; Approve is disabled while disarmed.
- **`run` embed**: host, tier (ROOT in red), argv code block, cwd, env keys,
  agent and its project, delegator, and **LLM risk summary**.
- **Shell embeds** are loud: red, `🚨 ROOT SHELL` / `⚠ USER SHELL`, owner
  mention, optionally in `DISCORD_LOUD_CHANNEL_ID`. Buttons are TOTP and Deny
  only.
- **Output**: the approval message is edited with the exit code, duration,
  and last ~30 lines. Full output (≤1 MiB) is attached and returned to the
  agent with a sha256, and `job.done` is signed by hostd.
- **[built]** The output is sent after the job ends, in chunks, and the
  host keeps it until the broker acknowledges it (resent after a reconnect).
  It is the *last* 1 MiB. There is no separate signature on `job.done`: it
  travels in the channel's signed envelopes like everything else.
- **Desktop approval of hostexec on the same host** (phase 8, not built).
  This is the only approval path where the UI is rendered from what hostd
  itself received, so it binds the approval to the content.
  - **User tier**: hostd-user runs `sbx-prompt` with the command *as hostd
    received it*. `once` = a direct approval; `session` = arm the user tier
    for `maxArm`.
  - **Root tier** **[decided: zenity, then password]**:
    1. hostd-user shows `sbx-prompt --no-session` with the full command,
       cwd, agent, risk summary and the agent's justification (labelled
       unverified). This is the readable context.
    2. On Allow, hostd-root asks polkitd itself (`CheckAuthorization`,
       subject = hostd-user's process, `auth_admin` action
       `com.otisroot.agent-auth.hostexec-root`, fixed message "Approve the
       root command shown in the agent-auth dialog"). hyprpolkitagent then
       asks for **your password**.
    3. Only polkitd's answer counts. A `jrt` process could fake step 1 but
       can't fake step 2's result. It could spoof the polkit agent and
       capture the password, which is the standard Linux-desktop weakness
       and is accepted. Zenity alone is never accepted for root.

### 8.7 Shells **[decided, built]**

- **Open**: `hostexec shell` with `{tier}`, a duration ≤ `shell.maxDuration`,
  and a justification. Approval is TOTP only. hostd records `shell_id →
  expires_at` **locally**, so the broker can't extend it.
- **Use**: `host_shell_exec(grant_id, argv, cwd?, stdin?)`. Each command is a
  discrete job: there is no PTY, and every command is logged before it runs.
- **Mirror**: a Discord thread on the approval message gets every command
  **before** dispatch, then its output. **End shell** revokes the grant, and
  hostd drops the `shell_id` and kills any running job.
- **[built]** If the command can't be posted, it is not sent to the host. A
  shell is never decided by a rule or the LLM (`authority.human_only`), and
  hostd opens one only on an authorization from a direct TOTP code. A hostd
  restart ends its shells. The agent's calls are
  `POST /v1/hostexec/shells/{grant}/exec|close` (`host_shell_exec`,
  `host_shell_close`).

### 8.8 Risk summary **[decided]**

The broker calls OpenRouter (existing config, new prompt; a small model by
default, e.g. the `deepseek-v4-flash` judge already in policy) for one line
plus `low|medium|high` per run/tpl/shell request. It is advisory only and
never approves anything.

### 8.9 Execution details

- Jobs run under `systemd-run --unit=aa-job-<id> --collect --pipe --wait -p
  RuntimeMaxSec=<timeout>` (the user tier adds `--user --machine`).
- env is allowlisted by key; stdin is optional and capped.
- Default timeout is 10m, capped by local policy.

### 8.10 Direct desktop prompts **[decided: allowed, with anti-spam policy]**

**[built, as phase 9]** with these differences from the text below:

- **Every present desktop is asked, not one "active desk".** The first
  answer decides and the other dialogs are taken down.
- **Presence** comes from hooks, because Hyprland keeps no logind hints:
  `agent-auth-hostctl presence idle|active|locked|unlocked`, called from
  hypridle and around the lock screen (or `idleSource = "logind"` where a
  desktop maintains them). Unknown counts as away. hostd-user adds the
  fullscreen check (`hyprctl activewindow`).
- **Eligibility** is `desktop.agents` / `desktop.platforms` globs in the
  policy, not a per-rule `channels:` list. Sensitive requests stay on
  Discord unless `desktop.sensitive`; shells never reach a desktop.
- A hostexec request is offered only while its target tier is armed, since a
  desktop answer carries no TOTP code. The **same-host content-bound path**
  (and the polkit step for root) is still phase 8.
- Not built: coalescing ("3 requests from …"), the "Allow 30 min" button,
  and local overrides of the limits in hostd-user.
- Trust: an answer is accepted only for a prompt the broker sent to that
  host and that is still open. That still means any process running as you
  on such a desktop, and any compromised host, can approve whatever the
  policy allows on desktops.

Agents can get a human decision at your desktop without going through Discord.
This applies to any broker request (a GitHub grant, an MCP grant, a hostexec),
not only hostexec on the local host.

**Routing: where a prompt goes**

- Each hostd-user reports **presence** in its heartbeat:
  - idle seconds, via `ext-idle-notify` on Hyprland;
  - locked or unlocked;
  - a fullscreen window (games) or Do Not Disturb.
- When a request reaches `surface`, the broker picks the **active desk**: the
  desktop host whose hostd-user is unlocked and idle < 5 min, most recent
  input first.
- Policy chooses the channels per rule:
  `channels: [desktop, discord]` (default: desktop when present, else
  Discord), `[discord]`, or `[desktop]`.
- The Discord message is still posted as the record. When the desk answers,
  it is edited to "answered on excelsior's desktop".
- A desktop prompt unanswered within 90s falls back to Discord.
- When the desk is the **same host** as a hostexec target, the prompt is the
  §8.6 content-bound path, and its answer counts as local evidence.
- Elsewhere, hostd-user's answer travels back to the broker signed by that
  host's hostd-root, as `source=human, via=desktop:<host>`.
  - A desktop answer from host A **does not** satisfy host B's hostd for a
    hostexec on B. B still requires its own arming or TOTP, because B can't
    verify A's dialog.
  - The B prompt therefore shows "Approve (B is armed)" or offers a TOTP
    field, the same as Discord.

**What the dialog looks like**

- `sbx-prompt`-style: the requester label comes from the broker or hostd,
  never from agent text. It shows the platform, resource, authority, duration,
  delegator and risk summary, and the justification labelled "the agent says
  (unverified)".
- Buttons: **Allow once** · **Allow 30 min** (an approve-all window, only
  where §8.6 allows windows) · **Deny** · **Mute this agent 1h** ·
  **Send to Discord**.

**Anti-spam policy** (defaults; configured under `desktop:` in policy, with
local overrides in hostd-user):

| rule | default | effect |
|---|---|---|
| eligibility | `desktop: allow` must match the agent in policy | agents not listed never reach the desktop |
| one at a time | 1 dialog on screen | others queue for at most 30s, then go to Discord |
| coalescing | same agent + platform + resource pending | one dialog says "3 requests from claude-larder…", with Allow all / Deny all / Review on Discord |
| per-agent rate | burst 2, 6/hour | excess goes to Discord with "desktop rate-limited" |
| global rate | 20/hour | same |
| deny cooldown | after a Deny, that agent's desktop prompts pause 10 min; 3 denies in an hour mute it for 1h | stops retry loops |
| presence | not shown while locked, idle > 5 min, fullscreen, or DND | goes to Discord instead |
| quiet hours | **off** by default; optional window, e.g. 23:00–08:00 | Discord only |
| DND toggle | `agent-auth-hostctl dnd 2h`, a Hyprland keybind, `/dnd` on Discord | |

**Spoofing**:
- Agents run in the VM, which has no display access, so they can't draw
  look-alike dialogs.
- Sandboxed desktop apps reach the compositor only through
  `wp_security_context_v1`. They can't read or click the dialog, but they
  could draw a look-alike.
- The existing `sbx-prompt` limits apply: no secure-attention mechanism, and
  input synthesized by a compromised session is out of scope.

---

## 9. Kill switch **[decided, built]**

**[built]** `scope: host <h>` covers that host's hostd and the agents of its
agent VM. A daemon that was offline is locked when it reconnects. sandboxd
freezes its units and queues incoming work until unlocked. The broker also
refuses `hostexec` requests while locked. "Kill" is a button on the lockdown
message and `kill_vm` on the command.

`/lockdown [scope: all | sandboxes | host <h>]` (owner only), or `agent-auth
admin lockdown`:

- **Broker**: revokes every active grant of `*-sandbox` agents (all agents for
  `all`), refuses `agents:mint`, closes their threads.
- **hostd**:
  - disarms both tiers;
  - kills running jobs and shells;
  - sets a persistent lockdown flag;
  - **freezes the local agent VM from the host** (`systemctl freeze
    agent-vm.service`). The whole guest stops, inspectable, and nothing
    inside it is trusted to cooperate.
- **sandboxd**: also freezes its agent units, for the case where only one
  host's hostd is reachable.
- **Kill** in the Discord reply stops the VM outright.

Unlock: `/unlock` clears the broker side. Each hostd stays locked until it gets
a root **arm** TOTP (`/unlock host code`) or a local `agent-auth-hostctl
unlock`, so a compromised broker can't undo a lockdown.

---

## 10. Fleet health **[decided]**

- **Heartbeats** every 30s, carrying:
  - hostd: version, per-tier `{enabled, armed_until}`, jobs, shells,
    lockdown, agent VM state;
  - sandboxd: conversations by state, queue depth, guest load/memory/disk.
- **Surfaces**:
  - `agent-auth admin daemons` and Discord `/hosts`;
  - `GET /v1/catalog` `hosts` (online, tiers enabled, armed);
  - a Discord alert after 3 missed heartbeats.
- **[built]** hostd's status (tiers, armed-until, jobs, shells, lockdown, VM
  state, desktop presence) is in `/hosts`, `admin hosts` and the catalog.
  The missed-heartbeat alert is not built.

---

## 11. Mounts **[decided: as grants; local host first, remote later]**

Built on the existing folder-grant machinery (crosvm fs allowlist + guest
grant daemon), driven by hostd and sandboxd instead of sbx-broker and the
user hub:

1. A `mount` request goes to policy/Discord. hostd gates it like a root `run`
   (arming or TOTP); paths matched by `autoRo` can skip that.
2. hostd-root checks local policy and sends `{"AddPaths":{"paths":[rel]}}` on
   the agent VM's grants allowlist socket. The fs device runs as `jrt` and
   shares `$HOME`, uid-mapped to guest uid 1001 as in the app tier.
3. sandboxd mounts the path in the guest at
   `/var/lib/sandbox/projects/<p>/.mounts/<name>`, **id-mapped** so guest
   1001 appears as `p-<p>`.
   - `ro` is a read-only bind. As in the app tier, the share itself is rw,
     so `ro` holds only as long as VM root is honest.
   - **[verify]** idmapped mounts on virtiofs with the guest kernel
     (fallback: bindfs `--map`).
4. Revoke/expiry: sandboxd unmounts first, then hostd removes the allowlist
   entry.
   - **[verify]** whether the patched crosvm fs supports removing allowlist
     paths. Today grants can't be revoked at all (`grants.py:19-21`). If it
     doesn't, revocation is guest-side only until the VM restarts. Patching
     a `RemovePaths` into `crosvm-fs.nix` is the real fix.

Remote-host mounts (a path on a different host than the VM) are deferred
**[decided]**.

---

## 12. MCP catalog **[decided: catalog + broker proxy]**

```yaml
platforms:
  mcp:
    catalog:
      linear:
        url: https://mcp.linear.app/mcp
        auth: oauth            # broker-held refresh token (admin mcp-login)
        tools: ["*"]
        description: "Linear issues/projects"
      context7:
        url: https://mcp.context7.com/mcp
        auth: none
```

`/v1/mcp/<server>` is a streamable-HTTP proxy:
- Agents authenticate with their own key.
- The broker checks for an active `mcp` grant, filters
  `tools/list`/`tools/call` to the granted tools, injects the upstream
  credential, and logs every call.

Agents never see upstream tokens, and revocation is instant.

Upstream auth is `none`, `header` (a secret file), or `oauth`. For `oauth`,
`admin mcp-login <server>` runs PKCE with the link posted to Discord, and
the refresh token is stored Fernet-wrapped.

sandboxd writes each conversation's MCP config pointing at the proxy:
- Claude: `--mcp-config`.
- Codex: `-c mcp_servers.<n>.url=…` with a bearer env var. **[verify]**

New grants appear on the next resume, or sandboxd restarts and resumes
immediately. Local stdio MCPs (rare) run inside the project unit.

---

## 13. Changes, by repo

### agent-auth

- `core/states.py`: `Platform` += `agents`, `sandbox`, `mcp`, `hostexec`,
  `mount`.
- `authority.py`: `fold`/`split`/`label`/`is_sensitive` for those platforms.
- `models.py` + migrations:
  - agents: `parent_agent_id`, `sandbox_id`, `runtime`, `project`;
  - new tables: `daemons`, `pairing_codes`, `host_jobs`, `host_shells`,
    `daemon_controls`, `pending_key_deliveries`, `mcp_upstream_tokens`;
  - rules: `expires_at`.
- `provisioners/`: `agents.py`, `sandbox.py`, `mcp.py`, `hostexec.py`,
  `mount.py`.
- `daemons/` (new): WS endpoint, envelopes, pairing, heartbeats, control
  outbox.
- `api/`: `/v1/daemons/*`, `/v1/mcp/<server>`, catalog `hosts`, job result and
  shell exec endpoints.
- `discord_bot/`:
  - hostexec views (Approve / Approve all / TOTP / Deny / Edit);
  - loud shell embeds and mirror threads;
  - `/arm` `/disarm` `/lockdown` `/unlock` `/hosts`;
  - the risk summary field.
- `mcp_server.py`: `AGENT_AUTH_SESSION_ID`; tools `host_run`,
  `host_shell_open/exec/close`.
- Desktop notifier (`notify/desktop.py`):
  - presence tracking from hostd-user heartbeats;
  - active-desk selection, channel routing per rule (`channels:`);
  - rate limits, cooldowns, coalescing;
  - fallback to Discord, and Discord records edited with "answered on
    desktop".
- `sandboxd` operator API (conversation list/send/stream/attach) for `avm`,
  and later the web UI.
- New packages: `agent_auth.hostd`, `agent_auth.sandboxd`,
  `agent_auth.daemon_common`. hostd imports no server or DB code.
- `flake.nix`: `nixosModules.hostd`, `nixosModules.sandboxd` (guest);
  `BROKER_SIGNING_KEY` in the server module.

### nixos-dots

- `lib/vm/core/*.nix`: VMM/fs/net/relay/CID pieces extracted from
  `instance.nix`, with no behavior change for app VMs, plus a new `allowPorts`
  (nftables cgroupv2 match) on the net piece.
- `nixos/modules/system/agent-vm.nix` (`modules.agentVm.{enable, memory,
  vcpus, diskSize, network}`): host units (§3.2) plus a guest from
  `inputs.agent-auth.nixosModules.sandboxd`. CID reserved.
- `crosvm-fs.nix`: allowlist `RemovePaths`, if it's missing.
- `avm` CLI and the `avm-claude`/`avm-codex` shortcuts on hosts with an agent
  VM. Group `agent-vm-users` = `jrt`.
- `users.users.jrt.linger = true` on headless hosts whose hostd user tier is
  enabled.
- `nixos/default.nix`: import `inputs.agent-auth.nixosModules.hostd` on
  every host; `services.agent-auth-hostd` defaults (broker URL, pinned key).
  hostd-user on desktops only.
- `recusant/agent-auth.nix`: `BROKER_SIGNING_KEY` in the env secret;
  `agent-auth-policy.yaml` gets the new platforms and rules (§14).

---

## 14. Policy example

```yaml
platforms:
  agents:
    runtimes: [claude, codex]
    default_lease: 30d
  hostexec:
    templates:            # mirrored from hostd for validation/display
      nixos-rebuild: {tier: root, argv: ["nixos-rebuild", "switch", "--flake", "{flake}"]}

rules:
  - match: {agent: "orchestrator-*-sandbox", platform: agents, capability: mint}
    action: approve
  - match: {agent: "hermes-*", platform: a2a, resource: "*-sandbox"}
    action: approve
  - match: {agent: "*-sandbox", platform: sandbox, capability: project.read}
    action: llm
  - match: {agent: "*-sandbox", platform: mcp}
    action: surface
  - match: {agent: "*", platform: hostexec}
    action: surface        # root/shell are sensitive anyway; hostd gates the rest
```

---

## 15. Phases

Each phase is usable on its own and ships with tests (fake daemons over an
in-process WS, a fake runtime adapter).

1. **Daemon channel + hostd skeleton**: signing key, pairing, WS, envelopes,
   heartbeats, `admin daemons` / `/hosts`. hostd on every host, with no
   privileged actions yet.
2. **Agent VM** (nixos-dots): the `lib/vm/core` extraction (checked by
   diffing app VM units), `allowPorts`, `agent-vm.nix`, and the guest with
   persistent disk, nix overlay and userdb. Bring up on excelsior first,
   then galaxy and recusant.
3. **sandboxd**:
   - `agents:mint` and lineage, projects/users/units, Claude and Codex
     adapters, park/resume conversations, routing and triage, the sandbox
     MCP, the orchestrator, and `sandbox:project.*` grants;
   - the operator API and the **`avm` interactive CLI** (new, attach, logs,
     send). Interactive use is a requirement, so it ships with the headless
     core, not after it.
4. **hostexec `run`**: TOTP enroll, arming, local policy, Discord views
   (approve-all, TOTP), output, risk summary, templates. The **kill
   switch**, including the host-side VM freeze, lands here, before shells.
5. **Shells**: TOTP-only, loud embeds, mirror threads.
6. **MCP catalog + broker proxy** (none/header first, then OAuth).
7. **Mounts** (local host): allowlist revoke, idmapped binds.
8. **Content-bound desktop approval of hostexec** (§8.6): on the host a
   command targets, `sbx-prompt` for the user tier, and `sbx-prompt` then
   polkit `auth_admin` for root, counted by that hostd as local evidence.
   Builds on phase 9's helper.
9. **Desktop prompts on every active host** (§8.10) **[built]**:
   - hostd-user and presence (hooks, or logind);
   - the broker's desktop notifier: every present desktop is asked, the
     first answer decides;
   - the anti-spam policy.

   Built before 6–8 because it only needed the channel and hostd.

Later: the web UI (§6.8), remote-host mounts, per-project egress, and a `net`
grant platform for other tailnet services.

---

## 16. Open questions

None at the moment. Revision 3 answers on record:
- The anti-spam defaults in §8.10 are accepted, with quiet hours off by
  default.
- A desktop approval from host A is Discord-equivalent for a hostexec on host
  B (B still needs arming or TOTP).
- k3s nodes are reachable on ports 6443, 443 and 80.

The **[verify]** items are the remaining unknowns. Prototype first: resuming
`claude -p` / `codex app-server` sessions in the interactive TUIs and back
(§6.8), since interactive takeover depends on it.
