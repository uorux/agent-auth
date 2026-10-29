# Spec: paired daemons, the broker↔daemon channel, and commands on hosts (hostexec / hostd)

Behavioral specification for the Rust port. The Python is the reference; this
document says what must be reproduced, byte-exactly where peers interoperate,
and cites `file:line` for subtle points. Paths are relative to
`src/agent_auth/` unless they start with `tests/`, `docs/`, `deploy/` or
`flake.nix`.

Sources covered: `daemon_common/{crypto,channel,totp,localsock,hostexec}.py`,
`core/daemons.py`, `api/daemon_routes.py`, `core/hostexec.py`,
`api/hostexec_routes.py`, `provisioners/hostexec.py`,
`discord_bot/{hostexec,hosts}.py`, `hostd/{main,daemon,executor,config,user,asuser,ctl}.py`,
`deploy/macos/*`, `docs/hostd-macos.md`, `docs/sandbox-design.md` §7–§10,
the `nixosModules.hostd` / `darwinModules.hostd` parts of `flake.nix`, the
README sections "Paired daemons", "Commands on hosts", "Desktop prompts", and
`tests/test_{daemons,hostexec,hostd_macos}.py`. Touch points elsewhere
(`core/service.py` gates, `authority.py`, `policy/engine.py`,
`core/desktop.py`, `policy/risk.py` Watcher) are described only as far as this
subsystem depends on them.

Throughout: "broker" = the agent-auth server; "hostd" = `agent-auth-hostd run`
(root on hosts with a tier or VM configured); "hostd-user" = the desktop
helper (`agent-auth-hostd user`); "sandboxd" shares the channel code but is
out of scope here except where the hub treats roles differently.

---

## 1. Components and trust model

| component | runs as | holds | decides |
|---|---|---|---|
| broker `DaemonHub` (`core/daemons.py`) | broker | broker ed25519 signing key (`BROKER_SIGNING_KEY`), daemon public keys (DB) | who is paired; relays |
| broker `HostExecService` (`core/hostexec.py`) | broker | `host_jobs` rows, lockdown flag | bookkeeping; never whether a command runs |
| hostd (`hostd/daemon.py`) | root (or unprivileged `agent-auth-hostd` when no tier/VM) | its ed25519 identity key, 4 TOTP secrets, arm state (memory), lockdown flag (disk), local policy (nix-store JSON) | **whether anything runs** |
| hostd-user (`hostd/user.py`) | the configured desktop user | nothing | nothing (reports presence, shows dialogs) |
| hostctl (`hostd/ctl.py`) | root or the configured user | nothing | local arming/disarm/lockdown/unlock/presence/dnd |

Trust directions:
- The daemon trusts the broker only via `broker_public_key` **pinned in the daemon's own config** (`daemon_common/channel.py:5-8`). It is never learned from the network.
- The broker trusts a daemon only via the public key bound at pairing (`daemons.public_key`).
- hostd re-validates every job spec from scratch and admits it only on its own evidence (TOTP, desk approval, arm state, local policy). Broker-supplied "evidence" (`source`, `window`) is believed **only while the tier is armed** (`core/hostexec.py:241-249`, `hostd/daemon.py:375-406`).
- Residual risk, accepted by design (`docs/sandbox-design.md` §8.5): a compromised broker can attach a direct TOTP code the human typed to a different command (once per code), and while a tier is armed it can run anything in that tier. Disarmed, without codes, it can run only the user-tier `auto_commands`.

---

## 2. Cryptographic primitives and encodings (interop-critical)

All in `daemon_common/crypto.py` (line numbers below are within that file).

### 2.1 Encodings
- `b64(x)` = URL-safe base64 **without padding** (`crypto.py:76-77`).
- `unb64(s)` = append `=` padding to a multiple of 4, then URL-safe decode (`crypto.py:80-81`). Python's decoder is lenient: it also accepts `+`/`/` and silently discards non-alphabet characters. A Rust decoder should accept the URL-safe alphabet with or without padding; being stricter than Python only rejects input no honest peer produces.
- `transcript(parts…)`: for each part (str → UTF-8 bytes), emit `u32 big-endian length ‖ bytes`; concatenate (`crypto.py:84-89`). Every signed/MACed message is a transcript whose first part is a context label.

Context labels (`crypto.py:51-56`), exact ASCII bytes:
```
CTX_PAIR_KEY      = "agent-auth/v1/pair-key"
CTX_PAIR          = "agent-auth/v1/pair"
CTX_PAIR_SELECTOR = "agent-auth/v1/pair-selector"
CTX_SESSION       = "agent-auth/v1/session"
CTX_HELLO         = "agent-auth/v1/hello"
CTX_MSG           = "agent-auth/v1/msg"
```

### 2.2 Keys
- All identity keys are Ed25519.
- Private key text = `b64(32-byte seed)` (no prefix). This is the `BROKER_SIGNING_KEY` format and the content of a daemon's key file (followed by `\n`). Parsing strips whitespace and requires exactly 32 bytes (`crypto.py:110-117`).
- Public key text = `"ed25519:" + b64(32-byte raw public key)` (43 base64 chars). Parsing requires the prefix and 32 decoded bytes (`crypto.py:126-135`). NixOS option type: `ed25519:[A-Za-z0-9_-]{43}` (`flake.nix` brokerPublicKey).
- Fingerprint: `hex(sha256(raw_pub))[:32]`, split into 8 groups of 4 joined by `:` (e.g. `e6c4:3ab3:bdce:125a:f325:8d43:690e:4f1f`) (`crypto.py:138-143`).

### 2.3 Daemon key file (`load_or_create_key`, `crypto.py:146-188`)
1. `mkdir -p` parent with mode 0700.
2. If the path doesn't exist: generate a key; write `b64(seed)\n` to a temp file `.{name}.{16 hex}` in the same dir opened `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0400; fsync; `link(tmp, path)` (EEXIST = another process won; use its key) and fsync the directory on success; always unlink the temp.
3. Open `path` with `O_RDONLY|O_NOFOLLOW` (a symlink is refused, `tests/test_daemons.py:161`). `fstat`: must be a regular file, owned by the **effective** uid, and `mode & 0o077 == 0`; otherwise refuse (PermissionError). Parse as private key text.

### 2.4 Principals
- `daemon_principal(role, name) = "{role}:{name}"`, e.g. `host:excelsior`. The broker's principal is the literal `"broker"`.
- Roles: `("host", "sandbox")`. Name regex (broker, `core/daemons.py:60`): full match `[a-z0-9][a-z0-9-]{0,62}` (no trailing newline accepted: `tests/test_daemons.py:181`).

---

## 3. Pairing

### 3.1 Codes
- Alphabet `ABCDEFGHJKMNPQRSTVWXYZ23456789` (30 symbols, no I L O U 0 1); 12 symbols from a CSPRNG, formatted `XXXX-XXXX-XXXX` (14 chars) (`crypto.py:65-66, 194-199`). ≈59 bits.
- Normalization: `upper()` then keep only `isalnum()` chars (`crypto.py:202-203`). So `abcd efgh-ijkl` ≡ `ABCD-EFGH-IJKL`. (Python's `upper`/`isalnum` are Unicode-aware; codes are ASCII, so an ASCII-only normalization is equivalent for every valid code.)
- `pairing_key(code) = SHA256(CTX_PAIR_KEY ‖ normalized_code_utf8)` — plain concatenation, **not** a transcript (`crypto.py:206-208`). 32 bytes.
- `selector = hex(HMAC-SHA256(key, CTX_PAIR_SELECTOR))[:32]` (`crypto.py:211-216`) — lowercase hex, first 16 bytes.
- `daemon_proof = hex(HMAC-SHA256(key, transcript(CTX_PAIR, "daemon", role, name, daemon_pub_text)))` (`crypto.py:219-222`).
- `broker_proof = hex(HMAC-SHA256(key, transcript(CTX_PAIR, "broker", role, name, daemon_pub_text, broker_pub_text)))` (`crypto.py:225-232`).
- Proof comparison: constant-time over the UTF-8 bytes; non-string → false (`crypto.py:235-241`).

### 3.2 Issuing (admin)
`POST /admin/daemons/pairing-codes {role, name}` (admin bearer) → `DaemonHub.create_pairing_code` (`core/daemons.py:245-271`):
- 503 if no `BROKER_SIGNING_KEY`; 400 if role/name invalid.
- In one transaction: mark every unused code for (role, name) used (`used_at = now`) — **only the newest code is live** — and insert `{role, name, pairing_key: hex(key), expires_at: now + DAEMON_PAIRING_CODE_TTL_SECS (600), failed_attempts: 0}`. The code itself is never stored; the HMAC key is (so DB read access during a code's lifetime is enough to pair; accepted, `models.py` comment on `pairing_key`).
- Response `{role, name, code, expires_at, broker_public_key}`. CLI: `agent-auth admin daemon-pair <name> [--role host|sandbox]` prints code, expiry and the broker key fingerprint.

### 3.3 `POST /v1/daemons/pair` (unauthenticated; `api/daemon_routes.py`, `core/daemons.py:273-364`)
Body (pydantic, else 422): `role` ≤16 chars, `name` ≤128, `public_key` ≤128, `selector` matches `^[0-9a-f]{32}$`, `proof` matches `^[0-9a-f]{64}$`.
1. 503 if daemons disabled. 400 if role/name invalid or public key unparseable.
2. Select the newest code row with this (role, name), `used_at IS NULL`, `expires_at > now`, `failed_attempts < DAEMON_PAIRING_MAX_ATTEMPTS (5)`.
3. If none, or `selector` ≠ `pairing_selector(key)` (constant-time) → **403** with the single message `PAIRING_REFUSED` = `"pairing refused: no pending code for this daemon matches (expired, used, or wrong code)"`. A wrong selector spends **no** attempt (`tests/test_daemons.py:293`).
4. Spend an attempt atomically **before** checking the proof: `UPDATE … SET failed_attempts = failed_attempts + 1 WHERE id = ? AND used_at IS NULL AND failed_attempts < max`; rowcount ≠ 1 → 403 (`core/daemons.py:309-320`). Concurrent wrong proofs therefore evaluate at most `max` proofs (`tests/test_daemons.py:308`).
5. Wrong proof → commit the spent attempt, then 403 (same message) (`core/daemons.py:321-322, 342-344`).
6. Right proof → `UPDATE … SET used_at = now WHERE id = ? AND used_at IS NULL` (rowcount ≠ 1 → 403); upsert `daemons` row (new: `paired_at = now`; existing: replace `public_key`, `paired_at = now`, `last_status = NULL`). Note a successful pairing leaves `failed_attempts` incremented by one; harmless.
7. After commit: `_kick(role, name, "re-paired")` (bump generation, close any live connection with 4409); run `on_paired` hooks (errors logged, swallowed).
8. 200 `{broker_public_key, proof: broker_proof, fingerprint: fingerprint(daemon_pub)}`.

Every refusal (unknown daemon, expired, used, burned, wrong selector, wrong proof) returns the identical 403 body (`tests/test_daemons.py:273-291`).

### 3.4 Daemon side (`daemon_common/channel.py:94-131`)
- Code source: env `AGENT_AUTH_HOSTD_PAIRING_CODE`, else stdin (`pair -`), else a hidden prompt. **Never argv**: any positional other than `-` is refused with exit 2 (`hostd/main.py:103-124`).
- POST the body above to `{broker_url without trailing /}/v1/daemons/pair` (timeout 30 s).
- Non-200 → fail with status and `detail`. Non-object JSON → fail. `broker_public_key` ≠ pinned → fail ("not trusting it"). `broker_proof` ≠ expected (constant-time) → fail.
- On success hostd writes `{state_dir}/paired.json` `{role, name, broker_url, broker_public_key, paired_at (ISO UTC)}` (indent 2) and prints both fingerprints. `run` only warns if `paired.json` is missing.

### 3.5 Unpair
`DELETE /admin/daemons/{id}` → delete the row, mark all unused codes for that (role, name) used (a leaked code can't re-pair), `_kick(…, "unpaired")` (`core/daemons.py:366-385`). 404 if unknown.

Other admin: `GET /admin/daemons` → list of `{id, role, name, fingerprint, online, paired_at, last_seen_at, version, status}` ordered by role, name; `GET /admin/broker-key` → `{broker_public_key}` or 503.

---

## 4. The channel

### 4.1 Transport
- Daemon dials `wss://…/v1/daemons/connect` (`ws://` only when the broker URL is plain http to a loopback host). URL check (`channel.py:59-67`): scheme `https` with a non-empty hostname, or `http` with hostname exactly `localhost`, `127.0.0.1` or `::1`; otherwise refuse at identity construction. Envelopes are signed, **not encrypted**; confidentiality is TLS's.
- ws URL: strip trailing `/`, `https://`→`wss://`, `http://`→`ws://`, append `/v1/daemons/connect` (`channel.py:134-140`).
- Daemon websocket options: open timeout 15 s, protocol pings every 20 s with 20 s pong timeout (`channel.py:172-177`). Default max frame (python `websockets`) is 1 MiB; the largest frame in practice is a 96 KiB output chunk double-base64'd inside an envelope (~175 KB). The Rust client must allow ≥1 MiB.
- Pre-hello frames are plain JSON text frames; post-hello frames are envelope text frames.

### 4.2 Handshake
```
broker → {"type":"challenge","nonce": bn}
daemon → {"type":"hello","role","name","nonce": dn,"params": P_d,"sig": S_d}
broker → {"type":"welcome","params": P_b,"sig": S_b}
```
- Nonces: `b64(32 random bytes)` (`crypto.py:247-248`).
- `hello_transcript(speaker, role, name, bn, dn, params) = transcript(CTX_HELLO, speaker, role, name, bn, dn, params)`; `speaker` ∈ {`"daemon"`, `"broker"`} so a welcome can't be reflected as a hello. Signature = `b64(ed25519_sign(transcript))`.
- `P_d` is a JSON **string** (signed as the exact string sent): Python sends `json.dumps({"version": VERSION})` (default separators `", "`/`": "`). `P_b` = `json.dumps({"heartbeat_secs": DAEMON_HEARTBEAT_SECS})`.
- `session_id = SHA256(transcript(CTX_SESSION, role, name, bn, dn))` — 32 raw bytes (`crypto.py:261-266`).

Broker side (`core/daemons.py:389-518`):
1. Accept the WS. No signing key → close 4503 "daemon channel disabled".
2. If ≥ 32 handshakes are pending (`MAX_PENDING_HANDSHAKES`) → close 1013 "too many pending handshakes". Otherwise hold a slot for the duration of the handshake.
3. Send challenge; wait ≤ 10 s (`HELLO_TIMEOUT_SECS`) for a JSON object with `type=="hello"` whose `role`, `name`, `nonce`, `sig`, `params` are all strings and role/name valid. Any failure (timeout, bad JSON, missing key, wrong type, disconnect) → close **4400** "bad hello".
4. Read the identity's current in-memory **generation** (before any DB await).
5. Load the `daemons` row; verify `S_d` over `("daemon", role, name, bn, dn, P_d)` against its public key. Unknown daemon or bad signature → close **4401** "not paired or bad signature".
6. On success, in the same transaction set `last_seen_at = now` and, if `json.loads(P_d).version` passes `VERSION_RE` (`[0-9A-Za-z.+_-]{1,64}`, full match), `version`.
7. Send welcome with `S_b` = sign `("broker", role, name, bn, dn, P_b)`. Send failure → drop silently.
8. After releasing the handshake slot: if the current generation ≠ the one read in step 4 (re-paired/unpaired meanwhile) → close **4409** "re-paired or unpaired during handshake" (`core/daemons.py:402-408`). This check and the registration below must be atomic with respect to `_kick` (Python: no await in between; Rust: one lock).
9. Register as the live connection for (role, name); an existing one is closed with **4409** "replaced by a newer connection" (`tests/test_daemons.py:565`). Spawn `on_connect` hooks (background, errors logged).

Daemon side (`channel.py:200-265`):
1. Wait ≤ 15 s for the first frame; must be an object with `type=="challenge"` and string `nonce`, else `HandshakeRejected("malformed handshake")`.
2. Send hello (fields above).
3. Wait ≤ 15 s for the welcome; must be a JSON object. If the connection closes with code **4401** → `HandshakeRejected` (not paired / key replaced). Other closes propagate as connection errors.
4. Require `type=="welcome"`, string `params`, and `S_b` verifying under the **pinned** broker key over `("broker", role, name, bn, dn, P_b)`; else `HandshakeRejected("broker did not prove possession of the pinned key")`.
5. Heartbeat interval = `clamp(int(json.loads(P_b)["heartbeat_secs"] default 30), 5, 300)`; any parse error → 30.

Close codes: 4400 bad hello / bad envelope / heartbeat timeout; 4401 unauthorized (unknown, bad sig, or key changed while connected); 4409 replaced / re-paired / unpaired; 4503 disabled; 1013 try again.

### 4.3 Envelopes (`crypto.py:288-381`)
Wire form (a text frame): `{"p": b64(P), "s": b64(sig)}` where
- `P` = UTF-8 JSON of the body. Python produces `json.dumps(body, separators=(",",":"), sort_keys=True, allow_nan=False)` (ASCII-escaped). **Verification is over the received bytes of P**, so the receiver never re-canonicalizes; senders need not reproduce Python's formatting, only valid JSON.
- `sig = ed25519_sign(transcript(CTX_MSG, session_id_32_bytes, P))`.
- `body = payload ∪ {id: uuid4 hex, iss: sender principal, aud: recipient principal, seq: int, iat: unix float secs, exp: iat + ttl}`. These six keys **overwrite** same-named payload keys (`crypto.py:300-301`); no message type uses them.
- Default ttl 60 s; `DaemonHub.call` uses ttl = its timeout.

Sealer (one per direction per connection): `seq` starts at 1 and increments by 1 per sealed message. Concurrent senders must seal **and** send under one lock so the wire order equals seq order (`channel.py:306-315`, `core/daemons.py:577-578`).

Verifier (one per direction per connection), in this order (`crypto.py:353-381`):
1. Outer JSON with `p`, `s` decodable → else "malformed envelope".
2. Signature over `transcript(CTX_MSG, session_id, P)` under the peer key → else "bad signature".
3. Parse `P` rejecting `NaN`/`Infinity` literals; require `id` (string), `iss`, `aud`, `seq` (an integer, **not** a boolean), `iat`, `exp` (convertible to finite floats) → else "malformed envelope body". (Python's `float()` would also accept numeric strings; Rust may require JSON numbers.)
4. `iss == expected sender` and `aud == expected audience` → else "not for this channel". Broker→daemon: iss `broker`, aud `role:name`. Daemon→broker: iss `role:name`, aud `broker`.
5. `seq > last_seq` (strictly increasing; gaps allowed) → else "replayed or reordered envelope".
6. `iat ≤ now + 30` (`MAX_CLOCK_SKEW_SECS`) → else "issued in the future".
7. `exp ≥ now` → else "expired". (No skew allowance on expiry.)
8. `exp − iat ≤ 3600` (`MAX_ENVELOPE_TTL_SECS`) → else "lifetime too long".
9. Only now set `last_seq = seq`; return the body (including the six envelope keys).

On any verifier error: the broker closes with 4400 "bad envelope" (`core/daemons.py:435-446`); the daemon logs and drops the connection, then reconnects after ~1 s (`channel.py:282-286`).

### 4.4 Liveness and reconnect
- Daemon heartbeat task: immediately on connect, then every interval, send `{"type":"heartbeat","status": status()}` where `status()` exceptions become `{"error":"status unavailable"}` and `version` is defaulted in (`channel.py:295-304`).
- Broker idle timeout: no frame for `DAEMON_HEARTBEAT_SECS × 3` (90 s default) → close 4400 "heartbeat timeout" (`core/daemons.py:422-434`).
- Broker heartbeat handling (`core/daemons.py:523-549`): ignore (no DB write) if the previous write for this connection was < `heartbeat_secs / 2` ago (monotonic). Else: status must be a dict whose `json.dumps` length ≤ 16384 (`MAX_STATUS_BYTES`), otherwise store `{"error":"status missing or too large"}`. Load the row; if gone or its `public_key` ≠ the key this connection authenticated with → remove from live map, close **4401** "no longer paired with this key", stop. Else set `last_seen_at`, `last_status`, and `version` (if `status.version` passes `VERSION_RE`). Spawn `on_heartbeat` hooks. `last_status` is informational only and must never feed an authorization decision on the broker side, except as noted in §10.1 (early refusal of disabled tiers).
- Daemon reconnect loop (`channel.py:167-198`): `backoff` starts at 1. Each iteration: `delay = backoff`; connect + handshake; on success `backoff = 1`, run the session; a session that ends normally sets `delay = 1`. `HandshakeRejected` → `delay = 300`. Network/WS errors and any other exception → `backoff = min(2·backoff, 60)` (delay stays the value captured at the top). Sleep `delay × U(0.8, 1.2)`. The daemon never exits on broker misbehavior.

### 4.5 Message dispatch, `call`/`reply`
- Broker (`core/daemons.py:520-563`): `heartbeat` (above); `reply` → resolve the pending call whose `call_id` matches **and** whose recorded target is this connection's (role, name), if not already resolved; registered handler types (`job.output`, `job.done`, `presence`, `prompt.answer`, plus sandbox types) → await handler inline, exceptions logged; anything else ignored. Handler registration refuses `heartbeat`, `reply` and duplicates.
- `DaemonHub.call(role, name, payload, timeout=30)`: `call_id = uuid4 hex`; send `{**payload, call_id}` with ttl = timeout; offline → `DaemonCallError("<p> is offline")`; no reply in time → `DaemonCallError("<p> did not answer within Ns")`; reply `ok` false → `DaemonCallError(error[:500] or "refused by the daemon")`; else return `data` if a dict, else `{}`.
- `DaemonHub.send` returns false if offline or the send raises.
- hostd (`hostd/daemon.py:266-297`): dispatch by `type` (§5.1); unknown types ignored (no reply). Handler result → `{"ok":true,"data": result or {}}`; `Refused`/`SpecError`/`TotpError` → `{"ok":false,"error": str}`; other exceptions → `{"ok":false,"error":"hostd error: …"}`. A reply `{"type":"reply","call_id",…}` is sent **only if** the message carried a truthy `call_id`.
- Handlers run inline in the receive loop on both sides: a slow handler delays every later message on that connection (see §17).

### 4.6 Generations (in-memory, `core/daemons.py:136-140, 584-588`)
`_kick(role, name)` increments the identity's generation and closes the live connection (4409). Called on re-pair and unpair. The generation map and the live map are process-local: the broker must be a single process (or these must move to shared state).

---

## 5. Message catalog

All payloads below are the envelope body minus the six envelope keys. `call` = sent with `call_id` and answered with `reply`.

### 5.1 Broker → hostd

| type | how | fields | hostd reply `data` |
|---|---|---|---|
| `hostexec.precheck` (job) | call 20 s | `spec` (job spec), `source` ∈ human/rule/llm/policy, `totp` (bool), `job_id`? , `window`? (bool) | `{"via": …}` |
| `hostexec.precheck` (shell) | call 20 s | `kind:"shell"`, `tier`, `duration` (int s) | `{"needs":"totp"}` |
| `hostexec.authorize` | call 20 s | `job_id`, `tier`, `digest` (64 lowercase hex), `totp` (code string) | `{"authorized": true}` |
| `job.start` | call 20 s | `job_id`, `spec`, `evidence {request_id, decided_by, source, window}` | `{"started": true, "via": …}` |
| `job.kill` | call 10 s | `job_id` | `{"killed": bool}` |
| `job.ack` | send | `job_id` | — |
| `shell.open` | call 20 s | `shell_id`, `spec` (shell spec) | `{"expires_at": float}` |
| `shell.exec` | call 20 s | `shell_id`, `job_id`, `spec` (run spec) | `{"started": true}` |
| `shell.close` | call 10 s, or send (on connect) | `shell_id` | `{"closed": bool}` |
| `arm` | call 20 s | `tier`, `duration` (string like `"30m"` or int), `totp` | `{"armed_until": float}` |
| `disarm` | call 20 s | `tier` (user/root/null) | `{"disarmed": true}` |
| `lockdown` | call (5 s sandboxes / 20 s hosts), or send (on connect) | `kill_vm` (bool) | `{"locked": true, "vm": str|null}` |
| `unlock` | call 20 s | `totp` (root-arm code) | `{"locked": false, "vm": str|null}` |
| `dnd` | send | `duration` (int s or null) | `{"dnd_until": float|null}` |
| `prompt` | call 10 s | `prompt_id`, `request_id`, `who`, `what`, `detail`, `timeout`, `job`? `{job_id, spec}` | `{"shown": true, "approves": bool}` |
| `prompt.cancel` | send | `prompt_id` | `{}` |
| `notify` | call 10 s or send | `title`, `text`, `urgency` | `{"shown": true}` |

### 5.2 hostd → broker

| type | fields |
|---|---|
| `heartbeat` | `status` = hostd `status()` (§8.13) |
| `reply` | `call_id`, `ok`, `data` or `error` |
| `job.output` | `job_id`, `seq` (0-based chunk index), `data` (**standard** base64 with padding of ≤ 96 KiB raw) |
| `job.done` | `job_id`, `exit_code` (int|null), `error` (str|null), `duration_secs` (float rounded to ms |null), `bytes`, `sha256` (hex of the whole kept output), `truncated` (bool) |
| `presence` | `enabled`, `present`, `away_reason`, `dnd_until` (the `desktop` part of status) |
| `prompt.answer` | `prompt_id`, `answer` ∈ allow/deny/mute/discord/timeout, `authorized` (bool) |

Note the two base64 flavours: crypto fields are URL-safe unpadded; job output (`job.output.data`, spool `output`) is standard padded base64, decoded by the broker with strict validation (`core/hostexec.py:348`).

---

## 6. Job specs, digest, templates, patterns (`daemon_common/hostexec.py`)

### 6.1 Limits (`hostexec.py:26-37`)
`TIERS=("user","root")`, `KINDS=("run","tpl","shell")`, `MAX_ARGS=256`, `MAX_ARG_BYTES=16384`, `MAX_ARGV_BYTES=65536` (sum of UTF-8 lengths), `MAX_STDIN_BYTES=65536`, `MAX_ENV_VARS=32`, `MAX_OUTPUT_BYTES=1048576`, `OUTPUT_CHUNK_BYTES=98304`, `DEFAULT_TIMEOUT_SECS=600`, env key regex `[A-Za-z_][A-Za-z0-9_]{0,63}`, template name regex `[a-z0-9][a-z0-9._-]{0,62}` (full matches).

### 6.2 `make_spec` (`hostexec.py:103-138`) — canonical run/tpl spec
Validation (each failure raises `SpecError` with the quoted message family):
- `kind` ∈ KINDS; `tier` ∈ TIERS (`tier must be "user" or "root"`).
- `tpl`: `template` matches the name regex; `params` is an object of string→string with no NUL and each value ≤ 4096 chars; stored sorted by key. No `argv` key.
- `run` (or any kind with `argv` given): argv non-empty list, ≤256 items, each a string without NUL, ≤16 KiB UTF-8, total ≤64 KiB, `argv[0]` non-empty.
- `cwd`: `None`/`""` → null; else string starting with `/`, no NUL, ≤4096 chars; stored **POSIX-normalized** (`os.path.normpath`: collapses `.`, `..`, duplicate slashes; note POSIX normpath keeps a leading `//` exactly as `//`).
- `env`: `None`/`{}` → `{}`; else object of ≤32 entries, keys match the env regex, values strings without NUL or `\n`, ≤4096 chars; stored sorted by key.
- `timeout`: `None` → 600; else an integer (not bool) in 1..=86400.
- `stdin`: `None` or a string ≤ 65536 UTF-8 bytes.

Result key set: `kind, host, tier, [template, params] | [argv], cwd, env, timeout, stdin` (cwd/stdin may be null; env may be `{}`).

`shell_spec(host, tier, duration)` = `{"kind":"shell","host","tier","duration"}`; duration must be a positive int (not bool).

### 6.3 Digest (`hostexec.py:150-153`) — interop-critical
`digest(spec) = hex(SHA256(json.dumps(spec, sort_keys=True, separators=(",",":"), ensure_ascii=True)))`.
Rust must reproduce Python's serialization exactly: keys sorted by Unicode code point at every level; no whitespace; strings escaped as Python does with `ensure_ascii=True` (`\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, other C0 controls as `\u00XX` lowercase hex, every non-ASCII char as `\uXXXX` lowercase hex with UTF-16 surrogate pairs for astral chars; `/` not escaped; DEL 0x7f emitted raw); integers in decimal; `null`, `true`, `false`. Specs contain only strings, ints, null, objects and arrays. The broker computes the digest it sends in `hostexec.authorize`; hostd computes `digest(raw)` over the **raw spec dict exactly as received** in `job.start` (not over its normalized form) and over its own canonical `shell_spec(...)` for shells. If both sides are Rust, consistency is still required between gate-time and start-time specs (§10.3).

### 6.4 Templates (`hostexec.py:156-172`)
Host template: `{"tier", "argv": [...with {name} placeholders], "params": {name: regex}}`.
1. The set of given param names must equal the set of the template's names, else `template takes exactly these parameters: …`.
2. Each value must **fully** match its regex (Python `re.fullmatch`), else `parameter 'x' does not match the template's pattern`.
3. Each argv element: replace every `\{([a-z0-9_]+)\}` with the param value if that name is a param, else leave it; one pass (substituted values are not re-expanded). Substitution can be inside an argument (`"name={device}"`), but can never add or split arguments, and nothing goes through a shell.
Regex dialect: Python `re`. Rust's `regex` lacks backreferences/lookaround; templates in configs must stay within the common subset, or use `fancy-regex`. Config loading compiles every template regex and fails on error (`hostd/config.py:218-219`).

### 6.5 argv patterns (`hostd/config.py:231-246`)
`match_argv(pattern, argv, loose_program=false)`: if the last pattern element is exactly `"**"`, it matches zero or more further args and the rest are "fixed"; otherwise lengths must be equal. Each fixed element is an `fnmatchcase` glob for one argument (`*` matches any chars including `/`, `?` one char, `[seq]`, `[!seq]`; case-sensitive; no escaping beyond `[]`). With `loose_program`, element 0 also matches against `basename(argv[0])`. Deny patterns use `loose_program=true`; auto patterns use `false`.

### 6.6 Durations (`hostd/config.py:50-61`)
`duration_secs(v)`: bool → error; int → must be > 0; else `str(v).strip().lower()` must fully match `(\d+)([smhdw]?)` with value > 0; units s=1, m=60, h=3600, d=86400, w=604800, none=1.

---

## 7. TOTP (`daemon_common/totp.py`)

- RFC 6238: HMAC-SHA1, 6 digits, 30 s step, T0 = 0. `code_at(secret, step)`: key = base32-decode(`secret.upper()` padded with `=` to a multiple of 8); `HMAC-SHA1(key, step as u64 BE)`; dynamic truncation (`offset = last_byte & 0x0F`; 31-bit BE int at offset) mod 10^6, zero-padded (`totp.py:47-52`). RFC test vector: secret `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, step 1 → `287082`.
- Secrets: 20 CSPRNG bytes, base32 (32 chars, no padding). Four per host: `user-arm`, `user-direct`, `root-arm`, `root-direct` (`totp.py:28`); any other name → `TotpError("unknown TOTP secret …")`.
- Storage: `{state_dir}/totp/{name}` (secret + `\n`, created `O_EXCL|O_NOFOLLOW` mode 0400, dir 0700) and `{state_dir}/totp/{name}.state` (JSON, written via `.{name}.state.tmp` + rename, mode 0600). `enroll(name, replace)` refuses an existing secret unless `replace` (then unlinks it first) and deletes the state file.
- `otpauth://totp/{percent-encode("agent-auth:{host} {name}", safe="/")}?secret={S}&issuer=agent-auth&digits=6&period=30` (`:` → `%3A`, space → `%20`).

`verify(name, code, now)` (`totp.py:107-135`), exactly:
1. Read the secret; missing → `no {name} secret on this host (run totp-enroll)`.
2. Read state (missing/corrupt/non-object → `{}`). If `locked_until > now` → `too many wrong codes; {name} is locked for Ns` (does **not** count as a failure).
3. `code` := the digits of `str(code)` only.
4. For step in `current−1, current, current+1` (`current = floor(now/30)`): if `len(code)==6` and constant-time equal to `code_at(step)`, `matched = step` (the highest matching step wins).
5. No match: `failures += 1`; if `failures ≥ 5` then `failures = 0`, `locked_until = now + 300`; write state (keeping other keys, incl. `last_step`); raise `wrong code`.
6. `matched ≤ state.last_step` (default −1) → raise `that code was already used; wait for the next one` (not a failure; state unchanged).
7. Write state `{"last_step": matched, "failures": 0}` (drops `locked_until`) **before** returning, so the caller acts only on a persisted acceptance.

Consequences: each code is single use, and after accepting step s no code for any step ≤ s is accepted. Verification of one secret must be serialized (Python is single-threaded; Rust needs a per-secret mutex around steps 2–7).

CLI `agent-auth-hostd totp-enroll [--rotate NAME] [--config] [--state-dir] [--qrencode]`: requires euid 0; enrolls every missing secret (or the one rotated); prints a QR (`qrencode -t ANSIUTF8 <uri>`, falling back to text), the secret and the URI, once.

---

## 8. hostd: the decision logic (`hostd/daemon.py`)

### 8.1 State
- `armed_until: {"user": 0.0, "root": 0.0}` — **memory only**; a restart disarms.
- `authorizations: {job_id → Authorization{digest, expires_at, via ∈ "totp"|"desk", tier}}` — memory only, TTL 300 s (`AUTHZ_TTL_SECS`); expired entries are pruned whenever one is added.
- `jobs: {job_id → RunningJob{tier, task, shell_id?, killed, chunks}}`; `shells: {shell_id → Shell{tier, expires_at, timer}}` — memory only; a restart ends shells.
- Lockdown: the file `{state_dir}/lockdown` (`{"at", "via"}`); `locked_down` ⇔ the file exists. Survives restarts.
- Spool `{state_dir}/jobs/{job_id}.json` (§9).
- Desk prompts `{prompt_id → DeskPrompt{job_id, digest, tier, message}}`, presence (§8.11).

### 8.2 Validators
- `_tier(t)`: `t` ∈ TIERS else `Refused("tier must be user or root")`; tier enabled in config else `Refused("the {tier} tier is not enabled on {name}")`.
- `_job_id(v)`: string fully matching `[0-9a-f-]{8,64}` else `Refused("malformed job id")`. Also used for `shell_id` and `prompt_id`. (This is what keeps spool paths safe.)

### 8.3 `_normalize(raw, shell_command=false)` (`daemon.py:313-355`)
Re-validates a broker spec from scratch:
1. `raw` must be an object; `raw.host == config.name` else `Refused("that job is for 'X', this is NAME")`; `raw.kind` ∈ {run, tpl} else `Refused("not a runnable job")`.
2. `spec = make_spec(kind, host=config.name, tier, argv, template, params, cwd, env, timeout = raw.timeout or config.default_timeout_secs, stdin)` — `SpecError` propagates.
3. `tpl`: refused inside a shell (`templates don't run inside a shell`); the template must exist **in hostd's own config** (`no template 'x' on NAME`), its tier must equal the spec tier (`template 'x' is a T-tier template`), and `spec.argv = expand_template(host_template, spec.params)`. The broker's mirror of templates is for display only.
4. `_tier(spec.tier)`.
5. `spec.timeout > config.max_timeout_secs` → `Refused("timeout exceeds this host's maximum (Ns)")`.
6. Any env key not in `config.env_allow` → `Refused("environment variables not allowed on this host: A, B")` (sorted).
7. Any `deny_commands` pattern matching `spec.argv` with `loose_program=true` → `Refused("that command is denied by this host's policy")`.

### 8.4 `_admit(job_id, raw, spec, evidence)` — §8.5 of the design, in order (`daemon.py:375-406`)
1. Locked down → `Refused("{name} is locked down")`.
2. **Take** (pop) `authorizations[job_id]`; if it exists, is unexpired, its `digest == digest(raw)` and its `tier == spec.tier` → admit with `via = authz.via` ("totp" or "desk"). The entry is consumed even when it doesn't match.
3. `spec.kind == "run"` and `tier == "user"` and some `auto_commands` pattern matches argv (strict program match) → `"auto"`. (No evidence needed at all.)
4. `evidence.source` ∉ {human, rule, llm, policy} → `Refused("no approval evidence")`.
5. If the tier is armed (`armed_until[tier] > now`):
   - `evidence.window` truthy → `"armed+window"` if `tiers[tier].accept_approve_all`, else `Refused("{name} does not accept approve-all windows for the {tier} tier")`;
   - `source == "human"` → `"armed+human"`;
   - `accept_machine_approvals` → `"armed+{source}"`;
   - else `Refused("{name} only accepts a human's approval for the {tier} tier (this one came from {source})")`.
6. Else `Refused("not_armed: the {tier} tier of {name} is not armed — arm it (/arm) or approve with a TOTP code")`. The prefix `not_armed` is relied on by tests and UI.

### 8.5 `hostexec.precheck` (`daemon.py:408-436`) — consumes nothing
- Shell form (`kind == "shell"`): `_tier(tier)`; shells enabled for the tier else `Refused("{tier} shells are not enabled on {name}")`; locked → refuse; if `duration` is an int > `shell_max_duration_secs` → `Refused("a {tier} shell on {name} lasts at most Ns")`; reply `{"needs":"totp"}`.
- Job form: `_normalize(spec)` (all refusals above apply, so a denied command is refused **before** a TOTP code is spent on it, `tests/test_hostexec.py:512`). If `totp` truthy: refuse if locked, else `{"via":"totp"}` (the code is not checked here). Else if `job_id` is a string and not locked and a matching authorization exists (peek, not take) → `{"via": that.via}`. Else `{"via": _admit("precheck", raw, spec, {source, window})}` — the stand-in id `"precheck"` never has an authorization.

### 8.6 `hostexec.authorize` (`daemon.py:438-455`)
`_job_id`, `_tier(tier)`, digest must match `[0-9a-f]{64}` (full) else `Refused("malformed digest")`, refuse if locked, then `totp.verify("{tier}-direct", code)` (audit `totp.refused` and re-raise on failure), then record `Authorization(digest, now+300, "totp", tier)` under `job_id` (replacing any previous one) and audit `totp.accepted`. **The authorization's tier is the tier of the secret that verified the code**; `_admit` and `_shell_open` require it to equal the job's/shell's tier, so a user code relayed for a root digest authorizes nothing (`tests/test_hostexec.py:470`).

### 8.7 `job.start` (`daemon.py:459-473`)
`_job_id`; refuse `that job already ran here` if the id is running or has a spool file; `evidence` = the message's `evidence` if a dict else `{}`; `_normalize` + `_admit` (refusals audited as `job.refused` with evidence and the spec, stdin replaced by `<N chars>`); audit `job.admitted {via, evidence, spec}`; launch (§9); reply `{"started": true, "via": via}`.

### 8.8 `job.kill`
`_job_id`; if running: mark `killed`, audit, `executor.kill(job_id, tier)`; reply `{"killed": bool}`.

### 8.9 Shells (`daemon.py:628-700`)
- `shell.open`: `_job_id(shell_id)`; `spec` must be a dict for this host else `Refused("malformed shell request")`; `shell_spec(name, raw.tier, raw.duration)` (SpecError propagates); `_tier`; then, refusals audited as `shell.refused`: locked; shells disabled for the tier; `duration > shell_max_duration_secs`; and **take** the authorization for `shell_id` requiring `digest == digest(canonical shell_spec)`, matching tier, unexpired **and `via == "totp"`** — else `Refused("a shell is opened with a TOTP code only")`. Desk approvals, arming, windows and rules never open a shell. Record `Shell(tier, expires_at = now + duration)` with a timer that ends it at expiry; audit `shell.open`; reply `{"expires_at"}`. The broker can end a shell but never extend it.
- `shell.exec`: `_job_id` both ids; refuse if the job id ran already; then (refusals audited `shell.exec.refused`): locked; the shell must exist with `expires_at > now` (`no such shell on this host (expired, closed, or hostd restarted)`); `_normalize(spec, shell_command=true)` (tpl refused, deny list applies, tier must be enabled, env allowlist, max timeout); `spec.tier == shell.tier` else `that is a T shell`. No `_admit`: the shell's opening was the approval. Audit `shell.exec` **before** launching; launch with `shell_id`; reply `{"started": true}`.
- `_end_shell(id, why)`: remove the shell, cancel its timer (unless it is the caller), kill every running job of that shell, audit `shell.close`. `shell.close` replies `{"closed": bool}`.

### 8.10 Arming, lockdown, unlock
- `arm(tier, seconds, via)`: `_tier`; refuse if locked; `armed_until[tier] = now + min(seconds, tiers[tier].max_arm_secs)`; audit; return the new `armed_until`.
- `disarm(tier|None)`: set the tier (or both) to 0; never refused; needs no proof.
- Remote `arm`: `_tier`; `seconds = duration_secs(duration or max_arm_secs)`; `totp.verify("{tier}-arm", code)`; then `arm(…, "totp via the broker")`. (The code is spent before the lockdown check; §17.)
- Remote `disarm`: tier if in TIERS else both.
- `lockdown(via, kill_vm)`: write the lockdown file (dir 0700); disarm both; clear all authorizations and desk prompts; end every shell; kill every job; if `vm_unit`: `executor.unit_action("stop" if kill_vm else "freeze", vm_unit)` and report `"{action}: ok"` or `"{action}: {output or code}"`; audit; return `{"locked": true, "vm"}`. Remote lockdown needs no proof (it only removes authority).
- `unlock(via)`: remove the lockdown file; if `vm_unit`, `thaw` it; audit; return `{"locked": false, "vm"}`. Remote unlock requires `totp.verify("root-arm", code)` first. Locally only uid 0 may unlock. Unlocking does **not** arm.
- VM watcher (if `vm_unit`): every 30 s, `is-active` → `vm_state` = first output line, or `active`/`unknown` by exit code; reported as `"frozen"` when locked down and active; exceptions → `unknown`.

### 8.11 Desktop: presence and desk prompts
Presence (`daemon.py:100-115, 203-228`): `away_reason()` returns None (present) or the first of: desktop prompts off; helper not connected; DND active (`dnd_until > now`); `fullscreen` (busy); lock state (explicit hostctl report wins over the helper's) unknown → away, locked → away; idle: explicit report wins (`now − idle_since` if explicitly idle, else 0), else helper-reported `idle_secs + (now − reported_at)`, else unknown → away; idle > `max_idle_secs` → away. **Unknown counts as away.** Explicit flags and `idle_since` persist in `{runtime_dir}/presence.json` (survives hostd restarts, not reboots).

`prompt` (`daemon.py:1002-1026`): `_job_id(prompt_id)`; not present → `Refused("nobody is at this desktop")`. `who/what/detail` are collapsed to one line (`" ".join(s.split())`) and truncated to 120/600/800 chars. If `job` is present (a command at **this** host's desk), `_desk_job` (`daemon.py:974-1000`): `_job_id(job.job_id)`, `_normalize(job.spec)`, refuse if locked; `what` is rebuilt from what hostd would run: `run on {name} as {ROOT|user}: {shlex.join(argv)}` plus extras `in {cwd}`, `env K=V …`, `with N chars on stdin`; if `desktop.approve.{tier}` is on, register `DeskPrompt(job_id, digest(raw spec), tier, "{who} asks to {what}"[:700])`; else if the tier is not armed → `Refused("the {tier} tier is not armed, and this desk doesn't approve {tier} commands")`. Then write `{"type":"prompt","id","who","what","detail","timeout": min(int(msg.timeout or 90), prompt_timeout_secs)}` to the helper; not delivered → drop the desk prompt and refuse. Reply `{"shown": true, "approves": prompt_id ∈ desk_prompts}`.

Answer handling (`daemon.py:948-972`, spawned as its own task because root waits on polkit): pop the desk prompt; if it existed and the answer is `allow`: OK iff not locked and the answering connection is still the current helper connection; for `root` additionally `executor.polkit_auth(helper_pid, user_uid, message, prompt_timeout_secs)` must return true. OK → `_authorize_job(job_id, digest, "desk", tier)` (300 s), audit `desk.accepted`, `authorized=true`; not OK → the answer becomes `"discord"` (request stays where it was), audit `desk.refused`. Always audit `prompt.answer` and send `{"type":"prompt.answer","prompt_id","answer","authorized"}`.

`prompt.cancel`: drop the desk prompt; tell the helper `{"type":"cancel","id"}`. `notify`: not present → refuse; urgency ∈ low/normal/critical else normal; send `{"type":"notify","title"(≤120, default "agent-auth"),"text"(≤600),"urgency"}`; reply `{"shown": true}`. `dnd`: `dnd_until = now + duration_secs(duration)` or 0 when absent/null.

Whenever presence changes (helper connects/disconnects, `presence`/`dnd` via hostctl, a helper report that flips `present()`), hostd sends `{"type":"presence", …status.desktop}` to the broker.

### 8.12 Audit journal
Logger `agent_auth.hostd.audit`, one JSON object per line: `{"event", "host", …fields}` with `default=str`. Events: `totp.refused`, `totp.accepted`, `job.refused`, `job.admitted`, `job.done`, `job.kill`, `shell.refused`, `shell.open`, `shell.close`, `shell.exec.refused`, `shell.exec`, `arm`, `disarm`, `lockdown`, `unlock`, `desk.accepted`, `desk.refused`, `prompt.answer`, `prompt.shown`. Stdin content is never logged (`<N chars>`).

### 8.13 `status()` (heartbeat payload, `daemon.py:233-259`)
```
{"version", "role":"host", "started_at": float,
 "tiers": {"user"|"root": {"enabled", "armed_until": float|null (null unless in the future),
                           "shell": shell_enable, "totp": arm AND direct secrets enrolled}},
 "jobs": int, "shells": int, "lockdown": bool,
 "vm": {"unit","state"} | null, "templates": [sorted names],
 "desktop": {"enabled","present","away_reason","dnd_until": float|null}}
```

---

## 9. Running a job, capturing output, delivering results

### 9.1 Launch (`daemon.py:475-531`)
1. Write the spool `{"status":"running","tier","at": now}` (dir `jobs/` 0700; write `.{id}.json.tmp` then rename).
2. Register `RunningJob` and start a task running `executor.run(job_id, tier, argv, cwd, env, timeout, stdin bytes|None, on_output)`.
3. `on_output(chunk)`: append; `size += len`; while `size − len(chunks[0]) ≥ MAX_OUTPUT_BYTES`, drop the first chunk and set `truncated`. (Keeps the **end** of the output.)
4. Outcome: return value = exit code; `CancelledError` (hostd stopping) → `executor.kill`, error `"hostd stopped while the job was running"`; other exception → error `"could not run: {exc}"`. If `killed` and no error → error `"killed"`.
5. `output = join(chunks)[-MAX_OUTPUT_BYTES:]`; result `{job_id, exit_code, error, duration_secs: round(elapsed, 3), bytes: len(output), sha256: hex(sha256(output)), truncated}`; audit `job.done`; write spool `{"status":"done","at","result","output": std-base64(output)}`; remove from `jobs`; send the result.

### 9.2 Sending, acking, resending
- `_send_result(id)` (`daemon.py:591-607`): only if the spool says `done`; send `job.output` chunks of 96 KiB with `seq` 0,1,2,… (none for empty output), then `job.done` with the stored result. Any failed send aborts (returns false).
- Broker `_on_output` (`core/hostexec.py:339-352`): ignore unless from a `host` connection with string `job_id` and `data`; buffer key `(host name, job_id)`; `seq == 0` resets the buffer; append strictly-decoded bytes (invalid base64 → ignore the chunk); if the buffer exceeds `MAX_OUTPUT_BYTES + OUTPUT_CHUNK_BYTES` it is emptied.
- Broker `_on_done` (`core/hostexec.py:354-391`): pop the buffer; if `sha256(buffer) ≠ msg.sha256` → log and **don't ack** (hostd will resend everything). Load the job; if it doesn't exist or `job.host ≠ connection name` → ignore (no ack). If status is `starting`/`running`: set `done`, `exit_code` (only if an int), `error` (`str[:2000]` or null), `output` (UTF-8 decode with replacement), `output_bytes`, `output_sha256`, `truncated`, `duration_ms = int(duration_secs·1000)` (if a number), `finished_at`. In all these cases send `job.ack`. If it was fresh: notify waiters (`job:{id}`), then `notifier.job_finished(request, job)`.
- hostd `job.ack`: delete the spool file if it says `done`.
- `_resend_results` (`daemon.py:609-624`): whenever connected, every 15 s, for each spool file (sorted) whose job isn't running and whose mtime is ≥ 15 s old, `_send_result`. So an unacked result is resent every ~15 s until acked.
- Startup `_recover_spool` (`daemon.py:567-589`): unreadable spool → delete; `running` → rewrite as `done` with `exit_code null, duration_secs null, bytes 0, sha256 = sha256(""), truncated false, error "hostd restarted while the job was running; its outcome is unknown"`, `output ""`; any other spool older than 7 days (`at`) → delete.

### 9.3 Broker job lifecycle (`host_jobs.status`)
`starting` (row committed before the host is asked) → `running` (host accepted) → `done` (verified result). `refused` when the host (or the call) failed, or a shell command couldn't be mirrored. `lost` exists in the schema, API (`client.py:21`, `job_out`) and UI but is **never set** (§17). `_set_status` only moves a row that is still `starting` (never overwrites a result that already arrived) and writes `via` unconditionally; it notifies waiters unless the new status is `running`.

---

## 10. Broker side end to end (`core/hostexec.py`, `provisioners/hostexec.py`)

Platform `hostexec`; resource = host name; capabilities `run`, `tpl.<name>`, `shell`.

### 10.1 Validation at request time (`provisioners/hostexec.py:41-97`)
1. `host = resource.strip().lower()` must match the daemon name regex; a `daemons` row with role `host` must exist (`no host 'x' is paired with this broker`); the host must be **online** (`host X is offline`); the broker must not be locked for it (`locked down: nothing runs on X until it is unlocked`).
2. `shell`: scope keys ⊆ {tier}; `shell_spec(host, tier, 1)` validates the tier; scope := `{"tier"}`; adds a risk note.
3. `run` / `tpl.*`: scope keys ⊆ {tier, cwd, env, timeout, stdin, argv (run) | params (tpl)} else `unknown scope keys: …`; `job_spec` (make_spec) validates; the normalized scope keeps `argv`/`params` always and the others only when not None/`{}` (so timeout is always present, default 600). Template requests are checked against the broker's mirror if it has one (tier must match; parameters validated; note shows the expansion), else a note says only the host knows.
4. Anything else: `hostexec capability is "run", "tpl.<name>" or "shell"`.
5. Early refusal from the host's **last heartbeat**: if `last_status.tiers[tier]` exists, refuse when not `enabled`, or for a shell when `shell` is false. (The host re-checks everything.)
A validation failure denies the request at creation.

### 10.2 Routing (`core/service.py:259-310`, `authority.py`)
- Authority (fold): shell → `{"action":"shell","tier"}`; run → `{"action":"run","argv","tier","cwd","env","timeout","stdin"}`; tpl → `{"action":"tpl","template","params",…common}`. `split` drops `None`, `{}` and `""` values from the common keys (so an empty-string stdin becomes absent → null in the spec).
- `needs_explicit_rule(hostexec) = true` (catch-all rules never clear a host command); `is_sensitive` ⇔ `tier == "root"` or shell (always a human unless a pinned saved rule); `human_only` ⇔ shell (never a rule, never the LLM; surfaced even if a pinned rule matches).
- A saved rule with authority `{"action":"window","tier":t}` ("approve all" window) covers any `run`/`tpl` request of tier t, never a shell; requests it approves get `decision_source = rule`, `decided_by = "window:{rule_id}"`.

### 10.3 The approval gate (human decisions) (`core/hostexec.py:160-231`, `core/service.py:600-622`)
`decide(approve=true)` first runs `gate(request, agent, decision)` (only for requests in awaiting_human / llm_denied / llm_evaluating). A `TransitionError` leaves the request pending.
1. `final_spec`: re-run `validate_request` with any overrides, then `split(fold(...))`, then: shell → `shell_spec(host, tier, min(decision.duration_secs or engine.cap_duration(requested, None), HUMAN_MAX_DURATION_SECS))`; else `job_spec(capability, host, scope)`. This must equal, byte for byte after digesting, the spec `start()` later builds from the grant (§10.4); both go through the same validate→fold→split path, and the shell duration equals `approved_duration_secs` computed in `decide`.
2. Shell without `decision.totp` → `a shell is approved with a TOTP code only (Approve with TOTP)`.
3. Shell: call `hostexec.precheck {kind:"shell", tier, duration}`. Job: call `hostexec.precheck {job_id: request.id, spec, source:"human", totp: bool(decision.totp)}`.
4. If a code was given: call `hostexec.authorize {job_id: request.id, tier, digest: digest(spec), totp}`.
5. Host errors become `TransitionError("{host}: {error}")`.
Then `decide` transitions, re-validates, stores `approved_authority`, sets `decision_source = human`, and provisions.

### 10.4 Provisioning (`core/hostexec.py:251-288`)
- Shell grant: `shell_spec(host, grant.scope.tier, request.approved_duration_secs)`; call `shell.open {shell_id: request.id, spec}`; credential output `{shell_id, host, tier, expires_at}`.
- run/tpl grant (one execution): spec = `job_spec(grant.capability, host, grant.scope)`; insert `host_jobs` row (`id = request.id`, status `starting`) and commit; call `job.start {job_id, spec, evidence}` with `evidence = {request_id, decided_by, source: decision_source value, window: decided_by startswith "window:"}`. Host error → status `refused` (error text) and `ProvisionerError("{host} refused: …")` → the request becomes provision_failed. Success → status `running`, `via` from the reply. If the decision was not a human's, or was a window: hand the job to the watcher (§10.8).
- Revoke (grant ended: revoked, expired, lockdown, containment): shell → `shell.close` (10 s, best effort); run/tpl → `job.kill` (10 s, best effort) if the job is `starting`/`running`. **A run grant's expiry kills its job.**
- Credential (`get_credential`): shell → `{kind:"hostexec_shell", value: grant.id, expires_at, note}` (refused if the grant isn't active); run → `{kind:"hostexec_job", value: JSON(job_out(full=false) minus output, plus output_tail)}`.

### 10.5 Agent API (`api/hostexec_routes.py`)
All 501 when hostexec is disabled.
- `GET /v1/hostexec/jobs/{job_id}?wait=W` (W clamped to 0..300, NaN → 0): the agent's own job only (404 otherwise); waits on `job:{id}` events in ≤2 s slices until the job is not starting/running or W elapses. Body `job_out`: `{job_id, host, tier, status, exit_code, error, duration_ms, output_bytes, output_sha256, truncated, command: argv or template name}` plus `output` (full) once status ∈ done/refused/lost.
- `POST /v1/hostexec/shells/{grant_id}/exec` body `{argv (≥1 strings), cwd?, env {}, stdin?, timeout?, wait=60}` → `shell_exec` then wait (0..300). Errors: unknown/foreign/non-shell grant 404 `unknown shell`; `SpecError` 400; `HostExecError` 409.
- `POST /v1/hostexec/shells/{grant_id}/close` → revoke the grant ("closed by the agent"); already ended is fine; `{"closed": true}`; 404 as above.

### 10.6 `shell_exec` (`core/hostexec.py:417-473`)
Grant must exist, belong to the agent, be platform hostexec capability shell (else `LookupError`); active and `expires_at > now` (else `that shell has ended`); broker not locked for the host (`locked down`). Build `make_spec(kind="run", host, tier = grant tier, argv, cwd, env, timeout, stdin)`; insert `host_jobs` row (new uuid4 id, `shell_id = request.id`, status `starting`). **Before dispatch**, `notifier.shell_command(request, job)` must return true (posted to the shell's Discord thread); otherwise status `refused` ("could not show the command on Discord") and `HostExecError("could not show the command on Discord; not run")`. Then call `shell.exec`; host error → `refused`, `job_finished` notification, re-raise. Success → `running`; the watcher always looks at shell commands.

### 10.7 Windows, arming, lockdown, unlock (broker)
- `arm(host, tier, duration, totp)` / `disarm(host, tier)`: plain calls; errors surface to the operator. Admin: `POST /admin/hosts/{name}/arm {tier="user", duration="1h", totp}`, `POST /admin/hosts/{name}/disarm?tier=`, `GET /admin/hosts` → `{lockdown: flag value, hosts: hosts()}`; 409 on host errors, 503 when disabled.
- `open_window(request, agent, secs, by)` (Discord "Approve all…", duration ≤ `platforms.hostexec.window_max`, default `window_default` 30m, max 8h): refuse shells; `precheck_window`: call `hostexec.precheck {spec: make_spec(run, host, tier, ["true"]), source:"rule", window:true}` (so the host must be armed and accept windows now); insert an expiring `AUTO_APPROVE` rule (`agent_pattern = agent.name`, `delegator_pattern` = the delegator's name or null, platform hostexec, `resource_pattern = host`, authority `{"action":"window","tier"}`, `expires_at = now + secs`); `apply_rule_to_pending` approves waiting requests it covers (never human-only ones).
- `lockdown(scope ∈ sandboxes|all|host, host?, kill_vm, by)` (`core/hostexec.py:537-625`): upsert broker flag `lockdown = {"hosts": sorted(previous ∪ {host or "*"}), by, at (ISO), scope}`; targets = every daemon (or those named `host` for scope host, which includes the VM's sandboxd of the same name); call `lockdown {kill_vm}` on sandboxes first (5 s each, in parallel), then on hosts (20 s each, in parallel); per daemon report `locked[ · vm …]`, or for an unanswering sandbox whose host froze a VM a "stopped by its host" note, else `NOT reached (…)`; revoke active grants of affected agents (all agents for `all`, else agents whose `sandbox_id` is a targeted sandboxd), falling back to `expires_at = now` if revoke fails; orphan their inbound a2a threads; record a containment entry (`match {}` / `{"placement":"sandbox"}` / `{"host": host}`, source `lockdown`) and announce. Returns `{scope, host, daemons, grants_revoked, threads_closed}`.
- `unlock(host?, totp?, by)`: with both, first call `unlock {totp}` on that host (errors abort everything); then remove `host` from the flag's set, or delete the flag when `host` is null (a remaining `"*"` keeps the broker locked); send `{"type":"unlock"}` to matching sandboxes; lift lockdown-sourced containment entries (all, or those with `match == {"host": host}`). Returns `{host, daemons, broker_locked: [...]}`.
- `locked(host)` ⇔ the flag's hosts contain `"*"` or `host`.
- `_on_connect(live)` (each new connection): if locked for that name → send `lockdown {kill_vm:false}`; sandboxes get `agents.contained`; hosts get `shell.close` for every shell grant on that host revoked/expired within the last day.

### 10.8 Watcher (advisory; `core/hostexec.py:290-324`, `policy/risk.py:128-172`)
Background task per job, never blocking it: for shell commands and for jobs no human approved individually. Gathers the agent name, host, tier, the request's justification, earlier argvs of the same shell (by `created_at`), and the argv; asks an OpenRouter model (`platforms.hostexec.risk_model` or `llm.model`, 20 s timeout, JSON schema `{level: fine|odd|alarming, summary}`); on `alarming`, `notifier.watch_alert(request, job, "watch ({model}, advisory): {summary}")`. Any failure is logged and ignored. Enabled only with `OPENROUTER_API_KEY` and `platforms.hostexec.watch` (default true).

### 10.9 Discord surface (behavior only; `discord_bot/hostexec.py`, `discord_bot/bot.py:85-275`)
- Owner-only interactions. run/tpl request embed: title `Run on {host} as ROOT|your user` (orange for root, yellow otherwise); command code block; agent, project, delegator; cwd, env **keys**, stdin length, timeout; a host line from the last heartbeat (offline / locked down / tier not enabled / armed until <t> / not armed); risk notes. Buttons: Approve · Approve all… · Approve with TOTP · Deny · Edit.
- Shell request: red, `🚨 ROOT SHELL` / `⚠️ USER SHELL`, posted to `DISCORD_LOUD_CHANNEL_ID` if set; buttons Approve with TOTP · Deny only. Once granted, the view becomes **End shell** (revokes the grant).
- TOTP modal: code 6–8 chars (`{host} {tier}-direct code`), shell duration (prefilled with the requested one), optional reason → `HumanDecision(approve, totp=code, duration_secs)`.
- Results: run → appended to the approval message (`result_field`: refused / error / `✅|❌ exit N in Xs`, last 30 lines ≤1500 chars, truncation note), full output attached when longer than the shown tail; rule-approved runs (no message) go to the activity channel; shell commands are posted to a thread on the approval message (created on first command) **before** dispatch, results follow there.
- Code blocks: ```` ``` ```` replaced by `ʼʼʼ`; text longer than 900 chars shows `…` + the **last** 899 chars.
- Slash: `/arm host tier code [duration=1h]`, `/disarm host [tier]`, `/lockdown [scope] [host] [kill_vm]` (reply has a **Kill VMs** button re-running lockdown with kill_vm), `/unlock [host] [code]`, `/dnd [duration]`, `/hosts` (fleet: online, version escaped, last seen, fingerprint prefix, and for hosts only fixed words/numbers from the status: lockdown, per-tier 🔓/🔒, job/shell counts, at the desk).

---

## 11. Executors (`hostd/executor.py`, `hostd/asuser.py`)

Interface: `run(job_id, tier, argv, cwd, env, timeout, stdin, on_output) -> exit code` (combined stdout+stderr streamed in ≤64 KiB reads; raise if it can't start), `kill(job_id, tier)`, `polkit_auth(pid, uid, message, timeout) -> bool`, `unit_action(action, unit) -> (code, output)`.

### 11.1 Linux (`LinuxExecutor`)
Every job is a **transient system unit started by PID 1**, never a child of hostd (so it inherits none of hostd's sandbox, env or fds):
```
{systemd_run} [-p User=<user>]                       # user tier only
  --unit=aa-job-<job_id> --collect --quiet --pipe --wait
  -p RuntimeMaxSec=<timeout> -p KillMode=control-group
  -p "Description=agent-auth job <job_id>"
  --working-directory=<cwd or (user tier: $HOME of user) or "/">
  --setenv=PATH=<path>
  --setenv=K=V …                                      # merged env, in order
  -- argv…
```
- `path` = `job_path` (default `/run/wrappers/bin:/run/current-system/sw/bin`), plus `:/etc/profiles/per-user/<user>/bin` for the user tier.
- User tier env base (overridable by the job's allowlisted env): `HOME, USER, LOGNAME, SHELL` from passwd, `XDG_RUNTIME_DIR=/run/user/<uid>`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus`. Root tier: only the job's env. Requires `user` configured for the user tier (`no user configured for the user tier`).
- The systemd-run process itself gets env `{PATH: path, LANG: C.UTF-8}`, stdin = a pipe if stdin was given (written fully, then closed) else /dev/null, stdout = a pipe, stderr → stdout. Its exit status is the job's exit code.
- Timeout = `RuntimeMaxSec` only (no hostd-side timer). Kill = `systemctl stop aa-job-<id>.service` (whole cgroup). `unit_action` allows only `freeze|thaw|stop|is-active` and runs `systemctl <action> <unit>` with `PATH=job_path`, returning `(exit code, stripped output)`.
- `polkit_auth`: read `/proc/<pid>/stat`, take field 22 (start time: the 20th field after the last `)`); run `pkcheck --action-id dev.agent-auth.hostd.run-as-root --process <pid>,<start>,<uid> --allow-user-interaction --detail polkit.message <message>`; true iff exit 0 within `timeout` (killed on timeout). The NixOS module installs the action with `allow_active = auth_admin` (any/inactive: no).

### 11.2 macOS (`DarwinExecutor`, `docs/hostd-macos.md`)
Jobs are hostd's children, each in a **new session/process group** (`start_new_session`), with their own cwd and env and no inherited fds.
- Root tier: before running, refuse (`RuntimeError("not running a root job: …")`) if any **existing** directory on `job_path` is not owned by uid 0 or has group/other write bits (`mode & 0o022`); `stat` follows symlinks; missing dirs are skipped; other stat errors refuse. argv runs directly with cwd `cwd or "/"` and env `{PATH: job_path, LANG: C.UTF-8, HOME: /var/root, USER: root, LOGNAME: root, …job env}`.
- User tier: PATH = `job_path:/etc/profiles/per-user/<user>/bin:/opt/homebrew/bin:/usr/local/bin`; command = `/bin/launchctl asuser <uid> <python> -I -m agent_auth.hostd.asuser <JSON {"user","cwd": cwd or home,"env": {PATH, LANG, HOME, USER, LOGNAME, SHELL, …job env},"argv"}>`, started in `/` with env `{PATH: /usr/bin:/bin:/usr/sbin:/sbin, LANG: C.UTF-8}` (launchctl gets none of the job's env).
- `asuser` (runs as root inside the user's launchd domain): refuse if the user's uid is 0; `initgroups(name, gid)`, `setgid(gid)`, `setuid(uid)`; verify real uid, effective uid, effective gid; then `setuid(0)` must fail with EPERM (if it succeeds → exit "root could be regained"); `chdir(cwd)`; `execvpe(argv[0], argv, env)` (PATH lookup in the job's env); exec failure → stderr `asuser: <prog>: <strerror>` and exit 127. A Rust port can do this in-process between fork and exec, but must keep the `launchctl asuser` hop (only root may `asuser`) and the post-drop checks.
- Timeout: wait for the main process (polling, not for the pipe to close) up to `timeout`; on expiry `kill`. Then, in all cases, SIGKILL the process group (stragglers die with the job, like KillMode=control-group); wait ≤5 s for the output relay to drain (cancel otherwise) and ≤5 s for reaping.
- Kill: SIGTERM the group; poll every 0.1 s up to 5 s for the group to vanish (`killpg(pgid, 0)` fails); then SIGKILL.
- Exit code: `returncode or 0`; a signal death (negative returncode −N) is reported as `128 + N`.
- `polkit_auth` always false (and `desktop.approve.root` is refused by config on macOS); `unit_action` raises (no units; `vm_unit` refused on macOS).
- Known gap: processes that leave the group (setsid, double fork, launchd-started services) escape timeouts, kills and lockdown.

---

## 12. Local sockets

### 12.1 Generic local API (`daemon_common/localsock.py`)
JSON lines over a unix stream socket. Request `{"method": str, "params": object (default {}), "token": any}` per line (≤1 MiB per line); reply `{"ok": true, "result": …}` or `{"ok": false, "error": str}` per line (`default=str` serialization). `ApiError`, `LookupError`, `ValueError`, `RuntimeError` → their message; any other exception → `"internal error: …"`. Several requests per connection allowed. The server unlinks any stale path, binds, then `chmod`s to the given mode.

Peer credentials, read once per connection: Linux `SO_PEERCRED` (`struct ucred {pid, uid, gid}` as three native ints); macOS `getsockopt(SOL_LOCAL=0, LOCAL_PEERCRED=1, 76 bytes)` = `struct xucred {u32 cr_version, u32 cr_uid, i16 cr_ngroups, pad, u32 groups[16]}` → uid at offset 4; pid via `LOCAL_PEERPID=2` (4-byte int).

Client `call(path, method, params, token, timeout=600)`: one request, read until `\n`; empty reply → error "no reply from the daemon"; `ok` false → `LocalApiError(error)`.

### 12.2 hostctl socket `{runtime_dir}/ctl.sock` (mode 0666), served when the config is privileged or the desktop is enabled (`daemon.py:169-170, 790-828`)
Caller uid (from peer creds) must be 0 or the configured user's uid; else `not for this user`. `token` is ignored.

| method | params | who | effect / result |
|---|---|---|---|
| `status` | — | root, user | `status()` |
| `arm` | `tier` (default user), `duration` (default "1h") | user tier: root or user; other tiers: root (`{method} needs root`) | `arm()` → `{"armed_until"}` — **no TOTP** (local presence) |
| `disarm` | `tier`? | root, user | `{"disarmed": true}` |
| `lockdown` | `kill_vm`? | root, user | lockdown result |
| `unlock` | — | root only | unlock result |
| `dnd` | `duration`? (falsy → off) | root, user | `{"dnd_until": float|null}`; pushes presence |
| `presence` | `state` ∈ idle/active/locked/unlocked | root, user | `{"present": bool}`; pushes presence |
`Refused`/`TotpError` → `ApiError`; unknown method → `unknown method 'x'`.
Presence events: `idle` → explicit_idle=true, idle_since=now; `active` → explicit_idle=false, idle_since=null; `locked` → explicit_locked=true; `unlocked` → explicit_locked=false and as `active`.

CLI `agent-auth-hostctl` (socket from `AGENT_AUTH_HOSTD_CTL`, default `{default runtime_dir}/ctl.sock`, 60 s timeout): `status [--json]`, `arm [DURATION=1h] [--tier user|root]`, `disarm [--tier]`, `lockdown [--kill-vm]`, `unlock`, `dnd [DURATION]`, `presence STATE`. Errors print in red and exit 1.

### 12.3 hostd-user socket `{runtime_dir}/user.sock` (mode 0666), when `desktop.enable` (`daemon.py:885-935`, `hostd/user.py`)
- hostd closes any connection whose peer uid ≠ the configured user's uid. A new valid connection **replaces** the previous one (the old one is closed). `connected = true` while one is attached; its pid is remembered (the polkit subject).
- Lines are JSON objects (bad lines ignored; default line limit 64 KiB).
  - helper → hostd `{"type":"presence","idle_secs": number|null,"locked": bool|null,"fullscreen": bool,"fresh": bool}`. With `idle_source == "hooks"`, a `fresh` report (first after the helper started) while no explicit idle/lock report exists counts as `unlocked`.
  - helper → hostd `{"type":"answer","id","answer"}`; answers outside allow/deny/mute/discord/timeout become `timeout`.
  - hostd → helper `prompt` / `cancel` / `notify` (§8.11).
- Helper behavior (`user.py`): reconnects every 5 s (2 s after a session ends); reports presence every 10 s; idle/lock from `loginctl` hints (`logind`), `ioreg` (`macos`: `HIDIdleTime` ns, `IOConsoleUsers[uid].CGSSessionScreenIsLocked` or not on console), or nothing (`hooks`); busy = `busy_command` exit 0 (failure/timeout counts as busy), else Hyprland's focused window `fullscreen ≥ 2` (or `true`). One dialog at a time; placeholders `{who} {what} {detail} {title} {text} {timeout}` replace **whole arguments** only; default dialog zenity (`--default-cancel`, Allow once / Deny / Mute agent 1h / Send to Discord) or an osascript dialog on macOS (Deny default/cancel, Send to Discord, Allow once; arguments passed as `argv`, never interpolated into the script); answer parsing: stdout word (`mute agent 1h|mute`→mute, `send to discord|discord`→discord, `once|session|allow`→allow, `deny`, `timeout`) else exit 0→allow, 5→timeout, other→deny; dialog killed after `timeout + 10` s; a cancelled prompt answers `timeout`. Notifications: `notify_command` with `{title} {text}` HTML-escaped on Linux (unescaped osascript on macOS by default); `attention_command` spawned on each prompt/notification.

---

## 13. Configuration

### 13.1 Broker settings (env, pydantic-settings, case-insensitive)
| var | default | meaning |
|---|---|---|
| `BROKER_SIGNING_KEY` | "" | ed25519 seed (b64url). Empty → daemon endpoints 503/close 4503, hostexec disabled |
| `DAEMON_HEARTBEAT_SECS` | 30 | sent in the welcome; broker idle timeout = 3× |
| `DAEMON_PAIRING_CODE_TTL_SECS` | 600 | |
| `DAEMON_PAIRING_MAX_ATTEMPTS` | 5 | wrong proofs before a code burns |
| `DISCORD_LOUD_CHANNEL_ID` | 0 | shell requests (0 = approvals channel) |
| `DISCORD_ACTIVITY_CHANNEL_ID` | 0 | results of rule-approved runs |
| `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL` | "", openrouter | risk line and watcher |
Policy `platforms.hostexec`: `templates {name: {tier, argv, params, description}}`, `risk_summary` (true), `risk_model`, `watch` (true), `window_default` ("30m"), `window_max` ("8h").

### 13.2 hostd config JSON (`hostd/config.py`; written by the nix modules; path from `AGENT_AUTH_HOSTD_CONFIG` or `--config`)
Required: `broker_url`, `broker_public_key`, `name`. Optional (JSON-loader defaults):
| key | default |
|---|---|
| `state_dir` | `/var/lib/agent-auth-hostd` (macOS `/var/db/agent-auth-hostd`) |
| `runtime_dir` | `/run/agent-auth-hostd` (macOS `/var/run/agent-auth-hostd`) |
| `user` | null (required if the user tier is enabled) |
| `tiers.{user,root}` | `enable` false, `max_arm` 3600, `accept_approve_all` false, `accept_machine_approvals` false, `shell.enable` false, `shell.max_duration` 1800 |
| `auto_commands`, `deny_commands` | [] (each pattern a non-empty list of strings) |
| `templates` | {} (each needs tier ∈ user/root and a non-empty argv; regexes must compile) |
| `env_allow` | `["LANG","LC_ALL","TZ","TERM"]` |
| `vm_unit` | null |
| `job_path` | Linux `/run/wrappers/bin:/run/current-system/sw/bin`; macOS `/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin:/usr/sbin:/sbin` |
| `default_timeout` / `max_timeout` | 600 / 3600 (durations) |
| `systemd_run`, `systemctl`, `qrencode`, `pkcheck` | bare names (the module sets store paths) |
| `desktop` | `enable` false, `max_idle` 300, `prompt_command` [] (built-in), `prompt_timeout` 90, `busy_command` [], `approve.{user,root}` false, `attention_command` [], `notify_command` [], `idle_source` ∈ hooks/logind/macos (anything else → hooks) |
`privileged` ⇔ any tier enabled or `vm_unit` set. macOS refuses `vm_unit`, `desktop.approve.root`, `idle_source: logind`. The nix modules use different defaults (user `max_arm` 8h & `accept_approve_all` true; root `max_arm` 1h; shell max 1h user / 30m root; notify via notify-send; zenity prompt) and always write explicit values; the Rust loader should keep the JSON defaults above.

Without a config file, `run`/`pair` build a connect-only config from `--broker-url`/`AGENT_AUTH_HOSTD_BROKER_URL`, `--broker-key`/`AGENT_AUTH_HOSTD_BROKER_KEY`, `--name`/`AGENT_AUTH_HOSTD_NAME` (default: first label of the hostname, lowercased), `--state-dir`/`AGENT_AUTH_HOSTD_STATE_DIR`: no tier enabled, so it runs nothing. Invalid config → exit 2. `LOG_LEVEL` sets logging. `run` warns if privileged but not root. On SIGTERM/SIGINT the daemon task is cancelled (running jobs are killed, results spooled).

### 13.3 Deployment (`flake.nix` `nixosModules.hostd`)
- `/etc/agent-auth/hostd.json` = the generated config (store path; `restartTriggers` on change).
- `systemd.services.agent-auth-hostd`: `ExecStart=agent-auth-hostd run`, `StateDirectory=agent-auth-hostd` (0700), `RuntimeDirectory=agent-auth-hostd` (0755), `Restart=always`, `RestartSec=10`, `UMask=0077`; hardening: `NoNewPrivileges, ProtectSystem=strict, PrivateTmp, PrivateDevices, ProtectKernelTunables/Modules/Logs, ProtectControlGroups, ProtectClock, RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX, RestrictNamespaces, RestrictRealtime, RestrictSUIDSGID, RemoveIPC, ProtectHostname, LockPersonality, SystemCallArchitectures=native`. Privileged: `User=root`, `CapabilityBoundingSet=""` (root uid, **no capabilities**; PID 1 starts the job units because polkit authorizes uid 0). Unprivileged: `User/Group=agent-auth-hostd`, `ProtectHome`, `ProtectProc=invisible`, empty capabilities, `SystemCallFilter=@system-service ~@privileged`.
- tmpfiles: `d /var/lib/agent-auth-hostd 0700 <owner>` and `Z` (recursive chown) so the key always belongs to the service's uid (hostd refuses a key not its own). Owner = root when privileged else the service user. Persist this directory on impermanence hosts.
- The `agent-auth-hostd` CLI wrapper exports the config path; when unprivileged and invoked as root (except `totp-enroll`), it re-execs via `runuser -u agent-auth-hostd`.
- polkit enabled when privileged or `desktop.approve.root`; the `dev.agent-auth.hostd.run-as-root` action is installed with `approve.root`.
- `systemd.user.services.agent-auth-hostd-user` (desktop): `wantedBy/partOf/after graphical-session.target`, `ConditionUser=<user>`, `Restart=always`, `RestartSec=5`.
- Assertions: user tier needs `user`; `desktop.approve` needs `desktop.enable`; desktop needs `user`. Option types: `brokerUrl` must match `https://[^/].*|http://(localhost|127\.0\.0\.1|\[::1])(:[0-9]+)?(/.*)?`; name `[a-z0-9][a-z0-9-]{0,62}`; durations int > 0 or `[0-9]+[smhdw]?`.
- macOS (`darwinModules.hostd`, `deploy/macos/*`): LaunchDaemon `dev.agent-auth.hostd` (root, `RunAtLoad`, `KeepAlive`, `ThrottleInterval 10`, `Umask 63` = 0077, log `/var/log/agent-auth-hostd.log`), LaunchAgent `dev.agent-auth.hostd-user` (`LimitLoadToSessionType Aqua`, `ProcessType Interactive`); `prepare_dirs` creates `state_dir` 0700 and `runtime_dir` 0755 (`hostd/main.py:254-261`). Everything hostd executes from (the venv/Python under `/opt/agent-auth` or the nix store) and the config must be root-owned and not group/other-writable (`install.sh` checks). The Rust binary inherits the same requirement.

---

## 14. Database (PostgreSQL)

- `daemons(id uuid pk, role varchar16, name varchar128, public_key varchar128, paired_at, last_seen_at?, version varchar64?, last_status jsonb?, created_at, updated_at; UNIQUE(role, name))`.
- `daemon_pairing_codes(id, role, name, pairing_key char64 hex, expires_at, used_at?, failed_attempts int default 0, created_at, updated_at; INDEX(role, name))`. The attempt spend and claim must be single conditional UPDATEs checking rowcount.
- `host_jobs(id varchar36 pk, grant_id? fk, request_id fk, agent_id fk, host varchar128, tier varchar8, shell_id varchar36?, spec jsonb, status varchar16 indexed, via varchar32?, exit_code?, error text?, output text?, output_bytes?, output_sha256 char64?, truncated bool, duration_ms?, finished_at?, created_at, updated_at)`.
- `broker_flags(key varchar64 pk, value jsonb, updated_at)`; key `"lockdown"`.
- `access_requests.discord_thread_id` (the shell mirror thread); `rules.expires_at` (windows).

---

## 15. Security invariants

Notation: "authorization A for (job j, digest d, tier t)" is an entry created only by `hostexec.authorize` after `totp.verify("{t}-direct")` succeeded (via `totp`), or by a desk Allow (via `desk`). "Armed(t) at τ" ⇔ `armed_until[t] > τ`.

Channel and pairing
- **INV-1** The broker accepts a WebSocket as daemon (r, n) only if the hello signature verifies, under the public key stored for (r, n) at that moment, over `transcript(CTX_HELLO, "daemon", r, n, bn, dn, params)` where `bn` is the nonce this broker generated for this very connection.
- **INV-2** A daemon treats a connection as the broker only if the welcome signature verifies under the broker key from its **local config** over `transcript(CTX_HELLO, "broker", r, n, bn, dn, params_b)` with `dn` the nonce it generated for this connection. No network input can change the pinned key.
- **INV-3** Every message acted on after the handshake is an envelope whose signature verifies under the peer's authenticated key over `(CTX_MSG, session_id(r, n, bn, dn), P)`; hence an envelope from one connection never verifies on another (different nonces ⇒ different session id, except with negligible probability).
- **INV-4** Per connection and direction, the sequence of accepted `seq` values is strictly increasing: no envelope is accepted twice, and none is accepted after a later one.
- **INV-5** An accepted envelope has `iss` = the authenticated peer's principal, `aud` = the receiver's principal, `iat ≤ now + 30`, `exp ≥ now`, `exp − iat ≤ 3600`.
- **INV-6** After a re-pair or unpair of (r, n) completes, no connection authenticated with the previous key remains registered: it was closed by `_kick`, or refused by the generation check at registration, or is closed with 4401 at its next heartbeat write (backstop).
- **INV-7** A pairing code row admits at most one successful pairing; at most `DAEMON_PAIRING_MAX_ATTEMPTS` proofs are ever evaluated against it (counting concurrent attempts); attempts whose selector is wrong evaluate no proof and change no counter; only the newest unused, unexpired code for (r, n) can succeed; unpairing invalidates all unused codes for (r, n).
- **INV-8** A daemon completes pairing only if the broker's reply carries the pinned broker key and a valid broker proof bound to (role, name, daemon key, broker key).
- **INV-9** The pairing code never appears in hostd's argv; the broker never stores the code itself.
- **INV-10** A `reply` resolves a pending `call` only if it arrives on the connection of the daemon the call was sent to.
- **INV-11** A daemon's private key file is used only if it is a regular file (not followed through a symlink), owned by the effective uid, with no group/other permission bits.

TOTP
- **INV-12** For each secret, a code is accepted only if it equals `code_at(secret, s)` for some `s ∈ {c−1, c, c+1}` and `s > last_step`; on acceptance `last_step := s` is persisted before the caller proceeds. Therefore the sequence of accepted steps per secret is strictly increasing, and no code value is accepted twice.
- **INV-13** While `locked_until > now`, no code is accepted for that secret; five consecutive wrong codes set `locked_until = now + 300`.
- **INV-14** A secret of tier t, purpose p is consulted only for: `{t}-direct` → `hostexec.authorize` for tier t; `{t}-arm` → remote `arm` of tier t; `root-arm` → remote `unlock`. No other code path accepts a TOTP code.

Admission (hostd)
- **INV-15** hostd starts a process for job j only via `job.start` or `shell.exec`, and only after `_normalize` succeeded for its spec: host = own name, kind ∈ {run, tpl} (tpl never in a shell), tier enabled locally, timeout ≤ `max_timeout`, env keys ⊆ `env_allow`, no deny pattern matches, and, for tpl, argv = expansion of the host's **own** template whose tier equals the spec's tier.
- **INV-16** hostd never starts a process while the lockdown file exists.
- **INV-17** (TOTP tier binding) If a job of tier t is admitted with `via == "totp"`, then a `{t}-direct` code was accepted for this job id within the previous 300 s, and the digest given with that code equals `digest(raw spec of this job.start)`. In particular **a TOTP code admits only a job of its own tier**, and a user-direct code never admits a root job.
- **INV-18** Each authorization admits at most one job or shell (it is removed from the map on the first `job.start`/`shell.open` that looks it up, whether or not it matched), and none after `lockdown` (which clears the map).
- **INV-19** If a job is admitted with `via == "desk"`, then a desk prompt for (job id, digest, tier) was shown on this host, answered `allow` over the then-current helper connection by the configured user's uid, `desktop.approve.{tier}` is true in local config, and for `root` polkit's `pkcheck` for `dev.agent-auth.hostd.run-as-root` returned success for the helper process.
- **INV-20** (root needs a human) A root-tier job is admitted only via (a) `totp` with a `root-direct` code (INV-17), (b) `desk` with polkit admin authentication (INV-19), or (c) Armed(root) at admission, where every arming of root came from a `root-arm` TOTP code or from `hostctl arm --tier root` by uid 0, and lasts at most `tiers.root.max_arm`. `auto` never applies to root, and no rule, window or LLM approval admits a root job unless (c) holds.
- **INV-21** A job is admitted via `auto` only if it is kind `run`, tier `user`, and its argv matches an `auto_commands` pattern under strict (non-basename) matching.
- **INV-22** A job admitted via any `armed+*` reason was admitted while Armed(tier); `armed+window` additionally requires `accept_approve_all`, and `armed+{rule,llm,policy}` requires `accept_machine_approvals`. (These two flags constrain an honest broker only: `source` and `window` are broker-asserted.)
- **INV-23** A shell is opened only with an authorization of `via == "totp"` whose tier equals the shell's tier and whose digest equals `digest(shell_spec(host, tier, duration))`, with shells enabled for the tier and `duration ≤ shell.max_duration`. Arming, windows, rules, LLM decisions and desk answers never open a shell.
- **INV-24** A shell command runs only while its shell exists in hostd's memory with `expires_at > now`, its tier equals the shell's tier, and no lockdown is in force. `expires_at` is fixed at opening; no broker message can extend it. A hostd restart ends all shells.
- **INV-25** Arm state is memory-only (a restart disarms); `armed_until[t] ≤ arm_time + tiers[t].max_arm`; arming is refused while locked; lockdown disarms both tiers.
- **INV-26** Lockdown persists across restarts and is cleared only by uid-0 `hostctl unlock` or a remote `unlock` carrying a valid `root-arm` code. No broker message without a code clears it.
- **INV-27** Every admission and refusal of a job, shell, arming, TOTP use, desk answer, lockdown and unlock is written to the audit log before (or as) it takes effect; stdin content never is.
- **INV-28** The spool path of a job id is always `{state_dir}/jobs/{id}.json` with id matching `[0-9a-f-]{8,64}` (no traversal); a job id that is running or still spooled is never started again.

Broker
- **INV-29** A shell request is never decided by a rule, window or LLM, and a human approval of a shell takes effect only if a TOTP code accompanied it and the host accepted that code (gate) — the request otherwise stays pending.
- **INV-30** A human approval of a run/tpl request takes effect only after the host's precheck (and, with a code, its authorize) succeeded for the exact spec the grant will later start: `digest(final_spec at gate) == digest(spec sent in job.start)`.
- **INV-31** A shell command is posted to the human-visible mirror before it is sent to the host; if posting fails, it is never sent.
- **INV-32** A job result is stored only if the SHA-256 of the reassembled output equals the reported hash, it came from the host the job was sent to, and the job was still `starting`/`running`; a stored result is never overwritten.
- **INV-33** While the broker's lockdown flag covers a host (`"*"` or its name), no new hostexec request for it validates and no shell command for it is sent; a host connecting while covered is sent `lockdown`.
- **INV-34** `last_status` (daemon-supplied) is never sufficient to approve anything; it can only cause an early refusal.

Local sockets
- **INV-35** hostctl serves only uid 0 and the configured user's uid; only uid 0 may unlock or arm a non-user tier.
- **INV-36** hostd reads hostd-user messages only from a connection whose peer uid is the configured user's uid.

---

## 16. Tests worth porting

From `tests/test_daemons.py`:
- envelope roundtrip; editing `p` breaks the signature.
- envelope refused for the wrong audience or sender.
- envelope from one session id refused under another.
- replay, reorder, expired, future-dated (>30 s), and >3600 s lifetime envelopes refused.
- NaN `exp` in a correctly signed body refused as malformed.
- sealer numbers 1, 2, 3.
- hello signatures bind speaker, nonces and params (no reflection, no reuse, no param rewrite).
- `proofs_equal` tolerates non-ASCII and non-string inputs.
- pairing code shape (14 chars, 2 dashes) and normalization (lowercase, spaces).
- key file created 0400, reused, no temp files left, 0644 refused; symlinked key refused.
- broker URL: https required except loopback http.
- name validation rejects a trailing newline.
- pairing binds the key, broker proof correct, code single use.
- code bound to its daemon name.
- five wrong proofs burn the code; all refusals share one message.
- wrong-selector attempts never burn the code.
- 30 concurrent wrong proofs evaluate ≤ max attempts.
- malformed proof → 422; new code supersedes old; expired code refused; invalid identity 400; disabled broker 503; unpair burns pending codes; admin endpoints require the admin token.
- channel end to end: heartbeat stored with version, broker→daemon message delivered with `aud`, unpair drops the connection.
- daemon refuses a broker without the pinned key (handshake and pairing).
- hello rejections: unknown daemon, wrong key, wrong nonce → 4401; correct → welcome.
- forged envelope after hello → 4400; envelope captured from an earlier connection → 4400.
- newer connection replaces older (4409).
- unpair during handshake leaves no live connection.
- silent connection dropped after 3 heartbeat intervals.
- daemon survives garbage welcomes (`[]`, `"x"`, `1`, non-string params).
- `/hosts` embed escapes daemon-supplied text; version strings validated.

From `tests/test_hostexec.py`:
- TOTP: RFC vector; single use; earlier step refused after a later one; ±1 step; missing secret; double enroll refused; 5 wrong → locked even for the right code; usable after 300 s.
- argv patterns (`*`, `**`, exact length, basename for deny); `duration_secs`.
- templates substitute whole arguments; extra/missing params and pattern mismatch refused.
- spec validation (cwd normalized, env sorted, default timeout 600) and digest stable across JSON roundtrip, sensitive to argv.
- Approve refused `not_armed` when disarmed and the request stays pending; wrong arm code arms nothing; arming capped at `max_arm`; armed approval runs with via `armed+human`; disarm.
- Approve with TOTP works disarmed (via `totp`, stdin and stderr captured, exit 3); a code is single use across requests; a user code is not a root code.
- A TOTP authorization is bound to its digest: a different spec under the same job id is refused.
- A user-direct code relayed with a root digest admits nothing.
- Machine approvals: refused disarmed; armed but `accept_machine_approvals` false → refused; auto patterns run unarmed (via `auto`); catch-all rules and root never auto-approve.
- Host policy refuses denied commands even with TOTP (code not spent), env outside the allowlist, jobs addressed to another host.
- Validation fails fast (empty argv, bad tier, unknown scope key, unknown host, unknown capability).
- Templates expanded by the host; broker-mirror pattern mismatch denied; a root spec for a user template refused by the host.
- Output keeps its end and sets `truncated`; revoking a running job's grant kills it (`error == "killed"`).
- Job API is per agent; catalog shows host tiers.
- Approve-all window: needs armed, approves pending run requests (not shells, not root), new ones from the same agent only, worthless once disarmed, expires; root without `accept_approve_all` refuses windows.
- Shell: human-only, TOTP-only (broker and host), every command mirrored first, unmirrorable commands not run, deny list applies, other agents can't use it, ending kills running commands, ended shell refuses.
- Host bounds shells (duration at precheck and at open; disabled root shells; host-side expiry).
- Lockdown: freezes the VM, kills jobs, disarms, refuses new jobs and arming; broker unlock alone leaves the host locked; wrong root-arm code refused; right one unlocks and thaws; unlocked ≠ armed.
- Lockdown survives a hostd restart and is re-sent to a reconnecting host.
- Lockdown revokes only agent-VM agents' grants for `sandboxes`, everyone's for `all`.
- hostctl rules (uid checks, user arms user tier only, user may lock but not unlock, root arm capped).
- A job running when hostd died is reported with "outcome is unknown".
- A host without a config runs nothing.
- Config loading from the module JSON; user tier without `user` refused.
- Linux executor command line (User=, unit name, working dir, env, `--` argv, exit code) and systemctl verbs.
- Watcher: alarming shell command → one alert, nothing stopped, earlier commands passed; human-approved run not watched.

From `tests/test_hostd_macos.py`:
- platform defaults (paths, job_path); macOS refuses vm_unit / approve.root / logind; example config loads.
- peer credentials: xucred parsing (uid at offset 4, LOCAL_PEERPID) and Linux SO_PEERCRED over a real socket.
- user tier goes through `launchctl asuser` with the JSON spec; launchctl gets no job env.
- root tier env and cwd; stdin reaches the job; timeout kills the whole group (exit 143); stragglers die with the job; kill stops a job (143).
- root jobs refuse a PATH directory writable by others or not root-owned; Homebrew only on the user tier's PATH.
- asuser drops privileges, refuses when root can be regained, never runs as root.
- dialog command/answer parsing (macOS and zenity); notification escaping; ioreg idle/lock parsers; `prepare_dirs` modes.

---

## 17. Suspected bugs and questionable behavior in the Python

1. **`truncated` can be false although output was cut** (`hostd/daemon.py:486-493, 513`). The drop loop keeps chunks while `size − len(chunks[0]) < MAX`, so up to `len(chunks[0]) − 1` bytes beyond MAX can remain; the final `[-MAX:]` slice then cuts them without setting `truncated`. Example with MAX=100: chunks 60+60 → nothing dropped, 20 bytes sliced off, `truncated=false`. Fix: set `truncated = true` whenever the total produced exceeds MAX. Also `bytes` reports the kept size, not the produced size.
2. **A slow host reply records a job that ran as `refused` and throws its result away.** `start()` (`core/hostexec.py:273-280`) marks the job `refused` and fails provisioning on any `HostExecError`, including the 20 s call timeout. If hostd did start it (its reply was slow — and replies queue behind inline handlers on both sides, e.g. a Discord upload inside `_on_done`), the later `job.done` finds status `refused`, is acked and discarded (`core/hostexec.py:370`). The grant is `provision_failed`, so nothing revokes/kills the job either, and a spent TOTP code is gone.
3. **Status `lost` is never produced.** The model comment, `job_out`, the client and the UI expect it; a hostd restart produces `done` with `exit_code null` and an error instead. A broker never hears about jobs whose spool vanished (state dir lost): such rows stay `running` forever; there is no reaper.
4. **Orphaned job units after a hostd crash (Linux).** Jobs run in their own systemd units, so a SIGKILL/crash of hostd leaves them running; `_recover_spool` reports them "outcome unknown" but neither stops the `aa-job-*` unit nor tracks it, so `job.kill`, shell end and **lockdown cannot kill them** (only `RuntimeMaxSec` bounds them). A graceful stop does kill them (CancelledError path).
5. **Approval UIs don't show the whole command they authorize.** Discord `_code` shows `…` + the last 899 chars (the head of a long argv is hidden, `discord_bot/hostexec.py:42-46`); the desk prompt shows the first 600 chars (`daemon.py:1007-1011`) and the polkit message 700; `_line` collapses all whitespace (newlines inside a `sh -c` script render as spaces); stdin content is never shown anywhere (only its length) yet is covered by the digest a TOTP/desk approval authorizes (argv ≤ 64 KiB and stdin ≤ 64 KiB). The "desk approval is bound to content" claim (`docs/sandbox-design.md` §8.6) is weaker than stated. Consider refusing approval UIs for specs that don't fit, or showing a digest/head+tail.
6. **TOTP lockout doesn't escalate.** 5 guesses per 300 s per secret ≈ 1 guess/min indefinitely; with 3 valid codes per window the success chance is ≈3·10⁻⁶ per guess ≈ 0.43 %/day ≈ 79 %/year for an attacker who controls code relay (a compromised broker — exactly the adversary TOTP is meant to stop). Failures go only to the journal; no alert, no exponential lockout, no hard lock after N lockouts.
7. **TOTP state is not fsynced** (`totp.py:99-105`): the comment "Persisted before the caller acts on it: a crash can't make a code reusable" holds for a process crash but not for power loss. Same for the lockdown file and the spool.
8. **Remote `arm` spends the code before checking lockdown** (`daemon.py:719-723` then `704-707`): on a locked host a valid arm code is burned and the request refused. Check `locked_down` before `verify`.
9. **Re-locking after a local unlock.** `_on_connect` sends `lockdown` whenever the broker flag covers the host (`core/hostexec.py:680-681`). After a global lockdown (`"*"`), `/unlock host:<h> code:<…>` unlocks the host but leaves `"*"`, so the host is locked (and its VM frozen) again at its next reconnect; a host unlocked locally with `hostctl unlock` is likewise re-locked. Arguably intended ("the broker is still locked"), but surprising and not stated.
10. **Watcher sees an empty command for templates**: the broker's tpl spec has no `argv` (`core/hostexec.py:315`), so template jobs approved by a rule/window are assessed as `[]`. Also, "earlier commands" includes commands created after the one being assessed if the watcher runs late (`!= job.id`, not `created_at <`).
11. **"One at a time" isn't enforced.** Neither the broker (`shell_exec`) nor hostd (`_shell_exec`) prevents concurrent commands in one shell, despite the docs and the MCP description.
12. **Docstring contradiction about desk answers.** `hostd/user.py:8-11` says a desk answer "never … satisfies a host's own TOTP/arming check", but with `desktop.approve.user|root` a desk Allow is exactly a host authorization (`daemon.py:953-962`). With `approve.user`, any process running as the user can connect to `user.sock` (replacing the helper), spoof presence and answer allow for user-tier jobs — accepted in the design doc, but the code comment is wrong.
13. **`precheck_window` uses argv `["true"]`**: if an `auto_commands` pattern matches `true` (e.g. `["*"]` or `["true"]`), `_admit` returns `auto` and the window precheck passes even when the tier is disarmed (`core/hostexec.py:233-236`). Harmless for safety (each job is re-checked) but the operator is told the window works.
14. **Envelope body keys clobber payload keys** (`crypto.py:301`): a payload with `id`, `iss`, `aud`, `seq`, `iat` or `exp` is silently overwritten. No current message uses them; the Rust sealer should reject such payloads.
15. **Stale reconnect delay.** In `DaemonChannel.run` (`channel.py:167-198`) `delay` is captured before the handshake; a session that later dies with an exception sleeps the **old** backoff (up to 60 s) although the connection had succeeded and `backoff` was reset.
16. **In-memory generations and live map**: re-pair/unpair races are only closed within one broker process. Multiple broker replicas would break INV-6 and `call` routing.
17. **Inline handlers serialize everything per connection.** hostd awaits each broker message's handler before reading the next (e.g. a lockdown that kills many macOS jobs sequentially at up to 5 s each can exceed the broker's 20 s call timeout, which then reports the host "NOT reached" although it locked); the broker likewise awaits `_on_done` → Discord. Feeds bug 2.
18. **`hostd` default timeout is dead config.** The broker's `make_spec` always fills `timeout` (600), so hostd's `default_timeout` (`raw.get("timeout") or default`, `daemon.py:332`) never applies to broker-originated specs; a host with `max_timeout < 600` refuses every request that doesn't set a timeout explicitly.
19. **Catalog/Discord "armed" is stale**: `hosts()` reports `armed_until` from the last heartbeat without comparing to now (`api/agent_routes.py:87-89` uses `bool(armed_until)`), so a tier that expired since the last heartbeat (≤30 s) is shown armed. Display only.
20. **Desk prompts can leak**: entries in `_desk_prompts` are removed only on answer, cancel or lockdown; if the broker drops before cancelling, they persist for the process lifetime (an answer to a stale prompt still creates a valid authorization, though only for the original digest and job id).
21. **Linux root-tier jobs get no HOME/USER**: the user tier gets passwd-derived env and macOS root gets `HOME=/var/root`, but Linux root-tier units get only PATH and the job's env (systemd sets HOME/USER only with `User=`). Inconsistent; tools that need HOME fail on Linux root jobs.
22. **Run grants kill their job at grant expiry** (provisioner `revoke` → `job.kill`): a job whose `timeout` exceeds the request's duration is killed when the grant expires, not at its own timeout. Possibly intended; undocumented.

---

## 18. Porting notes (Python-isms to preserve or deliberately fix)

- Atomicity that Python gets from a single-threaded event loop must be explicit in Rust: (a) generation check + live-map registration vs `_kick` (one mutex); (b) TOTP verify per secret; (c) authorization take/peek and insert; (d) sealer seq assignment + send (per-connection send lock); (e) `_set_status`'s conditional update and `_on_done`'s read-modify-write (use `SELECT … FOR UPDATE` or conditional UPDATEs in PostgreSQL).
- Interop-critical byte formats: transcripts (u32 BE length prefixes), context labels, b64url-unpadded keys/nonces/signatures, standard base64 for output, the digest JSON serialization (§6.3), TOTP (§7), fingerprints, selector truncation to 32 hex chars, close codes, message field names and error-string prefixes (`not_armed`, `wrong code`, `already used`, `locked`), which tests and UIs match on.
- Python `re.fullmatch` for template params, `fnmatchcase` for argv patterns, `os.path.normpath` for cwd, `shlex.join` for display, `str.split()` whitespace semantics in `_line`: replicate exactly where they change what runs (normpath, template regex, fnmatch) and closely where they only change display.
- `exit codes`: Linux = systemd-run's exit status; macOS = `128 + signal` for signal deaths.
- Keep refusal-before-spend ordering: precheck before authorize at the gate; deny/env/tier checks before any TOTP verification on hostd where possible (fix bug 8).
