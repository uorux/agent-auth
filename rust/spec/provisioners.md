# Provisioners: behavioral specification (Rust port)

Source of truth: `src/agent_auth/provisioners/*.py`, the credential route
`src/agent_auth/api/agent_routes.py:217-249`, the token routes
`src/agent_auth/api/token_routes.py`, the catalog `src/agent_auth/api/catalog.py`,
registration in `src/agent_auth/main.py:61-119,157-181`, and the lifecycle in
`src/agent_auth/core/service.py`. Tests: `tests/test_provisioners.py`,
`tests/test_github_create.py`, `tests/test_kubernetes.py`, `tests/test_models.py`.

Conventions in this document:

- `{x!r}` in a quoted message means **Python `repr()`**: a string comes out
  single-quoted (`'jrt/x'`), or double-quoted if it contains `'` and no `"`,
  with control characters escaped. A list prints as `['a', 'b']`. Rust needs a
  small `py_repr()` helper so the strings stay byte-identical. Tests match
  substrings, but agents and humans also read these strings.
- "Denial" means `SpecValidationError(msg)`. At request creation it becomes
  `status=denied`, `decision_source=policy`, `decision_reason="validator: <msg>"`
  (`service.py:216-233`). During an approval with edits it becomes
  `TransitionError("edited approval rejected by validator: <msg>")`, and the
  request stays awaiting a human (`service.py:656-668`).
- "Failure" means `ProvisionerError(msg)`. See §1.4 for where it surfaces.
- All times are UTC. With Postgres, `expires_at` columns are `timestamptz`.

---

## 1. Common framework

### 1.1 Trait

`base.py:31-49`. Each provisioner has a `platform` and four async operations:

| op | contract |
|---|---|
| `validate_request(session, spec) -> spec` | Normalizes `resource`/`capability`/`scope` (canonical form) and appends human-facing `notes`. It raises a denial on any structural problem or hard-ceiling breach. It may read the DB. It must not do external I/O (none of the Python implementations do). |
| `provision(session, grant) -> provisioner_state (JSON object)` | Applies the grant externally. Must be idempotent. The return value is stored in `grants.provisioner_state`. |
| `revoke(session, grant)` | Removes external access. Must be idempotent. Raising `ProvisionerError` (or anything else) means "retry later" and the grant stays ACTIVE. |
| `get_credential(session, grant) -> CredentialOut` | Returns or mints the credential. Every provisioner that issues a secret must refuse unless `grant.status == ACTIVE && grant.expires_at > now`. |

`RequestSpec { agent: Agent, capability: str, resource: str, scope: map, notes: Vec<String> }`.
Notes are merged into `request.risk_notes` (`service.py:255`).

`grant.capability` and `grant.scope` are not columns. They come from
`authority::split(platform, grant.authority)` (`models.py:67-93`,
`authority.py:84-118`). The authority stored on the request and grant is
`fold(platform, spec.capability, spec.scope)` of the **validated** spec
(`service.py:250-254`, and `approved_authority` at `service.py:670-672`). Per
platform:

| platform | fold → authority | split → (capability, scope) |
|---|---|---|
| github repo | `{"permissions": {...}}` | `("repo", {"permissions": {...}})` |
| github create | `{"action":"create","visibility":v}` | `("create", {"visibility": v})` |
| kubernetes | `{"role": r}` (+ `"cluster": true` if scope.cluster) | `(r, {"cluster":true}` or `{})` |
| homelab | `{}` | `("group", {})` |
| models | `{"action":"use"}` | `("use", {})` |
| mcp | `{"tools": sorted-unique or ["*"]}` | `("use", {"tools": [...]})` |
| agents | `{"action": cap, "runtime": scope.runtime}` | `(action or "mint", {"runtime": ...})` |
| sandbox | `{"access": cap}` | `(access, {})` |
| a2a | `dict(scope)` | `("talk", dict(authority))` |
| google | `{"action": cap}` | `(action, {})` |
| hostexec | see the hostexec spec | |

### 1.2 Errors and registry

- `ProvisionerError`: an external-system failure, or a refusal to issue.
- `SpecValidationError`: an immediate deny.
- `ProvisionerRegistry` (`base.py:52-68`) maps `Platform` to a provisioner, and
  the last `register` wins. `get(p)` on an unregistered platform raises
  `SpecValidationError(f"platform {p.value!r} is not enabled on this broker")`,
  for example `platform 'github' is not enabled on this broker`. In
  `POST /v1/requests` this becomes HTTP 400 with that text and no request row
  (`agent_routes.py:117-118`). `enabled(p)` is a boolean.

### 1.3 Registration (`main.py:61-181`)

| platform | registered when | notes |
|---|---|---|
| a2a, google | always | |
| github | `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY_FILE` are both non-empty | `ENCRYPTION_KEY` is required, otherwise the process exits with `ENCRYPTION_KEY is required when GitHub is enabled` |
| homelab | `LLDAP_URL` is non-empty | `secret_box` is only present when `ENCRYPTION_KEY` is set. Without it, managed accounts are off and a warning is logged |
| kubernetes | `KUBERNETES_API_URL` is non-empty | `k8s.zones = Zones(policy)` |
| models | `platforms.models.url` is non-empty **and** `LITELLM_MASTER_KEY` **and** `ENCRYPTION_KEY` | otherwise a warning is logged and the platform is off |
| agents, sandbox, hostexec | the daemon channel is enabled (`BROKER_SIGNING_KEY` set) | |
| mcp | `platforms.mcp.servers` is non-empty **and** `BROKER_SIGNING_KEY` | `TokenIssuer(derive(BROKER_SIGNING_KEY), platforms.mcp.issuer)`, also stored as `app.state.tokens` |

### 1.4 Where the operations are called (lifecycle)

- **validate**: at `create_request`, after the containment and delegation checks
  and before zones and rules (`service.py:216-233`). It runs again on approval
  with the final, possibly edited, resource and scope (`service.py:643-672`).
  The request's `approved_resource` and `approved_authority` come from that
  second pass.
- **provision**: provisioning has two phases. `_begin_provision`
  (`service.py:825-886`) runs inside the deciding transaction. It creates the
  Grant row with `status=PROVISIONING` and
  `expires_at = now + approved_duration`, capped at the backing a2a grant's
  expiry when the request is delegated. It refuses if the agent is contained,
  or if the delegation thread or backing grant is no longer open or active.
  **No provisioner runs inside that transaction.** After commit,
  `_finish_provision` (`service.py:888-932`) re-checks containment in a new
  transaction, calls `provision`, and then:
  - on success, sets `provisioner_state` to the result and moves the grant to
    ACTIVE and the request to GRANTED;
  - on any exception, moves the grant to `PROVISION_FAILED` with
    `revoke_reason=str(exc)`, moves the request to PROVISION_FAILED, and appends
    `" | provisioning failed: <exc>"` to `decision_reason`. **The agent sees this
    text**, so provisioner error messages must never contain secrets or
    upstream response bodies. Some Python messages (models) do include up to 200
    characters of the upstream body.

  The same transaction also commits whatever the provisioner wrote, such as
  `agents.lldap_*` and `credentials` rows, even when provisioning fails. If a
  containment landed while the provisioner ran, the grant is then revoked through
  `revoke_grant`.
- **reap** (`service.py:934-978`): grants still PROVISIONING with
  `created_at <= now - 15min` (`scheduler.py:14`, or any age on the boot tick)
  get `revoke()` run on them, then move to PROVISION_FAILED with
  `revoke_reason="provisioning interrupted; external state reverted"`. If
  `revoke` raises, the row stays PROVISIONING and is retried on the next tick.
  `revoke` therefore has to handle an empty `provisioner_state` (LLDAP and
  Kubernetes do; see their sections).
- **expire** (`service.py:1037-1068`, every 30s): ACTIVE grants with
  `expires_at <= now` get `revoke()` and then status EXPIRED. If `revoke`
  raises, the grant stays ACTIVE and is retried next tick.
- **revoke_grant** (`service.py:1022-1035`): only for ACTIVE grants. It calls
  `revoke()` and then sets status REVOKED. An exception propagates and the
  grant is unchanged.

### 1.5 Credential fetch route: `GET /v1/grants/{grant_id}/credential`

`agent_routes.py:217-249`. The caller is authenticated as an agent by its API
key, **or by a web-UI OAuth `aat_` access token** (`deps.py:67-72`). Disabled
agents get 401. Steps, in order:

1. Grant missing, or `grant.agent_id != caller.id` → **404 `unknown grant`**.
   The response is identical in both cases.
2. The agent is contained (`lockdown.holding`) → security-log
   `credential_refused`, then **403 `contained (<id>): credentials are not issued`**.
3. `grant.delegation_thread_id` is set, and the thread is missing or not
   `open` → **403 `delegation thread is closed; credential no longer issuable`**.
4. `registry.get(grant.platform).get_credential(session, grant)`.
   `ProvisionerError` → **403 `str(exc)`**. `NotImplementedError` → **501**.
   Any other exception is a 500. That includes `SpecValidationError` when the
   platform has since been disabled; see bug B18.

The route does not check grant status itself. Each provisioner does (§ per
platform).

Response body: `CredentialOut` (`schemas.py:103-111`) is serialized **without**
`exclude_none`, so all six keys are always present:

```json
{"kind": "...", "value": "...|null", "username": "...|null",
 "url": "...|null", "expires_at": "ISO-8601 UTC|null", "note": "...|null"}
```

`expires_at` is a tz-aware datetime rendered by pydantic as
`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.

---

## 2. GitHub (`provisioners/github.py`)

Two capabilities: `repo` (mint installation tokens) and `create` (the broker
creates an org repository).

### 2.1 Config

Env (`config.py:45-48`):
- `GITHUB_APP_ID`: the JWT `iss`.
- `GITHUB_APP_PRIVATE_KEY_FILE`: path to a PEM. It is **re-read from disk on
  every JWT** (`github.py:540`).
- `GITHUB_API_URL`: default `https://api.github.com`, trailing `/` stripped.
- `GITHUB_INSTALLATION_ID`: optional pin. Empty means installations are
  resolved per repo.
- `ENCRYPTION_KEY`: Fernet, used for the token cache.

Policy `platforms.github` (`schema.py:88-113`):
- `repo_allowlist: [glob]`, default `[]`. **Empty means every repo.**
- `repo_denylist: [glob]`, default `[]`.
- `permission_ceiling: {perm: "read"|"write"|"admin"}`, default `{}`, meaning
  nothing is grantable. The values are not validated; see B7.
- `sensitive_permissions`, default `["secrets","administration"]`. Used only by
  policy `is_sensitive`, where any listed key at any level is sensitive.
- `create_owners: [org]`, default `[]`, meaning creation is disabled.

Globs are Python `fnmatch`: case-sensitive on POSIX, with `*`, `?`, `[seq]`
and `[!seq]`, and `*` **does** match `/`. They are matched against the
normalized lowercase `owner/repo`.

Permission levels: `read=1 < write=2 < admin=3`.

### 2.2 validate_request

**Normalization `_normalize_repo`** (`github.py:42-51`). This applies to both
capabilities.
1. If `resource` is not pure ASCII, or contains any char `< 0x20` or `0x7f`
   (checked **before** stripping) → deny
   `github resource contains control or non-ASCII characters`.
2. Then `strip()` whitespace, strip `/` on both ends, `strip()` again, and
   lowercase. Python `str.strip()` strips Unicode whitespace, but step 1
   already guarantees ASCII.

**capability dispatch**: `create` goes to §2.2b. Anything other than `repo` →
deny `github capability must be 'repo' or 'create'`.

**2.2a `repo`** (`github.py:104-142`). The order matters:
1. normalize
2. `repo.count("/") != 1` → `github resource must be 'owner/repo'`
3. Not a fullmatch of `[a-z0-9_.-]+/[a-z0-9_.-]+`, or the repo half is `.` or
   `..` → `invalid github repository {repo!r}`. The owner half may be `.`,
   `..`, `_` and so on; see B6.
4. Any denylist glob matches → `repo {repo!r} is never brokered (denylist)`
5. The allowlist is non-empty and no glob matches → `repo {repo!r} is not in the allowlist`
6. `scope.permissions` is not a non-empty object →
   `scope.permissions is required, e.g. {"contents": "write"}`
7. For each `(perm, level)` **sorted by perm**:
   - `level = str(level).lower()`. Not in `read|write|admin` →
     `invalid permission level {level!r} for {perm!r}`.
   - `perm` is not a key of `permission_ceiling` →
     `permission {perm!r} is not grantable by policy`.
   - `level > ceiling` →
     `permission {perm}:{level} exceeds policy ceiling {perm}:{ceiling}` (no repr).
   - For levels >= write, add the note `grants {perm}:{level} on {repo}`.
8. The output is `resource=repo` and `scope={"permissions": normalized}`.
   Any other scope keys are dropped silently.

**2.2b `create`** (`github.py:144-181`):
1. normalize
2. `count("/") != 1` → `github create resource must be 'org/name'`
3. `owner` is not in `{o.lower() for o in create_owners}` →
   `repos can't be created under {owner!r} (platforms.github.create_owners)`
4. Any of the following → `invalid repository name {name!r}`:
   - `name` is not a fullmatch of `[a-z0-9._-]{1,100}`
   - it ends with `.git`
   - it starts with `.`
   - it ends with `.github.io`
   - it has no alphanumeric character (`.`, `..`, `...`, `-`, `_`, `-._` are all refused)
5. denylist / allowlist exactly as in `repo` steps 4-5, with the same messages.
6. `set(scope) - {"visibility"}` is non-empty →
   `unknown scope keys for create: {sorted(unknown)}` (Python list repr).
7. `visibility = str(scope.get("visibility","private")).lower()`. Not in
   `private|public` → `scope.visibility must be 'private' or 'public'`.
8. Notes: `creates a new {visibility} repo {repo}`. When public, also add
   `PUBLIC: everything pushed to it is visible to anyone`.
9. The output is `resource=repo` and `scope={"visibility": v}`.

Accepted examples, from tests: `a.b`, `x-1`, `_x`, `github.io-notes`.

### 2.3 GitHub API mechanics

Every call uses a fresh HTTP client. Timeouts are noted per call.

**App JWT** (`_app_headers`, `github.py:536-547`): RS256 over the PEM file,
with claims `{"iat": now-60, "exp": now+540, "iss": app_id}`. `app_id` is a
JSON **string**, and the JWT header is the PyJWT default
`{"alg":"RS256","typ":"JWT"}`. Request headers:
`Authorization: Bearer <jwt>`, `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28`.

**Installation-token headers** (`_token_headers`): `Authorization: token <tok>`
plus the same `Accept` and `X-GitHub-Api-Version`.

**Installation resolution** `_installation_for(repo)` (`github.py:260-296`):
- **Pinned** (`installation_id` set): resolve the account login once with
  `GET {api}/app/installations/{id}` (App JWT, 30s).
  - A non-200 response → `lookup of pinned installation {id!r} failed ({status})`.
  - No `account.login` → `pinned installation {id!r} has no account login`.
  - The login is cached lowercased for the life of the process.
  - If `repo.owner != login` →
    `repo {repo!r} is not covered by the pinned installation (GITHUB_INSTALLATION_ID belongs to {account!r}); unset it to resolve installations per repo`.
  - Otherwise return the pinned id.
- **Unpinned**: look in the in-memory cache `repo -> id`, which is never
  invalidated. Otherwise call `GET {api}/repos/{owner}/{repo}/installation`
  (App JWT, 30s).
  - 404 → `the GitHub App is not installed on {repo!r} (install it on that account/repo, then retry)`.
  - Any other non-200 → `installation lookup for {repo!r} failed ({status})`.
  - Otherwise cache and return `json.id`.

**Mint** `_mint(grant)` (`github.py:512-534`): `POST {api}/app/installations/{iid}/access_tokens`
(App JWT, 30s), body:

```json
{"repositories": ["<repo half of grant.resource>"], "permissions": <grant.scope.permissions>}
```

The repository is given as the bare name; GitHub resolves it against the
installation's account. A response other than 201 logs the status and the
first 300 characters of the body, then raises
`GitHub token mint failed ({status})`. The result is `(json.token,
parse(json.expires_at))`, where the `Z` suffix means UTC.

**Token cache**: table `credentials(id, grant_id, kind, value_encrypted, expires_at, created_at)`.
`_cache_token` deletes every row for the grant, then inserts
`kind="github_installation_token"` with the Fernet-encrypted token and
GitHub's `expires_at`. `_cached` returns the newest row for the grant.

### 2.4 `repo`: provision / credential / revoke

- **provision**: `_mint`, then `_cache_token`. Minting proves the installation
  covers the repo. State: `{"repo": resource, "permissions": {...}}`.
- **get_credential** (`github.py:208-235`):
  - The grant is not ACTIVE, or `expires_at <= now` →
    `grant is not active; refusing to mint a token`.
  - If the cached row has `expires_at - now > 5 min`, return it decrypted.
  - Otherwise `_mint` and `_cache_token`, then return.
  - Response: `{kind:"github_installation_token", value:<token>, expires_at:<token expiry>}`.
    `username`, `url` and `note` are null. Note that `expires_at` is the
    **token's** expiry, up to 1h, and can be later than the grant's expiry.
- **revoke** (`github.py:191-206`): if a cached row exists, decrypt it and send
  `DELETE {api}/installation/token` (token auth, 15s). This is best effort: any
  exception, including a decrypt error, is logged as a warning, and the
  response status is not checked. Then delete every `credentials` row for the
  grant. It never raises, apart from DB errors.
  Already-issued tokens that were not the latest cached one, or that come from
  a concurrent mint, are not revoked and live up to 1h.

### 2.5 `create`: provision / credential / revoke

**provision** `_create` (`github.py:319-377`):
1. `org, name = resource.split("/", 1)`; `visibility = scope.visibility`.
2. `_org_installation(org)`:
   - Pinned: the account must equal `org`, otherwise
     `org {org!r} is not the pinned installation's account ({account!r})`.
   - Unpinned: `GET {api}/orgs/{org}/installation` (App JWT, 15s). A non-200 →
     `the GitHub App is not installed on org {org!r} ({status})`. Otherwise use `json.id`.
3. `_admin_token`: `POST {api}/app/installations/{iid}/access_tokens` (App JWT,
   30s), body **exactly** `{"permissions": {"administration": "write", "metadata": "read"}}`.
   There is no `repositories` key, so the token covers every repo of the
   installation. A response other than 201 logs the body, then raises
   `could not mint an Administration token for {org!r} ({status}); does the GitHub App have Administration: write there?`.
4. `POST {api}/orgs/{org}/repos` (admin token auth, 30s), body
   `{"name": name, "visibility": visibility, "private": visibility == "private"}`.
   - 201 → `repo = json`, `created = true`.
   - 422 → log a warning with the first 300 characters of the body (never shown
     to the agent), then `_adopt_own`, and `created = false`.
   - Anything else → log, then
     `ProvisionerError(f"GitHub repo create failed ({status})")`.
5. **Always**, in a `finally`, once a token has been minted:
   `DELETE {api}/installation/token` with the admin token (15s), run
   **shielded from cancellation** (`asyncio.shield`). Rust must use a
   detached or `Drop`-guarded task that runs even when the provisioning future
   is dropped. Exceptions are logged
   (`failed to revoke the Administration token after a repo create`). A status
   other than 204 is logged with `returned {status}`, which the test asserts.
   Nothing is raised.
6. `_installation_covers(resource)`: `GET {api}/repos/{resource}/installation`
   (App JWT, 15s). 200 → cache the id and return true. Any other status →
   false. Any exception → false, with a warning. A coverage failure never
   fails the grant.
7. State:
   `{"action":"create","repo":resource,"html_url":repo.html_url,"repo_id":repo.id,"visibility":repo.visibility or requested,"created":bool,"installation_covers":bool}`.

**`_adopt_own`** (`github.py:379-406`), on 422:
- `own` = the GitHub ids from earlier grants with the same agent_id, the same
  resource, `platform=github`, `id != this`, `capability=="create"`,
  `state.created is True` and a non-null `state.repo_id`. Any status counts,
  including expired, revoked and failed.
- `own` empty → `repository already exists (not created by the broker)`.
  **No GitHub lookup is made.**
- Otherwise `GET {api}/repos/{resource}` with the admin token. A non-200 →
  `GitHub repo create failed (422)`.
- `repo.id not in own` → `repository already exists (not created by the broker)`.
- `actual = repo.visibility or ("private" if repo.private else "public")`.
  If it differs from the requested visibility →
  `repository already exists as {actual}, not the requested {wanted}`.
- Otherwise return the repo dict.

**get_credential**: requires ACTIVE and unexpired, like `repo`. It returns
`{kind:"github_repo", value: state.html_url, note}`. The note is:

```
"{'created' if state.created else 'already existed'}: {state.repo} ({state.visibility}). Request a 'repo' grant on it for access."
```

plus, if `state.installation_covers` is false (missing counts as true):
`" The broker's GitHub App installation does not cover it yet, so repo grants on it will fail until it is added to the installation."`

**revoke**: no-op. The broker never deletes repositories.

### 2.6 `own_token(repo, permissions)` (wiki, broker-internal)

`github.py:490-510`. The in-memory cache is keyed by
`(repo, sorted(permissions))`. A cached token is reused while more than
5 minutes of validity remain. Otherwise `_installation_for`, then
`POST .../access_tokens` with `{"repositories":[name], "permissions": permissions}`.
A response other than 201 → `GitHub token mint for {repo!r} failed ({status})`.
This token is never returned to an agent.

### 2.7 Catalog

`{platform:"github", capability_hint:"repo", resource_hint:"owner/repo", repo_allowlist: allowlist or ["<any>"], permission_ceiling, create_owners: list or omitted, create_disposition: <disposition of capability "create"> if create_owners else omitted}`.
The denylist is **not** advertised. `create_disposition` is downgraded to
`"human review"` when the matching rule is not explicit and the authority needs
an explicit rule (`catalog.py:44-51`).

---

## 3. Homelab / LLDAP (`provisioners/lldap.py`)

`capability="group"`, `resource=<LLDAP group displayName>`, `scope={}`.

### 3.1 Config

Env:
- `LLDAP_URL` (trailing `/` stripped)
- `LLDAP_ADMIN_USER`
- `LLDAP_ADMIN_PASSWORD`
- `LLDAP_SET_PASSWORD_BIN`, default `lldap_set_password`
- `ENCRYPTION_KEY`, needed for managed accounts

Policy `platforms.homelab`:
- `allowed_groups`, default `[]`. **Empty means every group, including
  `lldap_admin`**; see B1.
- `group_descriptions: {group: text}`, used by the catalog.
- `managed_accounts`, default `true`.
- `managed_username_prefix`, default `"svc-"`, at most 32 characters.
- `managed_email_domain`, default `"agents.invalid"`, at least 1 character.

`manages_accounts = managed_accounts && secret_box.is_some()`.

### 3.2 validate_request (`lldap.py:94-106`)

1. `capability != "group"` → `homelab capability must be 'group'`
2. `group = resource.strip()`. There is no case folding.
3. `allowed_groups` is non-empty and `group` is not in it (exact match) →
   `group {group!r} is not brokered (allowed_groups)`
4. The agent has no `lldap_username` and `!manages_accounts` →
   `agent {agent.name!r} has no LLDAP service account configured`
5. The output is `resource=group` and `scope={}`. Other scope is dropped.

### 3.3 LLDAP API mechanics

- **Login** `_login` (`lldap.py:297-306`): `POST {url}/auth/simple/login` with
  JSON `{"username": admin_user, "password": admin_password}` (15s). A non-200 →
  `LLDAP login failed ({status})`. The JWT is `json.token`, cached in memory.
- **GraphQL** `_graphql` (`lldap.py:308-332`): `POST {url}/api/graphql` with
  `Authorization: Bearer <jwt>` and JSON `{"query": q, "variables": vars or {}}`
  (15s). It logs in first if no JWT is cached. On **401 for the first attempt
  only**, it logs in again and retries once. Then:
  - A non-200 → logs the first 300 characters of the body, then raises
    `LLDAP GraphQL error ({status})`.
  - A non-empty `errors` array → raises `LLDAP GraphQL error (see broker logs)`.
    The messages joined with `; ` are logged unless `log_errors=false`.
- Queries and mutations, verbatim:
  - `query { groups { id displayName } }`
  - `mutation AddUserToGroup($user: String!, $group: Int!) { addUserToGroup(userId: $user, groupId: $group) { ok } }`
  - `mutation RemoveUserFromGroup($user: String!, $group: Int!) { removeUserFromGroup(userId: $user, groupId: $group) { ok } }`
  - `mutation CreateUser($user: CreateUserInput!) { createUser(user: $user) { id } }`
  - `query UserExists($user: String!) { user(userId: $user) { id } }`
  - `query UserGroups($user: String!) { user(userId: $user) { groups { id } } }`
- **Group id** `_group_id(name)`: there is an in-memory map
  `displayName -> id`. If `name` is missing, re-fetch all groups and **replace**
  the map. If it is still missing → `LLDAP group {name!r} does not exist`.
  An existing entry is never refreshed; see B5.
- **`_mutate(mutation, user, group_id, want_member)`** (`lldap.py:344-364`):
  run the mutation. On `ProvisionerError`, query `UserGroups`:
  - If that query also fails, re-raise the **original** error.
  - If `(group_id in groups) == want_member`, treat it as success and log the
    no-op.
  - Otherwise re-raise.

  This is how duplicate adds and absent removes are handled: LLDAP reports both
  as opaque DB errors.
- **`_user_exists(u)`**: runs `UserExists` with `log_errors=false`. Any
  `ProvisionerError` counts as false (LLDAP returns an error for an unknown
  user). Otherwise the result is `bool(data.user)`.

### 3.4 Managed accounts

**`managed_username(agent)`** = `(prefix + agent.name).lower()`.

**`ensure_account(session, agent)`** (`lldap.py:191-229`):
1. Return immediately if `agent.lldap_username` is set.
2. If `!manages_accounts` →
   `agent {name!r} has no LLDAP service account and managed accounts are unavailable (ENCRYPTION_KEY unset or disabled in policy)`.
3. Take a process-wide async mutex, then re-read the agent row (refresh) and
   return if `lldap_username` is now set.
4. `username` must fullmatch `[a-z0-9_.-]+`, otherwise
   `cannot derive an LLDAP user id from {agent.name!r}`.
5. If `!_user_exists(username)`, run `CreateUser` with
   `{"user": {"id": username, "email": f"{username}@{managed_email_domain}", "displayName": f"{agent.name} (agent-auth managed)"}}`.
   If the user already exists, it is **adopted** with no ownership check; see B2.
6. `password = token_urlsafe(32)`: 32 random bytes, base64url without padding,
   which is 43 characters. Run the set-password tool (below). On failure the
   error propagates and the agent row is **not** modified.
7. Set `agent.lldap_username = username` and
   `agent.lldap_password_encrypted = Fernet(password)`, then flush. The commit
   happens with the provision transaction.

**Set password** `_run_set_password` (`lldap.py:249-285`):
1. Get a **fresh** admin JWT with `_login()`; the cached one is not used.
2. Exec `[bin, "--base-url", url, "--token", <jwt>, "--username", username]`
   with environment = broker env plus `LLDAP_USER_PASSWORD=<password>`, stdin
   from `/dev/null`, and stdout and stderr merged into one pipe.
3. Errors:
   - Binary not found →
     `{bin!r} not found; install lldap's lldap_set_password or set LLDAP_SET_PASSWORD_BIN`
   - More than 30s → kill it, then `lldap_set_password timed out`
   - rc != 0 → log rc and the first 300 characters of output, then
     `lldap_set_password failed (see broker logs)`

   The admin JWT is on the command line; see B4.

**`rotate_password(session, agent)`** (`lldap.py:231-242`). It is reached from
`POST /admin/agents/{id}/rotate-lldap-password` (`admin_routes.py:213-238`).
That route returns 501 if homelab is disabled, refuses the operator row, maps
`ProvisionerError` to 409, and returns `AgentOut` **without** the password.
The checks:
- No `lldap_username` or no `lldap_password_encrypted` →
  `agent {name!r} has no broker-managed LLDAP account to rotate`. This means
  hand-registered accounts are never touched.
- No secret_box → `ENCRYPTION_KEY is unset; cannot store the new password`.
- Otherwise generate a new password, set it, store it encrypted, and flush.

### 3.5 provision / revoke / credential

- **provision** (`lldap.py:108-115`): load the agent and run `ensure_account`
  if it has no username. Then `_group_id(resource)` and
  `_mutate(ADD, username, gid, want_member=true)`. State:
  `{"lldap_user": username, "group": resource, "group_id": gid}`.
- **revoke** (`lldap.py:117-156`):
  1. Take `user` and `group_id` from state. If either is missing (the reaper
     path), use `agent.lldap_username`. If that is also missing, return with
     nothing to do. Otherwise `group_id = _group_id(resource)`.
  2. **Keeper check**: if another grant exists with `id != this`, the same
     agent_id, `platform=homelab`, the same resource, `status=ACTIVE` and
     `expires_at > now`, log and return **without** removing. Expiry is
     checked as well as status, so that when several grants lapse in the same
     tick, one of them still removes the membership.
  3. Otherwise `_mutate(REMOVE, user, gid, want_member=false)`.
- **get_credential** (`lldap.py:158-182`): the grant is not ACTIVE or has
  expired → `grant is not active`.
  - **Managed** (the agent has `lldap_password_encrypted` and a secret_box
    exists): `{kind:"lldap_account", username: agent.lldap_username, value: <decrypted password>, note}`.
    The note is
    `LLDAP service account {username!r} is in group {resource!r}; log in to Authelia-protected services with this username/password`.
    The value is the same on every fetch until it is rotated.
  - **Otherwise**: `{kind:"lldap_group", username: agent.lldap_username (or null), value: null, note}`.
    The note is
    `your service account is now in group {resource!r}; authenticate to Authelia-protected services with your own credentials`.

### 3.6 Catalog

`{platform:"homelab", capability_hint:"group", resource_hint:"<lldap group>", groups:[{name, description: group_descriptions.get(name)}] for allowed_groups}`.
With an empty `allowed_groups`, the list is empty even though every group is
grantable.

---

## 4. Kubernetes (`provisioners/kubernetes.py`)

`capability=<ClusterRole name>`, `resource=<namespace>` or `"*"` for
cluster-wide.

### 4.1 Config

Env:
- `KUBERNETES_API_URL`: either `in-cluster`, or a comma-separated list of URLs.
  Entries are trimmed, empty ones dropped, and a trailing `/` stripped. An
  empty list raises `ValueError("kubernetes api_url is empty")`.
- `KUBERNETES_TOKEN`
- `KUBERNETES_TOKEN_FILE`
- `KUBERNETES_CA_FILE`
- `KUBERNETES_INSECURE_SKIP_VERIFY`, default false

`in-cluster` means:
- URL `https://{KUBERNETES_SERVICE_HOST or kubernetes.default.svc}:{KUBERNETES_SERVICE_PORT or 443}`
- token_file defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`
- ca_file defaults to `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`

TLS verify is off if the insecure flag is set. Otherwise it uses `ca_file`, or
the system roots when no CA file is given.

**Bearer token**: if `token_file` is set, it is **re-read on every request**
(projected tokens rotate). A read error →
`cannot read kubernetes token file: {exc}`. If there is no file and no token →
`no kubernetes credentials configured`.

Policy `platforms.kubernetes` (`schema.py:130-166`):
- `namespace_allowlist`, default `[]`, meaning nothing is grantable.
- `role_allowlist`, default `["view"]`.
- `cluster_role_allowlist`, default `[]`, meaning cluster-wide is off.
- `cluster_grant_namespace`, default `"default"`.
- `role_descriptions`.
- `sensitive_roles`, default `["edit","admin"]`.
- `sensitive_namespaces`, default
  `["kube-system","kube-public","kube-node-lease","flux-system"]`.

`namespace_is_sensitive(ns) = ns == cluster_grant_namespace || any fnmatch(ns, sensitive_namespaces)`.

### 4.2 validate_request (`kubernetes.py:93-141`)

`role = capability.strip()`, which is case-sensitive.
`namespace = resource.strip().lower()`.

**Cluster-wide** (`namespace == "*"`):
1. `cluster_role_allowlist` is empty → `cluster-wide grants are not enabled`
2. `role` is not in it →
   `role {role!r} is not grantable cluster-wide; allowed: {cluster_role_allowlist}`
   (Python list repr). The role does **not** also need to be in `role_allowlist`.
3. The output is `capability=role`, `resource="*"`, `scope={"cluster": true}`,
   with the note
   `binds role {role!r} CLUSTER-WIDE across all namespaces — very broad; always human-reviewed`.

**Namespaced**:
1. `role` is not in `role_allowlist` →
   `role {role!r} is not grantable; allowed: {role_allowlist}`
2. `namespace` does not fullmatch `[a-z0-9]([a-z0-9-]*[a-z0-9])?` →
   `invalid namespace name {namespace!r}`. There is no 63-character limit check.
3. No `namespace_allowlist` glob matches →
   `namespace {namespace!r} is not brokered (allowlist)`
4. The output is `scope={}`. Any input scope is discarded, including
   `cluster: true`.
5. Notes:
   - Always: `binds role {role!r} in namespace {namespace!r} (namespace-scoped)`.
   - If the role is `edit` or `admin`: `{role} can run pods as any ServiceAccount in {namespace} — broad`.
   - If the namespace is sensitive: `{namespace} is a sensitive namespace (its ServiceAccounts are the cluster's own or back other grants) — always human-reviewed`.

### 4.3 HTTP mechanics

**`_request(method, path, json?)`** (`kubernetes.py:326-354`):
- The headers are `Authorization: Bearer <token>`, computed once per call
  before any endpoint is tried. Timeout is 20s.
- Try the endpoints in their current order. A transport error
  (connect/timeout/etc.) logs a warning and moves to the next one. **Any HTTP
  response, whatever its status, is returned to the caller.**
- If endpoint `i > 0` answered, rotate the list so that it comes first. The
  list is replaced, not mutated.
- If every endpoint failed → `kubernetes API unreachable: {last_exc}`.

**`_create(path, body)`**: POST. 200 or 201 is OK. 409 → `_verify_ours`.
Anything else → log the first 300 characters of the body, then
`create {kind} failed ({status})`.

**`_verify_ours(collection_path, body)`**: `GET {collection_path}/{name}`.
- A non-200 →
  `{kind} {name!r} already exists but could not be verified ({status}); refusing to adopt it`.
- A mismatch in any of the following →
  `{kind} {name!r} already exists and belongs to something else ({list} differ); refusing to adopt it`,
  where `{list}` is the comma-joined names below, in this order:
  - `grant-id annotation`: the wanted annotation is empty, or
    `existing.metadata.annotations["agent-auth/grant-id"]` differs from it
  - `roleRef`: only if the body has one; compared by deep equality
  - `subjects`: only if the body has them; compared by deep equality

**`_delete(path)`**: DELETE. 200, 202 or 404 is OK. Anything else →
`delete failed ({status})`.

### 4.4 Object names and manifests

**SA name** `_sa_name(agent_name, grant_id)` (`kubernetes.py:31-36`):
1. `base = re.sub("[^a-z0-9-]+", "-", agent_name.lower()).strip("-")[:22].rstrip("-")`
2. `name = f"aa-{base}-{grant_id}"[:63].rstrip("-")`

The full 36-character UUID always fits, because 3 + 22 + 1 + 36 = 62.

Common metadata, where `cluster = (resource == "*")` and
`sa_ns = cluster ? cluster_grant_namespace : resource`:

```yaml
labels:      {app.kubernetes.io/managed-by: agent-auth}
annotations: {agent-auth/agent: <agent.name>, agent-auth/grant-id: <grant.id>,
              agent-auth/expires-at: <grant.expires_at.isoformat()>}   # e.g. 2026-10-25T12:00:00.123456+00:00
```

**provision** (`kubernetes.py:143-239`):
1. `POST /api/v1/namespaces/{sa_ns}/serviceaccounts`:
   `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name","namespace":sa_ns,"labels","annotations"}}`.
2. `subject = {"kind":"ServiceAccount","name":name,"namespace":sa_ns}` and
   `roleRef = {"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":role}`.
   The roleRef is always a ClusterRole, even for namespaced grants.
3. Pick a branch:
   - **Cluster with zone exclusions**: `excluded = zones.excluded_namespaces(agent)`
     is non-empty.
     - `GET /api/v1/namespaces`. A non-200 → `listing namespaces failed ({status})`.
     - `bound` = the item names, sorted, that match no excluded glob.
     - For each namespace in `bound`, `POST /apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings`
       with `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{name, namespace:ns, labels, annotations},"roleRef","subjects":[subject]}`.
     - On a `ProvisionerError` mid-loop, delete every RoleBinding created so far
       and the SA, then re-raise.
   - **Cluster without exclusions**: `POST /apis/rbac.authorization.k8s.io/v1/clusterrolebindings`
     with `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{name, labels, annotations},"roleRef","subjects":[subject]}`.
   - **Namespaced**: `POST /apis/rbac.authorization.k8s.io/v1/namespaces/{sa_ns}/rolebindings`
     with a RoleBinding as above, with `namespace: sa_ns`.
4. State: `{"namespace": sa_ns, "service_account": name, "role": role, "cluster": bool}`,
   plus `"bound_namespaces": [...]` and `"excluded": [...]` in the zone branch.

**revoke** (`kubernetes.py:248-266`):
- If the state has no `namespace` or no `service_account`, return with nothing
  to do. This is the reaper or failed-provision path; see B10.
- If `bound_namespaces` is present (even if empty), delete each
  `/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}`.
- Else if `cluster`, delete `/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}`.
- Otherwise delete `/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings/{name}`.
- **Then**, in every case, delete `/api/v1/namespaces/{namespace}/serviceaccounts/{name}`.
  Deleting the SA invalidates every token bound to it.

**get_credential** (`kubernetes.py:268-311`):
1. The grant is not ACTIVE or has expired →
   `grant is not active; refusing to mint a token`.
2. The state has no namespace or service_account →
   `grant has no provisioned service account`.
3. `remaining = int(expires_at - now)` seconds.
   `expiration = max(600, min(3600, remaining))`.
4. `POST /api/v1/namespaces/{ns}/serviceaccounts/{name}/token` with
   `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"expirationSeconds": expiration}}`.
   There are no audiences and no boundObjectRef. A status other than 200/201
   → log, then `TokenRequest failed ({status})`.
5. Response: `{kind:"kubernetes_token", value: status.token, expires_at: parse(status.expirationTimestamp) or null, note}`.
   The note is
   `bearer token for ServiceAccount {ns}/{name} ({state.role}) against {current preferred api_url}; re-fetch rather than caching — the account is deleted when the grant ends`.
   Nothing is cached.

### 4.5 Catalog

`{platform:"kubernetes", capability_hint:"<role name>", resource_hint:'<namespace>, or "*" for cluster-wide', namespace_allowlist, roles:[{name, description: role_descriptions.get, typical_disposition}] for role_allowlist, cluster_roles: cluster_role_allowlist or omitted}`.
`typical_disposition` is evaluated with `resource="*"` and `scope={}`.

---

## 5. Models / LiteLLM (`provisioners/models.py`)

`capability="use"`, `resource=<platforms.models.name>`, `scope={}`.

### 5.1 Config

Env:
- `LITELLM_MASTER_KEY`: sent only as `Authorization: Bearer <master>` to the
  admin base.
- `ENCRYPTION_KEY`

Policy `platforms.models` (`schema.py:268-301`):
- `name`, default `"litellm"`, must match `[a-z0-9][a-z0-9-]{0,62}`.
- `url`: empty means off. It must match `https?://[^\s/]+(/[^\s]*)?`.
- `admin_url`: optional, same pattern. The admin base is
  `(admin_url or url).rstrip("/")`.
- `models: [str]`: empty means every model.
- `by_runtime: {runtime|"*": [str]}`: when non-empty it takes precedence.
- `max_budget: float|null`
- `budget_duration`, default `"30d"`.

`_models(agent)`: if `by_runtime` is non-empty, return
`by_runtime[agent.runtime]` if that key is present, otherwise
`by_runtime.get("*", [])`. Otherwise return `models`. An agent with
`runtime=None` gets the `"*"` list.

### 5.2 validate_request (`models.py:48-61`)

1. `capability != "use"` → `models capability must be "use"`
2. `resource != name` (exact, no strip or lowercase) →
   `unknown model gateway {resource!r} (this broker has {name!r})`
3. `scope` is non-empty →
   `no scope for models grants: what a key may call is the gateway's policy`
4. `by_runtime` is set and `_models(agent)` is empty →
   `no models for runtime {(agent.runtime or '(none)')!r} at this gateway (only {', '.join(sorted(by_runtime))})`
5. Note: `may call: {', '.join(models) or 'every model the gateway serves'}`.

### 5.3 LiteLLM calls (timeout 20s; a transport error raises `model gateway: {exc}`)

**`_ensure_user(agent)`**:
1. `GET {admin}/user/info?user_id=<agent.name>`. If the response is 200 and
   `json.user_info.user_id == agent.name`, the user exists; done.
2. Otherwise `POST {admin}/user/new` with
   `{"user_id": name, "user_alias": name, "user_role": "internal_user_viewer", "auto_create_key": false, "metadata": fields(agent)}`.
   A status other than 200/201, unless the body contains `already exists` →
   `model gateway refused the user for {name}: {status} {text[:200]}`.

`fields(agent) = {"agent","project","host","runtime","placement"}`, taken from
the agent row.

**provision** (`models.py:98-128`):
1. The agent is missing → `agent not found`.
2. `_ensure_user`.
3. `secs = max(60, int(expires_at - now))`.
4. Build the body:
   `{"user_id": name, "key_alias": f"{name}/{grant.id[:8]}", "duration": f"{secs}s", "metadata": {**fields, "grant_id": grant.id, "issued_by": "agent-auth"}}`.
   - If `by_runtime` is set and the model list is empty →
     `no models for runtime {agent.runtime!r}`.
   - Add `"models"` only when the list is non-empty.
   - Add `"max_budget"` and `"budget_duration"` only when `max_budget` is not null.
5. `POST {admin}/key/generate`. A non-200, or no `json.key` →
   `model gateway refused the key: {status} {text[:200]}`.
6. State: `{"key_encrypted": Fernet(key), "key_alias": alias, "user_id": name}`.
   The key is stored in `provisioner_state`, not in the `credentials` table.

**revoke** (`models.py:130-139`):
1. If the state has no `key_encrypted`, return.
2. `POST {admin}/key/delete` with `{"keys": [<plaintext key>]}`.
3. A 404, or a 400 whose body contains `not found` (case-insensitive), counts
   as success. Any other non-200 →
   `model gateway did not delete {key_alias}: {status} {text[:200]}`.

**get_credential** (`models.py:141-158`):
- The grant is not ACTIVE or has expired → `grant is not active`.
- No key in state → `no key was issued for this grant`.
- Response: `{kind:"model_gateway_key", value: key, url: config.url.rstrip("/"), expires_at: grant.expires_at, note}`.
  The note is
  `Claude Code: ANTHROPIC_BASE_URL={base} and ANTHROPIC_AUTH_TOKEN=<this key>. OpenAI-compatible clients (codex): base URL {base}/v1 with this key. The key is yours alone and ends with the grant.`

**usage(names)**, used by `/admin/models/usage` (`admin_log_routes.py:281-318`):
- Up to 8 concurrent calls to `GET /user/info?user_id=` for the names of agents
  that ever held a models grant.
- A 400 or 404 means "no user". Any other non-200 →
  `model gateway: {status} {text[:200]}`.
- Users whose `user_info.user_id` differs from the requested name are ignored.
- **It must never call `/user/list`**, which the test asserts.

### 5.4 Catalog

`{platform:"models", capability_hint:"use", resource_hint:name, capabilities:["use"], gateway:{name, url, models: models or null}}`.
`by_runtime` is not shown.

---

## 6. MCP (`provisioners/mcp.py`) and the token routes

`capability="use"`, `resource=<server name>`, `scope={"tools":[...]}`.

### 6.1 Config

Policy `platforms.mcp`:
- `issuer`: required `https://…` when servers are listed.
- `token_ttl`, default `"1h"` (`parse_duration`).
- `servers: {name: {url, description="", tools=[], audience=null}}`. The name
  must match `[a-z0-9][a-z0-9-]{0,62}`.

`audience(server) = server.audience or server.url`.

Env: `BROKER_SIGNING_KEY`. The ES256 key is derived from it with HKDF; see the
token spec.

### 6.2 validate_request (`mcp.py:42-66`)

1. `name = resource.strip().lower()`. It is not in `servers` →
   `no MCP server {name!r} in the catalog (there is: {', '.join(sorted(servers)) or 'none'})`.
   This check comes **before** the capability check.
2. `capability != "use"` → `mcp capability is "use"`
3. Scope keys other than `tools` → `an mcp scope is {"tools": [...]} (omit it for every tool)`
4. `tools = scope.get("tools", ["*"])`. Not a list, empty, or more than 64
   entries → `"tools" is a list of 1 to 64 tool names, or ["*"]`
5. Any entry is not a string equal to `*` or matching
   `[A-Za-z0-9_.:/-]{1,128}` → `malformed tool name`
6. `tools = ["*"]` if `"*"` is present, otherwise sorted and unique.
7. `server.tools` is non-empty, `tools != ["*"]`, and some are unknown →
   `{name} has no tool {', '.join(sorted(unknown))}`. `["*"]` is allowed even
   when `server.tools` is non-empty.
8. The output is `resource=name` and `scope={"tools": tools}`. Note:
   `{"every tool" | "tools a, b"} of {name} ({server.url})` plus
   `: {description}` when a description exists.

### 6.3 provision / revoke / credential

- **provision**: the resource is no longer in `servers` →
  `MCP server {resource!r} is no longer in the catalog`. State:
  `{"server": resource}`. No external call is made.
- **revoke**: no-op.
- **get_credential** (`mcp.py:76-103`):
  - The grant is not ACTIVE or has expired → `grant is not active`.
  - The server has been removed → the same "no longer in the catalog" error.
  - Otherwise mint a token:
    `TokenIssuer.mint(subject=f"agent:{agent.name}", audience=audience(server), ttl_secs=min(parse_duration(token_ttl), remaining_secs), claims={"agent": name, "server": resource, "tools": scope.tools or ["*"], "grant": grant.id})`.
  - JWT payload: the claims plus `iss` (issuer with any trailing `/` removed),
    `sub`, `aud` (a single string), `iat=now`, `nbf=now-5`,
    `exp=now+max(1,ttl)`, and `jti=uuid4`. The header is
    `{"alg":"ES256","typ":"JWT","kid":<RFC7638 thumbprint>}`.
  - Response: `{kind:"mcp_token", value: jwt, expires_at: exp as UTC datetime, note}`.
    The note is
    `` Send it to {server.url} as `Authorization: Bearer <value>`. It is short-lived: call get_credential again for a fresh one (nothing new is issued once the grant ends). ``

### 6.4 Token routes (`api/token_routes.py`), unauthenticated

- `GET /.well-known/jwks.json` returns `{"keys":[{crv,kty,x,y,kid,use:"sig",alg:"ES256"}]}`.
  404 if no TokenIssuer is configured.
- `GET /.well-known/openid-configuration` returns the issuer's discovery
  document (`issuer, jwks_uri, id_token_signing_alg_values_supported:["ES256"], subject_types_supported:["public"], response_types_supported:["token"]`).
  When OAuth (remote MCP) is enabled and its base URL equals the issuer (after
  stripping `/`), or there is no issuer, the OAuth authorization-server
  metadata is merged in. If neither exists → 404.
- `GET /v1/tokens/verify?server=<name>`. `server` is a required query param.
  1. If no TokenIssuer is configured → 404.
  2. Any of the following → 401 with header
     `WWW-Authenticate: Bearer error="invalid_token", error_description="a bearer token for a known server is required"`:
     - `server` is not in `platforms.mcp.servers`;
     - the auth scheme, case-insensitive, is not `bearer`;
     - the token is empty.
  3. Verify ES256 with `aud=audience(entry)` and `iss=issuer`; require
     `exp, iat, sub, aud, iss`; allow 5s leeway. Failure, **or**
     `claims.server != server` → 401 with `not a valid token for this server`.
  4. Load the grant by `claims.grant` and then its agent. If any of these hold,
     return 401 with `the grant behind this token has ended`:
     - the grant is missing;
     - the agent is missing or disabled;
     - the grant's platform is not mcp;
     - `grant.resource != server`;
     - the grant is not ACTIVE;
     - the grant has expired.

     Containment and delegation-thread state are **not** checked; see B20.
  5. Otherwise 200 with an empty body, plus headers
     `X-Agent-Auth-Agent: <agent.name>` and
     `X-Agent-Auth-Tools: <claims.tools joined by ",">`.

### 6.5 Catalog

`{platform:"mcp", capability_hint:'use (scope {"tools": [...]}; omit for every tool)', resource_hint:"<server>", capabilities:["use"], servers:[{name,url,description,tools: tools or null}] sorted by name}`.

---

## 7. Agents (`provisioners/agents.py`): minting identities in an agent VM

`capability="mint"`, `resource="<runtime>-<project>-<daemon>-sandbox"`,
`scope={"runtime": r}`.

Config `platforms.agents`:
- `runtimes`, default `["claude","codex"]`. Empty means minting is disabled.
- `lease`, default `"30d"`, giving `lease_secs`.

**validate** (`agents.py:31-66`):
1. `capability != "mint"` → `agents capability must be 'mint'`
2. `runtimes` is empty → `minting is disabled (platforms.agents.runtimes is empty)`
3. The requester's `sandbox_id` daemon is missing or its role is not
   `"sandbox"` → `only agents running in an agent VM can mint identities`
4. `HostExecService.locked(session, daemon.name)` →
   `locked down: no identities are minted until it is lifted`
5. `name = resource.strip().lower()` and `suffix = f"-{daemon.name}-sandbox"`.
   `runtime` is the first configured runtime `r` such that `name` starts with
   `f"{r}-"` and ends with the suffix. If there is none →
   `resource must be '<runtime>-<project>{suffix}' with runtime one of {', '.join(runtimes)}`.
6. `project = name[len(r)+1 : -len(suffix)]` must fullmatch
   `[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?`, otherwise
   `invalid project name {project!r} (lowercase letters, digits and '-', ≤30)`.
7. `scope.runtime` is not in `(None, runtime)`, or other scope keys are present →
   `scope may only repeat the name's runtime`.
8. The output is `scope={"runtime": runtime}`, with the note
   `mints {name} ({runtime} on project {project}) in the agent VM on {daemon.name}`.

**provision** (`agents.py:68-89`):
1. Reload the parent and its daemon. If either is missing →
   `the requesting agent is no longer in an agent VM`.
2. Re-slice `project` from the resource using the **current** daemon name.
3. Call `SandboxService.mint(session, parent, runtime, project, lease_secs)`
   (`core/sandboxes.py:239-284`). `SandboxError` → `ProvisionerError(str)`.
   `mint` behaves as follows:
   - **Existing agent**: if it belongs to a different sandbox, runtime or
     project → `SandboxError("{name} exists and doesn't belong to this sandbox")`.
     Otherwise renew the lease and set `disabled=false` (see B15), and keep its
     key.
   - **New agent**: generate an API key and create the agent row with
     `kind="service"`, `host=daemon.name`, `placement="sandbox"`,
     `sandbox_id=daemon.id`, `parent_agent_id=parent.id` and the lease. The
     full key is queued for delivery to the sandbox daemon, Fernet-wrapped.
4. `nudge(daemon.id)`.
5. State: `{"agent_id","name","created","lease_expires_at": iso}`.

**revoke**: no-op. The identity lives by its lease.

**get_credential** does **not** check grant status. It returns
`{kind:"agent_identity", value: state.name, note}`. The note is
`{'minted'|'renewed'}; lease until {state.lease_expires_at}. Its key went to the sandbox daemon, which runs it — you never hold it.`

**Catalog**: shown only if the agent has a `sandbox_id`:
`{platform:"agents", capability_hint:"mint", resource_hint:"<runtime>-<project>-<this host>-sandbox", capabilities: runtimes}`.

---

## 8. Sandbox (`provisioners/sandbox.py`): cross-project access in an agent VM

`capability ∈ {"project.read","project.write"}`, `resource=<target project>`,
`scope={}`.

**validate** (`sandbox.py:31-49`):
1. The capability is not one of those two →
   `sandbox capability must be one of project.read, project.write`
2. The agent has no `sandbox_id` or no `project` →
   `only a project's agent in an agent VM can ask for this`. The daemon role is
   not checked here.
3. `target = resource.strip().lower()` does not match the PROJECT_RE (§7) →
   `invalid project name {target!r}`
4. `target == agent.project` → `that's your own project`
5. `scope` is non-empty → `no scope for sandbox grants`
6. Note: `{'reads'|'WRITES'} project {target} from project {agent.project}`.

`project.write` is sensitive (`authority.is_sensitive`).

**provision**:
1. Resolve `(agent, daemon)`. The agent is missing, the daemon is missing, or
   the daemon's role is not `"sandbox"` →
   `the requesting agent is no longer in an agent VM`.
2. `hub.call(role, daemon.name, {"type":"project.grant","grant_id","project": agent.project,"target": resource,"access": capability})`.
   `DaemonCallError` → `sandbox {daemon.name}: {exc}`.
3. State: `{"project","target","access"}`.

**revoke**: the same resolution, then
`hub.call(..., {"type":"project.revoke","grant_id","project","target"})`. A
`DaemonCallError` becomes a `ProvisionerError`, which is retried.

**get_credential** does not check status. It returns
`{kind:"project_access", note}`. The note is
`{capability} on /var/lib/sandbox/projects/{resource} is applied to your project's user; it ends with the grant.`

**Catalog**: shown only if the agent has both `sandbox_id` and `project`:
`{platform:"sandbox", capability_hint:"project.read | project.write (write: always a human)", resource_hint:"<another project in this agent VM>", capabilities:["project.read","project.write"]}`.

---

## 9. A2A (`provisioners/a2a.py`), brief; see the a2a spec

**validate**:
1. `capability != "talk"` → `a2a capability must be 'talk'`
2. The recipient is looked up by exact name, with no normalization. Missing or
   disabled → `unknown target agent {resource!r}`
3. The recipient is the requester → `agent cannot request a2a access to itself`
4. `recipient.kind != "service"` →
   `a2a targets must be service agents; {resource!r} is ephemeral and can only initiate threads itself`

The scope is **not** normalized or restricted. It is folded verbatim into the
authority; `topic` is the glob used by `check_grant`.

The other operations:
- provision returns `{"mode":"check_based"}`
- revoke is a no-op
- get_credential returns `{kind:"a2a_grant", note:"a2a grants are check-based; open a thread via POST /v1/a2a/threads"}`
  with no status check.

`check_grant` (`a2a.py:62-98`) is covered by the a2a spec.

**Catalog**: peers are the service agents other than self that are not
disabled and not zone-separated. Each carries a `description` and its
reachability, sorted by `(not reachable, name)`.

## 10. Google stub (`provisioners/google_stub.py`)

- **validate**: the capability is not in
  `{calendar.read, calendar.write, gmail.read, drive.read}` →
  `unknown google capability {cap!r}; known: ['calendar.read', 'calendar.write', 'drive.read', 'gmail.read']`.
  Resource and scope are left untouched. Note:
  `google provisioning is a stub: decision recorded, no credential minted`.
- **provision** returns `{"stub": true}`.
- **revoke** is a no-op.
- **get_credential** raises `NotImplementedError("google workspace provisioning is not implemented")`,
  which becomes HTTP **501**.
- **Catalog**: `{platform:"google", capability_hint:"<calendar.read | gmail.read | ...>", resource_hint:"<calendar id / label / folder>", capabilities: sorted list}`.

## 11. Hostexec (one paragraph; covered by the hostexec spec)

`HostexecProvisioner` (`provisioners/hostexec.py`) has `resource=<host>`,
validated against `NAME_RE` and lowercased. Capabilities are `run`,
`tpl.<name>` and `shell`, and the scope is normalized through
`daemon_common.hostexec.job_spec` or `shell_spec`. Validation denies a host
that is unpaired, offline or locked, a tier the host last reported as disabled,
and shells the host does not allow. `provision` starts the job or shell via
`HostExecService.start`, mapping errors to `"{host} refused: {exc}"`. `revoke`
kills the job or closes the shell. `get_credential` returns
`kind:"hostexec_shell"` (value = grant id; refused once the grant is not
ACTIVE) or `kind:"hostexec_job"` (value = a JSON job summary with
`output_tail`, **with no status check**).

---

## 12. Config summary (env vars read by provisioners)

| env | default | used by |
|---|---|---|
| `ENCRYPTION_KEY` | "" | github (required), homelab managed accounts, models (required), agents key delivery |
| `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY_FILE` | "" | github on/off, JWT |
| `GITHUB_INSTALLATION_ID` | "" | github pin |
| `GITHUB_API_URL` | `https://api.github.com` | github |
| `LLDAP_URL` / `LLDAP_ADMIN_USER` / `LLDAP_ADMIN_PASSWORD` | "" | homelab |
| `LLDAP_SET_PASSWORD_BIN` | `lldap_set_password` | homelab managed accounts |
| `KUBERNETES_API_URL` | "" | k8s (`in-cluster` or comma list) |
| `KUBERNETES_TOKEN` / `KUBERNETES_TOKEN_FILE` / `KUBERNETES_CA_FILE` | "" | k8s |
| `KUBERNETES_INSECURE_SKIP_VERIFY` | false | k8s |
| `KUBERNETES_SERVICE_HOST` / `_PORT` | `kubernetes.default.svc` / `443` | k8s in-cluster |
| `LITELLM_MASTER_KEY` | "" | models |
| `BROKER_SIGNING_KEY` | "" | mcp, agents, sandbox, hostexec |

---

## 13. Security invariants

General:

- **INV-1**: `get_credential` for github, homelab, kubernetes, models and mcp
  issues nothing (no secret, no mint, no gateway call) unless
  `grant.status == ACTIVE` and `grant.expires_at > now`, evaluated inside the
  provisioner at call time.
- **INV-2**: The credential route returns 404 `unknown grant` for any grant
  whose `agent_id` is not the caller's, indistinguishable from a missing grant.
  It returns 403 while the caller is contained, and 403 for a delegated grant
  whose thread is not `open`.
- **INV-3**: No provisioner external mutation runs inside the transaction that
  decides a request. A grant row in `PROVISIONING` is committed before
  `provision` starts. Any grant still in `PROVISIONING` at boot, or older than
  15 minutes, has `revoke` run on it before it is marked `PROVISION_FAILED`,
  and is never issuable.
- **INV-4**: A grant's `resource` and `authority` are exactly the output of
  `validate_request`, run on the final (possibly human-edited) spec at approval
  time. Unvalidated input never reaches `provision`.
- **INV-5**: `revoke` is idempotent. "Already gone" (k8s 404, LLDAP
  membership absent, LiteLLM key not found) counts as success. Any other
  failure leaves the grant ACTIVE for retry.
- **INV-6**: Error messages that reach agents (through `decision_reason` or the
  403 detail) never contain tokens, passwords, the master key, the admin JWT,
  or GitHub/LLDAP/k8s response bodies.

GitHub:

- **INV-G1**: Every token handed to an agent was minted with a body whose
  `repositories` is exactly `[<repo half of grant.resource>]` (length 1) and
  whose `permissions` deep-equals `grant.scope.permissions`.
- **INV-G2**: For every `(perm, level)` in a repo grant, `perm` is a key of
  `permission_ceiling` and `level <= ceiling[perm]` in `read<write<admin`.
- **INV-G3**: A repo grant's resource is ASCII with no control characters as
  submitted, lowercase, and fullmatches `[a-z0-9_.-]+/[a-z0-9_.-]+`. Its repo
  half is not `.` or `..`. It matches no `repo_denylist` glob, and matches some
  `repo_allowlist` glob whenever the allowlist is non-empty. These checks run
  on the normalized string.
- **INV-G4**: When `GITHUB_INSTALLATION_ID` is set, no token is minted for a
  resource whose owner, lowercased, differs from the pinned installation's
  account login, lowercased.
- **INV-G5**: The Administration token minted for `create` is never stored, in
  `credentials` or `provisioner_state`, never returned, and never logged. It
  is used only for `POST /orgs/{org}/repos` and, on a 422 when the agent has a
  prior broker-created repo of that name, for `GET /repos/{org}/{name}`. Once
  it is minted, `DELETE /installation/token` is attempted exactly once, even if
  provisioning errors or is cancelled.
- **INV-G6**: A repo is created only under an org in `create_owners`, with a
  name that passes the §2.2b rules and the allow/denylists. The broker never
  issues a repository DELETE.
- **INV-G7**: A `create` whose name is taken succeeds only if all of these
  hold:
  - the same agent has an earlier github `create` grant on the same resource
    with `state.created == true`;
  - that grant's `state.repo_id` equals the existing repo's id;
  - the existing visibility equals the requested one.

  Otherwise it fails with no details of the existing repository reaching the
  agent.
- **INV-G8**: Cached installation tokens are only at rest Fernet-encrypted. A
  grant has at most one `credentials` row after any mint, and none after
  revoke.

Homelab:

- **INV-L1**: When `allowed_groups` is non-empty, no membership is ever added
  for a group outside it (exact match after trimming).
- **INV-L2**: A managed LLDAP password leaves the broker only:
  - in a `get_credential` response to the owning agent with an ACTIVE,
    unexpired homelab grant;
  - and in the `LLDAP_USER_PASSWORD` environment variable of the
    `lldap_set_password` child.

  It is never in `provisioner_state`, argv, logs, `decision_reason`, admin
  responses (including rotate), or the catalog.
- **INV-L3**: `agents.lldap_username` and `agents.lldap_password_encrypted`
  for a managed account are written only after `lldap_set_password` exited 0.
  The stored ciphertext always corresponds to the last password set by the
  broker.
- **INV-L4**: A revoke removes `(user, group)` membership only if no other
  grant exists with the same agent, the homelab platform, the same resource,
  status ACTIVE and `expires_at > now`.
- **INV-L5**: The broker never sets or rotates the password of an account it
  did not create, meaning one with `lldap_password_encrypted IS NULL`. The
  Python adoption path violates this; see B2.

Kubernetes:

- **INV-K1**: Each grant has its own ServiceAccount, named
  `aa-<≤22-char sanitized agent>-<full grant UUID>` (≤63 characters, DNS-1123).
  It is annotated `agent-auth/grant-id=<grant.id>`, and every binding the
  grant creates has `subjects == [{kind:ServiceAccount, name, namespace: sa_ns}]`.
- **INV-K2**: Every binding's `roleRef` is `ClusterRole/<role>`. For a
  namespaced grant, the role is in `role_allowlist` and the namespace is a
  DNS-1123 label matching `namespace_allowlist`. For a cluster-wide grant, the
  role is in `cluster_role_allowlist`.
- **INV-K3**: An `AlreadyExists` (409) object is adopted only if its
  `agent-auth/grant-id` annotation equals this grant's id and, for bindings,
  its `roleRef` and `subjects` deep-equal the intended ones. Otherwise
  provisioning fails before any later object is created.
- **INV-K4**: TokenRequest `expirationSeconds` is
  `clamp(remaining_grant_secs, 600, 3600)`. Revocation deletes the binding(s)
  **before** the ServiceAccount, and deleting the SA is what kills issued
  tokens.
- **INV-K5**: A cluster-wide grant for an agent with zone exclusions never
  creates a ClusterRoleBinding. It creates RoleBindings only in namespaces that
  match no excluded glob, and if any creation fails, it deletes every binding
  it made plus the SA.
- **INV-K6**: Cluster-wide authorities, sensitive roles and sensitive
  namespaces are always sensitive, so a human decides them (policy spec).

Models:

- **INV-M1**: `LITELLM_MASTER_KEY` is sent only as a Bearer header to the
  configured admin base, and appears in no response or log.
- **INV-M2**: Each grant gets a distinct gateway key with
  `user_id = agent.name`, `duration = max(60, remaining secs)`, and `models`
  equal to `_models(agent)` whenever that list is non-empty. The key is stored
  only Fernet-encrypted in `provisioner_state`.
- **INV-M3**: With `by_runtime` set, an agent whose runtime has no list (and no
  `"*"` list) is denied at validation and refused at provision. No key is
  generated for it.
- **INV-M4**: Revoking or expiring a models grant deletes its key at the
  gateway, or the gateway reports it as already gone.

MCP:

- **INV-P1**: Every MCP token has:
  - `aud = audience(server of grant.resource)`
  - `server = grant.resource`
  - `tools = grant.scope.tools`
  - `grant = grant.id`
  - `sub = "agent:<name>"`
  - `exp <= min(now + token_ttl, grant.expires_at)`, apart from the 1-second
    floor.
- **INV-P2**: `/v1/tokens/verify` returns 200 only if every one of these holds:
  - the signature, `aud` and `iss` are valid;
  - `claims.server` equals the query `server`;
  - the grant exists, has platform mcp and `resource == server`, is ACTIVE and
    unexpired;
  - its agent exists and is not disabled.
- **INV-P3**: When a server lists `tools`, a grant's tools are `["*"]` or a
  subset of them, and there are at most 64.

Agents and sandbox:

- **INV-A1**: Only an agent whose `sandbox_id` is a daemon with role `sandbox`
  can mint. The minted name must end in `-<that daemon's name>-sandbox` and
  start with a configured runtime. Minting is refused while the host is locked
  down.
- **INV-A2**: A minted agent's `host`, `sandbox_id` and `placement` come from
  the daemon, never from the request. Its API key never appears in any
  credential response.
- **INV-S1**: A sandbox grant never targets the requester's own project, and
  `project.write` is always sensitive.

Catalog:

- **INV-C1**: The catalog never lists `repo_denylist` or `by_runtime`
  internals.
- **INV-C2**: A disposition shown as auto-approve or llm review is never shown
  for an authority that needs an explicit rule (github create) unless the
  matching rule is explicit.

---

## 14. Tests worth porting (one line each)

GitHub (`test_provisioners.py`, `test_github_create.py`):
- Each ceiling denial is raised: allowlist, denylist, a level above the ceiling, a permission not in the ceiling, permissions missing. ` JRT/Cactus/ ` normalizes to `jrt/cactus` and `WRITE` to `write`.
- End to end: an auto-approved repo grant mints a token; the second credential fetch is served from the cache with no new call; after expiry the fetch raises `not active`.
- Unpinned installation lookup is cached after the first call; a 404 gives "not installed". Pinned mode resolves the account once and refuses `other-org/…` with "not covered by the pinned".
- Create validator: normalization; the PUBLIC note; create_owners; denylist; `..`, `x.git`, `has space`, and 101 characters; visibility `internal`; unknown scope keys.
- Private create end to end: the admin mint body is exactly `{permissions:{administration:write,metadata:read}}`, the create body is exactly `{name,visibility,private}`, the auth header is `token ghs_admin`, a revoke is sent, and the credential is `github_repo` with the URL and no token text.
- A retried create by the same agent with the same repo id is adopted (`created=false`, note "already existed"), and the revoke count is 2.
- A failed create (403) still revokes the admin token.
- An installation not covering the new repo produces the "does not cover it" note; a coverage lookup that raises does not fail the grant.
- Adoption is refused: not created by the broker (no GET lookup at all), a different id, a different visibility, a different agent.
- Control and non-ASCII resources are refused for both capabilities (`\n/`, `\t`, `\x7f`, Cyrillic `е`). `jrt/nixos-dots /` still hits the denylist. `a b`, `..`, `%0a` and `?` are refused as invalid.
- Special names are refused (`.github`, `.github-private`, `.hidden`, `jrt.github.io`, `...`, `-`, `_`, `-._`); `a.b`, `x-1`, `_x` and `github.io-notes` are allowed.
- A 401 on the admin-token revoke is logged with "returned 401" and the grant is still granted.
- Cancelling provision mid-create still sends the admin-token DELETE.
- The catalog shows `create_owners`, and `create_disposition == "human review"` under an llm catch-all.

LLDAP (`test_provisioners.py`):
- Grant, then expiry: an add mutation for `(svc-homelab-agent, 4)`, then a remove.
- Pre-existing membership: provisioning succeeds with no mutation recorded (verification path).
- Overlapping grants: the first expiry keeps the membership, the last removes it.
- Both grants expire in one tick: exactly one remove, and both end EXPIRED.
- Membership removed out of band: expiry still succeeds.
- `lldap_admin` is refused as "not brokered" when the allowlist is set.
- Managed account: createUser then add; email `@agents.invalid`; a password of ≥32 characters stored encrypted; the credential is `lldap_account` with that password; a second grant creates no new user and changes no password.
- A hand-registered account gets no createUser and no password, and the credential is `lldap_group` with value null.
- A leftover user with the managed name is adopted: no createUser, and the password is set.
- A set-password failure gives PROVISION_FAILED, a reason containing "lldap_set_password failed", an untouched agent row, and no membership.
- Rotate changes the password and the next fetch returns the new one; a hand-registered account is refused with "no broker-managed".
- Validator: with managed accounts off, or no secret box, an agent with no username is refused; with both on it passes.

Kubernetes (`test_kubernetes.py`):
- `_sa_name` sanitization and the 63-character cap; the full grant id is always included.
- Validator: not brokered, not grantable, invalid namespace; ` APPS-cactus ` normalizes; the edit "broad" note.
- Full cycle: SA and RoleBinding created; a TokenRequest on credential fetch; on expiry the RoleBinding then the SA are deleted; a fetch afterwards raises `not active`.
- A 409 on our own object (matching annotation) proceeds; a 409 on a foreign object fails with "refusing to adopt" and no binding is created.
- An allowlist of `["*"]` admits any namespace, and the role ceiling still applies.
- Cluster-wide: `*` gives `scope {"cluster": true}` and the CLUSTER-WIDE note; a role outside the cluster allowlist is refused; it is disabled by default; it always surfaces to a human; it creates a ClusterRoleBinding with the SA in `cluster_grant_namespace`.
- Role-matched routing (view auto, edit to a human); a sensitive namespace always goes to a human; `cluster_grant_namespace` is always sensitive.
- Multi-endpoint failover promotes the answering endpoint; all endpoints down raises "unreachable".

Models (`test_models.py`):
- A key is generated under a per-agent user with metadata, `key_alias=<name>/<grant8>`, models, max_budget, duration ≈ grant remaining, stored encrypted, and returned with `url`. A second grant reuses the user. Revoke deletes the key.
- Wrong gateway, wrong capability and non-empty scope are denied with the stated strings. An agent catch-all rule does not approve a models grant.
- The catalog shows the gateway; usage is per agent, never calls `/user/list`, and ignores non-agent users.
- With `by_runtime`, the claude, codex and hermes runtimes get their own lists or a denial; `"*"` covers unnamed runtimes and runtime null.

---

## 15. Suspected bugs / questionable behavior in the Python

- **B1. LLDAP: an empty `allowed_groups` brokers every group, including
  `lldap_admin`.** See `lldap.py:98`. An approved request for `lldap_admin`, or
  for `lldap_password_manager`, makes the agent an LLDAP administrator, which
  is the broker's own privilege. Kubernetes treats an empty allowlist as
  "nothing" (`kubernetes.py:125`). The catalog then advertises no groups at
  all. Recommendation for Rust: always deny the `lldap_*` built-in groups, and
  consider treating an empty list as "nothing" (this needs Jacob's sign-off,
  since it changes config semantics).
- **B2. LLDAP managed-account adoption has no ownership check.** See
  `lldap.py:209-226`. `managed_username` is `(prefix + name).lower()`. Agent
  names are unique case-sensitively (`models.py:104`), and the name pattern
  allows upper case (`schemas.py:214`). The adoption path runs whenever an
  LLDAP user with that id exists, so:
  - Agents `Foo` and `foo` share `svc-foo`. The second one's first grant resets
    the first one's password and shares every group membership.
  - If a hand-registered agent X uses `lldap_username="svc-bar"` and a new
    agent `bar` is registered without one, `bar`'s first grant **resets X's
    hand-managed password** and inherits X's groups.

  The docstring's "no other agent can own it" does not hold. Fix by both:
  - refusing adoption when any agent row already has that `lldap_username`;
  - requiring the existing user's displayName to be `"<name> (agent-auth managed)"`.

  Alternatively, make agent names unique case-insensitively.
- **B3. The LLDAP account mutex does not span the commit.** See
  `lldap.py:205-229`. The flush happens inside the mutex, but the commit only
  happens after the group add in `_finish_provision`. A concurrent second
  provision for the same agent refreshes, sees no username (uncommitted), and
  adopts and resets the password again. In Postgres its UPDATE then waits on
  A's row lock, so the final state is consistent. In between, though, the
  agent can fetch the stale password from A's commit, and the second password
  set is pointless. It is also an in-process lock only. Rust: use
  `SELECT … FOR UPDATE` on the agent row (or an advisory lock keyed by agent
  id) in a transaction that commits the username and password before the
  group add.
- **B4. The LLDAP admin JWT is passed on argv.** See `lldap.py:255-263`
  (`--token <jwt>`). It is readable by any local user through
  `/proc/<pid>/cmdline` or `ps` for the child's lifetime. That JWT is
  `lldap_admin`. The password is correctly passed through the environment.
  Prefer an env or stdin mechanism if `lldap_set_password` supports one;
  otherwise document it.
- **B5. The LLDAP group-id cache is never invalidated for existing names.** See
  `lldap.py:334-342`. If group `svc-a` is renamed to `svc-b` and a new `svc-a`
  is created, the cache still maps `svc-a` to the old id, so new grants for
  `svc-a` add the agent to **`svc-b`**. Revoke uses the id recorded in state,
  so it stays consistent with the wrong add. Rust: re-resolve the id per
  provision, or at least re-check the displayName before mutating.
- **B6. The GitHub owner half may be `.` or `..`.** See `github.py:112`, which
  only checks the repo half. For example, `../x` passes the regex. With an
  empty allowlist it reaches `GET /repos/../x/installation`. HTTP clients
  normalize dot segments, so this becomes `/x/installation` and fails with a
  404, so the impact is nil today. Rust should reject `.`/`..` for both halves
  so that nothing depends on URL normalization.
- **B7. GitHub ceiling values are never validated, and ceilings are not
  re-checked at mint.**
  - A ceiling value outside `read|write|admin` makes `_PERM_LEVELS[ceiling]`
    raise `KeyError`. The result is an unhandled 500 from `POST /v1/requests`
    (`github.py:132`).
  - Validation happens only at request time and approval time. After a policy
    tightening and restart, active grants keep minting with the old
    permissions and repos (including ones newly denylisted) until they expire.
    The same holds for k8s roles and LLDAP groups. Consider re-checking the
    denylist and ceiling in `get_credential`.
- **B8. Orphan GitHub tokens.**
  - Concurrent `get_credential` calls each mint a token. `_cache_token`
    deletes the earlier rows without revoking them at GitHub
    (`github.py:250`), so those tokens survive revocation for up to 1h.
  - On the reaper path, a token minted inside a provision whose transaction
    never committed is likewise never revoked.

  This is acceptable given the documented ~55 minute window, but Rust could
  revoke the replaced token before deleting its row.
- **B9. The GitHub installation cache is never invalidated** (`_installation_cache`,
  `_pinned_account`). After an app reinstall, mints fail until the process
  restarts. This is operational, not security.
- **B10. Partial Kubernetes provisions leak.** In the namespaced and plain
  cluster branches, if the SA is created and then the binding create fails,
  the error propagates without cleanup. Because no `provisioner_state` is
  saved, `revoke` returns early (`kubernetes.py:252`) and the SA is orphaned
  forever. In the zone branch, `_namespaces()` (`kubernetes.py:182`) runs
  **outside** the cleanup `try`, so a failed namespace listing also orphans
  the SA. An orphaned SA has no binding, but any RBAC granted to the group
  `system:serviceaccounts` applies to it. Rust: clean up on every failure path,
  or make `revoke` derive the names from `(agent, grant.id)` when the state is
  empty, as LLDAP does.
- **B11. The Kubernetes token floor exceeds the grant.** When
  `remaining < 600`, the token lives 600s, up to 10 minutes past the grant.
  This only matters if the SA delete is delayed (the scheduler runs every 30s
  and retries on failure). Note it, but keep the behavior: the API rejects
  values under 600.
- **B12. Models user id = bare agent name, with adoption of any existing
  gateway user.** See `models.py:79-96`. If a LiteLLM user with the same id
  already exists, for example a human or `proxy_admin` user created in the
  gateway UI, the broker generates the agent's key under that user. LiteLLM
  derives some key privileges, and budgets, from the owning user's role, so an
  agent named after an admin user could get an admin-capable key. Spend is
  also conflated. Rust: verify that the existing user's
  `metadata.agent == name`, or its role is `internal_user_viewer`, before
  reusing it. Alternatively, prefix user ids (a migration concern for existing
  gateways; ask Jacob).
- **B13. Upstream bodies reach the agent.** The models errors include
  `text[:200]` of the LiteLLM response (`models.py:96,121,139`), and this ends
  up in `decision_reason`, which the agent sees. GitHub and LLDAP deliberately
  keep bodies in the logs only. Prefer the logs-only pattern.
- **B14. Models revoke matches the substring `"not found"` on a 400.** This is
  brittle across LiteLLM versions. A wrong match marks a live key as deleted,
  although the key still expires through `duration`.
- **B15. Minting re-enables a disabled agent.** `SandboxService.mint` renewal
  sets `agent.disabled = False` (`core/sandboxes.py:260`). If the operator
  disables a minted agent, a parent with an auto-approve mint rule (or a human
  who approves without noticing) silently re-enables it. Lease expiry uses the
  same flag, which is why it is cleared. Rust should distinguish "disabled by
  lease" from "disabled by operator".
- **B16. Agents provision trusts the current daemon name.** `agents.py:74`
  re-slices `project` using the parent's **current** daemon name without
  checking `agent_name(runtime, project, daemon.name) == grant.resource`. If
  the parent's sandbox changed between validation and provisioning, the agent
  minted can differ from the approved resource. Rust: assert equality and fail
  otherwise.
- **B17. Revoke can wedge a grant forever.**
  - Sandbox `revoke` raises `ProvisionerError` forever once the agent or daemon
    row is gone (`sandbox.py:54-59`), so the grant stays ACTIVE and is retried
    every 30s indefinitely.
  - LLDAP revoke does the same if the LLDAP user was deleted out of band (the
    verification query errors, so the original error is re-raised;
    `lldap.py:353-356`).
  - Models revoke does the same if `ENCRYPTION_KEY` changed (decrypt raises).

  Consider a terminal "external target gone" outcome.
- **B18. The credential route has unhandled error paths.**
  - `registry.get()` for a platform disabled since the grant raises
    `SpecValidationError`, which is not caught and gives a 500.
  - MCP `get_credential` with a deleted agent dereferences `None`
    (`mcp.py:84-87`), also a 500.

  Map both to 403 or 503.
- **B19. The credential REST route accepts web-UI OAuth tokens.** The remote-MCP
  tool list deliberately omits `get_credential` ("a secret would land in a
  third party's chat history"; `schema.py` REMOTE_MCP_TOOLS, `oauth.py:21-23`).
  However, `get_caller` accepts `aat_` tokens on every `/v1` route
  (`deps.py:67-72`), so whoever holds the UI's access token (the UI vendor's
  backend) can call `GET /v1/grants/{id}/credential` directly. Whether this is
  exploitable depends on whether `/v1` is publicly routed. Rust: refuse
  credential fetches for `runtime == "web"` agents, or for OAuth-authenticated
  callers. Confirm with Jacob.
- **B20. `/v1/tokens/verify` does not check containment or the delegation
  thread,** unlike the credential route. Containment revokes grants, so the gap
  is the time until revocation completes. A delegated MCP grant whose thread
  closed stays verifiable until the scheduler revokes it (≤30s).
- **B21. Several `get_credential` implementations skip the status check.**
  Agents, sandbox, a2a and hostexec-job `get_credential` do not check the
  grant status. None returns a secret, but hostexec returns a job output tail
  after the grant ended. Rust may add the check uniformly. Decide with the
  hostexec spec owner.
- **B22. A2A validate accepts arbitrary scope keys** and folds them verbatim
  into the authority (`authority.py:42-43`). They are harmless to enforcement,
  which only reads `topic`, but they pollute rule pinning. Consider
  restricting the scope to `{topic}`.
