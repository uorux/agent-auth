# Hermes ↔ agent-auth a2a integration

How a Discord-based Hermes instance serves a2a threads. Hermes maps onto the
broker's concepts one-to-one:

| Hermes concept                    | Broker concept                              |
|-----------------------------------|---------------------------------------------|
| Hermes instance (`hermes-homelab-recusant`) | `service` agent identity + API key |
| a conversation (a Discord thread) | an `AgentSession` (worker)                  |
| the always-on daemon              | the sessionless **dispatcher**              |
| one exchange with a peer agent    | one a2a thread, bound to the worker session |

Hermes conversations are trigger-driven (a Discord message, a cron schedule,
a webhook), and each trigger determines where the conversation's **final
message** is routed. a2a becomes one more trigger kind with its own sink —
see [Final-message routing](#final-message-routing-the-sink-rule).

## The dispatcher: two wake mechanisms

The dispatcher is one loop iteration, identical under both mechanisms:

```
iteration(cursor):
    ev = GET /v1/a2a/events?wait=...&after=cursor     # SESSIONLESS (no X-Agent-Session)
    for t in ev.pending_opens:  handle_open(t)        # accept/reject → spawn conversation
    for t in ev.activity:       handle_unbound(t)     # rare: activity on unclaimed threads
    return ev.cursor
```

Sessionless calls see pending opens and unbound-thread activity only; once a
worker claims a thread, its events route to the worker's session and stop
appearing here.

### Method 1 — events long-poll loop (recommended)

Run the iteration in a `while True` with `wait=60`. Properties:

- No inbound network surface, no webhook secret to manage.
- Wakes within ~2s of any open (the long-poll is event-driven, not interval).
- The loop itself refreshes the daemon's `last_seen_at`, so agent-level
  liveness is free.
- Survives broker restarts (just re-poll; cursor is a timestamp).

This is strictly simpler; use it unless the Hermes runtime can't host a
resident loop.

### Method 2 — webhook doorbell + cron catch-up

Matches Hermes's existing webhook+cron trigger pattern:

1. Broker side: `agent-auth admin set-webhook <agent-id> --url http://hermes-host:9000/a2a-hook`
   — record the `webhook_secret` it prints ONCE into the Hermes host's secrets.
2. Hermes side: the endpoint verifies
   `X-Agent-Auth-Signature == "sha256=" + HMAC_SHA256(secret, raw_body)`
   (constant-time compare), then schedules **one dispatcher iteration** and
   returns 200 immediately. Pings are payload-free
   (`{type, thread_id, from, topic, seq?}`) — treat them purely as a doorbell;
   never act on their contents.
3. **Cron catch-up is mandatory, not optional**: webhook delivery is
   best-effort with no retries (5s timeout, failures swallowed — polling is
   authoritative by design). A `*/5` cron running the same iteration bounds
   the miss window. The two share the cursor.

Latency is the same as method 1 when the webhook lands, 0–5 min when it
doesn't. Choose this only if a resident loop is awkward in your Hermes
deployment.

## Conversation lifecycle (concrete)

`handle_open(thread)` — runs in the dispatcher:

1. **Triage.** Accept asks this Hermes serves (key on peer name + the opening
   payload — topics are entirely optional, see below); otherwise
   `POST /v1/a2a/threads/{id}/reject {"reason": "..."}` — the reason reaches
   the initiator as `close_note`. Unhandled opens auto-close after
   `A2A_OPEN_TIMEOUT_SECS` (default 10 min), so failing closed is safe.
2. **Mint the worker session** — the dispatcher does this, with the agent's
   own API key: `POST /v1/sessions {"label": "a2a-<peer>-<thread-id[:8]>"}`
   → `session_id`. The label is cosmetic (routing is by session/thread *id*;
   the broker appends a random suffix and retries on the unlikely per-agent
   name clash) — peer + thread-id prefix keeps it greppable. Note the MCP
   server auto-creates sessions for *ephemeral* agents only; a service
   agent's worker session always comes from an explicit call like this.
3. **Spawn the Hermes conversation**: via the Hermes Discord bot, create a
   Discord thread in the agent's channel (name it `a2a: <peer> <tid[:8]>`),
   seeded with:
   - the opening payload (fetch via `GET /v1/a2a/threads/{id}/messages` —
     the ping/event carries no payload),
   - a metadata block: a2a thread id, peer name, topic,
   - the conversation's MCP env: `AGENT_AUTH_SESSION=<session_id>` (per-
     conversation MCP server instance, same `AGENT_AUTH_API_KEY`).

   The Discord thread is a **workspace and observation surface, not a
   transport** — the a2a peer never sees it, and only what Hermes explicitly
   `a2a_send`s reaches the peer. Access is ordinary Discord permissions:
   in a single-human private server, humans typing in the thread is a
   feature (live supervision — you can steer or halt a machine-to-machine
   exchange mid-flight). In a server with other humans it is an injection
   surface into a conversation that may hold delegated credentials: put
   these threads in an owner-only channel or bot-lock them. Approval
   buttons stay `DISCORD_OWNER_ID`-gated either way — a channel member can
   steer the chat but never approve its access requests.
4. **Claim**: the worker calls `a2a_accept(thread_id)` from its session. The
   thread is now bound: wakes route only to this session, the dispatcher and
   other conversations get 403 on it, and the initiator's `peer_alive` tracks
   this session.

**Topics are optional — start without them.** Grants requested without
`scope.topic` are unscoped, opens without a topic match them, policy rules and
delegation work topicless. Nothing engages until you issue a topic-scoped
grant (from then on, opens under it must carry a matching topic). Tighten
incrementally later via Edit→rule pinning if you want per-subject scoping.

**Broker-side thread privacy**: only the two participant agents can read an
a2a thread (session-bound on both sides once claimed); there is no admin API
that reads transcripts — message payloads are, however, stored unencrypted in
the broker's SQLite, so treat DB access as transcript access.

During the conversation, the worker drives everything through its MCP tools:

- **Inbound**: `a2a_poll(thread_id, after_seq=<cursor>, wait=300)` — this is
  also the session keep-alive. If the conversation instead waits on Discord
  input for long stretches, something must touch the broker at least every
  `SESSION_IDLE_TIMEOUT_SECS` (default 15 min) or the thread ends `peer_gone`.
  A parked poll does this automatically; a conversation architecture with no
  resident poll should run a trivial keep-alive tick.
- **Outbound**: `a2a_send(thread_id, payload)`.
- **Credentials**: `request_access(..., on_behalf_of_thread=<thread_id>)` —
  cite ONLY this conversation's thread. Policy authorizes the
  (hermes, delegator) pair; the grant is revoked when the thread closes, so
  closing the thread is also releasing the access.
- **Downstream help**: open threads to other agents *from this session*
  (hermes→hermes). If this conversation dies, those downstream threads close
  `peer_gone` automatically — teardown cascades down the chain.

## Final-message routing (the sink rule)

Every Hermes conversation already routes its final message based on its
trigger. Extend that table with one rule:

| trigger          | final-message sink                                   |
|------------------|------------------------------------------------------|
| Discord message  | the same Discord thread (status quo)                 |
| cron             | the configured Discord channel (status quo)          |
| webhook          | wherever the hook config says (status quo)           |
| **a2a thread**   | **the a2a thread itself**: `a2a_send` + `a2a_close`  |

The initiator is a machine parked on `a2a_poll` — Discord is not a delivery
mechanism for it. The authoritative finish sequence is:

```
a2a_send(thread_id, {"type": "result", "status": "done" | "failed" | "declined",
                     "summary": "<one paragraph>", "detail": {...}})
a2a_close(thread_id, reason="<matches status>")
POST /v1/sessions/close        # ends the worker session; archives cleanly
```

Keep the payload convention stable (`type: "result"` with `status`/`summary`)
so initiator-side agents can parse outcomes uniformly. Mirror the summary into
the conversation's Discord thread too — but as *observability for the human*,
never as the delivery path. Order matters: send the result **before** closing
(sends on a closed thread 409).

**Crash semantics**: if the conversation dies without a result, its session
idles out and the thread closes `peer_gone`. Initiators should treat any close
without a `type: "result"` message (`peer_gone`, `idle_timeout`,
`open_timeout`) as "no result is coming" and decide whether to reopen. This is
deliberate — there is no session handoff; a replacement worker can't adopt a
dead worker's thread.

## Adoption path

You don't need the full dispatcher/worker architecture on day one:

- **v0 — no code, no new nix units**: use Hermes's existing **cron trigger**.
  A cron-fired conversation every few minutes, with the agent-auth MCP server
  attached and a skill/prompt that says: call `a2a_events()`; for each pending
  open — `create_session`, `a2a_accept`, do the work, `a2a_send` the result,
  `a2a_close`, close the session. Pure Hermes configuration. Costs: latency =
  cron period, and opens are handled serially inside one conversation. Fine
  at low traffic.
- **v1 — one nix systemd unit**: the resident sessionless events loop
  (even just `agent-auth a2a events --wait 60` in a loop) that invokes
  Hermes's conversation-start entrypoint per pending open — the
  dispatcher/worker shape described above, with ~2s wake latency and
  parallel conversations. The only Hermes-side code needed is a generic
  "start a conversation with this seed" hook, if the cron/webhook triggers
  don't already expose one.
- The **webhook** method is v1 plus an HTTP endpoint and secret — add it only
  if the resident loop is somehow awkward.

Note the dispatcher itself can never be "just a conversation": it is the
thing that *creates* conversations, so it must outlive them — the v0 cron
conversation works because cron is the durable part.

## Checklist

```bash
# broker
agent-auth admin agent-create hermes-homelab-recusant --description "homelab executor" \
    --lldap-username svc-hermes            # key printed ONCE
agent-auth admin set-webhook <id> --url ...   # method 2 only; secret printed ONCE

# policy.yaml
#  - a2a approve/surface rules for who may open threads to this hermes
#  - delegated pair rules: {agent: "hermes-homelab-*", platform: ..., delegator: "claude-*"}

# hermes host
#  AGENT_AUTH_URL / AGENT_AUTH_API_KEY in the daemon env (sops/agenix)
#  method 2: AGENT_AUTH_WEBHOOK_SECRET + endpoint + */5 cron catch-up
#  per-conversation: AGENT_AUTH_SESSION=<session_id> on that conversation's MCP server
```
