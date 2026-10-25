//! The command line (the Python's Typer app, cli.py): the same commands,
//! arguments, options and defaults.

use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "agent-auth",
    about = "agent-auth broker CLI",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the calling agent's identity.
    Me,
    /// List what you can request: platforms, roles, groups, repos, peers.
    Catalog,
    /// Submit an access request.
    Request {
        /// github | homelab | kubernetes | a2a | mail | pool | google | ...
        platform: String,
        /// e.g. repo, create (new github repo / new mail alias), group, view/edit (k8s role), talk, read/send/read+send (mail), lease (pool), calendar.read
        capability: String,
        /// e.g. jrt/myrepo, svc-gitea, media (k8s namespace), homelab-agent, airline@my.domain (mail), minecraft (pool)
        resource: String,
        /// Why you need this
        #[arg(long = "why", short = 'j')]
        justification: String,
        /// e.g. 30m, 8h, 2d
        #[arg(long, short = 'd', default_value = "1h")]
        duration: String,
        /// JSON scope object
        #[arg(long, short = 's', default_value = "{}")]
        scope: String,
        /// a2a thread id whose conversation asked for this work (delegated
        /// request; you must be the thread's responder)
        #[arg(long)]
        on_behalf_of_thread: Option<String>,
        /// Block until decided
        #[arg(long, short = 'w')]
        wait: bool,
    },
    /// Get a request's current status.
    Status { request_id: String },
    /// Long-poll until the request is decided.
    Wait {
        request_id: String,
        /// Seconds to wait
        #[arg(long, default_value_t = 60.0)]
        timeout: f64,
    },
    /// Retry an LLM-denied request with a revised justification.
    Retry {
        request_id: String,
        #[arg(long = "why", short = 'j')]
        justification: String,
    },
    /// Escalate an LLM-denied request to human review.
    Escalate { request_id: String },
    /// List your grants.
    Grants {
        /// active|expired|revoked|all
        #[arg(long, default_value = "active")]
        status: String,
    },
    /// Fetch the credential for an active grant.
    Cred { grant_id: String },
    /// End one of your grants now (done with it).
    Release { grant_id: String },
    /// Messages on a mail grant's address, screened.
    MailList {
        grant_id: String,
        /// at most 50
        #[arg(long, default_value_t = 20)]
        limit: i64,
        /// next_page from the previous list
        #[arg(long)]
        page: Option<String>,
        /// plain words
        #[arg(long)]
        search: Option<String>,
    },
    /// One message, in full.
    MailRead {
        grant_id: String,
        message_id: String,
    },
    /// Send as the grant's address (reviewed first).
    MailSend {
        grant_id: String,
        /// recipient (repeat for more, from a mailbox)
        #[arg(long = "to")]
        to: Vec<String>,
        #[arg(long)]
        subject: Option<String>,
        /// a message id to answer
        #[arg(long = "reply-to")]
        reply_to: Option<String>,
        /// the text; default: stdin
        #[arg(long = "body-file")]
        body_file: Option<PathBuf>,
    },
    /// Agent sessions (ephemeral agents need one for a2a; AGENT_AUTH_SESSION)
    #[command(subcommand, arg_required_else_help = true)]
    Session(SessionCommand),
    /// Agent-to-agent threads
    #[command(subcommand, arg_required_else_help = true)]
    A2a(A2aCommand),
    /// Admin operations (AGENT_AUTH_ADMIN_TOKEN)
    #[command(subcommand, arg_required_else_help = true)]
    Admin(AdminCommand),
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Mint a session; export AGENT_AUTH_SESSION=<session_id> to use it.
    Create {
        /// Defaults to cwd basename
        #[arg(long, short = 'l')]
        label: Option<String>,
    },
    /// Close the current session (AGENT_AUTH_SESSION); its threads end peer_gone.
    Close,
}

#[derive(Debug, Subcommand)]
pub enum A2aCommand {
    Check {
        peer: String,
        /// out: can I reach peer; in: can peer reach me
        #[arg(long, default_value = "out")]
        direction: String,
        #[arg(long)]
        topic: Option<String>,
    },
    /// Open a thread; it stays pending_open until the peer accepts or replies.
    Open {
        to: String,
        /// JSON payload (first message)
        #[arg(long, short = 'p')]
        payload: String,
        #[arg(long)]
        topic: Option<String>,
    },
    /// Send a message into an open thread.
    Send {
        thread_id: String,
        /// JSON payload
        #[arg(long, short = 'p')]
        payload: String,
    },
    /// Read a thread past your cursor; --wait blocks for the reply.
    Poll {
        thread_id: String,
        /// Return messages with seq greater than this
        #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
        after_seq: i64,
        /// Long-poll seconds (0 = return immediately)
        #[arg(long, default_value_t = 0.0)]
        wait: f64,
    },
    Threads {
        /// pending_open|open|closed
        #[arg(long)]
        state: Option<String>,
        /// initiator|responder
        #[arg(long)]
        role: Option<String>,
    },
    Show {
        thread_id: String,
    },
    Accept {
        thread_id: String,
    },
    Reject {
        thread_id: String,
        #[arg(long, short = 'r')]
        reason: Option<String>,
    },
    Close {
        thread_id: String,
        #[arg(long, short = 'r')]
        reason: Option<String>,
    },
    /// Pending opens awaiting you + threads with new activity (service loop).
    Events {
        /// Long-poll seconds
        #[arg(long, default_value_t = 0.0)]
        wait: f64,
        /// Cursor from the previous call
        #[arg(long)]
        after: Option<String>,
    },
    /// Resident sessionless dispatcher: reconcile pending thread-opens against
    /// a receiver by POSTing raw thread facts as JSON. Dumb data transport —
    /// it never mints sessions, accepts, or rejects; the receiving
    /// conversation does that. Redelivery stops only when the thread leaves
    /// pending_open (level-triggered).
    Serve(ServeArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct ServeArgs {
    /// POST target per pending open (runtime's conversation-start webhook)
    #[arg(long)]
    pub on_open_url: String,
    /// Env var holding the HMAC secret for X-Agent-Auth-Signature
    #[arg(long, default_value = "AGENT_AUTH_WEBHOOK_SECRET")]
    pub hmac_env: String,
    /// Skip signing (loopback/testing only)
    #[arg(long)]
    pub insecure_no_sign: bool,
    /// Header name carrying the signature (same sha256=<hex> format; e.g.
    /// X-Hub-Signature-256 for GitHub-style verifiers). Ignored with
    /// --insecure-no-sign
    #[arg(long, default_value = "X-Agent-Auth-Signature")]
    pub sig_header: String,
    /// Events long-poll seconds (server clamps 300)
    #[arg(long, default_value_t = 60.0)]
    pub wait: f64,
    /// Re-POST a still-pending thread no more often than this
    #[arg(long, default_value_t = 60.0)]
    pub redeliver_interval: f64,
    /// Shorter cooldown after a non-2xx POST
    #[arg(long, default_value_t = 5.0)]
    pub failure_backoff: f64,
    /// Min sleep between ticks while work is pending
    #[arg(long, default_value_t = 5.0)]
    pub poll_interval: f64,
    /// JSON state file (cursor + cooldowns)
    #[arg(long)]
    pub state: Option<PathBuf>,
    /// Also dispatch unbound `activity` threads (default: opens only)
    #[arg(long, overrides_with = "no_include_activity")]
    pub include_activity: bool,
    #[arg(long, overrides_with = "include_activity", hide = true)]
    pub no_include_activity: bool,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Generate an ENCRYPTION_KEY.
    GenKey,
    /// Register an agent; prints its API key (and webhook secret) ONCE.
    ///
    /// --runtime, --project and --host are what policy rules match on (the
    /// name is a label). An agent registered without them is matched only by
    /// rules about every agent, or about its name.
    AgentCreate {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// service = always-on, can RECEIVE a2a threads | ephemeral = CLI
        /// instances (Claude Code, Codex): initiate-only, never receivable
        #[arg(long, default_value = "service")]
        kind: String,
        #[arg(long)]
        webhook_url: Option<String>,
        /// Pre-existing LLDAP account to use as-is. Omit to let the broker
        /// create a managed account (svc-<name>) at the agent's first homelab
        /// grant.
        #[arg(long)]
        lldap_username: Option<String>,
        /// What runs it: claude, codex, hermes, …
        #[arg(long)]
        runtime: Option<String>,
        /// What it works on (a project of the policy)
        #[arg(long)]
        project: Option<String>,
        /// The machine it runs on
        #[arg(long)]
        host: Option<String>,
    },
    /// Correct what an agent is (the fields policy matches on). An option
    /// left out keeps its value; "" clears it. Agents minted in a VM are the
    /// broker's own record and cannot be changed here.
    AgentSet {
        /// Agent name or id
        agent: String,
        #[arg(long)]
        runtime: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        host: Option<String>,
    },
    /// Rename an agent. Its key, requests and grants are unaffected; saved
    /// rules written for exactly this agent and active a2a grants to it are
    /// carried over (the counts are reported). Rules that match it by a glob
    /// and the policy file are not touched. Agents minted in a VM cannot be
    /// renamed.
    AgentRename {
        /// Agent name or id
        agent: String,
        /// The new name
        name: String,
    },
    /// Rotate a broker-managed LLDAP account's password (delivered to the
    /// agent on its next homelab credential fetch, never printed).
    RotateLldapPassword {
        agent_id: String,
    },
    /// Mint/replace an agent's per-agent webhook HMAC key; prints it ONCE.
    RotateWebhookSecret {
        agent_id: String,
    },
    /// Set/replace an existing agent's webhook URL; prints the new secret ONCE.
    SetWebhook {
        agent_id: String,
        /// http(s) endpoint; omit to clear
        #[arg(long)]
        url: Option<String>,
    },
    /// Reclassify an existing agent WITHOUT rotating its API key.
    ///
    /// The fix for a CLI agent registered on the default kind: as 'service'
    /// it is advertised as an a2a peer and other agents open threads it never
    /// reads. Demoting to 'ephemeral' also clears its webhook, closes any
    /// thread it was responding to (initiators get peer_gone), and revokes
    /// every active a2a grant that targets it — nobody may hold a talk grant
    /// to an agent that cannot receive threads.
    SetKind {
        agent_id: String,
        /// service | ephemeral
        kind: String,
    },
    /// List agents with kind and last-seen — a 'service' agent that has never
    /// been seen, or that never polls, is usually a mis-registered CLI agent.
    Agents,
    /// Disable an agent and everything it minted; their grants end within a tick.
    AgentDisable {
        agent_id: String,
    },
    /// Enable a disabled agent again (not what it minted). An agent of an
    /// agent VM gets a new key, delivered to its sandbox.
    AgentEnable {
        agent_id: String,
    },
    RotateKey {
        agent_id: String,
    },
    Rules,
    RuleDelete {
        rule_id: String,
    },
    Requests {
        #[arg(long, default_value_t = 100, allow_negative_numbers = true)]
        limit: i64,
    },
    /// Decide a surfaced request via API (fallback when Discord is unavailable).
    #[command(group(ArgGroup::new("decision").required(true).args(["approve", "deny"])))]
    Decide {
        request_id: String,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        deny: bool,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long, short = 'd')]
        duration: Option<String>,
        /// hostexec: prompt for the host's direct TOTP code (required for shells)
        #[arg(long)]
        totp: bool,
    },
    Revoke {
        grant_id: String,
        #[arg(long, default_value = "revoked by admin")]
        reason: String,
    },
    /// Mail the gateway is holding for you: messages it wouldn't show an
    /// agent unasked, and messages agents want sent.
    MailHeld,
    /// Let a held message through (an outbound one is sent now).
    MailRelease {
        item_id: String,
        #[arg(long, default_value = "admin")]
        by: String,
    },
    /// Keep a held message from the agent (or never send it).
    MailDiscard {
        item_id: String,
        #[arg(long, default_value = "admin")]
        by: String,
    },
    /// The broker's model decisions: browse, label what they should have
    /// been, and replay them with another model, prompt or context.
    Evals {
        #[command(subcommand)]
        command: EvalsCommand,
    },
    /// Generate BROKER_SIGNING_KEY (ed25519 seed) and print its public key,
    /// which every daemon pins as brokerPublicKey. The seed is a secret:
    /// prefer --out and move the file into the broker's env secret.
    GenSigningKey {
        /// write BROKER_SIGNING_KEY=<seed> to this new file (0600, never overwritten)
        #[arg(long)]
        out: Option<PathBuf>,
        /// print the private seed even when stdout is not a terminal
        #[arg(long = "stdout")]
        to_stdout: bool,
    },
    /// Sign a Google account in for the broker, on your own machine: the
    /// consent screen in a browser, then a refresh token in --out (never
    /// printed). Put that file where the broker's refresh_token_file points
    /// (a sops secret). Consent only what the broker should hold for that
    /// account: the broker asks Google for just a grant's scope, and refuses
    /// the token if Google returns a wider one.
    GoogleConsent {
        /// the OAuth client JSON (a Desktop client)
        #[arg(long)]
        client_secret_file: PathBuf,
        /// comma-separated: gmail.readonly, gmail.send, calendar.readonly,
        /// calendar.events, drive.readonly
        #[arg(long, default_value = "gmail.readonly,gmail.send")]
        scopes: String,
        /// where the refresh token goes (new 0600 file)
        #[arg(long)]
        out: PathBuf,
        /// print the URL only
        #[arg(long)]
        no_browser: bool,
        /// loopback port (0: any free one)
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Issue a one-time pairing code; on the host, run `sudo agent-auth-hostd
    /// pair` and enter it at the prompt (never as an argument).
    DaemonPair {
        /// the host's name, e.g. excelsior
        name: String,
        /// host (hostd) | sandbox (sandboxd)
        #[arg(long, default_value = "host")]
        role: String,
    },
    /// Paired daemons with online state, last heartbeat and key fingerprint.
    Daemons,
    /// Forget a daemon's key and drop its connection; it must pair again.
    DaemonUnpair {
        daemon_id: String,
    },
    /// The broker's public signing key (what daemons pin).
    BrokerKey,
    /// Hosts with a hostd: tiers, arm state, lockdown, VM, desktop presence.
    Hosts,
    /// Arm a tier on a host: approvals made on Discord then count there.
    /// Prompts for a code from that host's <tier>-arm TOTP secret.
    Arm {
        host: String,
        /// user | root
        #[arg(long, default_value = "user")]
        tier: String,
        /// capped by the host's own policy
        #[arg(long, short = 'd', default_value = "1h")]
        duration: String,
    },
    Disarm {
        host: String,
        /// default: both
        #[arg(long)]
        tier: Option<String>,
    },
    /// The kill switch: revoke the grants of agent-VM agents (every agent
    /// with --scope all), refuse new identities and host commands, disarm
    /// hosts, kill their jobs and shells, and freeze their agent VMs from
    /// outside.
    Lockdown {
        /// sandboxes | all | host
        #[arg(long, default_value = "sandboxes")]
        scope: String,
        /// with --scope host
        #[arg(long)]
        host: Option<String>,
        /// stop agent VMs instead of freezing them
        #[arg(long)]
        kill_vm: bool,
    },
    /// Lift a lockdown on the broker. Each host stays locked until it gets
    /// its own root-unlock code (--host), or `sudo agent-auth-hostctl unlock`
    /// there.
    Unlock {
        /// also unlock this host's hostd (asks for its root-unlock code)
        #[arg(long)]
        host: Option<String>,
    },
    /// Hold agents wherever they run: revoke their grants (model keys too),
    /// refuse their requests and credentials, close their conversations,
    /// freeze their processes in agent VMs, kill their host commands.
    Contain {
        #[arg(long)]
        reason: String,
        /// agent name glob
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        runtime: Option<String>,
        /// every agent
        #[arg(long = "all")]
        everyone: bool,
    },
    ContainList,
    /// Lift a containment (the agents' grants do not come back: they ask again).
    ContainLift {
        /// its id; none: every containment
        entry: Option<String>,
    },
    /// Web UI connectors (remote MCP): who registered, which agent each acts as.
    Connectors,
    /// Revoke a connector: its tokens stop now; it must register and be authorized again.
    ConnectorRevoke {
        client_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EvalsCommand {
    /// The decision kinds: classes, context settings, current system prompts.
    Kinds,
    /// Recorded calls, newest first.
    Calls {
        #[arg(long)]
        kind: Option<String>,
        /// only labelled calls (the eval set)
        #[arg(long, conflicts_with = "unlabeled")]
        labeled: bool,
        /// only unlabelled calls (to label)
        #[arg(long)]
        unlabeled: bool,
        /// RFC 3339
        #[arg(long)]
        since: Option<String>,
        /// a page's `next`
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Everything recorded about one call: facts, prompts, answer, label.
    Show { call_id: String },
    /// Say what a call should have decided: a class of its kind (`*` for
    /// any part between `/`, e.g. in_scope/*).
    Label {
        call_id: String,
        expected: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove a call's label.
    Unlabel { call_id: String },
    /// Replay recorded calls of one kind under another model, system
    /// prompt or context settings, and compare.
    Replay {
        #[arg(long)]
        kind: String,
        /// ask this model (default: each call's own)
        #[arg(long)]
        model: Option<String>,
        /// a system prompt to use instead of the current one
        #[arg(long)]
        system_file: Option<PathBuf>,
        /// context settings as JSON, e.g. '{"history_items": 10}'
        #[arg(long)]
        context: Option<String>,
        /// only labelled calls (the eval set)
        #[arg(long, conflicts_with = "unlabeled")]
        labeled: bool,
        #[arg(long)]
        unlabeled: bool,
        /// RFC 3339
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// only these calls (repeat)
        #[arg(long = "call")]
        calls: Vec<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        note: Option<String>,
        /// wait for it to finish and show every case
        #[arg(long)]
        wait: bool,
    },
    /// Replays, newest first.
    Runs {
        #[arg(long)]
        kind: Option<String>,
    },
    /// One replay, with every case.
    Run { run_id: String },
}
