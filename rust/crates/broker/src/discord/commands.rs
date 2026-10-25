//! The slash commands (spec A.7) and their registration: in the approvals
//! channel's guild (instant), else globally. A bulk overwrite, so this
//! list is every command the bot has.

use serde_json::{Value, json};

use super::Bot;

const STRING: u8 = 3;
const BOOLEAN: u8 = 5;

/// The command definitions, as Discord takes them.
#[must_use]
pub fn definitions() -> Value {
    json!([
        {"type": 1, "name": "rules", "description": "View and manage auto-approve/deny rules"},
        {
            "type": 1,
            "name": "contain",
            "description": "Hold agents wherever they run: grants revoked, requests refused",
            "options": [
                {"type": STRING, "name": "reason", "description": "why (shown with the containment)", "required": true},
                {"type": STRING, "name": "name", "description": "agent name glob, e.g. codex-food-*"},
                {"type": STRING, "name": "project", "description": "every agent of this project"},
                {"type": STRING, "name": "host", "description": "every agent on this host"},
                {"type": STRING, "name": "runtime", "description": "every agent of this runtime"},
                {"type": BOOLEAN, "name": "everyone", "description": "every agent at once"},
            ],
        },
        {"type": 1, "name": "contained", "description": "What containments stand"},
        {
            "type": 1,
            "name": "release",
            "description": "Lift a containment (its agents ask for their grants again)",
            "options": [
                {
                    "type": STRING,
                    "name": "entry",
                    "description": "which one",
                    "autocomplete": true,
                },
                {"type": BOOLEAN, "name": "all", "description": "lift every containment"},
            ],
        },
        {"type": 1, "name": "hosts", "description": "Paired host and sandbox daemons"},
        {
            "type": 1,
            "name": "arm",
            "description": "Let approvals made here count on a host, for a while",
            "options": [
                {"type": STRING, "name": "host", "description": "the host", "required": true, "autocomplete": true},
                {"type": STRING, "name": "tier", "description": "user or root", "required": true, "choices": tiers()},
                {"type": STRING, "name": "code", "description": "a code from that host's <tier>-arm TOTP secret", "required": true},
                {"type": STRING, "name": "duration", "description": "e.g. 30m, 2h (the host caps it)"},
            ],
        },
        {
            "type": 1,
            "name": "disarm",
            "description": "Stop approvals made here from counting on a host",
            "options": [
                {"type": STRING, "name": "host", "description": "the host", "required": true, "autocomplete": true},
                {"type": STRING, "name": "tier", "description": "user or root (default: both)", "choices": tiers()},
            ],
        },
        {
            "type": 1,
            "name": "lockdown",
            "description": "Kill switch: revoke agents' grants, stop hosts, freeze VMs",
            "options": [
                {
                    "type": STRING,
                    "name": "scope",
                    "description": "sandboxes: agent-VM agents (default) · all: every agent · host: one host",
                    "choices": [
                        {"name": "sandboxes", "value": "sandboxes"},
                        {"name": "all", "value": "all"},
                        {"name": "host", "value": "host"},
                    ],
                },
                {"type": STRING, "name": "host", "description": "with scope host", "autocomplete": true},
                {"type": BOOLEAN, "name": "kill_vm", "description": "stop the agent VMs instead of freezing them"},
            ],
        },
        {
            "type": 1,
            "name": "unlock",
            "description": "Lift a lockdown (a host needs its own root arm code)",
            "options": [
                {"type": STRING, "name": "host", "description": "the host", "autocomplete": true},
                {"type": STRING, "name": "code", "description": "the host's root-unlock code"},
            ],
        },
        {
            "type": 1,
            "name": "dnd",
            "description": "No approval prompts on your desktops for a while",
            "options": [
                {"type": STRING, "name": "duration", "description": "e.g. 2h; leave empty to turn it off"},
            ],
        },
    ])
}

fn tiers() -> Value {
    json!([{"name": "user", "value": "user"}, {"name": "root", "value": "root"}])
}

/// Register the commands; true when done (else the next READY retries).
pub(crate) async fn sync(bot: &Bot, application: u64) -> bool {
    let guild = match bot.rest.channel_guild(bot.cfg.channel_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("failed to sync slash commands: {e}");
            return false;
        }
    };
    match bot
        .rest
        .put_commands(application, guild, &definitions())
        .await
    {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("failed to sync slash commands: {e}");
            false
        }
    }
}
