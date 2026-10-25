//! The slash commands (spec A.7) and their registration: in the approvals
//! channel's guild (instant), else globally. A bulk overwrite, so this
//! list is every command the bot has; the hostexec ones (/arm, /disarm,
//! /lockdown, /unlock, /dnd, /hosts) join it when that part is ported.

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
                    "description": "which one; leave empty to lift every containment",
                    "autocomplete": true,
                },
            ],
        },
    ])
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
