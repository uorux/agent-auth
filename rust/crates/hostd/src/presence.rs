//! Whether the user is at this host's desktop (§8.11). Unknown counts as
//! away: a prompt shown to nobody would decide nothing, and an Allow from
//! an empty desk must never be possible.

use std::path::Path;

use serde_json::{Value, json};

use crate::fsutil;

/// What is known about the user's desktop session.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Presence {
    /// hostd-user is attached.
    pub connected: bool,
    /// Reported by hostd-user (None: unknown).
    pub idle_secs: Option<f64>,
    pub locked: Option<bool>,
    pub fullscreen: bool,
    /// Unix seconds of hostd-user's last report.
    pub reported_at: f64,
    /// Set by `agent-auth-hostctl presence ...` (hypridle, lock-screen
    /// hooks); these win over what hostd-user polled.
    pub idle_since: Option<f64>,
    pub explicit_idle: Option<bool>,
    pub explicit_locked: Option<bool>,
    /// Unix seconds; 0 when off.
    pub dnd_until: f64,
}

/// A `presence` event from hostctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceEvent {
    Idle,
    Active,
    Locked,
    Unlocked,
}

impl PresenceEvent {
    #[must_use]
    pub fn parse(s: &str) -> Option<PresenceEvent> {
        match s {
            "idle" => Some(PresenceEvent::Idle),
            "active" => Some(PresenceEvent::Active),
            "locked" => Some(PresenceEvent::Locked),
            "unlocked" => Some(PresenceEvent::Unlocked),
            _ => None,
        }
    }
}

impl Presence {
    /// Why the user does not count as at this desktop now; `None` if they
    /// do. `enabled`: `desktop.enable`.
    #[must_use]
    pub fn away_reason(&self, enabled: bool, max_idle_secs: u64, now: f64) -> Option<String> {
        if !enabled {
            return Some("desktop prompts are off on this host".into());
        }
        if !self.connected {
            return Some(
                "the session helper isn't connected (systemctl --user status agent-auth-hostd-user)"
                    .into(),
            );
        }
        if self.dnd_until > now {
            return Some("do not disturb".into());
        }
        if self.fullscreen {
            return Some(
                "busy (a fullscreen window, or the host's busy check says not now)".into(),
            );
        }
        match self.explicit_locked.or(self.locked) {
            None => {
                return Some(
                    "lock state unknown (no `presence locked|unlocked` report yet)".into(),
                );
            }
            Some(true) => return Some("the session is locked".into()),
            Some(false) => {}
        }
        let idle = if let Some(explicit) = self.explicit_idle {
            match (explicit, self.idle_since) {
                (true, Some(since)) => now - since,
                _ => 0.0,
            }
        } else if let Some(idle) = self.idle_secs {
            idle + (now - self.reported_at)
        } else {
            return Some("idle state unknown (no `presence idle|active` report yet)".into());
        };
        // Compare as floats: max_idle is a small number of seconds.
        let max = f64::from(u32::try_from(max_idle_secs).unwrap_or(u32::MAX));
        if idle > max {
            return Some(format!("idle for {} s", idle.floor()));
        }
        None
    }

    pub fn apply(&mut self, event: PresenceEvent, now: f64) {
        match event {
            PresenceEvent::Idle => {
                self.explicit_idle = Some(true);
                self.idle_since = Some(now);
            }
            PresenceEvent::Active => {
                self.explicit_idle = Some(false);
                self.idle_since = None;
            }
            PresenceEvent::Locked => self.explicit_locked = Some(true),
            PresenceEvent::Unlocked => {
                self.explicit_locked = Some(false);
                self.explicit_idle = Some(false);
                self.idle_since = None;
            }
        }
    }

    /// The explicit reports survive hostd restarts (not reboots): they
    /// live in the runtime directory.
    pub fn save(&self, path: &Path) {
        let v = json!({
            "explicit_idle": self.explicit_idle,
            "explicit_locked": self.explicit_locked,
            "idle_since": self.idle_since,
        });
        if let Some(dir) = path.parent() {
            let _ = fsutil::private_dir(dir, 0o755);
        }
        if let Err(e) = fsutil::write_atomic(path, v.to_string().as_bytes(), 0o600) {
            tracing::warn!(error = %e, "could not save presence");
        }
    }

    pub fn load(&mut self, path: &Path) {
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(Value::Object(saved)) = serde_json::from_slice::<Value>(&bytes) else {
            return;
        };
        self.explicit_idle = saved.get("explicit_idle").and_then(Value::as_bool);
        self.explicit_locked = saved.get("explicit_locked").and_then(Value::as_bool);
        self.idle_since = saved
            .get("idle_since")
            .and_then(Value::as_f64)
            .filter(|f| f.is_finite());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here() -> Presence {
        Presence {
            connected: true,
            locked: Some(false),
            idle_secs: Some(10.0),
            reported_at: 1000.0,
            ..Presence::default()
        }
    }

    #[test]
    fn away_locked_or_do_not_disturb() {
        let now = 1005.0;
        assert_eq!(here().away_reason(true, 300, now), None);
        assert!(here().away_reason(false, 300, now).unwrap().contains("off"));
        let mut p = here();
        p.connected = false;
        assert!(p.away_reason(true, 300, now).unwrap().contains("helper"));
        let mut p = here();
        p.dnd_until = now + 60.0;
        assert_eq!(
            p.away_reason(true, 300, now).as_deref(),
            Some("do not disturb")
        );
        let mut p = here();
        p.fullscreen = true;
        assert!(p.away_reason(true, 300, now).unwrap().starts_with("busy"));
        let mut p = here();
        p.locked = None;
        assert!(
            p.away_reason(true, 300, now)
                .unwrap()
                .contains("lock state unknown")
        );
        // An explicit report wins over the helper's.
        p.apply(PresenceEvent::Locked, now);
        assert_eq!(
            p.away_reason(true, 300, now).as_deref(),
            Some("the session is locked")
        );
        p.apply(PresenceEvent::Unlocked, now);
        assert_eq!(p.away_reason(true, 300, now), None);
        p.apply(PresenceEvent::Idle, now);
        assert_eq!(p.away_reason(true, 300, now + 100.0), None);
        assert_eq!(
            p.away_reason(true, 300, now + 400.0).as_deref(),
            Some("idle for 400 s")
        );
        let mut p = here();
        p.idle_secs = None;
        assert!(
            p.away_reason(true, 300, now)
                .unwrap()
                .contains("idle state unknown")
        );
        assert!(
            here()
                .away_reason(true, 300, now + 300.0)
                .unwrap()
                .starts_with("idle for")
        );
    }

    #[test]
    fn explicit_reports_survive_a_restart() {
        let d = crate::fsutil::testdir::TestDir::new("presence");
        let path = d.path().join("presence.json");
        let mut p = Presence::default();
        p.apply(PresenceEvent::Idle, 42.0);
        p.apply(PresenceEvent::Locked, 43.0);
        p.save(&path);
        let mut q = Presence::default();
        q.load(&path);
        assert_eq!(q.explicit_idle, Some(true));
        assert_eq!(q.explicit_locked, Some(true));
        assert_eq!(q.idle_since, Some(42.0));
    }
}
