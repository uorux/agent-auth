//! hostctl's local socket (`{runtime_dir}/ctl.sock`, §12.2): root may do
//! everything; the configured user may see the status, arm and disarm the
//! user tier, lock down (never unlock), set do-not-disturb and report
//! desktop presence (INV-35). The caller's uid comes from the kernel.

use std::sync::Arc;

use agent_auth_core::Tier;
use agent_auth_core::hostd::LocalCaller;
use agent_auth_core::hostd::totp::SecretName;
use agent_auth_daemon::localsock::{LocalApi, LocalError, Peer};
use serde_json::{Map, Value, json};

use crate::config::duration_secs;
use crate::daemon::Hostd;
use crate::executor::Executor;
use crate::presence::PresenceEvent;

/// The hostctl API over a hostd.
#[derive(Debug)]
pub struct Ctl<E: Executor>(pub Arc<Hostd<E>>);

fn err(e: impl std::fmt::Display) -> LocalError {
    LocalError(e.to_string())
}

impl<E: Executor> Ctl<E> {
    async fn caller(&self, uid: u32) -> Result<LocalCaller, LocalError> {
        if uid == 0 {
            Ok(LocalCaller::Root)
        } else if self.0.is_user(uid).await {
            Ok(LocalCaller::User)
        } else {
            Err(LocalError::new("not for this user"))
        }
    }
}

fn root_only(caller: LocalCaller, method: &str) -> Result<(), LocalError> {
    if caller == LocalCaller::Root {
        Ok(())
    } else {
        Err(LocalError(format!("{method} needs root")))
    }
}

impl<E: Executor> LocalApi for Ctl<E> {
    async fn call(
        &self,
        method: &str,
        params: Map<String, Value>,
        _token: Option<Value>,
        peer: Peer,
    ) -> Result<Value, LocalError> {
        let caller = self.caller(peer.uid).await?;
        let hostd = &self.0;
        let uid = peer.uid;
        match method {
            "status" => Ok(Value::Object(hostd.status())),
            "arm" => {
                let tier_name = params.get("tier").and_then(Value::as_str).unwrap_or("user");
                if tier_name != "user" {
                    root_only(caller, method)?;
                }
                let tier = Tier::parse(tier_name)
                    .ok_or_else(|| LocalError::new("tier must be user or root"))?;
                let duration = params
                    .get("duration")
                    .filter(|d| !d.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!("1h"));
                let secs = duration_secs(&duration).map_err(err)?;
                let until = hostd.arm_local(tier, secs, caller, uid).map_err(err)?;
                Ok(json!({"armed_until": until.as_secs_f64()}))
            }
            "disarm" => {
                let tier = params
                    .get("tier")
                    .and_then(Value::as_str)
                    .and_then(Tier::parse);
                hostd.disarm(tier, &format!("local uid {uid}"));
                Ok(json!({"disarmed": true}))
            }
            "lockdown" => {
                let kill_vm = params
                    .get("kill_vm")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                hostd
                    .lockdown(&format!("local uid {uid}"), kill_vm)
                    .await
                    .map(Value::Object)
                    .map_err(err)
            }
            "unlock" => {
                root_only(caller, method)?;
                hostd
                    .unlock(&format!("local uid {uid}"))
                    .await
                    .map(Value::Object)
                    .map_err(err)
            }
            "totp-unlock" => {
                // Clearing a TOTP lock is root's alone: it is what stops a
                // relayed guessing attack.
                root_only(caller, method)?;
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(SecretName::parse)
                    .ok_or_else(|| {
                        LocalError::new("name: user-arm | user-direct | root-arm | root-direct")
                    })?;
                hostd
                    .totp()
                    .clear_lock(name, hostd.totp_now())
                    .map_err(err)?;
                crate::daemon::audit(
                    hostd.config.name.as_str(),
                    "totp.unlock",
                    json!({"secret": name.as_str(), "via": format!("local uid {uid}")}),
                );
                Ok(json!({"unlocked": name.as_str()}))
            }
            "dnd" => {
                let secs = match params
                    .get("duration")
                    .filter(|d| !d.is_null() && d.as_str() != Some("") && d.as_u64() != Some(0))
                {
                    Some(d) => duration_secs(d).map_err(err)?,
                    None => 0,
                };
                let until = hostd.set_dnd(secs);
                hostd.presence_changed().await;
                Ok(json!({"dnd_until": until}))
            }
            "presence" => {
                let state = params.get("state").and_then(Value::as_str).unwrap_or("");
                let event = PresenceEvent::parse(state).ok_or_else(|| {
                    LocalError::new("presence state: idle | active | locked | unlocked")
                })?;
                let present = hostd.presence_event(event);
                hostd.presence_changed().await;
                Ok(json!({"present": present}))
            }
            other => Err(LocalError(format!(
                "unknown method {}",
                agent_auth_core::pyfmt::repr(other)
            ))),
        }
    }
}
