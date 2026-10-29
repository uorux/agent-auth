//! hostd-user (`agent-auth-hostd user`): the part of hostd that lives in
//! the desktop session (§12.3). It holds no secrets and decides nothing: it
//! tells hostd whether you are at this desktop, shows the prompts hostd
//! passes on, and sends back which button you pressed.
//!
//! Anything else running as you can connect to hostd's user socket and do
//! the same. So which requests are asked on a desktop at all is the
//! broker's policy, and an Allow here approves a command on this host only
//! where the host's own config says so (`desktop.approve.{user,root}`; for
//! root, polkit asks for your password too). It never opens a shell. (The
//! Python's docstring claimed a desk answer never satisfies the host's own
//! checks; with `desktop.approve` it does, by design — daemons bug 12.)

use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_daemon::localsock::read_line_capped;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{HostConfig, IdleSource, darwin};

pub const PRESENCE_SECS: u64 = 10;
/// zenity's exit code on timeout.
pub const ZENITY_TIMEOUT: i32 = 5;

/// zenity, with `--default-cancel`: a stray Enter denies.
#[must_use]
pub fn default_prompt_linux() -> Vec<String> {
    [
        "zenity",
        "--question",
        "--no-markup",
        "--default-cancel",
        "--width",
        "560",
        "--title",
        "{title}",
        "--text",
        "{text}",
        "--timeout",
        "{timeout}",
        "--ok-label",
        "Allow once",
        "--cancel-label",
        "Deny",
        "--extra-button",
        "Mute agent 1h",
        "--extra-button",
        "Send to Discord",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// AppleScript whose inputs are the run handler's arguments: an agent's
/// text is never part of the script.
fn osascript(lines: &[&str], args: &[&str]) -> Vec<String> {
    let mut out = vec!["/usr/bin/osascript".to_owned()];
    for line in lines {
        out.push("-e".into());
        out.push((*line).to_owned());
    }
    out.extend(args.iter().map(|a| (*a).to_owned()));
    out
}

/// macOS: three buttons at most (no Mute); Deny is the default and cancel.
#[must_use]
pub fn default_prompt_macos() -> Vec<String> {
    osascript(
        &[
            "on run argv",
            "set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons {\"Deny\", \"Send to Discord\", \"Allow once\"} default button \"Deny\" cancel button \"Deny\" giving up after ((item 3 of argv) as integer) with icon caution",
            "if gave up of r then return \"timeout\"",
            "if button returned of r is \"Allow once\" then return \"allow\"",
            "if button returned of r is \"Send to Discord\" then return \"discord\"",
            "return \"deny\"",
            "end run",
        ],
        &["{title}", "{text}", "{timeout}"],
    )
}

#[must_use]
pub fn macos_notify() -> Vec<String> {
    osascript(
        &[
            "on run argv",
            "display notification (item 2 of argv) with title (item 1 of argv)",
            "end run",
        ],
        &["{title}", "{text}"],
    )
}

/// Placeholders are whole arguments: nothing is parsed by a shell.
#[must_use]
pub fn fill(template: &[String], fields: &BTreeMap<&str, String>) -> Vec<String> {
    template
        .iter()
        .map(|arg| {
            arg.strip_prefix('{')
                .and_then(|a| a.strip_suffix('}'))
                .and_then(|k| fields.get(k))
                .cloned()
                .unwrap_or_else(|| arg.clone())
        })
        .collect()
}

/// What a dialog's stdout and exit code mean.
#[must_use]
pub fn parse_answer(returncode: i32, stdout: &str) -> &'static str {
    match stdout.trim().to_lowercase().as_str() {
        "mute agent 1h" | "mute" => "mute",
        "send to discord" | "discord" => "discord",
        "once" | "session" | "allow" => "allow",
        "deny" => "deny",
        "timeout" => "timeout",
        _ if returncode == 0 => "allow",
        _ if returncode == ZENITY_TIMEOUT => "timeout",
        _ => "deny",
    }
}

/// HTML escaping for notification daemons that render markup.
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// Seconds since the last input, from `ioreg -c IOHIDSystem`.
#[must_use]
pub fn parse_hid_idle(text: &str) -> Option<f64> {
    let at = text.find("\"HIDIdleTime\" = ")?;
    let rest = text.get(at.saturating_add(16)..)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let ns: u64 = digits.parse().ok()?;
    let secs = u32::try_from(ns / 1_000_000_000).ok()?;
    Some(f64::from(secs))
}

/// Is `uid`'s console session locked (or switched away from)? From the
/// XML plist of `ioreg -n Root -d 1 -a`; `None` when it can't be told.
#[must_use]
pub fn parse_console_locked(plist: &str, uid: u32) -> Option<bool> {
    let users = plist.find("<key>IOConsoleUsers</key>")?;
    let rest = plist.get(users..)?;
    let array_end = rest.find("</array>").unwrap_or(rest.len());
    let array = rest.get(..array_end)?;
    for dict in array.split("<dict>").skip(1) {
        let dict = dict.split("</dict>").next().unwrap_or("");
        let fields = plist_fields(dict);
        if fields.get("kCGSSessionUserIDKey").map(String::as_str) == Some(&uid.to_string()) {
            let locked = fields.get("CGSSessionScreenIsLocked").map(String::as_str) == Some("true");
            let on_console =
                fields.get("kCGSSessionOnConsoleKey").map(String::as_str) != Some("false");
            return Some(locked || !on_console);
        }
    }
    None
}

/// `<key>K</key><integer>V</integer>` / `<true/>` / `<false/>` / `<string>`.
fn plist_fields(dict: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = dict;
    while let Some(k) = rest.find("<key>") {
        let after = rest.get(k.saturating_add(5)..).unwrap_or("");
        let Some(end) = after.find("</key>") else {
            break;
        };
        let key = after.get(..end).unwrap_or("").to_owned();
        let value_part = after
            .get(end.saturating_add(6)..)
            .unwrap_or("")
            .trim_start();
        let value = if value_part.starts_with("<true/>") {
            "true".to_owned()
        } else if value_part.starts_with("<false/>") {
            "false".to_owned()
        } else if let Some(v) = value_part.strip_prefix("<integer>") {
            v.split('<').next().unwrap_or("").to_owned()
        } else if let Some(v) = value_part.strip_prefix("<string>") {
            v.split('<').next().unwrap_or("").to_owned()
        } else {
            String::new()
        };
        out.insert(key, value);
        rest = value_part;
    }
    out
}

async fn output(argv: &[&str], timeout: Duration) -> Option<String> {
    let (program, args) = argv.split_first()?;
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(timeout, child).await.ok()?.ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The helper's state: one dialog at a time.
#[derive(Debug)]
pub struct UserHelper {
    config: HostConfig,
    fresh: Mutex<bool>,
    dialog: AsyncMutex<()>,
    cancelled: Mutex<BTreeSet<String>>,
    current: Mutex<Option<(String, u32)>>,
}

impl UserHelper {
    #[must_use]
    pub fn new(config: HostConfig) -> UserHelper {
        UserHelper {
            config,
            fresh: Mutex::new(true),
            dialog: AsyncMutex::new(()),
            cancelled: Mutex::new(BTreeSet::new()),
            current: Mutex::new(None),
        }
    }

    async fn idle_and_lock(&self) -> (Option<f64>, Option<bool>) {
        match self.config.desktop.idle_source {
            IdleSource::Hooks => (None, None),
            IdleSource::Logind => logind().await,
            IdleSource::Macos => {
                let idle = output(
                    &["/usr/sbin/ioreg", "-c", "IOHIDSystem", "-d", "4"],
                    Duration::from_secs(5),
                )
                .await
                .and_then(|t| parse_hid_idle(&t));
                let uid = crate::effective_uid();
                let locked = output(
                    &["/usr/sbin/ioreg", "-n", "Root", "-d", "1", "-a"],
                    Duration::from_secs(5),
                )
                .await
                .and_then(|t| parse_console_locked(&t, uid));
                (idle, locked)
            }
        }
    }

    async fn busy(&self) -> bool {
        let busy = &self.config.desktop.busy_command;
        if let Some((program, args)) = busy.split_first() {
            let status = tokio::process::Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status();
            // A check that can't run or doesn't answer counts as busy.
            return match tokio::time::timeout(Duration::from_secs(5), status).await {
                Ok(Ok(s)) => s.success(),
                _ => true,
            };
        }
        if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
            return false;
        }
        let out = output(&["hyprctl", "activewindow", "-j"], Duration::from_secs(5)).await;
        let v: Value = out
            .and_then(|o| serde_json::from_str(&o).ok())
            .unwrap_or(Value::Null);
        match v.get("fullscreen") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Number(n)) => n.as_i64().is_some_and(|n| n >= 2),
            _ => false,
        }
    }

    /// One presence report.
    pub async fn presence(&self) -> Value {
        let (idle, locked) = self.idle_and_lock().await;
        let fullscreen = self.busy().await;
        let fresh = {
            let mut f = self.fresh.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *f, false)
        };
        json!({"type": "presence", "idle_secs": idle, "locked": locked,
               "fullscreen": fullscreen, "fresh": fresh})
    }

    fn take_cancelled(&self, id: &str) -> bool {
        self.cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)
    }

    /// Show one prompt (later ones wait their turn) and return the answer.
    pub async fn show(&self, prompt: &Map<String, Value>) -> &'static str {
        let id = prompt
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let _turn = self.dialog.lock().await;
        if self.take_cancelled(&id) {
            return "timeout";
        }
        let text = |k: &str| {
            prompt
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let (who, what, detail) = (text("who"), text("what"), text("detail"));
        let timeout = prompt.get("timeout").and_then(Value::as_u64).unwrap_or(90);
        let mut fields: BTreeMap<&str, String> = BTreeMap::new();
        fields.insert(
            "title",
            format!("agent-auth: {who}").chars().take(120).collect(),
        );
        let mut body = format!("{who} asks to:\n    {what}");
        if !detail.is_empty() {
            body.push_str(&format!("\n\n{detail}"));
        }
        fields.insert("text", body);
        fields.insert("who", who);
        fields.insert("what", what);
        fields.insert("detail", detail);
        fields.insert("timeout", timeout.to_string());
        let template = if self.config.desktop.prompt_command.is_empty() {
            if darwin() {
                default_prompt_macos()
            } else {
                default_prompt_linux()
            }
        } else {
            self.config.desktop.prompt_command.clone()
        };
        let argv = fill(&template, &fields);
        self.attention();
        let Some((program, args)) = argv.split_first() else {
            return "timeout";
        };
        let child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("could not show the prompt ({program}): {e}");
                return "timeout";
            }
        };
        if let Some(pid) = child.id() {
            *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some((id.clone(), pid));
        }
        let waited = tokio::time::timeout(
            Duration::from_secs(timeout.saturating_add(10)),
            child.wait_with_output(),
        )
        .await;
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = None;
        let Ok(Ok(out)) = waited else {
            return "timeout";
        };
        if self.take_cancelled(&id) {
            return "timeout";
        }
        parse_answer(
            crate::executor::exit_code(out.status),
            &String::from_utf8_lossy(&out.stdout),
        )
    }

    fn attention(&self) {
        spawn_quiet(self.config.desktop.attention_command.clone());
    }

    /// A notification, and the attention sound. The text may be an agent's:
    /// markup is escaped (Linux notification daemons render it).
    pub fn notify(&self, msg: &Map<String, Value>) {
        self.attention();
        let (template, escape): (Vec<String>, fn(&str) -> String) =
            if self.config.desktop.notify_command.is_empty() && darwin() {
                (macos_notify(), str::to_owned)
            } else {
                (self.config.desktop.notify_command.clone(), html_escape)
            };
        if template.is_empty() {
            return;
        }
        let urgency = match msg.get("urgency").and_then(Value::as_str) {
            Some(u @ ("low" | "normal" | "critical")) => u.to_owned(),
            _ => "normal".to_owned(),
        };
        let title = msg
            .get("title")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .unwrap_or("agent-auth");
        let text = msg.get("text").and_then(Value::as_str).unwrap_or("");
        let mut fields: BTreeMap<&str, String> = BTreeMap::new();
        fields.insert("title", escape(title));
        fields.insert("text", escape(text));
        fields.insert("urgency", urgency);
        spawn_quiet(fill(&template, &fields));
    }

    pub fn cancel(&self, id: &str) {
        self.cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_owned());
        let current = self
            .current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some((cur, pid)) = current
            && cur == id
        {
            let kill = if darwin() { "/bin/kill" } else { "kill" };
            spawn_quiet(vec![
                kill.to_owned(),
                "-s".into(),
                "TERM".into(),
                pid.to_string(),
            ]);
        }
    }
}

fn spawn_quiet(argv: Vec<String>) {
    let Some((program, args)) = argv.split_first() else {
        return;
    };
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let program = program.clone();
    tokio::spawn(async move {
        match cmd.spawn() {
            Ok(mut c) => {
                let _ = tokio::time::timeout(Duration::from_secs(30), c.wait()).await;
            }
            Err(e) => tracing::warn!("{program}: {e}"),
        }
    });
}

async fn logind() -> (Option<f64>, Option<bool>) {
    let uid = crate::effective_uid().to_string();
    let session = output(
        &["loginctl", "show-user", &uid, "-p", "Display", "--value"],
        Duration::from_secs(5),
    )
    .await
    .unwrap_or_default();
    let session = session.trim();
    if session.is_empty() {
        return (None, None);
    }
    let Some(out) = output(
        &[
            "loginctl",
            "show-session",
            session,
            "-p",
            "IdleHint",
            "-p",
            "IdleSinceHint",
            "-p",
            "LockedHint",
        ],
        Duration::from_secs(5),
    )
    .await
    else {
        return (None, None);
    };
    let props: BTreeMap<&str, &str> = out.lines().filter_map(|l| l.split_once('=')).collect();
    let locked = match props.get("LockedHint") {
        Some(&"yes") => Some(true),
        Some(&"no") => Some(false),
        _ => None,
    };
    if props.get("IdleHint") == Some(&"no") {
        return (Some(0.0), locked);
    }
    let since_us: u64 = props
        .get("IdleSinceHint")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if since_us == 0 {
        return (None, locked);
    }
    let since = u32::try_from(since_us / 1_000_000).map_or(0.0, f64::from);
    ((crate::daemon::now_f64() - since).max(0.0).into(), locked)
}

/// Connect to hostd's user socket and serve it, reconnecting forever.
pub async fn run(config: HostConfig) {
    let socket = config.user_socket();
    let helper = Arc::new(UserHelper::new(config));
    loop {
        let Ok(stream) = UnixStream::connect(&socket).await else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        tracing::info!("connected to hostd");
        session(Arc::clone(&helper), stream).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn session(helper: Arc<UserHelper>, stream: UnixStream) {
    let (read, mut write) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut line = msg.to_string().into_bytes();
            line.push(b'\n');
            if write.write_all(&line).await.is_err() {
                break;
            }
        }
    });
    let reporter = {
        let helper = Arc::clone(&helper);
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                if tx.send(helper.presence().await).is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(PRESENCE_SECS)).await;
            }
        })
    };
    let mut reader = BufReader::new(read);
    while let Ok(Some(line)) = read_line_capped(&mut reader, crate::desk::MAX_HELPER_LINE).await {
        let Ok(Value::Object(msg)) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        let id = msg.get("id").and_then(Value::as_str).map(str::to_owned);
        match (msg.get("type").and_then(Value::as_str), id) {
            (Some("prompt"), Some(id)) => {
                let helper = Arc::clone(&helper);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let answer = helper.show(&msg).await;
                    let _ = tx.send(json!({"type": "answer", "id": id, "answer": answer}));
                });
            }
            (Some("cancel"), Some(id)) => helper.cancel(&id),
            (Some("notify"), _) => helper.notify(&msg),
            _ => {}
        }
    }
    reporter.abort();
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_answers() {
        assert_eq!(parse_answer(0, ""), "allow");
        assert_eq!(parse_answer(1, ""), "deny");
        assert_eq!(parse_answer(5, ""), "timeout");
        assert_eq!(parse_answer(1, "Mute agent 1h\n"), "mute");
        assert_eq!(parse_answer(1, "Send to Discord"), "discord");
        assert_eq!(parse_answer(0, "session"), "allow");
        assert_eq!(parse_answer(0, "deny"), "deny");
        assert_eq!(parse_answer(0, "timeout"), "timeout");
    }

    #[test]
    fn placeholders_are_whole_arguments() {
        let mut f: BTreeMap<&str, String> = BTreeMap::new();
        f.insert("title", "a b; rm -rf /".into());
        let argv = fill(
            &[
                "x".into(),
                "{title}".into(),
                "--t={title}".into(),
                "{nope}".into(),
            ],
            &f,
        );
        assert_eq!(argv, ["x", "a b; rm -rf /", "--t={title}", "{nope}"]);
    }

    #[test]
    fn macos_dialog_passes_text_as_arguments() {
        let argv = default_prompt_macos();
        assert_eq!(argv[0], "/usr/bin/osascript");
        assert_eq!(&argv[argv.len() - 3..], ["{title}", "{text}", "{timeout}"]);
        assert!(argv.iter().all(|a| !a.contains("{text}") || a == "{text}"));
        assert_eq!(default_prompt_linux()[0], "zenity");
    }

    #[test]
    fn notifications_are_escaped_on_linux() {
        assert_eq!(
            html_escape("<b>x</b> & 'y'"),
            "&lt;b&gt;x&lt;/b&gt; &amp; &#x27;y&#x27;"
        );
    }

    #[test]
    fn hid_idle_and_console_lock() {
        let ioreg = "  | |   \"HIDIdleTime\" = 2500000000\n";
        assert_eq!(parse_hid_idle(ioreg), Some(2.0));
        assert_eq!(parse_hid_idle("nothing"), None);
        let plist = r#"<plist><array><dict>
            <key>IOConsoleUsers</key><array>
              <dict><key>kCGSSessionUserIDKey</key><integer>502</integer>
                    <key>kCGSSessionOnConsoleKey</key><true/></dict>
              <dict><key>CGSSessionScreenIsLocked</key><true/>
                    <key>kCGSSessionUserIDKey</key><integer>501</integer>
                    <key>kCGSSessionOnConsoleKey</key><true/></dict>
            </array></dict></array></plist>"#;
        assert_eq!(parse_console_locked(plist, 501), Some(true));
        assert_eq!(parse_console_locked(plist, 502), Some(false));
        assert_eq!(parse_console_locked(plist, 503), None);
        let away = plist.replace(
            "<integer>502</integer>\n                    <key>kCGSSessionOnConsoleKey</key><true/>",
            "<integer>502</integer><key>kCGSSessionOnConsoleKey</key><false/>",
        );
        assert_eq!(parse_console_locked(&away, 502), Some(true));
    }
}
