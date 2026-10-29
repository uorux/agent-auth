//! The configured user's account (uid, gid, home, shell), without libc:
//! `getent passwd` (or `/etc/passwd`) on Linux, `dscl` on macOS.

use std::process::Stdio;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// One `/etc/passwd` line, if it is `name`'s.
#[must_use]
pub fn parse_passwd_line(line: &str, name: &str) -> Option<Passwd> {
    let mut f = line.trim_end_matches('\n').split(':');
    let (user, _pw, uid, gid, _gecos, home, shell) = (
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
    );
    if user != name || f.next().is_some() {
        return None;
    }
    Some(Passwd {
        name: user.to_owned(),
        uid: uid.parse().ok()?,
        gid: gid.parse().ok()?,
        home: home.to_owned(),
        shell: shell.to_owned(),
    })
}

/// `dscl . -read /Users/<name> UniqueID PrimaryGroupID NFSHomeDirectory
/// UserShell` (a value with spaces comes on the next line, indented).
#[must_use]
pub fn parse_dscl(text: &str, name: &str) -> Option<Passwd> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(' ') {
            if let Some(last) = fields.last_mut()
                && last.1.is_empty()
            {
                last.1 = rest.trim().to_owned();
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let get = |k: &str| {
        fields
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    Some(Passwd {
        name: name.to_owned(),
        uid: get("UniqueID")?.parse().ok()?,
        gid: get("PrimaryGroupID")?.parse().ok()?,
        home: get("NFSHomeDirectory")?,
        shell: get("UserShell").unwrap_or_else(|| "/bin/zsh".to_owned()),
    })
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Look `name` up. An account name with odd characters is refused before
/// anything is asked.
pub async fn lookup(name: &str) -> Result<Passwd, String> {
    let ok = !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !ok {
        return Err(format!("not an account name: {name:?}"));
    }
    if cfg!(target_os = "macos") {
        let path = format!("/Users/{name}");
        let text = output(
            "/usr/bin/dscl",
            &[
                ".",
                "-read",
                &path,
                "UniqueID",
                "PrimaryGroupID",
                "NFSHomeDirectory",
                "UserShell",
            ],
        )
        .await
        .ok_or_else(|| format!("no user {name}"))?;
        return parse_dscl(&text, name).ok_or_else(|| format!("no user {name}"));
    }
    if let Some(line) = output("getent", &["passwd", name]).await
        && let Some(p) = parse_passwd_line(line.trim(), name)
    {
        return Ok(p);
    }
    let text = tokio::fs::read_to_string("/etc/passwd")
        .await
        .map_err(|e| format!("/etc/passwd: {e}"))?;
    text.lines()
        .find_map(|l| parse_passwd_line(l, name))
        .ok_or_else(|| format!("no user {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_lines() {
        let p = parse_passwd_line(
            "jrt:x:1000:100:Jacob:/home/jrt:/run/current-system/sw/bin/zsh",
            "jrt",
        )
        .unwrap();
        assert_eq!((p.uid, p.gid, p.home.as_str()), (1000, 100, "/home/jrt"));
        assert!(parse_passwd_line("jrt:x:1000:100::/home/jrt:/bin/sh", "jr").is_none());
        assert!(parse_passwd_line("jrt:x:abc:100::/home/jrt:/bin/sh", "jrt").is_none());
        assert!(parse_passwd_line("jrt:x:1000", "jrt").is_none());
    }

    #[test]
    fn dscl_output() {
        let text = "NFSHomeDirectory: /Users/jrt\nPrimaryGroupID: 20\nUniqueID: 501\nUserShell: /bin/zsh\n";
        let p = parse_dscl(text, "jrt").unwrap();
        assert_eq!(
            (p.uid, p.gid, p.home.as_str(), p.shell.as_str()),
            (501, 20, "/Users/jrt", "/bin/zsh")
        );
        let spaced = "NFSHomeDirectory:\n /Users/Jacob Root\nPrimaryGroupID: 20\nUniqueID: 502\n";
        let p = parse_dscl(spaced, "jacob").unwrap();
        assert_eq!(p.home, "/Users/Jacob Root");
        assert!(parse_dscl("UniqueID: x", "a").is_none());
    }
}
