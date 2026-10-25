//! `agent-auth admin google-consent`: the operator's one-time helper for a
//! Google account's refresh token (`google_consent.py`), run on their own
//! machine, where a browser can sign in.
//!
//! It runs Google's loopback flow: the consent page redirects to
//! `http://127.0.0.1:<port>/` on this machine, which only a *Desktop app*
//! OAuth client accepts (the copy-a-code "OOB" flow is gone). PKCE (S256)
//! and a state value guard the redirect. The refresh token goes to a file,
//! mode 0600, and is never printed: hand that file to the broker
//! (`platforms.google.accounts.<name>.refresh_token_file`, via your
//! secrets).
//!
//! Two things Google does that matter here:
//! - An OAuth app whose publishing status is "Testing" issues refresh
//!   tokens that expire after 7 days. Set it to "In production" (unverified
//!   is fine for your own account), or on Workspace make the app "Internal".
//! - The consent screen lets the person untick scopes (granular consent):
//!   the result lists what was granted and what is missing.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use agent_auth_core::authority::{GOOGLE_SCOPES, google_scope_url};
use agent_auth_core::pyfmt::repr;
use agent_auth_crypto::{Secret, b64url_encode, ct_eq, token_urlsafe};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Why the consent did not finish (printed in red, exit 1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConsentError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, ConsentError> {
    Err(ConsentError(msg.into()))
}

/// An OAuth client from the Google Cloud console's JSON (`installed`,
/// `web`, or the object itself).
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub auth_uri: Option<String>,
    pub token_uri: Option<String>,
}

/// What the command prints (field order is the Python's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentResult {
    pub granted: Vec<String>,
    pub missing: Vec<String>,
    pub file: String,
}

fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(i) => text.get(..i).unwrap_or(&text).to_owned(),
        None => text,
    }
}

pub fn load_client(client_secret_file: &str) -> Result<OAuthClient, ConsentError> {
    let text = std::fs::read_to_string(client_secret_file).map_err(|e| {
        ConsentError(format!(
            "cannot read {client_secret_file}: {}",
            strerror(&e)
        ))
    })?;
    let not_client = || ConsentError(format!("{client_secret_file} is not an OAuth client JSON"));
    let data: Value = serde_json::from_str(&text).map_err(|_| not_client())?;
    let client = data
        .get("installed")
        .filter(|v| v.is_object())
        .or_else(|| data.get("web").filter(|v| v.is_object()))
        .unwrap_or(&data);
    if !client.is_object() {
        return Err(not_client());
    }
    let s = |k: &str| {
        client
            .get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let Some(client_id) = s("client_id") else {
        return err(format!(
            "{client_secret_file} is not an OAuth client JSON (no client_id)"
        ));
    };
    Ok(OAuthClient {
        client_id,
        client_secret: s("client_secret").unwrap_or_default(),
        auth_uri: s("auth_uri"),
        token_uri: s("token_uri"),
    })
}

/// The scopes' URLs; refuses an unknown one, or none.
pub fn full_scopes(scopes: &[String]) -> Result<Vec<String>, ConsentError> {
    let unknown: Vec<String> = scopes
        .iter()
        .filter(|s| google_scope_url(s).is_none())
        .map(|s| repr(s))
        .collect();
    if !unknown.is_empty() || scopes.is_empty() {
        let known: Vec<String> = GOOGLE_SCOPES.iter().map(|s| repr(s)).collect();
        return err(format!(
            "unknown scope(s) [{}]; known: [{}]",
            unknown.join(", "),
            known.join(", ")
        ));
    }
    Ok(scopes.iter().filter_map(|s| google_scope_url(s)).collect())
}

/// `(verifier, S256 challenge)`.
pub fn pkce() -> Result<(Secret<String>, String), ConsentError> {
    let verifier = token_urlsafe(64).map_err(|e| ConsentError(e.to_string()))?;
    let challenge = b64url_encode(&agent_auth_crypto::digest::sha256(verifier.as_bytes()));
    Ok((Secret::new(verifier), challenge))
}

pub fn auth_url(
    client: &OAuthClient,
    scopes: &[String],
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> Result<String, ConsentError> {
    let scope = full_scopes(scopes)?.join(" ");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", client.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", scope.as_str()),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "false"),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ])
        .finish();
    Ok(format!(
        "{}?{query}",
        client.auth_uri.as_deref().unwrap_or(AUTH_URL)
    ))
}

/// https, or plain http to a loopback host only.
fn endpoint_ok(endpoint: &str) -> bool {
    let Ok(u) = url::Url::parse(endpoint) else {
        return false;
    };
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        },
        _ => false,
    }
}

/// The token response for an authorization code; an error without a
/// refresh token.
pub async fn exchange(
    client: &OAuthClient,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Value, ConsentError> {
    let endpoint = client.token_uri.as_deref().unwrap_or(TOKEN_URL);
    if !endpoint_ok(endpoint) {
        return err(format!(
            "the client's token_uri {} is not an https URL",
            repr(endpoint)
        ));
    }
    let tls = agent_auth_tls::default_client_config()
        .map_err(|e| ConsentError(format!("TLS client configuration: {e}")))?;
    let http = agent_auth_tls::reqwest_builder(tls, Duration::from_secs(30))
        .build()
        .map_err(|e| ConsentError(format!("HTTP client: {e}")))?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client.client_id.as_str()),
            ("client_secret", client.client_secret.as_str()),
            ("code_verifier", verifier),
            ("redirect_uri", redirect_uri),
        ])
        .finish();
    let resp = http
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| ConsentError(format!("token exchange failed: {}", e.without_url())))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ConsentError(format!("token exchange failed: {}", e.without_url())))?;
    let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status != 200 {
        let field = |k: &str| answer.get(k).and_then(Value::as_str).unwrap_or("");
        let text = format!(
            "token exchange failed: {status} {} {}",
            field("error"),
            field("error_description")
        );
        return err(text.trim().to_owned());
    }
    if answer
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return err(
            "Google returned no refresh token (is the client a Desktop app, and was \
             prompt=consent shown?)",
        );
    }
    Ok(answer)
}

fn non_empty_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file() || m.len() > 0)
}

/// Write `value` to `path`, mode 0600 from creation on. An existing file is
/// replaced only if it is an empty regular file (never through a link).
pub fn write_secret(path: &str, value: &str) -> Result<(), ConsentError> {
    let p = Path::new(path);
    if non_empty_file(p) {
        return err(format!("{path} exists and is not empty; remove it first"));
    }
    let io = |e: std::io::Error| ConsentError(format!("cannot write {path}: {}", strerror(&e)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .map_err(io)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(io)?;
    file.write_all(value.as_bytes()).map_err(io)?;
    Ok(())
}

/// `(granted, missing)` of the scopes asked for, by the answer's `scope`.
#[must_use]
pub fn granted(answer: &Value, scopes: &[String]) -> (Vec<String>, Vec<String>) {
    let have: Vec<&str> = answer
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect();
    scopes
        .iter()
        .cloned()
        .partition(|s| google_scope_url(s).is_some_and(|u| have.contains(&u.as_str())))
}

/// The largest request the callback reads.
const MAX_REQUEST: usize = 16 * 1024;

/// Serve requests on `listener` until one carries a query; its parameters.
async fn one_callback(listener: &TcpListener) -> Result<BTreeMap<String, String>, ConsentError> {
    loop {
        let (mut sock, _) = listener
            .accept()
            .await
            .map_err(|e| ConsentError(format!("the callback listener failed: {}", strerror(&e))))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_REQUEST {
            match tokio::time::timeout(Duration::from_secs(10), sock.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let target = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        let query = target.split_once('?').map_or("", |(_, q)| q);
        let params: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .fold(BTreeMap::new(), |mut m, (k, v)| {
                m.entry(k).or_insert(v);
                m
            });
        let reply = "agent-auth: done, you can close this tab.\n";
        let _ = sock
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = sock.shutdown().await;
        if !params.is_empty() {
            return Ok(params);
        }
    }
}

/// What `consent` needs.
#[derive(Debug, Clone)]
pub struct ConsentOptions {
    pub client_secret_file: String,
    pub scopes: Vec<String>,
    pub out: String,
    /// Loopback port; 0: any free one.
    pub port: u16,
}

/// The whole flow. `ready(url)` is called once the callback listens: it
/// shows the URL (and opens a browser).
pub async fn consent(
    opts: &ConsentOptions,
    ready: impl FnOnce(&str),
) -> Result<ConsentResult, ConsentError> {
    let client = load_client(&opts.client_secret_file)?;
    full_scopes(&opts.scopes)?;
    if non_empty_file(Path::new(&opts.out)) {
        return err(format!(
            "{} exists and is not empty; remove it first",
            opts.out
        ));
    }
    let (verifier, challenge) = pkce()?;
    let state = token_urlsafe(24).map_err(|e| ConsentError(e.to_string()))?;
    let listener = TcpListener::bind(("127.0.0.1", opts.port))
        .await
        .map_err(|e| ConsentError(format!("cannot listen on 127.0.0.1: {}", strerror(&e))))?;
    let port = listener
        .local_addr()
        .map_err(|e| ConsentError(strerror(&e)))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/");
    ready(&auth_url(
        &client,
        &opts.scopes,
        &redirect_uri,
        &state,
        &challenge,
    )?);
    let params = one_callback(&listener).await?;
    drop(listener);
    if let Some(e) = params.get("error") {
        return err(format!("consent refused: {e}"));
    }
    let returned = params.get("state").map_or("", String::as_str);
    if !ct_eq(returned.as_bytes(), state.as_bytes()) {
        return err("state mismatch: the callback did not come from this consent");
    }
    let Some(code) = params.get("code").filter(|c| !c.is_empty()) else {
        return err("no authorization code in the callback");
    };
    let answer = exchange(&client, code, verifier.expose(), &redirect_uri).await?;
    let refresh = answer
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    write_secret(&opts.out, refresh)?;
    let (yes, missing) = granted(&answer, &opts.scopes);
    Ok(ConsentResult {
        granted: yes,
        missing,
        file: opts.out.clone(),
    })
}

/// Open `url` in the desktop's browser; failing is not an error (the URL
/// was printed).
pub fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Dir {
            let p = std::env::temp_dir().join(format!(
                "aa-consent-{}",
                token_urlsafe(9).unwrap().replace(['-', '_'], "x")
            ));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fake token endpoint answering `answer`, recording form bodies.
    async fn fake_token(answer: (u16, Value)) -> (String, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let s2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // headers, then Content-Length bytes
                loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len: usize = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= i + 4 + len {
                            s2.lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&buf[i + 4..]).into_owned());
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let body = answer.1.to_string();
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            answer.0,
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (format!("http://{addr}/token"), seen)
    }

    fn client_file(dir: &Dir, token_uri: &str) -> String {
        let p = dir.path("client.json");
        std::fs::write(
            &p,
            json!({"installed": {"client_id": "cid", "client_secret": "csec", "token_uri": token_uri}})
                .to_string(),
        )
        .unwrap();
        p
    }

    fn form(body: &str) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    #[test]
    fn auth_url_and_pkce() {
        let dir = Dir::new();
        let client = load_client(&client_file(&dir, TOKEN_URL)).unwrap();
        let (verifier, challenge) = pkce().unwrap();
        assert_eq!(verifier.expose().len(), 86);
        assert_eq!(
            challenge,
            b64url_encode(&agent_auth_crypto::digest::sha256(
                verifier.expose().as_bytes()
            ))
        );
        let u = auth_url(
            &client,
            &scopes(&["gmail.readonly", "gmail.send"]),
            "http://127.0.0.1:5555/",
            "st",
            &challenge,
        )
        .unwrap();
        let parsed = url::Url::parse(&u).unwrap();
        assert_eq!(
            format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap(),
                parsed.path()
            ),
            AUTH_URL
        );
        let q: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["client_id"], "cid");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5555/");
        assert_eq!(
            q["scope"],
            "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send"
        );
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["include_granted_scopes"], "false");
        assert_eq!(q["code_challenge"], challenge);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["state"], "st");
        assert_eq!(q["response_type"], "code");
        let e = auth_url(&client, &scopes(&["gmail.everything"]), "x", "s", "c").unwrap_err();
        assert!(
            e.0.starts_with("unknown scope(s) ['gmail.everything']"),
            "{e}"
        );
        assert!(full_scopes(&[]).is_err());
        let missing = dir.path("nope.json");
        assert!(
            load_client(&missing)
                .unwrap_err()
                .0
                .starts_with("cannot read")
        );
        std::fs::write(&missing, "{}").unwrap();
        assert!(
            load_client(&missing)
                .unwrap_err()
                .0
                .ends_with("(no client_id)")
        );
    }

    #[tokio::test]
    async fn exchanges() {
        let dir = Dir::new();
        let (url, seen) = fake_token((
            200,
            json!({"access_token": "a", "refresh_token": "1//r",
                   "scope": "https://www.googleapis.com/auth/gmail.readonly"}),
        ))
        .await;
        let client = load_client(&client_file(&dir, &url)).unwrap();
        let body = exchange(&client, "code1", "verifier1", "http://127.0.0.1:5555/")
            .await
            .unwrap();
        let f = form(&seen.lock().unwrap()[0]);
        let expected: BTreeMap<String, String> = [
            ("grant_type", "authorization_code"),
            ("code", "code1"),
            ("client_id", "cid"),
            ("client_secret", "csec"),
            ("code_verifier", "verifier1"),
            ("redirect_uri", "http://127.0.0.1:5555/"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(f, expected);
        assert_eq!(
            granted(&body, &scopes(&["gmail.readonly", "gmail.send"])),
            (scopes(&["gmail.readonly"]), scopes(&["gmail.send"]))
        );

        let (url, _) = fake_token((200, json!({"access_token": "a"}))).await;
        let client = load_client(&client_file(&dir, &url)).unwrap();
        let e = exchange(&client, "c", "v", "http://127.0.0.1:1/")
            .await
            .unwrap_err();
        assert!(e.0.contains("no refresh token"), "{e}");

        let (url, _) = fake_token((400, json!({"error": "invalid_grant"}))).await;
        let client = load_client(&client_file(&dir, &url)).unwrap();
        let e = exchange(&client, "c", "v", "http://127.0.0.1:1/")
            .await
            .unwrap_err();
        assert_eq!(e.0, "token exchange failed: 400 invalid_grant");

        let client = load_client(&client_file(&dir, "http://oauth2.example/token")).unwrap();
        let e = exchange(&client, "c", "v", "http://127.0.0.1:1/")
            .await
            .unwrap_err();
        assert!(e.0.contains("is not an https URL"), "{e}");
    }

    #[test]
    fn write_secret_mode() {
        let dir = Dir::new();
        let out = dir.path("rt");
        write_secret(&out, "1//secret").unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "1//secret");
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let e = write_secret(&out, "again").unwrap_err();
        assert!(e.0.contains("not empty"), "{e}");
        let empty = dir.path("empty");
        std::fs::write(&empty, "").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret(&empty, "x").unwrap();
        let mode = std::fs::metadata(&empty).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// The browser, played by a request to the callback.
    fn browser(forge_state: bool) -> impl FnOnce(&str) {
        move |u: &str| {
            let parsed = url::Url::parse(u).unwrap();
            let q: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();
            let state = if forge_state {
                "forged".to_owned()
            } else {
                q["state"].clone()
            };
            let redirect = url::Url::parse(&q["redirect_uri"]).unwrap();
            let port = redirect.port().unwrap();
            tokio::spawn(async move {
                let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                // A request with no query first (a favicon): ignored.
                let req = "GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n";
                sock.write_all(req.as_bytes()).await.unwrap();
                let mut sink = Vec::new();
                let _ = sock.read_to_end(&mut sink).await;
                let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("code", "c1"), ("state", state.as_str())])
                    .finish();
                let req = format!("GET /?{query} HTTP/1.1\r\nHost: x\r\n\r\n");
                sock.write_all(req.as_bytes()).await.unwrap();
                let mut answer = Vec::new();
                let _ = sock.read_to_end(&mut answer).await;
                assert!(String::from_utf8_lossy(&answer).contains("you can close this tab"));
            });
        }
    }

    #[tokio::test]
    async fn consent_end_to_end() {
        let dir = Dir::new();
        let (url, seen) = fake_token((
            200,
            json!({"refresh_token": "1//r", "scope": "https://www.googleapis.com/auth/gmail.readonly"}),
        ))
        .await;
        let out = dir.path("refresh");
        let opts = ConsentOptions {
            client_secret_file: client_file(&dir, &url),
            scopes: scopes(&["gmail.readonly", "gmail.send"]),
            out: out.clone(),
            port: 0,
        };
        let result = consent(&opts, browser(false)).await.unwrap();
        assert_eq!(
            result,
            ConsentResult {
                granted: scopes(&["gmail.readonly"]),
                missing: scopes(&["gmail.send"]),
                file: out.clone(),
            }
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "1//r");
        let f = form(&seen.lock().unwrap()[0]);
        assert_eq!(f["code"], "c1");
        assert!(f["redirect_uri"].starts_with("http://127.0.0.1:"));
        assert_eq!(f["code_verifier"].len(), 86);
    }

    #[tokio::test]
    async fn consent_state_mismatch_writes_nothing() {
        let dir = Dir::new();
        let (url, seen) = fake_token((200, json!({"refresh_token": "1//r"}))).await;
        let out = dir.path("rt");
        let opts = ConsentOptions {
            client_secret_file: client_file(&dir, &url),
            scopes: scopes(&["gmail.readonly"]),
            out: out.clone(),
            port: 0,
        };
        let e = consent(&opts, browser(true)).await.unwrap_err();
        assert!(e.0.contains("state mismatch"), "{e}");
        assert!(!Path::new(&out).exists());
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_existing_token_file_is_never_overwritten() {
        let dir = Dir::new();
        let out = dir.path("rt");
        std::fs::write(&out, "old").unwrap();
        let opts = ConsentOptions {
            client_secret_file: client_file(&dir, TOKEN_URL),
            scopes: scopes(&["gmail.readonly"]),
            out: out.clone(),
            port: 0,
        };
        let e = consent(&opts, |_| panic!("no URL")).await.unwrap_err();
        assert_eq!(
            e.0,
            format!("{out} exists and is not empty; remove it first")
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "old");
    }
}
