//! JSON lines over a unix socket, with the caller's uid from the kernel
//! (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS, through tokio): the
//! local APIs of hostd (hostctl) and sandboxd (§12.1).
//!
//! ```text
//! request: {"method": "...", "params": {...}, "token": ...}   one per line
//! reply:   {"ok": true, "result": ...} | {"ok": false, "error": "..."}
//! ```
//!
//! Lines are capped ([`MAX_LINE`]); a longer one ends the connection. The
//! caller's credentials are read once per connection, from the socket, and
//! handed to the API with every request: the API decides who may do what.

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The longest request or reply line.
pub const MAX_LINE: usize = 1024 * 1024;

/// Who is on the other end, as the kernel says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

impl Peer {
    pub fn of(stream: &UnixStream) -> io::Result<Peer> {
        let cred = stream.peer_cred()?;
        Ok(Peer {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        })
    }
}

/// A refusal or failure, answered as `{"ok": false, "error": <text>}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct LocalError(pub String);

impl LocalError {
    pub fn new(msg: impl Into<String>) -> LocalError {
        LocalError(msg.into())
    }
}

/// A local API.
pub trait LocalApi: Send + Sync + 'static {
    fn call(
        &self,
        method: &str,
        params: Map<String, Value>,
        token: Option<Value>,
        peer: Peer,
    ) -> impl Future<Output = Result<Value, LocalError>> + Send;
}

/// Bind `path` (its parent created, a stale socket replaced) and set its
/// mode. Each connection checks its caller, so the mode only says who may
/// knock.
pub fn bind(path: &Path, mode: u32) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Serve `api` on `listener` until the task is dropped.
pub async fn serve<A: LocalApi>(listener: UnixListener, api: Arc<A>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let api = Arc::clone(&api);
                tokio::spawn(async move { serve_conn(stream, api).await });
            }
            Err(e) => {
                tracing::warn!(error = %e, "local socket accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One line of at most `cap` bytes (without its newline). `Ok(None)` at
/// end of stream; an over-long line is an error (`InvalidData`).
pub async fn read_line_capped<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        let (chunk, found) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (buf.get(..i).unwrap_or_default(), Some(i)),
            None => (buf, None),
        };
        if line.len().saturating_add(chunk.len()) > cap {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        line.extend_from_slice(chunk);
        match found {
            Some(i) => {
                reader.consume(i.saturating_add(1));
                return Ok(Some(line));
            }
            None => {
                let n = chunk.len();
                reader.consume(n);
            }
        }
    }
}

fn reply_line(reply: &Result<Value, LocalError>) -> Vec<u8> {
    let v = match reply {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(e) => json!({"ok": false, "error": e.0}),
    };
    let mut out = v.to_string().into_bytes();
    out.push(b'\n');
    out
}

async fn serve_conn<A: LocalApi>(stream: UnixStream, api: Arc<A>) {
    let peer = match Peer::of(&stream) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "no peer credentials on a local connection");
            return;
        }
    };
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let line = match read_line_capped(&mut reader, MAX_LINE).await {
            Ok(Some(l)) => l,
            Ok(None) => return,
            Err(e) => {
                let _ = write
                    .write_all(&reply_line(&Err(LocalError::new(format!(
                        "bad request: {e}"
                    )))))
                    .await;
                return;
            }
        };
        let reply = handle(&*api, &line, peer).await;
        if write.write_all(&reply_line(&reply)).await.is_err() {
            return;
        }
    }
}

async fn handle<A: LocalApi>(api: &A, line: &[u8], peer: Peer) -> Result<Value, LocalError> {
    let req: Value = serde_json::from_slice(line).map_err(|_| LocalError::new("bad request"))?;
    let Value::Object(mut req) = req else {
        return Err(LocalError::new("bad request"));
    };
    let Some(Value::String(method)) = req.remove("method") else {
        return Err(LocalError::new("bad request"));
    };
    let params = match req.remove("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(p)) => p,
        Some(_) => return Err(LocalError::new("params must be an object")),
    };
    let token = req.remove("token").filter(|t| !t.is_null());
    api.call(&method, params, token, peer).await
}

/// A failed client call.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The daemon answered no.
    #[error("{0}")]
    Refused(String),
    #[error("the daemon is not reachable: {0}")]
    Io(#[from] io::Error),
    #[error("no reply from the daemon")]
    NoReply,
    #[error("timed out waiting for the daemon")]
    Timeout,
}

/// Client: one request, one reply.
pub async fn call(
    path: &Path,
    method: &str,
    params: Map<String, Value>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Value, CallError> {
    let fut = async {
        let mut stream = UnixStream::connect(path).await?;
        let mut req = json!({"method": method, "params": params, "token": token}).to_string();
        req.push('\n');
        stream.write_all(req.as_bytes()).await?;
        let mut reader = BufReader::new(stream);
        let line = read_line_capped(&mut reader, MAX_LINE)
            .await?
            .ok_or(CallError::NoReply)?;
        let reply: Value = serde_json::from_slice(&line).map_err(|_| CallError::NoReply)?;
        if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(reply.get("result").cloned().unwrap_or(Value::Null))
        } else {
            let error = reply
                .get("error")
                .and_then(Value::as_str)
                .filter(|e| !e.is_empty())
                .unwrap_or("no reply from the daemon");
            Err(CallError::Refused(error.to_owned()))
        }
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| CallError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl LocalApi for Echo {
        async fn call(
            &self,
            method: &str,
            params: Map<String, Value>,
            _token: Option<Value>,
            peer: Peer,
        ) -> Result<Value, LocalError> {
            match method {
                "whoami" => Ok(json!({"uid": peer.uid, "pid": peer.pid})),
                "echo" => Ok(Value::Object(params)),
                _ => Err(LocalError::new(format!("unknown method '{method}'"))),
            }
        }
    }

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aa-localsock-{}-{}",
            std::process::id(),
            uuid_like()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    /// Our own uid, as the kernel reports it on a socket pair.
    fn my_uid() -> u32 {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let a = UnixStream::from_std({
            a.set_nonblocking(true).unwrap();
            a
        })
        .unwrap();
        Peer::of(&a).unwrap().uid
    }

    #[tokio::test]
    async fn peer_credentials_over_a_real_socket() {
        let dir = scratch();
        let path = dir.join("ctl.sock");
        let listener = bind(&path, 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let server = tokio::spawn(serve(listener, Arc::new(Echo)));
        let who = call(&path, "whoami", Map::new(), None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(who["uid"], json!(my_uid()));
        assert_eq!(who["pid"], json!(std::process::id()));
        let mut p = Map::new();
        p.insert("a".into(), json!(1));
        assert_eq!(
            call(&path, "echo", p, None, Duration::from_secs(5))
                .await
                .unwrap(),
            json!({"a": 1})
        );
        let err = call(&path, "nope", Map::new(), None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "unknown method 'nope'");
        // A stale socket is replaced on bind.
        server.abort();
        assert!(bind(&path, 0o666).is_ok());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn malformed_and_oversized_requests() {
        let dir = scratch();
        let path = dir.join("x.sock");
        let server = tokio::spawn(serve(bind(&path, 0o600).unwrap(), Arc::new(Echo)));
        let mut s = UnixStream::connect(&path).await.unwrap();
        s.write_all(b"[1]\n{\"method\": 3}\n{\"method\":\"echo\",\"params\":[]}\n")
            .await
            .unwrap();
        let mut r = BufReader::new(s);
        for want in ["bad request", "bad request", "params must be an object"] {
            let line = read_line_capped(&mut r, MAX_LINE).await.unwrap().unwrap();
            let v: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(v["error"], json!(want));
        }
        let mut s = UnixStream::connect(&path).await.unwrap();
        let big = vec![b'x'; MAX_LINE + 10];
        let _ = s.write_all(&big).await;
        let mut r = BufReader::new(s);
        let line = read_line_capped(&mut r, MAX_LINE).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&line).contains("line too long"));
        assert!(read_line_capped(&mut r, MAX_LINE).await.unwrap().is_none());
        server.abort();
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn capped_lines() {
        let data: &[u8] = b"abc\ndefgh\nij";
        let mut r = BufReader::with_capacity(2, data);
        assert_eq!(read_line_capped(&mut r, 4).await.unwrap().unwrap(), b"abc");
        assert!(read_line_capped(&mut r, 4).await.is_err());
        let mut r = BufReader::with_capacity(2, data);
        let mut lines = Vec::new();
        while let Some(l) = read_line_capped(&mut r, 10).await.unwrap() {
            lines.push(l);
        }
        assert_eq!(
            lines,
            vec![b"abc".to_vec(), b"defgh".to_vec(), b"ij".to_vec()]
        );
    }
}
