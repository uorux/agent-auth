//! JSON lines over a unix socket, with the caller's uid from the kernel
//! (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS, through tokio): the
//! local APIs of hostd (hostctl) and sandboxd (§12.1).
//!
//! ```text
//! request: {"method": "...", "params": {...}, "token": ...}   one per line
//! reply:   {"ok": true, "result": ...} | {"ok": false, "error": "..."}
//! ```
//!
//! Lines are capped ([`Limits::max_line`]); a longer one ends the
//! connection. The caller's credentials are read once per connection, from
//! the socket, and the API admits or refuses the caller before anything is
//! read ([`LocalApi::admit`]); they are handed to the API with every
//! request too. Connections are capped per uid and overall, and one that
//! sends nothing for [`Limits::idle`] is closed (security review 2026-10,
//! finding 3: any uid could hold descriptors and memory).

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The longest request or reply line.
pub const MAX_LINE: usize = 1024 * 1024;
/// The longest line of a control socket (hostctl's requests are small).
pub const MAX_CONTROL_LINE: usize = 4 * 1024;

/// What one listener allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest request line.
    pub max_line: usize,
    /// Connections at once.
    pub max_conns: usize,
    /// Connections at once from one uid.
    pub max_per_uid: usize,
    /// A connection is closed when a request line takes longer than this
    /// to arrive.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_line: MAX_LINE,
            max_conns: 64,
            max_per_uid: 8,
            idle: Duration::from_secs(60),
        }
    }
}

impl Limits {
    /// A control socket's: short lines.
    #[must_use]
    pub fn control() -> Limits {
        Limits {
            max_line: MAX_CONTROL_LINE,
            ..Limits::default()
        }
    }
}

/// Open connections, per uid and overall.
#[derive(Debug, Default)]
struct Slots {
    total: usize,
    per_uid: HashMap<u32, usize>,
}

/// A connection's place, given back on drop.
struct Slot {
    slots: Arc<Mutex<Slots>>,
    uid: u32,
}

impl Slot {
    fn take(slots: &Arc<Mutex<Slots>>, uid: u32, limits: Limits) -> Option<Slot> {
        let mut s = slots.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = s.per_uid.get(&uid).copied().unwrap_or(0);
        if s.total >= limits.max_conns || mine >= limits.max_per_uid {
            return None;
        }
        s.total = s.total.saturating_add(1);
        s.per_uid.insert(uid, mine.saturating_add(1));
        Some(Slot {
            slots: Arc::clone(slots),
            uid,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut s = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.per_uid.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.per_uid.remove(&self.uid);
            }
        }
    }
}

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
    /// Whether `peer` may use this socket at all, decided before anything
    /// it sent is read. By default everyone may (each call still checks).
    fn admit(&self, peer: Peer) -> impl Future<Output = Result<(), LocalError>> + Send {
        let _ = peer;
        async { Ok(()) }
    }

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

/// Serve `api` on `listener` with the default [`Limits`] until the task is
/// dropped.
pub async fn serve<A: LocalApi>(listener: UnixListener, api: Arc<A>) {
    serve_with(listener, api, Limits::default()).await;
}

/// Serve `api` on `listener` within `limits` until the task is dropped.
pub async fn serve_with<A: LocalApi>(listener: UnixListener, api: Arc<A>, limits: Limits) {
    let slots = Arc::new(Mutex::new(Slots::default()));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let api = Arc::clone(&api);
                let slots = Arc::clone(&slots);
                tokio::spawn(async move { serve_conn(stream, api, &slots, limits).await });
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

async fn serve_conn<A: LocalApi>(
    stream: UnixStream,
    api: Arc<A>,
    slots: &Arc<Mutex<Slots>>,
    limits: Limits,
) {
    let peer = match Peer::of(&stream) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "no peer credentials on a local connection");
            return;
        }
    };
    let (read, mut write) = stream.into_split();
    // Who it is, before reading a byte.
    if let Err(e) = api.admit(peer).await {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            write.write_all(&reply_line(&Err(e))),
        )
        .await;
        return;
    }
    let Some(_slot) = Slot::take(slots, peer.uid, limits) else {
        let busy = Err(LocalError::new("too many connections"));
        let _ =
            tokio::time::timeout(Duration::from_secs(1), write.write_all(&reply_line(&busy))).await;
        return;
    };
    let mut reader = BufReader::new(read);
    loop {
        let line =
            match tokio::time::timeout(limits.idle, read_line_capped(&mut reader, limits.max_line))
                .await
            {
                Err(_) => return,
                Ok(Ok(Some(l))) => l,
                Ok(Ok(None)) => return,
                Ok(Err(e)) => {
                    let _ = write
                        .write_all(&reply_line(&Err(LocalError::new(format!(
                            "bad request: {e}"
                        )))))
                        .await;
                    return;
                }
            };
        let reply = handle(&*api, &line, peer).await;
        let sent = tokio::time::timeout(limits.idle, write.write_all(&reply_line(&reply))).await;
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
    }
}

async fn handle<A: LocalApi>(api: &A, line: &[u8], peer: Peer) -> Result<Value, LocalError> {
    let req = agent_auth_wire::daemon::local::parse_request(line).map_err(LocalError)?;
    api.call(&req.method, req.params, req.token, peer).await
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

    struct Picky;

    impl LocalApi for Picky {
        async fn admit(&self, _peer: Peer) -> Result<(), LocalError> {
            Err(LocalError::new("not you"))
        }

        async fn call(
            &self,
            _: &str,
            _: Map<String, Value>,
            _: Option<Value>,
            _: Peer,
        ) -> Result<Value, LocalError> {
            panic!("a refused peer's request was read");
        }
    }

    /// Security review 2026-10, finding 3: the caller is refused before
    /// anything is read; connections are capped per uid; a silent one is
    /// closed; control lines are short.
    #[tokio::test]
    async fn callers_are_checked_first_and_connections_are_bounded() {
        let dir = scratch();
        let path = dir.join("p.sock");
        let server = tokio::spawn(serve(bind(&path, 0o600).unwrap(), Arc::new(Picky)));
        let err = call(&path, "status", Map::new(), None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "not you");
        server.abort();

        let path = dir.join("q.sock");
        let limits = Limits {
            max_per_uid: 2,
            idle: Duration::from_secs(2),
            ..Limits::control()
        };
        let server = tokio::spawn(serve_with(
            bind(&path, 0o600).unwrap(),
            Arc::new(Echo),
            limits,
        ));
        // Two connections that hold their slots: each answered once (so its
        // slot is surely taken: slots are taken on the connection's own
        // task, in no particular order), then silent.
        let mut held = Vec::new();
        for _ in 0..2 {
            let mut s = BufReader::new(UnixStream::connect(&path).await.unwrap());
            s.get_mut()
                .write_all(b"{\"method\": \"echo\", \"params\": {}, \"token\": null}\n")
                .await
                .unwrap();
            let line = read_line_capped(&mut s, 1000).await.unwrap().unwrap();
            assert!(line.starts_with(b"{\"ok\":true"), "{line:?}");
            held.push(s);
        }
        let err = call(&path, "echo", Map::new(), None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "too many connections");
        // The silent ones are closed after the idle time, freeing the slots.
        for mut r in held {
            let closed =
                tokio::time::timeout(Duration::from_secs(30), read_line_capped(&mut r, 100))
                    .await
                    .unwrap();
            assert!(matches!(closed, Ok(None)));
        }
        assert!(
            call(&path, "echo", Map::new(), None, Duration::from_secs(5))
                .await
                .is_ok()
        );
        // A control line is at most 4 KiB.
        let mut p = Map::new();
        p.insert("x".into(), json!("y".repeat(MAX_CONTROL_LINE)));
        let err = call(&path, "echo", p, None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("line too long"), "{err}");
        server.abort();
        std::fs::remove_dir_all(dir).ok();
    }
}
