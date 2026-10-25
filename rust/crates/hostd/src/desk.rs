//! hostd's side of the desktop helper's socket (`{runtime_dir}/user.sock`,
//! §12.3). Anyone may connect (mode 0666); only the configured user's uid
//! is listened to (INV-36), and a new such connection replaces the old one.
//!
//! helper → hostd: `{"type":"presence",...}`, `{"type":"answer","id","answer"}`.
//! hostd → helper: `prompt`, `cancel`, `notify`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_auth_daemon::localsock::{Peer, read_line_capped};
use serde_json::Value;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::daemon::Hostd;
use crate::executor::Executor;

/// The longest line from the helper.
pub const MAX_HELPER_LINE: usize = 64 * 1024;

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Accept helper connections until the task is dropped.
pub async fn serve<E: Executor>(listener: UnixListener, hostd: Arc<Hostd<E>>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let hostd = Arc::clone(&hostd);
                tokio::spawn(async move { connection(stream, hostd).await });
            }
            Err(e) => {
                tracing::warn!(error = %e, "user socket accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn connection<E: Executor>(stream: UnixStream, hostd: Arc<Hostd<E>>) {
    let Ok(peer) = Peer::of(&stream) else {
        return;
    };
    if !hostd.is_user(peer.uid).await {
        // Not the configured user: closed without a word.
        return;
    }
    let conn = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
    let (read, mut write) = stream.into_split();
    let mut outbox = hostd.helper_attached(conn, peer.pid.unwrap_or(0)).await;
    let writer = tokio::spawn(async move {
        while let Some(line) = outbox.recv().await {
            let mut bytes = line.into_bytes();
            bytes.push(b'\n');
            // A helper that stops reading is dropped (drain timeout).
            let sent =
                tokio::time::timeout(std::time::Duration::from_secs(5), write.write_all(&bytes))
                    .await;
            if !matches!(sent, Ok(Ok(()))) {
                break;
            }
        }
    });
    let mut reader = BufReader::new(read);
    while let Ok(Some(line)) = read_line_capped(&mut reader, MAX_HELPER_LINE).await {
        // A replaced connection is not listened to any more.
        if !hostd.helper_is(conn) {
            break;
        }
        let Ok(Value::Object(msg)) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        match msg.get("type").and_then(Value::as_str) {
            Some("presence") => hostd.helper_presence(&msg).await,
            Some("answer") => {
                if let Some(id) = msg.get("id").and_then(Value::as_str) {
                    let answer = msg
                        .get("answer")
                        .and_then(Value::as_str)
                        .unwrap_or("timeout")
                        .to_owned();
                    let id = id.to_owned();
                    let hostd = Arc::clone(&hostd);
                    // Not inline: for root this waits for a password.
                    tokio::spawn(async move { hostd.answered(&id, &answer, conn).await });
                }
            }
            _ => {}
        }
    }
    writer.abort();
    hostd.helper_detached(conn).await;
}
