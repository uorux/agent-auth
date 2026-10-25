//! Connections for IMAP and SMTP: TLS through the caller's rustls config
//! (the broker's shared one), never plaintext, and a buffered reader with
//! limits on what one line or literal may hold.

use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// What can go wrong talking to a mail server. The texts are short and
/// carry nothing the server said (that goes to the log): they may reach an
/// agent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnError {
    #[error("unreachable")]
    Connect,
    #[error("TLS handshake failed")]
    Tls,
    #[error("timed out")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("the server's answer was malformed")]
    Malformed,
    #[error("the server's answer was too large")]
    TooLarge,
    #[error("{0}")]
    Refused(String),
}

/// How long one read or write may take (the Python's socket timeout).
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// TCP to `host:port`, then TLS for `host`.
pub async fn connect_tls(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
) -> Result<TlsStream<TcpStream>, ConnError> {
    let tcp = tcp(host, port).await?;
    upgrade(tls, host, tcp).await
}

/// A plain TCP connection (for SMTP STARTTLS, which upgrades it before
/// anything secret is sent).
pub async fn tcp(host: &str, port: u16) -> Result<TcpStream, ConnError> {
    match tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            tracing::warn!(host, port, error = %e, "mail: connect failed");
            Err(ConnError::Connect)
        }
        Err(_) => Err(ConnError::Timeout),
    }
}

/// TLS over an established stream, verified for `host`.
pub async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    stream: S,
) -> Result<TlsStream<S>, ConnError> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| ConnError::Connect)?;
    let connector = TlsConnector::from(Arc::clone(tls));
    match tokio::time::timeout(IO_TIMEOUT, connector.connect(name, stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            tracing::warn!(host, error = %e, "mail: TLS handshake failed");
            Err(ConnError::Tls)
        }
        Err(_) => Err(ConnError::Timeout),
    }
}

/// A buffered line reader over a stream, with bounds.
#[derive(Debug)]
pub struct Lines<S> {
    stream: S,
    buf: Vec<u8>,
    start: usize,
    /// Longest line accepted (without its CRLF).
    pub max_line: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Lines<S> {
    pub fn new(stream: S, max_line: usize) -> Lines<S> {
        Lines {
            stream,
            buf: Vec::new(),
            start: 0,
            max_line,
        }
    }

    /// The stream, with nothing buffered (for a TLS upgrade). Data the
    /// server sent ahead is an error: nothing may be injected before TLS.
    pub fn into_inner(self) -> Result<S, ConnError> {
        if self.start < self.buf.len() {
            return Err(ConnError::Malformed);
        }
        Ok(self.stream)
    }

    async fn fill(&mut self) -> Result<(), ConnError> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = [0u8; 16 * 1024];
        let n = match tokio::time::timeout(IO_TIMEOUT, self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Err(ConnError::Closed),
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(ConnError::Closed),
            Err(_) => return Err(ConnError::Timeout),
        };
        self.buf
            .extend_from_slice(chunk.get(..n).ok_or(ConnError::Malformed)?);
        Ok(())
    }

    /// One line, without its CRLF (a bare LF ends a line too).
    pub async fn line(&mut self) -> Result<Vec<u8>, ConnError> {
        let mut searched = 0usize;
        loop {
            let pending = self.buf.get(self.start..).unwrap_or(&[]);
            if let Some(pos) = pending
                .get(searched..)
                .and_then(|r| r.iter().position(|b| *b == b'\n'))
            {
                let end = searched.saturating_add(pos);
                let mut line = pending.get(..end).unwrap_or(&[]).to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.start = self.start.saturating_add(end).saturating_add(1);
                return Ok(line);
            }
            searched = pending.len();
            if searched > self.max_line {
                return Err(ConnError::TooLarge);
            }
            self.fill().await?;
        }
    }

    /// Exactly `n` bytes, keeping at most `keep` of them (the rest is
    /// read and dropped).
    pub async fn bytes(&mut self, n: usize, keep: usize) -> Result<Vec<u8>, ConnError> {
        let mut out = Vec::with_capacity(n.min(keep).min(1024 * 1024));
        let mut left = n;
        while left > 0 {
            if self.start >= self.buf.len() {
                self.fill().await?;
            }
            let avail = self.buf.len().saturating_sub(self.start);
            let take = avail.min(left);
            let end = self.start.saturating_add(take);
            let room = keep.saturating_sub(out.len()).min(take);
            if let Some(chunk) = self.buf.get(self.start..self.start.saturating_add(room)) {
                out.extend_from_slice(chunk);
            }
            self.start = end;
            left = left.saturating_sub(take);
        }
        Ok(out)
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), ConnError> {
        match tokio::time::timeout(IO_TIMEOUT, async {
            self.stream.write_all(data).await?;
            self.stream.flush().await
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(ConnError::Closed),
            Err(_) => Err(ConnError::Timeout),
        }
    }

    /// Close the write side (best effort).
    pub async fn shutdown(&mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.stream.shutdown()).await;
    }
}
