//! A TCP stream, with TLS (the shared rustls config) or without (loopback
//! http only).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::url::BrokerUrl;

#[derive(Debug)]
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// Connect to the broker's host and port, with TLS for https.
pub(crate) async fn connect(
    url: &BrokerUrl,
    tls: &Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> io::Result<Stream> {
    let host = url.host();
    let fut = async {
        let tcp = TcpStream::connect((host.as_str(), url.port())).await?;
        tcp.set_nodelay(true)?;
        if !url.is_tls() {
            return Ok(Stream::Plain(tcp));
        }
        let name = ServerName::try_from(host.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tls = TlsConnector::from(Arc::clone(tls))
            .connect(name, tcp)
            .await?;
        Ok(Stream::Tls(Box::new(tls)))
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "connecting to the broker timed out",
        )
    })?
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
