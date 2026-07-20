//! The transport seam and its native TCP implementation.
//!
//! The ADNL protocol logic is sans-I/O: it produces bytes to send and consumes bytes
//! received. A [`Transport`] is the one thing that moves those bytes over a real link.
//! Keeping the seam this narrow is what lets the same [`AdnlConnection`](crate::AdnlConnection)
//! run over TCP today and over a browser WebSocket in a later release without the
//! protocol code changing.

use std::future::Future;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long to wait for a TCP connection before giving up.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A bidirectional byte stream to one liteserver.
///
/// A transport moves ordered bytes and does not frame them; ADNL framing is the
/// caller's concern. The methods return `impl Future<Output = ...> + Send` rather than
/// using `async fn` so the `Send` bound is stated explicitly, which the generic
/// connection driver needs to run on a multi-threaded runtime.
pub trait Transport: Send {
    /// Writes the whole buffer to the stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the stream is closed or the write fails.
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Reads exactly enough bytes to fill the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the stream closes before the buffer is filled.
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(), TransportError>> + Send;
}

/// A transport failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The underlying socket could not connect, read, or write.
    #[error("transport i/o failed: {0}")]
    Io(#[from] std::io::Error),

    /// A connection did not establish within the timeout.
    #[error("transport connect timed out")]
    ConnectTimeout,
}

/// A [`Transport`] over a TCP socket, the native default.
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Opens a TCP connection to `addr` and disables Nagle's algorithm.
    ///
    /// `addr` is a `host:port` string. Nagle's algorithm is off so a small ADNL frame
    /// is sent at once rather than being held for coalescing, which matters for a
    /// request and response protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectTimeout`] if the connection does not establish
    /// within the timeout, or [`TransportError::Io`] if it is refused.
    pub async fn connect(addr: &str) -> Result<Self, TransportError> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::ConnectTimeout)??;
        stream.set_nodelay(true)?;
        Ok(Self { stream })
    }
}

impl Transport for TcpTransport {
    // The trait states `-> impl Future + Send`; an `async fn` in the impl satisfies it,
    // and the compiler checks the returned future is `Send`.
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(buf).await?;
        Ok(())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        self.stream.read_exact(buf).await?;
        Ok(())
    }
}
