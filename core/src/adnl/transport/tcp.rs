// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The native TCP transport.
//!
//! The socket is the only part of the link that needs a runtime, so it is the only part
//! behind the `net` feature. Everything the seam above it carries, the [`Transport`]
//! trait and the ADNL protocol core, builds for a target with no sockets at all.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{Transport, TransportError};

/// How long to wait for a TCP connection before giving up.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
