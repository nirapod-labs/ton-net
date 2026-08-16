// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The transport seam.
//!
//! The ADNL protocol logic is sans-I/O: it produces bytes to send and consumes bytes
//! received. A [`Transport`] is the one thing that moves those bytes over a real link.
//! Keeping the seam this narrow is what lets the same [`AdnlConnection`](crate::adnl::AdnlConnection)
//! run over TCP today and over a browser WebSocket in a later release without the
//! protocol code changing.
//!
//! The seam is also where the `net` feature cuts. The trait and its error are pure and
//! build for any target; [`TcpTransport`] is the socket and is the part that is gated.

use std::future::Future;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
mod tcp;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub use tcp::TcpTransport;

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
