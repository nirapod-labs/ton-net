// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The ADNL transport: the encrypted link to a liteserver.
//!
//! ADNL is the transport TON nodes speak. This module opens and runs a liteserver
//! session over it, split along the sans-I/O seam of NET-ADR-002:
//!
//! - The protocol core is pure. [`client_handshake`] builds the 256-byte handshake
//!   packet and derives the session ciphers, and [`SessionCiphers`] seals and opens the
//!   stream frames. These are synchronous functions over bytes, tested against fixed
//!   vectors, with no socket and no clock.
//! - I/O lives behind the [`Transport`] seam. It moves ordered bytes and nothing more;
//!   [`TcpTransport`] implements it over TCP. A browser transport is added later without
//!   touching the core.
//! - [`AdnlConnection`] is the async surface. It draws the per-session randomness from a
//!   CSPRNG, completes the handshake over a transport, and runs a query to its answer.
//!
//! [`AdnlConnection`] speaks the ADNL message layer: it wraps a query with an id and
//! matches the answer. The liteserver methods that build the query and decode the answer
//! live in [`crate::lite`].

use sha2::{Digest, Sha256};

// The handshake and the frame cipher are pure functions over bytes and build for any
// target, so neither is gated. The message layer is gated whole, and that is wider than
// what it needs: it is generic over the seam and reaches the OS at exactly one line, the
// per-session randomness at `connection.rs`. Narrowing it means a constructor that takes
// the randomness rather than drawing it, which is a surface addition rather than a move.
#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
mod connection;
mod frame;
mod handshake;
mod transport;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub use connection::{AdnlConnection, AdnlError};
pub use frame::{FrameError, SessionCiphers};
pub use handshake::{client_handshake, Handshake, HandshakeError, HandshakeSecrets};
#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub use transport::TcpTransport;
pub use transport::{Transport, TransportError};

/// AES-256 in counter mode with a 128-bit big-endian counter: the ADNL stream cipher,
/// used both to wrap the handshake parameters and to frame every session byte after.
pub(crate) type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// SHA-256 over a sequence of byte slices, hashed in order as if concatenated.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
