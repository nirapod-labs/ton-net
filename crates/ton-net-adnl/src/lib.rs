//! ADNL transport for ton-net: the encrypted link to a liteserver.
//!
//! ADNL is the transport TON nodes speak. This crate opens and runs a liteserver
//! session over it, split along the sans-I/O seam of NET-ADR-001:
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
//! live in ton-net-lite.
//!
//! This is an internal crate of the ton-net client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use sha2::{Digest, Sha256};

pub mod connection;
pub mod frame;
pub mod handshake;
pub mod transport;

pub use connection::{AdnlConnection, AdnlError};
pub use frame::{FrameError, SessionCiphers};
pub use handshake::{client_handshake, Handshake, HandshakeError, HandshakeSecrets};
pub use transport::{TcpTransport, Transport, TransportError};

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
