//! ADNL transport for ton-net: the encrypted link to a liteserver.
//!
//! ADNL is the transport TON nodes speak. Over TCP a client opens a session with a
//! liteserver in two parts, both built here as pure functions over bytes with no
//! socket in sight:
//!
//! - [`client_handshake`] builds the 256-byte handshake packet and derives the two
//!   session stream ciphers from fresh client randomness and the server's public key.
//! - [`SessionCiphers`] frames the traffic that follows: [`SessionCiphers::seal`]
//!   encrypts one payload into a wire frame, and [`SessionCiphers::open_len`] with
//!   [`SessionCiphers::open_body`] decrypt and check one coming back.
//!
//! Keeping this layer sans-I/O follows NET-ADR-001: the protocol math is synchronous
//! and testable against fixed vectors, and the socket lives behind a transport seam
//! added in a later step. The connection driver that reads and writes the frames these
//! functions produce arrives with that transport. The randomness a real session needs
//! is drawn from a CSPRNG at that edge and passed in, so nothing here reaches for the
//! operating system.
//!
//! This is an internal crate of the ton-net client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use sha2::{Digest, Sha256};

pub mod frame;
pub mod handshake;

pub use frame::{FrameError, SessionCiphers};
pub use handshake::{client_handshake, Handshake, HandshakeError, HandshakeSecrets};

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
