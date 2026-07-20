//! The async connection driver: a liteserver session over a transport.
//!
//! [`AdnlConnection`] is the one async object in this crate. It draws the per-session
//! randomness from the operating system, drives the sans-I/O handshake and framing over
//! a [`Transport`], and runs the ADNL message layer: it wraps a query with a fresh id,
//! sends it, and reads frames until the answer to that id comes back. The liteserver
//! methods that build the query bytes and decode the answer live in ton-net-lite.

use ton_net_tl::{adnl, deserialize, serialize};

use crate::frame::FrameError;
use crate::frame::SessionCiphers;
use crate::handshake::{client_handshake, HandshakeError, HandshakeSecrets};
use crate::transport::{Transport, TransportError};

/// The most frames to read while waiting for one answer before giving up.
///
/// A liteserver usually sends at most an empty confirmation frame and then the answer,
/// so a small bound catches a server that streams unrelated frames without letting the
/// read loop run forever.
const MAX_FRAMES_PER_QUERY: usize = 8;

/// An open ADNL session with one liteserver.
///
/// Built by [`connect`](Self::connect), then queried with [`query`](Self::query). It
/// owns the transport and the session ciphers; it is not `Clone`, because the ciphers
/// are a moving stream position that only one caller may advance.
pub struct AdnlConnection<T> {
    transport: T,
    ciphers: SessionCiphers,
}

/// A failure opening or running an ADNL session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdnlError {
    /// The transport could not move the bytes.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// The handshake could not be built, which means the server key is not a point.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),

    /// A received frame did not decrypt or check out.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// A frame decrypted but did not decode as an ADNL message.
    #[error("server sent a malformed adnl message")]
    Malformed,

    /// No answer to the query arrived within the frame budget.
    #[error("no answer to the query")]
    NoAnswer,
}

impl<T: Transport> AdnlConnection<T> {
    /// Completes the ADNL handshake over `transport` and returns the open session.
    ///
    /// `server_key` is the liteserver's Ed25519 public key. The per-session randomness
    /// is drawn from the operating system here, at the I/O edge, and handed to the
    /// sans-I/O handshake. Only the 256-byte handshake packet is sent; the server does
    /// not answer it, so the first bytes back come after the first [`query`](Self::query).
    ///
    /// # Errors
    ///
    /// Returns [`AdnlError::Handshake`] if `server_key` is not a valid point, or
    /// [`AdnlError::Transport`] if the packet cannot be sent.
    pub async fn connect(mut transport: T, server_key: &[u8; 32]) -> Result<Self, AdnlError> {
        let secrets = HandshakeSecrets {
            key_seed: random(),
            params: random(),
        };
        let handshake = client_handshake(server_key, &secrets)?;
        transport.write_all(&handshake.packet).await?;
        Ok(Self {
            transport,
            ciphers: handshake.ciphers,
        })
    }

    /// Runs one query and returns the answer bytes.
    ///
    /// `query` is the payload to carry, the liteserver query bytes ton-net-lite builds.
    /// It is wrapped in an `adnl.message.query` with a fresh random id, sealed into a
    /// frame, and sent; frames are then read until an `adnl.message.answer` echoes that
    /// id, and its answer bytes are returned. An empty confirmation frame is skipped.
    ///
    /// # Errors
    ///
    /// Returns [`AdnlError::Transport`] or [`AdnlError::Frame`] on an I/O or framing
    /// failure, [`AdnlError::Malformed`] if a frame is not an ADNL message, or
    /// [`AdnlError::NoAnswer`] if no matching answer arrives within the frame budget.
    pub async fn query(&mut self, query: &[u8]) -> Result<Vec<u8>, AdnlError> {
        let query_id: [u8; 32] = random();
        let message = serialize(adnl::Message::Query {
            query_id,
            query: query.to_vec(),
        });
        let nonce: [u8; 32] = random();
        let frame = self.ciphers.seal(&nonce, &message);
        self.transport.write_all(&frame).await?;

        for _ in 0..MAX_FRAMES_PER_QUERY {
            let payload = self.recv().await?;
            if payload.is_empty() {
                continue; // an ADNL confirmation frame carries no message
            }
            match deserialize::<adnl::Message>(&payload) {
                Ok(adnl::Message::Answer {
                    query_id: answered,
                    answer,
                }) if answered == query_id => return Ok(answer),
                Ok(_) => continue, // some other message; keep waiting for this answer
                Err(_) => return Err(AdnlError::Malformed),
            }
        }
        Err(AdnlError::NoAnswer)
    }

    /// Reads one frame: the length prefix, then the body, decrypted and checked.
    async fn recv(&mut self) -> Result<Vec<u8>, AdnlError> {
        let mut prefix = [0u8; 4];
        self.transport.read_exact(&mut prefix).await?;
        let len = self.ciphers.open_len(&mut prefix)?;
        let mut body = vec![0u8; len];
        self.transport.read_exact(&mut body).await?;
        Ok(self.ciphers.open_body(&mut body)?)
    }
}

/// Fills an array with operating-system randomness.
///
/// This is the crate's only draw from the OS, kept at the I/O edge so the protocol core
/// stays a pure function of its inputs.
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("operating system rng");
    bytes
}
