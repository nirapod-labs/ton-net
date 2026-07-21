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
    /// Whether this side still knows where it is in the stream.
    ///
    /// The frame ciphers are a counter the two ends advance in step, so a frame that is
    /// only half moved leaves this side counting from a place the server is not, and
    /// every later frame decrypts to nothing. Nothing observable happens at the moment it
    /// goes wrong: a read that is cancelled partway takes bytes off the socket and drops
    /// them, and a cancelled future in Rust is a dropped one, so there is no error to
    /// catch and no code left to run.
    ///
    /// What can be arranged is that the flag is lowered before a frame starts moving and
    /// raised only once it has finished. An interruption anywhere in between leaves it
    /// lowered by simply not reaching the line that would raise it.
    intact: bool,
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

    /// A frame stopped partway, so this side no longer knows where the stream is.
    ///
    /// The session cannot recover: the ciphers count in step with the server and there is
    /// no way to find the place again from this end. A caller reconnects. This is what a
    /// cancelled read leaves behind, so it follows an abandoned deadline as often as it
    /// follows a real failure.
    #[error("the session lost its place in the stream")]
    Desynchronized,
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
            intact: true,
        })
    }

    /// Whether the session still knows where it is in the stream.
    ///
    /// False once a frame has stopped partway, which is permanent. A caller holding a
    /// connection across deadlines checks this to tell a session worth reusing from one
    /// that will fail every later query.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.intact
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
    /// failure, [`AdnlError::Desynchronized`] if an earlier frame stopped partway,
    /// [`AdnlError::Malformed`] if nothing that arrived decoded as an ADNL message, or
    /// [`AdnlError::NoAnswer`] if no matching answer arrives within the frame budget.
    pub async fn query(&mut self, query: &[u8]) -> Result<Vec<u8>, AdnlError> {
        let query_id: [u8; 32] = random();
        let message = serialize(adnl::Message::Query {
            query_id,
            query: query.to_vec(),
        });
        let nonce: [u8; 32] = random();
        self.send(&nonce, &message).await?;

        let mut undecodable = 0usize;
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
                // A frame that decrypted and passed its checksum but names a message this
                // crate does not model. ADNL has more message kinds than the two read
                // here, so this is a gap in what is decoded rather than a broken stream,
                // and it is skipped like any other message that is not the answer. The
                // frame was read whole, so the stream position is still known.
                Err(_) => undecodable += 1,
            }
        }
        if undecodable == MAX_FRAMES_PER_QUERY {
            return Err(AdnlError::Malformed);
        }
        Err(AdnlError::NoAnswer)
    }

    /// Seals one frame and puts it on the wire.
    async fn send(&mut self, nonce: &[u8; 32], message: &[u8]) -> Result<(), AdnlError> {
        self.check()?;
        let frame = self.ciphers.seal(nonce, message);
        // Sealing has already advanced the send keystream over the whole frame, so a
        // write that stops partway leaves the server reading the rest of one frame out of
        // the front of the next.
        self.intact = false;
        self.transport.write_all(&frame).await?;
        self.intact = true;
        Ok(())
    }

    /// Reads one frame: the length prefix, then the body, decrypted and checked.
    async fn recv(&mut self) -> Result<Vec<u8>, AdnlError> {
        self.check()?;
        // Both reads and `open_len` are inside the window. A partial read of the prefix
        // loses bytes the socket will not give back, and `open_len` moves the receive
        // keystream by four bytes that only the body read can consume.
        self.intact = false;
        let mut prefix = [0u8; 4];
        self.transport.read_exact(&mut prefix).await?;
        let len = self.ciphers.open_len(&mut prefix)?;
        let mut body = vec![0u8; len];
        self.transport.read_exact(&mut body).await?;
        let payload = self.ciphers.open_body(&mut body)?;
        self.intact = true;
        Ok(payload)
    }

    fn check(&self) -> Result<(), AdnlError> {
        if self.intact {
            Ok(())
        } else {
            Err(AdnlError::Desynchronized)
        }
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
