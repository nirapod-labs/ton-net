//! ADNL stream framing: sealing and opening one frame.
//!
//! Once the handshake is done, each direction of the session is an AES-256-CTR stream
//! whose keystream runs continuously across every frame. One frame on the wire is
//!
//! ```text
//! length (u32 LE) ++ nonce (32) ++ payload ++ checksum (32)
//! ```
//!
//! where `length` counts the bytes after it, `checksum` is `sha256(nonce ++ payload)`,
//! and the whole frame is encrypted under the sending direction's keystream. The nonce
//! makes each frame's ciphertext unique, and the checksum lets the receiver reject a
//! corrupted or desynchronized one.
//!
//! [`SessionCiphers`] owns the two ciphers and advances them. Because the counter is
//! shared state, a frame must be opened in the same order it was sealed; opening out of
//! order desynchronizes the stream and every later frame fails to open.

use aes::cipher::{KeyIvInit, StreamCipher};

use crate::{sha256, Aes256Ctr};

/// The smallest a frame body can be: a 32-byte nonce and a 32-byte checksum around an
/// empty payload. A shorter length means the stream is desynchronized.
const MIN_FRAME: usize = 64;

/// The largest frame body accepted, one mebibyte. A larger length is read as a
/// desynchronized stream (a wrong handshake decrypts the length prefix to garbage)
/// rather than a real frame, and is refused before any allocation follows it.
const MAX_FRAME: usize = 1 << 20;

/// The two stream ciphers of one ADNL session.
///
/// `rx` decrypts bytes coming from the server; `tx` encrypts bytes going to it. Each is
/// a counter-mode keystream that advances with every byte it processes, so frames must
/// be sealed and opened in order. [`client_handshake`](crate::client_handshake) builds
/// this from the session parameters the client put in its handshake packet.
pub struct SessionCiphers {
    rx: Aes256Ctr,
    tx: Aes256Ctr,
}

/// A frame that could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The decrypted length prefix was outside the accepted range, so the stream is
    /// desynchronized. This is what a wrong handshake looks like on the first frame.
    #[error("implausible frame length {0}")]
    ImplausibleLength(usize),

    /// The frame body was too short to hold a nonce and a checksum.
    #[error("frame body too short")]
    BodyTooShort,

    /// The frame checksum did not match its nonce and payload, so the frame is corrupt.
    #[error("frame checksum mismatch")]
    Checksum,
}

impl SessionCiphers {
    /// Builds the client's ciphers from the 160 session parameters.
    ///
    /// `rx` takes params[0..32] as its key and params[64..80] as its iv; `tx` takes
    /// params[32..64] and params[80..96]. The server derives the mirror image from the
    /// same parameters, so the two sides' keystreams line up.
    pub(crate) fn from_params(params: &[u8; 160]) -> Self {
        Self {
            rx: Aes256Ctr::new_from_slices(&params[0..32], &params[64..80])
                .expect("32-byte key and 16-byte iv"),
            tx: Aes256Ctr::new_from_slices(&params[32..64], &params[80..96])
                .expect("32-byte key and 16-byte iv"),
        }
    }

    /// Seals one payload into a wire frame under the tx keystream.
    ///
    /// The returned bytes are `length ++ nonce ++ payload ++ checksum`, encrypted in
    /// place. The nonce is supplied by the caller so this stays a pure function; a real
    /// session draws a fresh one from a CSPRNG for every frame and never repeats it.
    pub fn seal(&mut self, nonce: &[u8; 32], payload: &[u8]) -> Vec<u8> {
        let checksum = sha256(&[nonce, payload]);
        let len = (32 + payload.len() + 32) as u32;
        let mut frame = Vec::with_capacity(4 + len as usize);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(nonce);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&checksum);
        self.tx.apply_keystream(&mut frame);
        frame
    }

    /// Decrypts the four-byte length prefix of the next frame and returns the body
    /// length to read.
    ///
    /// The prefix is decrypted in place, advancing the rx keystream by four bytes, so
    /// [`open_body`](Self::open_body) must follow with exactly that many bytes before any
    /// other frame is touched.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::ImplausibleLength`] if the decrypted length is outside the
    /// accepted range, which means the stream is desynchronized.
    pub fn open_len(&mut self, prefix: &mut [u8; 4]) -> Result<usize, FrameError> {
        self.rx.apply_keystream(prefix);
        let len = u32::from_le_bytes(*prefix) as usize;
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return Err(FrameError::ImplausibleLength(len));
        }
        Ok(len)
    }

    /// Decrypts a frame body and returns its payload.
    ///
    /// `body` must be the number of bytes [`open_len`](Self::open_len) returned. It is
    /// decrypted in place, the nonce and checksum are stripped, and the checksum is
    /// verified over the nonce and payload.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::BodyTooShort`] if the body cannot hold a nonce and a
    /// checksum, or [`FrameError::Checksum`] if the checksum does not match, meaning the
    /// frame was corrupted or the stream is desynchronized.
    pub fn open_body(&mut self, body: &mut [u8]) -> Result<Vec<u8>, FrameError> {
        if body.len() < MIN_FRAME {
            return Err(FrameError::BodyTooShort);
        }
        self.rx.apply_keystream(body);
        let end = body.len() - 32;
        let checksum = sha256(&[&body[..32], &body[32..end]]);
        if body[end..] != checksum[..] {
            return Err(FrameError::Checksum);
        }
        Ok(body[32..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> [u8; 160] {
        let mut params = [0u8; 160];
        for (i, byte) in params.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        params
    }

    // The peer's view of a session built from the same parameters: rx and tx swapped, so
    // a frame this client seals with tx opens here with rx. This is what the server does
    // with the parameters it recovers from the handshake, reproduced without a socket.
    fn peer(params: &[u8; 160]) -> SessionCiphers {
        SessionCiphers {
            rx: Aes256Ctr::new_from_slices(&params[32..64], &params[80..96]).unwrap(),
            tx: Aes256Ctr::new_from_slices(&params[0..32], &params[64..80]).unwrap(),
        }
    }

    fn open(dec: &mut SessionCiphers, frame: Vec<u8>) -> Result<Vec<u8>, FrameError> {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&frame[..4]);
        dec.open_len(&mut prefix)?;
        let mut body = frame[4..].to_vec();
        dec.open_body(&mut body)
    }

    #[test]
    fn seals_and_opens_a_payload() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let frame = client.seal(&[0x5a; 32], b"masterchain please");
        assert_eq!(open(&mut server, frame).unwrap(), b"masterchain please");
    }

    #[test]
    fn seals_and_opens_an_empty_payload() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let frame = client.seal(&[0; 32], b"");
        assert_eq!(frame.len(), 4 + MIN_FRAME);
        assert_eq!(open(&mut server, frame).unwrap(), b"");
    }

    #[test]
    fn the_keystream_advances_across_frames() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let first = client.seal(&[1; 32], b"first");
        let second = client.seal(&[2; 32], b"second");
        assert_eq!(open(&mut server, first).unwrap(), b"first");
        assert_eq!(open(&mut server, second).unwrap(), b"second");
    }

    #[test]
    fn opening_out_of_order_desyncs() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let _first = client.seal(&[1; 32], b"first");
        let second = client.seal(&[2; 32], b"second");
        // The server is still at the first frame's keystream position, so the second
        // frame cannot open there.
        assert!(open(&mut server, second).is_err());
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let mut frame = client.seal(&[9; 32], b"balance");
        frame[10] ^= 0x01; // flip a byte inside the body
        assert!(matches!(
            open(&mut server, frame),
            Err(FrameError::Checksum)
        ));
    }

    #[test]
    fn a_corrupt_length_prefix_is_rejected() {
        let params = params();
        let mut client = SessionCiphers::from_params(&params);
        let mut server = peer(&params);
        let mut frame = client.seal(&[9; 32], b"x");
        frame[3] ^= 0xff; // flip the top byte of the length into an implausible size
        assert!(matches!(
            open(&mut server, frame),
            Err(FrameError::ImplausibleLength(_))
        ));
    }

    #[test]
    fn a_different_session_cannot_open_a_frame() {
        let mut client = SessionCiphers::from_params(&params());
        // A peer from unrelated parameters, standing in for a failed handshake.
        let mut stranger = {
            let mut other = params();
            for byte in other.iter_mut() {
                *byte = !*byte;
            }
            peer(&other)
        };
        let frame = client.seal(&[3; 32], b"hello");
        assert!(open(&mut stranger, frame).is_err());
    }
}
