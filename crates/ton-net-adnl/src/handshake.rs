// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The ADNL handshake: opening an encrypted session with a liteserver.
//!
//! The client sends one 256-byte packet and, from that moment, both sides share the
//! two stream ciphers that frame the rest of the session. The packet is
//!
//! ```text
//! server_key_id (32) ++ client_pub (32) ++ checksum (32) ++ encrypted_params (160)
//! ```
//!
//! - `server_key_id` names which server key the client used, so the server can pick the
//!   matching private key: `sha256` of the server key in its TL `pub.ed25519` form.
//! - `client_pub` is an ephemeral Curve25519 public key. The shared secret is the
//!   Diffie-Hellman of it with the server key, giving a key only the two parties know.
//! - `checksum` is `sha256` of the 160 session parameters, in the clear.
//! - `encrypted_params` is those 160 parameters under a cipher keyed by the shared
//!   secret and the checksum, so only the real server can recover them.
//!
//! The parameters seed the session ciphers ([`SessionCiphers`]). This construction is
//! the one the feasibility spike completed against mainnet; the layout is fixed by the
//! reference node, not chosen here.

use aes::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use sha2::{Digest, Sha512};
use ton_net_tl::{adnl::PublicKey, serialize};

use crate::frame::SessionCiphers;
use crate::{sha256, Aes256Ctr};

/// The fresh randomness one handshake consumes.
///
/// A handshake needs 192 bytes of it: a 32-byte seed for the ephemeral key and 160
/// bytes of session parameters. This type carries them in so [`client_handshake`] stays
/// a pure function; the connection driver fills it from a CSPRNG at the I/O edge. The
/// same bytes must never be reused across two handshakes.
pub struct HandshakeSecrets {
    /// The seed for the ephemeral Curve25519 key. Its Diffie-Hellman scalar is
    /// `sha512(key_seed)[..32]`.
    pub key_seed: [u8; 32],
    /// The 160 session parameters that seed the two session stream ciphers. They travel
    /// encrypted in the packet and never appear on the wire in the clear.
    pub params: [u8; 160],
}

/// A built handshake: the packet to send and the ciphers to keep.
pub struct Handshake {
    /// The 256-byte packet to write to the liteserver, exactly as constructed.
    pub packet: [u8; 256],
    /// The session ciphers to frame traffic with once the packet is sent.
    pub ciphers: SessionCiphers,
}

/// A handshake that could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The server public key does not decode to a valid Ed25519 point, so no shared
    /// secret can be derived from it.
    #[error("server public key is not a valid ed25519 point")]
    InvalidServerKey,

    /// The key exchange produced the all-zero secret, which is no secret at all.
    ///
    /// A key of small order decodes as a point and multiplies to zero, so it passes
    /// [`InvalidServerKey`](Self::InvalidServerKey) and then collapses the session onto
    /// values the packet carries in the clear. Distinct from an unreadable key because
    /// the cause is different: this key is well formed and chosen to be useless.
    #[error("the key exchange produced no shared secret")]
    DegenerateSharedSecret,
}

/// Builds a client handshake for one liteserver.
///
/// `server_key` is the server's 32-byte Ed25519 public key, as published in the network
/// config. `secrets` is the fresh per-handshake randomness. On success the returned
/// [`Handshake`] carries the 256-byte packet to send and the [`SessionCiphers`] to frame
/// the session that follows.
///
/// # Errors
///
/// Returns [`HandshakeError::InvalidServerKey`] if `server_key` is not a valid Ed25519
/// point, which no honest network config should contain.
pub fn client_handshake(
    server_key: &[u8; 32],
    secrets: &HandshakeSecrets,
) -> Result<Handshake, HandshakeError> {
    // The server key id is sha256 of the key in its TL pub.ed25519 form, which is the
    // constructor id (little-endian) followed by the 32 key bytes. ton-net-tl owns that
    // id, so it is not repeated here.
    let server_key_id = sha256(&[&serialize(PublicKey { key: *server_key })]);

    // Ephemeral client key. The Diffie-Hellman scalar is sha512(seed)[..32]. Both
    // mul_base_clamped (for the public key) and mul_clamped (for the shared secret)
    // apply the RFC 7748 clamp, so the key sent and the secret derived share one scalar.
    let scalar = {
        let full = Sha512::digest(secrets.key_seed);
        let mut scalar = [0u8; 32];
        #[expect(
            clippy::indexing_slicing,
            reason = "the first half of a 64-byte digest"
        )]
        scalar.copy_from_slice(&full[..32]);
        scalar
    };
    let client_pub = EdwardsPoint::mul_base_clamped(scalar).compress().to_bytes();

    let server_point = CompressedEdwardsY(*server_key)
        .decompress()
        .ok_or(HandshakeError::InvalidServerKey)?;
    let shared = server_point.to_montgomery().mul_clamped(scalar).to_bytes();
    // RFC 7748 section 6.1: abort on the all-zero output. Decoding as a point is not
    // enough, because the clamp forces the scalar to a multiple of the cofactor and every
    // small-order key then multiplies to zero. The key below is built from `shared` and
    // `checksum`, and `checksum` travels in the clear, so a zero secret would hand the
    // whole session to anyone watching the packet go past.
    if shared == [0u8; 32] {
        return Err(HandshakeError::DegenerateSharedSecret);
    }

    let checksum = sha256(&[&secrets.params]);

    // The handshake cipher wraps the 160 parameters: key = shared[..16] ++ checksum[16..],
    // iv = checksum[..4] ++ shared[20..]. Only a party holding the shared secret can
    // recover the parameters, and so the session ciphers.
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&shared[..16]);
    key[16..].copy_from_slice(&checksum[16..]);
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&checksum[..4]);
    iv[4..].copy_from_slice(&shared[20..]);

    // Taking the key and iv as arrays rather than slices settles their lengths in the
    // type, so the constructor has nothing left to check and cannot fail.
    let mut encrypted = secrets.params;
    Aes256Ctr::new((&key).into(), (&iv).into()).apply_keystream(&mut encrypted);

    let mut packet = [0u8; 256];
    packet[..32].copy_from_slice(&server_key_id);
    packet[32..64].copy_from_slice(&client_pub);
    packet[64..96].copy_from_slice(&checksum);
    packet[96..].copy_from_slice(&encrypted);

    Ok(Handshake {
        packet,
        ciphers: SessionCiphers::from_params(&secrets.params),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    // A real mainnet liteserver key from the feasibility spike, so the Diffie-Hellman
    // runs against a genuine Ed25519 point rather than a contrived one.
    fn server_key() -> [u8; 32] {
        unhex32("9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309")
    }

    fn secrets() -> HandshakeSecrets {
        let mut params = [0u8; 160];
        for (i, byte) in params.iter_mut().enumerate() {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "params is a fixed [u8; 160], so enumerate() bounds i to 0..160, well within u8::MAX"
            )]
            {
                *byte = (i as u8).wrapping_mul(3).wrapping_add(5);
            }
        }
        HandshakeSecrets {
            key_seed: [0x11; 32],
            params,
        }
    }

    fn scalar_of(seed: [u8; 32]) -> [u8; 32] {
        let full = Sha512::digest(seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&full[..32]);
        scalar
    }

    #[test]
    fn packet_has_the_documented_layout() {
        let hs = client_handshake(&server_key(), &secrets()).unwrap();

        // server key id: sha256 of the TL-encoded pub.ed25519.
        let id = sha256(&[&serialize(PublicKey { key: server_key() })]);
        assert_eq!(&hs.packet[..32], &id);

        // client public key: the ephemeral key from the seed.
        let client_pub = EdwardsPoint::mul_base_clamped(scalar_of([0x11; 32]))
            .compress()
            .to_bytes();
        assert_eq!(&hs.packet[32..64], &client_pub);

        // checksum region: sha256(params), carried in the clear.
        assert_eq!(&hs.packet[64..96], &sha256(&[&secrets().params]));
    }

    #[test]
    fn encrypted_params_decrypt_back_to_params() {
        let secrets = secrets();
        let hs = client_handshake(&server_key(), &secrets).unwrap();

        // Reconstruct the handshake key and iv from the shared secret, then decrypt the
        // packet tail. It must recover the original parameters, which proves the tail is
        // the parameters under the documented cipher and nothing else.
        let server_point = CompressedEdwardsY(server_key()).decompress().unwrap();
        let shared = server_point
            .to_montgomery()
            .mul_clamped(scalar_of(secrets.key_seed))
            .to_bytes();
        let checksum = sha256(&[&secrets.params]);

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&shared[..16]);
        key[16..].copy_from_slice(&checksum[16..]);
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&checksum[..4]);
        iv[4..].copy_from_slice(&shared[20..]);

        let mut decrypted = [0u8; 160];
        decrypted.copy_from_slice(&hs.packet[96..]);
        Aes256Ctr::new_from_slices(&key, &iv)
            .unwrap()
            .apply_keystream(&mut decrypted);
        assert_eq!(decrypted, secrets.params);
    }

    #[test]
    fn the_same_inputs_build_the_same_packet() {
        let a = client_handshake(&server_key(), &secrets()).unwrap();
        let b = client_handshake(&server_key(), &secrets()).unwrap();
        assert_eq!(a.packet, b.packet);
    }

    #[test]
    fn a_non_point_server_key_is_rejected() {
        // The y-coordinate 2 has no matching x on the Ed25519 curve, so this key does
        // not decode to a point and no shared secret can be derived from it.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert!(matches!(
            client_handshake(&bad, &secrets()),
            Err(HandshakeError::InvalidServerKey)
        ));
    }

    #[test]
    fn a_small_order_server_key_is_rejected() {
        // These decode to points, so the check above passes them, and then every one
        // multiplies to zero because the clamp makes the scalar a multiple of the
        // cofactor. A zero secret leaves the handshake key as sixteen zero bytes followed
        // by half of a checksum the packet carries in the clear, which is a session
        // anyone watching can read and write. RFC 7748 section 6.1 says to abort.
        let low_order = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];
        for key in low_order {
            let key = unhex32(key);
            assert!(
                matches!(
                    client_handshake(&key, &secrets()),
                    Err(HandshakeError::DegenerateSharedSecret | HandshakeError::InvalidServerKey)
                ),
                "a key of small order was accepted: {key:02x?}"
            );
        }

        // The real key still works, so the check costs nothing an honest config pays.
        assert!(client_handshake(&server_key(), &secrets()).is_ok());
    }
}
