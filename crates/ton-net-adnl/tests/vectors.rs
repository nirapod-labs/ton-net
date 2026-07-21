// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Fixed public-API vectors for the ADNL handshake and framing.
//!
//! These pin the exact bytes the public functions produce for fixed inputs, so any
//! change to the construction is caught here. The construction itself is the one the
//! feasibility spike completed against a mainnet liteserver; these vectors anchor the
//! byte layout that server accepted. The deeper checks (that the key id is the TL form
//! of the key, that the encrypted tail decrypts back to the parameters, that a tampered
//! frame is rejected) live in the crate's unit tests.

use ton_net_adnl::{client_handshake, HandshakeSecrets};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// A real mainnet liteserver Ed25519 key, from the feasibility spike.
const SERVER_KEY: &str = "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309";

fn secrets() -> HandshakeSecrets {
    let mut params = [0u8; 160];
    for (i, byte) in params.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(3).wrapping_add(5);
    }
    HandshakeSecrets {
        key_seed: [0x11; 32],
        params,
    }
}

#[test]
fn handshake_packet_matches_the_pinned_vector() {
    let hs = client_handshake(&unhex32(SERVER_KEY), &secrets()).unwrap();
    assert_eq!(
        hex(&hs.packet),
        "5b281b7d9c4559afe95175a529ffd1b6bfb818fb73cf4ac47d7d500d8a25f9dc\
         d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737\
         85afab363ab509cd0ef3eaf2c68a0087b2469aeadf927ba4378c1e6f372923a0\
         08439a231a8ea4ff01e166f8f2f862e0eb984d63b468a261f415ff7167efa9d6\
         08b0cd8bcd466954506df085143e02e4f7a14967eda504a8eec41d8c0cb5dac4\
         e6a888cecbd76f6c7d2006540cba62aad120191af27378b1317a3e06c42498ea\
         27d2b44f1041407406da6c73738af0958ec1d4b70710cd7d414824b07d30ba64\
         7717b3c729e3e9a31b7d51c4069ebea9f12db7c980535cdbfc664251ac6c6ea9"
    );
}

#[test]
fn a_sealed_frame_matches_the_pinned_vector() {
    let hs = client_handshake(&unhex32(SERVER_KEY), &secrets()).unwrap();
    let mut ciphers = hs.ciphers;
    let frame = ciphers.seal(&[0x22; 32], b"getMasterchainInfo");

    // length prefix (4) + nonce (32) + payload (18) + checksum (32).
    assert_eq!(frame.len(), 4 + 32 + 18 + 32);
    assert_eq!(
        hex(&frame),
        "1226b10422a78cec84bb185099587ad191f680319c0d4ac7c84041a9344ca708\
         944fd72c06279304de013d4e31638ced02f51083bb8e1553ee3fd91eedaee9cb\
         de5eb5b85168861aeda9114ae1fc6aa4984e556c3e6c"
    );
}
