// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Ed25519 verification and the weight rule, on the crates already in the tree.
//!
//! NET-ADR-003 keeps one copy of each crypto crate and rejects `ed25519-dalek` as a
//! dependency. Both current versions would break that rule, one by duplicating the
//! curve and one by duplicating the whole digest generation, so this builds the
//! verification equation on `curve25519-dalek` and `sha2`, which are already here.
//! Proving that works is part of what the spike is for.
//!
//! The target is not "as strict as possible" but "the rule the network itself uses",
//! which is libsodium's `crypto_sign_verify_detached`: canonical `A`, `R` and `S`,
//! neither `A` nor `R` of small order, and the uncofactored equation. Matching it
//! exactly is what keeps this client from disagreeing with the validators in either
//! direction, and the margins measured on mainnet are thin enough that being stricter
//! than the network is a real way to stall rather than a free safety margin.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;
use sha2::{Digest, Sha256, Sha512};

/// `ton.blockId root_cell_hash:int256 file_hash:int256`
pub const TON_BLOCK_ID: u32 = 0xc50b_6e70;
/// `ton.blockIdApprove root_cell_hash:int256 file_hash:int256`
pub const TON_BLOCK_ID_APPROVE: u32 = 0x2dd4_4a49;

/// `consensus.candidateId slot:int hash:int256`
pub const CANDIDATE_ID: u32 = 0xb691_cd3f;
/// `consensus.simplex.notarizeVote id:consensus.CandidateId`
pub const NOTARIZE_VOTE: u32 = 0xcdf6_05a8;
/// `consensus.simplex.finalizeVote id:consensus.CandidateId`
pub const FINALIZE_VOTE: u32 = 0x40a7_e105;

/// The 68 bytes an ordinary validator signature covers: a constructor id, then the
/// block's two hashes.
pub fn signed_message(constructor: u32, root_hash: &[u8; 32], file_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&constructor.to_le_bytes());
    out.extend_from_slice(root_hash);
    out.extend_from_slice(file_hash);
    out
}

/// `consensus.dataToSign session_id:int256 data:bytes`
pub const DATA_TO_SIGN: u32 = 0xa8e3_3df8;

/// Wraps bytes in the envelope every Simplex signature covers.
///
/// A vote is never signed on its own. It is placed in a `consensus.dataToSign`
/// alongside the session id, so a signature from one consensus session cannot be
/// replayed into another, and that whole object is what the key signs. The inner
/// bytes are a TL `bytes` field, so they carry a length and padding rather than
/// sitting flush against the session id.
pub fn data_to_sign(session_id: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 4 + data.len() + 3);
    out.extend_from_slice(&DATA_TO_SIGN.to_le_bytes());
    out.extend_from_slice(session_id);
    write_tl_bytes(&mut out, data);
    out
}

/// Writes a TL `bytes` field: a length, the data, then padding to four.
fn write_tl_bytes(out: &mut Vec<u8>, data: &[u8]) {
    let header = if data.len() < 254 {
        out.push(data.len() as u8);
        1
    } else {
        out.push(254);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()[..3]);
        4
    };
    out.extend_from_slice(data);
    out.resize(out.len() + (4 - (header + data.len()) % 4) % 4, 0);
}

/// The vote a Simplex signature covers, before it is wrapped for signing.
///
/// A vote names a candidate by slot and by the hash of its serialized hash-data,
/// which is why a signature set ships that data as bytes: the client hashes it rather
/// than needing to understand it. The vote and the candidate id are both boxed, so
/// each carries its constructor id.
pub fn simplex_vote(vote: u32, slot: i32, candidate: &[u8]) -> Vec<u8> {
    let hash: [u8; 32] = Sha256::digest(candidate).into();
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&vote.to_le_bytes());
    out.extend_from_slice(&CANDIDATE_ID.to_le_bytes());
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&hash);
    out
}

/// Decompresses a point and requires the encoding to have been canonical.
///
/// `decompress` accepts a y-coordinate above the field prime, which is a second
/// encoding of the same point. Re-compressing and comparing rejects that, which is
/// what keeps a signature from having more than one valid form.
fn canonical_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().as_bytes() == bytes).then_some(point)
}

/// Verifies an ed25519 signature over `message`.
///
/// Returns false rather than an error: a signature that does not check is an ordinary
/// outcome here, since a set is a vote and some of it may be junk.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("32 bytes");

    let Some(a) = canonical_point(public_key) else {
        return false;
    };
    // A small-order key verifies against many messages, so it is refused outright.
    if a.is_small_order() {
        return false;
    }
    let Some(r) = canonical_point(&r_bytes) else {
        return false;
    };
    // libsodium refuses a small-order R as well, so refusing it here keeps this client
    // from counting a signature the validators' own software would not.
    if r.is_small_order() {
        return false;
    }
    // from_canonical_bytes is what enforces s < L, the check that stops a signature
    // from being malleable into a second valid form.
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };

    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // k * (-A) + s * B, which equals R exactly when the signature is valid.
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a), &s) == r
}

/// What checking one signature set against one validator set produced.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tally {
    /// Weight from distinct validators in the set whose signature verified.
    pub weight: u64,
    /// How many signatures verified.
    pub valid: usize,
    /// Signatures whose signer is not in this set.
    pub unknown_signer: usize,
    /// Signatures from a signer already counted.
    pub duplicate: usize,
    /// Signatures from a known signer that did not verify.
    pub invalid: usize,
}

impl Tally {
    /// Whether the tallied weight carries the block: strictly more than two thirds.
    ///
    /// Integer arithmetic on purpose, so a set landing exactly on two thirds is
    /// refused rather than rounded into acceptance.
    pub fn carries(&self, total_weight: u64) -> bool {
        (self.weight as u128) * 3 > (total_weight as u128) * 2
    }

    pub fn share(&self, total_weight: u64) -> f64 {
        self.weight as f64 / (total_weight as f64).max(1.0)
    }
}
