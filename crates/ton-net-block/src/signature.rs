//! Ed25519 verification, and the two messages a TON validator signature covers.
//!
//! # The acceptance rule
//!
//! The target is not the strictest rule available but **the rule the network itself
//! uses**, which is libsodium's `crypto_sign_verify_detached`: canonical `A`, `R` and
//! `S`, neither `A` nor `R` of small order, and the equation compared without cofactor
//! slack. This client aims to accept exactly that set, no more and no less.
//!
//! Stricter is not safer here, which is the part that surprises. Ed25519 verifiers
//! famously disagree on edge cases, and the tempting position is that refusing more can
//! only be cautious, since a stricter rule never wrongly accepts. The thinnest link on
//! the real chain from the block the mainnet config pins to today carries 66.6712% of
//! its set's weight against a two-thirds threshold: **0.0046 percentage points of
//! headroom**, about a two-hundredth of one validator. Refusing a single signature the
//! validators accepted drops that link below the threshold and the sync stops. Being
//! stricter than the network is a way to stall, not a free margin.
//!
//! Nothing here is secret, so nothing here needs to be constant time. Verification runs
//! on a public key, a public message and a public signature, which is why the
//! variable-time double-scalar multiplication is the right primitive rather than a
//! shortcut.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;
use sha2::{Digest, Sha256, Sha512};
use ton_net_tl::{serialize, signed};

/// The message the older signed form covers: the identity of the block being committed.
///
/// The file hash is the load-bearing part. It is the one field of a block identity no
/// Merkle proof can establish, being a hash of the serialized block file rather than of
/// the cell tree, so a link's destination is believed only after its signatures check
/// and not after its header proof checks.
#[must_use]
pub fn block_id_message(root_hash: &[u8; 32], file_hash: &[u8; 32]) -> Vec<u8> {
    serialize(signed::BlockId {
        root_cell_hash: *root_hash,
        file_hash: *file_hash,
    })
}

/// The message a Simplex signature covers, built from what the signature set carries.
///
/// The vote is never signed on its own: it travels inside a `consensus.dataToSign`
/// beside the session id, so a signature raised in one consensus session cannot be
/// replayed into another. The candidate is hashed whole and never decoded here; which
/// block it names is a separate question, answered by
/// [`ton_net_tl::signed::CandidateBlock`].
#[must_use]
pub fn simplex_message(session_id: &[u8; 32], slot: i32, candidate: &[u8]) -> Vec<u8> {
    let hash: [u8; 32] = Sha256::digest(candidate).into();
    serialize(signed::DataToSign {
        session_id: *session_id,
        data: serialize(signed::Vote::Finalize {
            id: signed::CandidateId { slot, hash },
        }),
    })
}

/// Decompresses a point and requires the encoding to have been canonical.
///
/// Decompression accepts a y-coordinate above the field prime, which is a second
/// encoding of the same point. Re-compressing and comparing rejects that, which is what
/// keeps a signature from having more than one valid form.
fn canonical_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().as_bytes() == bytes).then_some(point)
}

/// Verifies an ed25519 signature over `message`.
///
/// Returns `false` rather than an error. A signature that does not check is an ordinary
/// outcome here: a signature set is a vote, and some of it may be junk from a validator
/// of another round.
#[must_use]
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
    // from_canonical_bytes is what enforces s < L, the check that stops a signature from
    // being malleable into a second valid form.
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
