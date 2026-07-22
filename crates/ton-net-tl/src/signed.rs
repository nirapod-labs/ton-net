// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The messages a validator signature covers.
//!
//! A signature in a [`crate::lite::SignatureSet`] is 64 bytes and a signer id. It says
//! nothing about what was signed, so a client that wants to check one has to rebuild
//! the exact bytes the validator's key went over. There are two such forms, and a walk
//! from the block the mainnet config pins to today crosses both: mainnet changed form
//! at masterchain block 59379986.
//!
//! [`BlockId`] is the older form and signs a block's identity outright. The Simplex
//! form signs a vote instead, and is assembled from three types here:
//!
//! ```text
//! DataToSign { session_id, data = Vote::Finalize { id = CandidateId { slot, hash } } }
//! ```
//!
//! Nothing in this module hashes. `CandidateId::hash` is the SHA-256 of the candidate
//! bytes the signature set carries, computed by the caller, which keeps the digest
//! crates out of a codec crate.
//!
//! These types are written and never read: a client builds one to check a signature
//! against it. They deserialize anyway so a round-trip test can pin the layout.

use tl_proto::{TlRead, TlWrite};

/// The `ton.blockId` form: the identity of the block being signed.
///
/// This is the whole of the older signed message, 68 bytes with its constructor id.
/// The file hash is the load-bearing part. It is the one field of a block identity no
/// Merkle proof can establish, being a hash of the serialized block file rather than
/// of the cell tree, so a link's destination is believed only after its signatures
/// check and not after its header proof checks.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0xc50b6e70)]
pub struct BlockId {
    /// The block's root cell hash.
    pub root_cell_hash: [u8; 32],
    /// The block's file hash.
    pub file_hash: [u8; 32],
}

/// The `ton.blockIdApprove` form: the same two fields under a different constructor.
///
/// It shares [`BlockId`]'s scheme line and result type and differs from it in four
/// bytes, and it is not what a block proof's signatures cover. It is here as the
/// negative control that keeps that from being an assumption. A client checking a real
/// set against the wrong constructor finds every signature invalid, which looks exactly
/// like a forged set, so the two are worth telling apart in a test rather than in
/// prose.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x2dd44a49)]
pub struct BlockIdApprove {
    /// The block's root cell hash.
    pub root_cell_hash: [u8; 32],
    /// The block's file hash.
    pub file_hash: [u8; 32],
}

/// A `consensus.candidateId`: the candidate a Simplex vote names.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0xb691cd3f)]
pub struct CandidateId {
    /// The slot the candidate was proposed for.
    pub slot: i32,
    /// SHA-256 of the serialized `consensus.CandidateHashData` the signature set
    /// carries as `candidate`.
    pub hash: [u8; 32],
}

/// A `consensus.simplex.UnsignedVote`: what a validator votes on a candidate.
///
/// A block proof rests on [`Finalize`](Self::Finalize), because finalization is what
/// commits a block. [`Notarize`](Self::Notarize) is its near neighbour and serves the
/// same purpose here as [`BlockIdApprove`]: checking a real set against it finds every
/// signature invalid, so it is what shows the right one was not a lucky guess. The
/// union has a third member this client never builds.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed)]
#[non_exhaustive]
pub enum Vote {
    /// A vote on a candidate that does not commit it.
    #[tl(id = 0xcdf605a8)]
    Notarize {
        /// The candidate voted on.
        id: CandidateId,
    },
    /// A vote committing a candidate, which is what a block proof carries.
    #[tl(id = 0x40a7e105)]
    Finalize {
        /// The candidate voted on.
        id: CandidateId,
    },
}

/// A `consensus.CandidateHashData`, read only for the block the candidate is for.
///
/// This closes the gap the Simplex form opens. The older form signs a block identity
/// outright, so a valid signature is already a statement about a particular block. A
/// Simplex signature covers a vote naming a candidate by hash, which on its own says
/// nothing about which block that candidate was: a set of real signatures lifted from
/// one block and attached to a link claiming another would verify. The candidate bytes
/// travel with the set precisely so a client can read the block out of them, and a link
/// is worth nothing until that block is required to be the one the link claims.
///
/// Both constructors open with the block identity and this reads no further, so it
/// deliberately implements no writer. The bytes after the identity are covered by the
/// hash the vote signs, so reading them would add nothing to what the signature already
/// binds; which block the bytes name is the whole question, and it is answered here.
#[derive(TlRead, Debug, Clone, PartialEq, Eq)]
#[tl(boxed)]
#[non_exhaustive]
pub enum CandidateBlock {
    /// `consensus.candidateHashDataOrdinary`, a candidate carrying a block.
    #[tl(id = 0xe8f9bcdc)]
    Ordinary {
        /// The block the candidate proposes.
        block: crate::lite::BlockIdExt,
    },
    /// `consensus.candidateHashDataEmpty`, a candidate for a slot that produced no block
    /// of its own.
    ///
    /// The block named here is not a proposal. It is the tip the empty slot extends, and
    /// a validator refuses to vote for a candidate naming anything else, so a set of
    /// finalize votes over one of these is a certificate that the named block is
    /// committed. Simplex finalization is transitive: finalizing an empty slot finalizes
    /// its nearest ordinary ancestor, which is how a committed block followed by empty
    /// slots comes to be served with a signature set in this form.
    ///
    /// The two constructors therefore say the same thing about the block they name, which
    /// is why [`block`](CandidateBlock::block) unions them. Requiring `Ordinary` would
    /// tighten nothing and would stall a sync at the first block an empty slot follows.
    #[tl(id = 0x72b4d933)]
    Empty {
        /// The block the empty slot extends, and thereby finalizes.
        block: crate::lite::BlockIdExt,
    },
}

impl CandidateBlock {
    /// The block identity the candidate names, whichever form it takes.
    #[must_use]
    pub fn block(&self) -> &crate::lite::BlockIdExt {
        match self {
            Self::Ordinary { block } | Self::Empty { block } => block,
        }
    }

    /// Reads the identity out of the head of a serialized candidate.
    ///
    /// The bytes a signature set carries are a whole `consensus.CandidateHashData`, and
    /// this reads its opening. Trailing bytes are expected and are not an error, which
    /// is why this exists rather than a plain [`crate::deserialize`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::TlError::UnknownConstructor`] if the bytes are some other
    /// candidate form, or [`crate::TlError::UnexpectedEof`] if they end before the
    /// identity does.
    pub fn read_prefix(bytes: &[u8]) -> crate::TlResult<Self> {
        <Self as TlRead>::read_from(&mut &bytes[..])
    }
}

/// A `consensus.dataToSign`: the envelope every Simplex signature covers.
///
/// A vote is never signed on its own. It is placed here beside the session id and the
/// whole object is signed, so a signature raised in one consensus session cannot be
/// replayed into another. The vote travels as a TL `bytes` field, so it carries a
/// length and padding rather than sitting flush against the session id.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0xa8e33df8)]
pub struct DataToSign {
    /// The consensus session the signature belongs to.
    pub session_id: [u8; 32],
    /// The serialized [`Vote`].
    pub data: Vec<u8>,
}
