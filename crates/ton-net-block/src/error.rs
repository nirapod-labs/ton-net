// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The error type for decoding block and account structures.

/// A failure decoding a TON block or account structure from cells.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BlockError {
    /// A cell could not be read.
    #[error(transparent)]
    Cell(#[from] ton_net_cell::CellError),

    /// A structure did not begin with the constructor tag it should.
    #[error("expected {expected}, found a different constructor")]
    WrongConstructor {
        /// The structure that was expected.
        expected: &'static str,
    },

    /// A structure was laid out in a way this decoder does not accept.
    #[error("malformed {0}")]
    Malformed(&'static str),

    /// A cell that has to be a Merkle proof is some other kind of cell.
    #[error("not a merkle proof")]
    NotAMerkleProof,

    /// A Merkle proof's content does not hash to the root the proof itself claims.
    #[error("merkle proof content does not hash to the root it carries")]
    ProofInconsistent,

    /// No proof roots at the hash it was required to root at.
    ///
    /// This is what a proof for some other block, or for some other part of this block,
    /// fails as.
    #[error("no merkle proof roots at the required hash")]
    ProofNotAnchored,

    /// The proof prunes away the part of the block that was being read.
    ///
    /// A server that returns this has not answered the question, which is different from
    /// proving the answer is nothing.
    #[error("the proof does not cover what was read")]
    NotCovered,

    /// A proof chain does not connect the blocks it claims to.
    ///
    /// The server chooses the route a proof takes, so a run of links that skips a block,
    /// doubles back, leaves the masterchain, or ends somewhere other than it says is a
    /// well-formed answer that proves nothing.
    #[error("the proof chain {0}")]
    ChainBroken(&'static str),

    /// A proof chain carries a backward link, which this release does not check.
    ///
    /// A backward link exists so a client whose known block is not a key block can reach
    /// the last key block before it. An anchor that is always a key block never needs
    /// one, so rather than being read and half-checked it is refused by name.
    #[error("the proof chain has a backward link, which this release does not verify")]
    BackwardLink,

    /// A signature set is of a form this release does not know.
    #[error("a signature set of a form this release does not know")]
    UnknownSignedForm,

    /// The valid signatures on a link do not carry more than two thirds of the weight of
    /// the set that had to sign it.
    #[error("signatures carry {carried} of {total}, short of two thirds")]
    NotEnoughWeight {
        /// The weight of the valid signatures from distinct members of the set.
        carried: u64,
        /// The weight of the whole set, which is what two thirds is measured against.
        total: u64,
    },

    /// The network configuration was read from a block that carries none.
    ///
    /// Only a key block holds the configuration in its body. This is what a proof chain
    /// that tries to continue from an ordinary block fails as.
    #[error("not a key block, so it carries no configuration")]
    NotAKeyBlock,

    /// The account state does not match the hash the proof binds to the block.
    ///
    /// Either the state is some other account, or some other version of this one, or the
    /// server claimed an existence the proof contradicts.
    #[error("the account state does not bind to the proved block")]
    NotBound,
}
