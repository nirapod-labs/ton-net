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

    /// A dictionary key was longer than the dictionary holds.
    #[error("dictionary key is {given} bits, the dictionary holds {expected}")]
    KeyLength {
        /// The length of the key supplied.
        given: usize,
        /// The length the dictionary holds.
        expected: usize,
    },

    /// A dictionary label claimed more bits than the remaining key can hold.
    #[error("dictionary label is longer than the key it labels")]
    LabelTooLong,

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

    /// The proof prunes away the path to the account, so it says nothing about it.
    ///
    /// A server that returns this has not answered the question, which is different from
    /// proving the account is not there.
    #[error("the proof does not cover the account")]
    NotCovered,

    /// The account state does not match the hash the proof binds to the block.
    ///
    /// Either the state is some other account, or some other version of this one, or the
    /// server claimed an existence the proof contradicts.
    #[error("the account state does not bind to the proved block")]
    NotBound,
}
