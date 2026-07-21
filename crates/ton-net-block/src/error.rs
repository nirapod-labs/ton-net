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
}
