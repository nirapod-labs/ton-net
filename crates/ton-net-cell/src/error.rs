// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The error type for cell and bag-of-cells operations.

/// A failure parsing a bag of cells or reading a cell.
///
/// Every parse and read returns this rather than panicking: a bag of cells arrives from
/// a liteserver, which is not trusted, so hostile bytes must end in an error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CellError {
    /// The bytes do not begin with the bag-of-cells magic.
    #[error("not a bag of cells")]
    NotABagOfCells,

    /// The bytes ended before a declared field or cell was complete.
    #[error("bag of cells is truncated")]
    Truncated,

    /// A header field held a value outside its allowed range.
    #[error("bag of cells header is invalid: {0}")]
    Header(&'static str),

    /// The bag carried a checksum that its bytes do not match.
    #[error("bag of cells checksum does not match")]
    Checksum,

    /// A cell referenced a cell that does not exist, or that does not come after it.
    ///
    /// References point strictly forward in a bag of cells, which is also what keeps the
    /// cell graph acyclic.
    #[error("cell reference is out of range or does not point forward")]
    BadReference,

    /// A cell's descriptors or data are inconsistent.
    #[error("cell is malformed: {0}")]
    Malformed(&'static str),

    /// The bag declares more cells than this crate will parse.
    #[error("bag of cells declares more than {limit} cells")]
    TooManyCells {
        /// The limit that was exceeded.
        limit: usize,
    },

    /// The cell tree is deeper than this crate will parse.
    #[error("cell tree is deeper than {limit}")]
    TooDeep {
        /// The limit that was exceeded.
        limit: usize,
    },

    /// A read asked for more bits than the slice has left.
    #[error("slice has {available} bits left, {requested} requested")]
    NotEnoughBits {
        /// The number of bits the read asked for.
        requested: usize,
        /// The number of bits the slice had left.
        available: usize,
    },

    /// A read asked for a reference the slice has already spent.
    #[error("slice has no references left")]
    NotEnoughRefs,

    /// A read asked for more bits than the target integer holds.
    #[error("cannot read {requested} bits into a {width}-bit integer")]
    TooWide {
        /// The number of bits the read asked for.
        requested: u32,
        /// The width of the target integer.
        width: u32,
    },

    /// A store asked for more bits than the cell has room for.
    ///
    /// The store fails rather than truncating. A short write produces a cell with a
    /// different hash, and since a hash is an identity here rather than a checksum,
    /// nothing downstream would report the difference as an error.
    #[error("cell has {available} bits free, {requested} requested")]
    NoRoomForBits {
        /// The number of bits the store asked for.
        requested: usize,
        /// The number of bits the cell had free.
        available: usize,
    },

    /// A store asked for a reference the cell has no room for.
    #[error("cell already holds its {limit} references")]
    NoRoomForRefs {
        /// The limit that was reached.
        limit: usize,
    },
}
