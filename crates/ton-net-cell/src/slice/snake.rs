// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a snake string.
//!
//! The inverse of [`store_snake`](crate::Builder::store_snake): the whole bytes of this
//! cell, then those of the cell chained through its first reference, and so on to the end.

use super::Slice;
use crate::cell::Cell;
use crate::error::CellError;

impl Slice<'_> {
    /// Reads a snake string: the whole bytes of this slice, then those of each cell chained
    /// through the first reference.
    ///
    /// Only whole bytes are read from each cell, since a snake is written in bytes; any bits
    /// a cell carries past its last whole byte are left for the caller.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if a chained reference cannot be reached.
    pub fn load_snake(&mut self) -> Result<Vec<u8>, CellError> {
        let mut out = Vec::new();
        let whole = self.remaining_bits() / 8;
        out.extend(self.load_bytes(whole)?);

        let mut next: Option<&Cell> = if self.remaining_refs() > 0 {
            Some(self.load_ref()?)
        } else {
            None
        };
        while let Some(cell) = next {
            let mut slice = cell.parse();
            let whole = slice.remaining_bits() / 8;
            out.extend(slice.load_bytes(whole)?);
            next = if slice.remaining_refs() > 0 {
                Some(slice.load_ref()?)
            } else {
                None
            };
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::Builder;

    /// Writes a snake, then reads it back whole.
    fn round_trip(bytes: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new();
        builder.store_snake(bytes).expect("it fits");
        builder
            .build()
            .expect("well formed")
            .parse()
            .load_snake()
            .expect("it reads back")
    }

    #[test]
    fn an_empty_string_round_trips() {
        assert!(round_trip(b"").is_empty());
    }

    #[test]
    fn a_short_string_round_trips() {
        let expected = b"USDT".to_vec();
        assert_eq!(round_trip(&expected), expected);
    }

    #[test]
    fn a_long_string_round_trips_across_cells() {
        let expected: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(300)
            .copied()
            .collect();
        assert_eq!(round_trip(&expected), expected);
    }
}
