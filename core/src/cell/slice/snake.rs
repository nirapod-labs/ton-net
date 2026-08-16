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
        self.load_snake_into(&mut out)?;
        Ok(out)
    }

    /// Reads a snake string onto the end of `into`.
    ///
    /// A snake spans as many cells as it needs and each of them lands on the end of `into`.
    /// [`load_snake`](Slice::load_snake) is this with a fresh vector for a destination.
    ///
    /// # Errors
    ///
    /// As [`load_snake`](Slice::load_snake). A chain that fails partway leaves what it
    /// already read on `into`.
    pub fn load_snake_into(&mut self, into: &mut Vec<u8>) -> Result<(), CellError> {
        let whole = self.remaining_bits() / 8;
        self.load_bytes_into(whole, into)?;

        let mut next: Option<&Cell> = if self.remaining_refs() > 0 {
            Some(self.load_ref()?)
        } else {
            None
        };
        while let Some(cell) = next {
            let mut slice = cell.parse();
            let whole = slice.remaining_bits() / 8;
            slice.load_bytes_into(whole, into)?;
            next = if slice.remaining_refs() > 0 {
                Some(slice.load_ref()?)
            } else {
                None
            };
        }
        Ok(())
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

    #[test]
    fn a_snake_read_into_a_buffer_lands_after_what_the_buffer_already_holds() {
        // The chained read is the one that has to append rather than overwrite: it fills
        // the same buffer once per cell on the chain, so a write that started at the front
        // would leave only the last cell's bytes.
        let written: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(300)
            .copied()
            .collect();
        let mut builder = Builder::new();
        builder.store_snake(&written).expect("it fits");
        let cell = builder.build().expect("well formed");
        assert!(!cell.refs().is_empty(), "300 bytes do not fit one cell");

        let mut buffer = b"held: ".to_vec();
        cell.parse()
            .load_snake_into(&mut buffer)
            .expect("it reads back");
        let mut expected = b"held: ".to_vec();
        expected.extend_from_slice(&written);
        assert_eq!(buffer, expected);
    }
}
