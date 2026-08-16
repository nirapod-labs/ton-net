// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Writing a snake string.
//!
//! A run of bytes longer than one cell holds is written as a snake: each cell takes as many
//! whole bytes as it has room for, and the rest go in a child cell chained through the first
//! reference. This is the form a jetton's metadata and other long strings on TON take.

use super::Builder;
use crate::error::CellError;

impl Builder {
    /// Writes `bytes` as a snake string, spilling into child cells when one will not hold
    /// the whole run.
    ///
    /// Each cell takes as many whole bytes as it has room for; the rest go in a child
    /// chained through the first reference, which [`load_snake`](crate::Slice::load_snake)
    /// reads back.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if a byte or a reference cannot be stored.
    pub fn store_snake(&mut self, bytes: &[u8]) -> Result<&mut Self, CellError> {
        let capacity = usize::from(self.bits_left() / 8);
        let take = capacity.min(bytes.len());
        let (head, tail) = bytes.split_at(take);
        self.store_bytes(head)?;
        if !tail.is_empty() {
            let mut child = Self::new();
            child.store_snake(tail)?;
            self.store_ref(child.build()?)?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::Builder;

    #[test]
    fn a_short_string_stays_in_one_cell() {
        let mut builder = Builder::new();
        builder.store_snake(b"USDT").expect("it fits");
        let cell = builder.build().expect("well formed");
        assert_eq!(cell.refs().len(), 0, "a short string needs no child");
    }

    #[test]
    fn a_long_string_spills_into_children() {
        let long: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(300)
            .copied()
            .collect();
        let mut builder = Builder::new();
        builder.store_snake(&long).expect("it fits");
        let cell = builder.build().expect("well formed");
        assert!(!cell.refs().is_empty(), "a long string chains into a child");
    }
}
