// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The references a cell holds, kept where the cell is rather than in an allocation of
//! their own.
//!
//! A cell has at most four references, so the room for them is small enough and fixed
//! enough to sit inside the cell. What decides the shape is [`Cell::refs`](super::Cell::refs):
//! it hands out a slice, and a slice has to come from somewhere contiguous, which four
//! optional slots are not. One variant per count is, and it costs the pointer-sized tag
//! that tells them apart.

use super::{Cell, MAX_REFS};
use crate::error::CellError;

/// A cell's references, in order, held inline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Refs {
    #[default]
    None,
    One([Cell; 1]),
    Two([Cell; 2]),
    Three([Cell; 3]),
    Four([Cell; 4]),
}

impl Refs {
    /// The references as a slice, in the order they were added.
    pub fn as_slice(&self) -> &[Cell] {
        match self {
            Self::None => &[],
            Self::One(refs) => refs,
            Self::Two(refs) => refs,
            Self::Three(refs) => refs,
            Self::Four(refs) => refs,
        }
    }

    /// Adds a reference at the end.
    ///
    /// Growing means moving the ones already held into the next variant, which is a handful
    /// of pointer moves and never an allocation: filling a cell costs six moves in total.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForRefs`] if the cell already holds [`MAX_REFS`], and
    /// leaves the references it already had.
    pub fn push(&mut self, cell: Cell) -> Result<(), CellError> {
        if matches!(*self, Self::Four(_)) {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        *self = match std::mem::take(self) {
            Self::None => Self::One([cell]),
            Self::One([a]) => Self::Two([a, cell]),
            Self::Two([a, b]) => Self::Three([a, b, cell]),
            Self::Three([a, b, c]) => Self::Four([a, b, c, cell]),
            // Refused above, before anything was taken out of the cell.
            full @ Self::Four(_) => full,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    fn cell_of(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("well formed")
    }

    #[test]
    fn references_come_back_in_the_order_they_went_in() {
        let mut refs = Refs::default();
        for byte in [0xA1, 0xB2, 0xC3, 0xD4] {
            refs.push(cell_of(byte)).expect("four fit");
        }
        let seen: Vec<u8> = refs.as_slice().iter().map(|cell| cell.data()[0]).collect();
        assert_eq!(seen, [0xA1, 0xB2, 0xC3, 0xD4]);
    }

    #[test]
    fn a_fifth_reference_is_refused_and_the_first_four_stay() {
        let mut refs = Refs::default();
        for byte in [0xA1, 0xB2, 0xC3, 0xD4] {
            refs.push(cell_of(byte)).expect("four fit");
        }
        let full = refs.clone();
        assert!(refs.push(cell_of(0xE5)).is_err(), "a fifth does not fit");
        assert_eq!(refs, full, "and the refusal changed nothing");
    }
}
