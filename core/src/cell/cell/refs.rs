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
use crate::cell::error::CellError;

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

    /// Drops every reference past the first `len`.
    ///
    /// A count at or above what is held changes nothing, which is what `truncate` means
    /// everywhere else in Rust and keeps the caller from having to check first. Shrinking
    /// moves the kept references into the smaller variant, the mirror of what
    /// [`push`](Refs::push) does growing, and never allocates.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.as_slice().len() {
            return;
        }
        *self = match (std::mem::take(self), len) {
            (Self::Four([a, b, c, _]), 3) => Self::Three([a, b, c]),
            (Self::Three([a, b, _]) | Self::Four([a, b, _, _]), 2) => Self::Two([a, b]),
            (Self::Two([a, _]) | Self::Three([a, _, _]) | Self::Four([a, _, _, _]), 1) => {
                Self::One([a])
            }
            // Every remaining pair has len below the count held, and the only count below
            // one is zero, so what is left holds nothing.
            _ => Self::None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::Builder;

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

    #[test]
    fn truncating_keeps_the_first_references_in_order() {
        let bytes: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
        for len in 0..=bytes.len() {
            let mut refs = Refs::default();
            for byte in bytes {
                refs.push(cell_of(u64::from(byte))).expect("four fit");
            }
            refs.truncate(len);
            let seen: Vec<u8> = refs.as_slice().iter().map(|cell| cell.data()[0]).collect();
            assert_eq!(seen, bytes[..len], "truncating four to {len}");
        }
    }

    #[test]
    fn truncating_to_a_count_at_or_above_what_is_held_changes_nothing() {
        let mut refs = Refs::default();
        refs.push(cell_of(0xA1)).expect("one fits");
        refs.push(cell_of(0xB2)).expect("two fit");
        let held = refs.clone();
        refs.truncate(2);
        assert_eq!(refs, held);
        refs.truncate(9);
        assert_eq!(refs, held);
    }

    #[test]
    fn a_truncated_set_takes_references_again_up_to_the_limit() {
        let mut refs = Refs::default();
        for byte in [0xA1, 0xB2, 0xC3, 0xD4] {
            refs.push(cell_of(byte)).expect("four fit");
        }
        refs.truncate(1);
        for byte in [0xE5, 0xF6, 0x07] {
            refs.push(cell_of(byte)).expect("the room came back");
        }
        assert!(refs.push(cell_of(0x18)).is_err(), "and stops at four again");
        let seen: Vec<u8> = refs.as_slice().iter().map(|cell| cell.data()[0]).collect();
        assert_eq!(seen, [0xA1, 0xE5, 0xF6, 0x07]);
    }
}
