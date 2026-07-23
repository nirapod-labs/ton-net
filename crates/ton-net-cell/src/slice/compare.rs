// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Comparing the bits two slices have left to read.
//!
//! A comparison reads from each slice's current position to its end, so two cursors that
//! have already read a differing prefix compare by what remains rather than by the whole
//! cell. Neither slice is advanced; the comparison works on copies.

use std::cmp::Ordering;

use super::Slice;

impl Slice<'_> {
    /// Whether this slice and another have the same bits left to read.
    #[must_use]
    pub fn bits_equal(&self, other: &Self) -> bool {
        self.compare_bits(other) == Ordering::Equal
    }

    /// Orders this slice's remaining bits against another's.
    ///
    /// The order is lexicographic, a zero bit before a one, and a run that is a prefix of a
    /// longer one comes first. Neither slice is advanced.
    #[must_use]
    pub fn compare_bits(&self, other: &Self) -> Ordering {
        let mut here = self.clone();
        let mut there = other.clone();
        loop {
            match (here.load_bit(), there.load_bit()) {
                // The bits match, so read on.
                (Ok(this), Ok(that)) if this == that => {}
                (Ok(this), Ok(that)) => return this.cmp(&that),
                // One run ended while the other kept going, so the shorter comes first.
                (Ok(_), Err(_)) => return Ordering::Greater,
                (Err(_), Ok(_)) => return Ordering::Less,
                (Err(_), Err(_)) => return Ordering::Equal,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Builder, Cell};
    use std::cmp::Ordering;

    /// A cell holding exactly the given bits.
    fn cell_of_bits(bits: &[bool]) -> Cell {
        let mut builder = Builder::new();
        for &bit in bits {
            builder.store_bit(bit).expect("a bit fits");
        }
        builder.build().expect("well formed")
    }

    #[test]
    fn equal_runs_compare_equal() {
        let one = cell_of_bits(&[true, false, true]);
        let two = cell_of_bits(&[true, false, true]);
        assert!(one.parse().bits_equal(&two.parse()));
        assert_eq!(one.parse().compare_bits(&two.parse()), Ordering::Equal);
    }

    #[test]
    fn a_prefix_comes_before_a_longer_run() {
        let short = cell_of_bits(&[true, false]);
        let long = cell_of_bits(&[true, false, true]);
        assert_eq!(short.parse().compare_bits(&long.parse()), Ordering::Less);
        assert_eq!(long.parse().compare_bits(&short.parse()), Ordering::Greater);
        assert!(!short.parse().bits_equal(&long.parse()));
    }

    #[test]
    fn a_differing_bit_orders_the_runs() {
        let lower = cell_of_bits(&[true, false, false]);
        let higher = cell_of_bits(&[true, true, false]);
        assert_eq!(lower.parse().compare_bits(&higher.parse()), Ordering::Less);
    }

    #[test]
    fn comparison_reads_from_the_current_position() {
        // The two runs differ only in a first bit that both cursors have already read.
        let one = cell_of_bits(&[true, false, true, false]);
        let two = cell_of_bits(&[false, false, true, false]);
        let mut here = one.parse();
        let mut there = two.parse();
        here.load_bit().expect("skip the differing bit");
        there.load_bit().expect("skip the differing bit");
        assert!(here.bits_equal(&there), "what remains is the same");
    }
}
