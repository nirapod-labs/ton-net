// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Inspecting the bits a slice has left to read.
//!
//! A comparison reads from each slice's current position to its end, so two cursors that
//! have already read a differing prefix compare by what remains rather than by the whole
//! cell. A run of one bit value at either end is counted the same way, over the remaining
//! window rather than the whole cell. None of this advances a cursor; the work is done on
//! a copy or by reading the underlying data in place.

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

    /// Counts the run of `bit` at the front of what is left, without advancing.
    ///
    /// The count stops at the first bit that differs or at the end of the slice, so it is
    /// how many times [`load_bit`](Slice::load_bit) would return `bit` before returning
    /// anything else. A dictionary label reads its own `hml_same` run this way.
    #[must_use]
    pub fn count_leading(&self, bit: bool) -> usize {
        let mut probe = self.clone();
        let mut run = 0;
        while matches!(probe.load_bit(), Ok(seen) if seen == bit) {
            run += 1;
        }
        run
    }

    /// Counts the run of `bit` at the back of what is left, without advancing.
    ///
    /// The count is measured from the last remaining bit toward the cursor and stops at the
    /// first bit that differs, so it never counts bits already read.
    #[must_use]
    pub fn count_trailing(&self, bit: bool) -> usize {
        let data = self.cell.data();
        let remaining = self.remaining_bits();
        let mut run = 0;
        while run < remaining && super::bit_at(data, self.bit + remaining - 1 - run) == bit {
            run += 1;
        }
        run
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

    #[test]
    fn a_leading_run_is_counted_up_to_the_first_differing_bit() {
        let cell = cell_of_bits(&[true, true, true, false, true, false, false]);
        let slice = cell.parse();
        assert_eq!(slice.count_leading(true), 3);
        assert_eq!(slice.count_leading(false), 0);
    }

    #[test]
    fn a_trailing_run_is_counted_from_the_last_bit_back() {
        let cell = cell_of_bits(&[true, true, true, false, true, false, false]);
        let slice = cell.parse();
        assert_eq!(slice.count_trailing(false), 2);
        assert_eq!(slice.count_trailing(true), 0);
    }

    #[test]
    fn a_count_measures_only_what_is_left() {
        let cell = cell_of_bits(&[true, true, true, false, true, false, false]);
        let mut slice = cell.parse();
        slice.skip_bits(4).expect("four bits are there"); // leaves [true, false, false]
        assert_eq!(slice.count_leading(true), 1);
        assert_eq!(slice.count_trailing(false), 2);
    }

    #[test]
    fn an_all_same_run_counts_the_whole_remainder() {
        let cell = cell_of_bits(&[false, false, false, false]);
        let slice = cell.parse();
        assert_eq!(slice.count_leading(false), 4);
        assert_eq!(slice.count_trailing(false), 4);
    }

    #[test]
    fn a_spent_slice_counts_nothing() {
        let cell = cell_of_bits(&[true, false]);
        let mut slice = cell.parse();
        slice.skip_bits(2).expect("two bits are there");
        assert_eq!(slice.count_leading(true), 0);
        assert_eq!(slice.count_leading(false), 0);
        assert_eq!(slice.count_trailing(true), 0);
        assert_eq!(slice.count_trailing(false), 0);
    }
}
