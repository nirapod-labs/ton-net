// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The level-mask arithmetic a cell's hashing is defined over.
//!
//! A cell's level mask records which levels it is significant at, and that governs how many
//! representation hashes it has and which one answers for a given level. The descriptor
//! bytes a hash is taken over are computed from the same mask. None of this touches a cell;
//! it is the pure arithmetic the hashing in the sibling module leans on.

/// The highest level a mask marks, or zero for an empty mask.
pub(super) fn level_of(mask: u8) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "mask is a u8, so leading_zeros is at most 8, and u8::BITS - leading_zeros is at most 8, which fits u8"
    )]
    let level = (u8::BITS - mask.leading_zeros()) as u8;
    level
}

/// The mask as it applies at `level`: only the levels below it remain.
fn applied_mask(mask: u8, level: u8) -> u8 {
    if level >= 3 {
        mask
    } else {
        mask & ((1u8 << level) - 1)
    }
}

/// Which of a cell's stored hashes answers for `level`.
pub(super) fn hash_index(mask: u8, level: u8) -> usize {
    applied_mask(mask, level).count_ones() as usize
}

/// The bit descriptor for a bit count: `floor(b/8) + ceil(b/8)`.
pub(super) fn bits_descriptor(bits: u16) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits is at most MAX_BITS (1023), so floor(bits/8) + ceil(bits/8) is at most 127 + 128 = 255, which fits u8"
    )]
    let descriptor = ((bits / 8) + bits.div_ceil(8)) as u8;
    descriptor
}

/// The refs-and-type descriptor at a level: `r + 8s + 32l`.
pub(super) fn refs_descriptor(refs: usize, exotic: bool, mask: u8, level: u8) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "refs is a cell's reference count, bounded to at most MAX_REFS (4) by every constructor, so this fits u8"
    )]
    let refs = refs as u8;
    refs + if exotic { 8 } else { 0 } + 32 * applied_mask(mask, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_reads_the_highest_marked_level() {
        assert_eq!(level_of(0b000), 0);
        assert_eq!(level_of(0b001), 1);
        assert_eq!(level_of(0b011), 2);
        assert_eq!(level_of(0b111), 3);
        assert_eq!(level_of(0b100), 3);
    }

    #[test]
    fn a_mask_applies_only_the_levels_below() {
        assert_eq!(applied_mask(0b101, 0), 0b000);
        assert_eq!(applied_mask(0b101, 1), 0b001);
        assert_eq!(applied_mask(0b101, 2), 0b001);
        assert_eq!(applied_mask(0b101, 3), 0b101);
        // A level past the top answers with the whole mask.
        assert_eq!(applied_mask(0b101, 4), 0b101);
    }

    #[test]
    fn hash_indices_step_once_per_marked_level() {
        // A mask marking levels 1 and 3 has three hashes: 0, 1, 2.
        assert_eq!(hash_index(0b101, 0), 0);
        assert_eq!(hash_index(0b101, 1), 1);
        assert_eq!(hash_index(0b101, 2), 1);
        assert_eq!(hash_index(0b101, 3), 2);
    }

    #[test]
    fn descriptors_follow_the_specification() {
        // d2 = floor(b/8) + ceil(b/8).
        assert_eq!(bits_descriptor(0), 0);
        assert_eq!(bits_descriptor(8), 2);
        assert_eq!(bits_descriptor(12), 3);
        assert_eq!(bits_descriptor(1023), 255);
        // d1 = r + 8s + 32l.
        assert_eq!(refs_descriptor(0, false, 0, 0), 0);
        assert_eq!(refs_descriptor(4, false, 0, 0), 4);
        assert_eq!(refs_descriptor(1, true, 0, 0), 9);
        // A pruned branch at its own level: no refs, exotic, one marked level.
        assert_eq!(refs_descriptor(0, true, 1, 1), 40);
        // The same cell at level zero drops the mask.
        assert_eq!(refs_descriptor(0, true, 1, 0), 8);
    }
}
