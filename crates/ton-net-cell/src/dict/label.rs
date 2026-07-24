// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! An edge label: the run of key bits every key below an edge shares.
//!
//! A label has three encodings and all three parse. TON's rule is that the shortest one
//! is the only correct one, with a tie going to the earliest constructor, so a dictionary
//! has exactly one representation and therefore exactly one hash. Choosing a longer
//! encoding builds a tree that reads back with the same entries and hashes differently,
//! which nothing downstream would report: a hash here is an identity, not a checksum.
//! [`store_label`] is where that choice is made.

use crate::builder::Builder;
use crate::error::CellError;
use crate::slice::Slice;

/// The width of a `#<= max` field: enough bits to hold every value up to `max`.
pub(super) fn bounded_width(max: u16) -> u32 {
    u16::BITS - max.leading_zeros()
}

/// Reads an edge label, returning the key bits it covers.
///
/// The three encodings are a unary-counted run, an explicit length, and a repeated bit.
pub(super) fn read_label(slice: &mut Slice<'_>, max: u16) -> Result<Vec<bool>, CellError> {
    if !slice.load_bit()? {
        // hml_short: a unary length, then that many bits.
        let mut len = 0u16;
        while slice.load_bit()? {
            len += 1;
            if len > max {
                return Err(CellError::LabelTooLong);
            }
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    if !slice.load_bit()? {
        // hml_long: an explicit length, then that many bits.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "bounded_width(max) is at most 16 because max is itself a u16, so this reads at most 16 bits and the result always fits u16"
        )]
        let len = slice.load_uint(bounded_width(max))? as u16;
        if len > max {
            return Err(CellError::LabelTooLong);
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    // hml_same: one bit repeated a given number of times.
    let value = slice.load_bit()?;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded_width(max) is at most 16 because max is itself a u16, so this reads at most 16 bits and the result always fits u16"
    )]
    let len = slice.load_uint(bounded_width(max))? as u16;
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    Ok(vec![value; usize::from(len)])
}

/// Writes an edge label in the only encoding TON accepts for it.
///
/// All three forms read back as the same label, so the choice is invisible to a reader
/// and decides the cell's hash. The shortest wins; a tie goes to the earliest
/// constructor.
pub(super) fn store_label(into: &mut Builder, label: &[bool], max: u16) -> Result<(), CellError> {
    let len = u16::try_from(label.len()).unwrap_or(u16::MAX);
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    let width = bounded_width(max);
    let bits = u32::from(len);

    let short = 2 * bits + 2;
    let long = 2 + width + bits;
    let repeated = match label.first() {
        Some(first) if label.iter().all(|bit| bit == first) => 3 + width,
        _ => u32::MAX,
    };

    if short <= long && short <= repeated {
        into.store_bit(false)?;
        into.store_same_bit(true, len)?;
        into.store_bit(false)?;
        into.store_bits(label)?;
    } else if long <= repeated {
        into.store_uint(0b10, 2)?;
        into.store_uint(u64::from(len), width)?;
        into.store_bits(label)?;
    } else {
        into.store_uint(0b11, 2)?;
        into.store_bit(label.first().copied().unwrap_or(false))?;
        into.store_uint(u64::from(len), width)?;
    }
    Ok(())
}
