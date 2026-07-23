// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading and checking a bag's header, before any cell is built.

use super::{crc32c, Header, Reader, MAGIC, MAX_CELLS};
use crate::error::CellError;

/// Reads and checks a bag's header, leaving `reader` at the first cell.
///
/// Everything a bag states about itself is checked here before a cell is read: the magic,
/// the field sizes, the checksum over the whole bag, that the counts are in range, and that
/// the stated cell-area size accounts for exactly the bytes that remain. A header that
/// passes describes a bag whose cells can be read without another check on the shape.
pub(super) fn read_header(reader: &mut Reader<'_>, bytes: &[u8]) -> Result<Header, CellError> {
    if reader.take(4)? != MAGIC {
        return Err(CellError::NotABagOfCells);
    }

    let flags = reader.byte()?;
    let has_index = flags & 0x80 != 0;
    let has_checksum = flags & 0x40 != 0;
    let ref_size = usize::from(flags & 0x07);
    let offset_size = usize::from(reader.byte()?);
    if !(1..=4).contains(&ref_size) {
        return Err(CellError::Header("reference size"));
    }
    if !(1..=8).contains(&offset_size) {
        return Err(CellError::Header("offset size"));
    }

    // A checksum, when present, trails the whole bag and covers everything before it.
    // Checking it first means corrupt bytes are rejected before anything is built.
    if has_checksum {
        let split = bytes.len().checked_sub(4).ok_or(CellError::Truncated)?;
        let (body, tail) = bytes.split_at(split);
        let stored = u32::from_le_bytes(tail.try_into().map_err(|_| CellError::Truncated)?);
        if crc32c(body) != stored {
            return Err(CellError::Checksum);
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let count = reader.uint(ref_size)? as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let roots = reader.uint(ref_size)? as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let absent = reader.uint(ref_size)? as usize;
    // Unlike the reads above, this one is as wide as offset_size allows, which is eight
    // bytes, so it can name a bag larger than a 32-bit target can address. Refusing is
    // what keeps the check below meaningful: a size narrowed to fit would let a bag claim
    // one length, carry another, and still pass.
    let Ok(cell_area) = usize::try_from(reader.uint(offset_size)?) else {
        return Err(CellError::Header("cell area size"));
    };

    // An absent cell is a reference to a cell the bag does not carry, which only the
    // format's incremental-update use has. A bag holding one cannot be read whole.
    if absent != 0 {
        return Err(CellError::Header("absent cells"));
    }
    if count > MAX_CELLS {
        return Err(CellError::TooManyCells { limit: MAX_CELLS });
    }
    if roots == 0 || roots > count {
        return Err(CellError::Header("root count"));
    }
    // Every cell costs at least its two descriptor bytes, so a count the remaining bytes
    // could not hold is truncation. Checked before allocating for the count.
    if count.saturating_mul(2) > reader.remaining() {
        return Err(CellError::Truncated);
    }

    let mut root_list = Vec::with_capacity(roots);
    for _ in 0..roots {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "ref_size is at most 4, so this is under 2^32"
        )]
        let index = reader.uint(ref_size)? as usize;
        if index >= count {
            return Err(CellError::BadReference);
        }
        root_list.push(index);
    }
    if has_index {
        // The index only repeats where each cell starts, which this reader already knows.
        reader.take(count.saturating_mul(offset_size))?;
    }

    // The header states how many bytes the cells take. Holding a bag to its own statement
    // leaves no unread tail to hide bytes in, and rejects a bag that claims a size it does
    // not carry rather than reading whatever happens to follow.
    let stated_end = reader
        .consumed()
        .checked_add(cell_area)
        .ok_or(CellError::Header("cell area size"))?;
    let body_end = if has_checksum {
        bytes.len().saturating_sub(4)
    } else {
        bytes.len()
    };
    if stated_end != body_end {
        return Err(CellError::Header("cell area size"));
    }

    Ok(Header {
        count,
        ref_size,
        root_list,
        has_index,
        has_checksum,
        cell_area,
        body_offset: reader.consumed(),
    })
}
