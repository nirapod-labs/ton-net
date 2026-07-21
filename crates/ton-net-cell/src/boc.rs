//! The bag of cells: the serialized form of a cell graph.

use crate::cell::{Cell, CellType};
use crate::error::CellError;

/// The four bytes every bag of cells begins with.
const MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// The most data bits a cell may hold.
const MAX_BITS: u16 = 1023;

/// The most cells [`parse_boc`] will read from one bag.
///
/// A bag arrives from a liteserver, which is not trusted, so a declared cell count is
/// checked against this before anything is allocated for it.
pub const MAX_CELLS: usize = 1 << 20;

/// The longest chain of references [`parse_boc`] will read.
///
/// Bounding the depth keeps a deep graph from overflowing the stack when the cells are
/// later walked or dropped.
pub const MAX_DEPTH: usize = 1024;

/// A cell as read from the bag, with its references still as indices.
struct RawCell {
    data: Vec<u8>,
    bits: u16,
    refs: Vec<usize>,
    cell_type: CellType,
    level_mask: u8,
}

/// A reader that returns an error rather than reading past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CellError> {
        let end = self.at.checked_add(n).ok_or(CellError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(CellError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, CellError> {
        self.take(1).map(|b| b[0])
    }

    fn uint(&mut self, n: usize) -> Result<u64, CellError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |value, &b| (value << 8) | u64::from(b)))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

/// The number of data bits a cell holds, from its bit descriptor and stored bytes.
///
/// An odd descriptor means the final byte is partial: it carries the data bits, then a
/// set bit, then zeros.
fn bit_len(d2: u8, data: &[u8]) -> Result<u16, CellError> {
    let full = u16::from(d2 >> 1);
    if d2 & 1 == 0 {
        return Ok(full * 8);
    }
    let last = *data
        .last()
        .ok_or(CellError::Malformed("partial byte with no data"))?;
    if last == 0 {
        return Err(CellError::Malformed("partial byte has no completion bit"));
    }
    Ok(full * 8 + (7 - last.trailing_zeros() as u16))
}

/// Determines a cell's kind, and checks an exotic cell is long enough to be read.
fn classify(exotic: bool, data: &[u8]) -> Result<CellType, CellError> {
    if !exotic {
        return Ok(CellType::Ordinary);
    }
    let tag = *data
        .first()
        .ok_or(CellError::Malformed("exotic cell has no type byte"))?;
    let cell_type =
        CellType::from_tag(tag).ok_or(CellError::Malformed("unknown exotic cell type"))?;

    if cell_type == CellType::PrunedBranch {
        // A pruned branch stores one hash and one depth per marked level, after its type
        // and mask bytes. Checking the length here keeps every later read in range.
        let levels = data
            .get(1)
            .ok_or(CellError::Malformed("pruned branch has no mask byte"))?
            .count_ones() as usize;
        if data.len() < 2 + levels * 34 {
            return Err(CellError::Malformed(
                "pruned branch is too short for its level mask",
            ));
        }
    }
    Ok(cell_type)
}

/// Parses a bag of cells and returns its root cells.
///
/// A bag holds a whole cell graph plus the indices of the roots it is read from. Most
/// bags have one root; a liteserver's account proof has two.
///
/// # Errors
///
/// Returns [`CellError::NotABagOfCells`] if the magic does not match,
/// [`CellError::Truncated`] if the bytes end early, [`CellError::Header`] if a header
/// field is out of range, [`CellError::BadReference`] if a reference is out of range or
/// does not point forward, [`CellError::Malformed`] if a cell's descriptors and data
/// disagree, [`CellError::TooManyCells`] past [`MAX_CELLS`], or [`CellError::TooDeep`]
/// past [`MAX_DEPTH`].
///
/// # Examples
///
/// ```
/// use ton_net_cell::parse_boc;
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// assert_eq!(roots.len(), 1);
/// assert_eq!(roots[0].data(), &[0xab]);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
pub fn parse_boc(bytes: &[u8]) -> Result<Vec<Cell>, CellError> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(4)? != MAGIC {
        return Err(CellError::NotABagOfCells);
    }

    let flags = reader.byte()?;
    let has_index = flags & 0x80 != 0;
    let ref_size = usize::from(flags & 0x07);
    let offset_size = usize::from(reader.byte()?);
    if !(1..=4).contains(&ref_size) {
        return Err(CellError::Header("reference size"));
    }
    if !(1..=8).contains(&offset_size) {
        return Err(CellError::Header("offset size"));
    }

    let count = reader.uint(ref_size)? as usize;
    let roots = reader.uint(ref_size)? as usize;
    let _absent = reader.uint(ref_size)?;
    let _total_size = reader.uint(offset_size)?;

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

    let mut raw = Vec::with_capacity(count);
    for index in 0..count {
        let d1 = reader.byte()?;
        let d2 = reader.byte()?;
        if d1 & 16 != 0 {
            return Err(CellError::Malformed("cell stores its hashes inline"));
        }
        let ref_count = usize::from(d1 & 7);
        let exotic = d1 & 8 != 0;
        let level_mask = d1 >> 5;

        let data = reader.take(usize::from((d2 >> 1) + (d2 & 1)))?.to_vec();
        let bits = bit_len(d2, &data)?;
        if bits > MAX_BITS {
            return Err(CellError::Malformed("cell holds more than 1023 bits"));
        }
        let cell_type = classify(exotic, &data)?;

        let mut refs = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            let target = reader.uint(ref_size)? as usize;
            // References point strictly forward, which is what keeps the graph acyclic.
            if target >= count || target <= index {
                return Err(CellError::BadReference);
            }
            refs.push(target);
        }

        raw.push(RawCell {
            data,
            bits,
            refs,
            cell_type,
            level_mask,
        });
    }

    // References point forward, so a descending pass meets every child before its parent.
    let mut depth = vec![0usize; count];
    for index in (0..count).rev() {
        let mut deepest = 0usize;
        for &target in &raw[index].refs {
            deepest = deepest.max(depth.get(target).copied().unwrap_or(0) + 1);
        }
        if deepest > MAX_DEPTH {
            return Err(CellError::TooDeep { limit: MAX_DEPTH });
        }
        depth[index] = deepest;
    }

    // Built in the same descending order. Position k in `built` holds cell `count-1-k`.
    let mut built: Vec<Cell> = Vec::with_capacity(count);
    for index in (0..count).rev() {
        let raw_cell = &raw[index];
        let mut refs = Vec::with_capacity(raw_cell.refs.len());
        for &target in &raw_cell.refs {
            let child = built
                .get(count - 1 - target)
                .ok_or(CellError::BadReference)?;
            refs.push(child.clone());
        }
        built.push(Cell::from_parts(
            raw_cell.data.clone(),
            raw_cell.bits,
            refs,
            raw_cell.cell_type,
            raw_cell.level_mask,
        ));
    }

    root_list
        .into_iter()
        .map(|index| {
            built
                .get(count - 1 - index)
                .cloned()
                .ok_or(CellError::BadReference)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // One cell of eight bits holding 0xab.
    const ONE_CELL: [u8; 14] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
    ];

    // A root with one reference; the referenced cell holds 0xcd.
    const TWO_CELLS: [u8; 17] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0xcd,
    ];

    #[test]
    fn parses_a_single_cell() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].bit_len(), 8);
        assert_eq!(roots[0].data(), &[0xab]);
        assert_eq!(roots[0].cell_type(), CellType::Ordinary);
        assert_eq!(roots[0].level_mask(), 0);
        assert!(roots[0].refs().is_empty());
    }

    #[test]
    fn parses_a_reference() {
        let roots = parse_boc(&TWO_CELLS).unwrap();
        assert_eq!(roots[0].refs().len(), 1);
        assert_eq!(roots[0].refs()[0].data(), &[0xcd]);
        assert_eq!(roots[0].reference(0).unwrap().bit_len(), 8);
        assert!(roots[0].reference(1).is_none());
    }

    #[test]
    fn rejects_bytes_that_are_not_a_bag_of_cells() {
        assert_eq!(
            parse_boc(&[0, 1, 2, 3, 4, 5]),
            Err(CellError::NotABagOfCells)
        );
        assert_eq!(parse_boc(&[]), Err(CellError::Truncated));
    }

    #[test]
    fn rejects_a_truncated_bag() {
        for cut in 4..ONE_CELL.len() {
            assert!(
                parse_boc(&ONE_CELL[..cut]).is_err(),
                "a bag cut to {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn rejects_a_reference_out_of_range() {
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::BadReference));
    }

    #[test]
    fn rejects_a_reference_that_does_not_point_forward() {
        // A cell referencing itself would be a cycle.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::BadReference));
    }

    #[test]
    fn rejects_a_cell_count_past_the_limit_before_allocating() {
        // Four-byte reference indices and a count of 0xffffffff.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x04, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::TooManyCells { limit: MAX_CELLS })
        );
    }

    #[test]
    fn rejects_a_cell_count_the_bytes_cannot_hold() {
        // Two hundred cells declared, no cell data at all.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0xc8, 0x01, 0x00, 0x03, 0x00,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::Truncated));
    }

    #[test]
    fn rejects_bad_header_sizes() {
        // A reference size of zero.
        let bag = [0xb5, 0xee, 0x9c, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("reference size")));
        // An offset size of zero.
        let bag = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("offset size")));
    }

    #[test]
    fn rejects_a_root_count_of_zero() {
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("root count")));
    }

    #[test]
    fn rejects_an_unknown_exotic_type() {
        // The exotic flag is set and the leading data byte names no kind.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x08, 0x02, 0x7f,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed("unknown exotic cell type"))
        );
    }

    #[test]
    fn rejects_a_pruned_branch_too_short_for_its_mask() {
        // Exotic, pruned, a mask marking one level, but no room for a hash and depth.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00, 0x28, 0x04, 0x01,
            0x01,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed(
                "pruned branch is too short for its level mask"
            ))
        );
    }

    #[test]
    fn reads_the_bit_length_of_a_partial_byte() {
        // Twelve bits: the byte 0x12, then four bits, a set bit, and zeros.
        assert_eq!(bit_len(0x03, &[0x12, 0xa8]).unwrap(), 12);
        // Eight bits, a whole byte.
        assert_eq!(bit_len(0x02, &[0xab]).unwrap(), 8);
        // No bits at all.
        assert_eq!(bit_len(0x00, &[]).unwrap(), 0);
        // A partial byte with no completion bit cannot be read.
        assert!(bit_len(0x01, &[0x00]).is_err());
    }
}
