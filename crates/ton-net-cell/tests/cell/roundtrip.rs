// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A bag this crate writes reads back.
//!
//! The cases here came out of the decode-boundary fuzz targets in [`fuzz`](super::fuzz).

use ton_net_cell::{parse_boc, serialize_boc, CellError, ParseOptions};

/// Two roots naming one cell survive a reserialization.
///
/// A bag's root list holds indices into its cell array, and nothing stops two entries holding
/// the same index: the bag below carries two identical cells and names both. Writing those
/// roots back stores the cell once, so the header states one cell and two roots, and reading
/// it has to admit a root list longer than the cell list.
#[test]
fn two_roots_naming_one_cell_survive_a_reserialization() {
    // Magic, one root-list entry width, two cells, two roots, then two empty cells.
    let bag: [u8; 16] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let roots = parse_boc(&bag).expect("the bag as written reads");
    assert_eq!(roots.len(), 2, "two roots");
    assert_eq!(
        roots[0].repr_hash(),
        roots[1].repr_hash(),
        "and they are the same cell, which is what makes the write store it once"
    );

    let written = serialize_boc(&roots).expect("the roots write back");
    let read = parse_boc(&written).expect("a bag this crate wrote reads back");

    assert_eq!(read.len(), 2, "both roots survive the trip");
    assert_eq!(
        read[0].repr_hash(),
        roots[0].repr_hash(),
        "and the cell they name is the one that went in"
    );
    assert_eq!(read[1].repr_hash(), roots[1].repr_hash());
}

/// The root list is still bounded, and the bound is the ceiling a parse is running under.
///
/// A root list is allocated from the count the header states, before an index of it has been
/// read. The cell count used to bound that, and once roots stopped answering to it the
/// ceiling had to take the bound over, or a twenty-byte header could name four billion roots
/// and the reader would size a vector for all of them.
///
/// The bag below is built to reach that check and nothing else: one cell, so the cell ceiling
/// is satisfied, and two roots, so the root ceiling is not. A bag with two cells would be
/// refused a line earlier, at the cell count, leaving this bound ungraded.
#[test]
fn a_bag_naming_more_roots_than_the_ceiling_allows_is_refused() {
    // Magic, one-byte refs and offsets, one cell, two roots, no absent, a two-byte cell area,
    // both root entries naming cell zero, then the one empty cell.
    let bag: [u8; 14] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];

    let read = parse_boc(&bag).expect("one cell named by two roots reads under the default");
    assert_eq!(read.len(), 2, "both roots name the one cell");

    // A ceiling of one admits the cell and refuses the roots, so this reaches the root bound
    // rather than stopping at the cell count above it.
    let narrowed = ParseOptions::default().with_max_cells(1);
    assert_eq!(
        ton_net_cell::parse_boc_with(&bag, &narrowed).err(),
        Some(CellError::Header("root count")),
        "a root list past the ceiling is refused before it is allocated for"
    );
}
