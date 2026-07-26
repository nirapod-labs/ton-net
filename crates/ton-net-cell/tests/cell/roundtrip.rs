// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A bag this crate writes that this crate will not read back.
//!
//! Found by the decode-boundary fuzzing in [`fuzz`](super::fuzz), which is what that work is
//! for. Kept as a case rather than a comment because a defect described in prose beside the
//! assertion that steps around it reads as design.

use ton_net_cell::{parse_boc, serialize_boc, CellError};

/// Two roots naming one cell survive a parse and do not survive a reserialization.
///
/// A bag's root list holds indices into its cell array, and nothing stops two entries holding
/// the same index: the bag below carries two identical cells and names both, and
/// [`parse_boc`] reads it. Writing those roots back deduplicates the cell, because a bag
/// stores each distinct cell once, so the header states one cell and two roots. Reading that
/// header refuses it, on the rule that a root count above the cell count is malformed.
///
/// One of the two is wrong and the fix is not this test's to choose. Either a root count above
/// the cell count is legal, in which case `header.rs` refuses a bag it should read, or it is
/// not, in which case `serialize_boc` writes one it should refuse to write. The direction is a
/// decode-boundary decision: loosening the reader widens what untrusted input may say, and
/// tightening the writer turns a silent round-trip failure into a refusal at the call that
/// causes it.
#[test]
#[ignore = "a known defect, kept as its reproduction until the direction of the fix is decided"]
fn two_roots_naming_one_cell_do_not_survive_a_reserialization() {
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
        "and they are the same cell, which is what makes the write deduplicate them"
    );

    let written = serialize_boc(&roots).expect("the roots write back");

    // The failure this pins: the crate refuses its own output.
    assert_eq!(
        parse_boc(&written).err(),
        Some(CellError::Header("root count")),
        "a bag this crate wrote reads back"
    );
}
