// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Rendering a cell as text, for reading and logging a tree.
//!
//! A cell's data is a run of bits that need not fill a whole number of bytes. The hex form
//! writes whole nibbles as hex and completes a trailing partial nibble with a set bit and
//! zeros, marked `_`, which is the notation TON's own tools read: `x{}` is empty, `x{A}` is
//! the four bits `1010`, and `x{B_}` is the three bits `101`. The binary form writes every
//! bit as `0` or `1` and needs no completion. References are the tree below, each indented
//! one step under the cell that holds it, and an exotic cell is named by its kind.

use std::fmt::Write as _;

use super::{Cell, CellType};

/// One step of indentation for each level of depth.
const INDENT: &str = "  ";

/// Whether a dump writes each cell's bits as hex or as binary.
#[derive(Clone, Copy)]
enum Radix {
    Hex,
    Binary,
}

/// The bit at `index`, counted from the most significant bit of the first byte.
fn bit_at(data: &[u8], index: usize) -> u8 {
    match data.get(index / 8) {
        Some(byte) => (byte >> (7 - index % 8)) & 1,
        None => 0,
    }
}

/// Renders `bits` bits of `data` as `x{...}`.
///
/// Whole nibbles are hex. A trailing partial nibble is completed with a set bit and zeros
/// and marked `_`, so the reader counts back from the last set bit to recover how many bits
/// were data.
fn hex_form(data: &[u8], bits: u16) -> String {
    let mut out = String::from("x{");
    let bits = usize::from(bits);
    let whole = bits / 4;
    for nibble in 0..whole {
        let mut value = 0u8;
        for offset in 0..4 {
            value = (value << 1) | bit_at(data, nibble * 4 + offset);
        }
        let _ = write!(out, "{value:X}");
    }
    let remainder = bits % 4;
    if remainder != 0 {
        let mut value = 0u8;
        for offset in 0..remainder {
            value = (value << 1) | bit_at(data, whole * 4 + offset);
        }
        value = (value << 1) | 1;
        value <<= 3 - remainder;
        let _ = write!(out, "{value:X}_");
    }
    out.push('}');
    out
}

/// Renders `bits` bits of `data` as `b{...}`, one character per bit.
fn binary_form(data: &[u8], bits: u16) -> String {
    let mut out = String::from("b{");
    for index in 0..usize::from(bits) {
        out.push(if bit_at(data, index) == 1 { '1' } else { '0' });
    }
    out.push('}');
    out
}

/// The name that prefixes an exotic cell, or empty for an ordinary one.
fn kind_prefix(kind: CellType) -> &'static str {
    match kind {
        CellType::Ordinary => "",
        CellType::PrunedBranch => "pruned ",
        CellType::LibraryReference => "library ",
        CellType::MerkleProof => "merkle_proof ",
        CellType::MerkleUpdate => "merkle_update ",
    }
}

/// Appends `cell` at `depth`, then each reference one step deeper.
fn render(cell: &Cell, depth: usize, radix: Radix, out: &mut String) {
    for _ in 0..depth {
        out.push_str(INDENT);
    }
    out.push_str(kind_prefix(cell.cell_type()));
    let form = match radix {
        Radix::Hex => hex_form(cell.data(), cell.bit_len()),
        Radix::Binary => binary_form(cell.data(), cell.bit_len()),
    };
    out.push_str(&form);
    out.push('\n');
    for child in cell.refs() {
        render(child, depth + 1, radix, out);
    }
}

/// Renders `cell` and the tree below it in `radix`, without a trailing newline.
fn dump(cell: &Cell, radix: Radix) -> String {
    let mut out = String::new();
    render(cell, 0, radix, &mut out);
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Renders `cell` and the tree below it in the hex bitstring notation.
pub(super) fn hex(cell: &Cell) -> String {
    dump(cell, Radix::Hex)
}

/// Renders `cell` and the tree below it in binary.
pub(super) fn binary(cell: &Cell) -> String {
    dump(cell, Radix::Binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    #[test]
    fn the_hex_form_completes_a_partial_nibble() {
        assert_eq!(hex_form(&[], 0), "x{}");
        assert_eq!(hex_form(&[0xA0], 4), "x{A}"); // 1010
        assert_eq!(hex_form(&[0xB0], 3), "x{B_}"); // 101 -> 1011
        assert_eq!(hex_form(&[0x80], 1), "x{C_}"); // 1 -> 1100
        assert_eq!(hex_form(&[0x40], 1), "x{4_}"); // 0 -> 0100
        assert_eq!(hex_form(&[0xAC], 6), "x{AE_}"); // 101011 -> 10101110
        assert_eq!(hex_form(&[0xAB], 8), "x{AB}");
    }

    #[test]
    fn the_binary_form_writes_every_bit() {
        assert_eq!(binary_form(&[], 0), "b{}");
        assert_eq!(binary_form(&[0xB0], 3), "b{101}");
        assert_eq!(binary_form(&[0xAB], 8), "b{10101011}");
    }

    #[test]
    fn a_tree_indents_each_reference_under_its_parent() {
        let leaf = {
            let mut builder = Builder::new();
            builder.store_uint(0x01, 8).expect("a byte fits");
            builder.build().expect("a leaf is well formed")
        };
        let root = {
            let mut builder = Builder::new();
            builder.store_uint(0xAB, 8).expect("a byte fits");
            builder.store_ref(leaf).expect("a reference fits");
            builder.build().expect("a node is well formed")
        };
        assert_eq!(hex(&root), "x{AB}\n  x{01}");
        assert_eq!(binary(&root), "b{10101011}\n  b{00000001}");
    }

    #[test]
    fn an_exotic_cell_is_named_by_its_kind() {
        assert_eq!(kind_prefix(CellType::Ordinary), "");
        assert_eq!(kind_prefix(CellType::PrunedBranch), "pruned ");
        assert_eq!(kind_prefix(CellType::LibraryReference), "library ");
        assert_eq!(kind_prefix(CellType::MerkleProof), "merkle_proof ");
        assert_eq!(kind_prefix(CellType::MerkleUpdate), "merkle_update ");
    }
}
