// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Properties the cell model has to hold for every input, not for the inputs somebody
//! thought to write down.
//!
//! The example tests next to each function pin behaviour that is already understood. A
//! property states the rule and lets the generator look for the case nobody pictured.
//!
//! What a property can look for depends on what the generator can build, and that is
//! worth being exact about. The round-trip properties below start from a tree and go
//! out through the serializer, so every encoding they ever see is the canonical one.
//! That is enough for the codec agreeing with itself, and it is not enough for the
//! defect this format actually had: a byte-aligned cell also had a second, longer
//! encoding, and accepting it left a byte of padding inside the data the hash covers,
//! so this crate and TON disagreed about the identity of a cell they both accepted. No
//! amount of round-tripping reaches that, because the serializer never writes the long
//! form. It is reached by [`encoding_is_unique`](self), which builds the second
//! encoding directly.
//!
//! These live inside the crate rather than in `tests/` because building a cell goes
//! through `Cell::from_parts`, which is crate-private on purpose: outside this crate a
//! cell can only come from parsing, so no caller can construct one whose hashes
//! disagree with its contents.

use proptest::prelude::*;

use crate::{
    boc::{bit_len, parse_boc, serialize_boc},
    cell::{Cell, CellType},
};

/// The largest data payload a cell can hold, in bytes.
const MAX_DATA_BYTES: usize = 127;

/// Builds an ordinary cell from generated parts.
///
/// Ordinary cells carry a level mask of zero as long as no exotic sits beneath them,
/// which is the case for everything this module generates: the exotic kinds carry
/// hashes of subtrees in their data, so a generated one would be refused for saying
/// something untrue about a tree that does not exist. Exotic handling is pinned by
/// example in `tests/hostile.rs`, where the point is rejection rather than round-trip.
fn ordinary(data: Vec<u8>, bits: u16, refs: Vec<Cell>) -> Cell {
    Cell::from_parts(data, bits, refs, CellType::Ordinary, 0).unwrap()
}

/// Data bytes together with the bit count they represent.
///
/// The bit count drives the encoding that mattered here. A cell whose bit count is not
/// a multiple of eight stores a completion tag, a set bit after the data followed by
/// zeros, and a byte-aligned cell stores none. Generating both halves of that split is
/// the point of pairing the two rather than generating bytes alone.
fn data_and_bits() -> impl Strategy<Value = (Vec<u8>, u16)> {
    (0usize..=MAX_DATA_BYTES).prop_flat_map(|len| {
        let max_bits = len * 8;
        let bits = if max_bits == 0 {
            Just(0usize).boxed()
        } else {
            // Every bit count the byte count can hold, so aligned and unaligned cells
            // both arrive, and the top of the range is exercised rather than approached.
            (max_bits.saturating_sub(7)..=max_bits).boxed()
        };
        (proptest::collection::vec(any::<u8>(), len), bits).prop_map(|(mut bytes, bits)| {
            // Bits below the count are data; the rest of the final byte is the
            // completion tag and zero padding, which the codec writes itself. Clearing
            // them here keeps the generated cell in the stored form a parsed one has,
            // so a round-trip compares like with like.
            if bits % 8 != 0 {
                if let Some(last) = bytes.last_mut() {
                    let used = (bits % 8) as u32;
                    let keep = 0xffu8 << (8 - used);
                    *last &= keep;
                    *last |= 1 << (7 - used);
                }
            }
            #[allow(clippy::cast_possible_truncation)]
            (bytes, bits as u16)
        })
    })
}

/// A tree of ordinary cells, bounded in depth and breadth.
///
/// The bounds are small on purpose. A property that needs a hundred thousand cells to
/// fail is a property about the cell limit, which `tests/hostile.rs` covers directly;
/// what this looks for is an encoding that is wrong at any size, and a shrunk failure
/// of four cells can be read.
fn cell_tree() -> impl Strategy<Value = Cell> {
    let leaf = data_and_bits().prop_map(|(data, bits)| ordinary(data, bits, Vec::new()));
    leaf.prop_recursive(4, 24, 4, |inner| {
        (data_and_bits(), proptest::collection::vec(inner, 0..=4))
            .prop_map(|((data, bits), refs)| ordinary(data, bits, refs))
    })
}

proptest! {
    /// Serializing a tree and reading it back gives the same tree.
    ///
    /// The representation hash is the identity TON uses: a proof names a subtree by
    /// this hash, so two encodings of one cell that hash differently would let a server
    /// answer with a tree the caller asked for under a name the caller would not
    /// recognise. Comparing the hash rather than the bytes is deliberate, because it is
    /// the hash that has to survive the round trip.
    #[test]
    fn boc_round_trip_preserves_the_representation_hash(root in cell_tree()) {
        let bytes = serialize_boc(std::slice::from_ref(&root)).unwrap();
        let parsed = parse_boc(&bytes).unwrap();
        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(parsed[0].repr_hash(), root.repr_hash());
    }

    /// A cell has one encoding, and the second one is refused.
    ///
    /// A byte-aligned cell can be described two ways: an even bit descriptor and the
    /// bytes, or an odd one and a trailing `0x80` that carries no data. Both name the
    /// same bits. Accepting the second leaves that padding byte inside the data the
    /// representation hash covers, so a cell both implementations accept gets two
    /// different identities, and a proof naming a subtree by hash stops meaning the
    /// same thing on each side.
    ///
    /// This is the one property here that reaches that defect. The round-trip
    /// properties cannot: the serializer only ever writes the canonical form, so the
    /// long form has to be built by hand, which is why the descriptor is read directly
    /// rather than through a bag of cells.
    #[test]
    fn encoding_is_unique(bytes in proptest::collection::vec(any::<u8>(), 1..=MAX_DATA_BYTES)) {
        #[allow(clippy::cast_possible_truncation)]
        let full = bytes.len() as u8;

        // The canonical description of those bytes: even descriptor, no tag.
        prop_assert_eq!(bit_len(full * 2, &bytes).unwrap(), u16::from(full) * 8);

        // The same bits the long way round: odd descriptor, and a final byte holding
        // nothing but the completion bit.
        let mut padded = bytes;
        padded.push(0x80);
        prop_assert!(bit_len(full * 2 + 1, &padded).is_err());
    }

    /// The bytes are stable, not merely equivalent.
    ///
    /// A codec can round-trip a value while writing it differently each time, and for a
    /// format whose hash covers the bytes that is the same defect as losing the value.
    #[test]
    fn serializing_a_parsed_tree_reproduces_the_bytes(root in cell_tree()) {
        let once = serialize_boc(&[root]).unwrap();
        let parsed = parse_boc(&once).unwrap();
        let twice = serialize_boc(&parsed).unwrap();
        prop_assert_eq!(once, twice);
    }

    /// Every cell in a parsed tree hashes to what its own contents imply.
    ///
    /// The round-trip properties above would still pass if the parser recomputed a
    /// consistent but wrong hash on both sides. This walks the parsed tree and rebuilds
    /// each cell from the parts the parser reports, so the hash is checked against the
    /// contents rather than against the other direction of the same code.
    #[test]
    fn a_parsed_cell_hashes_to_what_its_parts_imply(root in cell_tree()) {
        let bytes = serialize_boc(&[root]).unwrap();
        let parsed = parse_boc(&bytes).unwrap();
        let mut stack = vec![parsed[0].clone()];
        while let Some(cell) = stack.pop() {
            let rebuilt = ordinary(cell.data().to_vec(), cell.bit_len(), cell.refs().to_vec());
            prop_assert_eq!(rebuilt.repr_hash(), cell.repr_hash());
            prop_assert_eq!(rebuilt.depth(), cell.depth());
            stack.extend(cell.refs().iter().cloned());
        }
    }

    /// Arbitrary bytes are refused, never fatal.
    ///
    /// A bag of cells arrives from a liteserver, so the input is an attacker's to
    /// choose. The crate denies the panicking constructs for that reason; this asserts
    /// the outcome rather than the coding rule, since arithmetic is deliberately outside
    /// that lint set and an overflow would still abort a debug build.
    #[test]
    fn parsing_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_boc(&bytes);
    }

    /// Truncating a real encoding is refused, never fatal.
    ///
    /// Arbitrary bytes rarely get past the header, so most of that generator tests one
    /// early rejection. A prefix of a valid bag reaches the length fields, the index
    /// table and the reference decoding with values that look plausible, which is where
    /// a short read would be read as a large count.
    #[test]
    fn parsing_a_truncated_encoding_never_panics(root in cell_tree(), cut in 0usize..512) {
        let bytes = serialize_boc(&[root]).unwrap();
        let cut = cut.min(bytes.len());
        let _ = parse_boc(&bytes[..cut]);
    }
}
