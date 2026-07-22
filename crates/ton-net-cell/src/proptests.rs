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

/// A tree assembled by the builder rather than by the crate-private constructor.
///
/// The generators above shape `Cell::from_parts` arguments directly, which is the right
/// reach for properties about parsing. These go the other way: through the public API a
/// caller has, so the completion tag, the capacity checks and the level mask are the
/// ones a caller actually meets.
fn built_tree() -> impl Strategy<Value = Cell> {
    let leaf = data_and_bits().prop_map(|(bytes, bits)| {
        let mut b = crate::Builder::new();
        for index in 0..bits {
            let byte = bytes.get(usize::from(index / 8)).copied().unwrap_or(0);
            b.store_bit((byte >> (7 - (index % 8))) & 1 == 1).unwrap();
        }
        b.build().unwrap()
    });
    leaf.prop_recursive(3, 16, 3, |inner| {
        (data_and_bits(), proptest::collection::vec(inner, 0..=4)).prop_map(
            |((bytes, bits), refs)| {
                let mut b = crate::Builder::new();
                for index in 0..bits {
                    let byte = bytes.get(usize::from(index / 8)).copied().unwrap_or(0);
                    b.store_bit((byte >> (7 - (index % 8))) & 1 == 1).unwrap();
                }
                for cell in refs {
                    b.store_ref(cell).unwrap();
                }
                b.build().unwrap()
            },
        )
    })
}

proptest! {
    /// An integer the builder stores is the integer a slice reads back.
    #[test]
    fn integers_round_trip_through_the_builder(value in any::<u64>(), bits in 1u32..=64) {
        let value = if bits == 64 { value } else { value & ((1u64 << bits) - 1) };
        let mut b = crate::Builder::new();
        b.store_uint(value, bits).unwrap();
        prop_assert_eq!(b.build().unwrap().parse().load_uint(bits).unwrap(), value);
    }

    /// A signed integer survives the sign extension in both directions.
    #[test]
    fn signed_integers_round_trip_through_the_builder(value in any::<i64>(), bits in 1u32..=64) {
        // Bring the value into the range this width holds by keeping its low bits and
        // sign-extending them. Wrapping by arithmetic overflows near the top of the
        // range, which is where the cases worth generating are.
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let value = (((value as u64) << (64 - bits)) as i64) >> (64 - bits);
        let mut b = crate::Builder::new();
        b.store_int(value, bits).unwrap();
        prop_assert_eq!(b.build().unwrap().parse().load_int(bits).unwrap(), value);
    }

    /// An amount survives the variable-length encoding, whose byte count must be minimal.
    #[test]
    fn coins_round_trip_through_the_builder(value in any::<u128>()) {
        // `VarUInteger 16` carries fifteen bytes.
        let value = value >> 8;
        let mut b = crate::Builder::new();
        b.store_coins(value).unwrap();
        prop_assert_eq!(b.build().unwrap().parse().load_coins().unwrap(), value);
    }

    /// A built tree keeps its identity through the serializer.
    #[test]
    fn a_built_tree_keeps_its_identity(root in built_tree()) {
        let bytes = serialize_boc(std::slice::from_ref(&root)).unwrap();
        let parsed = parse_boc(&bytes).unwrap();
        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(parsed[0].repr_hash(), root.repr_hash());
    }

    /// Copying a slice into a builder reproduces the cell it came from.
    #[test]
    fn a_slice_copied_into_a_builder_rebuilds_its_cell(root in built_tree()) {
        let copy = root.parse().to_cell().unwrap();
        prop_assert_eq!(copy.repr_hash(), root.repr_hash());
    }
}

/// A key width and a set of distinct keys of that width.
///
/// The width is generated rather than fixed because it decides how wide a label's length
/// field is, and so which of the three label encodings wins. Mainnet uses four widths;
/// these reach the ones between them, where a length field changes size.
fn keys() -> impl Strategy<Value = (u16, Vec<Vec<u8>>)> {
    (1u16..=64).prop_flat_map(|key_bits| {
        let bytes = usize::from(key_bits).div_ceil(8);
        let spare = u32::from(bytes as u16 * 8 - key_bits);
        let key = proptest::collection::vec(any::<u8>(), bytes).prop_map(move |mut key| {
            // The bits past the key width are not part of the key, so leaving them set
            // would make two spellings of one key look like two keys.
            if let Some(last) = key.last_mut() {
                *last &= u8::MAX.checked_shl(spare).unwrap_or(0);
            }
            key
        });
        (
            Just(key_bits),
            proptest::collection::hash_set(key, 1..24).prop_map(|set| set.into_iter().collect()),
        )
    })
}

/// The dictionary those keys build, each key stored under its own bytes.
fn dict_of(key_bits: u16, keys: &[Vec<u8>]) -> crate::Dict {
    let mut dict = crate::Dict::new(key_bits).unwrap();
    for key in keys {
        let mut value = crate::Builder::new();
        value.store_bytes(key).unwrap();
        dict.set(key, &value).unwrap();
    }
    dict
}

proptest! {
    /// A dictionary is the same tree whatever order its keys arrived in.
    ///
    /// A radix tree has one shape per key set, so this is the property a wrong split or
    /// a wrong merge breaks first, and it needs no oracle outside the crate to state.
    #[test]
    fn a_dictionary_does_not_depend_on_the_order_its_keys_arrive_in((key_bits, keys) in keys()) {
        let forwards = dict_of(key_bits, &keys);
        let backwards = dict_of(key_bits, &keys.iter().rev().cloned().collect::<Vec<_>>());
        prop_assert_eq!(
            forwards.root().map(Cell::repr_hash),
            backwards.root().map(Cell::repr_hash)
        );
    }

    /// Every key stored reads back, and the walk yields them in ascending order.
    #[test]
    fn every_key_stored_reads_back_in_order((key_bits, keys) in keys()) {
        let dict = dict_of(key_bits, &keys);
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        let walked: Vec<Vec<u8>> = dict.iter().map(|entry| entry.unwrap().0).collect();
        prop_assert_eq!(walked, sorted);
        for key in &keys {
            let found = dict.get(key).unwrap().found().unwrap();
            prop_assert_eq!(found.slice().unwrap().load_bytes(key.len()).unwrap(), key.clone());
        }
    }

    /// Taking a key out leaves the dictionary the same keys would have built without it.
    ///
    /// A removal has to undo the split its insertion made, label and all. Comparing
    /// against a dictionary built from the remaining keys is what says it did, since a
    /// tree that merely read back correctly would pass any round trip.
    #[test]
    fn removing_a_key_leaves_the_dictionary_that_never_held_it((key_bits, keys) in keys()) {
        for dropped in &keys {
            let mut edited = dict_of(key_bits, &keys);
            prop_assert!(edited.remove(dropped).unwrap());
            let rest: Vec<Vec<u8>> = keys.iter().filter(|k| *k != dropped).cloned().collect();
            let never = dict_of(key_bits, &rest);
            prop_assert_eq!(
                edited.root().map(Cell::repr_hash),
                never.root().map(Cell::repr_hash)
            );
        }
    }
}
