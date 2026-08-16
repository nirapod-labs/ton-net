// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The TON cell model and the bag-of-cells codec.
//!
//! A [`Cell`] is TON's universal container: up to 1023 bits of data and up to four
//! references to other cells, forming a directed acyclic graph. Every structure on TON,
//! an account, a block, a contract's code, is a tree of cells. A cell is either
//! [ordinary](CellType::Ordinary) or one of four exotic kinds the cell model gives a
//! meaning, which is what makes Merkle proofs possible.
//!
//! [`parse_boc`] reads the serialized form, a bag of cells, into the root cells it
//! holds, and [`serialize_boc`] writes one back. [`Cell::parse`] opens a [`Slice`], a
//! cursor that reads typed values out of a cell's bits and references, and [`Builder`]
//! is the way back: outside this library a cell comes from parsing or from a builder and
//! from nowhere else. Inside it, `Cell::from_parts` and `Builder::finish` are crate-private
//! and no module but this one calls either.
//!
//! A bag and a hash travel as text more often than as bytes, so [`base64_encode`] and
//! [`hex_encode`] write one down and [`base64_decode`] and [`hex_decode`] read it back.
//! What each reader takes beyond what its own encoder writes is stated on the reader:
//! base64 takes that one spelling and nothing else, hex takes either case.
//!
//! [`Dict`] is TON's dictionary, a radix tree over fixed-width keys that carries almost
//! everything a block holds. It sits here rather than above the block types because it
//! belongs to the cell model: the virtual machine has opcodes for it, and a wallet needs
//! one without needing to know what a block is. [`AugDict`] is the same tree with a
//! summary of every subtree kept in the node above it, which is the form a shard's
//! accounts and a block's transactions take.
//!
//! # Identity and proofs
//!
//! A cell's identity is its representation hash, returned by [`Cell::hash`]. The hash is
//! computed when the cell is built, following the level rules that give exotic cells
//! their meaning: at level zero a pruned branch answers with the hash of the subtree it
//! replaced, so a pruned copy of a tree hashes to the same value as the full tree. That
//! substitution is what makes a Merkle proof checkable, and [`Cell::hash_at`] reaches
//! the other levels. [`virtualize`] reads the tree a Merkle proof stands for,
//! [`create_proof`] builds one, and a [`UsageTree`] records the cells a read touches so
//! [`UsageTree::prove`] builds a proof of just those.
//!
//! # Untrusted input
//!
//! A bag of cells arrives from a liteserver, which this client does not trust, and a
//! Merkle proof is attacker-shaped by design. Parsing therefore never panics and never
//! allocates on a declared size it has not checked: it returns [`CellError`] instead,
//! and refuses a bag past [`MAX_CELLS`] or [`MAX_DEPTH`], a reference that does not
//! point strictly forward, or a cell whose descriptors and data disagree.
//!
//! # Examples
//!
//! ```
//! use ton_net::cell::parse_boc;
//!
//! // A bag of cells holding one cell of eight bits.
//! let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
//!              0x00, 0x02, 0xab];
//! let roots = parse_boc(&bytes)?;
//! let mut slice = roots[0].parse();
//! assert_eq!(slice.load_uint(8)?, 0xab);
//! # Ok::<(), ton_net::cell::CellError>(())
//! ```

// A module is public here when it is a subject a reader navigates to, not merely a file:
// each of these four owns a group of the re-exports below and carries the argument for it,
// and that argument reaches nobody from behind a private module. The flat re-exports stay,
// so every path a caller already writes keeps resolving.
pub mod boc;
pub mod codec;
pub mod dict;
pub mod merkle;

mod builder;
// `cell::cell` stutters and is kept rather than renamed. The engine is one nested tree
// rather than ten modules promoted to the crate root, so the inner name is the cell
// type's own module and renaming it would be a cosmetic edit through the largest tree in
// the library. No reader types the path: `Cell` is re-exported here and at the root.
#[allow(clippy::module_inception)]
mod cell;
mod error;
mod slice;
mod usage;

// Building a cell goes through a crate-private constructor, deliberately: outside this
// crate a cell can only come from parsing. So the properties over generated trees have
// to sit inside the crate rather than in `tests/`.
#[cfg(test)]
mod proptests;

#[cfg(feature = "compress")]
pub use boc::compress;
pub use boc::{
    file_hash, parse_boc, parse_boc_with, serialize_boc, serialize_boc_chunks,
    serialize_boc_chunks_with, serialize_boc_with, BocChunks, BocOptions, BocView, LazyBoc,
    ParseOptions, MAX_CELLS, MAX_DEPTH,
};
pub use builder::Builder;
#[cfg(feature = "json")]
pub use cell::json;
pub use cell::{Cell, CellType, Identity, MAX_BITS, MAX_REFS};
pub use codec::{base64_decode, base64_encode, hex_decode, hex_encode};
pub use dict::{
    AugDict, AugDictIter, AugEntry, AugItem, AugNode, Augmentation, Dict, DictEntry, DictIter,
    ForkExtra, Lookup, PfxDict, PfxDictIter, PfxMatch, Traverse,
};
pub use error::CellError;
pub use merkle::{
    apply_update, combine_updates, create_proof, create_update, is_virtualized, may_apply,
    rebuild_with_refs, validate_update, virtualize,
};
pub use slice::{MsgAddress, Slice};
pub use usage::UsageTree;
