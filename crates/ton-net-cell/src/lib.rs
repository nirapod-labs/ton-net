// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// A library that decodes bytes from a peer it does not trust must fail by returning, not
// by unwinding: a panic in a decoder is a denial of service in whatever process embedded
// it. The lints sit on the library because a test is the opposite case, where an unwrap
// is the assertion. Arithmetic is deliberately not in the set: every count these formats
// carry is bounded before it is used, and each subtraction sits within a few lines of the
// guard that makes it safe, so denying it would bury the real bounds under checked_sub.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::indexing_slicing
)]

//! The TON cell model and bag-of-cells codec for ton-net.
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
//! is the way back: outside this crate a cell comes from parsing or from a builder and
//! from nowhere else.
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
//! This is an internal crate of the ton-net client.
//!
//! # Examples
//!
//! ```
//! use ton_net_cell::parse_boc;
//!
//! // A bag of cells holding one cell of eight bits.
//! let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
//!              0x00, 0x02, 0xab];
//! let roots = parse_boc(&bytes)?;
//! let mut slice = roots[0].parse();
//! assert_eq!(slice.load_uint(8)?, 0xab);
//! # Ok::<(), ton_net_cell::CellError>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod boc;
mod builder;
mod cell;
mod dict;
mod error;
mod merkle;
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
    file_hash, parse_boc, serialize_boc, serialize_boc_with, BocOptions, BocView, MAX_CELLS,
    MAX_DEPTH,
};
pub use builder::Builder;
#[cfg(feature = "json")]
pub use cell::json;
pub use cell::{Cell, CellType, MAX_BITS, MAX_REFS};
pub use dict::{
    AugDict, AugDictIter, AugEntry, Augmentation, Dict, DictEntry, DictIter, ForkExtra, Lookup,
};
pub use error::CellError;
pub use merkle::{
    apply_update, combine_updates, create_proof, create_update, is_virtualized, may_apply,
    rebuild_with_refs, validate_update, virtualize,
};
pub use slice::{MsgAddress, Slice};
pub use usage::UsageTree;

// The README ships to crates.io and cannot be replaced once a version is published,
// so its examples are compiled here rather than trusted. Doc-only: this does not
// appear in the rendered documentation.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;
