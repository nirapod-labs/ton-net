//! The TON cell model and bag-of-cells codec for ton-net.
//!
//! A [`Cell`] is TON's universal container: up to 1023 bits of data and up to four
//! references to other cells, forming a directed acyclic graph. Every structure on TON,
//! an account, a block, a contract's code, is a tree of cells. A cell is either
//! [ordinary](CellType::Ordinary) or one of four exotic kinds the cell model gives a
//! meaning, which is what makes Merkle proofs possible.
//!
//! [`parse_boc`] reads the serialized form, a bag of cells, into the root cells it
//! holds. [`Cell::parse`] opens a [`Slice`], a cursor that reads typed values out of a
//! cell's bits and references.
//!
//! # Untrusted input
//!
//! A bag of cells arrives from a liteserver, which this client does not trust, and a
//! Merkle proof is attacker-shaped by design. Parsing therefore never panics and never
//! allocates on a declared size it has not checked: it returns [`CellError`] instead,
//! and refuses a bag past [`MAX_CELLS`] or [`MAX_DEPTH`], a reference that does not
//! point strictly forward, or a cell whose descriptors and data disagree.
//!
//! # This release
//!
//! This release parses and reads. Representation hashing and serialization arrive with
//! the proof engine, and the cell model here carries the level mask and exotic kinds
//! they need.
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
mod cell;
mod error;
mod slice;

pub use boc::{parse_boc, MAX_CELLS, MAX_DEPTH};
pub use cell::{Cell, CellType};
pub use error::CellError;
pub use slice::Slice;
