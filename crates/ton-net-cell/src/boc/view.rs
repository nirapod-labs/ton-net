// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag of cells in two steps: its header, then its cells on demand.
//!
//! [`parse_boc`](super::parse_boc) reads a bag whole. A [`BocView`] splits that in two: it
//! reads and checks the header, which is cheap and builds no cells, and leaves the cells for
//! a later call. That lets a large or unfamiliar bag be inspected, its cells counted or its
//! flags read, and refused if it is corrupt, before anything is allocated for its graph.
//!
//! From there a bag can be taken two ways. [`materialize`](BocView::materialize) builds the
//! whole graph, as `parse_boc` does. [`verify`](BocView::verify) checks every cell and
//! returns only the roots' hashes, keeping a summary per cell rather than a cell, so a bag
//! too large to hold as a graph can still be verified and its identity read.

use super::{build_cell, read_and_build, read_header, verify_roots, Header, Reader};
use crate::cell::Cell;
use crate::error::CellError;

/// A bag of cells read only as far as its header.
///
/// Built with [`open`](BocView::open), which runs every check
/// [`parse_boc`](super::parse_boc) runs on a bag's header, and [`materialize`] to build the
/// cells once the header has been looked at. The view borrows the bag's bytes, so the cells
/// can be built from them whenever the caller is ready.
///
/// [`materialize`]: BocView::materialize
pub struct BocView<'a> {
    bytes: &'a [u8],
    header: Header,
}

impl<'a> BocView<'a> {
    /// Reads and checks a bag's header without building any of its cells.
    ///
    /// This runs the magic, field-size, checksum and size-accounting checks that
    /// [`parse_boc`](super::parse_boc) runs, so a view that opens describes a well-formed
    /// bag. What it leaves undone is the cell graph, which [`materialize`](BocView::materialize)
    /// builds, so a bag can be counted or refused before it is built.
    ///
    /// # Errors
    ///
    /// As [`parse_boc`](super::parse_boc), for the header it reads.
    pub fn open(bytes: &'a [u8]) -> Result<Self, CellError> {
        let mut reader = Reader { bytes, at: 0 };
        let header = read_header(&mut reader, bytes)?;
        Ok(Self { bytes, header })
    }

    /// The number of cells the bag carries.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.header.count
    }

    /// The number of root cells the bag is read from.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.header.root_list.len()
    }

    /// Whether the bag carries a per-cell offset index.
    #[must_use]
    pub fn has_index(&self) -> bool {
        self.header.has_index
    }

    /// Whether the bag ends in a CRC-32C checksum, which [`open`](BocView::open) has already
    /// checked.
    #[must_use]
    pub fn has_checksum(&self) -> bool {
        self.header.has_checksum
    }

    /// The number of bytes the cells themselves take, past the header and index.
    #[must_use]
    pub fn cell_area_len(&self) -> usize {
        self.header.cell_area
    }

    /// Builds every cell and returns the bag's roots, the work [`open`](BocView::open) left
    /// undone.
    ///
    /// This is [`parse_boc`](super::parse_boc)'s build over the header already read, so a
    /// view opened and then materialized reads a bag exactly as `parse_boc` does, in two
    /// steps rather than one.
    ///
    /// # Errors
    ///
    /// As [`parse_boc`](super::parse_boc), for the cells it builds.
    pub fn materialize(&self) -> Result<Vec<Cell>, CellError> {
        let mut reader = Reader {
            bytes: self.bytes,
            at: self.header.body_offset,
        };
        read_and_build(&mut reader, &self.header)
    }

    /// Hash-verifies every cell in the bag and returns its roots' identities, without
    /// building the cell graph.
    ///
    /// This runs the same checks [`materialize`](BocView::materialize) runs, over the same
    /// cells, but keeps a summary of each cell, tens of bytes, rather than the cell, so a bag
    /// far larger than its graph would fit in memory can still be verified and its root hashes
    /// read. The returned hashes are the roots' representation hashes, the identities a
    /// [`materialize`](BocView::materialize) of the same bag reports through
    /// [`Cell::repr_hash`](crate::Cell::repr_hash).
    ///
    /// # Errors
    ///
    /// As [`materialize`](BocView::materialize), for the cells it reads and verifies.
    pub fn verify(&self) -> Result<Vec<[u8; 32]>, CellError> {
        let mut reader = Reader {
            bytes: self.bytes,
            at: self.header.body_offset,
        };
        verify_roots(&mut reader, &self.header)
    }

    /// Builds one cell of the bag, and only the cells it reaches.
    ///
    /// Where [`materialize`](BocView::materialize) builds the whole graph, this builds the
    /// cell at `index` and its subtree, so a single cell of a large bag is read without
    /// building the rest. `index` is a position among the bag's cells in the order the bag
    /// stores them, the roots first, up to [`cell_count`](BocView::cell_count).
    ///
    /// # Errors
    ///
    /// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
    /// [`materialize`](BocView::materialize) for the cells it reads and builds.
    pub fn cell(&self, index: usize) -> Result<Cell, CellError> {
        let mut reader = Reader {
            bytes: self.bytes,
            at: self.header.body_offset,
        };
        build_cell(&mut reader, &self.header, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_boc, serialize_boc, serialize_boc_with, BocOptions, Builder};

    /// A one-cell bag holding `byte`, with or without the offset index, and a checksum.
    fn bag_of(byte: u64, index: bool) -> Vec<u8> {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        let cell = builder.build().expect("a cell forms");
        serialize_boc_with(
            &[cell],
            &BocOptions {
                index,
                crc32c: true,
            },
        )
        .expect("serializes")
    }

    /// A two-cell bag: a root holding `0xab` and a reference holding `0xcd`.
    fn two_cell_bag() -> Vec<u8> {
        let mut child = Builder::new();
        child.store_uint(0xcd, 8).expect("a byte fits");
        let mut root = Builder::new();
        root.store_uint(0xab, 8).expect("a byte fits");
        root.store_ref(child.build().expect("a cell forms"))
            .expect("a ref fits");
        serialize_boc(&[root.build().expect("a cell forms")]).expect("serializes")
    }

    #[test]
    fn open_reads_the_header_without_building_cells() {
        let bag = bag_of(0xab, false);
        let view = BocView::open(&bag).expect("the header reads");
        assert_eq!(view.cell_count(), 1);
        assert_eq!(view.root_count(), 1);
        assert!(view.has_checksum());
        assert!(!view.has_index());
        assert!(view.cell_area_len() > 0);
    }

    #[test]
    fn a_view_reports_an_index_when_the_bag_carries_one() {
        assert!(BocView::open(&bag_of(0xab, true)).unwrap().has_index());
        assert!(!BocView::open(&bag_of(0xab, false)).unwrap().has_index());
    }

    #[test]
    fn materialize_gives_what_parse_boc_gives() {
        let bag = bag_of(0xcd, false);
        let view = BocView::open(&bag).unwrap();
        let materialized = view.materialize().expect("the cells build");
        let parsed = parse_boc(&bag).unwrap();
        assert_eq!(materialized.len(), parsed.len());
        assert_eq!(materialized[0].repr_hash(), parsed[0].repr_hash());
    }

    #[test]
    fn verify_gives_the_same_root_hashes_as_materialize() {
        let bag = two_cell_bag();
        let view = BocView::open(&bag).expect("the header reads");
        let verified = view.verify().expect("the bag verifies");
        let materialized = view.materialize().expect("the cells build");
        assert_eq!(verified.len(), materialized.len(), "one hash per root");
        for (hash, cell) in verified.iter().zip(&materialized) {
            assert_eq!(
                hash,
                cell.repr_hash(),
                "a verified root hash is the built one"
            );
        }
    }

    #[test]
    fn verify_and_materialize_agree_on_a_bag_that_parse_boc_reads() {
        let bag = two_cell_bag();
        let roots = parse_boc(&bag).expect("parse_boc reads it");
        let verified = BocView::open(&bag)
            .unwrap()
            .verify()
            .expect("verify reads it");
        assert_eq!(verified.len(), roots.len());
        assert_eq!(&verified[0], roots[0].repr_hash());
    }

    #[test]
    fn cell_builds_a_single_cell_and_its_subtree() {
        let bag = two_cell_bag();
        let view = BocView::open(&bag).expect("the header reads");
        let root = parse_boc(&bag).expect("parses").remove(0);

        // Cell zero is the root and its reference; cell one is the leaf it points to.
        let built_root = view.cell(0).expect("the root builds");
        assert_eq!(built_root.repr_hash(), root.repr_hash());
        assert_eq!(built_root.refs().len(), 1);

        let leaf = view.cell(1).expect("the leaf builds");
        assert_eq!(leaf.data(), &[0xcd]);
        assert!(leaf.refs().is_empty());
        assert_eq!(
            leaf.repr_hash(),
            root.reference(0).expect("the root's child").repr_hash()
        );
    }

    #[test]
    fn cell_refuses_an_index_past_the_count() {
        let bag = bag_of(0xab, false);
        let view = BocView::open(&bag).unwrap();
        assert_eq!(view.cell(1).err(), Some(CellError::BadReference));
    }

    #[test]
    fn a_corrupt_bag_is_refused_at_open() {
        let mut bag = bag_of(0xab, false);
        // A payload byte flipped under a checksum that still describes the original.
        let at = bag.len() - 5;
        bag[at] ^= 0xff;
        assert_eq!(BocView::open(&bag).err(), Some(CellError::Checksum));
    }
}
