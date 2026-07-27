// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag of cells once, then building its cells one at a time and keeping them.
//!
//! [`materialize`](super::BocView::materialize) builds a bag's whole graph at once. A
//! [`LazyBoc`] reads the bag once, then builds the cell at an index only when it is asked
//! for, and keeps every cell it builds, so a caller that needs part of a large bag pays for
//! that part and pays nothing to read it again. The kept cells sit in the reader, not in the
//! cells themselves, so a [`Cell`] stays the immutable value it is everywhere else.
//!
//! The first of those two costs is paid once, at [`open`](LazyBoc::open). What the reader
//! keeps from there is the cells as they were read and never the bytes, so a `LazyBoc`
//! carries no lifetime and outlives the buffer it was read from.

use std::cell::RefCell;

use super::{build_at, read_cells, read_header, Build, Header, ParseOptions, RawCells, Reader};
use crate::cell::Cell;
use crate::error::CellError;

/// A bag of cells read once, with its cells built on demand and kept.
///
/// Built with [`open`](LazyBoc::open), which reads and checks the bag's header and every one
/// of its cells while building none of them. From there [`cell`](LazyBoc::cell) builds one
/// cell along with the subtree it reaches, and keeps all of them, so asking twice builds
/// once and asking for a cell beneath one already built builds nothing at all.
pub struct LazyBoc {
    header: Header,
    raw: RawCells,
    build: RefCell<Build>,
}

impl LazyBoc {
    /// Reads and checks a bag, its header and then its cells, building none of them.
    ///
    /// # Errors
    ///
    /// As [`BocView::open`](super::BocView::open) for the header it reads, and as
    /// [`BocView::materialize`](super::BocView::materialize) for the cells.
    pub fn open(bytes: &[u8]) -> Result<Self, CellError> {
        Self::open_with(bytes, &ParseOptions::default())
    }

    /// Reads and checks a bag under bounds the caller has narrowed, building none of it.
    ///
    /// This is [`open`](LazyBoc::open) with the crate's own bounds tightened, on the same
    /// terms as [`parse_boc_with`](super::parse_boc_with).
    ///
    /// # Errors
    ///
    /// As [`open`](LazyBoc::open), and as
    /// [`parse_boc_with`](super::parse_boc_with) for the ceiling `options` names.
    pub fn open_with(bytes: &[u8], options: &ParseOptions) -> Result<Self, CellError> {
        let mut reader = Reader { bytes, at: 0 };
        let header = read_header(&mut reader, bytes, *options)?;
        let mut reader = Reader {
            bytes,
            at: header.body_offset,
        };
        let raw = read_cells(&mut reader, &header)?;
        let build = Build::new(header.count);
        Ok(Self {
            header,
            raw,
            build: RefCell::new(build),
        })
    }

    /// The number of cells the bag carries.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.raw.len()
    }

    /// The number of root cells the bag is read from.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.header.root_list.len()
    }

    /// The number of cells built and kept so far.
    ///
    /// Building one cell builds the subtree it reaches, and all of it is kept, so this rises
    /// by a subtree rather than by one.
    #[must_use]
    pub fn built_count(&self) -> usize {
        // The borrow is taken and dropped inside this call, never held across another, so it
        // cannot conflict with the borrows `cell` takes.
        self.build.borrow().count()
    }

    /// The number of cells this reader has built, counting one built twice twice.
    ///
    /// This is [`built_count`](LazyBoc::built_count) plus whatever work was repeated, so the
    /// two are equal exactly when nothing has been built more than once. A rebuilt cell is
    /// equal to the one it replaced and takes the same place, so no count of cells held says
    /// it happened. The other thing that does is [`Cell::ptr_eq`](crate::Cell::ptr_eq), which
    /// asks whether two handles are one cell rather than two equal ones.
    #[must_use]
    pub fn builds_run(&self) -> usize {
        self.build.borrow().builds()
    }

    /// Builds the cell at `index` along with the subtree it reaches, keeping every one, or
    /// returns the cell already built there.
    ///
    /// `index` is a position among the bag's cells in the order it stores them, the roots
    /// first, up to [`cell_count`](LazyBoc::cell_count).
    ///
    /// # Errors
    ///
    /// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
    /// [`BocView::materialize`](super::BocView::materialize) for the cells it builds.
    pub fn cell(&self, index: usize) -> Result<Cell, CellError> {
        // The borrow is taken and dropped inside this call. Building reaches no code that
        // borrows again, so it cannot conflict with itself.
        let mut build = self.build.borrow_mut();
        build_at(&self.raw, &mut build, index)
    }

    /// The nth root cell, built and kept.
    ///
    /// # Errors
    ///
    /// [`CellError::BadReference`] if `n` is past the root count, and otherwise as
    /// [`cell`](LazyBoc::cell).
    pub fn root(&self, n: usize) -> Result<Cell, CellError> {
        let index = self
            .header
            .root_list
            .get(n)
            .copied()
            .ok_or(CellError::BadReference)?;
        self.cell(index)
    }

    /// The bag's root cells, built and kept, the roots [`materialize`] returns.
    ///
    /// [`materialize`]: super::BocView::materialize
    ///
    /// # Errors
    ///
    /// As [`cell`](LazyBoc::cell) for the roots it builds.
    pub fn roots(&self) -> Result<Vec<Cell>, CellError> {
        self.header
            .root_list
            .clone()
            .into_iter()
            .map(|index| self.cell(index))
            .collect()
    }

    /// Builds each of `indices` and keeps them, so a later read of any is free.
    ///
    /// # Errors
    ///
    /// As [`cell`](LazyBoc::cell) for the first index that will not build.
    pub fn prewarm(&self, indices: &[usize]) -> Result<(), CellError> {
        for &index in indices {
            self.cell(index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_boc, serialize_boc, Builder};

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

    /// A four-cell bag: a root over two parents that share one child, so a cell reached by
    /// two paths is exercised as well as a plain chain.
    fn shared_child_bag() -> Vec<u8> {
        let mut child = Builder::new();
        child.store_uint(0xcd, 8).expect("a byte fits");
        let child = child.build().expect("a cell forms");

        let parent = |tag: u64| {
            let mut b = Builder::new();
            b.store_uint(tag, 8).expect("a byte fits");
            b.store_ref(child.clone()).expect("a ref fits");
            b.build().expect("a cell forms")
        };
        let mut root = Builder::new();
        root.store_uint(0xab, 8).expect("a byte fits");
        root.store_ref(parent(0xa1)).expect("a ref fits");
        root.store_ref(parent(0xa2)).expect("a ref fits");
        serialize_boc(&[root.build().expect("a cell forms")]).expect("serializes")
    }

    #[test]
    fn a_lazily_built_cell_is_the_one_parse_boc_builds() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        let parsed = parse_boc(&bag).expect("parses").remove(0);
        assert_eq!(
            lazy.cell(0).expect("builds").repr_hash(),
            parsed.repr_hash()
        );
    }

    #[test]
    fn a_bag_is_read_once_and_the_bytes_are_not_kept() {
        // The buffer is dropped before the first read, so a reader that went back to the
        // bytes would not compile here.
        let lazy = {
            let bag = two_cell_bag();
            LazyBoc::open(&bag).expect("the header reads")
        };
        let root = lazy.cell(0).expect("builds without the bytes");
        assert_eq!(root.data(), &[0xab]);
        assert_eq!(root.refs().len(), 1);
    }

    #[test]
    fn building_a_cell_keeps_the_subtree_it_reaches() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        assert_eq!(lazy.built_count(), 0, "nothing is built at open");

        lazy.cell(0).expect("builds the root");
        assert_eq!(lazy.built_count(), 2, "the root and the leaf under it");
    }

    #[test]
    fn a_cell_under_one_already_built_builds_nothing() {
        let bag = shared_child_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");

        lazy.cell(0).expect("builds the root");
        let after_root = lazy.builds_run();
        assert_eq!(after_root, 4, "the root, both parents and the shared child");

        let kept: Vec<_> = (0..lazy.cell_count())
            .map(|index| lazy.cell(index).expect("the kept cell"))
            .collect();
        assert_eq!(
            lazy.builds_run(),
            after_root,
            "asking for a cell already built built it again"
        );
        for (index, cell) in kept.iter().enumerate() {
            assert!(
                cell.ptr_eq(&lazy.cell(index).expect("the kept cell")),
                "cell {index} came back as a second copy of itself"
            );
        }
    }

    #[test]
    fn a_cell_built_before_its_parent_is_left_where_it_is() {
        // The other order, and the one the walk has to get right on its own: a caller reads a
        // cell deep in the bag, then later reads something above it. The parent's walk runs
        // over ground already built, and has to step around it rather than through it.
        let bag = shared_child_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");

        let deepest = lazy.cell_count() - 1;
        let child = lazy.cell(deepest).expect("builds the deepest cell");
        assert_eq!(lazy.builds_run(), 1, "the one cell, with nothing under it");

        let root = lazy.cell(0).expect("builds the root above it");
        assert_eq!(
            lazy.builds_run(),
            lazy.cell_count(),
            "the cells above it, and not that one over again"
        );
        assert!(
            child.ptr_eq(
                root.reference(0)
                    .expect("a parent")
                    .reference(0)
                    .expect("the child under it")
            ),
            "building the root replaced the cell that was built under it"
        );
    }

    #[test]
    fn a_cell_asked_for_twice_is_the_same_cell() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        let first = lazy.cell(1).expect("builds");
        let again = lazy.cell(1).expect("the kept cell");
        // Equal is not enough: a rebuilt cell is equal to the one it replaced.
        assert!(first.ptr_eq(&again), "the second ask rebuilt the cell");
        assert_eq!(lazy.builds_run(), 1, "and did so without building anything");
        assert_eq!(again.data(), &[0xcd]);
    }

    #[test]
    fn a_shared_cell_is_built_once_and_reached_by_both_parents() {
        let bag = shared_child_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        let root = lazy.cell(0).expect("builds");
        let left = root.reference(0).expect("a first parent");
        let right = root.reference(1).expect("a second parent");
        assert!(
            left.reference(0)
                .expect("the shared child")
                .ptr_eq(right.reference(0).expect("the shared child")),
            "each parent got a copy of the child rather than the child"
        );
        assert_eq!(
            lazy.builds_run(),
            4,
            "the bag holds four cells and the walk built one of them twice"
        );
    }

    #[test]
    fn prewarm_keeps_the_asked_for_cells() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        lazy.prewarm(&[1]).expect("prewarms");
        assert_eq!(
            lazy.built_count(),
            1,
            "the leaf alone, not the root above it"
        );
        assert_eq!(lazy.cell(1).expect("kept").data(), &[0xcd]);
    }

    #[test]
    fn the_roots_are_the_ones_parse_boc_reads() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        let parsed = parse_boc(&bag).expect("parses");
        let roots = lazy.roots().expect("builds the roots");
        assert_eq!(roots.len(), parsed.len());
        assert_eq!(roots[0].repr_hash(), parsed[0].repr_hash());
    }

    #[test]
    fn a_root_index_past_the_count_is_refused() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        assert_eq!(lazy.root(1).err(), Some(CellError::BadReference));
    }

    #[test]
    fn a_cell_index_past_the_count_is_refused() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        assert_eq!(lazy.cell_count(), 2);
        assert_eq!(lazy.cell(2).err(), Some(CellError::BadReference));
    }

    #[test]
    fn a_corrupt_bag_is_refused_at_open() {
        // Every cell is read at open, so a bag that will not read fails there rather than at
        // whichever cell a caller happens to ask for first.
        let mut bag = two_cell_bag();
        let at = bag.len() - 2;
        bag[at] ^= 0xff;
        assert!(LazyBoc::open(&bag).is_err());
    }
}
