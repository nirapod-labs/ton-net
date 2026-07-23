// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag of cells one cell at a time, keeping what it builds.
//!
//! [`materialize`](super::BocView::materialize) builds a bag's whole graph at once. A
//! [`LazyBoc`] builds the cell at an index only when it is asked for, and keeps each cell it
//! builds, so a caller that needs part of a large bag pays to build that part and a later
//! read of the same cell is free. The kept cells sit in the reader, not in the cells
//! themselves, so a [`Cell`] stays the immutable value it is everywhere else.

use std::cell::RefCell;
use std::collections::HashMap;

use super::BocView;
use crate::cell::Cell;
use crate::error::CellError;

/// A bag of cells read one cell at a time, keeping each cell it builds.
///
/// Built with [`open`](LazyBoc::open), which reads and checks the header exactly as
/// [`BocView::open`](super::BocView::open) does. From there [`cell`](LazyBoc::cell) builds one
/// cell of the bag on demand, and every cell built is kept, so asking twice builds once. A
/// building of one cell builds the subtree it reaches, but only the cell asked for is kept by
/// its index; [`prewarm`](LazyBoc::prewarm) is the way to keep a chosen set.
pub struct LazyBoc<'a> {
    view: BocView<'a>,
    built: RefCell<HashMap<usize, Cell>>,
}

impl<'a> LazyBoc<'a> {
    /// Reads and checks a bag's header without building any of its cells.
    ///
    /// # Errors
    ///
    /// As [`BocView::open`](super::BocView::open), for the header it reads.
    pub fn open(bytes: &'a [u8]) -> Result<Self, CellError> {
        Ok(Self {
            view: BocView::open(bytes)?,
            built: RefCell::new(HashMap::new()),
        })
    }

    /// The number of cells the bag carries.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.view.cell_count()
    }

    /// The number of root cells the bag is read from.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.view.root_count()
    }

    /// The number of cells built and kept so far.
    #[must_use]
    pub fn built_count(&self) -> usize {
        // The borrow is taken and dropped inside this call, never held across another, so it
        // cannot conflict with the borrows `cell` takes.
        self.built.borrow().len()
    }

    /// Builds the cell at `index`, or returns the one already built there.
    ///
    /// `index` is a position among the bag's cells in the order it stores them, the roots
    /// first, up to [`cell_count`](LazyBoc::cell_count).
    ///
    /// # Errors
    ///
    /// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
    /// [`BocView::materialize`](super::BocView::materialize) for the cells it reads and builds.
    pub fn cell(&self, index: usize) -> Result<Cell, CellError> {
        if let Some(cell) = self.built.borrow().get(&index) {
            return Ok(cell.clone());
        }
        let cell = self.view.cell(index)?;
        self.built.borrow_mut().insert(index, cell.clone());
        Ok(cell)
    }

    /// The nth root cell, built and kept.
    ///
    /// # Errors
    ///
    /// [`CellError::BadReference`] if `n` is past the root count, and otherwise as
    /// [`cell`](LazyBoc::cell).
    pub fn root(&self, n: usize) -> Result<Cell, CellError> {
        let index = self
            .view
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
        self.view
            .header
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
    fn a_cell_is_kept_once_it_is_built() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        assert_eq!(lazy.built_count(), 0, "nothing is built at open");
        lazy.cell(0).expect("builds the root");
        assert_eq!(lazy.built_count(), 1);
        // Asking again keeps the count where it was: the kept cell answered.
        let again = lazy.cell(0).expect("the kept cell");
        assert_eq!(lazy.built_count(), 1);
        assert_eq!(
            again.repr_hash(),
            lazy.cell(0).expect("still kept").repr_hash()
        );
    }

    #[test]
    fn prewarm_keeps_the_asked_for_cells() {
        let bag = two_cell_bag();
        let lazy = LazyBoc::open(&bag).expect("the header reads");
        lazy.prewarm(&[0, 1]).expect("prewarms");
        assert_eq!(lazy.built_count(), 2);
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
}
