// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag of cells without building its whole graph.
//!
//! [`materialize`](super::BocView::materialize) builds every cell. These two hold less than
//! that: [`verify`](BocView::verify) checks every cell but keeps a summary of each rather than
//! the cell, and [`cell`](BocView::cell) builds one cell and only the subtree it reaches.
//!
//! What they save is the graph, not the bag. Both read every cell of the bag before either
//! checks or builds anything, so what they need is still proportional to the bag's own size.

use super::{build_cell, verify_roots, BocView, Reader};
use crate::cell::Cell;
use crate::error::CellError;

impl BocView<'_> {
    /// Hash-verifies every cell in the bag and returns its roots' identities, without
    /// building the cell graph.
    ///
    /// This runs the same checks [`materialize`](BocView::materialize) runs, over the same
    /// cells, but keeps a summary of each cell, tens of bytes, rather than the cell, hundreds.
    /// The saving is the graph on top of the bag rather than the bag: every cell is read
    /// before any is checked, so a bag still has to fit. The returned hashes are the roots'
    /// representation hashes, the identities a [`materialize`](BocView::materialize) of the
    /// same bag reports through [`Cell::repr_hash`](crate::Cell::repr_hash).
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
    /// Each call reads the bag again, which is what a caller wanting one cell asks for. A
    /// caller wanting several wants [`LazyBoc`](crate::LazyBoc), which reads once and keeps
    /// what it builds.
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
