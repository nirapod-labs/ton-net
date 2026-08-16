// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Controlling what a usage tree records.
//!
//! A read that walks a tree routes each load through [`note`](UsageTree::note), which marks
//! the cell it hands back so a later prune keeps exactly what was read. The tracing switch
//! turns that recording off for a stretch of reads that should stay out of the trace, and
//! [`combine`](UsageTree::combine) folds one tree's record into another taken over the same
//! tree.

use super::UsageTree;
use crate::cell::Cell;
use crate::error::CellError;
use crate::slice::Slice;

impl UsageTree {
    /// Whether a [`note`](UsageTree::note) currently records what it reads.
    #[must_use]
    pub fn is_tracing(&self) -> bool {
        self.tracing
    }

    /// Turns the load-notification recording on or off.
    ///
    /// An explicit [`mark`](UsageTree::mark) or [`mark_path`](UsageTree::mark_path) records
    /// regardless; this governs only [`note`](UsageTree::note), so a reader can stop tracing
    /// a stretch it does not want in the proof and start again after.
    pub fn set_tracing(&mut self, on: bool) {
        self.tracing = on;
    }

    /// Runs `read` with recording off, then restores whatever tracing was.
    ///
    /// This is the scoped form of [`set_tracing`](UsageTree::set_tracing): the loads `read`
    /// makes through [`note`](UsageTree::note) leave no mark, and tracing returns to its
    /// prior state after.
    pub fn without_tracing<R>(&mut self, read: impl FnOnce(&mut Self) -> R) -> R {
        let was = self.tracing;
        self.tracing = false;
        let out = read(self);
        self.tracing = was;
        out
    }

    /// Opens a cursor over `cell`, recording it as read when tracing is on.
    ///
    /// This is the load-notification a proof is built from: a reader that reaches every cell
    /// through `note` leaves behind exactly the set it touched, which is what a later
    /// [`prune`](UsageTree::prune) keeps. With tracing off the load is ignored and the
    /// cursor is the one [`Cell::parse`](crate::Cell::parse) would give.
    pub fn note<'c>(&mut self, cell: &'c Cell) -> Slice<'c> {
        if self.tracing {
            self.mark(cell);
        }
        cell.parse()
    }

    /// Folds another tree's record into this one.
    ///
    /// The two must be recorded over the same tree, since a mark only means anything against
    /// the tree it was taken over. After combining, this tree keeps every cell either kept,
    /// so a prune reveals the union of what the two reads touched.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if the two were recorded over different trees.
    pub fn combine(&mut self, other: &Self) -> Result<(), CellError> {
        if self.root.repr_hash() != other.root.repr_hash() {
            return Err(CellError::Malformed(
                "combining usage recorded over different trees",
            ));
        }
        self.used.extend(other.used.iter().copied());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Builder;

    /// An ordinary leaf holding one byte.
    fn leaf(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("a leaf is well formed")
    }

    /// An ordinary cell holding `byte` and the given children.
    fn node(byte: u64, children: &[&Cell]) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        for &child in children {
            builder.store_ref(child.clone()).expect("a reference fits");
        }
        builder.build().expect("a node is well formed")
    }

    #[test]
    fn note_records_the_cell_it_reads() {
        let child = leaf(0x11);
        let root = node(0xaa, &[&child]);
        let mut usage = UsageTree::new(root);
        assert!(!usage.touched(&child));
        let mut slice = usage.note(&child);
        assert_eq!(slice.load_uint(8).unwrap(), 0x11);
        assert!(usage.touched(&child), "the load was recorded");
    }

    #[test]
    fn a_note_with_tracing_off_is_ignored() {
        let child = leaf(0x11);
        let root = node(0xaa, &[&child]);
        let mut usage = UsageTree::new(root);
        usage.set_tracing(false);
        usage.note(&child);
        assert!(!usage.touched(&child), "the load left no mark");
        assert!(!usage.is_tracing());
    }

    #[test]
    fn without_tracing_suppresses_then_restores() {
        let seen = leaf(0x11);
        let hidden = leaf(0x22);
        let root = node(0xaa, &[&seen, &hidden]);
        let mut usage = UsageTree::new(root);
        usage.note(&seen);
        usage.without_tracing(|u| {
            u.note(&hidden);
        });
        assert!(usage.touched(&seen));
        assert!(
            !usage.touched(&hidden),
            "the hidden read stayed out of the trace"
        );
        assert!(usage.is_tracing(), "tracing is back on afterwards");
    }

    #[test]
    fn an_explicit_mark_ignores_the_tracing_switch() {
        let child = leaf(0x11);
        let root = node(0xaa, &[&child]);
        let mut usage = UsageTree::new(root);
        usage.set_tracing(false);
        usage.mark(&child);
        assert!(usage.touched(&child), "an explicit mark records regardless");
    }

    #[test]
    fn combine_unions_what_two_reads_touched() {
        let left = leaf(0x11);
        let right = leaf(0x22);
        let root = node(0xaa, &[&left, &right]);

        let mut one = UsageTree::new(root.clone());
        one.note(&left);
        let mut two = UsageTree::new(root);
        two.note(&right);

        one.combine(&two).expect("recorded over the same tree");
        assert!(one.touched(&left));
        assert!(one.touched(&right), "the other read's cells came across");
    }

    #[test]
    fn combine_refuses_two_different_trees() {
        let one = UsageTree::new(leaf(0x11));
        let mut two = UsageTree::new(leaf(0x22));
        assert_eq!(
            two.combine(&one),
            Err(CellError::Malformed(
                "combining usage recorded over different trees"
            ))
        );
    }
}
