// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! TON's dictionary: a binary radix tree over fixed-width keys.
//!
//! Each edge carries a label, a run of key bits everything below it shares, so a sparse
//! tree stays shallow. A node is a fork holding two references, or a leaf holding
//! whatever the dictionary stores; which one it is follows from how much of the key is
//! left rather than from anything in the cell.
//!
//! # The two shapes
//!
//! The plain `HashmapE n X` is [`Dict`] and the augmented `HashmapAug n X Y` is
//! [`AugDict`]. A plain fork is its label and two references and nothing else; an
//! augmented one also carries a summary of its subtree, and rebuilding it recomputes those
//! summaries rather than copying them forward. The two differ only in what a node carries
//! between its label and its value, so the descent, the split and the rebuild are written
//! once over a private `Shape` seam and shared. The label codec that gives a dictionary
//! its one canonical hash lives in the `label` submodule.

use crate::builder::Builder;
use crate::cell::{Cell, MAX_BITS};
use crate::error::CellError;
use crate::slice::Slice;

mod aug;
mod label;
mod plain;
mod typed;

pub use aug::{AugDict, AugDictIter, AugEntry, AugItem, Augmentation};
pub use plain::{Dict, DictIter};

/// A dictionary fork's key prefix and the summary it carries.
///
/// The prefix is the key bits everything below the fork shares; the summary is what the
/// fork stores over that subtree. [`AugDict::fork_extras`] yields one per interior fork.
pub type ForkExtra<E> = (Vec<bool>, E);

#[cfg(test)]
use label::bounded_width;
use label::{read_label, store_label};

/// How a lookup ended.
///
/// Over a complete dictionary only [`Found`](Lookup::Found) and [`Absent`](Lookup::Absent)
/// happen. Over a Merkle proof a third answer exists and matters: the proof covers one
/// path and replaces the rest with placeholders, so a walk can end at a placeholder
/// having learned nothing.
///
/// Keeping [`Pruned`](Lookup::Pruned) apart from [`Absent`](Lookup::Absent) is what makes
/// a proof of absence worth anything. A proof rooted at a trusted hash makes every label
/// it shows part of that hash, so a label that disagrees with the key is evidence no such
/// key exists. A placeholder is not evidence of anything, and a client that read the two
/// as one answer would accept "this account does not exist" from a server that had merely
/// declined to prove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// The dictionary holds the key.
    Found(T),
    /// The dictionary shows the key is not in it.
    Absent,
    /// A pruned branch stands where the walk had to go, so the key is unknown.
    Pruned,
}

impl<T> Lookup<T> {
    /// The value, if the key was found.
    pub fn found(self) -> Option<T> {
        match self {
            Self::Found(value) => Some(value),
            _ => None,
        }
    }
}

/// Where a lookup landed: the cell holding the leaf, and where its contents start.
///
/// The walk stops once the key is spent, which leaves the cursor just past the label.
/// [`slice`](DictEntry::slice) reopens the cell at that point, so the caller reads
/// whatever the dictionary stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictEntry {
    cell: Cell,
    bit_offset: usize,
}

impl DictEntry {
    /// The cell the leaf sits in.
    #[must_use]
    pub fn cell(&self) -> &Cell {
        &self.cell
    }

    /// A cursor positioned at the leaf's contents.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the cell is shorter than the walk recorded.
    pub fn slice(&self) -> Result<Slice<'_>, CellError> {
        let mut slice = self.cell.parse();
        slice.skip_bits(self.bit_offset)?;
        Ok(slice)
    }
}

/// What a fork missing a branch reports. A fork always has two.
const NO_BRANCH: CellError = CellError::Malformed("dictionary fork without both branches");

/// The bit of `key` at `index`, counting from the most significant bit of the first byte.
fn key_bit(key: &[u8], index: usize) -> bool {
    match key.get(index / 8) {
        Some(byte) => (byte >> (7 - (index % 8))) & 1 == 1,
        None => false,
    }
}

/// The bits of `key` from `at` onward. Every caller has already held `at` inside the key.
fn rest(key: &[bool], at: usize) -> &[bool] {
    key.get(at..).unwrap_or(&[])
}

/// Packs key bits into bytes, most significant bit of the first byte first.
fn pack(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            if let Some(byte) = out.get_mut(index / 8) {
                *byte |= 1 << (7 - (index % 8));
            }
        }
    }
    out
}

/// What a dictionary node carries between its label and its value.
///
/// A plain node carries nothing there; an augmented one carries a summary of everything
/// below it. That is the only difference between the two, so the descent, the split and
/// the rebuild below are written once over this rather than twice.
trait Shape {
    /// The summary a node carries, or `()` where it carries none.
    type Extra;

    /// Reads the summary, leaving the cursor on the value.
    ///
    /// A leaf holds `extra` then `value`, and a fork holds `extra` and two references, so
    /// in both the summary is whatever follows the label. That is what lets a node be
    /// summarised without first working out which of the two it is.
    fn read_extra(&self, slice: &mut Slice<'_>) -> Result<Self::Extra, CellError>;

    /// Writes the summary, after the label and before the value.
    fn write_extra(&self, extra: &Self::Extra, into: &mut Builder) -> Result<(), CellError>;

    /// Refuses a fork carrying anything this shape has no reading for.
    ///
    /// The cursor sits just past the label. Data neither shape accounts for would be
    /// dropped by a rebuild, so it is refused before one starts.
    fn check_fork(&self, slice: &mut Slice<'_>) -> Result<(), CellError>;

    /// The summary a fork over these two children carries.
    ///
    /// Both are read back off the cells rather than carried down from the walk, because a
    /// summary from before the change describes the subtree that used to be there.
    fn fork_extra(&self, left: &Cell, right: &Cell, below: u16) -> Result<Self::Extra, CellError>;
}

/// What a leaf holds, in the order it holds it.
struct Entry<'a, S: Shape> {
    extra: &'a S::Extra,
    value: &'a Builder,
}

/// Builds a leaf: the whole remaining key as a label, then what the leaf holds.
fn leaf<S: Shape>(
    shape: &S,
    key: &[bool],
    entry: &Entry<'_, S>,
    max: u16,
) -> Result<Cell, CellError> {
    let mut cell = Builder::new();
    store_label(&mut cell, key, max)?;
    shape.write_extra(entry.extra, &mut cell)?;
    cell.store_builder(entry.value)?;
    cell.build()
}

/// One fork on the path down, kept so the path can be rebuilt from the bottom up.
struct Step {
    node: Cell,
    label: Vec<bool>,
    remaining: u16,
    branch: usize,
}

impl Step {
    /// The key bits still to spend at either of this fork's children.
    fn below(&self) -> u16 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "read_label bounds label.len() to at most remaining, and a fork is only recorded where the label is shorter still, so this fits a u16"
        )]
        let spent = self.label.len() as u16;
        self.remaining - spent - 1
    }

    /// Rebuilds this fork with `child` in place of the branch the walk took.
    fn rebuild<S: Shape>(&self, shape: &S, child: &Cell) -> Result<Cell, CellError> {
        let sibling = self.node.reference(1 - self.branch).ok_or(NO_BRANCH)?;
        let (left, right) = if self.branch == 0 {
            (child, sibling)
        } else {
            (sibling, child)
        };

        let mut fork = Builder::new();
        store_label(&mut fork, &self.label, self.remaining)?;
        let extra = shape.fork_extra(left, right, self.below())?;
        shape.write_extra(&extra, &mut fork)?;
        fork.store_ref(left.clone())?;
        fork.store_ref(right.clone())?;
        fork.build()
    }
}

/// Refuses a key width no cell could carry as a label.
fn check_key_bits(key_bits: u16) -> Result<(), CellError> {
    if key_bits > MAX_BITS {
        return Err(CellError::Malformed("dictionary key wider than a cell"));
    }
    Ok(())
}

/// The key as a bit run, refusing one too short to be a key of a `key_bits` dictionary.
fn key_of(key: &[u8], key_bits: u16) -> Result<Vec<bool>, CellError> {
    let needed = usize::from(key_bits).div_ceil(8);
    if key.len() < needed {
        return Err(CellError::KeyLength {
            given: key.len() * 8,
            expected: usize::from(key_bits),
        });
    }
    Ok((0..usize::from(key_bits))
        .map(|index| key_bit(key, index))
        .collect())
}

/// Walks down to `bits`' leaf, reporting how the walk ended and what the leaf carries.
fn lookup<S: Shape>(
    shape: &S,
    root: Option<&Cell>,
    key_bits: u16,
    bits: &[bool],
) -> Result<Lookup<(S::Extra, DictEntry)>, CellError> {
    let Some(root) = root else {
        return Ok(Lookup::Absent);
    };

    let mut node = root.clone();
    let mut remaining = key_bits;
    let mut consumed = 0usize;

    loop {
        // A proof replaces the branches it does not cover with pruned placeholders, which
        // hold a hash rather than a dictionary node. Nothing can be read from one.
        if node.is_exotic() {
            return Ok(Lookup::Pruned);
        }

        let mut slice = node.parse();
        let label = read_label(&mut slice, remaining)?;
        // The label is the run of bits every key below this edge shares. A key that
        // disagrees with it has no entry below, and because the label is part of what the
        // root hash covers, that is evidence rather than an absence of evidence.
        if diverges(&label, rest(bits, consumed)).is_some() {
            return Ok(Lookup::Absent);
        }
        consumed += label.len();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "read_label bounds label.len() to at most its `max` argument (here `remaining`), and remaining is a u16, so this fits"
        )]
        let spent = label.len() as u16;
        remaining -= spent;

        if remaining == 0 {
            let extra = shape.read_extra(&mut slice)?;
            let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
            return Ok(Lookup::Found((
                extra,
                DictEntry {
                    cell: node,
                    bit_offset,
                },
            )));
        }

        // A fork: the next key bit chooses the branch.
        let branch = usize::from(bits.get(consumed).copied().unwrap_or(false));
        consumed += 1;
        remaining -= 1;
        node = node.reference(branch).ok_or(NO_BRANCH)?.clone();
    }
}

/// Where a key parts from the tree, and the forks passed on the way.
struct Walk {
    path: Vec<Step>,
    node: Cell,
    label: Vec<bool>,
    /// The key bits still to spend at [`node`](Walk::node).
    remaining: u16,
    /// The key bits spent above it, so `consumed + remaining` is the key width.
    consumed: usize,
    /// Where this node's label and the key disagree, if they do at all.
    diverged: Option<usize>,
}

/// Walks down to where `bits` parts from the tree, recording every fork it passes.
///
/// This is a loop rather than a recursion because its depth is the key width, which a
/// peer chooses. It stops at the first of three things: a label that disagrees with the
/// key, a key with nothing left to spend, or a branch a proof has pruned away.
///
/// Both writers share it, which is what keeps the bounds in one place. Every label is
/// read under the key bits still to spend, so it can never claim more than are left, and
/// a fork is only descended when its label is shorter than that, which is what leaves
/// room for the bit that picks the branch.
fn descend<S: Shape>(
    shape: &S,
    root: Cell,
    key_bits: u16,
    bits: &[bool],
) -> Result<Walk, CellError> {
    let mut path: Vec<Step> = Vec::new();
    let mut node = root;
    let mut remaining = key_bits;
    let mut consumed = 0usize;

    loop {
        // A pruned branch holds a hash, not a node. A change that fell inside one would
        // have to invent what it replaced.
        if node.is_exotic() {
            return Err(CellError::Pruned);
        }

        let mut slice = node.parse();
        let label = read_label(&mut slice, remaining)?;
        let len = label.len();
        let diverged = diverges(&label, rest(bits, consumed));

        if diverged.is_some() || len == usize::from(remaining) {
            return Ok(Walk {
                path,
                node,
                label,
                remaining,
                consumed,
                diverged,
            });
        }

        shape.check_fork(&mut slice)?;
        let branch = usize::from(bits.get(consumed + len).copied().unwrap_or(false));
        let child = node.reference(branch).ok_or(NO_BRANCH)?.clone();
        path.push(Step {
            node,
            label,
            remaining,
            branch,
        });
        node = child;
        consumed += len + 1;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "read_label bounds len to at most remaining, and the check above returned unless len < remaining, so this fits a u16"
        )]
        let spent = len as u16;
        remaining -= spent + 1;
    }
}

/// The first position where `label` and the key part company, if they do.
fn diverges(label: &[bool], key: &[bool]) -> Option<usize> {
    label
        .iter()
        .zip(key.iter())
        .position(|(left, right)| left != right)
}

/// Splits `node` at `at`, where its label and the key part company.
///
/// The old node keeps everything below the divergence and is relabelled with what is left
/// of its label; the new leaf takes the other branch; a fresh fork over their common
/// prefix stands where the old node stood.
fn split<S: Shape>(
    shape: &S,
    node: &Cell,
    label: &[bool],
    at: usize,
    remaining: u16,
    key: &[bool],
    entry: &Entry<'_, S>,
) -> Result<Cell, CellError> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "at is where diverges() found label and key part company, so at < label.len(), and read_label bounds label.len() to at most remaining; remaining is a u16, so this fits"
    )]
    let below = remaining - at as u16 - 1;

    let mut kept = Builder::new();
    store_label(&mut kept, rest(label, at + 1), below)?;
    let mut slice = node.parse();
    read_label(&mut slice, remaining)?;
    kept.store_slice(slice)?;
    let kept = kept.build()?;

    let fresh = leaf(shape, rest(key, at + 1), entry, below)?;

    // The old node's label decides which side it lands on: the bit they disagree on is
    // its bit, so the new leaf takes the other branch.
    let (left, right) = if label.get(at).copied().unwrap_or(false) {
        (fresh, kept)
    } else {
        (kept, fresh)
    };

    let mut fork = Builder::new();
    store_label(&mut fork, label.get(..at).unwrap_or(&[]), remaining)?;
    let extra = shape.fork_extra(&left, &right, below)?;
    shape.write_extra(&extra, &mut fork)?;
    fork.store_ref(left)?;
    fork.store_ref(right)?;
    fork.build()
}

/// Merges a fork's surviving branch into the fork, now that the other one is gone.
fn collapse(parent: &Step) -> Result<Cell, CellError> {
    let sibling = parent.node.reference(1 - parent.branch).ok_or(NO_BRANCH)?;
    if sibling.is_exotic() {
        return Err(CellError::Pruned);
    }

    let mut label = parent.label.clone();
    label.push(parent.branch == 0);
    let mut slice = sibling.parse();
    label.extend_from_slice(&read_label(&mut slice, parent.below())?);

    let mut merged = Builder::new();
    store_label(&mut merged, &label, parent.remaining)?;
    merged.store_slice(slice)?;
    merged.build()
}

/// Rebuilds every fork on the path, from the deepest up to the root.
fn rebuild<S: Shape>(shape: &S, mut path: Vec<Step>, mut child: Cell) -> Result<Cell, CellError> {
    while let Some(step) = path.pop() {
        child = step.rebuild(shape, &child)?;
    }
    Ok(child)
}

/// Re-roots at the subtree every key beginning with `want` lives under.
///
/// Walks down spending `want` a bit at a time. Where it runs out exactly at a node's edge,
/// that node already carries the right label under the right width and stands as the new
/// root unchanged. Where it runs out partway along a label, the node is rewritten with what
/// is left of that label under the narrower key the sub-dictionary spends; everything the
/// node held below is carried over untouched, so an augmented fork's summary still describes
/// the same subtree. A prefix that parts from the tree has no key under it, which is `None`.
/// A prefix that runs into a pruned branch cannot be followed, which is an error.
///
/// It is written over the cells rather than over a [`Shape`] because it neither reads nor
/// recomputes a summary: the subtree beneath the new root does not change, so whatever
/// summary it carried is still the one it should.
fn reroot(root: &Cell, key_bits: u16, want: &[bool]) -> Result<Option<Cell>, CellError> {
    let mut node = root.clone();
    let mut remaining = key_bits;
    let mut matched = 0usize;

    loop {
        if node.is_exotic() {
            return Err(CellError::Pruned);
        }
        let ahead = rest(want, matched);
        if ahead.is_empty() {
            // The prefix is spent at this node's edge, so the node is the new root as it
            // stands: its label is already written under the key the sub-dictionary spends.
            return Ok(Some(node));
        }

        let mut slice = node.parse();
        let label = read_label(&mut slice, remaining)?;
        let len = label.len();
        if diverges(&label, ahead).is_some() {
            return Ok(None);
        }

        if ahead.len() <= len {
            // The prefix ends inside this label. What is left of the label becomes the new
            // root's, under the narrower key, and the node's contents come over as they are;
            // store_slice takes both the bits and the references still ahead of the cursor.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "ahead.len() <= len and read_label bounds len to at most remaining, a u16, so ahead.len() fits a u16 and remaining - it does not underflow"
            )]
            let new_max = remaining - ahead.len() as u16;
            let mut fresh = Builder::new();
            store_label(&mut fresh, rest(&label, ahead.len()), new_max)?;
            fresh.store_slice(slice)?;
            return Ok(Some(fresh.build()?));
        }

        // The prefix reaches past this label. A leaf holds nothing past it, so a prefix that
        // long names no key; otherwise the next prefix bit picks the branch to follow.
        if len == usize::from(remaining) {
            return Ok(None);
        }
        matched += len;
        let branch = usize::from(rest(want, matched).first().copied().unwrap_or(false));
        matched += 1;
        node = node.reference(branch).ok_or(NO_BRANCH)?.clone();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the len == remaining case returned above, so len < remaining <= u16::MAX and len fits a u16 with room for the branch bit"
        )]
        let spent = len as u16;
        remaining -= spent + 1;
    }
}

/// A node a walk has still to visit: the node, the key bits spelled out above it, and the
/// bits still to spend at it.
type Pending = (Cell, Vec<bool>, u16);

/// What a walk's next step found: the key, the summary its leaf carries, and the value.
type Stepped<E> = Option<(Vec<u8>, E, DictEntry)>;

/// Descends a stacked walk to its next leaf, or reports that the walk is over.
fn walk_step<S: Shape>(
    shape: &S,
    stack: &mut Vec<Pending>,
) -> Result<Stepped<S::Extra>, CellError> {
    while let Some((node, prefix, remaining)) = stack.pop() {
        if node.is_exotic() {
            return Err(CellError::Pruned);
        }

        let mut slice = node.parse();
        let label = read_label(&mut slice, remaining)?;
        let len = label.len();
        let mut key = prefix;
        key.extend_from_slice(&label);

        if len == usize::from(remaining) {
            let extra = shape.read_extra(&mut slice)?;
            let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
            return Ok(Some((
                pack(&key),
                extra,
                DictEntry {
                    cell: node,
                    bit_offset,
                },
            )));
        }

        // The right branch goes on first so the left one comes off first, which is what
        // puts the keys in ascending order.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "read_label bounds len to at most remaining, and the check above returned unless len < remaining, so this fits a u16"
        )]
        let below = remaining - len as u16 - 1;
        for branch in [1usize, 0usize] {
            let child = node.reference(branch).ok_or(NO_BRANCH)?.clone();
            let mut key = key.clone();
            key.push(branch == 1);
            stack.push((child, key, below));
        }
    }
    Ok(None)
}

/// Every fork's stored summary, with the key prefix that leads to it, in pre-order.
///
/// A leaf carries a summary too, but [`walk_step`] already reads those alongside their
/// keys; this is the complement, the summaries the interior forks carry. A pruned branch
/// is opaque, so the walk does not descend into one.
fn collect_fork_extras<S: Shape>(
    shape: &S,
    root: Option<&Cell>,
    key_bits: u16,
) -> Result<Vec<ForkExtra<S::Extra>>, CellError> {
    let mut out = Vec::new();
    if let Some(root) = root {
        collect_forks(shape, root, key_bits, Vec::new(), &mut out)?;
    }
    Ok(out)
}

/// Descends `node`, pushing each fork's summary onto `out`. `prefix` is the key bits above
/// it.
fn collect_forks<S: Shape>(
    shape: &S,
    node: &Cell,
    remaining: u16,
    prefix: Vec<bool>,
    out: &mut Vec<(Vec<bool>, S::Extra)>,
) -> Result<(), CellError> {
    if node.is_exotic() {
        return Ok(());
    }
    let mut slice = node.parse();
    let label = read_label(&mut slice, remaining)?;
    let len = label.len();
    let mut here = prefix;
    here.extend_from_slice(&label);
    if len < usize::from(remaining) {
        out.push((here.clone(), shape.read_extra(&mut slice)?));
        #[allow(
            clippy::cast_possible_truncation,
            reason = "read_label bounds len to at most remaining, and this branch runs only when len < remaining, so len fits a u16"
        )]
        let below = remaining - len as u16 - 1;
        let left = node.reference(0).ok_or(NO_BRANCH)?;
        let right = node.reference(1).ok_or(NO_BRANCH)?;
        let mut left_prefix = here.clone();
        left_prefix.push(false);
        collect_forks(shape, left, below, left_prefix, out)?;
        here.push(true);
        collect_forks(shape, right, below, here, out)?;
    }
    Ok(())
}

/// Checks every fork's stored summary is the one its children combine to.
///
/// This is the read-side complement of the combine a write performs: it rebuilds each fork
/// in place, recomputing the summary from the children as stored, and requires the rebuilt
/// node to hash to the one on the tree. A pruned child cannot be summarised, so a fork
/// above one is left unchecked while the rest of the visible tree still is.
fn validate_tree<S: Shape>(shape: &S, root: Option<&Cell>, key_bits: u16) -> Result<(), CellError> {
    match root {
        None => Ok(()),
        Some(root) => validate_node(shape, root, key_bits),
    }
}

/// Checks `node` and everything visible below it.
fn validate_node<S: Shape>(shape: &S, node: &Cell, remaining: u16) -> Result<(), CellError> {
    if node.is_exotic() {
        return Ok(());
    }
    let mut slice = node.parse();
    let label = read_label(&mut slice, remaining)?;
    let len = label.len();
    if len == usize::from(remaining) {
        return Ok(());
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "read_label bounds len to at most remaining, and this runs only when len < remaining, so len fits a u16"
    )]
    let below = remaining - len as u16 - 1;
    let left = node.reference(0).ok_or(NO_BRANCH)?;
    let right = node.reference(1).ok_or(NO_BRANCH)?;

    // A fork whose child is pruned cannot have its summary recomputed, so its own check is
    // skipped; the visible child is still walked.
    if !left.is_exotic() && !right.is_exotic() {
        let mut fork = Builder::new();
        store_label(&mut fork, &label, remaining)?;
        let extra = shape.fork_extra(left, right, below)?;
        shape.write_extra(&extra, &mut fork)?;
        fork.store_ref(left.clone())?;
        fork.store_ref(right.clone())?;
        if fork.build()?.repr_hash() != node.repr_hash() {
            return Err(CellError::Malformed(
                "augmented fork summary disagrees with its children",
            ));
        }
    }

    validate_node(shape, left, below)?;
    validate_node(shape, right, below)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dictionary over 32-bit keys holding `keys`, each under its own value.
    fn built(key_bits: u16, keys: &[u32]) -> Dict {
        let mut dict = Dict::new(key_bits).unwrap();
        for key in keys {
            dict.set(&key.to_be_bytes(), &value(*key)).unwrap();
        }
        dict
    }

    fn value(seed: u32) -> Builder {
        let mut builder = Builder::new();
        builder.store_uint(u64::from(seed), 32).unwrap();
        builder
    }

    fn hash(dict: &Dict) -> Option<[u8; 32]> {
        dict.root().map(|root| *root.repr_hash())
    }

    #[test]
    fn a_bounded_width_holds_every_value_up_to_the_maximum() {
        // A 256-bit dictionary labels lengths 0..=256, which needs nine bits.
        assert_eq!(bounded_width(256), 9);
        assert_eq!(bounded_width(255), 8);
        assert_eq!(bounded_width(30), 5);
        assert_eq!(bounded_width(1), 1);
    }

    #[test]
    fn key_bits_read_most_significant_first() {
        let key = [0b1010_0000u8, 0b0000_0001];
        assert!(key_bit(&key, 0));
        assert!(!key_bit(&key, 1));
        assert!(key_bit(&key, 2));
        assert!(key_bit(&key, 15));
        // Past the end reads as zero rather than panicking.
        assert!(!key_bit(&key, 999));
    }

    #[test]
    fn a_key_shorter_than_the_dictionary_is_refused() {
        let dict = built(256, &[]);
        assert!(matches!(
            dict.get(&[0u8; 4]),
            Err(CellError::KeyLength { .. })
        ));
    }

    #[test]
    fn a_label_takes_the_shortest_encoding_and_a_tie_goes_to_the_short_form() {
        // A one-bit label with one bit of key left: the unary form is 0-1-0-v, the
        // explicit form is 10-1-v, the repeated form is 11-v-1, and all three come to
        // four bits. Mainnet writes the first. Choosing another parses back the same
        // and hashes differently.
        let mut builder = Builder::new();
        store_label(&mut builder, &[false], 1).unwrap();
        assert_eq!(builder.bits_used(), 4);
        let cell = builder.build().unwrap();
        let mut slice = cell.parse();
        assert_eq!(slice.load_uint(4).unwrap(), 0b0100);

        // With room for a longer label the explicit form wins: 2 + 9 + 200 beats 402.
        let long = [true, false].repeat(100);
        let mut builder = Builder::new();
        store_label(&mut builder, &long, 256).unwrap();
        assert_eq!(builder.bits_used(), 2 + 9 + 200);
        assert_eq!(builder.build().unwrap().parse().load_uint(2).unwrap(), 0b10);

        // A run of one repeated bit is spelled out once: 2 + 1 + 9 beats both.
        let mut builder = Builder::new();
        store_label(&mut builder, &[true; 200], 256).unwrap();
        assert_eq!(builder.bits_used(), 12);
        assert_eq!(builder.build().unwrap().parse().load_uint(2).unwrap(), 0b11);

        // An empty label is the two bits that say so.
        let mut builder = Builder::new();
        store_label(&mut builder, &[], 256).unwrap();
        assert_eq!(builder.bits_used(), 2);
    }

    #[test]
    fn every_label_this_writes_reads_back_as_itself() {
        for (label, max) in [
            (vec![], 0u16),
            (vec![], 256),
            (vec![true], 1),
            (vec![false; 200], 256),
            (vec![true, false, true, true, false], 8),
            (vec![true; 32], 32),
            ([true, false].repeat(100), 256),
        ] {
            let mut builder = Builder::new();
            store_label(&mut builder, &label, max).unwrap();
            let cell = builder.build().unwrap();
            assert_eq!(read_label(&mut cell.parse(), max).unwrap(), label);
        }
    }

    #[test]
    fn a_label_longer_than_the_key_it_labels_is_refused() {
        let mut builder = Builder::new();
        assert_eq!(
            store_label(&mut builder, &[true; 9], 8),
            Err(CellError::LabelTooLong)
        );
    }

    #[test]
    fn a_stored_key_reads_back() {
        let dict = built(32, &[7]);
        let Lookup::Found(entry) = dict.get(&7u32.to_be_bytes()).unwrap() else {
            panic!("the key was stored")
        };
        assert_eq!(entry.slice().unwrap().load_uint(32).unwrap(), 7);
        assert_eq!(dict.get(&8u32.to_be_bytes()).unwrap(), Lookup::Absent);
    }

    #[test]
    fn the_order_keys_arrive_in_does_not_change_the_dictionary() {
        // A radix tree has one shape per key set. If a split or a relabel were wrong,
        // the two orders would disagree here well before any hash from mainnet did.
        let ascending = built(32, &[1, 2, 3, 100, 1000, 70_000, 0xffff_ffff]);
        let descending = built(32, &[0xffff_ffff, 70_000, 1000, 100, 3, 2, 1]);
        let shuffled = built(32, &[1000, 1, 0xffff_ffff, 3, 70_000, 2, 100]);
        assert_eq!(hash(&ascending), hash(&descending));
        assert_eq!(hash(&ascending), hash(&shuffled));
    }

    #[test]
    fn storing_a_key_twice_replaces_its_value() {
        let mut dict = built(32, &[1, 2, 3]);
        dict.set(&2u32.to_be_bytes(), &value(999)).unwrap();
        let Lookup::Found(entry) = dict.get(&2u32.to_be_bytes()).unwrap() else {
            panic!("the key is there")
        };
        assert_eq!(entry.slice().unwrap().load_uint(32).unwrap(), 999);
        assert_eq!(dict.iter().count(), 3);
    }

    #[test]
    fn removing_a_key_leaves_the_dictionary_that_never_held_it() {
        // The collapse a removal performs has to undo the split an insert performed, so
        // the surviving tree must be the one built from the remaining keys alone. A
        // dictionary that read back correctly but kept a stale edge would fail here.
        let keys = [1u32, 2, 3, 100, 1000, 70_000, 0xffff_ffff];
        for dropped in keys {
            let mut dict = built(32, &keys);
            assert!(dict.remove(&dropped.to_be_bytes()).unwrap());
            let rest: Vec<u32> = keys.iter().copied().filter(|k| *k != dropped).collect();
            assert_eq!(hash(&dict), hash(&built(32, &rest)), "dropping {dropped}");
        }
    }

    #[test]
    fn removing_the_only_key_empties_the_dictionary() {
        let mut dict = built(32, &[42]);
        assert!(dict.remove(&42u32.to_be_bytes()).unwrap());
        assert!(dict.is_empty());
        assert_eq!(dict.get(&42u32.to_be_bytes()).unwrap(), Lookup::Absent);
    }

    #[test]
    fn removing_a_key_that_is_not_there_changes_nothing() {
        let mut dict = built(32, &[1, 2, 3]);
        let before = hash(&dict);
        assert!(!dict.remove(&9u32.to_be_bytes()).unwrap());
        assert_eq!(hash(&dict), before);
        assert!(!Dict::new(32).unwrap().remove(&1u32.to_be_bytes()).unwrap());
    }

    #[test]
    fn iteration_yields_every_key_in_ascending_order() {
        let keys = [0u32, 1, 2, 3, 100, 1000, 70_000, 0x8000_0000, 0xffff_ffff];
        let dict = built(32, &keys);
        let walked: Vec<u32> = dict
            .iter()
            .map(|entry| {
                let (key, found) = entry.unwrap();
                // The value each key was stored under is the key itself, so a walk that
                // paired a key with the wrong leaf would show up here.
                assert_eq!(
                    found.slice().unwrap().load_u32().unwrap(),
                    u32::from_be_bytes(key.clone().try_into().unwrap())
                );
                u32::from_be_bytes(key.try_into().unwrap())
            })
            .collect();
        assert_eq!(walked, keys);
        assert_eq!(Dict::new(32).unwrap().iter().count(), 0);
    }

    #[test]
    fn a_walk_reaches_the_widest_keys() {
        // 256 bits is what the accounts dictionary uses, and a key that wide is spelled
        // out over more edges than any narrower one.
        let mut dict = Dict::new(256).unwrap();
        let keys: Vec<[u8; 32]> = (0..16u8)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i << 4;
                key[31] = i;
                key
            })
            .collect();
        for key in &keys {
            dict.set(key, &value(u32::from(key[31]))).unwrap();
        }
        let walked: Vec<Vec<u8>> = dict.iter().map(|e| e.unwrap().0).collect();
        assert_eq!(walked, keys.iter().map(|k| k.to_vec()).collect::<Vec<_>>());
    }

    #[test]
    fn a_value_too_large_for_a_leaf_leaves_the_dictionary_alone() {
        // The leaf has to hold the label as well as the value, so a value that fills a
        // cell on its own cannot fit. The failure must not leave a tree behind that is
        // neither the old one nor the new one.
        let mut dict = built(32, &[1, 2, 3]);
        let before = hash(&dict);
        let mut huge = Builder::new();
        huge.store_same_bit(true, MAX_BITS).unwrap();
        assert!(dict.set(&4u32.to_be_bytes(), &huge).is_err());
        assert_eq!(hash(&dict), before);
        assert_eq!(dict.get(&4u32.to_be_bytes()).unwrap(), Lookup::Absent);
    }

    #[test]
    fn a_dictionary_key_wider_than_a_cell_is_refused() {
        assert!(Dict::new(MAX_BITS).is_ok());
        assert!(matches!(
            Dict::new(MAX_BITS + 1),
            Err(CellError::Malformed(_))
        ));
    }

    #[test]
    fn a_fork_carrying_data_past_its_label_is_refused() {
        // This is the shape of an augmented dictionary, whose forks each summarise the
        // subtree below them. Copying such a summary forward over a changed subtree
        // would describe the subtree that used to be there.
        // An eight-bit dictionary reads the first byte of each key, so the two entries
        // are the ends of that byte's range.
        let dict = built(8, &[0x0000_0000, 0xff00_0000]);
        let root = dict.root().expect("a root");
        let mut fork = Builder::new();
        fork.store_slice(root.parse()).unwrap();
        fork.store_bit(true).unwrap();
        let mut augmented = Dict::from_root(Some(fork.build().unwrap()), 8).unwrap();

        assert!(matches!(
            augmented.set(&[0x0f], &value(1)),
            Err(CellError::Malformed(_))
        ));
        assert!(matches!(
            augmented.remove(&[0x00]),
            Err(CellError::Malformed(_))
        ));
        // Reading one is fine: the extra sits where a reader can see it, and only a
        // rebuild has to know how to recompute it.
        assert!(matches!(augmented.get(&[0x00]).unwrap(), Lookup::Found(_)));
        assert_eq!(augmented.iter().count(), 2);
    }
}
