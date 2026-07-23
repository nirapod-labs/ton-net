// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! TON's prefix dictionary, `PfxHashmapE n X`: a dictionary over variable-length keys where
//! no stored key is a prefix of another.
//!
//! Where [`Dict`](crate::Dict) keys are all one fixed width, a prefix dictionary stores keys
//! of any length up to a ceiling, and answers the longest stored key that is a prefix of a
//! query. That is the shape a routing or code table takes, and the form the `PFXDICT`
//! virtual-machine opcodes read.
//!
//! From `block.tlb`:
//!
//! ```text
//! phm_edge#_ {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n)
//!   node:(PfxHashmapNode m X) = PfxHashmap n X;
//! phmn_leaf#0 {n:#} {X:Type} value:X = PfxHashmapNode n X;
//! phmn_fork#1 {n:#} {X:Type} left:^(PfxHashmap n X) right:^(PfxHashmap n X)
//!   = PfxHashmapNode (n + 1) X;
//! phme_empty#0 {n:#} {X:Type} = PfxHashmapE n X;
//! phme_root#1 {n:#} {X:Type} root:^(PfxHashmap n X) = PfxHashmapE n X;
//! ```
//!
//! An edge is a label followed by a node. A node is one bit: `0` a leaf carrying its value
//! inline, `1` a fork carrying its two children as references. The label codec is the same
//! `HmLabel` a [`Dict`](crate::Dict) uses, so a prefix dictionary's canonical form rests on
//! the same shortest-encoding rule, already pinned against mainnet labels. This models the
//! `PfxHashmap` edge; the `PfxHashmapE` wrapper, the maybe bit that says whether there is a
//! root at all, is the caller's, exactly as [`Dict`](crate::Dict) leaves `HashmapE`'s bit.

use super::label::{read_label, store_label};
use super::{check_key_bits, diverges, key_bit, pack, rest, DictEntry, Lookup, NO_BRANCH};
use crate::builder::Builder;
use crate::cell::Cell;
use crate::error::CellError;

/// Where a [`lookup_prefix`](PfxDict::lookup_prefix) landed: the stored key that is a prefix
/// of the query, by its length in bits and the value under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfxMatch {
    /// The length in bits of the stored key that matched.
    pub matched: u16,
    /// The value stored under it, with the cursor already past the leaf's marker.
    pub entry: DictEntry,
}

/// A prefix dictionary: TON's `PfxHashmapE n X`.
///
/// The tree of [`Dict`](crate::Dict), except a leaf may sit at any depth rather than only
/// where the key is fully spent, so the keys it holds are of varying length. No stored key
/// is a prefix of another, which is what makes the longest-prefix answer of
/// [`lookup_prefix`](PfxDict::lookup_prefix) unique.
///
/// # Examples
///
/// ```
/// use ton_net_cell::{Builder, PfxDict};
///
/// let mut dict = PfxDict::new(8)?;
/// let mut value = Builder::new();
/// value.store_uint(0xaa, 8)?;
/// // A two-bit key `10`.
/// dict.set(&[0b1000_0000], 2, &value)?;
///
/// // A six-bit query `101100` has the stored `10` as its longest prefix.
/// let found = dict.lookup_prefix(&[0b1011_0000], 6)?.expect("a prefix matches");
/// assert_eq!(found.matched, 2);
/// assert_eq!(found.entry.slice()?.load_uint(8)?, 0xaa);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Debug, Clone)]
pub struct PfxDict {
    root: Option<Cell>,
    key_bits: u16,
}

impl PfxDict {
    /// An empty prefix dictionary over keys up to `key_bits` bits.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn new(key_bits: u16) -> Result<Self, CellError> {
        Self::from_root(None, key_bits)
    }

    /// A dictionary rooted at the cell a `PfxHashmapE` points at, or empty when it points at
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn from_root(root: Option<Cell>, key_bits: u16) -> Result<Self, CellError> {
        check_key_bits(key_bits)?;
        Ok(Self { root, key_bits })
    }

    /// The root cell, or nothing when the dictionary is empty.
    #[must_use]
    pub fn root(&self) -> Option<&Cell> {
        self.root.as_ref()
    }

    /// The ceiling on key width this dictionary was built over.
    #[must_use]
    pub fn key_bits(&self) -> u16 {
        self.key_bits
    }

    /// Whether the dictionary holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Looks up the exact key of `key_len` bits, the outcomes as on [`Lookup`].
    ///
    /// A key that is only a prefix of a stored key, or that a stored key is a prefix of, is
    /// [`Absent`](Lookup::Absent): the dictionary holds neither shorter nor longer, only the
    /// key itself counts as present.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `key_len` is wider than the dictionary,
    /// [`CellError::KeyLength`] if `key` is too short to hold `key_len` bits, or a
    /// [`CellError`] if the tree does not read as a prefix dictionary.
    pub fn get(&self, key: &[u8], key_len: u16) -> Result<Lookup<DictEntry>, CellError> {
        let bits = pfx_key_of(key, key_len, self.key_bits)?;
        let Some(root) = self.root.clone() else {
            return Ok(Lookup::Absent);
        };

        let mut node = root;
        let mut remaining = self.key_bits;
        let mut consumed = 0usize;
        loop {
            if node.is_exotic() {
                return Ok(Lookup::Pruned);
            }
            let mut slice = node.parse();
            let label = read_label(&mut slice, remaining)?;
            let ahead = rest(&bits, consumed);
            if diverges(&label, ahead).is_some() || ahead.len() < label.len() {
                // The key parts from this edge, or ends inside it. Either way it is not the
                // key stored at a leaf below.
                return Ok(Lookup::Absent);
            }
            consumed += label.len();
            let is_fork = slice.load_bit()?;
            let below = remaining - label_width(&label);

            if !is_fork {
                if consumed == bits.len() {
                    let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
                    return Ok(Lookup::Found(DictEntry {
                        cell: node,
                        bit_offset,
                    }));
                }
                // A stored key is a proper prefix of the query, not the query itself.
                return Ok(Lookup::Absent);
            }
            if below == 0 {
                return Err(CellError::Malformed(
                    "a prefix-code fork with no key bits left",
                ));
            }
            if consumed == bits.len() {
                // The query is a proper prefix of stored keys, not one of them.
                return Ok(Lookup::Absent);
            }
            let branch = usize::from(rest(&bits, consumed).first().copied().unwrap_or(false));
            consumed += 1;
            remaining = below - 1;
            node = node.reference(branch).ok_or(NO_BRANCH)?.clone();
        }
    }

    /// The longest stored key that is a prefix of `key`, or nothing when none is.
    ///
    /// Because no stored key is a prefix of another, at most one stored key is a prefix of a
    /// given query, so the walk that finds it is a straight descent with no backtracking.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `key_len` is wider than the dictionary,
    /// [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if the descent
    /// meets a pruned branch, or a [`CellError`] if the tree does not read as a prefix
    /// dictionary.
    pub fn lookup_prefix(&self, key: &[u8], key_len: u16) -> Result<Option<PfxMatch>, CellError> {
        let bits = pfx_key_of(key, key_len, self.key_bits)?;
        let Some(root) = self.root.clone() else {
            return Ok(None);
        };

        let mut node = root;
        let mut remaining = self.key_bits;
        let mut consumed = 0usize;
        loop {
            if node.is_exotic() {
                return Err(CellError::Pruned);
            }
            let mut slice = node.parse();
            let label = read_label(&mut slice, remaining)?;
            let ahead = rest(&bits, consumed);
            if diverges(&label, ahead).is_some() || ahead.len() < label.len() {
                return Ok(None);
            }
            consumed += label.len();
            let is_fork = slice.load_bit()?;
            let below = remaining - label_width(&label);

            if !is_fork {
                let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "consumed <= key_len <= key_bits, which check_key_bits held to a u16"
                )]
                let matched = consumed as u16;
                return Ok(Some(PfxMatch {
                    matched,
                    entry: DictEntry {
                        cell: node,
                        bit_offset,
                    },
                }));
            }
            if below == 0 {
                return Err(CellError::Malformed(
                    "a prefix-code fork with no key bits left",
                ));
            }
            if consumed == bits.len() {
                // A fork, but the query is spent: every stored key here is longer than it.
                return Ok(None);
            }
            let branch = usize::from(rest(&bits, consumed).first().copied().unwrap_or(false));
            consumed += 1;
            remaining = below - 1;
            node = node.reference(branch).ok_or(NO_BRANCH)?.clone();
        }
    }

    /// Stores `value` under the `key_len`-bit key, replacing whatever exact key was there.
    ///
    /// A key the dictionary cannot hold beside what it already has, one that is a prefix of a
    /// stored key or that a stored key is a prefix of, is refused: the prefix-free invariant
    /// is what the whole structure rests on. The dictionary is left untouched when the store
    /// fails, so a refused key or a value too large leaves no half-written tree.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `key_len` is wider than the dictionary or the key
    /// collides with a stored one under the prefix-free rule, [`CellError::KeyLength`] if
    /// `key` is too short, [`CellError::Pruned`] if the change falls in a pruned branch, or
    /// [`CellError::NoRoomForBits`] if the label, marker and value do not fit one cell.
    pub fn set(&mut self, key: &[u8], key_len: u16, value: &Builder) -> Result<(), CellError> {
        let bits = pfx_key_of(key, key_len, self.key_bits)?;
        let new_root = match &self.root {
            None => leaf_cell(&bits, self.key_bits, value)?,
            Some(root) => insert(root, self.key_bits, &bits, value)?,
        };
        self.root = Some(new_root);
        Ok(())
    }

    /// Removes the exact key of `key_len` bits, reporting whether it was there.
    ///
    /// When a fork is left with one child, that child is merged back into the edge above it,
    /// so the tree stays the minimal one for the keys that remain: removing a key restores
    /// exactly the dictionary that never held it. The dictionary is left untouched when the
    /// key was not present.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `key_len` is wider than the dictionary,
    /// [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if the removal
    /// falls in a pruned branch, or a [`CellError`] if the tree does not read as a prefix
    /// dictionary.
    pub fn remove(&mut self, key: &[u8], key_len: u16) -> Result<bool, CellError> {
        let bits = pfx_key_of(key, key_len, self.key_bits)?;
        let Some(root) = self.root.clone() else {
            return Ok(false);
        };
        match remove_from(&root, self.key_bits, &bits)? {
            Removal::NotFound => Ok(false),
            Removal::Gone => {
                self.root = None;
                Ok(true)
            }
            Removal::Rebuilt(cell) => {
                self.root = Some(cell);
                Ok(true)
            }
        }
    }

    /// Checks the tree reads as a well-formed prefix dictionary.
    ///
    /// Every fork must leave at least one key bit for the branch it splits on, hold exactly
    /// two references, and carry nothing past its marker. A pruned branch is opaque, so a
    /// fork above one is left unchecked while the rest of the visible tree is still verified.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a fork breaks one of those rules, or a
    /// [`CellError`] if the tree does not read as a prefix dictionary.
    pub fn validate(&self) -> Result<(), CellError> {
        match &self.root {
            None => Ok(()),
            Some(root) => validate_node(root, self.key_bits),
        }
    }

    /// Every entry, in ascending key order, as its key bytes, the key's bit length, and where
    /// its value sits.
    #[must_use]
    pub fn iter(&self) -> PfxDictIter {
        PfxDictIter {
            stack: self
                .root
                .clone()
                .map(|root| vec![(root, Vec::new(), self.key_bits)])
                .unwrap_or_default(),
            done: false,
        }
    }
}

impl IntoIterator for &PfxDict {
    type Item = Result<(Vec<u8>, u16, DictEntry), CellError>;
    type IntoIter = PfxDictIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The key as a bit run, refusing one wider than the dictionary or too short for its length.
fn pfx_key_of(key: &[u8], key_len: u16, max: u16) -> Result<Vec<bool>, CellError> {
    if key_len > max {
        return Err(CellError::Malformed("prefix key wider than the dictionary"));
    }
    let needed = usize::from(key_len).div_ceil(8);
    if key.len() < needed {
        return Err(CellError::KeyLength {
            given: key.len() * 8,
            expected: usize::from(key_len),
        });
    }
    Ok((0..usize::from(key_len)).map(|i| key_bit(key, i)).collect())
}

/// A label's length as a key-width count. `read_label` bounds it to at most the width it was
/// read under, so it fits a `u16`.
fn label_width(label: &[bool]) -> u16 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "read_label bounds a label to at most its `max` argument, a u16"
    )]
    let width = label.len() as u16;
    width
}

/// Builds a leaf: the whole remaining key as a label, the `0` marker, then the value inline.
fn leaf_cell(key: &[bool], remaining: u16, value: &Builder) -> Result<Cell, CellError> {
    let mut cell = Builder::new();
    store_label(&mut cell, key, remaining)?;
    cell.store_bit(false)?;
    cell.store_builder(value)?;
    cell.build()
}

/// Inserts `key` (the bits still to place) with `value` under `node`, returning the rebuilt
/// subtree. `remaining` is the key width budget at `node`.
///
/// A recursion, not a loop, because it rebuilds the one path it changes from the bottom up;
/// its depth is at most the key width, which [`check_key_bits`] holds under a cell's bit
/// count, so it cannot run away.
fn insert(node: &Cell, remaining: u16, key: &[bool], value: &Builder) -> Result<Cell, CellError> {
    if node.is_exotic() {
        return Err(CellError::Pruned);
    }
    let mut slice = node.parse();
    let label = read_label(&mut slice, remaining)?;

    if let Some(at) = diverges(&label, key) {
        // The key and this edge's label part company at `at`, where each still has a bit, so
        // a fork over their common prefix takes the old edge on one side and the new key on
        // the other.
        return split(node, remaining, &label, at, key, value);
    }

    if key.len() < label.len() {
        // The key is spent inside this edge, so it is a proper prefix of the key below.
        return Err(CellError::Malformed(
            "a prefix-code key is a prefix of a stored key",
        ));
    }

    let is_fork = slice.load_bit()?;
    let below = remaining - label_width(&label);
    let tail = rest(key, label.len());

    if !is_fork {
        if tail.is_empty() {
            // The same key: keep the label and marker, write the new value.
            return leaf_cell(&label, remaining, value);
        }
        // The stored leaf's key is a proper prefix of the new one.
        return Err(CellError::Malformed(
            "a stored prefix-code key is a prefix of this key",
        ));
    }

    if tail.is_empty() {
        // The key ends exactly at a fork, so it is a prefix of the keys below it.
        return Err(CellError::Malformed(
            "a prefix-code key is a prefix of a stored key",
        ));
    }
    if below == 0 {
        return Err(CellError::Malformed(
            "a prefix-code fork with no key bits left",
        ));
    }

    let branch = usize::from(tail.first().copied().unwrap_or(false));
    let child = node.reference(branch).ok_or(NO_BRANCH)?;
    let new_child = insert(child, below - 1, rest(tail, 1), value)?;
    rebuild_fork(&label, remaining, node, branch, new_child)
}

/// Rebuilds a fork with `child` in place of the branch the descent took.
fn rebuild_fork(
    label: &[bool],
    remaining: u16,
    node: &Cell,
    branch: usize,
    child: Cell,
) -> Result<Cell, CellError> {
    let sibling = node.reference(1 - branch).ok_or(NO_BRANCH)?.clone();
    let (left, right) = if branch == 0 {
        (child, sibling)
    } else {
        (sibling, child)
    };
    let mut fork = Builder::new();
    store_label(&mut fork, label, remaining)?;
    fork.store_bit(true)?;
    fork.store_ref(left)?;
    fork.store_ref(right)?;
    fork.build()
}

/// Splits `node` at `at`, where its label and the new key part company, into a fork over
/// their common prefix with the old node on one side and a new leaf on the other.
fn split(
    node: &Cell,
    remaining: u16,
    label: &[bool],
    at: usize,
    key: &[bool],
    value: &Builder,
) -> Result<Cell, CellError> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "at < label.len() <= remaining, a u16, so at fits and remaining - at - 1 does not underflow"
    )]
    let child_width = remaining - at as u16 - 1;

    // The old node keeps everything past the branch bit, relabelled with what is left of its
    // label; store_slice carries its marker and its value or its two references over as they
    // stand.
    let mut kept = Builder::new();
    store_label(&mut kept, rest(label, at + 1), child_width)?;
    let mut slice = node.parse();
    read_label(&mut slice, remaining)?;
    kept.store_slice(slice)?;
    let kept = kept.build()?;

    let fresh = leaf_cell(rest(key, at + 1), child_width, value)?;

    // The bit they disagree on is the old node's, so the new leaf takes the other branch.
    let (left, right) = if label.get(at).copied().unwrap_or(false) {
        (fresh, kept)
    } else {
        (kept, fresh)
    };

    let mut fork = Builder::new();
    store_label(&mut fork, label.get(..at).unwrap_or(&[]), remaining)?;
    fork.store_bit(true)?;
    fork.store_ref(left)?;
    fork.store_ref(right)?;
    fork.build()
}

/// What removing a key did to a subtree.
enum Removal {
    /// The key was not under this subtree, so it is unchanged.
    NotFound,
    /// This node was the leaf holding the key, so its parent must drop the branch to it.
    Gone,
    /// A descendant was removed and this is the rebuilt subtree.
    Rebuilt(Cell),
}

/// Removes `key` from under `node`, reporting what became of the subtree. `remaining` is the
/// key width budget at `node`.
fn remove_from(node: &Cell, remaining: u16, key: &[bool]) -> Result<Removal, CellError> {
    if node.is_exotic() {
        return Err(CellError::Pruned);
    }
    let mut slice = node.parse();
    let label = read_label(&mut slice, remaining)?;
    if diverges(&label, key).is_some() || key.len() < label.len() {
        return Ok(Removal::NotFound);
    }

    let is_fork = slice.load_bit()?;
    let below = remaining - label_width(&label);
    let tail = rest(key, label.len());

    if !is_fork {
        // A leaf holds the key only when the key ends exactly here.
        if tail.is_empty() {
            return Ok(Removal::Gone);
        }
        return Ok(Removal::NotFound);
    }
    if below == 0 {
        return Err(CellError::Malformed(
            "a prefix-code fork with no key bits left",
        ));
    }
    if tail.is_empty() {
        // The key ends at a fork, so it is no stored leaf.
        return Ok(Removal::NotFound);
    }

    let branch = usize::from(tail.first().copied().unwrap_or(false));
    let child = node.reference(branch).ok_or(NO_BRANCH)?;
    match remove_from(child, below - 1, rest(tail, 1))? {
        Removal::NotFound => Ok(Removal::NotFound),
        // The branch lost its leaf, so the fork has one child left: merge it up.
        Removal::Gone => Ok(Removal::Rebuilt(collapse(
            node,
            remaining,
            &label,
            1 - branch,
        )?)),
        Removal::Rebuilt(new_child) => Ok(Removal::Rebuilt(rebuild_fork(
            &label, remaining, node, branch, new_child,
        )?)),
    }
}

/// Merges a fork's surviving branch back into the edge above it, now the other branch is gone.
///
/// The branch bit that led to the survivor rejoins the label, so the merged edge spells the
/// same key path in one node that the fork and the survivor spelled in two.
fn collapse(
    node: &Cell,
    remaining: u16,
    label: &[bool],
    survivor: usize,
) -> Result<Cell, CellError> {
    let sibling = node.reference(survivor).ok_or(NO_BRANCH)?;
    if sibling.is_exotic() {
        return Err(CellError::Pruned);
    }
    let below = remaining - label_width(label);
    if below == 0 {
        return Err(CellError::Malformed(
            "a prefix-code fork with no key bits left",
        ));
    }

    let mut merged_label = label.to_vec();
    merged_label.push(survivor == 1);
    let mut slice = sibling.parse();
    let sibling_label = read_label(&mut slice, below - 1)?;
    merged_label.extend_from_slice(&sibling_label);

    let mut merged = Builder::new();
    store_label(&mut merged, &merged_label, remaining)?;
    merged.store_slice(slice)?;
    merged.build()
}

/// Checks `node` and everything visible below it reads as a prefix dictionary.
fn validate_node(node: &Cell, remaining: u16) -> Result<(), CellError> {
    if node.is_exotic() {
        return Ok(());
    }
    let mut slice = node.parse();
    let label = read_label(&mut slice, remaining)?;
    let is_fork = slice.load_bit()?;
    if !is_fork {
        return Ok(());
    }

    let below = remaining - label_width(&label);
    if below == 0 {
        return Err(CellError::Malformed(
            "a prefix-code fork with no key bits left",
        ));
    }
    if slice.remaining_bits() != 0 || node.refs().len() != 2 {
        return Err(CellError::Malformed("a malformed prefix-code fork node"));
    }
    let left = node.reference(0).ok_or(NO_BRANCH)?;
    let right = node.reference(1).ok_or(NO_BRANCH)?;
    validate_node(left, below - 1)?;
    validate_node(right, below - 1)
}

/// A walk over every entry of a prefix dictionary, in ascending key order.
///
/// Built by [`PfxDict::iter`]. Like the plain dictionary's walk it stops at a pruned branch
/// rather than walking past one.
pub struct PfxDictIter {
    /// Each pending node, the key bits spelled above it, and the width still to spend at it.
    stack: Vec<(Cell, Vec<bool>, u16)>,
    done: bool,
}

impl Iterator for PfxDictIter {
    type Item = Result<(Vec<u8>, u16, DictEntry), CellError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

impl PfxDictIter {
    /// Descends to the next leaf, or reports the walk is over.
    fn step(&mut self) -> Result<Option<(Vec<u8>, u16, DictEntry)>, CellError> {
        while let Some((node, prefix, remaining)) = self.stack.pop() {
            if node.is_exotic() {
                return Err(CellError::Pruned);
            }
            let mut slice = node.parse();
            let label = read_label(&mut slice, remaining)?;
            let is_fork = slice.load_bit()?;
            let mut key = prefix;
            key.extend_from_slice(&label);

            if !is_fork {
                let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "key.len() <= key_bits, which check_key_bits held to a u16"
                )]
                let key_len = key.len() as u16;
                return Ok(Some((
                    pack(&key),
                    key_len,
                    DictEntry {
                        cell: node,
                        bit_offset,
                    },
                )));
            }

            let below = remaining - label_width(&label);
            if below == 0 {
                return Err(CellError::Malformed(
                    "a prefix-code fork with no key bits left",
                ));
            }
            // The right branch goes on first so the left one comes off first, which is what
            // puts the keys in ascending order.
            for branch in [1usize, 0usize] {
                let child = node.reference(branch).ok_or(NO_BRANCH)?.clone();
                let mut key = key.clone();
                key.push(branch == 1);
                self.stack.push((child, key, below - 1));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_boc;

    /// An eight-bit value builder.
    fn val(byte: u64) -> Builder {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder
    }

    /// Reads back the eight-bit value a lookup found.
    fn value_of(entry: &DictEntry) -> u64 {
        entry
            .slice()
            .expect("a value")
            .load_uint(8)
            .expect("a byte")
    }

    #[test]
    fn lookup_prefix_finds_the_longest_stored_prefix() {
        // The scenario a reference client's own test walks: three keys of different lengths,
        // and a query whose longest stored prefix is the shortest of them.
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 2, &val(0xaa)).expect("set 10");
        dict.set(&[0b0110_0000], 3, &val(0xbb)).expect("set 011");
        dict.set(&[0b1110_0000], 4, &val(0xcc)).expect("set 1110");

        let found = dict
            .lookup_prefix(&[0b1011_0000], 6)
            .expect("query")
            .expect("a prefix matches 101100");
        assert_eq!(found.matched, 2);
        assert_eq!(value_of(&found.entry), 0xaa);

        let Lookup::Found(exact) = dict.get(&[0b0110_0000], 3).expect("query") else {
            panic!("011 is stored")
        };
        assert_eq!(value_of(&exact), 0xbb);

        // The six-bit query is no key of its own.
        assert_eq!(dict.get(&[0b1011_0000], 6).expect("query"), Lookup::Absent);
        // 1111 diverges inside the 1110 edge, so no stored key is a prefix of it.
        assert!(dict
            .lookup_prefix(&[0b1111_0000], 4)
            .expect("query")
            .is_none());
    }

    #[test]
    fn a_key_that_would_break_the_prefix_rule_is_refused() {
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 2, &val(0x02)).expect("set 10");
        dict.set(&[0b1100_0000], 2, &val(0x05)).expect("set 11");

        // A one-bit key 1 lands on the fork between 10 and 11, so it is a prefix of both.
        assert!(matches!(
            dict.set(&[0b1000_0000], 1, &val(0x06)),
            Err(CellError::Malformed(_))
        ));
        assert_eq!(dict.get(&[0b1000_0000], 1).expect("query"), Lookup::Absent);
        // The refused set left the two keys as they were.
        let Lookup::Found(kept) = dict.get(&[0b1000_0000], 2).expect("query") else {
            panic!("10 is still stored")
        };
        assert_eq!(value_of(&kept), 0x02);

        // A longer key whose prefix is a stored key is refused too.
        dict.set(&[0b0010_0000], 3, &val(0x77)).expect("set 001");
        assert!(matches!(
            dict.set(&[0b0010_0000], 5, &val(0x88)),
            Err(CellError::Malformed(_))
        ));
    }

    #[test]
    fn an_exact_key_is_replaced_in_place() {
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 2, &val(0x02)).expect("set 10");
        dict.set(&[0b1000_0000], 2, &val(0x04)).expect("replace 10");
        let Lookup::Found(entry) = dict.get(&[0b1000_0000], 2).expect("query") else {
            panic!("10 is stored")
        };
        assert_eq!(value_of(&entry), 0x04);
        assert_eq!(dict.iter().count(), 1, "a replace does not add an entry");
    }

    #[test]
    fn the_order_keys_arrive_in_does_not_change_the_tree() {
        // A prefix dictionary is canonical: one shape per key set. Building the same three
        // keys in different orders must reach the identical root hash, which also proves the
        // label codec chose the same encoding every time.
        let build = |order: &[(u8, u16, u64)]| {
            let mut dict = PfxDict::new(8).expect("a dictionary");
            for &(byte, len, v) in order {
                dict.set(&[byte], len, &val(v)).expect("set");
            }
            *dict.root().expect("not empty").repr_hash()
        };
        let ascending = build(&[
            (0b0110_0000, 3, 0xbb),
            (0b1000_0000, 2, 0xaa),
            (0b1110_0000, 4, 0xcc),
        ]);
        let descending = build(&[
            (0b1110_0000, 4, 0xcc),
            (0b1000_0000, 2, 0xaa),
            (0b0110_0000, 3, 0xbb),
        ]);
        assert_eq!(ascending, descending);
    }

    #[test]
    fn iteration_yields_every_key_with_its_length() {
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 2, &val(0xaa)).expect("set 10");
        dict.set(&[0b0110_0000], 3, &val(0xbb)).expect("set 011");
        dict.set(&[0b1110_0000], 4, &val(0xcc)).expect("set 1110");

        let walked: Vec<(Vec<u8>, u16, u64)> = dict
            .iter()
            .map(|item| {
                let (key, len, entry) = item.expect("an entry");
                (key, len, value_of(&entry))
            })
            .collect();
        assert_eq!(
            walked,
            vec![
                (vec![0b0110_0000], 3, 0xbb),
                (vec![0b1000_0000], 2, 0xaa),
                (vec![0b1110_0000], 4, 0xcc),
            ]
        );
    }

    #[test]
    fn a_serialized_prefix_dictionary_reads_back_the_same() {
        let mut dict = PfxDict::new(16).expect("a dictionary");
        dict.set(&[0xab, 0x00], 9, &val(0x11)).expect("set");
        dict.set(&[0xab, 0x80], 9, &val(0x22)).expect("set");
        dict.set(&[0x12, 0x34], 16, &val(0x33)).expect("set");
        dict.validate().expect("a built tree is well formed");

        let root = dict.root().expect("not empty").clone();
        let bag = root.to_boc().expect("serializes");
        let back = parse_boc(&bag).expect("parses");
        let reread = PfxDict::from_root(Some(back[0].clone()), 16).expect("a valid root");

        let Lookup::Found(entry) = reread.get(&[0xab, 0x80], 9).expect("query") else {
            panic!("the key survived the round trip")
        };
        assert_eq!(value_of(&entry), 0x22);
        assert_eq!(
            reread.root().map(Cell::repr_hash),
            dict.root().map(Cell::repr_hash),
        );
    }

    #[test]
    fn removing_a_key_merges_the_edge_that_is_left() {
        // Keys 100 and 101 fork on the third bit. Removing 100 must collapse the fork so the
        // root becomes the single leaf 101, the same tree a build of 101 alone gives. This is
        // the scenario a reference client's own delete test checks.
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 3, &val(0xa1)).expect("set 100");
        dict.set(&[0b1010_0000], 3, &val(0xb2)).expect("set 101");

        assert!(dict.remove(&[0b1000_0000], 3).expect("remove 100"));
        let Lookup::Found(entry) = dict.get(&[0b1010_0000], 3).expect("query") else {
            panic!("101 remains")
        };
        assert_eq!(value_of(&entry), 0xb2);
        assert_eq!(dict.iter().count(), 1);

        let mut only = PfxDict::new(8).expect("a dictionary");
        only.set(&[0b1010_0000], 3, &val(0xb2)).expect("set 101");
        assert_eq!(
            dict.root().map(Cell::repr_hash),
            only.root().map(Cell::repr_hash),
            "the collapsed tree is the one 101 alone builds"
        );

        assert!(!dict.remove(&[0b1000_0000], 3).expect("second remove"));
    }

    #[test]
    fn removing_the_only_key_empties_the_dictionary() {
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1100_0000], 2, &val(0x01)).expect("set 11");
        assert!(dict.remove(&[0b1100_0000], 2).expect("remove"));
        assert!(dict.is_empty());
        assert_eq!(dict.get(&[0b1100_0000], 2).expect("query"), Lookup::Absent);
    }

    #[test]
    fn removing_a_key_that_is_not_there_changes_nothing() {
        let mut dict = PfxDict::new(8).expect("a dictionary");
        dict.set(&[0b1000_0000], 2, &val(0xaa)).expect("set 10");
        dict.set(&[0b1100_0000], 2, &val(0xbb)).expect("set 11");
        let before = *dict.root().expect("not empty").repr_hash();
        assert!(!dict.remove(&[0b0000_0000], 2).expect("remove absent"));
        assert_eq!(*dict.root().expect("not empty").repr_hash(), before);
        assert!(!PfxDict::new(8)
            .expect("empty")
            .remove(&[0b1000_0000], 2)
            .expect("remove from empty"));
    }

    #[test]
    fn validate_refuses_a_fork_that_leaves_no_key_bit() {
        // A one-bit dictionary whose root fork spends its only bit on the label has nothing
        // left to branch on. A reference client rejects exactly this.
        let mut leaf = Builder::new();
        // A leaf under a zero-width child: an empty label then the 0 marker and a value.
        store_label(&mut leaf, &[], 0).expect("empty label");
        leaf.store_bit(false).expect("marker");
        leaf.store_uint(0, 2).expect("value");
        let leaf = leaf.build().expect("a leaf");

        let mut fork = Builder::new();
        store_label(&mut fork, &[false], 1).expect("a one-bit label");
        fork.store_bit(true).expect("fork marker");
        fork.store_ref(leaf.clone()).expect("left");
        fork.store_ref(leaf).expect("right");
        let fork = fork.build().expect("a fork");

        let dict = PfxDict::from_root(Some(fork), 1).expect("a root");
        assert_eq!(
            dict.validate(),
            Err(CellError::Malformed(
                "a prefix-code fork with no key bits left"
            ))
        );
    }
}
