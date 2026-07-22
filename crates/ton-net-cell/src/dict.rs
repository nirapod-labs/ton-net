// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! TON's dictionary: a binary radix tree over fixed-width keys.
//!
//! Each edge carries a label, a run of key bits everything below it shares, so a sparse
//! tree stays shallow. A node is a fork holding two references, or a leaf holding
//! whatever the dictionary stores; which one it is follows from how much of the key is
//! left rather than from anything in the cell.
//!
//! # Canonical form
//!
//! A label has three encodings and all three parse. TON's rule is that the shortest one
//! is the only correct one, with a tie going to the earliest constructor, so a dictionary
//! has exactly one representation and therefore exactly one hash. Choosing a longer
//! encoding builds a tree that reads back with the same entries and hashes differently,
//! which nothing downstream would report: a hash here is an identity, not a checksum.
//! [`store_label`] is where that choice is made.
//!
//! # What this type models
//!
//! This is the plain `HashmapE n X`. A fork in a plain dictionary is its label and two
//! references and nothing else, which is what [`Dict::set`] and [`Dict::remove`] check
//! before they rebuild one. An augmented dictionary carries a summary of its subtree in
//! every fork, and rebuilding one means recomputing those summaries rather than copying
//! them forward.

use crate::builder::Builder;
use crate::cell::{Cell, MAX_BITS};
use crate::error::CellError;
use crate::slice::Slice;

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

/// The width of a `#<= max` field: enough bits to hold every value up to `max`.
fn bounded_width(max: u16) -> u32 {
    u16::BITS - max.leading_zeros()
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

/// Reads an edge label, returning the key bits it covers.
///
/// The three encodings are a unary-counted run, an explicit length, and a repeated bit.
fn read_label(slice: &mut Slice<'_>, max: u16) -> Result<Vec<bool>, CellError> {
    if !slice.load_bit()? {
        // hml_short: a unary length, then that many bits.
        let mut len = 0u16;
        while slice.load_bit()? {
            len += 1;
            if len > max {
                return Err(CellError::LabelTooLong);
            }
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    if !slice.load_bit()? {
        // hml_long: an explicit length, then that many bits.
        let len = slice.load_uint(bounded_width(max))? as u16;
        if len > max {
            return Err(CellError::LabelTooLong);
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    // hml_same: one bit repeated a given number of times.
    let value = slice.load_bit()?;
    let len = slice.load_uint(bounded_width(max))? as u16;
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    Ok(vec![value; usize::from(len)])
}

/// Writes an edge label in the only encoding TON accepts for it.
///
/// All three forms read back as the same label, so the choice is invisible to a reader
/// and decides the cell's hash. The shortest wins; a tie goes to the earliest
/// constructor.
fn store_label(into: &mut Builder, label: &[bool], max: u16) -> Result<(), CellError> {
    let len = u16::try_from(label.len()).unwrap_or(u16::MAX);
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    let width = bounded_width(max);
    let bits = u32::from(len);

    let short = 2 * bits + 2;
    let long = 2 + width + bits;
    let repeated = match label.first() {
        Some(first) if label.iter().all(|bit| bit == first) => 3 + width,
        _ => u32::MAX,
    };

    if short <= long && short <= repeated {
        into.store_bit(false)?;
        into.store_same_bit(true, len)?;
        into.store_bit(false)?;
        into.store_bits(label)?;
    } else if long <= repeated {
        into.store_uint(0b10, 2)?;
        into.store_uint(u64::from(len), width)?;
        into.store_bits(label)?;
    } else {
        into.store_uint(0b11, 2)?;
        into.store_bit(label.first().copied().unwrap_or(false))?;
        into.store_uint(u64::from(len), width)?;
    }
    Ok(())
}

/// Builds a leaf: the whole remaining key as a label, then the value.
fn leaf(key: &[bool], value: &Builder, max: u16) -> Result<Cell, CellError> {
    let mut cell = Builder::new();
    store_label(&mut cell, key, max)?;
    cell.store_builder(value)?;
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
    /// Rebuilds this fork with `child` in place of the branch the walk took.
    fn rebuild(&self, child: Cell) -> Result<Cell, CellError> {
        let mut fork = Builder::new();
        store_label(&mut fork, &self.label, self.remaining)?;
        for branch in 0..2 {
            let cell = if branch == self.branch {
                child.clone()
            } else {
                self.node.reference(branch).ok_or(NO_BRANCH)?.clone()
            };
            fork.store_ref(cell)?;
        }
        fork.build()
    }
}

/// A dictionary: TON's `HashmapE n X` over `n`-bit keys.
///
/// Keys are given as bytes, most significant bit of the first byte first, and must be at
/// least `key_bits` long. Iteration yields them back in that same order, so a dictionary
/// walks in ascending unsigned big-endian key order.
///
/// # Examples
///
/// ```
/// use ton_net_cell::{Builder, Dict, Lookup};
///
/// let mut dict = Dict::new(32)?;
/// let mut value = Builder::new();
/// value.store_uint(7, 8)?;
/// dict.set(&1u32.to_be_bytes(), &value)?;
///
/// let Lookup::Found(entry) = dict.get(&1u32.to_be_bytes())? else {
///     unreachable!("the key was just stored")
/// };
/// assert_eq!(entry.slice()?.load_uint(8)?, 7);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dict {
    root: Option<Cell>,
    key_bits: u16,
}

impl Dict {
    /// An empty dictionary over `key_bits`-bit keys.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn new(key_bits: u16) -> Result<Self, CellError> {
        Self::from_root(None, key_bits)
    }

    /// A dictionary rooted at the cell a `HashmapE` points at, or empty when it points at
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn from_root(root: Option<Cell>, key_bits: u16) -> Result<Self, CellError> {
        if key_bits > MAX_BITS {
            return Err(CellError::Malformed("dictionary key wider than a cell"));
        }
        Ok(Self { root, key_bits })
    }

    /// The root cell, or nothing when the dictionary is empty.
    #[must_use]
    pub fn root(&self) -> Option<&Cell> {
        self.root.as_ref()
    }

    /// The key width this dictionary was built over.
    #[must_use]
    pub fn key_bits(&self) -> u16 {
        self.key_bits
    }

    /// Whether the dictionary holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// The key as a bit run, refusing one too short to be a key of this dictionary.
    fn key_of(&self, key: &[u8]) -> Result<Vec<bool>, CellError> {
        let needed = usize::from(self.key_bits).div_ceil(8);
        if key.len() < needed {
            return Err(CellError::KeyLength {
                given: key.len() * 8,
                expected: usize::from(self.key_bits),
            });
        }
        Ok((0..usize::from(self.key_bits))
            .map(|index| key_bit(key, index))
            .collect())
    }

    /// Looks `key` up.
    ///
    /// The three outcomes are described on [`Lookup`]. Over a Merkle proof, a caller that
    /// needs an answer rather than a maybe has to treat [`Lookup::Pruned`] as a failure of
    /// the server to answer.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, or
    /// [`CellError::Malformed`], [`CellError::LabelTooLong`] or [`CellError::NotEnoughBits`]
    /// if the tree does not read as a dictionary.
    pub fn get(&self, key: &[u8]) -> Result<Lookup<DictEntry>, CellError> {
        let bits = self.key_of(key)?;
        let Some(root) = self.root.clone() else {
            return Ok(Lookup::Absent);
        };

        let mut node = root;
        let mut remaining = self.key_bits;
        let mut consumed = 0usize;

        loop {
            // A proof replaces the branches it does not cover with pruned placeholders,
            // which hold a hash rather than a dictionary node. Nothing can be read from one.
            if node.is_exotic() {
                return Ok(Lookup::Pruned);
            }

            let mut slice = node.parse();
            let label = read_label(&mut slice, remaining)?;
            // The label is the run of bits every key below this edge shares. A key that
            // disagrees with it has no entry below, and because the label is part of what
            // the root hash covers, that is evidence rather than an absence of evidence.
            if diverges(&label, rest(&bits, consumed)).is_some() {
                return Ok(Lookup::Absent);
            }
            consumed += label.len();
            remaining -= label.len() as u16;

            if remaining == 0 {
                let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
                return Ok(Lookup::Found(DictEntry {
                    cell: node,
                    bit_offset,
                }));
            }

            // A fork: the next key bit chooses the branch.
            let branch = usize::from(bits.get(consumed).copied().unwrap_or(false));
            consumed += 1;
            remaining -= 1;
            node = node.reference(branch).ok_or(NO_BRANCH)?.clone();
        }
    }

    /// Stores `value` under `key`, replacing whatever was there.
    ///
    /// The dictionary is left untouched if the store fails, so a value too large for a
    /// leaf does not leave a half-written tree behind.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if
    /// the change would fall in a branch a proof has pruned away,
    /// [`CellError::Malformed`] if the tree is not a plain dictionary, or
    /// [`CellError::NoRoomForBits`] if the label and the value do not fit one cell.
    pub fn set(&mut self, key: &[u8], value: &Builder) -> Result<(), CellError> {
        let bits = self.key_of(key)?;
        let Some(root) = self.root.clone() else {
            self.root = Some(leaf(&bits, value, self.key_bits)?);
            return Ok(());
        };

        let walk = descend(root, self.key_bits, &bits)?;
        let tail = rest(&bits, walk.consumed);
        let bottom = match walk.diverged {
            // The key leaves this edge partway along it, so the edge becomes a fork over
            // the run they share, with the old subtree on one side and the new leaf on
            // the other.
            Some(at) => split(&walk.node, &walk.label, at, walk.remaining, tail, value)?,
            // The key is spent, so this is its leaf and the value replaces what was there.
            None => leaf(tail, value, walk.remaining)?,
        };

        // Nothing is assigned until the whole path is rebuilt, so a value too large for a
        // leaf leaves the dictionary as it was rather than half written.
        self.root = Some(rebuild(walk.path, bottom)?);
        Ok(())
    }

    /// Removes `key`, reporting whether it was there.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if
    /// the removal would fall in a branch a proof has pruned away, or
    /// [`CellError::Malformed`] if the tree is not a plain dictionary.
    pub fn remove(&mut self, key: &[u8]) -> Result<bool, CellError> {
        let bits = self.key_of(key)?;
        let Some(root) = self.root.clone() else {
            return Ok(false);
        };

        let mut walk = descend(root, self.key_bits, &bits)?;
        if walk.diverged.is_some() {
            return Ok(false);
        }

        // The leaf is gone. A fork with one branch is not a shape the format has, so its
        // parent collapses into the surviving sibling, which takes the whole run of bits
        // the two edges used to spell out between them.
        let Some(parent) = walk.path.pop() else {
            self.root = None;
            return Ok(true);
        };
        self.root = Some(rebuild(walk.path, collapse(&parent)?)?);
        Ok(true)
    }

    /// Every entry, in ascending key order.
    ///
    /// The iterator stops at a pruned branch with [`CellError::Pruned`] rather than
    /// walking past it: a proof shows one path and hides the rest, and an iteration that
    /// skipped what was hidden would report a subset as if it were the whole dictionary.
    #[must_use]
    pub fn iter(&self) -> DictIter {
        DictIter {
            stack: self
                .root
                .clone()
                .map(|root| vec![(root, Vec::new(), self.key_bits)])
                .unwrap_or_default(),
            done: false,
        }
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
fn descend(root: Cell, key_bits: u16, bits: &[bool]) -> Result<Walk, CellError> {
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

        require_plain_fork(&slice)?;
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
        remaining -= len as u16 + 1;
    }
}

/// The first position where `label` and the key part company, if they do.
fn diverges(label: &[bool], key: &[bool]) -> Option<usize> {
    label
        .iter()
        .zip(key.iter())
        .position(|(left, right)| left != right)
}

/// Refuses a fork carrying anything past its label.
///
/// A plain fork is a label and two references. Data after the label is the summary an
/// augmented dictionary keeps, and copying one forward over a changed subtree would
/// describe the old subtree.
fn require_plain_fork(slice: &Slice<'_>) -> Result<(), CellError> {
    if slice.remaining_bits() == 0 {
        return Ok(());
    }
    Err(CellError::Malformed(
        "a dictionary fork carrying data past its label",
    ))
}

/// Splits `node` at `at`, where its label and the key part company.
///
/// The old node keeps everything below the divergence and is relabelled with what is left
/// of its label; the new leaf takes the other branch; a fresh fork over their common
/// prefix stands where the old node stood.
fn split(
    node: &Cell,
    label: &[bool],
    at: usize,
    remaining: u16,
    key: &[bool],
    value: &Builder,
) -> Result<Cell, CellError> {
    let below = remaining - at as u16 - 1;

    let mut kept = Builder::new();
    store_label(&mut kept, rest(label, at + 1), below)?;
    let mut slice = node.parse();
    read_label(&mut slice, remaining)?;
    kept.store_slice(slice)?;
    let kept = kept.build()?;

    let fresh = leaf(rest(key, at + 1), value, below)?;

    let mut fork = Builder::new();
    store_label(&mut fork, label.get(..at).unwrap_or(&[]), remaining)?;
    let (left, right) = if label.get(at).copied().unwrap_or(false) {
        (fresh, kept)
    } else {
        (kept, fresh)
    };
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
    let below = parent.remaining - parent.label.len() as u16 - 1;
    let mut slice = sibling.parse();
    label.extend_from_slice(&read_label(&mut slice, below)?);

    let mut merged = Builder::new();
    store_label(&mut merged, &label, parent.remaining)?;
    merged.store_slice(slice)?;
    merged.build()
}

/// Rebuilds every fork on the path, from the deepest up to the root.
fn rebuild(mut path: Vec<Step>, mut child: Cell) -> Result<Cell, CellError> {
    while let Some(step) = path.pop() {
        child = step.rebuild(child)?;
    }
    Ok(child)
}

/// A walk over every entry of a dictionary, in ascending key order.
///
/// Built by [`Dict::iter`]. The cells are held by reference count, so the walk reads the
/// dictionary as it stood when it started.
pub struct DictIter {
    stack: Vec<(Cell, Vec<bool>, u16)>,
    done: bool,
}

impl DictIter {
    /// Descends to the next leaf, or reports that the walk is over.
    fn step(&mut self) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        while let Some((node, prefix, remaining)) = self.stack.pop() {
            if node.is_exotic() {
                return Err(CellError::Pruned);
            }

            let mut slice = node.parse();
            let label = read_label(&mut slice, remaining)?;
            let len = label.len();
            let mut key = prefix;
            key.extend_from_slice(&label);

            if len == usize::from(remaining) {
                let bit_offset = usize::from(node.bit_len()) - slice.remaining_bits();
                return Ok(Some((
                    pack(&key),
                    DictEntry {
                        cell: node,
                        bit_offset,
                    },
                )));
            }

            // The right branch goes on first so the left one comes off first, which is
            // what puts the keys in ascending order.
            let below = remaining - len as u16 - 1;
            for branch in [1usize, 0usize] {
                let child = node.reference(branch).ok_or(NO_BRANCH)?.clone();
                let mut key = key.clone();
                key.push(branch == 1);
                self.stack.push((child, key, below));
            }
        }
        Ok(None)
    }
}

impl Iterator for DictIter {
    type Item = Result<(Vec<u8>, DictEntry), CellError>;

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
                    found.slice().unwrap().load_uint(32).unwrap() as u32,
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
