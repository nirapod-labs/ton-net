// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The plain `HashmapE n X`: a dictionary whose nodes hold only a label and a value.

use super::{
    check_key_bits, collapse, descend, key_of, leaf, lookup, rebuild, rest, split, walk_step,
    DictEntry, Entry, Lookup, Pending, Shape,
};
use crate::builder::Builder;
use crate::cell::Cell;
use crate::error::CellError;
use crate::slice::Slice;

/// The plain shape: a node holds its label and its value and nothing between them.
pub(super) struct Plain;

impl Shape for Plain {
    type Extra = ();

    fn read_extra(&self, _slice: &mut Slice<'_>) -> Result<(), CellError> {
        Ok(())
    }

    fn write_extra(&self, _extra: &(), _into: &mut Builder) -> Result<(), CellError> {
        Ok(())
    }

    fn check_fork(&self, slice: &mut Slice<'_>) -> Result<(), CellError> {
        if slice.remaining_bits() == 0 {
            return Ok(());
        }
        Err(CellError::Malformed(
            "a dictionary fork carrying data past its label",
        ))
    }

    fn fork_extra(&self, _left: &Cell, _right: &Cell, _below: u16) -> Result<(), CellError> {
        Ok(())
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
        check_key_bits(key_bits)?;
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
        let bits = key_of(key, self.key_bits)?;
        match lookup(&Plain, self.root.as_ref(), self.key_bits, &bits)? {
            Lookup::Found(((), entry)) => Ok(Lookup::Found(entry)),
            Lookup::Absent => Ok(Lookup::Absent),
            Lookup::Pruned => Ok(Lookup::Pruned),
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
        let bits = key_of(key, self.key_bits)?;
        let entry = Entry { extra: &(), value };
        let Some(root) = self.root.clone() else {
            self.root = Some(leaf(&Plain, &bits, &entry, self.key_bits)?);
            return Ok(());
        };

        let walk = descend(&Plain, root, self.key_bits, &bits)?;
        let tail = rest(&bits, walk.consumed);
        let bottom = match walk.diverged {
            // The key leaves this edge partway along it, so the edge becomes a fork over
            // the run they share, with the old subtree on one side and the new leaf on
            // the other.
            Some(at) => split(
                &Plain,
                &walk.node,
                &walk.label,
                at,
                walk.remaining,
                tail,
                &entry,
            )?,
            // The key is spent, so this is its leaf and the value replaces what was there.
            None => leaf(&Plain, tail, &entry, walk.remaining)?,
        };

        // Nothing is assigned until the whole path is rebuilt, so a value too large for a
        // leaf leaves the dictionary as it was rather than half written.
        self.root = Some(rebuild(&Plain, walk.path, bottom)?);
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
        let bits = key_of(key, self.key_bits)?;
        let Some(root) = self.root.clone() else {
            return Ok(false);
        };

        let mut walk = descend(&Plain, root, self.key_bits, &bits)?;
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
        self.root = Some(rebuild(&Plain, walk.path, collapse(&parent)?)?);
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

impl IntoIterator for &Dict {
    type Item = Result<(Vec<u8>, DictEntry), CellError>;
    type IntoIter = DictIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A walk over every entry of a dictionary, in ascending key order.
///
/// Built by [`Dict::iter`]. The cells are held by reference count, so the walk reads the
/// dictionary as it stood when it started.
pub struct DictIter {
    stack: Vec<Pending>,
    done: bool,
}

impl Iterator for DictIter {
    type Item = Result<(Vec<u8>, DictEntry), CellError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match walk_step(&Plain, &mut self.stack) {
            Ok(Some((key, (), entry))) => Some(Ok((key, entry))),
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
