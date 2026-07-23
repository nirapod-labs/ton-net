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

    /// The number of entries.
    ///
    /// This walks the whole dictionary; a dictionary that keeps its own size is not a shape
    /// TON stores, so the count is computed rather than read.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if the tree does not read as a dictionary, or if a walk over a
    /// proof reaches a pruned branch.
    pub fn count(&self) -> Result<usize, CellError> {
        self.iter()
            .try_fold(0usize, |n, entry| entry.map(|_| n + 1))
    }

    /// The entry with the smallest key, or nothing when the dictionary is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](Dict::iter) does.
    pub fn min(&self) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        self.iter().next().transpose()
    }

    /// The entry with the largest key, or nothing when the dictionary is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](Dict::iter) does.
    pub fn max(&self) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        self.iter().last().transpose()
    }

    /// Removes the entry with the smallest key and returns it, or nothing when empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`min`](Dict::min) and [`remove`](Dict::remove) do.
    pub fn take_min(&mut self) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        let Some((key, entry)) = self.min()? else {
            return Ok(None);
        };
        self.remove(&key)?;
        Ok(Some((key, entry)))
    }

    /// Removes the entry with the largest key and returns it, or nothing when empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`max`](Dict::max) and [`remove`](Dict::remove) do.
    pub fn take_max(&mut self) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        let Some((key, entry)) = self.max()? else {
            return Ok(None);
        };
        self.remove(&key)?;
        Ok(Some((key, entry)))
    }

    /// The entry at `key`, or the next one after it in ascending key order.
    ///
    /// `key` is compared as bytes against the keys the dictionary holds, so it reads best
    /// given a key of the dictionary's own width.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](Dict::iter) does.
    pub fn entry_at_or_after(&self, key: &[u8]) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        for item in self {
            let (found, entry) = item?;
            if found.as_slice() >= key {
                return Ok(Some((found, entry)));
            }
        }
        Ok(None)
    }

    /// The entry at `key`, or the one before it in ascending key order.
    ///
    /// The floor to [`entry_at_or_after`](Dict::entry_at_or_after)'s ceiling. `key` is
    /// compared as bytes against the keys the dictionary holds, so it reads best given a key
    /// of the dictionary's own width.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](Dict::iter) does.
    pub fn entry_at_or_before(
        &self,
        key: &[u8],
    ) -> Result<Option<(Vec<u8>, DictEntry)>, CellError> {
        let mut floor = None;
        for item in self {
            let (found, entry) = item?;
            if found.as_slice() <= key {
                floor = Some((found, entry));
            } else {
                // The walk is ascending, so once it passes the key nothing nearer remains.
                break;
            }
        }
        Ok(floor)
    }

    /// Keeps only the entries `keep` returns true for.
    ///
    /// Every entry is shown to `keep` once, and the dictionary is left holding those it kept.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](Dict::iter) and [`remove`](Dict::remove) do.
    pub fn retain(
        &mut self,
        mut keep: impl FnMut(&[u8], &DictEntry) -> bool,
    ) -> Result<(), CellError> {
        let mut to_remove = Vec::new();
        for item in &*self {
            let (key, entry) = item?;
            if !keep(&key, &entry) {
                to_remove.push(key);
            }
        }
        for key in &to_remove {
            self.remove(key)?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-byte value holding `byte`.
    fn value(byte: u64) -> Builder {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder
    }

    /// A 32-bit-keyed dictionary holding each key with itself as the value.
    fn dict_of(keys: &[u32]) -> Dict {
        let mut dict = Dict::new(32).expect("a dictionary");
        for &key in keys {
            dict.set(&key.to_be_bytes(), &value(u64::from(key)))
                .expect("the set");
        }
        dict
    }

    #[test]
    fn count_walks_every_entry() {
        assert_eq!(dict_of(&[1, 2, 3]).count().expect("count"), 3);
        assert_eq!(
            Dict::new(32).expect("a dictionary").count().expect("count"),
            0
        );
    }

    #[test]
    fn min_and_max_are_the_ends() {
        let dict = dict_of(&[5, 1, 9, 3]);
        let (min_key, _) = dict.min().expect("min").expect("nonempty");
        let (max_key, _) = dict.max().expect("max").expect("nonempty");
        assert_eq!(min_key, 1u32.to_be_bytes());
        assert_eq!(max_key, 9u32.to_be_bytes());
    }

    #[test]
    fn taking_the_min_removes_it() {
        let mut dict = dict_of(&[5, 1, 9]);
        let (key, _) = dict.take_min().expect("take").expect("nonempty");
        assert_eq!(key, 1u32.to_be_bytes());
        assert_eq!(dict.count().expect("count"), 2);
        let (next, _) = dict.min().expect("min").expect("nonempty");
        assert_eq!(next, 5u32.to_be_bytes());
    }

    #[test]
    fn an_entry_at_or_after_a_key_is_the_ceiling() {
        let dict = dict_of(&[10, 20, 30]);
        let (key, _) = dict
            .entry_at_or_after(&15u32.to_be_bytes())
            .expect("query")
            .expect("a ceiling");
        assert_eq!(key, 20u32.to_be_bytes());
        // Exactly on a key returns that key.
        let (key, _) = dict
            .entry_at_or_after(&20u32.to_be_bytes())
            .expect("query")
            .expect("a ceiling");
        assert_eq!(key, 20u32.to_be_bytes());
        // Past the last key returns nothing.
        assert!(dict
            .entry_at_or_after(&99u32.to_be_bytes())
            .expect("query")
            .is_none());
    }

    #[test]
    fn an_entry_at_or_before_a_key_is_the_floor() {
        let dict = dict_of(&[10, 20, 30]);
        let (key, _) = dict
            .entry_at_or_before(&25u32.to_be_bytes())
            .expect("query")
            .expect("a floor");
        assert_eq!(key, 20u32.to_be_bytes());
        // Exactly on a key returns that key.
        let (key, _) = dict
            .entry_at_or_before(&20u32.to_be_bytes())
            .expect("query")
            .expect("a floor");
        assert_eq!(key, 20u32.to_be_bytes());
        // Before the first key returns nothing.
        assert!(dict
            .entry_at_or_before(&5u32.to_be_bytes())
            .expect("query")
            .is_none());
    }

    #[test]
    fn retain_keeps_only_matching_entries() {
        let mut dict = dict_of(&[1, 2, 3, 4]);
        dict.retain(|key, _| {
            let bytes: [u8; 4] = key.try_into().expect("a four-byte key");
            u32::from_be_bytes(bytes) % 2 == 0
        })
        .expect("retain");
        assert_eq!(dict.count().expect("count"), 2);
        assert!(matches!(
            dict.get(&2u32.to_be_bytes()).expect("get"),
            Lookup::Found(_)
        ));
        assert!(matches!(
            dict.get(&1u32.to_be_bytes()).expect("get"),
            Lookup::Absent
        ));
    }
}
