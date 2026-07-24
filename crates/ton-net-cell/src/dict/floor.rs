// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The plain dictionary's nearest-key lookups, bulk build, and prefix sub-dictionary.
//!
//! These sit apart from the get, set and remove of [`Dict`](super::Dict) because each reads
//! the dictionary whole rather than walking one path: a floor or ceiling query scans in key
//! order, a prefix carve re-roots the tree, and a bulk build is a convenience over repeated
//! [`set`](super::Dict::set).

use core::borrow::Borrow;

use super::{key_of, reroot, Dict, DictEntry};
use crate::builder::Builder;
use crate::error::CellError;

impl Dict {
    /// A dictionary holding every item, built in one call.
    ///
    /// Each item is a key and the value stored under it. A key given more than once keeps
    /// the last value it was given, and the result is the one canonical dictionary for its
    /// final key set: the same tree [`set`](Dict::set) builds one entry at a time, and the
    /// same whatever order the items arrive in.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::{Builder, Dict};
    ///
    /// let mut value = Builder::new();
    /// value.store_uint(1, 8)?;
    /// let dict = Dict::from_items(32, [(1u32.to_be_bytes(), &value), (2u32.to_be_bytes(), &value)])?;
    /// assert_eq!(dict.count()?, 2);
    /// # Ok::<(), ton_net_cell::CellError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`set`](Dict::set) does for the first item whose key is too
    /// short or whose label and value will not share one cell.
    pub fn from_items<K, V>(
        key_bits: u16,
        items: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, CellError>
    where
        K: AsRef<[u8]>,
        V: Borrow<Builder>,
    {
        let mut dict = Self::new(key_bits)?;
        for (key, value) in items {
            dict.set(key.as_ref(), value.borrow())?;
        }
        Ok(dict)
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

    /// The sub-dictionary of every entry whose key begins with `prefix`.
    ///
    /// `prefix` is read as its first `prefix_bits` bits, most significant bit of the first
    /// byte first. The result is a dictionary over the remaining `key_bits - prefix_bits`
    /// bits of the key, holding each matching entry under its key with the prefix taken off,
    /// and it is the one canonical dictionary for that narrower key set. A prefix no key
    /// begins with gives an empty dictionary.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::{Builder, Dict};
    ///
    /// let mut value = Builder::new();
    /// value.store_uint(1, 8)?;
    /// let dict = Dict::from_items(16, [(0xab01u16.to_be_bytes(), &value), (0x1234u16.to_be_bytes(), &value)])?;
    /// let under_ab = dict.subdict(&[0xab], 8)?;
    /// assert_eq!(under_ab.key_bits(), 8);
    /// assert_eq!(under_ab.count()?, 1);
    /// # Ok::<(), ton_net_cell::CellError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `prefix_bits` is wider than the key,
    /// [`CellError::KeyLength`] if `prefix` is too short to hold `prefix_bits`,
    /// [`CellError::Pruned`] if reaching the sub-dictionary would cross a branch a proof has
    /// pruned away, or [`CellError`] if the tree does not read as a dictionary.
    pub fn subdict(&self, prefix: &[u8], prefix_bits: u16) -> Result<Self, CellError> {
        if prefix_bits > self.key_bits() {
            return Err(CellError::Malformed("dictionary prefix wider than the key"));
        }
        let want = key_of(prefix, prefix_bits)?;
        let narrower = self.key_bits() - prefix_bits;
        match self.root().cloned() {
            Some(root) => match reroot(&root, self.key_bits(), &want)? {
                Some(cell) => Self::from_root(Some(cell), narrower),
                None => Self::new(narrower),
            },
            None => Self::new(narrower),
        }
    }
}
