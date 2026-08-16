// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The augmented `HashmapAug n X Y`: a dictionary whose every node also carries a summary
//! of the subtree below it.

use core::borrow::Borrow;

use super::label::{skip_label, Label};
use super::{
    build_all, check_key_bits, collapse, collect_fork_extras, descend, key_of, leaf, lookup,
    rebuild, reroot, rest, split, traverse, validate_tree, walk_step, AugNode, DictEntry, Entry,
    ForkExtra, Lookup, Pending, Shape, Traverse,
};
use crate::cell::builder::Builder;
use crate::cell::cell::Cell;
use crate::cell::error::CellError;
use crate::cell::slice::Slice;

/// How a caller reads, writes and combines the summaries an augmented dictionary carries.
///
/// TON's `HashmapAug n X Y` puts a `Y` in every node: a leaf carries one for its own
/// entry, and a fork carries the combination of its two children's. What a `Y` means is
/// the caller's, not this crate's, so all three operations are supplied here. The
/// accounts dictionary of a shard summarises balances; the account blocks of a block
/// summarise fees.
///
/// [`write`](Augmentation::write) has to be canonical in the same sense a label does: a
/// summary written some other way reads back the same and hashes differently, and a
/// dictionary's hash is its identity rather than a checksum over it.
///
/// # Examples
///
/// ```
/// use ton_net::cell::{Augmentation, Builder, CellError, Slice};
///
/// /// A summary that counts the entries below it.
/// struct Count;
///
/// impl Augmentation for Count {
///     type Extra = u32;
///
///     fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> {
///         slice.load_u32()
///     }
///
///     fn combine(&self, left: &u32, right: &u32) -> Result<u32, CellError> {
///         Ok(left + right)
///     }
///
///     fn write(&self, extra: &u32, into: &mut Builder) -> Result<(), CellError> {
///         into.store_uint(u64::from(*extra), 32)?;
///         Ok(())
///     }
/// }
/// ```
pub trait Augmentation {
    /// The summary a node carries.
    type Extra;

    /// Reads one summary, leaving the cursor on whatever follows it.
    ///
    /// # Errors
    ///
    /// Returns whatever [`CellError`] the summary's own encoding reports, and
    /// [`CellError::NotEnoughBits`] if the node ends inside one.
    fn read(&self, slice: &mut Slice<'_>) -> Result<Self::Extra, CellError>;

    /// Combines a fork's two children's summaries, left then right.
    ///
    /// # Errors
    ///
    /// Returns a [`CellError`] if the two do not combine, which for a summary that adds
    /// up is an overflow.
    fn combine(&self, left: &Self::Extra, right: &Self::Extra) -> Result<Self::Extra, CellError>;

    /// Writes one summary, in the one encoding TON accepts for it.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the summary does not fit beside the label
    /// and the value.
    fn write(&self, extra: &Self::Extra, into: &mut Builder) -> Result<(), CellError>;
}

/// The augmented shape, over a caller's [`Augmentation`].
pub(super) struct Aug<'a, A>(pub(super) &'a A);

impl<A: Augmentation> Shape for Aug<'_, A> {
    type Extra = A::Extra;

    fn read_extra(&self, slice: &mut Slice<'_>) -> Result<A::Extra, CellError> {
        self.0.read(slice)
    }

    fn write_extra(&self, extra: &A::Extra, into: &mut Builder) -> Result<(), CellError> {
        self.0.write(extra, into)
    }

    fn check_fork(&self, slice: &mut Slice<'_>) -> Result<(), CellError> {
        self.0.read(slice)?;
        if slice.remaining_bits() == 0 {
            return Ok(());
        }
        Err(CellError::Malformed(
            "a dictionary fork carrying data past its summary",
        ))
    }

    fn fork_extra(&self, left: &Cell, right: &Cell, below: u16) -> Result<A::Extra, CellError> {
        let left = extra_of(self, left, below)?;
        let right = extra_of(self, right, below)?;
        self.0.combine(&left, &right)
    }
}

/// The summary a node carries, read back off the cell.
fn extra_of<S: Shape>(shape: &S, node: &Cell, max: u16) -> Result<S::Extra, CellError> {
    // A pruned branch holds a hash rather than a node, so there is nothing below it to
    // summarise, and no honest summary of the fork above it either.
    if node.is_exotic() {
        return Err(CellError::Pruned);
    }
    let mut slice = node.parse();
    // The summary is whatever follows the label, so the label itself is stepped over rather
    // than read. This runs once per child of every fork a rebuild touches.
    skip_label(&mut slice, max)?;
    shape.read_extra(&mut slice)
}

/// Where a lookup landed in an augmented dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugEntry<E> {
    /// The summary the leaf carries.
    pub extra: E,
    /// The value under it, with the cursor already past the summary.
    pub entry: DictEntry,
}

/// A key and the augmented entry stored under it, the pair an [`AugDict`] query returns.
pub type AugItem<E> = (Vec<u8>, AugEntry<E>);

/// An augmented dictionary: TON's `HashmapAug n X Y`.
///
/// The same tree as [`Dict`](crate::cell::Dict), except every node also carries a `Y`
/// summarising everything below it, and a fork's is the combination of its two children's.
/// What a `Y` is and how two combine come from the [`Augmentation`] this is built over.
///
/// A summary is recomputed from the children on every write rather than carried forward,
/// because a fork above a changed subtree that kept its old summary would describe the
/// subtree that used to be there while still hashing as a well-formed dictionary.
///
/// This models the `HashmapAug` edge. `HashmapAugE`'s wrapper, the bit saying whether
/// there is a root at all and the summary beside it, belongs to the caller, exactly as
/// [`Dict`](crate::cell::Dict) leaves `HashmapE`'s bit to its own.
///
/// # Examples
///
/// ```
/// # use ton_net::cell::{Augmentation, AugDict, Builder, CellError, Lookup, Slice};
/// # struct Count;
/// # impl Augmentation for Count {
/// #     type Extra = u32;
/// #     fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> { slice.load_u32() }
/// #     fn combine(&self, l: &u32, r: &u32) -> Result<u32, CellError> { Ok(l + r) }
/// #     fn write(&self, e: &u32, into: &mut Builder) -> Result<(), CellError> {
/// #         into.store_uint(u64::from(*e), 32)?;
/// #         Ok(())
/// #     }
/// # }
/// let mut dict = AugDict::new(Count, 32)?;
/// let mut value = Builder::new();
/// value.store_uint(7, 8)?;
/// dict.set(&1u32.to_be_bytes(), &1, &value)?;
/// dict.set(&2u32.to_be_bytes(), &1, &value)?;
///
/// // The fork over the two leaves counts both.
/// assert_eq!(dict.root_extra()?, Some(2));
///
/// let Lookup::Found(found) = dict.get(&1u32.to_be_bytes())? else {
///     unreachable!("the key was just stored")
/// };
/// assert_eq!(found.extra, 1);
/// assert_eq!(found.entry.slice()?.load_uint(8)?, 7);
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
#[derive(Debug, Clone)]
pub struct AugDict<A: Augmentation> {
    root: Option<Cell>,
    key_bits: u16,
    aug: A,
}

impl<A: Augmentation> AugDict<A> {
    /// An empty augmented dictionary over `key_bits`-bit keys.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn new(aug: A, key_bits: u16) -> Result<Self, CellError> {
        Self::from_root(aug, None, key_bits)
    }

    /// A dictionary rooted at the cell a `HashmapAugE` points at, or empty when it points
    /// at nothing.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key that wide could not label a cell.
    pub fn from_root(aug: A, root: Option<Cell>, key_bits: u16) -> Result<Self, CellError> {
        check_key_bits(key_bits)?;
        Ok(Self {
            root,
            key_bits,
            aug,
        })
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

    /// The summary over the whole dictionary, or nothing when it is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Pruned`] if the root is a pruned branch, or a [`CellError`]
    /// if the root does not read as an augmented node.
    pub fn root_extra(&self) -> Result<Option<A::Extra>, CellError> {
        self.root
            .as_ref()
            .map(|root| extra_of(&Aug(&self.aug), root, self.key_bits))
            .transpose()
    }

    /// Every interior fork's stored summary, each with the key prefix that reaches it, in
    /// ascending order.
    ///
    /// A leaf's summary comes back from [`iter`](AugDict::iter) beside its key; this is the
    /// complement, the summaries the forks above the leaves carry. A pruned branch is
    /// opaque, so the walk does not descend into one.
    ///
    /// # Errors
    ///
    /// Returns a [`CellError`] if the tree does not read as an augmented dictionary.
    pub fn fork_extras(&self) -> Result<Vec<ForkExtra<A::Extra>>, CellError> {
        collect_fork_extras(&Aug(&self.aug), self.root.as_ref(), self.key_bits)
    }

    /// Checks every fork carries the summary its two children combine to.
    ///
    /// This is the read-side complement of the recombination a write performs: for each
    /// fork it recomputes the summary from the children as they stand and requires the
    /// result to match what the fork stores, so a tree whose summaries were copied forward
    /// over a changed subtree is caught. A pruned branch is opaque, so a fork above one is
    /// left unchecked while the rest of the visible tree is still verified.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a fork's summary disagrees with its children,
    /// or a [`CellError`] if the tree does not read as an augmented dictionary. Whatever
    /// [`Augmentation::combine`] reports is returned as it stands.
    pub fn validate(&self) -> Result<(), CellError> {
        validate_tree(&Aug(&self.aug), self.root.as_ref(), self.key_bits)
    }

    /// Looks `key` up, returning the summary its leaf carries alongside the value.
    ///
    /// The three outcomes are described on [`Lookup`], and mean here what they mean for
    /// [`Dict::get`](crate::cell::Dict::get).
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, or a [`CellError`] if the
    /// tree does not read as an augmented dictionary.
    pub fn get(&self, key: &[u8]) -> Result<Lookup<AugEntry<A::Extra>>, CellError> {
        let bits = key_of(key, self.key_bits)?;
        match lookup(&Aug(&self.aug), self.root.as_ref(), self.key_bits, &bits)? {
            Lookup::Found((extra, entry)) => Ok(Lookup::Found(AugEntry { extra, entry })),
            Lookup::Absent => Ok(Lookup::Absent),
            Lookup::Pruned => Ok(Lookup::Pruned),
        }
    }

    /// Stores `value` under `key` with `extra` summarising it, replacing whatever was
    /// there, and recomputes every summary above it.
    ///
    /// The dictionary is left untouched if the store fails, so a value too large for a
    /// leaf does not leave a half-written tree behind.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if
    /// the change would fall in a branch a proof has pruned away, or
    /// [`CellError::NoRoomForBits`] if the label, the summary and the value do not fit
    /// one cell. Whatever [`Augmentation::combine`] reports is returned as it stands.
    pub fn set(&mut self, key: &[u8], extra: &A::Extra, value: &Builder) -> Result<(), CellError> {
        let bits = key_of(key, self.key_bits)?;
        let shape = Aug(&self.aug);
        let entry = Entry { extra, value };

        let Some(root) = self.root.clone() else {
            self.root = Some(leaf(&shape, &bits, &entry, self.key_bits)?);
            return Ok(());
        };

        let walk = descend(&shape, root, self.key_bits, &bits)?;
        let tail = rest(&bits, walk.consumed);
        let bottom = match walk.diverged {
            Some(at) => split(
                &shape,
                &walk.node,
                &walk.label,
                at,
                walk.remaining,
                tail,
                &entry,
            )?,
            None => leaf(&shape, tail, &entry, walk.remaining)?,
        };

        self.root = Some(rebuild(&shape, walk.path, bottom)?);
        Ok(())
    }

    /// Removes `key`, reporting whether it was there, and recomputes every summary above
    /// where it was.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::KeyLength`] if `key` is too short, [`CellError::Pruned`] if
    /// the removal would fall in a branch a proof has pruned away, or a [`CellError`] if
    /// the tree does not read as an augmented dictionary.
    pub fn remove(&mut self, key: &[u8]) -> Result<bool, CellError> {
        let bits = key_of(key, self.key_bits)?;
        let shape = Aug(&self.aug);

        let Some(root) = self.root.clone() else {
            return Ok(false);
        };

        let mut walk = descend(&shape, root, self.key_bits, &bits)?;
        if walk.diverged.is_some() {
            return Ok(false);
        }

        // The surviving sibling keeps its own contents, summary included, because its
        // subtree is the one thing this removal did not change. Everything above it is
        // recomputed by the rebuild.
        let Some(parent) = walk.path.pop() else {
            self.root = None;
            return Ok(true);
        };
        self.root = Some(rebuild(&shape, walk.path, collapse(&parent)?)?);
        Ok(true)
    }

    /// Every entry, in ascending key order, each with the summary its leaf carries.
    #[must_use]
    pub fn iter(&self) -> AugDictIter<'_, A> {
        AugDictIter {
            aug: &self.aug,
            stack: self
                .root
                .clone()
                .map(|root| vec![(root, Label::new(), self.key_bits)])
                .unwrap_or_default(),
            done: false,
        }
    }

    /// An augmented dictionary holding every item, built in one call.
    ///
    /// Each item is a key, the summary of the value under it, and the value. A key given
    /// more than once keeps the last of each it was given, and the result is the one
    /// canonical dictionary for its final key set, independent of the order the items arrive
    /// in.
    ///
    /// Wherever [`set`](AugDict::set) can build that dictionary at all, this builds the same
    /// tree. It can also build ones [`set`](AugDict::set) cannot, for the reason
    /// [`Dict::from_items`](crate::cell::Dict::from_items) gives: a first key inserted alone carries
    /// a label its whole width, and a value that fits beside the finished tree's short label
    /// may not fit beside that one.
    ///
    /// The items are sorted by key once and the tree is laid out from the leaves up, so each
    /// fork is built with both children already final and its summary is combined from them
    /// where they stand. Repeated [`set`](AugDict::set) instead rebuilds the forks it
    /// descended through, recombining each summary, once per key stored.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a key `key_bits` wide could not label a cell,
    /// [`CellError::KeyLength`] where an item's key is too short, reported at the earliest
    /// such item the iterator yields, or [`CellError::NoRoomForBits`] where a label, a
    /// summary and a value will not share one cell. Whatever
    /// [`Augmentation::combine`] reports is returned as it stands.
    pub fn from_items<K, V>(
        aug: A,
        key_bits: u16,
        items: impl IntoIterator<Item = (K, A::Extra, V)>,
    ) -> Result<Self, CellError>
    where
        K: AsRef<[u8]>,
        V: Borrow<Builder>,
    {
        let root = build_all(&Aug(&aug), key_bits, items)?;
        Self::from_root(aug, root, key_bits)
    }

    /// The number of entries, computed by walking the dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) does.
    pub fn count(&self) -> Result<usize, CellError> {
        self.iter()
            .try_fold(0usize, |n, entry| entry.map(|_| n + 1))
    }

    /// The entry with the smallest key, or nothing when the dictionary is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) does.
    pub fn min(&self) -> Result<Option<AugItem<A::Extra>>, CellError> {
        self.iter().next().transpose()
    }

    /// The entry with the largest key, or nothing when the dictionary is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) does.
    pub fn max(&self) -> Result<Option<AugItem<A::Extra>>, CellError> {
        self.iter().last().transpose()
    }

    /// Removes the entry with the smallest key and returns it, or nothing when empty.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`min`](AugDict::min) and [`remove`](AugDict::remove) do.
    pub fn take_min(&mut self) -> Result<Option<AugItem<A::Extra>>, CellError> {
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
    /// Returns [`CellError`] as [`max`](AugDict::max) and [`remove`](AugDict::remove) do.
    pub fn take_max(&mut self) -> Result<Option<AugItem<A::Extra>>, CellError> {
        let Some((key, entry)) = self.max()? else {
            return Ok(None);
        };
        self.remove(&key)?;
        Ok(Some((key, entry)))
    }

    /// The entry at `key`, or the next one after it in ascending key order.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) does.
    pub fn entry_at_or_after(&self, key: &[u8]) -> Result<Option<AugItem<A::Extra>>, CellError> {
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
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) does.
    pub fn entry_at_or_before(&self, key: &[u8]) -> Result<Option<AugItem<A::Extra>>, CellError> {
        let mut floor = None;
        for item in self {
            let (found, entry) = item?;
            if found.as_slice() <= key {
                floor = Some((found, entry));
            } else {
                break;
            }
        }
        Ok(floor)
    }

    /// Keeps only the entries `keep` returns true for, recomputing summaries as it goes.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`iter`](AugDict::iter) and [`remove`](AugDict::remove) do.
    pub fn retain(
        &mut self,
        mut keep: impl FnMut(&[u8], &AugEntry<A::Extra>) -> bool,
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

    /// The sub-dictionary of every entry whose key begins with `prefix`.
    ///
    /// As [`Dict::subdict`](crate::cell::Dict::subdict), over the narrower `key_bits -
    /// prefix_bits`-bit key that remains. The carve leaves every subtree it keeps untouched,
    /// so each fork it carries still summarises the same two children and the result is a
    /// consistent augmented dictionary its own [`validate`](AugDict::validate) accepts.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `prefix_bits` is wider than the key,
    /// [`CellError::KeyLength`] if `prefix` is too short to hold `prefix_bits`,
    /// [`CellError::Pruned`] if reaching the sub-dictionary would cross a pruned branch, or
    /// [`CellError`] if the tree does not read as an augmented dictionary.
    pub fn subdict(&self, prefix: &[u8], prefix_bits: u16) -> Result<Self, CellError>
    where
        A: Clone,
    {
        if prefix_bits > self.key_bits {
            return Err(CellError::Malformed("dictionary prefix wider than the key"));
        }
        let want = key_of(prefix, prefix_bits)?;
        let narrower = self.key_bits - prefix_bits;
        let root = match self.root.clone() {
            Some(root) => reroot(&root, self.key_bits, &want)?,
            None => None,
        };
        Self::from_root(self.aug.clone(), root, narrower)
    }

    /// Merges `other` into this dictionary, recomputing every summary the union changes.
    ///
    /// The two must be over the same key width and hold disjoint keys; a key in both is a
    /// conflict this cannot resolve, so it is refused rather than one value chosen over the
    /// other. The result is the one canonical dictionary for the union of the two key sets,
    /// summaries and all. Nothing is changed unless the whole merge succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if the key widths differ or the two share a key,
    /// [`CellError::Pruned`] if either side hides part of itself behind a pruned branch, or
    /// a [`CellError`] as [`set`](AugDict::set) does. Whatever [`Augmentation::combine`]
    /// reports is returned as it stands.
    pub fn combine_with(&mut self, other: &Self) -> Result<(), CellError>
    where
        A: Clone,
    {
        if other.key_bits != self.key_bits {
            return Err(CellError::Malformed(
                "combining dictionaries of different key widths",
            ));
        }

        // The other side is read whole, and every key checked against this one, before this
        // dictionary is touched, so a conflict or a pruned branch is found before any change.
        let mut additions = Vec::new();
        for item in other {
            let (key, found) = item?;
            if !matches!(self.get(&key)?, Lookup::Absent) {
                return Err(CellError::Malformed(
                    "combining dictionaries that share a key",
                ));
            }
            let value = found.entry.slice()?.to_builder()?;
            additions.push((key, found.extra, value));
        }

        // Built into a copy so a store that fails leaves this dictionary as it was.
        let mut merged = self.clone();
        for (key, extra, value) in &additions {
            merged.set(key, extra, value)?;
        }
        *self = merged;
        Ok(())
    }

    /// Walks the dictionary in ascending key order, offering each fork's summary before its
    /// subtree so a caller can steer the walk by it.
    ///
    /// A fork is visited before either of its children, carrying the summary over everything
    /// beneath it; `visit` answers [`Traverse::Continue`] to descend, [`Traverse::Skip`] to
    /// leave that subtree unvisited, or [`Traverse::Stop`] to end the walk. A leaf is visited
    /// with its key, its summary and its value. Because a fork's summary stands for its whole
    /// subtree, a walk that only wants the subtrees meeting some bound on the summary can skip
    /// the rest without reading a single one of their leaves.
    ///
    /// The summaries are read as the tree stores them, not recomputed, so a tree this crate
    /// did not build wants a [`validate`](AugDict::validate) first. Like [`iter`](AugDict::iter)
    /// the walk stops at a pruned branch rather than walking past one: descending into a
    /// partly pruned subtree ends in [`CellError::Pruned`], while a visitor that skips that
    /// subtree by its summary never reaches the placeholder.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Pruned`] if the walk descends into a pruned branch, or a
    /// [`CellError`] if the tree does not read as an augmented dictionary.
    pub fn traverse_extra(
        &self,
        mut visit: impl FnMut(AugNode<'_, A::Extra>) -> Traverse,
    ) -> Result<(), CellError> {
        traverse(
            &Aug(&self.aug),
            self.root.as_ref(),
            self.key_bits,
            &mut visit,
        )
    }
}

impl<'a, A: Augmentation> IntoIterator for &'a AugDict<A> {
    type Item = Result<(Vec<u8>, AugEntry<A::Extra>), CellError>;
    type IntoIter = AugDictIter<'a, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A walk over every entry of an augmented dictionary, in ascending key order.
///
/// Built by [`AugDict::iter`]. Like [`DictIter`](crate::cell::DictIter) it stops at a pruned
/// branch rather than walking past it.
pub struct AugDictIter<'a, A: Augmentation> {
    aug: &'a A,
    stack: Vec<Pending>,
    done: bool,
}

impl<A: Augmentation> Iterator for AugDictIter<'_, A> {
    type Item = Result<(Vec<u8>, AugEntry<A::Extra>), CellError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match walk_step(&Aug(self.aug), &mut self.stack) {
            Ok(Some((key, extra, entry))) => Some(Ok((key, AugEntry { extra, entry }))),
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

    /// A summary that counts the leaves below a node.
    #[derive(Clone)]
    struct CountSum;

    impl Augmentation for CountSum {
        type Extra = u32;

        fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> {
            slice.load_u32()
        }

        fn combine(&self, left: &u32, right: &u32) -> Result<u32, CellError> {
            Ok(left + right)
        }

        fn write(&self, extra: &u32, into: &mut Builder) -> Result<(), CellError> {
            into.store_uint(u64::from(*extra), 32)?;
            Ok(())
        }
    }

    /// A summary that is not commutative, so which child a fork reads first shows in the
    /// tree's root hash.
    ///
    /// `CountSum` cannot see that: addition gives a fork the same summary whichever way round
    /// its children are read, so a build that swapped them agrees with one that did not. Every
    /// augmentation shipped with a real dictionary is free to be order-sensitive, and a bulk
    /// build that read its children in the wrong order would corrupt one silently. The
    /// trait asks a summary to fold two children in order; it does not ask it to commute.
    struct CountSkew;

    impl Augmentation for CountSkew {
        type Extra = u32;

        fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> {
            slice.load_u32()
        }

        fn combine(&self, left: &u32, right: &u32) -> Result<u32, CellError> {
            // Wrapping because 31 compounds up the tree and leaves a u32 within a few
            // levels. The value only has to differ under a swap, not mean anything.
            Ok(left.wrapping_mul(31).wrapping_add(*right))
        }

        fn write(&self, extra: &u32, into: &mut Builder) -> Result<(), CellError> {
            into.store_uint(u64::from(*extra), 32)?;
            Ok(())
        }
    }

    /// The same summary read and written the same way, but combined wrongly, so a tree its
    /// forks were built for reads as inconsistent under it.
    struct CountOff;

    impl Augmentation for CountOff {
        type Extra = u32;

        fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> {
            slice.load_u32()
        }

        fn combine(&self, left: &u32, right: &u32) -> Result<u32, CellError> {
            Ok(left + right + 1)
        }

        fn write(&self, extra: &u32, into: &mut Builder) -> Result<(), CellError> {
            into.store_uint(u64::from(*extra), 32)?;
            Ok(())
        }
    }

    /// A run of key bits written out, so a test can state a prefix as the bits it spells
    /// rather than as a count of them.
    fn bits(run: &str) -> Vec<bool> {
        run.chars().map(|c| c == '1').collect()
    }

    /// Three keys over a tree whose interior labels run longer than a bit and read
    /// differently backwards.
    ///
    /// The first parts from the other two at the fifth bit and those two part at the ninth,
    /// so the root's label is `1011` and the sub-fork's is `001`. Neither run is its own
    /// reverse and neither is a single bit, which is what lets a prefix spelled in the wrong
    /// order, or not spelled at all, show in an assertion.
    const LABELLED_KEYS: [u32; 3] = [0xB000_0000, 0xB900_0000, 0xB980_0000];

    /// An augmented dictionary over 32-bit keys, one leaf per key, each counting as one.
    fn counted(keys: &[u32]) -> AugDict<CountSum> {
        let mut dict = AugDict::new(CountSum, 32).expect("a sane key width");
        let mut value = Builder::new();
        value.store_uint(0, 8).expect("fits");
        for key in keys {
            dict.set(&key.to_be_bytes(), &1, &value).expect("sets");
        }
        dict
    }

    #[test]
    fn fork_extras_carry_the_summary_of_the_subtree_below_each() {
        // Keys 1, 2 and 3 fork twice: the root over all three, then a sub-fork over 2 and 3.
        let dict = counted(&[1, 2, 3]);
        let forks = dict.fork_extras().expect("reads");
        assert_eq!(forks.len(), 2, "a root fork and one sub-fork");
        assert_eq!(forks[0].1, 3, "the root fork counts every leaf");
        assert_eq!(forks[1].1, 2, "the sub-fork counts its two leaves");
    }

    #[test]
    fn a_fork_prefix_spells_the_bits_every_entry_below_it_shares() {
        // A fork's prefix is the key path a caller reads a subtree's identity off, so it has
        // to be the run itself, in the order a key spells it, and not merely the right
        // number of bits. The root's is its own label; the sub-fork's is that label, the
        // branch bit that led to it, and its own label, in that order.
        let dict = counted(&LABELLED_KEYS);
        let forks = dict.fork_extras().expect("reads");

        let spelled: Vec<Vec<bool>> = forks.iter().map(|(prefix, _)| prefix.clone()).collect();
        assert_eq!(spelled, vec![bits("1011"), bits("10111001")]);
        assert_eq!(
            forks.iter().map(|(_, extra)| *extra).collect::<Vec<u32>>(),
            vec![3, 2],
            "the root fork counts every leaf and the sub-fork the two below it"
        );
    }

    #[test]
    fn a_leaf_only_dictionary_has_no_forks() {
        let dict = counted(&[42]);
        assert!(dict.fork_extras().expect("reads").is_empty());
        dict.validate().expect("a single leaf is consistent");
    }

    #[test]
    fn validate_passes_a_tree_its_own_writes_built() {
        counted(&[1, 2, 3, 100, 1000, 70_000, 0xffff_ffff])
            .validate()
            .expect("every fork sums its children");
    }

    #[test]
    fn validate_catches_a_summary_that_disagrees_with_its_children() {
        // The forks were built to sum; read back under a rule that adds one more, every
        // fork's stored summary is now short and validate must refuse the tree.
        let root = counted(&[1, 2, 3]).root().expect("not empty").clone();
        let reread = AugDict::from_root(CountOff, Some(root), 32).expect("a valid root");
        assert_eq!(
            reread.validate(),
            Err(CellError::Malformed(
                "augmented fork summary disagrees with its children"
            ))
        );
    }

    #[test]
    fn count_min_and_max_read_the_ends() {
        let dict = counted(&[5, 1, 9, 3]);
        assert_eq!(dict.count().expect("count"), 4);
        assert_eq!(
            dict.min().expect("min").expect("nonempty").0,
            1u32.to_be_bytes()
        );
        assert_eq!(
            dict.max().expect("max").expect("nonempty").0,
            9u32.to_be_bytes()
        );
    }

    #[test]
    fn an_entry_at_or_before_a_key_is_the_floor() {
        let dict = counted(&[10, 20, 30]);
        let (key, _) = dict
            .entry_at_or_before(&25u32.to_be_bytes())
            .expect("query")
            .expect("a floor");
        assert_eq!(key, 20u32.to_be_bytes());
        assert!(dict
            .entry_at_or_before(&5u32.to_be_bytes())
            .expect("query")
            .is_none());
    }

    #[test]
    fn from_items_builds_the_same_augmented_tree_as_repeated_set() {
        let items: Vec<([u8; 4], u32, Builder)> = [1u32, 2, 3, 100]
            .iter()
            .map(|&k| {
                let mut value = Builder::new();
                value.store_uint(0, 8).expect("a byte fits");
                (k.to_be_bytes(), 1u32, value)
            })
            .collect();
        let bulk = AugDict::from_items(CountSum, 32, items).expect("from_items");
        assert_eq!(bulk.root_extra().expect("extra"), Some(4));
        assert_eq!(
            bulk.root().map(Cell::repr_hash),
            counted(&[1, 2, 3, 100]).root().map(Cell::repr_hash),
        );
    }

    /// The same summary as [`CountSum`], which counts the calls to
    /// [`combine`](Augmentation::combine) it takes.
    ///
    /// A fork's summary is combined once when the fork is built, so the tally is the number
    /// of forks a build constructed rather than the number the finished tree holds. That is
    /// what tells a build that lays each fork down once from one that rebuilds forks it has
    /// already written.
    struct CountedCombines(core::cell::Cell<usize>);

    impl Augmentation for CountedCombines {
        type Extra = u32;

        fn read(&self, slice: &mut Slice<'_>) -> Result<u32, CellError> {
            slice.load_u32()
        }

        fn combine(&self, left: &u32, right: &u32) -> Result<u32, CellError> {
            self.0.set(self.0.get() + 1);
            Ok(left + right)
        }

        fn write(&self, extra: &u32, into: &mut Builder) -> Result<(), CellError> {
            into.store_uint(u64::from(*extra), 32)?;
            Ok(())
        }
    }

    /// An item for each key, summarised by the count 1.
    /// The same items, each carrying a summary of its own.
    ///
    /// [`counted_items`] gives every leaf the summary one, which makes a fork's two children
    /// equal wherever the tree is balanced, and `31a + a` is the same whichever way round a
    /// fork with equal children reads them. Under those items a build that swapped its
    /// children is invisible at every fork of a balanced tree. Distinct summaries make the
    /// swap show at every fork instead of only at the sizes that happen to be lopsided.
    fn skewed_items(keys: &[u32]) -> Vec<([u8; 4], u32, Builder)> {
        let mut value = Builder::new();
        value.store_uint(0, 8).expect("a byte fits");
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let extra = u32::try_from(i).expect("a small count") + 1;
                (key.to_be_bytes(), extra, value.clone())
            })
            .collect()
    }

    fn counted_items(keys: &[u32]) -> Vec<([u8; 4], u32, Builder)> {
        let mut value = Builder::new();
        value.store_uint(0, 8).expect("a byte fits");
        keys.iter()
            .map(|key| (key.to_be_bytes(), 1u32, value.clone()))
            .collect()
    }

    #[test]
    fn a_bulk_build_combines_a_summary_once_per_fork_it_lays_down() {
        // Sixteen keys make a tree of sixteen leaves over fifteen forks, and a build that
        // constructs each fork once combines fifteen summaries. Anything above that is a
        // fork built more than once.
        let keys: Vec<u32> = (0..16u32).collect();

        let bulk = AugDict::from_items(
            CountedCombines(core::cell::Cell::new(0)),
            32,
            counted_items(&keys),
        )
        .expect("from_items");
        let combines = bulk.aug.0.get();
        assert_eq!(
            combines,
            bulk.fork_extras().expect("reads").len(),
            "one combine per fork the finished tree holds"
        );
        assert_eq!(combines, keys.len() - 1);

        // The same keys one at a time recombine every summary above each key as it arrives,
        // which is the work the bulk build does not repeat.
        let mut one_at_a_time =
            AugDict::new(CountedCombines(core::cell::Cell::new(0)), 32).expect("a dictionary");
        for (key, extra, value) in counted_items(&keys) {
            one_at_a_time.set(&key, &extra, &value).expect("set");
        }
        assert_eq!(
            one_at_a_time.root().map(Cell::repr_hash),
            bulk.root().map(Cell::repr_hash),
            "the two builds are the same tree",
        );
        assert!(
            one_at_a_time.aug.0.get() > combines,
            "{} combines one at a time against {combines} in bulk",
            one_at_a_time.aug.0.get(),
        );
    }

    #[test]
    fn a_bulk_augmented_build_is_the_tree_the_same_items_set_one_at_a_time_give() {
        // The summaries are part of what the root hash covers, so a bulk build that folded
        // one up the tree differently disagrees here. Nothing and one entry are the shapes
        // with no fork to summarise and two is the smallest with one; the key families run
        // from keys that share every bit but the last few to keys that part at their first.
        for n in [0u32, 1, 2, 3, 8, 17, 64] {
            for (what, keys) in [
                ("counting up from zero", (0..n).collect::<Vec<u32>>()),
                ("ending on a fixed bit", (0..n).map(|i| i << 1).collect()),
                (
                    "parting at the first bit",
                    (0..n).map(u32::reverse_bits).collect(),
                ),
            ] {
                let items = counted_items(&keys);
                let bulk = AugDict::from_items(CountSum, 32, items.clone()).expect("from_items");

                let mut one_at_a_time = AugDict::new(CountSum, 32).expect("a dictionary");
                for (key, extra, value) in &items {
                    one_at_a_time.set(key, extra, value).expect("set");
                }
                assert_eq!(
                    bulk.root().map(Cell::repr_hash),
                    one_at_a_time.root().map(Cell::repr_hash),
                    "{n} keys {what}",
                );

                // Again under a summary that is not commutative, over items whose leaf
                // summaries all differ. Both are needed: `CountSum` cannot see a swapped
                // fork at all, and `CountSkew` cannot see one whose two children carry the
                // same summary, which is every fork of a balanced tree under `counted_items`.
                let skewed = skewed_items(&keys);
                let skew_bulk =
                    AugDict::from_items(CountSkew, 32, skewed.clone()).expect("from_items");
                let mut skew_one = AugDict::new(CountSkew, 32).expect("a dictionary");
                for (key, extra, value) in &skewed {
                    skew_one.set(key, extra, value).expect("set");
                }
                assert_eq!(
                    skew_bulk.root().map(Cell::repr_hash),
                    skew_one.root().map(Cell::repr_hash),
                    "{n} keys {what}, under a summary that reads its children in order",
                );
                skew_bulk
                    .validate()
                    .expect("every fork folds its children in order");

                // Every leaf counts one, so the root summary is the number of keys, and the
                // tree the bulk build wrote holds to its own summary rule.
                bulk.validate().expect("every fork sums its children");
                let expected = u32::try_from(keys.len()).expect("a small count");
                assert_eq!(
                    bulk.root_extra().expect("extra"),
                    (n > 0).then_some(expected),
                    "{n} keys {what}",
                );
            }
        }
    }

    #[test]
    fn a_carved_augmented_sub_dictionary_stays_consistent() {
        // Carving relabels the top edge but leaves every subtree it keeps as it was, so the
        // summaries still hold and the count over the kept keys is exact.
        let mut dict = AugDict::new(CountSum, 16).expect("a dictionary");
        let mut value = Builder::new();
        value.store_uint(0, 8).expect("a byte fits");
        for key in [0xab01u16, 0xab02, 0xabff, 0x1234] {
            dict.set(&key.to_be_bytes(), &1, &value).expect("set");
        }

        let sub = dict.subdict(&[0xab], 8).expect("subdict");
        assert_eq!(sub.key_bits(), 8);
        assert_eq!(sub.count().expect("count"), 3);
        assert_eq!(sub.root_extra().expect("extra"), Some(3));
        sub.validate()
            .expect("a carved augmented dictionary still sums");
    }

    #[test]
    fn combining_two_halves_rebuilds_the_whole() {
        let whole = counted(&[1, 2, 3, 100, 200]);
        let mut left = counted(&[1, 2, 3]);
        left.combine_with(&counted(&[100, 200]))
            .expect("disjoint keys combine");
        assert_eq!(
            left.root().map(Cell::repr_hash),
            whole.root().map(Cell::repr_hash),
        );
        assert_eq!(left.root_extra().expect("extra"), Some(5));
    }

    #[test]
    fn combining_dictionaries_that_share_a_key_is_refused_and_changes_nothing() {
        let mut dict = counted(&[1, 2]);
        assert!(matches!(
            dict.combine_with(&counted(&[2, 3])),
            Err(CellError::Malformed(_))
        ));
        assert_eq!(dict.count().expect("count"), 2, "the refused combine held");
    }

    #[test]
    fn combining_with_an_empty_dictionary_changes_nothing() {
        let mut dict = counted(&[1, 2, 3]);
        let before = dict.root().expect("not empty").repr_hash().to_owned();
        dict.combine_with(&AugDict::new(CountSum, 32).expect("empty"))
            .expect("an empty side combines");
        assert_eq!(dict.root().expect("not empty").repr_hash(), &before);
    }

    fn key_of(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes.try_into().expect("a four-byte key"))
    }

    #[test]
    fn traverse_extra_offers_each_fork_before_the_leaves_below_it() {
        /// One node a walk saw: a fork with its summary, or a leaf with its key and summary.
        #[derive(Debug, PartialEq)]
        enum Seen {
            Fork(u32),
            Leaf(u32, u32),
        }

        // Keys 1, 2 and 3 share thirty zero bits, so the root forks on the next: 1 to the
        // left, 2 and 3 to a sub-fork on the right. Pre-order visits a fork before its
        // subtree, so the summaries lead the leaves they cover.
        let dict = counted(&[1, 2, 3]);
        let mut seen = Vec::new();
        dict.traverse_extra(|node| {
            match node {
                AugNode::Fork { extra, .. } => seen.push(Seen::Fork(*extra)),
                AugNode::Leaf { key, extra, .. } => seen.push(Seen::Leaf(key_of(key), *extra)),
            }
            Traverse::Continue
        })
        .expect("walks");

        assert_eq!(
            seen,
            vec![
                Seen::Fork(3),
                Seen::Leaf(1, 1),
                Seen::Fork(2),
                Seen::Leaf(2, 1),
                Seen::Leaf(3, 1),
            ]
        );
    }

    #[test]
    fn a_walk_offers_each_fork_the_prefix_that_leads_to_it() {
        // A directed walk spells its prefixes down its own recursion rather than through the
        // one `fork_extras` uses, so the same keys go through both. The prefix a visitor is
        // handed is what it prunes a subtree by, and a subtree pruned by the wrong path is
        // the wrong answer with nothing to say so.
        let dict = counted(&LABELLED_KEYS);
        let mut offered = Vec::new();
        let mut leaves = Vec::new();
        dict.traverse_extra(|node| {
            match node {
                AugNode::Fork { prefix, .. } => offered.push(prefix.to_vec()),
                AugNode::Leaf { key, .. } => leaves.push(key_of(key)),
            }
            Traverse::Continue
        })
        .expect("walks");

        assert_eq!(offered, vec![bits("1011"), bits("10111001")]);
        assert_eq!(leaves, LABELLED_KEYS.to_vec(), "in ascending key order");
    }

    #[test]
    fn traverse_extra_skips_a_subtree_when_the_visitor_asks() {
        // The top bit splits 1, 2 and 3 from the high key, so the left subtree is a fork of
        // three under the root. Skipping that fork by its summary must leave its three leaves
        // unread while the leaf on the other side is still visited.
        let dict = counted(&[1, 2, 3, 0x8000_0000]);
        let mut leaves = Vec::new();
        let mut skipped = false;
        dict.traverse_extra(|node| match node {
            AugNode::Fork { extra, .. } if *extra == 3 => {
                skipped = true;
                Traverse::Skip
            }
            AugNode::Fork { .. } => Traverse::Continue,
            AugNode::Leaf { key, .. } => {
                leaves.push(key_of(key));
                Traverse::Continue
            }
        })
        .expect("walks");

        assert!(skipped, "the subtree fork was offered before its leaves");
        assert_eq!(
            leaves,
            vec![0x8000_0000],
            "the skipped subtree's leaves were not read"
        );
    }

    #[test]
    fn traverse_extra_stops_the_walk_when_the_visitor_asks() {
        // Stop at the first leaf. Ascending order makes that the smallest key, and nothing
        // after it is visited.
        let dict = counted(&[5, 1, 9, 3]);
        let mut visited = Vec::new();
        dict.traverse_extra(|node| {
            if let AugNode::Leaf { key, .. } = node {
                visited.push(key_of(key));
                return Traverse::Stop;
            }
            Traverse::Continue
        })
        .expect("walks");

        assert_eq!(visited, vec![1], "stop halts at the first, smallest, leaf");
    }

    #[test]
    fn a_subtree_total_reads_from_the_one_summary_the_fork_carries() {
        // The root fork's summary is the whole dictionary's, so skipping the root still learns
        // the total from the single summary that one visit saw, reading no leaf at all.
        let dict = counted(&[1, 2, 3, 100, 1000]);
        let mut total = None;
        let mut leaves = 0u32;
        dict.traverse_extra(|node| match node {
            AugNode::Fork { extra, .. } => {
                total = Some(*extra);
                Traverse::Skip
            }
            AugNode::Leaf { .. } => {
                leaves += 1;
                Traverse::Continue
            }
        })
        .expect("walks");

        assert_eq!(total, Some(5), "the root summary already counts every leaf");
        assert_eq!(leaves, 0, "skipping the root read no leaf");
    }
}
