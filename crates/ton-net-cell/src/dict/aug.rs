// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The augmented `HashmapAug n X Y`: a dictionary whose every node also carries a summary
//! of the subtree below it.

use super::label::read_label;
use super::{
    check_key_bits, collapse, collect_fork_extras, descend, key_of, leaf, lookup, rebuild, rest,
    split, validate_tree, walk_step, DictEntry, Entry, ForkExtra, Lookup, Pending, Shape,
};
use crate::builder::Builder;
use crate::cell::Cell;
use crate::error::CellError;
use crate::slice::Slice;

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
/// use ton_net_cell::{Augmentation, Builder, CellError, Slice};
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
    read_label(&mut slice, max)?;
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

/// An augmented dictionary: TON's `HashmapAug n X Y`.
///
/// The same tree as [`Dict`](crate::Dict), except every node also carries a `Y`
/// summarising everything below it, and a fork's is the combination of its two children's.
/// What a `Y` is and how two combine come from the [`Augmentation`] this is built over.
///
/// A summary is recomputed from the children on every write rather than carried forward,
/// because a fork above a changed subtree that kept its old summary would describe the
/// subtree that used to be there while still hashing as a well-formed dictionary.
///
/// This models the `HashmapAug` edge. `HashmapAugE`'s wrapper, the bit saying whether
/// there is a root at all and the summary beside it, belongs to the caller, exactly as
/// [`Dict`](crate::Dict) leaves `HashmapE`'s bit to its own.
///
/// # Examples
///
/// ```
/// # use ton_net_cell::{Augmentation, AugDict, Builder, CellError, Lookup, Slice};
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
/// # Ok::<(), ton_net_cell::CellError>(())
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
    /// [`Dict::get`](crate::Dict::get).
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
                .map(|root| vec![(root, Vec::new(), self.key_bits)])
                .unwrap_or_default(),
            done: false,
        }
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
/// Built by [`AugDict::iter`]. Like [`DictIter`](crate::DictIter) it stops at a pruned
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
}
