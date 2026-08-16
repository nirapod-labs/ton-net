// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Building a cell.
//!
//! [`Builder`] is the only way to make a cell that did not come from parsing. Until it
//! existed this crate could read TON's format and not write it, which left the library
//! able to check a proof and unable to construct a message, a dictionary or a proof of
//! its own.
//!
//! A builder accumulates bits and references and hands back a [`Cell`] whose hashes are
//! computed once, at the end, from what was stored. There is no way to set a hash, and
//! no way to reach the constructor that would let one disagree with its contents.

use crate::cell::cell::{Cell, CellType, Payload, Refs, MAX_BITS, MAX_REFS};
use crate::cell::dict::Dict;
use crate::cell::error::CellError;
use crate::cell::slice::Slice;

mod address;
mod either;
mod snake;

/// Accumulates the bits and references of a cell under construction.
///
/// The limits are the cell model's own: [`MAX_BITS`] bits and [`MAX_REFS`] references. A
/// store that would pass either fails rather than truncating, because a silently short
/// write produces a cell with a different hash, and a hash is an identity here rather
/// than a checksum.
///
/// # Examples
///
/// ```
/// use ton_net::cell::Builder;
///
/// let mut b = Builder::new();
/// b.store_uint(0xab, 8)?;
/// let cell = b.build()?;
/// assert_eq!(cell.bit_len(), 8);
/// assert_eq!(cell.data(), [0xab]);
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builder {
    /// Bits `0..bits`, most significant first. Anything past `bits` in the final byte is
    /// zero while building; [`build`](Builder::build) writes the completion tag.
    data: Vec<u8>,
    bits: u16,
    refs: Refs,
}

impl Builder {
    /// A builder holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            bits: 0,
            refs: Refs::None,
        }
    }

    /// How many data bits have been stored.
    #[must_use]
    pub fn bits_used(&self) -> u16 {
        self.bits
    }

    /// How many more data bits fit.
    #[must_use]
    pub fn bits_left(&self) -> u16 {
        MAX_BITS - self.bits
    }

    /// How many references have been stored.
    #[must_use]
    pub fn refs_used(&self) -> usize {
        self.refs.as_slice().len()
    }

    /// How many more references fit.
    #[must_use]
    pub fn refs_left(&self) -> usize {
        MAX_REFS - self.refs.as_slice().len()
    }

    /// Whether this many bits and references would still fit.
    #[must_use]
    pub fn can_extend_by(&self, bits: u16, refs: usize) -> bool {
        bits <= self.bits_left() && refs <= self.refs_left()
    }

    /// Checks there is room for `bits` more bits.
    fn room_for(&self, bits: u16) -> Result<(), CellError> {
        if bits > self.bits_left() {
            return Err(CellError::NoRoomForBits {
                requested: usize::from(bits),
                available: usize::from(self.bits_left()),
            });
        }
        Ok(())
    }

    /// Stores one bit.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the cell is full.
    pub fn store_bit(&mut self, bit: bool) -> Result<&mut Self, CellError> {
        self.room_for(1)?;
        if self.bits % 8 == 0 {
            self.data.push(0);
        }
        if bit {
            // The byte just pushed, or the one being filled; either way the last.
            if let Some(byte) = self.data.last_mut() {
                *byte |= 1 << (7 - (self.bits % 8));
            }
        }
        self.bits += 1;
        Ok(self)
    }

    /// Stores the low `bits` bits of `value`, most significant first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::TooWide`] if `bits` is over 64, [`CellError::Malformed`] if
    /// `value` does not fit in `bits`, and [`CellError::NoRoomForBits`] if the cell has
    /// no room. A value that does not fit is refused rather than truncated: the cell it
    /// would produce is a different cell, with a different hash, and nothing downstream
    /// would say so.
    pub fn store_uint(&mut self, value: u64, bits: u32) -> Result<&mut Self, CellError> {
        if bits > u64::BITS {
            return Err(CellError::TooWide {
                requested: bits,
                width: u64::BITS,
            });
        }
        if bits < u64::BITS && value >= (1u64 << bits) {
            return Err(CellError::Malformed(
                "value does not fit the requested bits",
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        self.room_for(bits as u16)?;
        for offset in (0..bits).rev() {
            self.store_bit((value >> offset) & 1 == 1)?;
        }
        Ok(self)
    }

    /// Stores `value` as a two's-complement signed integer of `bits` bits.
    ///
    /// A zero-width field holds only zero and writes nothing, which is what
    /// [`store_uint`](Builder::store_uint) does with the same argument and what
    /// [`load_int`](crate::cell::Slice::load_int) reads back from no bits at all. The three used
    /// to disagree: a zero width was a `TooWide` here and a written nothing there, so the
    /// one length a variable-width encoding reaches for its zero was a failure on the
    /// signed side alone.
    ///
    /// # Errors
    ///
    /// As [`store_uint`](Builder::store_uint), with the range check taken over the signed
    /// range that `bits` bits can hold.
    pub fn store_int(&mut self, value: i64, bits: u32) -> Result<&mut Self, CellError> {
        if bits > i64::BITS {
            return Err(CellError::TooWide {
                requested: bits,
                width: i64::BITS,
            });
        }
        if bits == 0 {
            if value != 0 {
                return Err(CellError::Malformed(
                    "value does not fit the requested bits",
                ));
            }
        } else if bits < i64::BITS {
            let limit = 1i64 << (bits - 1);
            if value >= limit || value < -limit {
                return Err(CellError::Malformed(
                    "value does not fit the requested bits",
                ));
            }
        }
        #[allow(clippy::cast_sign_loss)]
        let unsigned = value as u64;
        #[allow(clippy::cast_possible_truncation)]
        self.room_for(bits as u16)?;
        for offset in (0..bits).rev() {
            self.store_bit((unsigned >> offset) & 1 == 1)?;
        }
        Ok(self)
    }

    // The four fixed-width stores below are the write side of the fixed-width loads on
    // Slice. The width is the method rather than an argument, so the pair a field is
    // written and read with cannot disagree about how wide it is.

    /// Stores a `u8` in eight bits.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the cell has no room.
    pub fn store_u8(&mut self, value: u8) -> Result<&mut Self, CellError> {
        self.store_uint(u64::from(value), 8)
    }

    /// Stores a `u16` in sixteen bits, most significant first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the cell has no room.
    pub fn store_u16(&mut self, value: u16) -> Result<&mut Self, CellError> {
        self.store_uint(u64::from(value), 16)
    }

    /// Stores a `u32` in thirty-two bits, most significant first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the cell has no room.
    pub fn store_u32(&mut self, value: u32) -> Result<&mut Self, CellError> {
        self.store_uint(u64::from(value), 32)
    }

    /// Stores an `i32` in thirty-two bits, most significant first.
    ///
    /// This is TL-B's `int32`, which a workchain id uses, and the bits are the ones
    /// [`store_u32`](Builder::store_u32) writes; only the meaning of the top one differs.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if the cell has no room.
    pub fn store_i32(&mut self, value: i32) -> Result<&mut Self, CellError> {
        self.store_int(i64::from(value), 32)
    }

    /// Stores the low `bits` bits of a wide unsigned integer, most significant first.
    ///
    /// # Errors
    ///
    /// As [`store_uint`](Builder::store_uint), over 128 bits rather than 64.
    pub fn store_uint128(&mut self, value: u128, bits: u32) -> Result<&mut Self, CellError> {
        if bits > u128::BITS {
            return Err(CellError::TooWide {
                requested: bits,
                width: u128::BITS,
            });
        }
        if bits < u128::BITS && value >= (1u128 << bits) {
            return Err(CellError::Malformed(
                "value does not fit the requested bits",
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        self.room_for(bits as u16)?;
        for offset in (0..bits).rev() {
            self.store_bit((value >> offset) & 1 == 1)?;
        }
        Ok(self)
    }

    /// Stores `value` as a two's-complement signed integer of `bits` bits, over 128 bits
    /// rather than 64.
    ///
    /// The signed twin of [`store_uint128`](Builder::store_uint128), and not reachable
    /// through it: a negative value cast to `u128` sits above the field's range, which the
    /// unsigned store refuses at any width below 128.
    ///
    /// # Errors
    ///
    /// As [`store_int`](Builder::store_int), over 128 bits rather than 64.
    pub fn store_int128(&mut self, value: i128, bits: u32) -> Result<&mut Self, CellError> {
        if bits > i128::BITS {
            return Err(CellError::TooWide {
                requested: bits,
                width: i128::BITS,
            });
        }
        if bits == 0 {
            if value != 0 {
                return Err(CellError::Malformed(
                    "value does not fit the requested bits",
                ));
            }
        } else if bits < i128::BITS {
            let limit = 1i128 << (bits - 1);
            if value >= limit || value < -limit {
                return Err(CellError::Malformed(
                    "value does not fit the requested bits",
                ));
            }
        }
        #[allow(clippy::cast_sign_loss)]
        let unsigned = value as u128;
        #[allow(clippy::cast_possible_truncation)]
        self.room_for(bits as u16)?;
        for offset in (0..bits).rev() {
            self.store_bit((unsigned >> offset) & 1 == 1)?;
        }
        Ok(self)
    }

    /// Stores a `VarUInteger max`: a byte count, then that many bytes of value.
    ///
    /// The count is the fewest bytes that hold the value, and zero stores no bytes at
    /// all. That minimum is not a size optimisation but the encoding itself: a longer
    /// count with leading zeros reads back as the same number and gives the cell a
    /// different hash, the same way a non-minimal dictionary label does.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `max` is below two or the value needs more
    /// than `max - 1` bytes, and [`CellError::NoRoomForBits`] if it does not fit.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net::cell::Builder;
    ///
    /// let mut b = Builder::new();
    /// b.store_var_uint(42, 16)?;
    /// // A four-bit length of one, then the byte itself.
    /// assert_eq!(b.bits_used(), 12);
    /// # Ok::<(), ton_net::cell::CellError>(())
    /// ```
    pub fn store_var_uint(&mut self, value: u128, max: u32) -> Result<&mut Self, CellError> {
        if max < 2 {
            return Err(CellError::Malformed(
                "variable integer needs a max above one",
            ));
        }
        let len_bits = u32::BITS - (max - 1).leading_zeros();
        // The fewest whole bytes that hold the value; zero needs none.
        let bytes = if value == 0 {
            0u32
        } else {
            (u128::BITS - value.leading_zeros()).div_ceil(8)
        };
        if bytes >= max {
            return Err(CellError::Malformed(
                "value is too wide for this VarUInteger",
            ));
        }
        // Both halves are checked together. Writing the length and then failing on the
        // value leaves a count with nothing behind it, which reads back as a different
        // number rather than as an error.
        #[allow(clippy::cast_possible_truncation)]
        self.room_for((len_bits + bytes * 8) as u16)?;
        self.store_uint(u64::from(bytes), len_bits)?;
        self.store_uint128(value, bytes * 8)?;
        Ok(self)
    }

    /// Stores a `VarInteger max`: a byte count, then that many bytes of two's-complement
    /// value.
    ///
    /// The signed form of the same length-then-bytes shape TL-B gives `VarUInteger max`.
    /// The count is the fewest bytes whose two's-complement form holds the value, so the
    /// sign bit is part of what decides the length: 127 takes one byte and 128 takes two,
    /// while -128 takes one and -129 takes two. Zero stores no bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `max` is below two or the value needs more
    /// than `max - 1` bytes, and [`CellError::NoRoomForBits`] if it does not fit.
    pub fn store_var_int(&mut self, value: i128, max: u32) -> Result<&mut Self, CellError> {
        if max < 2 {
            return Err(CellError::Malformed(
                "variable integer needs a max above one",
            ));
        }
        let len_bits = u32::BITS - (max - 1).leading_zeros();
        let bytes = signed_byte_len(value);
        if bytes >= max {
            return Err(CellError::Malformed(
                "value is too wide for this VarInteger",
            ));
        }
        // Both halves are checked together, for the reason store_var_uint gives: a length
        // written with nothing behind it reads back as a different number, not as an error.
        #[allow(clippy::cast_possible_truncation)]
        self.room_for((len_bits + bytes * 8) as u16)?;
        self.store_uint(u64::from(bytes), len_bits)?;
        self.store_int128(value, bytes * 8)?;
        Ok(self)
    }

    /// Stores an amount in nanotons, which TON encodes as `VarUInteger 16`.
    ///
    /// # Errors
    ///
    /// As [`store_var_uint`](Builder::store_var_uint).
    pub fn store_coins(&mut self, nanotons: u128) -> Result<&mut Self, CellError> {
        self.store_var_uint(nanotons, 16)
    }

    /// Stores the same bit `count` times.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if they do not fit.
    pub fn store_same_bit(&mut self, bit: bool, count: u16) -> Result<&mut Self, CellError> {
        self.room_for(count)?;
        for _ in 0..count {
            self.store_bit(bit)?;
        }
        Ok(self)
    }

    /// Stores a run of bits.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if they do not fit.
    pub fn store_bits(&mut self, bits: &[bool]) -> Result<&mut Self, CellError> {
        let count = u16::try_from(bits.len()).unwrap_or(u16::MAX);
        self.room_for(count)?;
        for bit in bits {
            self.store_bit(*bit)?;
        }
        Ok(self)
    }

    /// Drops every data bit past `bits`, leaving the references alone.
    ///
    /// This is how a caller undoes a speculative write. The dropped bits are cleared
    /// rather than merely forgotten, because a later store sets bits and never clears
    /// them, so a stale one would survive underneath.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the builder holds fewer than `bits`.
    pub fn truncate_bits(&mut self, bits: u16) -> Result<&mut Self, CellError> {
        if bits > self.bits {
            return Err(CellError::NotEnoughBits {
                requested: usize::from(bits),
                available: usize::from(self.bits),
            });
        }
        self.bits = bits;
        self.data.truncate(usize::from(bits).div_ceil(8));
        if bits % 8 != 0 {
            if let Some(last) = self.data.last_mut() {
                *last &= 0xffu8 << (8 - (bits % 8));
            }
        }
        Ok(self)
    }

    /// Drops every reference past `refs`, leaving the data bits alone.
    ///
    /// The reference half of [`truncate_bits`](Builder::truncate_bits), and the only way
    /// to un-store a reference. A caller undoing a speculative write could put the bits
    /// back and not the children, which left a builder that had spent room it could not
    /// recover.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughRefs`] if the builder holds fewer than `refs`.
    pub fn truncate_refs(&mut self, refs: usize) -> Result<&mut Self, CellError> {
        if refs > self.refs.as_slice().len() {
            return Err(CellError::NotEnoughRefs);
        }
        self.refs.truncate(refs);
        Ok(self)
    }

    /// Stores whole bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForBits`] if they do not fit.
    pub fn store_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, CellError> {
        let bits =
            u16::try_from(bytes.len().saturating_mul(8)).map_err(|_| CellError::NoRoomForBits {
                requested: bytes.len().saturating_mul(8),
                available: usize::from(self.bits_left()),
            })?;
        self.room_for(bits)?;
        for byte in bytes {
            self.store_uint(u64::from(*byte), 8)?;
        }
        Ok(self)
    }

    /// Stores a reference.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForRefs`] if the cell already holds [`MAX_REFS`].
    pub fn store_ref(&mut self, cell: Cell) -> Result<&mut Self, CellError> {
        if self.refs.as_slice().len() >= MAX_REFS {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        self.refs.push(cell)?;
        Ok(self)
    }

    /// Stores a `Maybe`: one bit, and the reference when there is one.
    ///
    /// # Errors
    ///
    /// As [`store_bit`](Builder::store_bit) and [`store_ref`](Builder::store_ref). The
    /// bit and the reference are checked for room together, so a failure leaves the
    /// builder as it was rather than holding a set bit with nothing behind it.
    pub fn store_maybe_ref(&mut self, cell: Option<Cell>) -> Result<&mut Self, CellError> {
        match cell {
            Some(cell) => {
                if self.refs.as_slice().len() >= MAX_REFS {
                    return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
                }
                self.room_for(1)?;
                self.store_bit(true)?;
                self.store_ref(cell)?;
            }
            None => {
                self.store_bit(false)?;
            }
        }
        Ok(self)
    }

    /// Stores a `HashmapE`: the `Maybe` reference to a dictionary's root.
    ///
    /// An empty dictionary writes one clear bit; a non-empty one writes a set bit and a
    /// reference to its root. This is [`store_maybe_ref`](Builder::store_maybe_ref) over
    /// [`Dict::root`], named for a reader writing a dictionary field. An augmented
    /// dictionary is stored the same way, through `store_maybe_ref` on its own root.
    ///
    /// # Errors
    ///
    /// As [`store_maybe_ref`](Builder::store_maybe_ref).
    pub fn store_dict(&mut self, dict: &Dict) -> Result<&mut Self, CellError> {
        self.store_maybe_ref(dict.root().cloned())
    }

    /// Stores everything a slice has left: its remaining bits, then its remaining
    /// references.
    ///
    /// # Errors
    ///
    /// As the stores it performs. The slice is taken by value, so a caller keeps the
    /// original cursor if they need it.
    pub fn store_slice(&mut self, mut slice: Slice<'_>) -> Result<&mut Self, CellError> {
        let bits = u16::try_from(slice.remaining_bits()).unwrap_or(MAX_BITS);
        self.room_for(bits)?;
        if slice.remaining_refs() > self.refs_left() {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        while slice.remaining_bits() > 0 {
            self.store_bit(slice.load_bit()?)?;
        }
        while slice.remaining_refs() > 0 {
            self.store_ref(slice.load_ref()?.clone())?;
        }
        Ok(self)
    }

    /// Appends another builder's contents.
    ///
    /// # Errors
    ///
    /// As the stores it performs.
    pub fn store_builder(&mut self, other: &Self) -> Result<&mut Self, CellError> {
        self.room_for(other.bits)?;
        if other.refs.as_slice().len() > self.refs_left() {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        for index in 0..other.bits {
            self.store_bit(other.bit_at(index))?;
        }
        for cell in other.refs.as_slice() {
            self.store_ref(cell.clone())?;
        }
        Ok(self)
    }

    /// The bit at `index`, or false past the end.
    fn bit_at(&self, index: u16) -> bool {
        if index >= self.bits {
            return false;
        }
        match self.data.get(usize::from(index / 8)) {
            Some(byte) => (byte >> (7 - (index % 8))) & 1 == 1,
            None => false,
        }
    }

    /// Finishes an ordinary cell.
    ///
    /// The level mask is computed from the references rather than taken from the caller,
    /// so a built cell cannot claim a level its children do not give it.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if the parts do not form a cell, which for an
    /// ordinary cell means the hashing rules rejected them.
    pub fn build(self) -> Result<Cell, CellError> {
        let mask = self
            .refs
            .as_slice()
            .iter()
            .fold(0u8, |mask, child| mask | child.level_mask());
        self.finish(CellType::Ordinary, mask)
    }

    /// Finishes a cell of a given kind, with a level mask the caller names.
    ///
    /// Only a pruned branch needs this: its mask says which levels it stands in for, and
    /// that cannot be derived from children it does not have. Every other kind computes
    /// its own mask and ignores the argument.
    pub(crate) fn finish(mut self, cell_type: CellType, level_mask: u8) -> Result<Cell, CellError> {
        // The stored form carries the data bits, then a set bit, then zeros. Bits past
        // the count are already zero, so setting the completion bit is the whole of it.
        if self.bits % 8 != 0 {
            if let Some(last) = self.data.last_mut() {
                *last |= 1 << (7 - (self.bits % 8));
            }
        }
        Cell::from_parts(
            Payload::owned(self.data)?,
            self.bits,
            self.refs,
            cell_type,
            level_mask,
        )
    }
}

/// The fewest whole bytes whose two's-complement form holds `value`; zero needs none.
///
/// The sign bit is counted, which is what separates this from the unsigned measurement in
/// [`Builder::store_var_uint`]: 128 needs a ninth bit to keep it positive and so takes two
/// bytes, while -128 fills its eighth bit as the sign and takes one.
fn signed_byte_len(value: i128) -> u32 {
    if value == 0 {
        return 0;
    }
    // A negative's magnitude is measured on its complement, since leading_zeros counts the
    // bit pattern and every negative starts with a one. `!value` is `-value - 1`, which is
    // exactly the width -2^k needs: k bits of magnitude and one of sign.
    let magnitude_bits = if value < 0 {
        i128::BITS - (!value).leading_zeros()
    } else {
        i128::BITS - value.leading_zeros()
    };
    (magnitude_bits + 1).div_ceil(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a builder's contents back, which is the only way to check them without
    /// reaching into its fields.
    fn roundtrip(b: Builder) -> Cell {
        b.build().expect("builds")
    }

    #[test]
    fn a_built_cell_holds_what_was_stored() {
        let mut b = Builder::new();
        b.store_uint(0xab, 8).unwrap();
        b.store_bit(true).unwrap();
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 9);
        let mut s = cell.parse();
        assert_eq!(s.load_uint(8).unwrap(), 0xab);
        assert!(s.load_bit().unwrap());
        assert_eq!(s.remaining_bits(), 0);
    }

    #[test]
    fn a_stored_dictionary_reads_back_to_the_same_root() {
        // A small dictionary over sixteen-bit keys.
        let mut dict = Dict::new(16).expect("a sane key width");
        let mut value = Builder::new();
        value.store_uint(0xdead, 16).expect("fits");
        dict.set_uint(1, &value).expect("sets key one");
        dict.set_uint(2, &value).expect("sets key two");
        let root_hash = dict.root().expect("not empty").repr_hash();

        // Stored as a HashmapE, the Maybe reference reads back to that same root.
        let mut b = Builder::new();
        b.store_dict(&dict).expect("stores");
        let cell = roundtrip(b);
        let mut slice = cell.parse();
        let stored_root = slice
            .load_maybe_ref()
            .expect("a bit and a reference")
            .expect("present");
        assert_eq!(stored_root.repr_hash(), root_hash, "the same root cell");
        assert!(slice.is_empty(), "a HashmapE is only the Maybe reference");

        // And it reconstructs into a dictionary that still answers.
        let again = Dict::from_root(Some(stored_root.clone()), 16).expect("a valid root");
        assert!(again.get_uint(1).expect("lookup").found().is_some());
    }

    #[test]
    fn an_empty_dictionary_stores_a_single_clear_bit() {
        let dict = Dict::new(16).expect("a sane key width");
        let mut b = Builder::new();
        b.store_dict(&dict).expect("stores");
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 1);
        assert!(cell.parse().load_maybe_ref().expect("a bit").is_none());
    }

    #[test]
    fn an_unaligned_cell_carries_the_completion_tag() {
        // Three bits, 101, then the tag: 1011_0000.
        let mut b = Builder::new();
        b.store_uint(0b101, 3).unwrap();
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 3);
        assert_eq!(cell.data(), [0b1011_0000]);
    }

    #[test]
    fn an_aligned_cell_carries_no_tag() {
        let mut b = Builder::new();
        b.store_uint(0xff, 8).unwrap();
        assert_eq!(roundtrip(b).data(), [0xff]);
    }

    #[test]
    fn a_value_wider_than_its_field_is_refused() {
        let mut b = Builder::new();
        assert!(matches!(b.store_uint(256, 8), Err(CellError::Malformed(_))));
        // And nothing was written.
        assert_eq!(b.bits_used(), 0);
    }

    #[test]
    fn signed_values_round_trip_at_their_bounds() {
        for (value, bits) in [(-1i64, 8u32), (-128, 8), (127, 8), (0, 8), (-1, 64)] {
            let mut b = Builder::new();
            b.store_int(value, bits).unwrap();
            let cell = roundtrip(b);
            assert_eq!(
                cell.parse().load_int(bits).unwrap(),
                value,
                "{value} in {bits}"
            );
        }
    }

    #[test]
    fn a_signed_value_outside_its_range_is_refused() {
        let mut b = Builder::new();
        assert!(b.store_int(128, 8).is_err());
        assert!(b.store_int(-129, 8).is_err());
        b.store_int(-128, 8).unwrap();
    }

    #[test]
    fn coins_use_the_fewest_bytes() {
        // Zero stores a length of zero and no bytes at all.
        let mut b = Builder::new();
        b.store_coins(0).unwrap();
        assert_eq!(b.bits_used(), 4);
        assert_eq!(roundtrip(b).parse().load_coins().unwrap(), 0);

        // 255 fits one byte, 256 needs two. A longer encoding would read back the same
        // and hash differently, so the boundary is the whole point.
        let mut b = Builder::new();
        b.store_coins(255).unwrap();
        assert_eq!(b.bits_used(), 12);
        let mut b = Builder::new();
        b.store_coins(256).unwrap();
        assert_eq!(b.bits_used(), 20);
    }

    #[test]
    fn coins_round_trip_across_widths() {
        for value in [
            0u128,
            1,
            255,
            256,
            1_000_000_000,
            u128::from(u64::MAX),
            1 << 100,
        ] {
            let mut b = Builder::new();
            b.store_coins(value).unwrap();
            assert_eq!(roundtrip(b).parse().load_coins().unwrap(), value);
        }
    }

    #[test]
    fn a_full_cell_refuses_another_bit() {
        let mut b = Builder::new();
        b.store_same_bit(true, MAX_BITS).unwrap();
        assert_eq!(b.bits_left(), 0);
        assert!(matches!(
            b.store_bit(false),
            Err(CellError::NoRoomForBits { .. })
        ));
    }

    #[test]
    fn a_full_cell_refuses_another_reference() {
        let leaf = Builder::new().build().unwrap();
        let mut b = Builder::new();
        for _ in 0..MAX_REFS {
            b.store_ref(leaf.clone()).unwrap();
        }
        assert_eq!(b.refs_left(), 0);
        assert!(matches!(
            b.store_ref(leaf),
            Err(CellError::NoRoomForRefs { .. })
        ));
    }

    #[test]
    fn truncation_clears_the_bits_it_drops() {
        let mut b = Builder::new();
        b.store_uint(0b1111, 4).unwrap();
        b.truncate_bits(1).unwrap();
        b.store_uint(0b000, 3).unwrap();
        // Without clearing, the dropped ones would still be set underneath.
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 4);
        assert_eq!(cell.parse().load_uint(4).unwrap(), 0b1000);
    }

    #[test]
    fn a_maybe_ref_that_cannot_fit_stores_no_bit() {
        let leaf = Builder::new().build().unwrap();
        let mut b = Builder::new();
        for _ in 0..MAX_REFS {
            b.store_ref(leaf.clone()).unwrap();
        }
        assert!(b.store_maybe_ref(Some(leaf)).is_err());
        // A set bit with nothing behind it would decode as a reference that is not there.
        assert_eq!(b.bits_used(), 0);
    }

    #[test]
    fn a_var_uint_that_cannot_fit_stores_nothing() {
        // Room for the four-bit length but not the byte that follows it.
        let mut b = Builder::new();
        b.store_same_bit(false, MAX_BITS - 6).unwrap();
        let before = b.bits_used();
        assert!(b.store_coins(255).is_err());
        // A length with no value behind it decodes as a different number entirely.
        assert_eq!(
            b.bits_used(),
            before,
            "a failed store must leave nothing behind"
        );
    }

    /// A cell of one distinguishable byte, for telling references apart by their contents.
    fn leaf(byte: u64) -> Cell {
        let mut b = Builder::new();
        b.store_uint(byte, 8).expect("a byte fits");
        b.build().expect("builds")
    }

    #[test]
    fn a_zero_width_integer_field_holds_only_zero_signed_or_not() {
        // The three used to disagree: store_uint wrote nothing, load_int read zero, and
        // store_int refused the width outright, so the one length a variable-width
        // encoding reaches for its zero failed on the signed side alone.
        let mut b = Builder::new();
        b.store_uint(0, 0).unwrap();
        b.store_int(0, 0).unwrap();
        b.store_int128(0, 0).unwrap();
        assert_eq!(b.bits_used(), 0, "a zero-width field writes nothing");
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 0);
        assert_eq!(cell.parse().load_uint(0).unwrap(), 0);
        assert_eq!(cell.parse().load_int(0).unwrap(), 0);
        assert_eq!(cell.parse().load_int128(0).unwrap(), 0);

        // No bits hold no value but zero, and that is the same refusal on either side.
        let mut b = Builder::new();
        assert!(matches!(b.store_uint(1, 0), Err(CellError::Malformed(_))));
        assert!(matches!(b.store_int(1, 0), Err(CellError::Malformed(_))));
        assert!(matches!(b.store_int(-1, 0), Err(CellError::Malformed(_))));
        assert!(matches!(b.store_int128(1, 0), Err(CellError::Malformed(_))));
        assert_eq!(b.bits_used(), 0);
    }

    #[test]
    fn the_fixed_width_stores_write_what_the_matching_loads_read() {
        let mut b = Builder::new();
        b.store_u8(0x89).unwrap();
        b.store_u16(0xabcd).unwrap();
        b.store_u32(0xdead_beef).unwrap();
        b.store_i32(-1_985_229_329).unwrap();
        assert_eq!(b.bits_used(), 8 + 16 + 32 + 32);
        let cell = roundtrip(b);
        let mut s = cell.parse();
        assert_eq!(s.load_u8().unwrap(), 0x89);
        assert_eq!(s.load_u16().unwrap(), 0xabcd);
        assert_eq!(s.load_u32().unwrap(), 0xdead_beef);
        assert_eq!(s.load_i32().unwrap(), -1_985_229_329);
        assert!(s.is_empty());

        // The signed one carries the ends of its type, which is where a width taken as
        // unsigned would refuse the value.
        for value in [i32::MIN, -1, 0, i32::MAX] {
            let mut b = Builder::new();
            b.store_i32(value).unwrap();
            assert_eq!(roundtrip(b).parse().load_i32().unwrap(), value, "{value}");
        }
    }

    #[test]
    fn wide_signed_values_round_trip_at_their_bounds() {
        for (value, bits) in [
            (0i128, 8u32),
            (-1, 8),
            (-128, 8),
            (127, 8),
            (-1, 128),
            (i128::MIN, 128),
            (i128::MAX, 128),
            (1 << 100, 102),
            (-(1i128 << 100), 101),
        ] {
            let mut b = Builder::new();
            b.store_int128(value, bits).unwrap();
            assert_eq!(
                roundtrip(b).parse().load_int128(bits).unwrap(),
                value,
                "{value} in {bits}"
            );
        }
    }

    #[test]
    fn a_wide_signed_value_outside_its_range_is_refused() {
        let mut b = Builder::new();
        assert!(b.store_int128(128, 8).is_err());
        assert!(b.store_int128(-129, 8).is_err());
        assert_eq!(b.bits_used(), 0, "a refused store writes nothing");
        b.store_int128(-128, 8).unwrap();
        assert!(matches!(
            b.store_int128(0, 129),
            Err(CellError::TooWide { width: 128, .. })
        ));
    }

    #[test]
    fn a_signed_var_int_takes_the_fewest_bytes_the_sign_allows() {
        // The sign bit is part of the length, so the two edges do not sit at the same
        // magnitude: 127 fits one byte where 128 does not, and -128 fits one where -129
        // does not. A byte more would read back as the same number with a different hash.
        for (value, bits) in [
            (0i128, 4u16),
            (1, 12),
            (127, 12),
            (128, 20),
            (-1, 12),
            (-128, 12),
            (-129, 20),
        ] {
            let mut b = Builder::new();
            b.store_var_int(value, 16).unwrap();
            assert_eq!(b.bits_used(), bits, "{value}");
            assert_eq!(
                roundtrip(b).parse().load_var_int(16).unwrap(),
                value,
                "{value}"
            );
        }
    }

    #[test]
    fn a_signed_var_int_round_trips_across_widths() {
        // max 17 leaves room for sixteen bytes, which is what the ends of the type need.
        for value in [
            i128::MIN,
            i128::MAX,
            -(1i128 << 100),
            1 << 100,
            0,
            -1,
            255,
            -256,
        ] {
            let mut b = Builder::new();
            b.store_var_int(value, 17).unwrap();
            assert_eq!(
                roundtrip(b).parse().load_var_int(17).unwrap(),
                value,
                "{value}"
            );
        }
    }

    #[test]
    fn a_signed_var_int_too_wide_for_its_max_is_refused_and_stores_nothing() {
        // A VarInteger 16 carries fifteen bytes at most, and the ends of the type need
        // sixteen.
        let mut b = Builder::new();
        assert!(matches!(
            b.store_var_int(i128::MIN, 16),
            Err(CellError::Malformed(_))
        ));
        assert!(matches!(
            b.store_var_int(i128::MAX, 16),
            Err(CellError::Malformed(_))
        ));
        assert_eq!(b.bits_used(), 0);
        assert!(matches!(
            b.store_var_int(0, 1),
            Err(CellError::Malformed(_))
        ));

        // A max whose length field is wider than its own byte limit is where the two
        // refusals part. A VarInteger 3 carries two bytes, and its two-bit length field
        // has a spare code for a third, so without the width check a three-byte value
        // writes a length no reader of that type would accept.
        let mut b = Builder::new();
        assert!(matches!(
            b.store_var_int(100_000, 3),
            Err(CellError::Malformed(_))
        ));
        assert_eq!(b.bits_used(), 0);
        b.store_var_int(-32_768, 3).unwrap();
        assert_eq!(b.bits_used(), 2 + 16, "two bytes are what it does carry");
    }

    #[test]
    fn a_signed_var_int_that_cannot_fit_stores_nothing() {
        // Room for the four-bit length but not the byte behind it.
        let mut b = Builder::new();
        b.store_same_bit(false, MAX_BITS - 6).unwrap();
        let before = b.bits_used();
        assert!(b.store_var_int(-1, 16).is_err());
        assert_eq!(
            b.bits_used(),
            before,
            "a failed store must leave nothing behind"
        );
    }

    #[test]
    fn a_builder_counts_the_references_it_holds() {
        let mut b = Builder::new();
        assert_eq!(b.refs_used(), 0);
        for expected in 1..=MAX_REFS {
            b.store_ref(leaf(0x11)).unwrap();
            assert_eq!(b.refs_used(), expected);
            assert_eq!(b.refs_left(), MAX_REFS - expected);
        }
    }

    #[test]
    fn truncating_references_gives_the_room_back_and_keeps_the_earlier_ones() {
        let mut b = Builder::new();
        b.store_uint(0xab, 8).unwrap();
        for byte in [0xa1, 0xb2, 0xc3, 0xd4] {
            b.store_ref(leaf(byte)).unwrap();
        }
        assert!(b.store_ref(leaf(0xe5)).is_err(), "the cell is full");

        b.truncate_refs(2).unwrap();
        assert_eq!(b.refs_used(), 2);
        assert_eq!(b.refs_left(), MAX_REFS - 2);
        assert_eq!(b.bits_used(), 8, "the data bits are left alone");

        // The room is real: the store that just failed now succeeds.
        b.store_ref(leaf(0xe5)).unwrap();
        let cell = roundtrip(b);
        let kept: Vec<u64> = cell
            .refs()
            .iter()
            .map(|child| child.parse().load_uint(8).unwrap())
            .collect();
        assert_eq!(
            kept,
            vec![0xa1, 0xb2, 0xe5],
            "the first two, then the new one"
        );
    }

    #[test]
    fn truncating_to_more_references_than_are_held_is_refused_and_changes_nothing() {
        let mut b = Builder::new();
        b.store_ref(leaf(0xa1)).unwrap();
        b.store_ref(leaf(0xb2)).unwrap();
        assert!(matches!(b.truncate_refs(3), Err(CellError::NotEnoughRefs)));
        assert_eq!(b.refs_used(), 2);
        // Truncating to what is already there is a no-op rather than an error, which is
        // what makes it safe to call with a count a caller recorded earlier.
        b.truncate_refs(2).unwrap();
        assert_eq!(b.refs_used(), 2);
    }

    #[test]
    fn a_run_of_bits_reads_back_as_the_bools_that_went_in() {
        let written = [true, false, true, true, false, false, false, true, true];
        let mut b = Builder::new();
        b.store_bits(&written).unwrap();
        assert_eq!(b.bits_used(), 9);
        let cell = roundtrip(b);
        assert_eq!(cell.bit_len(), 9);
        assert_eq!(cell.parse().load_bits(9).unwrap(), written);
    }

    #[test]
    fn a_run_of_bits_that_does_not_fit_stores_none_of_them() {
        let mut b = Builder::new();
        b.store_same_bit(false, MAX_BITS - 2).unwrap();
        let before = b.bits_used();
        assert!(matches!(
            b.store_bits(&[true, true, true]),
            Err(CellError::NoRoomForBits { .. })
        ));
        assert_eq!(b.bits_used(), before, "a partial run is not a shorter cell");
    }

    #[test]
    fn the_level_mask_comes_from_the_children() {
        let leaf = Builder::new().build().unwrap();
        assert_eq!(leaf.level_mask(), 0);
        let mut b = Builder::new();
        b.store_ref(leaf).unwrap();
        assert_eq!(roundtrip(b).level_mask(), 0);
    }
}
