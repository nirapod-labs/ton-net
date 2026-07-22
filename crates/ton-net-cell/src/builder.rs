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

use crate::cell::{Cell, CellType, MAX_BITS, MAX_REFS};
use crate::error::CellError;
use crate::slice::Slice;

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
/// use ton_net_cell::Builder;
///
/// let mut b = Builder::new();
/// b.store_uint(0xab, 8)?;
/// let cell = b.build()?;
/// assert_eq!(cell.bit_len(), 8);
/// assert_eq!(cell.data(), [0xab]);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builder {
    /// Bits `0..bits`, most significant first. Anything past `bits` in the final byte is
    /// zero while building; [`build`](Builder::build) writes the completion tag.
    data: Vec<u8>,
    bits: u16,
    refs: Vec<Cell>,
}

impl Builder {
    /// A builder holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            bits: 0,
            refs: Vec::new(),
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
        self.refs.len()
    }

    /// How many more references fit.
    #[must_use]
    pub fn refs_left(&self) -> usize {
        MAX_REFS - self.refs.len()
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
    /// # Errors
    ///
    /// As [`store_uint`](Builder::store_uint), with the range check taken over the signed
    /// range that `bits` bits can hold.
    pub fn store_int(&mut self, value: i64, bits: u32) -> Result<&mut Self, CellError> {
        if bits == 0 || bits > i64::BITS {
            return Err(CellError::TooWide {
                requested: bits,
                width: i64::BITS,
            });
        }
        if bits < i64::BITS {
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
    /// use ton_net_cell::Builder;
    ///
    /// let mut b = Builder::new();
    /// b.store_var_uint(42, 16)?;
    /// // A four-bit length of one, then the byte itself.
    /// assert_eq!(b.bits_used(), 12);
    /// # Ok::<(), ton_net_cell::CellError>(())
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
        if self.refs.len() >= MAX_REFS {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        self.refs.push(cell);
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
                if self.refs.len() >= MAX_REFS {
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
        if other.refs.len() > self.refs_left() {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        for index in 0..other.bits {
            self.store_bit(other.bit_at(index))?;
        }
        for cell in &other.refs {
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
        Cell::from_parts(self.data, self.bits, self.refs, cell_type, level_mask)
    }
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

    #[test]
    fn the_level_mask_comes_from_the_children() {
        let leaf = Builder::new().build().unwrap();
        assert_eq!(leaf.level_mask(), 0);
        let mut b = Builder::new();
        b.store_ref(leaf).unwrap();
        assert_eq!(roundtrip(b).level_mask(), 0);
    }
}
