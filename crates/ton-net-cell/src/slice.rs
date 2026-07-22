// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A reading cursor over a cell's bits and references.

use crate::cell::Cell;
use crate::error::CellError;

/// Reads the bit at `index` of `data`, most significant bit first.
///
/// Every caller has already held `index` under the cell's bit length, which is what puts
/// it inside `data`. Reading past the end answers false rather than panicking, so a
/// caller that loses its bound returns a wrong value instead of unwinding through a
/// decoder.
fn bit_at(data: &[u8], index: usize) -> bool {
    data.get(index / 8)
        .is_some_and(|byte| (byte >> (7 - (index % 8))) & 1 == 1)
}

/// A cursor that reads typed values out of one cell.
///
/// A slice holds two independent positions, one into the cell's bits and one into its
/// references, because a TL-B structure spends them separately. Every read moves the
/// cursor forward and fails rather than panicking when the cell has nothing left.
///
/// Build one with [`Cell::parse`].
///
/// # Examples
///
/// ```
/// use ton_net_cell::parse_boc;
///
/// // One cell of eight bits holding 0xab.
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// let mut slice = roots[0].parse();
/// assert_eq!(slice.load_uint(4)?, 0xa);
/// assert_eq!(slice.load_uint(4)?, 0xb);
/// assert_eq!(slice.remaining_bits(), 0);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Slice<'a> {
    cell: &'a Cell,
    bit: usize,
    next_ref: usize,
}

impl<'a> Slice<'a> {
    /// Opens a cursor at the start of `cell`.
    pub(crate) fn new(cell: &'a Cell) -> Self {
        Slice {
            cell,
            bit: 0,
            next_ref: 0,
        }
    }

    /// The cell this slice reads.
    #[must_use]
    pub fn cell(&self) -> &'a Cell {
        self.cell
    }

    /// The number of data bits not yet read.
    #[must_use]
    pub fn remaining_bits(&self) -> usize {
        usize::from(self.cell.bit_len()) - self.bit
    }

    /// The number of references not yet taken.
    #[must_use]
    pub fn remaining_refs(&self) -> usize {
        self.cell.refs().len() - self.next_ref
    }

    /// Whether every bit and reference has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining_bits() == 0 && self.remaining_refs() == 0
    }

    /// Advances the bit cursor by `n` and returns where the run started.
    fn advance(&mut self, n: usize) -> Result<usize, CellError> {
        let available = self.remaining_bits();
        if n > available {
            return Err(CellError::NotEnoughBits {
                requested: n,
                available,
            });
        }
        let start = self.bit;
        self.bit += n;
        Ok(start)
    }

    /// Skips `n` bits.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than `n` bits left.
    pub fn skip_bits(&mut self, n: usize) -> Result<(), CellError> {
        self.advance(n).map(|_| ())
    }

    /// Reads one bit.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has no bits left.
    pub fn load_bit(&mut self) -> Result<bool, CellError> {
        let at = self.advance(1)?;
        Ok(bit_at(self.cell.data(), at))
    }

    /// Reads `n` bits as an unsigned integer, most significant bit first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::TooWide`] if `n` is over 64, or
    /// [`CellError::NotEnoughBits`] if the slice has fewer than `n` bits left.
    pub fn load_uint(&mut self, n: u32) -> Result<u64, CellError> {
        if n > 64 {
            return Err(CellError::TooWide {
                requested: n,
                width: 64,
            });
        }
        let start = self.advance(n as usize)?;
        let data = self.cell.data();
        let mut value = 0u64;
        for i in 0..n as usize {
            value = (value << 1) | u64::from(bit_at(data, start + i));
        }
        Ok(value)
    }

    // load_uint(n) cannot return more than n bits, so the high bytes are zero and the
    // narrowing below is total.

    /// Reads eight bits as a `u8`.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than eight bits left.
    pub fn load_u8(&mut self) -> Result<u8, CellError> {
        let [.., byte] = self.load_uint(8)?.to_be_bytes();
        Ok(byte)
    }

    /// Reads sixteen bits as a `u16`, most significant bit first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than sixteen bits
    /// left.
    pub fn load_u16(&mut self) -> Result<u16, CellError> {
        let [.., a, b] = self.load_uint(16)?.to_be_bytes();
        Ok(u16::from_be_bytes([a, b]))
    }

    /// Reads thirty-two bits as a `u32`, most significant bit first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than thirty-two bits
    /// left.
    pub fn load_u32(&mut self) -> Result<u32, CellError> {
        let [.., a, b, c, d] = self.load_uint(32)?.to_be_bytes();
        Ok(u32::from_be_bytes([a, b, c, d]))
    }

    /// Reads thirty-two bits as a two's complement `i32`, most significant bit first.
    ///
    /// This is TL-B's `int32`, which a workchain id uses. The bits are the ones
    /// [`load_u32`](Self::load_u32) reads; only the meaning of the top one differs.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than thirty-two bits
    /// left.
    pub fn load_i32(&mut self) -> Result<i32, CellError> {
        let [.., a, b, c, d] = self.load_uint(32)?.to_be_bytes();
        Ok(i32::from_be_bytes([a, b, c, d]))
    }

    /// Reads `n` bits as a wide unsigned integer, most significant bit first.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::TooWide`] if `n` is over 128, or
    /// [`CellError::NotEnoughBits`] if the slice has fewer than `n` bits left.
    pub fn load_uint128(&mut self, n: u32) -> Result<u128, CellError> {
        if n > 128 {
            return Err(CellError::TooWide {
                requested: n,
                width: 128,
            });
        }
        let start = self.advance(n as usize)?;
        let data = self.cell.data();
        let mut value = 0u128;
        for i in 0..n as usize {
            value = (value << 1) | u128::from(bit_at(data, start + i));
        }
        Ok(value)
    }

    /// Reads a variable-length unsigned integer of at most `max` bytes.
    ///
    /// This is the `VarUInteger max` encoding: a length in as many bits as `max - 1`
    /// needs, then that many bytes of value. TON amounts are `VarUInteger 16`, so
    /// `load_var_uint(16)` reads a four-bit length and up to fifteen bytes, which is why
    /// the result fits a `u128`.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if `max` is below two, or
    /// [`CellError::NotEnoughBits`] if the slice runs out mid-value.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::parse_boc;
    ///
    /// // One cell of twelve bits: length 1, then the byte 0x2a.
    /// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00,
    ///              0x00, 0x03, 0x12, 0xa8];
    /// let roots = parse_boc(&bytes)?;
    /// assert_eq!(roots[0].parse().load_var_uint(16)?, 42);
    /// # Ok::<(), ton_net_cell::CellError>(())
    /// ```
    pub fn load_var_uint(&mut self, max: u32) -> Result<u128, CellError> {
        if max < 2 {
            return Err(CellError::Malformed(
                "variable integer needs a max above one",
            ));
        }
        let len_bits = u32::BITS - (max - 1).leading_zeros();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "max >= 2 is checked above, so len_bits = 32 - leading_zeros(max - 1) is at most 32, and load_uint returns a value under 2^32, which fits u32"
        )]
        let len = self.load_uint(len_bits)? as u32;
        self.load_uint128(len * 8)
    }

    /// Reads `n` whole bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than `n` bytes left.
    pub fn load_bytes(&mut self, n: usize) -> Result<Vec<u8>, CellError> {
        // A byte count whose bit count does not fit a usize asks for more than any cell
        // holds. Without this the multiplication wraps to a small number, the length
        // check below passes on the wrapped value, and the allocation that follows is
        // made against the unwrapped one.
        let requested = n.checked_mul(8).ok_or(CellError::NotEnoughBits {
            requested: usize::MAX,
            available: self.remaining_bits(),
        })?;
        let start = self.advance(requested)?;
        let data = self.cell.data();
        let mut out = Vec::with_capacity(n);
        for byte in 0..n {
            let mut v = 0u8;
            for i in 0..8 {
                v = (v << 1) | u8::from(bit_at(data, start + byte * 8 + i));
            }
            out.push(v);
        }
        Ok(out)
    }

    /// Takes the next reference.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughRefs`] if the slice has no reference left.
    pub fn load_ref(&mut self) -> Result<&'a Cell, CellError> {
        let cell = self
            .cell
            .refs()
            .get(self.next_ref)
            .ok_or(CellError::NotEnoughRefs)?;
        self.next_ref += 1;
        Ok(cell)
    }

    /// Reads a `Maybe` reference: one bit, then a reference when that bit is set.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has no bits left, or
    /// [`CellError::NotEnoughRefs`] if the bit is set and no reference is left.
    pub fn load_maybe_ref(&mut self) -> Result<Option<&'a Cell>, CellError> {
        if self.load_bit()? {
            self.load_ref().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads `n` bits as a two's-complement signed integer.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::TooWide`] if `n` is over 64, or
    /// [`CellError::NotEnoughBits`] if the slice has fewer than `n` bits left.
    pub fn load_int(&mut self, n: u32) -> Result<i64, CellError> {
        if n > i64::BITS {
            return Err(CellError::TooWide {
                requested: n,
                width: i64::BITS,
            });
        }
        if n == 0 {
            return Ok(0);
        }
        let raw = self.load_uint(n)?;
        // Sign-extend from the top bit of the field. Shifting a full-width value left by
        // zero and back is the identity, so the 64-bit case needs no special handling.
        #[allow(clippy::cast_possible_wrap)]
        let shifted = (raw << (i64::BITS - n)) as i64;
        Ok(shifted >> (i64::BITS - n))
    }

    /// Reads an amount in nanotons, which TON encodes as `VarUInteger 16`.
    ///
    /// # Errors
    ///
    /// As [`load_var_uint`](Slice::load_var_uint).
    pub fn load_coins(&mut self) -> Result<u128, CellError> {
        self.load_var_uint(16)
    }

    /// Reads `n` bits as an unsigned integer without advancing.
    ///
    /// # Errors
    ///
    /// As [`load_uint`](Slice::load_uint).
    pub fn preload_uint(&mut self, n: u32) -> Result<u64, CellError> {
        let saved = self.bit;
        let value = self.load_uint(n);
        self.bit = saved;
        value
    }

    /// Reads one bit without advancing.
    ///
    /// # Errors
    ///
    /// As [`load_bit`](Slice::load_bit).
    pub fn preload_bit(&mut self) -> Result<bool, CellError> {
        let saved = self.bit;
        let value = self.load_bit();
        self.bit = saved;
        value
    }

    /// Looks at the next reference without taking it.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughRefs`] if the slice has no reference left.
    pub fn peek_ref(&self) -> Result<&'a Cell, CellError> {
        self.cell
            .refs()
            .get(self.next_ref)
            .ok_or(CellError::NotEnoughRefs)
    }

    /// Skips `n` references.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughRefs`] if the slice has fewer than `n` left.
    pub fn skip_refs(&mut self, n: usize) -> Result<(), CellError> {
        if n > self.remaining_refs() {
            return Err(CellError::NotEnoughRefs);
        }
        self.next_ref += n;
        Ok(())
    }

    /// Copies everything left into a builder.
    ///
    /// # Errors
    ///
    /// As the stores it performs; what a slice holds always fits one cell.
    pub fn to_builder(&self) -> Result<crate::Builder, CellError> {
        let mut builder = crate::Builder::new();
        builder.store_slice(self.clone())?;
        Ok(builder)
    }

    /// Copies everything left into a new cell.
    ///
    /// # Errors
    ///
    /// As [`to_builder`](Slice::to_builder).
    pub fn to_cell(&self) -> Result<Cell, CellError> {
        self.to_builder()?.build()
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse_boc, CellError};

    // One cell of eight bits holding 0xab.
    const ONE_CELL: [u8; 14] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
    ];

    // One cell of thirty-two bits holding 0x89abcdef. The top bit is set, so the signed
    // reading of those bits differs from the unsigned one.
    const FOUR_BYTES: [u8; 17] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x06, 0x00, 0x00, 0x08, 0x89, 0xab,
        0xcd, 0xef,
    ];

    // A root with one reference; the referenced cell holds the byte 0xcd.
    const TWO_CELLS: [u8; 17] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0xcd,
    ];

    #[test]
    fn reads_bits_and_integers() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        let mut slice = roots[0].parse();
        assert_eq!(slice.remaining_bits(), 8);
        assert!(slice.load_bit().unwrap()); // 0xab starts 1010
        assert!(!slice.load_bit().unwrap());
        assert_eq!(slice.load_uint(6).unwrap(), 0b10_1011);
        assert!(slice.is_empty());
    }

    #[test]
    fn reading_past_the_end_is_an_error() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        let mut slice = roots[0].parse();
        assert!(slice.load_uint(9).is_err());
        assert_eq!(slice.load_uint(8).unwrap(), 0xab);
        assert!(slice.load_bit().is_err());
    }

    #[test]
    fn a_uint_wider_than_its_target_is_refused() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        assert!(roots[0].parse().load_uint(65).is_err());
        assert!(roots[0].parse().load_uint128(129).is_err());
    }

    #[test]
    fn a_fixed_width_read_lands_in_its_own_type() {
        let roots = parse_boc(&FOUR_BYTES).unwrap();
        assert_eq!(roots[0].parse().load_u8().unwrap(), 0x89);
        assert_eq!(roots[0].parse().load_u16().unwrap(), 0x89ab);
        assert_eq!(roots[0].parse().load_u32().unwrap(), 0x89ab_cdef);
        // The same thirty-two bits, read as int32.
        assert_eq!(roots[0].parse().load_i32().unwrap(), -1_985_229_329);

        // Each advances by its own width, and the last one runs out rather than wrapping.
        let mut slice = roots[0].parse();
        assert_eq!(slice.load_u16().unwrap(), 0x89ab);
        assert_eq!(slice.load_u16().unwrap(), 0xcdef);
        assert!(slice.is_empty());
        assert!(slice.load_u8().is_err());
    }

    #[test]
    fn reads_bytes() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        assert_eq!(roots[0].parse().load_bytes(1).unwrap(), vec![0xab]);
    }

    #[test]
    fn takes_references_in_order_then_refuses() {
        let roots = parse_boc(&TWO_CELLS).unwrap();
        let mut slice = roots[0].parse();
        assert_eq!(slice.remaining_refs(), 1);
        let child = slice.load_ref().unwrap();
        assert_eq!(child.parse().load_uint(8).unwrap(), 0xcd);
        assert_eq!(slice.remaining_refs(), 0);
        assert!(slice.load_ref().is_err());
    }

    #[test]
    fn a_present_maybe_reference_yields_the_child() {
        // One bit set, then one reference holding 0xcd.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x07, 0x00, 0x01, 0x01, 0xc0,
            0x01, 0x00, 0x02, 0xcd,
        ];
        let roots = parse_boc(&bag).unwrap();
        let mut slice = roots[0].parse();
        let child = slice.load_maybe_ref().unwrap().expect("the bit is set");
        assert_eq!(child.parse().load_uint(8).unwrap(), 0xcd);
        assert!(slice.is_empty());
    }

    #[test]
    fn an_absent_maybe_reference_spends_only_the_bit() {
        // One bit clear, no reference.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x40,
        ];
        let roots = parse_boc(&bag).unwrap();
        let mut slice = roots[0].parse();
        assert!(slice.load_maybe_ref().unwrap().is_none());
        assert!(slice.is_empty());
    }

    #[test]
    fn a_maybe_reference_needs_a_bit_to_read() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        let mut slice = roots[0].parse();
        slice.skip_bits(8).unwrap();
        assert!(slice.load_maybe_ref().is_err());
    }

    #[test]
    fn a_variable_integer_needs_a_sane_maximum() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        assert!(roots[0].parse().load_var_uint(1).is_err());
    }

    #[test]
    fn a_slice_is_empty_only_once_bits_and_references_are_both_spent() {
        // Both halves matter. A reader calling this to confirm it consumed a cell whole
        // would accept one with an unread reference if either half were enough, and an
        // unread reference is a field nobody looked at.
        let roots = parse_boc(&TWO_CELLS).unwrap();
        let mut slice = roots[0].parse();
        assert!(!slice.is_empty(), "a fresh slice still holds a reference");
        slice.load_ref().unwrap();
        assert!(slice.is_empty(), "bits and references are both spent");

        let roots = parse_boc(&ONE_CELL).unwrap();
        let mut bits_only = roots[0].parse();
        assert!(!bits_only.is_empty(), "eight bits are still unread");
        bits_only.skip_bits(8).unwrap();
        assert!(bits_only.is_empty());
    }

    #[test]
    fn a_wide_integer_is_read_up_to_its_width_and_no_further() {
        let roots = parse_boc(&ONE_CELL).unwrap();

        // The widest read the type holds is allowed, so the guard is exclusive. Asking
        // for it from a short slice fails on the bits rather than on the width.
        assert_eq!(
            roots[0].parse().load_uint128(128),
            Err(CellError::NotEnoughBits {
                requested: 128,
                available: 8,
            })
        );

        // One bit wider than the type is refused before the slice is consulted.
        assert_eq!(
            roots[0].parse().load_uint128(129),
            Err(CellError::TooWide {
                requested: 129,
                width: 128,
            })
        );
    }

    #[test]
    fn a_byte_count_too_large_to_measure_in_bits_is_refused() {
        let roots = parse_boc(&ONE_CELL).unwrap();

        // The length check is in bits, so a byte count near the top of a usize has to be
        // multiplied before it can be checked. Wrapped, that product is small, the check
        // passes, and the allocation that follows is made against the count as given.
        assert_eq!(
            roots[0].parse().load_bytes(usize::MAX / 4),
            Err(CellError::NotEnoughBits {
                requested: usize::MAX,
                available: 8,
            })
        );
    }
}
