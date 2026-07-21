//! A reading cursor over a cell's bits and references.

use crate::cell::Cell;
use crate::error::CellError;

/// Reads the bit at `index` of `data`, most significant bit first.
fn bit_at(data: &[u8], index: usize) -> bool {
    (data[index / 8] >> (7 - (index % 8))) & 1 == 1
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
    pub(crate) fn new(cell: &'a Cell) -> Slice<'a> {
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
        let len = self.load_uint(len_bits)? as u32;
        self.load_uint128(len * 8)
    }

    /// Reads `n` whole bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has fewer than `n` bytes left.
    pub fn load_bytes(&mut self, n: usize) -> Result<Vec<u8>, CellError> {
        let start = self.advance(n * 8)?;
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
}

#[cfg(test)]
mod tests {
    use crate::parse_boc;

    // One cell of eight bits holding 0xab.
    const ONE_CELL: [u8; 14] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
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
}
