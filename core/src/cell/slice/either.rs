// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading an `Either X ^X` discriminator.
//!
//! ```text
//! left$0 {X:Type} {Y:Type} value:X = Either X Y;
//! right$1 {X:Type} {Y:Type} value:Y = Either X Y;
//! ```
//!
//! At `Y = ^X` that pair is what `Message X` and `MessageRelaxed X` use for two fields each,
//! `init:(Maybe (Either StateInit ^StateInit))` and `body:(Either X ^X)`; `EitherStateInit`
//! is that same `init` under a name of its own, and the block schema puts the combinator
//! nowhere else. Being variable in width is not what places a field behind one, which the
//! same schema shows at `CommonMsgInfo`: a `CurrencyCollection`, a `VarUInteger 16` and a
//! `Grams`, three variable-width fields carrying no discriminator between them.
//!
//! What the pair chooses is where the payload sits. A clear bit puts it inline, starting at
//! the bit after the discriminator, and a set bit puts it in the next reference.
//! `Maybe (Either X ^X)` puts a `nothing$0` or `just$1` bit in front of the same choice.
//!
//! The encoding carries the discriminator and nothing else. It does not carry how wide an
//! inline payload is, so only `X`'s own parse can end one, and a reader at this level can
//! say where the payload sits rather than hand it over. [`EitherRef`] is that answer, and
//! the caller reads `X` from wherever it names.

use super::Slice;
use crate::cell::cell::Cell;
use crate::cell::error::CellError;

/// Where the payload of an `Either X ^X` was written.
///
/// Two variants because the TL-B constructor has two, so this is exhaustive and stays that
/// way: a third arm would be a different type on the wire, not a later addition to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EitherRef<'a> {
    /// `left$0`: the payload is inline, and the cursor that answered this sits on its first
    /// bit.
    ///
    /// Nothing is carried here because there is nothing to carry. The cursor did not move
    /// past the payload, since its width is what the encoding leaves out.
    Inline,
    /// `right$1`: the payload is this reference, and the cursor stepped past it.
    Ref(&'a Cell),
}

impl<'a> Slice<'a> {
    /// Reads an `Either X ^X` discriminator, taking the reference when the payload is in one.
    ///
    /// The read side of [`store_either_ref`](crate::cell::Builder::store_either_ref). On
    /// [`EitherRef::Inline`] the cursor is left on the payload's first bit and the caller
    /// reads `X` from this slice; on [`EitherRef::Ref`] the cursor has already stepped past
    /// the reference and the caller reads `X` from the cell named.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NotEnoughBits`] if the slice has no bit left for the
    /// discriminator, or [`CellError::NotEnoughRefs`] if the bit is set and no reference is
    /// left. A set bit with nothing behind it consumes the bit before it fails, as
    /// [`load_maybe_ref`](Slice::load_maybe_ref) does.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net::cell::{Builder, EitherRef};
    ///
    /// let mut inner = Builder::new();
    /// inner.store_uint(0xab, 8)?;
    /// let payload = inner.build()?;
    ///
    /// let mut outer = Builder::new();
    /// outer.store_either_ref(payload)?;
    ///
    /// let cell = outer.build()?;
    /// let mut slice = cell.parse();
    /// assert_eq!(slice.load_either_ref()?, EitherRef::Inline);
    /// assert_eq!(slice.load_uint(8)?, 0xab);
    /// # Ok::<(), ton_net::cell::CellError>(())
    /// ```
    pub fn load_either_ref(&mut self) -> Result<EitherRef<'a>, CellError> {
        if self.load_bit()? {
            self.load_ref().map(EitherRef::Ref)
        } else {
            Ok(EitherRef::Inline)
        }
    }

    /// Reads a `Maybe (Either X ^X)`: the presence bit, then the discriminator behind it.
    ///
    /// The read side of
    /// [`store_maybe_either_ref`](crate::cell::Builder::store_maybe_either_ref). `None` is
    /// `nothing$0` and consumes one bit; `Some` is `just$1` and carries what
    /// [`load_either_ref`](Slice::load_either_ref) answered.
    ///
    /// # Errors
    ///
    /// As [`load_either_ref`](Slice::load_either_ref), plus
    /// [`CellError::NotEnoughBits`] if the slice has no bit left for the presence bit.
    pub fn load_maybe_either_ref(&mut self) -> Result<Option<EitherRef<'a>>, CellError> {
        if self.load_bit()? {
            self.load_either_ref().map(Some)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cell::{Builder, Cell, CellError, EitherRef};

    fn payload() -> Cell {
        let mut builder = Builder::new();
        builder
            .store_uint(0x0123_4567_89ab_cdef, 64)
            .expect("64 bits fit");
        builder.build().expect("well formed")
    }

    #[test]
    fn a_clear_bit_leaves_the_cursor_on_the_payload() {
        let mut builder = Builder::new();
        builder.store_bit(false).expect("one bit fits");
        builder
            .store_uint(0x0123_4567_89ab_cdef, 64)
            .expect("64 bits fit");
        let cell = builder.build().expect("well formed");

        let mut slice = cell.parse();
        assert_eq!(
            slice.load_either_ref().expect("the discriminator reads"),
            EitherRef::Inline
        );
        assert_eq!(slice.remaining_bits(), 64, "the payload is still ahead");
        assert_eq!(
            slice.load_uint(64).expect("the payload reads"),
            0x0123_4567_89ab_cdef
        );
    }

    #[test]
    fn a_set_bit_takes_the_reference() {
        let payload = payload();
        let mut builder = Builder::new();
        builder.store_bit(true).expect("one bit fits");
        builder
            .store_ref(payload.clone())
            .expect("one reference fits");
        let cell = builder.build().expect("well formed");

        let mut slice = cell.parse();
        assert_eq!(
            slice.load_either_ref().expect("the discriminator reads"),
            EitherRef::Ref(&payload)
        );
        assert_eq!(slice.remaining_refs(), 0, "the reference was consumed");
    }

    #[test]
    fn a_set_bit_with_no_reference_behind_it_fails() {
        let mut builder = Builder::new();
        builder.store_bit(true).expect("one bit fits");
        let cell = builder.build().expect("well formed");

        assert!(matches!(
            cell.parse().load_either_ref(),
            Err(CellError::NotEnoughRefs)
        ));
    }

    #[test]
    fn nothing_reads_as_absent_and_costs_one_bit() {
        let mut builder = Builder::new();
        builder.store_bit(false).expect("one bit fits");
        let cell = builder.build().expect("well formed");

        let mut slice = cell.parse();
        assert_eq!(
            slice
                .load_maybe_either_ref()
                .expect("the presence bit reads"),
            None
        );
        assert_eq!(slice.remaining_bits(), 0);
    }

    #[test]
    fn both_arms_read_back_as_the_payload_that_was_written() {
        // The header widths either side of the inline boundary, so one call takes each arm.
        // 1023 = 958 + 1 + 64, so 958 is the widest header the payload still fits behind.
        for (header, expect_inline) in [(958u16, true), (959u16, false)] {
            let mut builder = Builder::new();
            builder
                .store_same_bit(false, header)
                .expect("the header fits");
            builder
                .store_either_ref(payload())
                .expect("one arm or the other fits");
            let cell = builder.build().expect("well formed");

            let mut slice = cell.parse();
            slice
                .skip_bits(usize::from(header))
                .expect("the header is there");
            let read_back = match slice.load_either_ref().expect("the discriminator reads") {
                EitherRef::Inline => {
                    assert!(expect_inline, "the payload spilled at header {header}");
                    slice.to_cell().expect("what is left forms a cell")
                }
                EitherRef::Ref(cell) => {
                    assert!(
                        !expect_inline,
                        "the payload stayed inline at header {header}"
                    );
                    cell.clone()
                }
            };
            assert_eq!(read_back, payload(), "at header {header}");
        }
    }

    #[test]
    fn just_reads_the_discriminator_behind_it() {
        let payload = payload();
        let mut builder = Builder::new();
        builder.store_bit(true).expect("the presence bit fits");
        builder.store_bit(true).expect("the discriminator fits");
        builder
            .store_ref(payload.clone())
            .expect("one reference fits");
        let cell = builder.build().expect("well formed");

        assert_eq!(
            cell.parse()
                .load_maybe_either_ref()
                .expect("both bits read"),
            Some(EitherRef::Ref(&payload))
        );
    }
}
