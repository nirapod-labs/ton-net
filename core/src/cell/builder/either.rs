// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Writing an `Either X ^X`, inline or in a reference.
//!
//! ```text
//! left$0 {X:Type} {Y:Type} value:X = Either X Y;
//! right$1 {X:Type} {Y:Type} value:Y = Either X Y;
//! ```
//!
//! At `Y = ^X` the two constructors are the same payload in two places: a clear bit and the
//! payload written where the bit ended, or a set bit and the payload in the next reference.
//! `Maybe (Either X ^X)` puts a `nothing$0` or `just$1` bit in front of that choice. Both
//! encodings are well formed for the same value, so the choice is the writer's, and a writer
//! that chooses differently produces a different cell with a different hash. That is the
//! whole reason the decision is made in one function here rather than at each field.
//!
//! # Where the boundary sits
//!
//! The fit is tested before the discriminator is written, and the discriminator's own bit is
//! counted inside the test. What has to fit beside what the builder already holds is
//! therefore the whole field: one bit, then the payload's bits, and the payload's references
//! alongside the ones already stored.
//!
//! Writing the bit first and testing the payload alone afterwards decides identically, since
//! the bit moves both sides of the comparison by one. It is not the order taken, because a
//! builder that has already spent the bit cannot report a failure without leaving it behind.
//! [`Builder::store_maybe_ref`] states that same property for the same reason, and these two
//! are held to it as well.
//!
//! # What the fit test does not reserve
//!
//! Room is tested for this field and for nothing behind it. A caller writing a further field
//! after an inlined payload arranges that room itself. `Message X` is the case that matters:
//! it writes `init:(Maybe (Either StateInit ^StateInit))` and then `body:(Either X ^X)`, and
//! an `init` inlined to the last bit leaves `body`'s own discriminator nowhere to go. That
//! shows up as a failure at the later store rather than as a wrong encoding here, and the
//! count of what still has to be written is known at the level that writes the message, not
//! at this one.
//!
//! # What the payload is taken to be
//!
//! The payload argument stands for the serialization of `X`, and inlining copies its data
//! bits and its references into the parent. A payload that is exotic has its type tag copied
//! in as ordinary data by that, rather than keeping the meaning being a cell of that kind
//! gave it. Nothing here refuses one: [`Builder::build`] makes ordinary cells, so an exotic
//! payload can only have come from a parsed tree or a proof, which is a caller putting a
//! proof where a serialization belongs.

use super::Builder;
use crate::cell::cell::{Cell, MAX_REFS};
use crate::cell::error::CellError;

impl Builder {
    /// Writes an `Either X ^X`: one discriminator bit, then the payload inline or in a
    /// reference.
    ///
    /// The payload goes inline when its bits and its references fit beside what is already
    /// stored, counting the discriminator bit, and into a reference when they do not. The
    /// module documentation states which side of the discriminator that test sits on and
    /// what it deliberately does not reserve.
    ///
    /// [`load_either_ref`](crate::cell::Slice::load_either_ref) reads it back and says which
    /// arm was taken, since the encoding gives a reader no other way to tell.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::NoRoomForRefs`] if the payload does not fit inline and the cell
    /// already holds [`MAX_REFS`] references, and [`CellError::NoRoomForBits`] if it does not
    /// fit inline and there is no room for the discriminator either. The two conditions are
    /// not exclusive, and a builder short of both reports the reference limit, since that is
    /// the one tested first, which is the order [`Builder::store_maybe_ref`] reports them in.
    /// Neither arm writes anything in either case, so the builder is left as it was.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net::cell::Builder;
    ///
    /// let mut inner = Builder::new();
    /// inner.store_uint(0xab, 8)?;
    /// let payload = inner.build()?;
    ///
    /// let mut small = Builder::new();
    /// small.store_either_ref(payload.clone())?;
    /// let small = small.build()?;
    /// assert_eq!(small.bit_len(), 9, "the discriminator, then the payload inline");
    /// assert_eq!(small.refs().len(), 0);
    /// # Ok::<(), ton_net::cell::CellError>(())
    /// ```
    pub fn store_either_ref(&mut self, payload: Cell) -> Result<&mut Self, CellError> {
        let inline = self.either_goes_inline(&payload, 0)?;
        self.store_either_where(payload, inline)
    }

    /// Writes a `Maybe (Either X ^X)`: the presence bit, then the choice behind it.
    ///
    /// `None` is `nothing$0` and writes one clear bit. `Some` is `just$1` and writes the set
    /// bit followed by what [`store_either_ref`](Builder::store_either_ref) would write,
    /// decided by the same function and with the presence bit counted in the fit, so the two
    /// methods cannot reach opposite answers about the same payload in the same builder.
    ///
    /// # Errors
    ///
    /// As [`store_either_ref`](Builder::store_either_ref), and
    /// [`CellError::NoRoomForBits`] when not even the presence bit fits. The whole field is
    /// tested before any of it is written, so a failure never leaves a presence bit with
    /// nothing behind it.
    ///
    /// [`load_maybe_either_ref`](crate::cell::Slice::load_maybe_either_ref) reads it back.
    pub fn store_maybe_either_ref(
        &mut self,
        payload: Option<Cell>,
    ) -> Result<&mut Self, CellError> {
        match payload {
            Some(payload) => {
                let inline = self.either_goes_inline(&payload, 1)?;
                self.store_bit(true)?;
                self.store_either_where(payload, inline)?;
            }
            None => {
                self.store_bit(false)?;
            }
        }
        Ok(self)
    }

    /// The one place the inline-or-reference choice is made.
    ///
    /// `ahead` is how many bits are written between the current position and the
    /// discriminator: one for the `just$1` of a `Maybe`, zero for a bare `Either`. Counting
    /// them here is what holds both callers to one rule, since the room the discriminator
    /// will find is the room after those bits and not the room in front of them.
    ///
    /// Answers with an error rather than a false when neither arm fits, so no caller writes a
    /// bit it cannot follow.
    fn either_goes_inline(&self, payload: &Cell, ahead: u16) -> Result<bool, CellError> {
        let inline_bits = ahead.saturating_add(1).saturating_add(payload.bit_len());
        if self.can_extend_by(inline_bits, payload.refs().len()) {
            return Ok(true);
        }
        if self.refs_left() == 0 {
            return Err(CellError::NoRoomForRefs { limit: MAX_REFS });
        }
        self.room_for(ahead.saturating_add(1))?;
        Ok(false)
    }

    /// Writes the discriminator the decision chose, then the payload where it chose.
    ///
    /// Split from the decision so that the `Maybe` form can put its presence bit between the
    /// two without the decision being taken a second time against a builder one bit fuller.
    fn store_either_where(&mut self, payload: Cell, inline: bool) -> Result<&mut Self, CellError> {
        if inline {
            self.store_bit(false)?;
            self.store_slice(payload.parse())?;
        } else {
            self.store_bit(true)?;
            self.store_ref(payload)?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::cell::{Builder, Cell, CellError, MAX_BITS, MAX_REFS};

    /// Sixty-four bits of payload, wide enough that the boundary is not a rounding artifact
    /// of a byte.
    const PAYLOAD_BITS: u16 = 64;
    const PAYLOAD: u64 = 0x0123_4567_89ab_cdef;

    fn payload() -> Cell {
        let mut builder = Builder::new();
        builder
            .store_uint(PAYLOAD, u32::from(PAYLOAD_BITS))
            .expect("the payload fits one cell");
        builder.build().expect("well formed")
    }

    /// A payload of four references and no data bits, for the reference half of the fit.
    fn wide_payload() -> Cell {
        let mut builder = Builder::new();
        for index in 0..MAX_REFS {
            let tag = u64::try_from(index).expect("four fits a u64");
            let mut leaf = Builder::new();
            leaf.store_uint(tag, 8).expect("eight bits fit");
            builder
                .store_ref(leaf.build().expect("well formed"))
                .expect("four references fit");
        }
        builder.build().expect("well formed")
    }

    /// A builder already holding `bits` clear bits.
    fn filled(bits: u16) -> Builder {
        let mut builder = Builder::new();
        builder
            .store_same_bit(false, bits)
            .expect("the fill fits one cell");
        builder
    }

    /// The widest header that still leaves room for the discriminator and the payload:
    /// 1023 = 958 + 1 + 64.
    const EXACT_FIT_HEADER: u16 = MAX_BITS - 1 - PAYLOAD_BITS;

    #[test]
    fn a_payload_that_exactly_fits_is_written_inline() {
        let mut builder = filled(EXACT_FIT_HEADER);
        builder
            .store_either_ref(payload())
            .expect("the field fits to the last bit");
        let cell = builder.build().expect("well formed");

        assert_eq!(cell.bit_len(), MAX_BITS, "the cell is exactly full");
        assert_eq!(cell.refs().len(), 0, "nothing spilled");

        let mut slice = cell.parse();
        slice
            .skip_bits(usize::from(EXACT_FIT_HEADER))
            .expect("the header is there");
        assert!(!slice.load_bit().expect("the discriminator is there"));
        assert_eq!(
            slice.load_uint(u32::from(PAYLOAD_BITS)).expect("inline"),
            PAYLOAD
        );
    }

    #[test]
    fn a_payload_one_bit_too_large_goes_into_a_reference() {
        let mut builder = filled(EXACT_FIT_HEADER + 1);
        builder
            .store_either_ref(payload())
            .expect("the reference arm fits");
        let cell = builder.build().expect("well formed");

        assert_eq!(
            cell.bit_len(),
            EXACT_FIT_HEADER + 2,
            "the header and the discriminator, and no payload bits"
        );
        assert_eq!(cell.refs().len(), 1);
        assert_eq!(cell.refs()[0], payload(), "the payload is the reference");

        let mut slice = cell.parse();
        slice
            .skip_bits(usize::from(EXACT_FIT_HEADER) + 1)
            .expect("the header is there");
        assert!(slice.load_bit().expect("the discriminator is there"));
    }

    #[test]
    fn a_payload_whose_references_do_not_fit_goes_into_a_reference() {
        let mut inline = Builder::new();
        inline
            .store_either_ref(wide_payload())
            .expect("four references fit an empty builder");
        let inline = inline.build().expect("well formed");
        assert_eq!(inline.bit_len(), 1, "the discriminator alone");
        assert_eq!(
            inline.refs().len(),
            MAX_REFS,
            "the payload's own references"
        );

        let mut spilled = Builder::new();
        spilled
            .store_ref(payload())
            .expect("one reference fits")
            .store_either_ref(wide_payload())
            .expect("the reference arm fits");
        let spilled = spilled.build().expect("well formed");
        assert_eq!(spilled.bit_len(), 1);
        assert_eq!(
            spilled.refs().len(),
            2,
            "the one already stored, then the payload as one more"
        );
        assert_eq!(spilled.refs()[1], wide_payload());
    }

    #[test]
    fn nothing_is_one_clear_bit_and_no_reference() {
        let mut builder = Builder::new();
        builder
            .store_maybe_either_ref(None)
            .expect("one bit fits an empty builder");
        let cell = builder.build().expect("well formed");

        assert_eq!(cell.bit_len(), 1);
        assert_eq!(cell.refs().len(), 0);
        assert!(!cell.parse().load_bit().expect("the presence bit is there"));
    }

    #[test]
    fn the_presence_bit_moves_the_inline_boundary_by_one() {
        let mut fits = filled(EXACT_FIT_HEADER - 1);
        fits.store_maybe_either_ref(Some(payload()))
            .expect("the field fits to the last bit");
        let fits = fits.build().expect("well formed");
        assert_eq!(fits.bit_len(), MAX_BITS, "the cell is exactly full");
        assert_eq!(fits.refs().len(), 0, "nothing spilled");

        let mut spills = filled(EXACT_FIT_HEADER);
        spills
            .store_maybe_either_ref(Some(payload()))
            .expect("the reference arm fits");
        let spills = spills.build().expect("well formed");
        assert_eq!(
            spills.bit_len(),
            EXACT_FIT_HEADER + 2,
            "the header, the presence bit and the discriminator"
        );
        assert_eq!(spills.refs().len(), 1);
    }

    #[test]
    fn the_maybe_form_decides_as_the_bare_form_does_behind_its_own_bit() {
        // The property the shared decision exists for, over every header width: writing the
        // presence bit and then the bare form must produce the cell the `Maybe` form
        // produces, or the two have disagreed about where the payload goes.
        for header in 0..=MAX_BITS {
            let mut combined = filled(header);
            let by_hand = (|| -> Result<(), CellError> {
                combined.store_bit(true)?;
                combined.store_either_ref(payload())?;
                Ok(())
            })();

            let mut maybe = filled(header);
            let by_method = maybe.store_maybe_either_ref(Some(payload())).map(|_| ());

            match (by_hand, by_method) {
                (Ok(()), Ok(())) => assert_eq!(
                    combined.build().expect("well formed"),
                    maybe.build().expect("well formed"),
                    "the two forms disagreed at header {header}"
                ),
                (Err(_), Err(_)) => {}
                (by_hand, by_method) => panic!(
                    "one form stored and the other refused at header {header}: \
                     {by_hand:?} against {by_method:?}"
                ),
            }
        }
    }

    #[test]
    fn a_full_cell_refuses_both_arms_and_writes_nothing() {
        let mut builder = filled(MAX_BITS);
        let before = builder.clone();
        assert!(matches!(
            builder.store_either_ref(payload()),
            Err(CellError::NoRoomForBits { .. })
        ));
        assert_eq!(builder, before, "a refused store left the builder alone");
    }

    #[test]
    fn a_cell_out_of_references_refuses_a_payload_that_does_not_fit_inline() {
        let mut builder = filled(EXACT_FIT_HEADER + 1);
        for _ in 0..MAX_REFS {
            builder.store_ref(payload()).expect("four references fit");
        }
        let before = builder.clone();
        assert!(matches!(
            builder.store_either_ref(payload()),
            Err(CellError::NoRoomForRefs { .. })
        ));
        assert_eq!(builder, before, "a refused store left the builder alone");
    }
}
