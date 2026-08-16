// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! An edge label: the run of key bits every key below an edge shares.
//!
//! A label has three encodings and all three parse. TON's rule is that the shortest one
//! is the only correct one, with a tie going to the earliest constructor, so a dictionary
//! has exactly one representation and therefore exactly one hash. Choosing a longer
//! encoding builds a tree that reads back with the same entries and hashes differently,
//! which nothing downstream would report: a hash here is an identity, not a checksum.
//! [`store_label`] is where that choice is made.
//!
//! A walk reads one label per level, so where a label is held decides what the walk costs
//! the allocator. [`Label`] holds one inline, which is what lets a descent refill a single
//! value at every level rather than allocate a vector at each. The reader is written over
//! a sink and the writer over a run, so a [`Label`] and a plain `[bool]` of key bits go
//! through the same codec.

use crate::cell::builder::Builder;
use crate::cell::cell::MAX_BITS;
use crate::cell::error::CellError;
use crate::cell::slice::Slice;

/// Bytes enough for a label of every width a cell could carry.
const LABEL_BYTES: usize = (MAX_BITS as usize).div_ceil(8);

/// The width of a `#<= max` field: enough bits to hold every value up to `max`.
pub(super) fn bounded_width(max: u16) -> u32 {
    u16::BITS - max.leading_zeros()
}

/// A run of bits, whichever way it is held.
///
/// The label writer is handed both a label a walk read back off a cell, held inline as a
/// [`Label`], and a run of key bits the caller supplied, held as a slice of `bool`. This is
/// what lets it be written once over the two rather than twice.
pub(super) trait BitRun {
    /// How many bits the run holds.
    fn len(&self) -> usize;

    /// The bit at `index`, or false past the end.
    ///
    /// Past the end answers rather than panicking, for the reason the rest of this crate
    /// does: a lost bound in a decoder should give a wrong answer a hash catches, not
    /// unwind through whatever embedded it.
    fn bit(&self, index: usize) -> bool;
}

impl BitRun for [bool] {
    fn len(&self) -> usize {
        <[bool]>::len(self)
    }

    fn bit(&self, index: usize) -> bool {
        self.get(index).copied().unwrap_or(false)
    }
}

/// A label held inline, with room for every width a cell could carry.
///
/// The bits sit in a fixed 128-byte array beside a length, so building one costs no
/// allocation and copying one is a move of 130 bytes. A descent holds a single [`Label`]
/// and refills it at each level, where a returning reader handed back a fresh vector per
/// level.
///
/// No recursive walk in the dictionary holds one of these by value, deliberately. Those
/// walks are bounded in depth by the cell graph a peer sent, and a thousand frames carrying
/// 130 bytes apiece is over a hundred kilobytes of stack whose size the peer, rather than
/// this crate, decides. `dict.rs` states the same rule out loud on `descend`, which is a
/// loop for that reason. A walk that recurses either borrows one of these from the
/// iterative caller that owns it, or holds its label on the heap.
///
/// `clear` is the one thing that shortens a label and it zeroes the whole array, so bits
/// past the length are zero and the derived equality compares two labels by the run they
/// spell rather than by what one of them used to hold.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Label {
    bits: [u8; LABEL_BYTES],
    len: u16,
}

impl Label {
    /// An empty label.
    pub(super) const fn new() -> Self {
        Self {
            bits: [0; LABEL_BYTES],
            len: 0,
        }
    }

    /// How many bits the label holds.
    pub(super) fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// The same length as a key-width count.
    ///
    /// A label is read under a `u16` width and refuses to grow past what a cell carries, so
    /// this is a `u16` by construction rather than by a cast the caller has to justify.
    pub(super) fn width(&self) -> u16 {
        self.len
    }

    /// Empties the label, clearing the bits it held so none survives underneath.
    pub(super) fn clear(&mut self) {
        self.bits = [0; LABEL_BYTES];
        self.len = 0;
    }

    /// Writes the bit at `index`, which the caller has already held under the capacity.
    fn set(&mut self, index: usize, bit: bool) {
        if let Some(byte) = self.bits.get_mut(index / 8) {
            let mask = 1u8 << (7 - (index % 8));
            if bit {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
    }

    /// Appends one bit.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::LabelTooLong`] if the label already spells every bit a cell
    /// could carry.
    pub(super) fn push(&mut self, bit: bool) -> Result<(), CellError> {
        if self.len >= MAX_BITS {
            return Err(CellError::LabelTooLong);
        }
        self.set(usize::from(self.len), bit);
        self.len += 1;
        Ok(())
    }

    /// Appends every bit of `run`.
    ///
    /// # Errors
    ///
    /// As [`push`](Label::push).
    pub(super) fn extend<R: BitRun + ?Sized>(&mut self, run: &R) -> Result<(), CellError> {
        for index in 0..run.len() {
            self.push(run.bit(index))?;
        }
        Ok(())
    }

    /// A label of `len` bits taken from `from`, both already inside this one.
    fn copy_range(&self, from: u16, len: u16) -> Self {
        let mut out = Self::new();
        for index in 0..usize::from(len) {
            out.set(index, self.bit(usize::from(from) + index));
        }
        out.len = len;
        out
    }

    /// A position inside this label, held to its length, as the `u16` a length is.
    fn inside(&self, at: usize) -> u16 {
        u16::try_from(at).unwrap_or(u16::MAX).min(self.len)
    }

    /// The bits from `at` onward, empty where the label is already spent.
    pub(super) fn tail(&self, at: usize) -> Self {
        let from = self.inside(at);
        self.copy_range(from, self.len - from)
    }

    /// The leading `at` bits, or the whole label where it is shorter.
    pub(super) fn head(&self, at: usize) -> Self {
        self.copy_range(0, self.inside(at))
    }
}

impl core::fmt::Debug for Label {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Label(")?;
        for index in 0..self.len() {
            write!(f, "{}", u8::from(self.bit(index)))?;
        }
        write!(f, ")")
    }
}

impl BitRun for Label {
    fn len(&self) -> usize {
        usize::from(self.len)
    }

    fn bit(&self, index: usize) -> bool {
        if index >= self.len() {
            return false;
        }
        self.bits
            .get(index / 8)
            .is_some_and(|byte| (byte >> (7 - (index % 8))) & 1 == 1)
    }
}

/// Somewhere a label being read is written to.
///
/// A [`Label`] is what a reader passes wherever it can, held inline and refilled per level.
/// The prefix dictionary's `insert` and `remove_from` pass a `Vec<bool>` instead: each
/// rebuilds its fork with the label after its own recursive call has returned, so neither
/// can share a buffer a child would have overwritten, and neither may hold a label in a
/// frame whose depth a peer chooses. Both sinks read a label back the same, which
/// `every_label_this_writes_reads_back_as_itself` holds them to, because a label that came
/// back differently in one of them would put a different edge on a rebuilt node.
pub(super) trait LabelSink {
    /// Drops whatever the sink held, so a refill spells only what it last read.
    fn reset(&mut self);

    /// Makes room for `count` more bits. The count comes off a header [`read_run`] has
    /// already held under the width the label is read under.
    fn make_room(&mut self, count: u16);

    /// Appends one bit.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::LabelTooLong`] where the sink has no room for another bit. A
    /// `Vec<bool>` never returns it; a [`Label`] returns it at what a cell carries.
    fn write_bit(&mut self, bit: bool) -> Result<(), CellError>;
}

impl LabelSink for Label {
    fn reset(&mut self) {
        self.clear();
    }

    fn make_room(&mut self, _count: u16) {
        // The room is already there: that is what holding the bits inline buys.
    }

    fn write_bit(&mut self, bit: bool) -> Result<(), CellError> {
        self.push(bit)
    }
}

impl LabelSink for Vec<bool> {
    fn reset(&mut self) {
        self.clear();
    }

    fn make_room(&mut self, count: u16) {
        // The count came off a label header the reader has already held under the key
        // width, which check_key_bits holds under a cell's bit count, so this is bounded
        // by something the peer does not get to choose.
        self.reserve(usize::from(count));
    }

    fn write_bit(&mut self, bit: bool) -> Result<(), CellError> {
        self.push(bit);
        Ok(())
    }
}

/// What a label header says: how many bits, and whether the cell spells them out.
enum Run {
    /// `count` bits follow in the cell.
    Spelled(u16),
    /// One bit repeated `count` times, with nothing following it.
    Repeated(bool, u16),
}

/// Reads a label header, leaving the cursor on the bits it spells out, if it spells any.
///
/// The three encodings are a unary-counted run, an explicit length, and a repeated bit.
/// [`read_label_into`] and [`skip_label`] are its two callers, so the lengths the two accept
/// are decided in one place. That the two also move the cursor the same distance is what
/// `skipping_a_label_leaves_the_cursor_where_reading_one_does` holds them to.
fn read_run(slice: &mut Slice<'_>, max: u16) -> Result<Run, CellError> {
    if !slice.load_bit()? {
        // hml_short: a unary length, then that many bits.
        let mut len = 0u16;
        while slice.load_bit()? {
            len += 1;
            if len > max {
                return Err(CellError::LabelTooLong);
            }
        }
        return Ok(Run::Spelled(len));
    }

    if !slice.load_bit()? {
        // hml_long: an explicit length, then that many bits.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "bounded_width(max) is at most 16 because max is itself a u16, so this reads at most 16 bits and the result always fits u16"
        )]
        let len = slice.load_uint(bounded_width(max))? as u16;
        if len > max {
            return Err(CellError::LabelTooLong);
        }
        return Ok(Run::Spelled(len));
    }

    // hml_same: one bit repeated a given number of times.
    let value = slice.load_bit()?;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded_width(max) is at most 16 because max is itself a u16, so this reads at most 16 bits and the result always fits u16"
    )]
    let len = slice.load_uint(bounded_width(max))? as u16;
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    Ok(Run::Repeated(value, len))
}

/// Reads an edge label into `into`, replacing whatever it held.
///
/// # Errors
///
/// Returns [`CellError::LabelTooLong`] where the header claims more bits than `max`, and
/// [`CellError::NotEnoughBits`] where the cell ends inside the label.
pub(super) fn read_label_into<S: LabelSink + ?Sized>(
    slice: &mut Slice<'_>,
    max: u16,
    into: &mut S,
) -> Result<(), CellError> {
    into.reset();
    match read_run(slice, max)? {
        Run::Spelled(count) => {
            into.make_room(count);
            for _ in 0..count {
                into.write_bit(slice.load_bit()?)?;
            }
        }
        Run::Repeated(value, count) => {
            into.make_room(count);
            for _ in 0..count {
                into.write_bit(value)?;
            }
        }
    }
    Ok(())
}

/// Steps the cursor past an edge label without holding on to it.
///
/// This is what a reader that wants only what follows the label pays: the same header,
/// the same bounds, and no sink at all.
///
/// # Errors
///
/// As [`read_label_into`].
pub(super) fn skip_label(slice: &mut Slice<'_>, max: u16) -> Result<(), CellError> {
    match read_run(slice, max)? {
        Run::Spelled(count) => slice.skip_bits(usize::from(count)),
        // A repeated run spells its bits nowhere, so there is nothing to step over.
        Run::Repeated(..) => Ok(()),
    }
}

/// Writes `run` bit by bit, refusing the whole run before writing any of it.
fn store_run<R: BitRun + ?Sized>(into: &mut Builder, run: &R) -> Result<(), CellError> {
    let count = u16::try_from(run.len()).unwrap_or(u16::MAX);
    if !into.can_extend_by(count, 0) {
        return Err(CellError::NoRoomForBits {
            requested: usize::from(count),
            available: usize::from(into.bits_left()),
        });
    }
    for index in 0..run.len() {
        into.store_bit(run.bit(index))?;
    }
    Ok(())
}

/// Writes an edge label in the only encoding TON accepts for it.
///
/// All three forms read back as the same label, so the choice is invisible to a reader
/// and decides the cell's hash. The shortest wins; a tie goes to the earliest
/// constructor.
///
/// # Errors
///
/// Returns [`CellError::LabelTooLong`] where the label is wider than `max`, and
/// [`CellError::NoRoomForBits`] where it does not fit what the builder has left.
pub(super) fn store_label<R: BitRun + ?Sized>(
    into: &mut Builder,
    label: &R,
    max: u16,
) -> Result<(), CellError> {
    let len = u16::try_from(label.len()).unwrap_or(u16::MAX);
    if len > max {
        return Err(CellError::LabelTooLong);
    }
    let width = bounded_width(max);
    let bits = u32::from(len);

    let short = 2 * bits + 2;
    let long = 2 + width + bits;
    // The repeated form is on offer for an empty label as well, a bit run no times at all,
    // and costs 3 + width bits there. It never wins: the short form spells an empty label in
    // two, under that whatever the width, so an empty label takes the short form below.
    let first = label.bit(0);
    let repeated = if (1..label.len()).all(|index| label.bit(index) == first) {
        3 + width
    } else {
        u32::MAX
    };

    if short <= long && short <= repeated {
        into.store_bit(false)?;
        into.store_same_bit(true, len)?;
        into.store_bit(false)?;
        store_run(into, label)?;
    } else if long <= repeated {
        into.store_uint(0b10, 2)?;
        into.store_uint(u64::from(len), width)?;
        store_run(into, label)?;
    } else {
        into.store_uint(0b11, 2)?;
        into.store_bit(label.bit(0))?;
        into.store_uint(u64::from(len), width)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bits a run spells, as a vector, so a test can compare against a literal.
    fn spelled<R: BitRun + ?Sized>(run: &R) -> Vec<bool> {
        (0..run.len()).map(|index| run.bit(index)).collect()
    }

    /// A label spelling `bits`.
    fn label_of(bits: &[bool]) -> Label {
        let mut label = Label::new();
        label.extend(bits).expect("a run inside the ceiling");
        label
    }

    #[test]
    fn an_inline_label_holds_every_width_a_key_may_take_and_no_more() {
        // The argument for borrowing one of these rather than holding one in a recursive
        // frame rests on its size, so the size is asserted rather than remembered.
        assert_eq!(LABEL_BYTES, 128);
        assert_eq!(
            core::mem::size_of::<Label>(),
            130,
            "the size the argument for borrowing rather than holding one rests on moved"
        );

        // Every width a dictionary key may take has to fit, or a label would be refused
        // for a reason the format does not have.
        let mut label = Label::new();
        for _ in 0..MAX_BITS {
            label.push(true).expect("a cell's worth of bits fits");
        }
        assert_eq!(label.len(), usize::from(MAX_BITS));
        assert_eq!(label.push(false), Err(CellError::LabelTooLong));
    }

    #[test]
    fn a_refilled_label_spells_only_what_it_last_read() {
        // One label is reused all the way down a descent, so a refill that left a bit of
        // the last one behind would put a wrong label on a rebuilt node, and a wrong label
        // is a wrong hash.
        let mut builder = Builder::new();
        store_label(&mut builder, [true; 40].as_slice(), 64).expect("a long label");
        store_label(&mut builder, [false].as_slice(), 64).expect("a short one after it");
        let cell = builder.build().expect("well formed");

        let mut slice = cell.parse();
        let mut label = Label::new();
        read_label_into(&mut slice, 64, &mut label).expect("the long one");
        assert_eq!(label.len(), 40);
        read_label_into(&mut slice, 64, &mut label).expect("the short one");

        // The whole value rather than the run it spells, and in that order, because a read
        // back stops at the length: a bit of the long label left underneath the short one
        // is invisible to `spelled` and shows only in the value itself.
        assert_eq!(
            label,
            label_of(&[false]),
            "a stale bit survived the refill: the two spell the same run and part in what \
             sits past the end of it, which is why they print alike"
        );
        assert_eq!(spelled(&label), vec![false]);
    }

    #[test]
    fn a_head_and_a_tail_are_the_two_parts_of_a_label() {
        let label = label_of(&[true, false, true, true, false]);
        assert_eq!(spelled(&label.head(2)), vec![true, false]);
        assert_eq!(spelled(&label.tail(2)), vec![true, true, false]);
        assert_eq!(spelled(&label.head(0)), Vec::<bool>::new());
        assert_eq!(spelled(&label.tail(0)), spelled(&label));
        // Past the end each answers with what is left rather than reaching for a bit that
        // is not there.
        assert_eq!(spelled(&label.tail(5)), Vec::<bool>::new());
        assert_eq!(spelled(&label.tail(99)), Vec::<bool>::new());
        assert_eq!(spelled(&label.head(99)), spelled(&label));
    }

    #[test]
    fn skipping_a_label_leaves_the_cursor_where_reading_one_does() {
        // Skipping is the path a reader takes when it wants only what follows the label,
        // so the two have to spend the same bits or a summary is read from the wrong
        // offset.
        for (bits, max) in [
            (vec![], 0u16),
            (vec![], 256),
            (vec![true], 1),
            (vec![false; 200], 256),
            (vec![true, false, true, true, false], 8),
            ([true, false].repeat(100), 256),
        ] {
            let mut builder = Builder::new();
            store_label(&mut builder, bits.as_slice(), max).expect("the label fits");
            builder.store_uint(0b1011, 4).expect("a marker after it");
            let cell = builder.build().expect("well formed");

            let mut read = cell.parse();
            let mut label = Label::new();
            read_label_into(&mut read, max, &mut label).expect("the label reads");
            assert_eq!(spelled(&label), bits);

            let mut skipped = cell.parse();
            skip_label(&mut skipped, max).expect("the label skips");
            assert_eq!(
                skipped.remaining_bits(),
                read.remaining_bits(),
                "a {}-bit label under {max} skipped a different distance than it read",
                bits.len()
            );
            assert_eq!(skipped.load_uint(4).expect("the marker"), 0b1011);
        }
    }

    #[test]
    fn a_label_longer_than_its_width_is_refused_by_the_reader_and_by_the_skipper() {
        // A peer writes the header, so a length past the width is something this has to
        // refuse rather than something it may assume away.
        let mut label = Label::new();

        // hml_long, an explicit length of twelve read under a width of eight.
        let mut explicit = Builder::new();
        explicit.store_uint(0b10, 2).expect("the tag");
        explicit.store_uint(12, bounded_width(8)).expect("a length");
        explicit.store_same_bit(true, 12).expect("the bits");
        let explicit = explicit.build().expect("well formed");
        assert_eq!(
            read_label_into(&mut explicit.parse(), 8, &mut label),
            Err(CellError::LabelTooLong)
        );
        assert_eq!(
            skip_label(&mut explicit.parse(), 8),
            Err(CellError::LabelTooLong)
        );

        // hml_short, whose length is a run of set bits. The count is held under the width
        // as it is counted, so a run longer than the key stops rather than running on.
        let mut unary = Builder::new();
        unary.store_bit(false).expect("the tag");
        unary.store_same_bit(true, 12).expect("a unary length");
        unary.store_bit(false).expect("the terminator");
        unary.store_same_bit(true, 12).expect("the bits");
        let unary = unary.build().expect("well formed");
        assert_eq!(
            read_label_into(&mut unary.parse(), 8, &mut label),
            Err(CellError::LabelTooLong)
        );
        assert_eq!(
            skip_label(&mut unary.parse(), 8),
            Err(CellError::LabelTooLong)
        );

        // hml_same, which claims a length and spells no bits at all.
        let mut repeated = Builder::new();
        repeated.store_uint(0b11, 2).expect("the tag");
        repeated.store_bit(true).expect("the repeated bit");
        repeated.store_uint(12, bounded_width(8)).expect("a length");
        let repeated = repeated.build().expect("well formed");
        assert_eq!(
            read_label_into(&mut repeated.parse(), 8, &mut label),
            Err(CellError::LabelTooLong)
        );
        assert_eq!(
            skip_label(&mut repeated.parse(), 8),
            Err(CellError::LabelTooLong)
        );
    }
}
