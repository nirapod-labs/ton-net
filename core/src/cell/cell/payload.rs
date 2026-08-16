// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A cell's data bytes, and where they sit in the buffer they came from.
//!
//! A bag of cells arrives as one run of bytes and every cell's data is already inside it,
//! so a cell can hold a window on that run instead of a copy of its own slice of it. The
//! buffer lives as long as any cell taken from it, which is what makes the window safe and
//! what it costs: keeping one cell of a bag keeps the bag's bytes.
//! [`MAX_CELLS`](crate::cell::MAX_CELLS) is what bounds how much that is.
//!
//! A cell that comes from a [`Builder`](crate::cell::Builder) rather than a bag owns its own
//! bytes, which is the same shape with a buffer of one cell in it.

use std::sync::{Arc, OnceLock};

use crate::cell::error::CellError;

/// Where a cell's bytes sit in the buffer that holds them.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    start: u32,
    end: u32,
}

impl Span {
    /// A span of `len` bytes beginning at `start`.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if the span runs past what a bag can be indexed by.
    pub fn new(start: usize, len: usize) -> Result<Self, CellError> {
        let too_far = || CellError::Malformed("bag of cells is too large to index");
        let start = u32::try_from(start).map_err(|_| too_far())?;
        let len = u32::try_from(len).map_err(|_| too_far())?;
        let end = start.checked_add(len).ok_or_else(too_far)?;
        Ok(Self { start, end })
    }

    /// The bytes this span names, out of the buffer it was measured against.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Truncated`] if `bytes` is shorter than the span.
    pub fn of(self, bytes: &[u8]) -> Result<&[u8], CellError> {
        bytes
            .get(self.start as usize..self.end as usize)
            .ok_or(CellError::Truncated)
    }
}

/// The buffer an owned empty payload points at, so a cell built with no data costs no
/// allocation. A cell read out of a bag shares the bag's buffer instead, empty or not.
fn nothing() -> Arc<[u8]> {
    static NOTHING: OnceLock<Arc<[u8]>> = OnceLock::new();
    Arc::clone(NOTHING.get_or_init(|| Arc::from(&[][..])))
}

/// A cell's data bytes: a buffer, shared with whatever else came from it, and a window on it.
#[derive(Debug, Clone)]
pub struct Payload {
    bytes: Arc<[u8]>,
    span: Span,
}

impl Payload {
    /// The bytes of one cell, in a buffer of their own.
    ///
    /// # Errors
    ///
    /// As [`Span::new`].
    pub fn owned(data: Vec<u8>) -> Result<Self, CellError> {
        let span = Span::new(0, data.len())?;
        let bytes = if data.is_empty() {
            nothing()
        } else {
            Arc::from(data)
        };
        Ok(Self { bytes, span })
    }

    /// A window on a buffer shared with every other cell taken from it.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Truncated`] if the span runs past the buffer.
    pub fn window(bytes: &Arc<[u8]>, span: Span) -> Result<Self, CellError> {
        // Held to the buffer once, here, which is what lets reading it back never fail.
        span.of(bytes)?;
        Ok(Self {
            bytes: Arc::clone(bytes),
            span,
        })
    }

    /// The cell's data bytes.
    pub fn as_slice(&self) -> &[u8] {
        // The span was held to these bytes when the payload was made and neither has
        // changed since, so the fallback is unreachable.
        self.span.of(&self.bytes).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_reads_back_the_bytes_it_names() {
        let bag: Arc<[u8]> = Arc::from(&[0u8, 1, 2, 3, 4, 5][..]);
        let payload = Payload::window(&bag, Span::new(2, 3).expect("a span")).expect("in range");
        assert_eq!(payload.as_slice(), &[2, 3, 4]);
    }

    #[test]
    fn every_cell_of_a_bag_shares_one_buffer() {
        let bag: Arc<[u8]> = Arc::from(&[0u8, 1, 2, 3][..]);
        let first = Payload::window(&bag, Span::new(0, 2).expect("a span")).expect("in range");
        let second = Payload::window(&bag, Span::new(2, 2).expect("a span")).expect("in range");
        assert!(
            Arc::ptr_eq(&first.bytes, &second.bytes),
            "two cells of one bag hold one allocation between them"
        );
    }

    #[test]
    fn a_window_past_the_buffer_is_refused() {
        let bag: Arc<[u8]> = Arc::from(&[0u8, 1][..]);
        assert!(Payload::window(&bag, Span::new(1, 4).expect("a span")).is_err());
    }

    #[test]
    fn an_owned_empty_payload_costs_no_buffer_of_its_own() {
        let first = Payload::owned(Vec::new()).expect("empty is a payload");
        let second = Payload::owned(Vec::new()).expect("empty is a payload");
        assert!(first.as_slice().is_empty());
        assert!(
            Arc::ptr_eq(&first.bytes, &second.bytes),
            "two owned empty payloads point at the same nothing"
        );
    }

    #[test]
    fn an_empty_cell_read_from_a_bag_shares_the_bag() {
        // The nothing buffer is reachable from `owned` alone. A bag's empty cell holds a
        // zero-length window on the bag, which is why keeping it keeps the bag's bytes.
        let bag: Arc<[u8]> = Arc::from(&[7u8, 8, 9][..]);
        let empty = Payload::window(&bag, Span::new(1, 0).expect("a span")).expect("a window");
        assert!(empty.as_slice().is_empty());
        assert!(
            Arc::ptr_eq(&empty.bytes, &bag),
            "an empty cell out of a bag points at the bag, not at the nothing buffer"
        );
        let owned = Payload::owned(Vec::new()).expect("empty is a payload");
        assert!(
            !Arc::ptr_eq(&empty.bytes, &owned.bytes),
            "and so is not the buffer an owned empty payload points at"
        );
    }
}
