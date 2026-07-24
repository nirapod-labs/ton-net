// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reaching a dictionary by an integer key.
//!
//! A dictionary's keys are bytes, most significant bit first. Most dictionaries key on a
//! fixed-width integer, a config parameter number or a workchain, so these reach one by its
//! value: the integer is written big-endian to the dictionary's own key width, which has to
//! be a whole number of bytes.

use super::{Dict, DictEntry, Lookup};
use crate::builder::Builder;
use crate::error::CellError;

impl Dict {
    /// Looks up the entry under an unsigned integer key.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`get`](Dict::get) does, or if the key does not fit the
    /// dictionary's width or that width is not a whole number of bytes.
    pub fn get_uint(&self, key: u64) -> Result<Lookup<DictEntry>, CellError> {
        self.get(&uint_key(key, self.key_bits())?)
    }

    /// Stores `value` under an unsigned integer key.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`set`](Dict::set) does, or if the key does not fit.
    pub fn set_uint(&mut self, key: u64, value: &Builder) -> Result<(), CellError> {
        let bytes = uint_key(key, self.key_bits())?;
        self.set(&bytes, value)
    }

    /// Removes an unsigned integer key, reporting whether it was there.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`remove`](Dict::remove) does, or if the key does not fit.
    pub fn remove_uint(&mut self, key: u64) -> Result<bool, CellError> {
        let bytes = uint_key(key, self.key_bits())?;
        self.remove(&bytes)
    }

    /// Looks up the entry under a signed integer key, in two's complement.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`get`](Dict::get) does, or if the key does not fit.
    pub fn get_int(&self, key: i64) -> Result<Lookup<DictEntry>, CellError> {
        self.get(&int_key(key, self.key_bits())?)
    }

    /// Stores `value` under a signed integer key, in two's complement.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`set`](Dict::set) does, or if the key does not fit.
    pub fn set_int(&mut self, key: i64, value: &Builder) -> Result<(), CellError> {
        let bytes = int_key(key, self.key_bits())?;
        self.set(&bytes, value)
    }

    /// Removes a signed integer key, reporting whether it was there.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] as [`remove`](Dict::remove) does, or if the key does not fit.
    pub fn remove_int(&mut self, key: i64) -> Result<bool, CellError> {
        let bytes = int_key(key, self.key_bits())?;
        self.remove(&bytes)
    }
}

/// The width, in whole bytes, of a dictionary keyed on `key_bits`.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if the width is not a whole number of bytes, since an
/// integer key has no unambiguous placement in a partial byte.
fn key_width(key_bits: u16) -> Result<usize, CellError> {
    if key_bits % 8 != 0 {
        return Err(CellError::Malformed(
            "an integer key needs a byte-aligned dictionary width",
        ));
    }
    Ok(usize::from(key_bits / 8))
}

/// The big-endian bytes of an unsigned `key` at a dictionary's key width.
fn uint_key(key: u64, key_bits: u16) -> Result<Vec<u8>, CellError> {
    let width = key_width(key_bits)?;
    let be = key.to_be_bytes();
    if width >= be.len() {
        let mut out = vec![0u8; width - be.len()];
        out.extend_from_slice(&be);
        Ok(out)
    } else {
        let (high, low) = be.split_at(be.len() - width);
        if high.iter().any(|&byte| byte != 0) {
            return Err(CellError::Malformed(
                "key does not fit the dictionary width",
            ));
        }
        Ok(low.to_vec())
    }
}

/// The two's-complement bytes of a signed `key` at a dictionary's key width.
fn int_key(key: i64, key_bits: u16) -> Result<Vec<u8>, CellError> {
    let width = key_width(key_bits)?;
    let be = key.to_be_bytes();
    let fill = if key < 0 { 0xFFu8 } else { 0x00 };
    if width >= be.len() {
        let mut out = vec![fill; width - be.len()];
        out.extend_from_slice(&be);
        Ok(out)
    } else {
        let (high, low) = be.split_at(be.len() - width);
        // The truncated bytes have to be the sign extension, and the narrowed value's own
        // top bit has to match the sign, or the value did not fit the width.
        let fits_sign = low
            .first()
            .is_some_and(|&top| (top & 0x80 != 0) == (key < 0));
        if high.iter().any(|&byte| byte != fill) || !fits_sign {
            return Err(CellError::Malformed(
                "key does not fit the dictionary width",
            ));
        }
        Ok(low.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Builder, Dict, Lookup};

    /// A one-byte value to store.
    fn value(byte: u64) -> Builder {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder
    }

    #[test]
    fn an_unsigned_key_round_trips() {
        let mut dict = Dict::new(32).expect("a dictionary");
        dict.set_uint(7, &value(0xAB)).expect("the set");

        let looked = dict.get_uint(7).expect("the get");
        assert!(matches!(looked, Lookup::Found(_)), "the key was just set");
        if let Lookup::Found(entry) = looked {
            let read = entry
                .slice()
                .expect("a slice")
                .load_uint(8)
                .expect("a byte");
            assert_eq!(read, 0xAB);
        }
        assert!(matches!(dict.get_uint(8).expect("the get"), Lookup::Absent));
    }

    #[test]
    fn a_typed_key_matches_its_bytes() {
        let mut dict = Dict::new(32).expect("a dictionary");
        dict.set_uint(0x0102_0304, &value(1)).expect("the set");
        // The same key given as bytes finds the same entry.
        assert!(matches!(
            dict.get(&0x0102_0304u32.to_be_bytes()).expect("the get"),
            Lookup::Found(_)
        ));
    }

    #[test]
    fn a_signed_key_matches_its_twos_complement_bytes() {
        let mut dict = Dict::new(32).expect("a dictionary");
        dict.set_int(-5, &value(9)).expect("the set");
        assert!(matches!(
            dict.get_int(-5).expect("the get"),
            Lookup::Found(_)
        ));
        assert!(matches!(
            dict.get(&(-5i32).to_be_bytes()).expect("the get"),
            Lookup::Found(_)
        ));
    }

    #[test]
    fn a_key_too_wide_for_the_dictionary_is_refused() {
        let mut dict = Dict::new(8).expect("a dictionary");
        assert!(dict.set_uint(256, &value(1)).is_err());
        assert!(dict.get_int(128).is_err());
    }

    #[test]
    fn a_partial_byte_width_is_refused() {
        let dict = Dict::new(12).expect("a dictionary");
        assert!(dict.get_uint(1).is_err());
    }
}
