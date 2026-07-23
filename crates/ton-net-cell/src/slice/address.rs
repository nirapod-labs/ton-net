// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a message address.
//!
//! A message names its source and destination with a `MsgAddress`. The standard form
//! carries a workchain and a 256-bit account id; the none form names no account, as an
//! empty source or an uninitialised destination does. The external and variable forms are
//! refused rather than guessed, since this client sends to neither.

use super::Slice;
use crate::error::CellError;

/// An account address, as a message carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgAddress {
    /// No account, the form an empty source or an uninitialised destination takes.
    None,
    /// A standard internal address: a workchain and the account id within it.
    Std {
        /// The workchain the account lives in.
        workchain: i8,
        /// The account id, a 256-bit hash.
        account: [u8; 32],
    },
}

impl Slice<'_> {
    /// Reads a [`MsgAddress`].
    ///
    /// The none and standard forms are read. The external and variable forms are refused:
    /// this client sends to neither, and reading a form it cannot act on as if it were
    /// absent would be worse than naming it unsupported. An anycast prefix is refused for
    /// the same reason.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if the bits run out, if the address carries an anycast prefix,
    /// or if its form is external or variable.
    pub fn load_address(&mut self) -> Result<MsgAddress, CellError> {
        match self.load_uint(2)? {
            0b00 => Ok(MsgAddress::None),
            0b10 => {
                if self.load_bit()? {
                    return Err(CellError::Malformed("anycast address is not supported"));
                }
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "load_int(8) yields a value in i8 range"
                )]
                let workchain = self.load_int(8)? as i8;
                let account = self
                    .load_bytes(32)?
                    .try_into()
                    .map_err(|_| CellError::Malformed("address is not thirty-two bytes"))?;
                Ok(MsgAddress::Std { workchain, account })
            }
            _ => Err(CellError::Malformed(
                "external and variable addresses are not supported",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    /// Writes the cell an address stores to, then reads it back.
    fn round_trip(address: &MsgAddress) -> MsgAddress {
        let mut builder = Builder::new();
        builder.store_address(address).expect("an address fits");
        let cell = builder.build().expect("the cell is well formed");
        cell.parse().load_address().expect("the address reads back")
    }

    #[test]
    fn the_none_form_round_trips() {
        assert_eq!(round_trip(&MsgAddress::None), MsgAddress::None);
    }

    #[test]
    fn the_standard_form_round_trips() {
        for (workchain, fill) in [(0i8, 0x00u8), (-1, 0xff), (1, 0x11)] {
            let address = MsgAddress::Std {
                workchain,
                account: [fill; 32],
            };
            assert_eq!(round_trip(&address), address);
        }
    }

    #[test]
    fn an_anycast_address_is_refused() {
        // A standard address with the anycast bit set: tag 10, then a set maybe bit.
        let mut builder = Builder::new();
        builder.store_uint(0b10, 2).expect("the tag fits");
        builder.store_bit(true).expect("the anycast bit fits");
        builder.store_int(0, 8).expect("a workchain fits");
        builder.store_bytes(&[0u8; 32]).expect("an account fits");
        let cell = builder.build().expect("the cell is well formed");
        assert_eq!(
            cell.parse().load_address(),
            Err(CellError::Malformed("anycast address is not supported"))
        );
    }

    #[test]
    fn an_external_address_is_refused() {
        let mut builder = Builder::new();
        builder.store_uint(0b01, 2).expect("the tag fits");
        let cell = builder.build().expect("the cell is well formed");
        assert_eq!(
            cell.parse().load_address(),
            Err(CellError::Malformed(
                "external and variable addresses are not supported"
            ))
        );
    }
}
