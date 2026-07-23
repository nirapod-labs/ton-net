// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Writing a message address.
//!
//! The write side of [`load_address`](crate::Slice::load_address): the none and standard
//! forms, in the layout a message reads them from.

use super::Builder;
use crate::error::CellError;
use crate::slice::MsgAddress;

impl Builder {
    /// Writes a [`MsgAddress`] in the standard or none form.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if the cell has no room left for the address.
    pub fn store_address(&mut self, address: &MsgAddress) -> Result<&mut Self, CellError> {
        match address {
            MsgAddress::None => {
                self.store_uint(0b00, 2)?;
            }
            MsgAddress::Std { workchain, account } => {
                self.store_uint(0b10, 2)?;
                self.store_bit(false)?;
                self.store_int(i64::from(*workchain), 8)?;
                self.store_bytes(account)?;
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::slice::MsgAddress;
    use crate::Builder;

    #[test]
    fn the_none_form_is_two_bits() {
        let mut builder = Builder::new();
        builder.store_address(&MsgAddress::None).expect("it fits");
        assert_eq!(builder.build().expect("well formed").bit_len(), 2);
    }

    #[test]
    fn the_standard_form_is_two_hundred_sixty_seven_bits() {
        // Two for the tag, one for the absent anycast, eight for the workchain, and the
        // account's own two hundred fifty-six.
        let mut builder = Builder::new();
        builder
            .store_address(&MsgAddress::Std {
                workchain: 0,
                account: [0; 32],
            })
            .expect("it fits");
        assert_eq!(builder.build().expect("well formed").bit_len(), 267);
    }
}
