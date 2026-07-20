//! TON account addresses: parsing the raw and user-friendly forms.

use crate::codec::{base64_decode, crc16, decode_hex};
use crate::Error;

/// A TON account address: a workchain id and a 256-bit account id.
///
/// Parses both the raw `workchain:hex` form and the user-friendly base64 form. The
/// address carries no balance or state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    workchain: i32,
    account_id: [u8; 32],
}

impl Address {
    /// Parses an address from a string.
    ///
    /// Accepts the raw form, for example `-1:3333...3333`, and the user-friendly base64
    /// form, for example `Ef8z...`. A raw address is a workchain, a colon, and 64 hex
    /// digits. A user-friendly address is 36 base64 bytes whose CRC16 checksum is
    /// verified.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Address`] if the string is not a valid address in either form, or
    /// if a user-friendly address fails its checksum.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net::Address;
    /// let a = Address::parse(
    ///     "-1:3333333333333333333333333333333333333333333333333333333333333333",
    /// )?;
    /// assert_eq!(a.workchain(), -1);
    /// # Ok::<(), ton_net::Error>(())
    /// ```
    pub fn parse(s: &str) -> Result<Address, Error> {
        if let Some((workchain, account)) = s.split_once(':') {
            return Self::parse_raw(s, workchain, account);
        }
        Self::parse_user_friendly(s)
    }

    fn parse_raw(whole: &str, workchain: &str, account: &str) -> Result<Address, Error> {
        let workchain: i32 = workchain
            .parse()
            .map_err(|_| Error::Address(format!("invalid workchain in `{whole}`")))?;
        let account_id: [u8; 32] = decode_hex(account)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                Error::Address(format!("account id is not 32 hex bytes in `{whole}`"))
            })?;
        Ok(Address {
            workchain,
            account_id,
        })
    }

    fn parse_user_friendly(s: &str) -> Result<Address, Error> {
        // tag (1) ++ workchain (1) ++ account id (32) ++ crc16 (2)
        let raw = base64_decode(s)
            .filter(|bytes| bytes.len() == 36)
            .ok_or_else(|| Error::Address(format!("not a 36-byte user-friendly address: `{s}`")))?;

        let stored = [raw[34], raw[35]];
        if crc16(&raw[..34]).to_be_bytes() != stored {
            return Err(Error::Address(format!(
                "address checksum mismatch in `{s}`"
            )));
        }

        // The workchain byte is a signed 8-bit value: 0x00 is workchain 0, 0xff is -1.
        let workchain = i32::from(raw[1] as i8);
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&raw[2..34]);
        Ok(Address {
            workchain,
            account_id,
        })
    }

    /// Returns the workchain id.
    #[must_use]
    pub fn workchain(&self) -> i32 {
        self.workchain
    }

    /// Returns the 32-byte account id.
    #[must_use]
    pub fn account_id(&self) -> &[u8; 32] {
        &self.account_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parses_the_raw_form() {
        let a =
            Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        assert_eq!(a.workchain(), -1);
        assert_eq!(a.account_id(), &[0x33; 32]);
    }

    #[test]
    fn parses_a_real_user_friendly_address() {
        // The reference implementation packs 0:fcb91a...2260 to this address.
        let a = Address::parse("EQD8uRo6OBbQ97jCx2EIuKm8Wmt6Vb15-KsQHFLbKSMiYM0w").unwrap();
        assert_eq!(a.workchain(), 0);
        assert_eq!(
            hex(a.account_id()),
            "fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260"
        );
    }

    #[test]
    fn the_raw_and_user_friendly_forms_agree() {
        // The elector, in both forms, is one address.
        let raw =
            Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        let friendly = Address::parse("Ef8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0vF").unwrap();
        assert_eq!(raw, friendly);
    }

    #[test]
    fn rejects_a_corrupted_checksum() {
        // The elector's address with its last base64 digit changed.
        let corrupted = "Ef8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0vG";
        assert!(matches!(Address::parse(corrupted), Err(Error::Address(_))));
    }

    #[test]
    fn rejects_a_non_numeric_workchain() {
        assert!(matches!(
            Address::parse("zz:3333333333333333333333333333333333333333333333333333333333333333"),
            Err(Error::Address(_))
        ));
    }

    #[test]
    fn rejects_a_short_account_id() {
        assert!(matches!(Address::parse("0:3333"), Err(Error::Address(_))));
    }
}
