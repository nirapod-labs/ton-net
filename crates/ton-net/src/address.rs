//! TON account addresses: parsing the raw and user-friendly forms.

use crate::codec::{base64_decode, crc16, decode_hex};
use crate::Error;

/// The tag byte of a user-friendly address, with neither flag set.
const ADDRESS_TAG: u8 = 0x11;

/// The tag bit marking an address as usable only on a test network.
const TEST_ONLY: u8 = 0x80;

/// The tag bit marking an address as non-bounceable.
const NON_BOUNCEABLE: u8 = 0x40;

/// A TON account address: a workchain id and a 256-bit account id.
///
/// Parses both the raw `workchain:hex` form and the user-friendly base64 form. The
/// address carries no balance or state.
///
/// Two addresses are equal when they name the same account. The user-friendly form also
/// carries a bounceable and a test-only flag, which say how a message to the account
/// should be sent and which network it belongs to rather than which account it is, so
/// they are readable but do not enter into equality. The raw form carries neither, and an
/// address parsed from it reports the defaults: bounceable, and not test-only.
#[derive(Debug, Clone)]
pub struct Address {
    workchain: i32,
    account_id: [u8; 32],
    bounceable: bool,
    test_only: bool,
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
            bounceable: true,
            test_only: false,
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

        // The checksum covers the tag, so it validates whatever tag the string carries
        // rather than the ones the format defines. Reading the tag is what keeps this
        // from accepting a string every other TON implementation refuses.
        let tag = raw[0];
        if tag & !(TEST_ONLY | NON_BOUNCEABLE) != ADDRESS_TAG {
            return Err(Error::Address(format!(
                "unknown address tag {tag:#04x} in `{s}`"
            )));
        }

        // The workchain byte is a signed 8-bit value: 0x00 is workchain 0, 0xff is -1.
        let workchain = i32::from(raw[1] as i8);
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&raw[2..34]);
        Ok(Address {
            workchain,
            account_id,
            bounceable: tag & NON_BOUNCEABLE == 0,
            test_only: tag & TEST_ONLY != 0,
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

    /// Whether a failed message to this address should be returned to its sender.
    ///
    /// A hint about sending, not part of the account's identity. True for an address
    /// parsed from the raw form, which does not carry the flag.
    #[must_use]
    pub fn is_bounceable(&self) -> bool {
        self.bounceable
    }

    /// Whether the address was written for a test network.
    ///
    /// Which network a client is on is decided by its [`Config`](crate::Config), not by
    /// an address, so this is not enforced anywhere: a test-only address read against
    /// mainnet gets a correct answer about a mainnet account, which is almost certainly
    /// not the account the caller meant. A caller that cares checks this.
    #[must_use]
    pub fn is_test_only(&self) -> bool {
        self.test_only
    }
}

impl PartialEq for Address {
    /// Equal when they name the same account. The sending hints are not the account.
    fn eq(&self, other: &Address) -> bool {
        self.workchain == other.workchain && self.account_id == other.account_id
    }
}

impl Eq for Address {}

impl std::hash::Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.workchain.hash(state);
        self.account_id.hash(state);
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
    fn one_account_has_one_user_friendly_spelling() {
        // Forty-eight base64 characters carry exactly the thirty-six bytes an address
        // needs, with nothing left over. A forty-ninth adds six bits and no byte, so
        // without a canonical decoder it would spell the same address a second way and
        // any caller holding a list of addresses as strings could be walked past it.
        let real = "EQD8uRo6OBbQ97jCx2EIuKm8Wmt6Vb15-KsQHFLbKSMiYM0w";
        assert!(Address::parse(real).is_ok());
        for extra in ["A", "z", "9", "-", "_", "=", "=A"] {
            let padded = format!("{real}{extra}");
            assert!(
                matches!(Address::parse(&padded), Err(Error::Address(_))),
                "`{padded}` parsed as an address"
            );
        }
    }

    #[test]
    fn an_address_tag_is_read_rather_than_assumed() {
        // The checksum covers the tag, so a string carrying any tag at all checksums
        // correctly and the checksum alone cannot refuse one. The elector's address,
        // repacked under each tag the format defines and two it does not.
        let account = [0x33; 32];
        let packed = |tag: u8| {
            let mut raw = vec![tag, 0xff];
            raw.extend_from_slice(&account);
            raw.extend_from_slice(&crc16(&raw).to_be_bytes());
            base64_encode(&raw)
        };

        for (tag, bounceable, test_only) in [
            (0x11, true, false),
            (0x51, false, false),
            (0x91, true, true),
            (0xd1, false, true),
        ] {
            let address = Address::parse(&packed(tag)).expect("a tag the format defines");
            assert_eq!(address.workchain(), -1);
            assert_eq!(address.is_bounceable(), bounceable);
            assert_eq!(address.is_test_only(), test_only);
            // The flags describe how to send, not which account, so they leave the
            // address equal to the same account written any other way.
            assert_eq!(
                address,
                Address::parse(
                    "-1:3333333333333333333333333333333333333333333333333333333333333333"
                )
                .unwrap()
            );
        }

        for tag in [0x00, 0xff, 0x12, 0x21] {
            assert!(
                matches!(Address::parse(&packed(tag)), Err(Error::Address(_))),
                "tag {tag:#04x} was accepted"
            );
        }
    }

    /// Packs bytes as URL-safe base64, for building the tagged addresses above.
    fn base64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let n = u32::from_be_bytes([0, block[0], block[1], block[2]]);
            let digits = chunk.len() * 8 / 6 + 1;
            for i in 0..4 {
                if i < digits {
                    out.push(ALPHABET[((n >> (18 - i * 6)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
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
