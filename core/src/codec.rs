// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Small self-contained encoders: base64 and CRC16.
//!
//! These are the primitives the config and address parsers need beyond what
//! [`crate::cell`] already carries. They are written here rather than pulled as dependencies, the
//! same choice the feasibility spike made for CRC32: each is a handful of lines and
//! carries no supply-chain weight. Hex is the exception and is not written a second
//! time here: [`decode_hex`] reads [`crate::cell::hex_decode`].

/// Decodes base64 from both alphabets, in canonical form within an alphabet.
///
/// Accepts both alphabets (`+/` and `-_`) so it serves config keys, which are standard
/// base64, and user-friendly addresses, which are URL-safe. Returns `None` on any
/// character outside either alphabet.
///
/// Canonical within an alphabet and not across the two: a value whose bytes reach sextet
/// 62 or 63 has a spelling in each, and both decode here. Whether a user-friendly address
/// may be written both ways is an open question recorded beside the address parser, so
/// this reader does not settle it by refusing one.
///
/// # Within one alphabet
///
/// One input decodes to one output and one output encodes to one input. That is a
/// property worth spending a few lines on rather than a nicety: without it, appending a
/// character to a 48-character address adds six bits, emits no byte, and yields the same
/// address, so two different strings name one account and any caller keeping a list of
/// addresses as strings can be walked past it. The three things that would break it are
/// a length that is not a whole number of quanta, padding in the middle, and a final
/// character with bits set that no output byte carries.
///
/// # Across the two alphabets
///
/// It does not hold, and the difference is measured rather than argued. A `-` and a `+`
/// both decode to 62 and a `_` and a `/` both to 63, so swapping either pair spells the
/// same bytes: `-_8=`, `+_8=`, `-/8=` and `+/8=` are four strings for the two bytes
/// `fb ff`, and `EQD8uRo6OBbQ97jCx2EIuKm8Wmt6Vb15-KsQHFLbKSMiYM0w` with `+` in place of
/// its `-` is a second string that [`Address::parse`](crate::Address::parse) answers an
/// equal address for. A string taking characters from both alphabets at once decodes as
/// readily as one that stays in either. So the count of spellings a 36-byte address has
/// here is two raised to the number of its characters that decode to 62 or 63, and the
/// test below enumerates that count for one two-byte value rather than reasoning to it.
///
/// # Why it is left that way
///
/// Narrowing to one alphabet would close it, and is not done here. Nothing in this
/// repository establishes which alphabet a user-friendly address may be written in, and
/// the form is in circulation in both spellings, so refusing one would refuse addresses
/// other tools emit: a worse failure than the one it cures, chosen on no evidence. The
/// behaviour is pinned by `both_alphabets_spell_one_value` below so it cannot drift
/// while the question is open. A caller that needs one identity per account compares the
/// parsed [`Address`](crate::Address), which is equal across the spellings, rather than
/// the string it was parsed from.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a' + 26),
            b'0'..=b'9' => u32::from(c - b'0' + 52),
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    // At most two `=`, and only at the end.
    let padding = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    let body = bytes.get(..bytes.len() - padding)?;
    if padding > 2 || body.contains(&b'=') {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in body {
        acc = (acc << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "bits was just reduced below 8, so acc >> bits carries exactly the newly completed byte in its low 8 bits; anything the cast drops above that is a sextet already pushed in an earlier iteration"
            )]
            out.push((acc >> bits) as u8);
        }
    }
    // Whatever is left over belongs to no output byte, so an encoder would have left it
    // clear. Anything set here is a second spelling of the same value.
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// CRC-16/XMODEM (polynomial `0x1021`, initial value `0`), the checksum TON uses in a
/// user-friendly address.
///
/// Verified against addresses packed by the reference implementation, in both
/// workchains and both bounceable forms.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Decodes a hex string to bytes, or `None` if the length is odd or a character is not a
/// hex digit.
///
/// The rule lives in [`crate::cell::hex_decode`], which every hex read on this crate's
/// own parse paths goes through, and it carries the refusal of the leading `+` that the
/// standard library's `from_str_radix` accepts. The `Option` is what the parsers in this
/// crate already read, and the reason for the failure has nowhere to go in an address
/// error that quotes the whole string anyway.
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    crate::cell::hex_decode(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
    }

    #[test]
    fn base64_decodes_a_config_key() {
        // A liteserver key from the bundled config, standard-alphabet base64.
        let key = base64_decode("n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=").unwrap();
        assert_eq!(
            hex(&key),
            "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309"
        );
    }

    #[test]
    fn base64_decodes_the_url_safe_alphabet() {
        // `-` and `_` stand in for `+` and `/`.
        assert_eq!(base64_decode("-_8=").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn base64_rejects_an_invalid_character() {
        assert!(base64_decode("****").is_none());
    }

    /// The measured count of spellings one value has here, pinned while the question of
    /// which alphabet an address may use is open.
    ///
    /// This records the behaviour rather than endorsing it. Two bytes with a 62 and a 63
    /// in them have four spellings, not one, and the two mixed spellings are as good as
    /// the two pure ones. A change that narrows the decoder to a single alphabet is a
    /// change to what the library accepts and belongs with the evidence that settles the
    /// question, so it fails here first rather than silently.
    #[test]
    fn both_alphabets_spell_one_value() {
        // Enumerated rather than illustrated. Every three-character quantum over the 66
        // characters this decoder takes, filtered by what it decodes to: the two bytes
        // `fb ff` come back from four strings, one for each way the 62 and the 63 in
        // them may be written, and from no other string of that shape. Four characters
        // and one pad is the only shape that spells two bytes, because an accepted
        // string carries `len / 4 * 3 - padding` of them.
        const TAKEN: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_";
        let mut spellings = Vec::new();
        for &high in TAKEN {
            for &middle in TAKEN {
                for &low in TAKEN {
                    let text = String::from_utf8(vec![high, middle, low, b'='])
                        .expect("the alphabet is ascii");
                    if base64_decode(&text).as_deref() == Some(&[0xfb, 0xff][..]) {
                        spellings.push(text);
                    }
                }
            }
        }
        assert_eq!(spellings, ["+/8=", "+_8=", "-/8=", "-_8="]);
    }

    /// The same, one layer up, on a real address rather than on two bytes.
    #[test]
    fn both_alphabets_spell_one_address() {
        let url_safe = "EQD8uRo6OBbQ97jCx2EIuKm8Wmt6Vb15-KsQHFLbKSMiYM0w";
        let standard = "EQD8uRo6OBbQ97jCx2EIuKm8Wmt6Vb15+KsQHFLbKSMiYM0w";
        assert_ne!(url_safe, standard, "two strings, not one");
        assert_eq!(
            base64_decode(url_safe).unwrap(),
            base64_decode(standard).unwrap()
        );
        assert_eq!(
            crate::Address::parse(url_safe).unwrap(),
            crate::Address::parse(standard).unwrap()
        );
    }

    #[test]
    fn crc16_matches_the_reference() {
        // The first 34 bytes of the elector's bounceable address: tag, workchain, hash.
        let mut preimage = vec![0x11, 0xff];
        preimage.extend_from_slice(&[0x33; 32]);
        assert_eq!(crc16(&preimage), 0x4bc5);
    }

    #[test]
    fn decode_hex_round_trips() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(decode_hex("0").is_none());
        assert!(decode_hex("zz").is_none());
    }

    #[test]
    fn decode_hex_refuses_a_leading_sign() {
        // A reader that took the leading `+` that `u8::from_str_radix` accepts would
        // spell every byte below 0x10 a second way, so a raw address whose account id
        // holds k of them would have 2^k spellings rather than one.
        assert_eq!(decode_hex("0f").unwrap(), vec![0x0f]);
        assert!(decode_hex("+f").is_none());
        assert!(decode_hex("+f+f").is_none());
    }
}
