//! Small self-contained encoders: base64, CRC16, and hex.
//!
//! These are the few primitives the config and address parsers need. They are written
//! here rather than pulled as dependencies, the same choice the feasibility spike made
//! for CRC32: each is a handful of lines and carries no supply-chain weight.

/// Decodes standard or URL-safe base64, ignoring `=` padding.
///
/// Accepts both alphabets (`+/` and `-_`) so it serves config keys, which are standard
/// base64, and user-friendly addresses, which are URL-safe. Returns `None` on any
/// character outside either alphabet.
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        acc = (acc << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// CRC-16/XMODEM (polynomial `0x1021`, initial value `0`), the checksum TON uses in a
/// user-friendly address.
///
/// Verified against addresses packed by the reference implementation, in both
/// workchains and both bounceable forms.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
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
pub(crate) fn decode_hex(input: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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
}
