// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Base64 and hex: the two spellings a bag of cells and a cell hash travel in.
//!
//! A serialized bag and a 32-byte hash cross a JSON body, a log line, or a command
//! argument as text, and both spellings already appear in the surfaces this client
//! reads: the block a network config pins names its hashes in standard base64, and a raw
//! account address is written as hex. Both directions sit here so a caller holding a
//! [`Cell`](crate::cell::Cell) writes one down and reads it back without reaching outside this
//! crate. It admits no dependency, so NET-ADR-004 has nothing new to vet.
//!
//! # One base64 spelling for one value
//!
//! [`base64_decode`] takes the canonical standard-alphabet form and nothing else, which
//! is the half of the property [`base64_encode`] cannot hold alone. Encoding a byte
//! string and decoding the result gives that byte string back, and decoding a string
//! this function accepts and encoding the result gives that same string back. A byte
//! string therefore has one spelling here and no other.
//!
//! Three things would break that, and each is refused: a length that is not a whole
//! four-character quantum, a run of padding longer than the two characters a quantum can
//! end with, and a final character carrying bits that no output byte does. The last is
//! the one that is easy to miss, because a string carrying it decodes without complaint
//! to the same bytes the canonical spelling gives. What it costs is concrete rather than
//! tidy: where a caller keys a map or a list on the written form of a hash, a second
//! spelling of one hash is an entry that caller does not know it holds.
//!
//! The claim is enumerated as far as enumeration reaches. The tests walk every quantum
//! over the whole alphabet for the two shapes that carry spare bits, one output byte and
//! two, and count how many spellings survive: 256 and 65,536, one for each value. Past
//! two bytes it is reasoning rather than a count, because a full quantum has no spare
//! bits to set and the length a byte count implies is the only length that carries it.
//!
//! # The alphabet this does not take
//!
//! The URL-safe alphabet, `-` and `_` standing in for `+` and `/`, is refused. It is the
//! spelling of TON's user-friendly address rather than of a bag or a hash, and an
//! address is parsed a layer above this crate. Which alphabets an address may be written
//! in is an open question, recorded beside that parser; deciding it for a bag would fix
//! it in the wrong place.
//!
//! # How far the same claim carries to hex
//!
//! Not all the way, and the difference is worth naming rather than leaving to be
//! assumed. [`hex_decode`] refuses the leading `+` that the standard library's
//! `from_str_radix` accepts, which is what would otherwise make `+f` a second spelling
//! of `0f`. It does not refuse the other case, so `AB` and `ab` are one byte written two
//! ways, which is what the raw-address reader in this workspace already took. A caller
//! keying anything on the text of a hex string therefore lowers it first; for base64 no
//! such step exists to forget.

use crate::cell::error::CellError;

/// Writes bytes as standard-alphabet base64, padded to a whole number of quanta.
///
/// The alphabet is `A-Z`, `a-z`, `0-9`, `+` and `/`, and the output is the one form
/// [`base64_decode`] accepts, so the two round-trip in both directions.
///
/// # Examples
///
/// ```
/// use ton_net::cell::base64_encode;
///
/// assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
/// assert_eq!(base64_encode(b""), "");
/// ```
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // A quantum spells three bytes as four characters. A short final chunk spells
        // one byte as two characters and two bytes as three, and pads the rest, so the
        // count of characters that carry data is one more than the count of bytes.
        let (first, second, third, carried) = match chunk {
            [first, second, third] => (*first, *second, *third, 3),
            [first, second] => (*first, *second, 0, 2),
            [first] => (*first, 0, 0, 1),
            _ => continue,
        };
        let quantum = [
            digit(first >> 2),
            digit((first << 4) | (second >> 4)),
            digit((second << 2) | (third >> 6)),
            digit(third),
        ];
        for character in quantum.iter().take(carried + 1) {
            out.push(char::from(*character));
        }
        for _ in 0..3 - carried {
            out.push('=');
        }
    }
    out
}

/// Reads standard-alphabet base64, in its canonical form only.
///
/// The canonical form is what [`base64_encode`] writes: a whole number of four-character
/// quanta over `A-Z`, `a-z`, `0-9`, `+` and `/`, ending in at most two `=`, with no bit
/// set in the final character that no output byte carries. Every other spelling is
/// refused, including the URL-safe alphabet.
///
/// # Errors
///
/// Returns [`CellError::Encoding`] if the string is not that form.
///
/// # Examples
///
/// ```
/// use ton_net::cell::base64_decode;
///
/// assert_eq!(base64_decode("+/8=")?, vec![0xfb, 0xff]);
/// // The same bytes in the URL-safe alphabet, which is not this form.
/// assert!(base64_decode("-_8=").is_err());
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
pub fn base64_decode(text: &str) -> Result<Vec<u8>, CellError> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(CellError::Encoding(
            "base64 is not a whole number of quanta",
        ));
    }
    // Three `=` at the end would carry no character of data at all, and four would leave
    // an empty quantum that decodes to the nothing an empty string already spells.
    let padding = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if padding > 2 {
        return Err(CellError::Encoding("base64 pads a quantum away entirely"));
    }
    let body = bytes
        .get(..bytes.len() - padding)
        .ok_or(CellError::Encoding("base64 padding runs past its string"))?;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quantum in body.chunks(4) {
        // `=` is outside the alphabet, so a pad anywhere but the trailing run this
        // already cut away is refused by `sextet` rather than by a check of its own.
        match quantum {
            [first, second, third, fourth] => {
                let (first, second, third, fourth) = (
                    sextet(*first)?,
                    sextet(*second)?,
                    sextet(*third)?,
                    sextet(*fourth)?,
                );
                out.push((first << 2) | (second >> 4));
                out.push((second << 4) | (third >> 2));
                out.push((third << 6) | fourth);
            }
            [first, second, third] => {
                let (first, second, third) = (sextet(*first)?, sextet(*second)?, sextet(*third)?);
                if third & 0b11 != 0 {
                    return Err(CellError::Encoding("base64 sets a bit no byte carries"));
                }
                out.push((first << 2) | (second >> 4));
                out.push((second << 4) | (third >> 2));
            }
            [first, second] => {
                let (first, second) = (sextet(*first)?, sextet(*second)?);
                if second & 0b1111 != 0 {
                    return Err(CellError::Encoding("base64 sets a bit no byte carries"));
                }
                out.push((first << 2) | (second >> 4));
            }
            _ => {
                return Err(CellError::Encoding(
                    "base64 ends in a character that spells no byte",
                ))
            }
        }
    }
    Ok(out)
}

/// Writes bytes as lowercase hex, two characters for every byte.
///
/// # Examples
///
/// ```
/// use ton_net::cell::hex_encode;
///
/// assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
/// ```
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Reads hex into its bytes, in either case.
///
/// Every byte is two characters, so an odd-length string is refused, and the only
/// characters accepted are `0-9`, `a-f` and `A-F`. The standard library's
/// `from_str_radix` is deliberately not the reader here: it takes a leading `+`, which
/// would make `+f` a second spelling of `0f`.
///
/// # Errors
///
/// Returns [`CellError::Encoding`] if the length is odd or a character is not a hex
/// digit.
///
/// # Examples
///
/// ```
/// use ton_net::cell::hex_decode;
///
/// assert_eq!(hex_decode("000fff")?, vec![0x00, 0x0f, 0xff]);
/// assert!(hex_decode("+f").is_err());
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
pub fn hex_decode(text: &str) -> Result<Vec<u8>, CellError> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(CellError::Encoding("hex is not a whole number of bytes"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let [high, low] = pair else {
            return Err(CellError::Encoding("hex is not a whole number of bytes"));
        };
        out.push((nibble(*high)? << 4) | nibble(*low)?);
    }
    Ok(out)
}

/// The standard-alphabet character for the low six bits of `value`.
fn digit(value: u8) -> u8 {
    match value & 0b0011_1111 {
        sextet @ 0..=25 => b'A' + sextet,
        sextet @ 26..=51 => b'a' + sextet - 26,
        sextet @ 52..=61 => b'0' + sextet - 52,
        62 => b'+',
        _ => b'/',
    }
}

/// The six-bit value a standard-alphabet character stands for.
fn sextet(character: u8) -> Result<u8, CellError> {
    Ok(match character {
        b'A'..=b'Z' => character - b'A',
        b'a'..=b'z' => character - b'a' + 26,
        b'0'..=b'9' => character - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => {
            return Err(CellError::Encoding(
                "base64 holds a character outside its alphabet",
            ))
        }
    })
}

/// The four-bit value a hex digit stands for.
fn nibble(character: u8) -> Result<u8, CellError> {
    Ok(match character {
        b'0'..=b'9' => character - b'0',
        b'a'..=b'f' => character - b'a' + 10,
        b'A'..=b'F' => character - b'A' + 10,
        _ => return Err(CellError::Encoding("hex holds a character that is not one")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{parse_boc, Builder};

    /// A one-cell bag, and the hash of the cell it holds.
    fn bag_and_hash() -> (Vec<u8>, [u8; 32]) {
        let mut builder = Builder::new();
        builder.store_uint(0xab, 8).expect("a byte fits");
        let cell = builder.build().expect("a leaf forms");
        (cell.to_boc().expect("one cell serializes"), *cell.hash())
    }

    #[test]
    fn a_bag_and_a_hash_survive_both_spellings() {
        let (bag, hash) = bag_and_hash();

        let written = base64_encode(&bag);
        let read = base64_decode(&written).expect("what was written reads back");
        assert_eq!(read, bag);
        assert_eq!(
            parse_boc(&read).expect("and is still a bag")[0].hash(),
            &hash
        );

        let written = hex_encode(&hash);
        assert_eq!(written.len(), 64, "two characters for each of 32 bytes");
        assert_eq!(hex_decode(&written).expect("reads back"), hash);
    }

    #[test]
    fn base64_writes_the_padding_a_short_quantum_needs() {
        // One byte through five, so a full quantum, each short quantum, and a short one
        // after a full one are all written.
        assert_eq!(base64_encode(&[]), "");
        assert_eq!(base64_encode(&[0x01]), "AQ==");
        assert_eq!(base64_encode(&[0x01, 0x02]), "AQI=");
        assert_eq!(base64_encode(&[0x01, 0x02, 0x03]), "AQID");
        assert_eq!(base64_encode(&[0x01, 0x02, 0x03, 0x04]), "AQIDBA==");
        assert_eq!(base64_encode(&[0x01, 0x02, 0x03, 0x04, 0x05]), "AQIDBAU=");
    }

    #[test]
    fn base64_reaches_every_character_of_its_alphabet() {
        // 0x00 through 0x3f packed six bits at a time is the alphabet in order, which is
        // what catches an encoder whose table is right in the middle and wrong at an edge.
        let every: Vec<u8> = (0..64u8)
            .collect::<Vec<_>>()
            .chunks(4)
            .flat_map(|four| match four {
                [a, b, c, d] => vec![(a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d],
                _ => vec![],
            })
            .collect();
        let written = base64_encode(&every);
        assert_eq!(
            written,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        );
        assert_eq!(base64_decode(&written).expect("reads back"), every);
    }

    #[test]
    fn base64_refuses_a_length_that_is_not_a_whole_quantum() {
        // The cases that matter are the ones that would otherwise decode. A short
        // quantum carries its bytes whether or not the padding that fills it out is
        // written, so `AA` is `AA==` without its padding and `AAAAAA` is `AAAAAA==`
        // without its padding, and each would be a second spelling of bytes the padded
        // form already spells. `A` alone spells no byte at all.
        for text in ["A", "AA", "AAA", "AAAAA", "AAAAAA"] {
            assert!(
                base64_decode(text).is_err(),
                "`{text}` decoded despite its length"
            );
        }
        assert_eq!(base64_decode("AA==").expect("the padded form"), vec![0]);
        assert_eq!(base64_decode("AAA=").expect("the padded form"), vec![0; 2]);
    }

    #[test]
    fn base64_refuses_padding_that_carries_a_quantum_away() {
        // Without this, `====` is a second spelling of the empty string and `AAAA====`
        // a second spelling of `AAAA`, because the padding cuts the quantum off whole.
        assert!(base64_decode("")
            .expect("nothing spells nothing")
            .is_empty());
        assert!(base64_decode("====").is_err());
        assert!(base64_decode("AAAA====").is_err());
        assert_eq!(base64_decode("AAAA").expect("three zero bytes"), vec![0; 3]);
    }

    #[test]
    fn base64_refuses_the_url_safe_alphabet() {
        assert_eq!(
            base64_decode("+/8=").expect("the standard spelling"),
            vec![0xfb, 0xff]
        );
        assert!(base64_decode("-_8=").is_err(), "the URL-safe spelling");
        assert!(base64_decode("-/8=").is_err(), "one of each");
    }

    #[test]
    fn one_byte_has_one_base64_spelling() {
        // Every two-character quantum the alphabet can spell, enumerated. A quantum
        // carrying one byte has four bits left over, so 4,096 strings compete to spell
        // 256 values and only the 256 an encoder would write are taken.
        //
        // Four characters and two pads is the whole field rather than a sample of it:
        // an accepted string carries `len / 4 * 3 - padding` bytes, over a length that
        // is a multiple of four with at most two pads, and that count is one only at a
        // length of four with two pads.
        let mut accepted = 0usize;
        for high in 0..64u8 {
            for low in 0..64u8 {
                let text = format!("{}{}==", char::from(digit(high)), char::from(digit(low)));
                if let Ok(bytes) = base64_decode(&text) {
                    assert_eq!(bytes.len(), 1);
                    assert_eq!(
                        base64_encode(&bytes),
                        text,
                        "`{text}` is not what an encoder writes"
                    );
                    accepted += 1;
                }
            }
        }
        assert_eq!(
            accepted, 256,
            "one spelling for each of the 256 byte values"
        );
    }

    #[test]
    fn two_bytes_have_one_base64_spelling() {
        // The same over three-character quanta, where two bits are left over: 262,144
        // strings compete to spell 65,536 values, and by the same count of bytes a
        // length carries, four characters and one pad is the only shape that spells two.
        let mut accepted = 0usize;
        for high in 0..64u8 {
            for middle in 0..64u8 {
                for low in 0..64u8 {
                    let text = format!(
                        "{}{}{}=",
                        char::from(digit(high)),
                        char::from(digit(middle)),
                        char::from(digit(low))
                    );
                    if let Ok(bytes) = base64_decode(&text) {
                        assert_eq!(bytes.len(), 2);
                        assert_eq!(base64_encode(&bytes), text);
                        accepted += 1;
                    }
                }
            }
        }
        assert_eq!(accepted, 65_536, "one spelling for each two-byte value");
    }

    #[test]
    fn hex_refuses_a_leading_sign() {
        // `u8::from_str_radix("+f", 16)` answers 15, so a reader built on it spells one
        // byte two ways in the same two characters the even-length check waves through.
        assert_eq!(hex_decode("0f").expect("the hex spelling"), vec![0x0f]);
        assert!(hex_decode("+f").is_err());
        assert!(hex_decode("+f+f").is_err());
    }

    #[test]
    fn hex_refuses_an_odd_length_and_a_character_that_is_not_a_digit() {
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("000").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode(" f").is_err());
    }

    #[test]
    fn hex_reads_either_case_and_writes_one() {
        assert_eq!(hex_decode("AbCd").expect("mixed case"), vec![0xab, 0xcd]);
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(
            hex_encode(&[0x00, 0x0f]),
            "000f",
            "and pads each byte to two"
        );
    }
}
