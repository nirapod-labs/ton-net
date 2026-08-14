// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A JSON form of an ordinary cell tree.
//!
//! A cell renders as its bit length, its data as hex, and its references in order, each
//! rendered the same way. The form round-trips: reading back what [`to_json`] wrote rebuilds
//! a cell with the same hash. It covers ordinary cells only, the ones a caller authors or
//! inspects; an exotic cell's meaning is the hashes it carries rather than data a JSON form
//! could hold, and it arrives from parsing rather than from JSON, so it is refused here.
//!
//! Gated behind the `json` feature.

use serde_json::{json, Value};

use super::{Cell, MAX_BITS};
use crate::builder::Builder;
use crate::codec::{hex_decode, hex_encode};
use crate::error::CellError;

/// Renders an ordinary cell tree as JSON.
///
/// The value is an object with the cell's `bits`, its `data` as a hex string, and its
/// `refs` as an array of the same, in order. [`from_json`] reads it back.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `cell` or any cell below it is exotic.
pub fn to_json(cell: &Cell) -> Result<Value, CellError> {
    if cell.is_exotic() {
        return Err(CellError::Malformed(
            "only an ordinary cell renders as JSON",
        ));
    }
    let refs = cell
        .refs()
        .iter()
        .map(to_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "bits": cell.bit_len(),
        "data": hex_encode(cell.data()),
        "refs": refs,
    }))
}

/// Rebuilds an ordinary cell tree from the JSON [`to_json`] produces.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if the value is missing a field, its data is not whole
/// bytes of hex, or its data is too short for its stated bit length, and whatever
/// [`Builder`] reports if the parts do not form a cell.
pub fn from_json(value: &Value) -> Result<Cell, CellError> {
    let bits = value
        .get("bits")
        .and_then(Value::as_u64)
        .ok_or(CellError::Malformed("cell json has no bit length"))?;
    let bits = u16::try_from(bits)
        .ok()
        .filter(|&bits| bits <= MAX_BITS)
        .ok_or(CellError::Malformed("cell json bit length is out of range"))?;
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or(CellError::Malformed("cell json has no data"))?;
    let data = unhex(data)?;
    if data.len() < usize::from(bits).div_ceil(8) {
        return Err(CellError::Malformed(
            "cell json data is shorter than its bit length",
        ));
    }
    let refs = value
        .get("refs")
        .and_then(Value::as_array)
        .ok_or(CellError::Malformed("cell json has no references"))?;

    let mut builder = Builder::new();
    for index in 0..bits {
        builder.store_bit(bit_at(&data, index))?;
    }
    for child in refs {
        builder.store_ref(from_json(child)?)?;
    }
    builder.build()
}

/// Reads a hex string into its bytes, under this form's own wording for why it failed.
///
/// The length is checked here and again inside [`hex_decode`] because the two failures
/// are worth telling apart in a JSON value: a caller who wrote an odd number of
/// characters made a different mistake from one who wrote a character that is not a hex
/// digit. Once the length is even the only failure left is the character, so the map
/// below loses nothing.
fn unhex(text: &str) -> Result<Vec<u8>, CellError> {
    if text.len() % 2 != 0 {
        return Err(CellError::Malformed("cell json data is not whole bytes"));
    }
    hex_decode(text).map_err(|_| CellError::Malformed("cell json data is not hex"))
}

/// The bit at `index` of `data`, most significant bit first, false past the end.
fn bit_at(data: &[u8], index: u16) -> bool {
    let index = usize::from(index);
    data.get(index / 8)
        .is_some_and(|byte| (byte >> (7 - (index % 8))) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_proof;

    /// A leaf cell holding one byte.
    fn leaf(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("a leaf forms")
    }

    #[test]
    fn an_ordinary_tree_round_trips_through_json() {
        // A root of three bits (a partial byte) over two children.
        let mut builder = Builder::new();
        builder.store_uint(0b101, 3).expect("three bits fit");
        builder.store_ref(leaf(0xcd)).expect("a reference fits");
        builder.store_ref(leaf(0xef)).expect("a reference fits");
        let root = builder.build().expect("the root forms");

        let value = to_json(&root).expect("renders");
        let rebuilt = from_json(&value).expect("reads back");
        assert_eq!(rebuilt.repr_hash(), root.repr_hash());
    }

    #[test]
    fn an_exotic_cell_does_not_render_as_json() {
        let proof = create_proof(&leaf(0xab)).expect("a proof builds");
        assert_eq!(
            to_json(&proof),
            Err(CellError::Malformed(
                "only an ordinary cell renders as JSON"
            )),
        );
    }

    #[test]
    fn a_value_missing_a_field_is_refused() {
        assert_eq!(
            from_json(&json!({ "data": "ab", "refs": [] })),
            Err(CellError::Malformed("cell json has no bit length")),
        );
        assert_eq!(
            from_json(&json!({ "bits": 8, "refs": [] })),
            Err(CellError::Malformed("cell json has no data")),
        );
    }

    #[test]
    fn data_shorter_than_its_bit_length_is_refused() {
        // Sixteen bits claimed, one byte given.
        assert_eq!(
            from_json(&json!({ "bits": 16, "data": "ab", "refs": [] })),
            Err(CellError::Malformed(
                "cell json data is shorter than its bit length"
            )),
        );
    }

    #[test]
    fn data_that_is_not_hex_is_refused() {
        assert_eq!(
            from_json(&json!({ "bits": 8, "data": "zz", "refs": [] })),
            Err(CellError::Malformed("cell json data is not hex")),
        );
    }

    #[test]
    fn data_with_a_leading_sign_is_refused() {
        // `u8::from_str_radix` takes a leading `+`, so a reader built on it answers 15
        // for `+f` as well as for `0f`. Both are two characters, so the even-length check
        // waves them both through, and a cell gains a second spelling for every byte
        // below 0x10 it holds: four for the two below. Case is a second spelling too and
        // is not refused, so this closes one family and does not make the form canonical.
        let canonical = from_json(&json!({ "bits": 16, "data": "0f0f", "refs": [] }))
            .expect("the hex spelling builds");
        for spelling in ["+f0f", "0f+f", "+f+f"] {
            assert_eq!(
                from_json(&json!({ "bits": 16, "data": spelling, "refs": [] })),
                Err(CellError::Malformed("cell json data is not hex")),
                "`{spelling}` was read as hex",
            );
        }
        assert_eq!(canonical.data(), &[0x0f, 0x0f]);
    }
}
