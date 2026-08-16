// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What parse options are allowed to change, and what they are not.
//!
//! `NET-ADR-012` puts two properties on this work and they pull against each other. The
//! default has to be today's behaviour exactly, admitting every bag the crate admitted
//! before and refusing every one it refused. And an option has to reach far enough to
//! refuse something, or the whole surface is a value nothing reads.
//!
//! A test for the first alone passes on a crate that ignores its options. A test for the
//! second alone passes on a crate whose default has quietly moved. Both are here, and the
//! second is written so that deleting the option's one use site fails it.
//!
//! The third property is the one a caller's safety rests on: a bag comes from a liteserver
//! and the ceiling in front of it is the reason a declared count cannot be believed. The
//! bound is applied where the header is read, and `read_header` has three non-test call
//! sites, one for each way in: `parse_boc_with`, `BocView::open_with` and
//! `LazyBoc::open_with`. So what is tested is that those three refuse the same bytes, rather
//! than that each of them refuses something. Dropping the ceiling from the view door or the
//! lazy door is caught here and nowhere else; dropping it from the parse door is caught here
//! and by the second property too, since that one reads through the same call.

use ton_net::cell::{
    parse_boc, parse_boc_with, BocView, Cell, CellError, LazyBoc, ParseOptions, MAX_CELLS,
};

const PROOF_HEX: &str = include_str!("../fixtures/account-proof.hex");

/// The captured mainnet basechain block, the large bag of the two.
const BLOCK_HEX: &str = include_str!("../fixtures/block-basechain.hex");

/// Decodes a hex-dump fixture, skipping the comment lines that record where it came from.
fn unhex(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("the fixture is hex"))
        .collect()
}

/// The generator and seed the wave parity gate uses in `src/boc/parse.rs`, so the bags below
/// are that corpus rather than a second population with its own coverage question. That is
/// what lets the counts here be reconciled against its own further down.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the result is < bound as u64, and bound was widened losslessly into that u64"
        )]
        let result = (self.next() % bound as u64) as usize;
        result
    }
}

/// A parse's outcome in a form two runs can be compared by.
///
/// The cells are reduced to their representation hashes rather than compared as values,
/// because that hash is the identity the format defines a cell by: it covers the data, the
/// references, the kind and the level mask, so two runs agreeing on it built the same graph
/// short of a SHA-256 collision.
///
/// The error is carried rather than discarded because a bag the two calls refuse differently
/// is the divergence this file exists to catch, and a comparison that kept only the
/// successes would be an agreement about the bags that were never in question.
type Outcome = Result<Vec<[u8; 32]>, CellError>;

fn outcome(result: Result<Vec<Cell>, CellError>) -> Outcome {
    result.map(|roots| roots.iter().map(|root| *root.repr_hash()).collect())
}

#[test]
fn the_default_options_admit_and_refuse_exactly_what_no_options_do() {
    // The gate `NET-ADR-012` names, run over corrupted bytes rather than over bags that
    // parse. A bag that reads cleanly agrees under any pair of doors that both work at all,
    // so it cannot tell a default that has moved from one that has not. What can are the
    // bags that fail, and the comparison includes which error they failed with.
    //
    // The assertion below is made before the comparison, and is load-bearing rather than
    // decorative. Both sides below read the same default, so a default that had quietly
    // moved would still make them agree, and every line after this one would pass on a
    // crate whose bounds had changed. This is the line that says which figure it is.
    assert_eq!(
        ParseOptions::default().max_cells,
        MAX_CELLS,
        "the default parse is no longer the crate's own bound"
    );

    let proof = unhex(PROOF_HEX);
    let mut rng = Rng(0x1D8E_4A2B_7C36_F591);
    let mut admitted = 0usize;
    let mut refused = 0usize;

    for _ in 0..4_000 {
        let mut bytes = proof.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }

        let plain = outcome(parse_boc(&bytes));
        let defaulted = outcome(parse_boc_with(&bytes, &ParseOptions::default()));
        assert_eq!(
            plain, defaulted,
            "a bag read under the default options differed from the same bag read without them"
        );

        if plain.is_ok() {
            admitted += 1;
        } else {
            refused += 1;
        }
    }

    // Without these the test could pass having compared four thousand bags that all failed
    // in the header, which is one line of agreement and not the gate. Pinned as equalities
    // rather than bounds, so a corpus that stopped reaching the cells would fail here
    // rather than quietly certify less than it used to.
    //
    // The split is the same corpus the wave parity gate counts, seen from the other end,
    // and the two account for each other exactly: that gate reports 3,225 bags reaching the
    // finalizing pass and 54 refused inside it, so 775 fail ahead of the pass and 3,171 come
    // all the way through. 775 and 54 are the 829 refused here.
    assert_eq!(
        admitted, 3_171,
        "the corpus admitted a different set of bags"
    );
    assert_eq!(refused, 829, "the corpus refused a different set of bags");

    // The two captured fixtures, which the corpus above never reads unmutated.
    for hex in [PROOF_HEX, BLOCK_HEX] {
        let bytes = unhex(hex);
        assert_eq!(
            outcome(parse_boc(&bytes)),
            outcome(parse_boc_with(&bytes, &ParseOptions::default())),
            "a captured mainnet bag read differently under the default options"
        );
    }
}

#[test]
fn a_lowered_ceiling_refuses_a_bag_the_default_admits() {
    // What says the option is read at all. The proof is 45 cells: the default takes it, a
    // ceiling one under its count does not, and the refusal names the caller's figure
    // rather than the crate's, so a ceiling that was accepted and then ignored would fail
    // here on the limit even if it failed on nothing else.
    let proof = unhex(PROOF_HEX);
    let cells = BocView::open(&proof)
        .expect("the fixture opens")
        .cell_count();
    assert_eq!(cells, 45, "the captured proof changed shape");

    assert!(parse_boc(&proof).is_ok(), "the default admits the fixture");
    assert_eq!(
        parse_boc_with(&proof, &ParseOptions::default().with_max_cells(cells - 1)),
        Err(CellError::TooManyCells { limit: cells - 1 }),
        "a ceiling under the bag's own count did not refuse it"
    );
    assert!(
        parse_boc_with(&proof, &ParseOptions::default().with_max_cells(cells)).is_ok(),
        "a ceiling at the bag's own count refused it"
    );
}

#[test]
fn every_door_into_a_bag_refuses_the_same_bytes_at_the_same_ceiling() {
    // `NET-ADR-009` says a bound is defined once and cannot hold on one path and lapse on
    // another. There are three ways into a bag and each would be a place for the ceiling to
    // go missing, so what is asserted is that all three agree, not that each refuses
    // something. Removing it from the view or the lazy door fails this and nothing else;
    // removing it from the parse door fails the lowered-ceiling case as well, because that
    // case reads through the same call.
    let proof = unhex(PROOF_HEX);
    let tight = ParseOptions::default().with_max_cells(10);
    let loose = ParseOptions::default();

    let refusal = Some(CellError::TooManyCells { limit: 10 });
    assert_eq!(
        parse_boc_with(&proof, &tight).err(),
        refusal,
        "the parsing door admitted a bag over the ceiling"
    );
    assert_eq!(
        BocView::open_with(&proof, &tight).err(),
        refusal,
        "the view door admitted a bag over the ceiling"
    );
    assert_eq!(
        LazyBoc::open_with(&proof, &tight).err(),
        refusal,
        "the lazy door admitted a bag over the ceiling"
    );

    // The other direction, so the test is not passing because all three refuse everything.
    assert!(parse_boc_with(&proof, &loose).is_ok());
    assert!(BocView::open_with(&proof, &loose).is_ok());
    assert!(LazyBoc::open_with(&proof, &loose).is_ok());
}

#[test]
fn no_options_value_reachable_from_outside_widens_what_a_parse_takes() {
    // The safety property, and the reason the field can be public at all. `max_cells` is
    // written here both ways a caller has: through the setter, and by assigning the field,
    // which is the route that bypasses any check the setter carries.
    let asked = ParseOptions::default().with_max_cells(usize::MAX);
    assert_eq!(
        asked.max_cells, MAX_CELLS,
        "asking for more than the crate allows returned more than the crate allows"
    );

    let mut written = ParseOptions::default();
    written.max_cells = usize::MAX;

    // A bag whose header declares more cells than the crate admits, refused before
    // anything is allocated for the count. Building one is cheaper than it looks: the
    // refusal happens on the declared count, so the bag need not carry the cells. Written
    // with neither an index nor a checksum, so nothing is checked ahead of the count that
    // would refuse these bytes for some other reason and hide what is being asked.
    let over = MAX_CELLS + 1;
    let mut bag = vec![0xb5, 0xee, 0x9c, 0x72, 0x04, 0x04];
    bag.extend_from_slice(&u32::try_from(over).expect("fits").to_be_bytes());
    bag.extend_from_slice(&1u32.to_be_bytes());
    bag.extend_from_slice(&0u32.to_be_bytes());
    bag.extend_from_slice(&0u32.to_be_bytes());

    for options in [&written, &asked, &ParseOptions::default()] {
        assert_eq!(
            parse_boc_with(&bag, options),
            Err(CellError::TooManyCells { limit: MAX_CELLS }),
            "a declared count over the crate's ceiling was admitted"
        );
    }
}

#[test]
fn tightening_twice_keeps_the_stricter_figure_whichever_order_it_is_asked_in() {
    // The property that makes the setter safe to call from more than one place, which is
    // how a caller composing a policy out of parts would reach it.
    let down_then_up = ParseOptions::default()
        .with_max_cells(10)
        .with_max_cells(500);
    let up_then_down = ParseOptions::default()
        .with_max_cells(500)
        .with_max_cells(10);
    assert_eq!(down_then_up.max_cells, 10);
    assert_eq!(up_then_down.max_cells, 10);
    assert_eq!(down_then_up, up_then_down);
}
