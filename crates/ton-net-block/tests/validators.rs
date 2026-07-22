// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The block header and the validator set, read from captured mainnet proofs.
//!
//! The fixtures are whole `liteServer.getBlockProof` answers, each one forward link, so
//! a test reaches the proofs the way the library will: out of a server's reply rather
//! than out of a hand-cut blob. Each link carries a proof of its source key block's
//! configuration and a proof of its destination's header.
//!
//! Every expected validator set below was read from tonapi.io on 2026-07-21, at the same
//! masterchain sequence number, and is recorded here rather than recomputed. That is
//! what makes this a check: an implementation compared against itself proves only that
//! it is consistent.

use ton_net_block::{Block, BlockError, Lookup, ValidatorSet};
use ton_net_cell::Dict;
use ton_net_tl::{deserialize, lite};

/// One forward link from the block the mainnet config pins.
const ORDINARY: &str = include_str!("fixtures/chain.hex");

/// One forward link across the block where mainnet changed its signed form.
const SIMPLEX: &str = include_str!("fixtures/one-link-simplex.hex");

/// The round key block 46894135 names, as tonapi.io reports it.
///
/// `WEIGHT` is the sum over the first `MAIN` entries of the list, not the figure the
/// parameter declares: that one counts every validator in every shard and comes to
/// 1152921504606846779 over all 398.
mod round_a {
    pub const KEY_BLOCK: u32 = 46_894_135;
    pub const UTIME_SINCE: u32 = 1_744_785_160;
    pub const UTIME_UNTIL: u32 = 1_744_850_696;
    pub const TOTAL: u16 = 398;
    pub const MAIN: u16 = 100;
    pub const WEIGHT: u64 = 375_072_338_837_935_535;
    /// The first entry of the list, and what it weighs.
    pub const FIRST_KEY: &str = "5dbb663992f0224db56f5106dad8a2d1d8f2f296b75d210abd765c661a4d367e";
    pub const FIRST_WEIGHT: u64 = 4_656_190_297_133_788;
}

/// The round key block 59238081 names, as tonapi.io reports it. Its declared weight is
/// 1152921504606846789 over all 368.
mod round_b {
    pub const KEY_BLOCK: u32 = 59_238_081;
    pub const UTIME_SINCE: u32 = 1_775_718_152;
    pub const UTIME_UNTIL: u32 = 1_775_783_688;
    pub const TOTAL: u16 = 368;
    pub const MAIN: u16 = 100;
    pub const WEIGHT: u64 = 474_460_508_260_789_386;
    pub const FIRST_KEY: &str = "9b1accae6017593024e7e558c6bc99e23856dcca9a91e0be81e7fca8b30704d6";
    pub const FIRST_WEIGHT: u64 = 5_698_467_865_837_903;
}

/// The one forward link a fixture holds, in the shape these tests read it.
struct Link {
    from: lite::BlockIdExt,
    to: lite::BlockIdExt,
    to_key_block: bool,
    dest_proof: Vec<u8>,
    config_proof: Vec<u8>,
}

fn link(text: &str) -> Link {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();

    let proof: lite::PartialBlockProof = deserialize(&bytes).expect("the fixture decodes");
    match proof.steps.into_iter().next().expect("one step") {
        lite::BlockLink::Forward {
            from,
            to,
            to_key_block,
            dest_proof,
            config_proof,
            ..
        } => Link {
            from,
            to,
            to_key_block,
            dest_proof,
            config_proof,
        },
        other => panic!("expected a forward link, got {other:?}"),
    }
}

fn unhex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("32 bytes")
}

/// Reads the validator set the source key block of a link names.
fn set_of(link: &Link) -> ValidatorSet {
    let block = Block::from_proof(&link.config_proof, &link.from.root_hash)
        .expect("the config proof roots at the key block");
    ValidatorSet::from_config(&block.config().expect("a key block carries a configuration"))
        .expect("the configuration holds a validator set")
}

#[test]
fn a_key_block_names_the_set_a_second_source_reports() {
    for (text, since, until, total, main, weight, first_key, first_weight) in [
        (
            ORDINARY,
            round_a::UTIME_SINCE,
            round_a::UTIME_UNTIL,
            round_a::TOTAL,
            round_a::MAIN,
            round_a::WEIGHT,
            round_a::FIRST_KEY,
            round_a::FIRST_WEIGHT,
        ),
        (
            SIMPLEX,
            round_b::UTIME_SINCE,
            round_b::UTIME_UNTIL,
            round_b::TOTAL,
            round_b::MAIN,
            round_b::WEIGHT,
            round_b::FIRST_KEY,
            round_b::FIRST_WEIGHT,
        ),
    ] {
        let set = set_of(&link(text));

        assert_eq!(set.utime_since, since);
        assert_eq!(set.utime_until, until);
        assert_eq!(set.total, total);
        assert_eq!(set.main, main);

        // The subset that may sign, and its weight, are the two answers a signature
        // check needs, and a wrong head-of-list rule would move both.
        assert_eq!(set.len(), main as usize);
        assert_eq!(set.total_weight(), weight);

        // Finding a validator by the short id a signature would name it with exercises
        // the whole path: the key came out of the dictionary and the id was hashed from
        // it, so a match means both are right.
        let key = unhex32(first_key);
        let found = set
            .find(&ton_net_block::validators::short_id(&key))
            .expect("the reported validator is in the set");
        assert_eq!(found.public_key, key);
        assert_eq!(found.weight, first_weight);

        // A signer from some other round is not in the set, and is not an error either.
        // Refusing a whole set over one stray signature would let any peer stall a sync
        // by adding one.
        assert!(set.find(&[0x99; 32]).is_none());

        // What the set is iterated as has to weigh what the threshold divides by, or
        // the two answers a signature check needs come from different sets.
        assert_eq!(set.iter().count(), set.len());
        assert_eq!(
            set.iter().map(|v| v.weight).sum::<u64>(),
            set.total_weight()
        );
    }
}

#[test]
fn the_two_rounds_are_different_sets() {
    // Two rounds twelve million blocks apart share no validator with the same weight.
    // Asserting that keeps the test above from passing on a set read from the wrong
    // block, which is the way a fixture mix-up would otherwise hide.
    let a = set_of(&link(ORDINARY));
    let b = set_of(&link(SIMPLEX));
    assert_ne!(a, b);
    assert_ne!(a.total_weight(), b.total_weight());

    let shared = a
        .iter()
        .filter(|v| b.iter().any(|w| w.public_key == v.public_key))
        .count();
    assert!(
        shared < a.len(),
        "the two rounds have the same {shared} validators"
    );
}

#[test]
fn a_link_header_says_what_the_link_claims() {
    for (text, key_block) in [
        (ORDINARY, round_a::KEY_BLOCK),
        (SIMPLEX, round_b::KEY_BLOCK),
    ] {
        let link = link(text);
        assert_eq!(link.from.seqno as u32, key_block);

        let header = Block::from_proof(&link.dest_proof, &link.to.root_hash)
            .expect("the destination proof roots at the destination")
            .header()
            .expect("it holds a header");

        // The header is proof-backed and the link's own fields are not, so these are
        // the checks that make a link's claims worth anything.
        assert_eq!(header.seqno, link.to.seqno as u32);
        assert_eq!(header.workchain, link.to.workchain);
        assert_eq!(header.shard, link.to.shard);
        assert_eq!(header.key_block, link.to_key_block);
        assert_eq!(header.workchain, -1);
        assert_eq!(header.shard, 0x8000_0000_0000_0000);

        // Each fixture is a link to the very next key block, so the destination names
        // the source as the key block before it. That is the destination's own account
        // of where it sits, and it agrees with the route the server chose.
        assert_eq!(header.prev_key_block_seqno, key_block);
    }
}

#[test]
fn a_rotation_block_is_stamped_past_its_own_signing_window() {
    // The set that signs a rotation's first block runs out one second before that block
    // is generated. Requiring a signed block's time to fall inside the signing set's
    // window would therefore refuse the first link of every rotation, which is why no
    // such check exists. This pins the fact rather than the absence of the check.
    let link = link(ORDINARY);
    let set = set_of(&link);
    let header = Block::from_proof(&link.dest_proof, &link.to.root_hash)
        .expect("the proof roots")
        .header()
        .expect("it holds a header");

    assert!(header.gen_utime > set.utime_until);
    assert_eq!(header.gen_utime, set.utime_until + 1);
}

#[test]
fn a_proof_for_another_block_is_refused() {
    let link = link(ORDINARY);
    assert!(matches!(
        Block::from_proof(&link.config_proof, &link.to.root_hash),
        Err(BlockError::ProofNotAnchored)
    ));
    assert!(matches!(
        Block::from_proof(&link.dest_proof, &link.from.root_hash),
        Err(BlockError::ProofNotAnchored)
    ));
}

#[test]
fn a_header_proof_does_not_answer_for_the_configuration() {
    // A destination proof covers the header and prunes the rest, so asking it for the
    // configuration must say the proof does not cover it. Reading a pruned branch as an
    // empty one is how a partial proof would otherwise pass for a complete answer.
    let link = link(ORDINARY);
    let block = Block::from_proof(&link.dest_proof, &link.to.root_hash).expect("the proof roots");
    assert!(matches!(block.config(), Err(BlockError::NotCovered)));

    // The destination is itself a key block, so this is not the header saying no. The
    // proof simply does not carry the answer, and that is a different fact.
    assert!(block.header().expect("it holds a header").key_block);
}

#[test]
fn a_config_proof_covers_only_the_parameter_it_answers_for() {
    // Parameter 32 holds the round before 34's and would decode as a validator set just
    // as well, but a server sends the smallest proof that answers the question, so only
    // the path to 34 survives. Reading a pruned branch as an absent one is how a minimal
    // proof would otherwise pass for a configuration that simply has nothing in it.
    const PREVIOUS_VALIDATORS: i32 = 32;
    const CURRENT_VALIDATORS: i32 = 34;

    let link = link(ORDINARY);
    let block = Block::from_proof(&link.config_proof, &link.from.root_hash).expect("it roots");
    let config = block.config().expect("a key block carries a configuration");

    let params = Dict::from_root(Some(config), 32).expect("a 32-bit dictionary");
    assert!(matches!(
        params
            .get(&PREVIOUS_VALIDATORS.to_be_bytes())
            .expect("the lookup runs"),
        Lookup::Pruned
    ));

    let entry = params
        .get(&CURRENT_VALIDATORS.to_be_bytes())
        .expect("the lookup runs")
        .found()
        .expect("the proof covers the parameter it was sent for");
    let param = entry
        .slice()
        .expect("the entry is a slice")
        .load_ref()
        .expect("a parameter sits behind a reference")
        .clone();

    // Reading the parameter cell directly gives the same set as walking to it, which is
    // what makes the two entry points one behaviour rather than two.
    assert_eq!(
        ValidatorSet::from_cell(&param).expect("it is a validator set"),
        set_of(&link)
    );
}

#[test]
fn a_flipped_byte_anywhere_in_a_proof_is_refused() {
    // A proof carries the hash of the tree it stands for and that hash is recomputed, so
    // no single byte of it can be changed and still be read. Sampling rather than
    // sweeping keeps the test fast; the stride is fixed so the cases never move.
    let link = link(ORDINARY);
    let mut refused = 0;
    for at in (0..link.config_proof.len()).step_by(211) {
        let mut bytes = link.config_proof.clone();
        bytes[at] ^= 0x01;
        let read = Block::from_proof(&bytes, &link.from.root_hash)
            .and_then(|block| block.config())
            .and_then(|config| ValidatorSet::from_config(&config));
        assert!(read.is_err(), "a proof with byte {at} flipped was accepted");
        refused += 1;
    }
    assert!(refused > 100, "only {refused} positions were tried");
}

#[test]
fn a_truncated_proof_is_refused_rather_than_read() {
    let link = link(ORDINARY);
    for cut in [0, 1, 64, link.config_proof.len() / 2] {
        assert!(
            Block::from_proof(&link.config_proof[..cut], &link.from.root_hash).is_err(),
            "a proof cut to {cut} bytes was accepted"
        );
    }
}
