// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The block header and the validator set, read from captured mainnet proofs.
//!
//! The fixtures are whole `liteServer.getBlockProof` answers, so a test reaches the
//! proofs the way the library will: out of a server's reply rather than out of a
//! hand-cut blob. Every forward link in one carries a proof of its source key block's
//! configuration and a proof of its destination's header. Most tests below read the
//! first link of a fixture and nothing turns on which; the one asserting a property of
//! every captured configuration reads every link of every fixture instead.
//!
//! Every expected validator set below was read from tonapi.io on 2026-07-21, at the same
//! masterchain sequence number, and is recorded here rather than recomputed. That is
//! what makes this a check: an implementation compared against itself proves only that
//! it is consistent.
//!
//! Two tests here are **constructed rather than captured**, and each says so at its own
//! head. They cover the preference for configuration parameter 35 over 34. Every cell
//! they use is mainnet's; the arrangement is this file's, because no capture of the
//! arrangement was available to take. Parameter 35 is absent from the configuration of
//! every key block captured here, and from the mainnet and testnet configurations read
//! on 2026-08-16. What a capture would additionally establish is that a real
//! configuration carrying the parameter decodes and verifies end to end, and nothing
//! offline reaches that.

use ton_net::cell::Builder;
use ton_net::cell::Cell;
use ton_net::cell::Dict;
use ton_net::cell::Lookup;
use ton_net::cell::UsageTree;
use ton_net::proof;
use ton_net::proof::ValidatorSet;
use ton_net::tl::{deserialize, lite};
use ton_net::tlb::BlockError;

/// The parameter holding the standing validator set.
const CURRENT_VALIDATORS: i32 = 34;

/// The parameter holding the temporary one, which answers wherever it is present.
const CURRENT_TEMP_VALIDATORS: i32 = 35;

/// Three forward links from the block the mainnet config pins, crossing one rotation.
const ORDINARY: &str = include_str!("fixtures/chain.hex");

/// The first of those three links, captured on its own.
const ORDINARY_ONE_LINK: &str = include_str!("fixtures/one-link-ordinary.hex");

/// One forward link across the block where mainnet changed its signed form.
const SIMPLEX: &str = include_str!("fixtures/one-link-simplex.hex");

/// Every capture this file reads, for the checks that hold over all of them.
const FIXTURES: [&str; 3] = [ORDINARY, ORDINARY_ONE_LINK, SIMPLEX];

/// How many forward links those captures hold between them.
const CAPTURED_LINKS: usize = 5;

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

/// Every forward link a fixture holds, in order.
fn links(text: &str) -> Vec<Link> {
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
    proof
        .steps
        .into_iter()
        .map(|step| match step {
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
        })
        .collect()
}

/// The first forward link a fixture holds.
fn link(text: &str) -> Link {
    links(text).into_iter().next().expect("at least one step")
}

fn unhex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("32 bytes")
}

/// The configuration dictionary the source key block of a link carries.
fn config_of(link: &Link) -> Dict {
    let block = proof::covered_block(&link.config_proof, &link.from.root_hash)
        .expect("the config proof roots at the key block");
    let config = block.config().expect("a key block carries a configuration");
    Dict::from_root(Some(config), 32).expect("a 32-bit dictionary")
}

/// The cell a configuration parameter sits behind, where the proof covers it.
fn param_cell(config: &Dict, index: i32) -> Cell {
    config
        .get(&index.to_be_bytes())
        .expect("the lookup runs")
        .found()
        .expect("the proof covers the parameter")
        .slice()
        .expect("the entry is a slice")
        .load_ref()
        .expect("a parameter sits behind a reference")
        .clone()
}

/// A configuration dictionary value: one reference to the parameter's own cell.
fn param_value(cell: Cell) -> Builder {
    let mut value = Builder::new();
    value.store_ref(cell).expect("one reference fits");
    value
}

/// Marks `cell` and everything below it, so a prune keeps the whole subtree.
///
/// [`UsageTree::mark_path`] keeps a cell reachable and stops at it, which is enough to
/// walk a dictionary to a parameter and not enough to read what the parameter holds: a
/// validator set's descriptor dictionary hangs below the parameter cell and prunes away
/// with everything else unmarked. A narrowing meant to leave one parameter readable has
/// to mark both, the path down and the subtree under.
fn mark_subtree(usage: &mut UsageTree, cell: &Cell) {
    usage.mark(cell);
    for child in cell.refs() {
        mark_subtree(usage, child);
    }
}

/// Reads the validator set the source key block of a link names.
fn set_of(link: &Link) -> ValidatorSet {
    let block = proof::covered_block(&link.config_proof, &link.from.root_hash)
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
            .find(&ton_net::proof::validators::short_id(&key))
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
        #[allow(
            clippy::cast_sign_loss,
            reason = "the wire carries this as int32; the domain counts it unsigned"
        )]
        let from_seqno = link.from.seqno as u32;
        assert_eq!(from_seqno, key_block);

        let header = proof::covered_block(&link.dest_proof, &link.to.root_hash)
            .expect("the destination proof roots at the destination")
            .header()
            .expect("it holds a header");

        // The header is proof-backed and the link's own fields are not, so these are
        // the checks that make a link's claims worth anything.
        #[allow(
            clippy::cast_sign_loss,
            reason = "the wire carries this as int32; the domain counts it unsigned"
        )]
        let to_seqno = link.to.seqno as u32;
        assert_eq!(header.seqno, to_seqno);
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
    let header = proof::covered_block(&link.dest_proof, &link.to.root_hash)
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
        proof::covered_block(&link.config_proof, &link.to.root_hash),
        Err(BlockError::ProofNotAnchored)
    ));
    assert!(matches!(
        proof::covered_block(&link.dest_proof, &link.from.root_hash),
        Err(BlockError::ProofNotAnchored)
    ));
}

#[test]
fn a_header_proof_does_not_answer_for_the_configuration() {
    // A destination proof covers the header and prunes the rest, so asking it for the
    // configuration must say the proof does not cover it. Reading a pruned branch as an
    // empty one is how a partial proof would otherwise pass for a complete answer.
    let link = link(ORDINARY);
    let block =
        proof::covered_block(&link.dest_proof, &link.to.root_hash).expect("the proof roots");
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
    let block = proof::covered_block(&link.config_proof, &link.from.root_hash).expect("it roots");
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
fn every_captured_configuration_shows_parameter_35_absent_rather_than_pruned() {
    // The set in force is parameter 35 where the configuration carries it and 34
    // otherwise, so reading 34 is licensed by a covered absence of 35 and by nothing
    // else. A server sending the smallest proof that answers the question covers the
    // walk to 35 exactly because it selected the set the same way, and every
    // configuration captured here shows that: 35 absent, not pruned.
    //
    // What this settles is a property of the captured bytes, not of the code. Deleting
    // the preference leaves it green; what would go red is `chain.rs`, which verifies
    // every link of the same captures against the set each configuration names. The
    // count is asserted so a capture added and not read here is caught rather than
    // quietly left outside the word every.
    let mut checked = 0;
    for text in FIXTURES {
        for link in links(text) {
            let config = config_of(&link);
            assert!(matches!(
                config
                    .get(&CURRENT_TEMP_VALIDATORS.to_be_bytes())
                    .expect("the lookup runs"),
                Lookup::Absent
            ));
            assert!(matches!(
                config
                    .get(&CURRENT_VALIDATORS.to_be_bytes())
                    .expect("the lookup runs"),
                Lookup::Found(_)
            ));
            checked += 1;
        }
    }
    assert_eq!(checked, CAPTURED_LINKS, "not every capture was read");
}

#[test]
fn parameter_35_answers_where_the_configuration_carries_it() {
    // **A constructed fixture.** Both parameter cells below are mainnet bytes, taken
    // from the two captured rounds, and so is the configuration dictionary they sit in.
    // What is constructed is the placement: no captured key block here carries 35, and
    // none was found to capture, so this arrangement of real cells is as close as an
    // offline test reaches. What it does not establish is that a mainnet configuration
    // carrying 35 decodes and verifies end to end, which only a capture would.
    let a = link(ORDINARY);
    let b = link(SIMPLEX);
    let round_b = config_of(&b);

    let mut edited = config_of(&a);
    edited
        .set(
            &CURRENT_TEMP_VALIDATORS.to_be_bytes(),
            &param_value(param_cell(&round_b, CURRENT_VALIDATORS)),
        )
        .expect("the parameter fits");

    // The two rounds are twelve million blocks apart and share no set, so answering
    // with round B's out of round A's own configuration can only be the preference
    // firing. Reading 34 would answer with round A's, which is the defect this pins.
    let read = ValidatorSet::from_config(edited.root().expect("an edited root"))
        .expect("the configuration holds a validator set");
    assert_eq!(read, set_of(&b));
    assert_ne!(read, set_of(&a));

    // And with 35 taken out again the same dictionary answers with 34, so the fallback
    // is a fallback rather than a second reading of the same parameter.
    assert!(edited
        .remove(&CURRENT_TEMP_VALIDATORS.to_be_bytes())
        .expect("the removal runs"));
    assert_eq!(
        ValidatorSet::from_config(edited.root().expect("a root")).expect("it reads"),
        set_of(&a)
    );
}

#[test]
fn a_pruned_parameter_35_is_refused_rather_than_read_as_an_absent_one() {
    // **A constructed fixture**, on the arrangement of real cells the test above
    // builds: a configuration carrying both parameters, proved down to the walk to 34
    // alone. That is what a server selecting the set by reading 34 and nothing else
    // would send, and against it the walk to 35 answers neither found nor absent.
    //
    // Nothing in such a proof rules out the 35 standing behind the pruned branch, so
    // reading 34 would be deriving a set the block never signed under, in silence. The
    // refusal names the proof rather than the configuration, which is the difference
    // between a server that answered a narrower question and a configuration that has
    // nothing in it.
    //
    // The narrowing has to be built rather than captured for a second reason on top of
    // the one above: in a captured configuration 34 and 35 are adjacent keys reached
    // through one edge, so covering 34 covers the absence of 35 as a side effect and no
    // real proof this tree holds can put a pruned branch on that walk.
    let a = link(ORDINARY);
    let b = link(SIMPLEX);
    let mut config = config_of(&a);
    config
        .set(
            &CURRENT_TEMP_VALIDATORS.to_be_bytes(),
            &param_value(param_cell(&config_of(&b), CURRENT_VALIDATORS)),
        )
        .expect("the parameter fits");
    let root = config.root().expect("an edited configuration has a root");

    // The whole of 34 is kept, not merely the walk to it. Marking the path alone leaves
    // the descriptor dictionary hanging under the parameter cell pruned, so 34 reads as
    // uncovered too and the refusal below arrives whichever branch produced it. The test
    // then passes with the preference deleted, which is the shape this narrowing avoids.
    let param_34 = param_cell(&config, CURRENT_VALIDATORS);
    let mut usage = UsageTree::new(root.clone());
    assert!(usage.mark_path(&param_34), "the walk to 34 is in the tree");
    mark_subtree(&mut usage, &param_34);
    let narrowed = Dict::from_root(Some(usage.prune().expect("the tree prunes")), 32)
        .expect("a 32-bit dictionary");

    assert!(matches!(
        narrowed
            .get(&CURRENT_TEMP_VALIDATORS.to_be_bytes())
            .expect("the lookup runs"),
        Lookup::Pruned
    ));
    assert!(matches!(
        ValidatorSet::from_config(narrowed.root().expect("a root")),
        Err(BlockError::NotCovered)
    ));

    // Parameter 34 survives the narrowing all the way down to its last descriptor, so it
    // reads: it answers with round A's set. That is what makes the refusal above the
    // preference declining an uncovered 35 rather than the pruning having taken 34 away
    // with it, and it is what a fall-through to 34 would have returned here instead.
    assert_eq!(
        ValidatorSet::from_cell(&param_cell(&narrowed, CURRENT_VALIDATORS))
            .expect("the narrowing kept the whole of 34"),
        set_of(&a)
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
        let read = proof::covered_block(&bytes, &link.from.root_hash)
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
            proof::covered_block(&link.config_proof[..cut], &link.from.root_hash).is_err(),
            "a proof cut to {cut} bytes was accepted"
        );
    }
}
