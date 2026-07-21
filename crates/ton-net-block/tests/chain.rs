// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A real mainnet proof chain, verified end to end, and the ways it can be broken.
//!
//! The fixture is a whole `liteServer.getBlockProof` answer: three forward links from
//! the block the mainnet config pins, crossing one validator-set rotation. Verifying it
//! exercises everything at once, since a link is checked against the set the previous
//! key block named and the rotation means that set is genuinely rechosen part way
//! through.
//!
//! The tamper cases below are built by decoding the answer, changing one thing, and
//! verifying again. Each asserts which error came back, not merely that one did: a
//! chain that fails for the wrong reason is a chain whose checks are not doing what
//! they claim.

use ton_net_block::{verify_chain, BlockError};
use ton_net_tl::deserialize;
use ton_net_tl::lite::{BlockIdExt, BlockLink, PartialBlockProof, SignatureSet};

/// Three forward links from masterchain 46894135 to 46920655.
const CHAIN: &str = include_str!("fixtures/chain.hex");

/// One forward link whose signatures are in the Simplex form.
const SIMPLEX: &str = include_str!("fixtures/one-link-simplex.hex");

fn decode(text: &str) -> PartialBlockProof {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    deserialize(&bytes).expect("the fixture decodes")
}

fn chain() -> PartialBlockProof {
    decode(CHAIN)
}

/// The block the fixture starts from, which is the anchor a client would hold.
fn anchor(proof: &PartialBlockProof) -> BlockIdExt {
    proof.from.clone()
}

/// Runs a tamper case: change the chain, verify, and hand back what happened.
fn tampered(change: impl FnOnce(&mut PartialBlockProof)) -> BlockError {
    let mut proof = chain();
    let anchor = anchor(&proof);
    change(&mut proof);
    verify_chain(&anchor, &proof).expect_err("a tampered chain verified")
}

/// The parts of a forward link, for a case that needs to reach inside one.
macro_rules! forward {
    ($step:expr) => {
        match $step {
            BlockLink::Forward {
                to_key_block,
                from,
                to,
                dest_proof,
                config_proof,
                signatures,
            } => (to_key_block, from, to, dest_proof, config_proof, signatures),
            other => panic!("expected a forward link, got {other:?}"),
        }
    };
}

#[test]
fn a_real_chain_verifies_end_to_end() {
    let proof = chain();
    let anchor = anchor(&proof);
    assert_eq!(proof.steps.len(), 3);
    assert!(proof.complete);

    let proven = verify_chain(&anchor, &proof).expect("the captured chain verifies");
    assert_eq!(proven.id, proof.to);
    assert_eq!(proven.id.seqno, 46_920_655);
    assert!(
        proven.key_block,
        "a chain ends at a block it can continue from"
    );
    assert!(proven.gen_utime > 1_744_000_000);
}

#[test]
fn a_chain_in_the_simplex_form_verifies() {
    // The older form signs a block identity outright. This one signs a vote naming a
    // candidate, so it proves the block only once the candidate is read and required to
    // be the block the link claims.
    let proof = decode(SIMPLEX);
    let anchor = anchor(&proof);
    let (.., signatures) = forward!(&proof.steps[0]);
    assert!(matches!(signatures, SignatureSet::Simplex { .. }));

    let proven = verify_chain(&anchor, &proof).expect("the simplex link verifies");
    assert_eq!(proven.id.seqno, 59_379_986);
}

#[test]
fn the_chain_crosses_a_validator_set_rotation() {
    // Without a rotation the set is read once and reused, and a test would say nothing
    // about whether the set is rechosen per link. Reading the set each link names and
    // requiring them to differ is what makes the end-to-end test above mean something.
    use ton_net_block::{Block, ValidatorSet};

    let proof = chain();
    let mut rounds = Vec::new();
    for step in &proof.steps {
        let (_, from, _, _, config_proof, _) = forward!(step);
        let block = Block::from_proof(config_proof, &from.root_hash).expect("it roots");
        let set = ValidatorSet::from_config(&block.config().expect("a key block")).expect("a set");
        rounds.push(set.utime_since);
    }
    let rotations = rounds.windows(2).filter(|pair| pair[0] != pair[1]).count();
    assert_eq!(rotations, 1, "rounds were {rounds:?}");
}

#[test]
fn a_chain_from_a_block_it_does_not_start_at_is_refused() {
    let proof = chain();
    let mut elsewhere = anchor(&proof);
    elsewhere.seqno += 1;
    assert_eq!(
        verify_chain(&elsewhere, &proof).unwrap_err(),
        BlockError::ChainBroken("starts at a block other than the one it was asked about")
    );
}

#[test]
fn a_removed_link_is_refused() {
    assert_eq!(
        tampered(|proof| {
            proof.steps.remove(1);
        }),
        BlockError::ChainBroken("has a link that does not start where the last one ended")
    );
}

#[test]
fn transposed_links_are_refused() {
    assert_eq!(
        tampered(|proof| proof.steps.swap(0, 1)),
        BlockError::ChainBroken("has a link that does not start where the last one ended")
    );
}

#[test]
fn a_chain_that_stops_short_of_where_it_says_is_refused() {
    assert_eq!(
        tampered(|proof| {
            proof.steps.truncate(2);
        }),
        BlockError::ChainBroken("ends somewhere other than it says")
    );
}

#[test]
fn a_link_running_backwards_is_refused() {
    assert_eq!(
        tampered(|proof| {
            let (_, from, to, ..) = forward!(&mut proof.steps[0]);
            std::mem::swap(from, to);
        }),
        // A reversed link starts at the wrong end, so the rule about connecting to the
        // previous step catches it first. The direction rule below is what catches a
        // link that connects correctly and still does not move forward.
        BlockError::ChainBroken("has a link that does not start where the last one ended")
    );

    let mut proof = chain();
    let anchor = anchor(&proof);
    {
        let (_, from, to, ..) = forward!(&mut proof.steps[0]);
        to.seqno = from.seqno;
    }
    assert_eq!(
        verify_chain(&anchor, &proof).unwrap_err(),
        BlockError::ChainBroken("has a forward link that does not move forward")
    );
}

#[test]
fn a_backward_link_is_refused_by_name() {
    assert_eq!(
        tampered(|proof| {
            let original = proof.steps[0].clone();
            let (to_key_block, from, to, dest_proof, _, _) = forward!(&original);
            proof.steps[0] = BlockLink::Back {
                to_key_block: *to_key_block,
                from: from.clone(),
                to: to.clone(),
                dest_proof: dest_proof.clone(),
                proof: Vec::new(),
                state_proof: Vec::new(),
            };
        }),
        BlockError::BackwardLink
    );
}

#[test]
fn an_inverted_key_block_flag_is_refused() {
    assert_eq!(
        tampered(|proof| {
            let (to_key_block, ..) = forward!(&mut proof.steps[0]);
            *to_key_block = !*to_key_block;
        }),
        BlockError::ChainBroken("has a destination that is not the kind of block the link says")
    );
}

#[test]
fn a_link_out_of_the_masterchain_is_refused() {
    assert_eq!(
        tampered(|proof| {
            let (_, _, to, ..) = forward!(&mut proof.steps[0]);
            to.workchain = 0;
        }),
        BlockError::ChainBroken("has a link outside the masterchain")
    );
}

#[test]
fn a_changed_file_hash_is_refused() {
    // This is the whole reason a destination is believed only after its signatures
    // check. The file hash is a hash of the serialized block file, so no Merkle proof
    // covers it and the header proof still roots perfectly. Only the signatures, which
    // cover the two hashes together, notice.
    let error = tampered(|proof| {
        let (_, _, to, ..) = forward!(&mut proof.steps[0]);
        to.file_hash[0] ^= 0x01;
    });
    assert!(
        matches!(error, BlockError::NotEnoughWeight { carried: 0, .. }),
        "expected no weight at all, got {error}"
    );
}

#[test]
fn a_changed_root_hash_is_refused() {
    assert_eq!(
        tampered(|proof| {
            let (_, _, to, ..) = forward!(&mut proof.steps[0]);
            to.root_hash[0] ^= 0x01;
        }),
        BlockError::ProofNotAnchored
    );
}

#[test]
fn an_altered_configuration_proof_is_refused() {
    // A weight lives inside the configuration proof, so changing one changes the tree
    // the proof stands for and the recomputed hash stops matching the one it carries.
    let error = tampered(|proof| {
        let (_, _, _, _, config_proof, _) = forward!(&mut proof.steps[0]);
        let at = config_proof.len() / 2;
        config_proof[at] ^= 0x01;
    });
    assert!(
        matches!(
            error,
            BlockError::ProofInconsistent | BlockError::Cell(_) | BlockError::NotCovered
        ),
        "expected the proof to stop checking out, got {error}"
    );
}

#[test]
fn signatures_moved_to_another_link_are_refused() {
    assert!(matches!(
        tampered(|proof| {
            let original = proof.steps[0].clone();
            let (.., borrowed) = forward!(&original);
            let borrowed = borrowed.clone();
            let (.., signatures) = forward!(&mut proof.steps[1]);
            *signatures = borrowed;
        }),
        BlockError::NotEnoughWeight { .. }
    ));
}

#[test]
fn a_set_whose_every_signature_is_corrupt_is_refused() {
    let error = tampered(|proof| {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        for entry in signatures_mut(signatures) {
            entry.signature[0] ^= 0x01;
        }
    });
    assert!(
        matches!(error, BlockError::NotEnoughWeight { carried: 0, .. }),
        "expected no weight at all, got {error}"
    );
}

#[test]
fn a_set_signed_by_nobody_in_it_is_refused() {
    let error = tampered(|proof| {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        for (index, entry) in signatures_mut(signatures).iter_mut().enumerate() {
            entry.node_id_short = [index as u8; 32];
        }
    });
    assert!(
        matches!(error, BlockError::NotEnoughWeight { carried: 0, .. }),
        "expected no weight at all, got {error}"
    );
}

#[test]
fn one_bad_signature_does_not_sink_a_set() {
    // A signature set is a vote, and some of it may be junk from a validator of another
    // round. Refusing a whole set over one bad entry would let any peer stall a client
    // by adding one, so a single corruption is tolerated by design rather than by
    // accident. The two cases above are what happens when the whole set is touched.
    let mut proof = chain();
    let anchor = anchor(&proof);
    {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        let entries = signatures_mut(signatures);
        entries[0].signature[0] ^= 0x01;
        entries[1].node_id_short = [0xAA; 32];
        entries[2].signature.clear();
    }
    verify_chain(&anchor, &proof).expect("a set survives three spoiled entries");
}

#[test]
fn a_repeated_signature_is_counted_once() {
    // A validator paid twice towards a threshold is how a set of one could carry a
    // block. Duplicating every entry must move the carried weight by nothing.
    let mut proof = chain();
    let anchor = anchor(&proof);
    let honest = verify_chain(&anchor, &proof).expect("it verifies");

    {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        let entries = signatures_mut(signatures);
        let copies = entries.clone();
        entries.extend(copies);
    }
    assert_eq!(
        verify_chain(&anchor, &proof).expect("it still verifies"),
        honest
    );

    // And with only one validator's entry, repeated, it cannot carry the block.
    let error = tampered(|proof| {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        let entries = signatures_mut(signatures);
        let first = entries[0].clone();
        entries.clear();
        entries.extend(std::iter::repeat_n(first, 200));
    });
    assert!(
        matches!(error, BlockError::NotEnoughWeight { .. }),
        "expected the threshold to refuse, got {error}"
    );
}

#[test]
fn a_chain_with_no_steps_is_refused() {
    assert_eq!(
        tampered(|proof| proof.steps.clear()),
        BlockError::ChainBroken("has no steps")
    );
}

#[test]
fn a_simplex_set_lifted_onto_another_block_is_refused() {
    // A Simplex signature covers a vote naming a candidate by hash, so on its own it
    // says nothing about which block it is for. Reading the candidate and requiring it
    // to name the link's destination is what closes that.
    let mut proof = decode(SIMPLEX);
    let anchor = anchor(&proof);
    {
        let (.., signatures) = forward!(&mut proof.steps[0]);
        if let SignatureSet::Simplex { candidate, .. } = signatures {
            // Byte 20 is inside the block identity the candidate names, past the
            // constructor id, workchain and shard.
            candidate[20] ^= 0x01;
        }
    }
    assert_eq!(
        verify_chain(&anchor, &proof).unwrap_err(),
        BlockError::ChainBroken("has signatures for a block other than the one the link claims")
    );
}

#[test]
fn hostile_proof_bytes_never_panic() {
    // The proofs inside a link are attacker-controlled bytes fed straight to the cell
    // engine. A panic here would be a remote crash, so every input has to resolve to a
    // refusal, including the ones that are not bags of cells at all.
    let mut state: u64 = 0xF00D_BAAD_1234_5678;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..400 {
        let mut proof = chain();
        let anchor = anchor(&proof);
        let length = (next() % 512) as usize;
        let junk: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
        {
            let (_, _, _, dest_proof, config_proof, _) = forward!(&mut proof.steps[0]);
            if next() % 2 == 0 {
                *dest_proof = junk;
            } else {
                *config_proof = junk;
            }
        }
        assert!(verify_chain(&anchor, &proof).is_err());
    }

    // The same for a truncation of a real proof, which stays a plausible bag of cells
    // for longer than random bytes do.
    for cut in [0usize, 1, 2, 7, 64, 1_000, 20_000] {
        let mut proof = chain();
        let anchor = anchor(&proof);
        {
            let (_, _, _, _, config_proof, _) = forward!(&mut proof.steps[0]);
            config_proof.truncate(cut);
        }
        assert!(verify_chain(&anchor, &proof).is_err(), "cut to {cut}");
    }
}

/// The signatures of a set, mutably, whichever form it takes.
fn signatures_mut(set: &mut SignatureSet) -> &mut Vec<ton_net_tl::lite::Signature> {
    match set {
        SignatureSet::Ordinary { signatures, .. } | SignatureSet::Simplex { signatures, .. } => {
            signatures
        }
        other => panic!("an unknown signature set: {other:?}"),
    }
}
