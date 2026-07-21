// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Checking a signature set against a validator set.

use crate::block::ValidatorSet;
use crate::sig::{self, Tally};
use crate::tl::{Forward, SignatureSet};

/// Tries every candidate message against a set and prints what each produces.
pub fn report_messages(link: &Forward, set: &ValidatorSet) {
    for (name, message) in candidate_messages(link) {
        let tally = tally(link, set, &message);
        println!(
            "  {name:<21} weight {:>21} of {:>21} ({:>5.1}%)  valid {:>3}  unknown {:>3}  invalid {:>3}  carries: {}",
            tally.weight,
            set.total_weight,
            tally.share(set.total_weight) * 100.0,
            tally.valid,
            tally.unknown_signer,
            tally.invalid,
            tally.carries(set.total_weight)
        );
    }
}

/// Every message the signatures on a link might cover, named, most likely first.
///
/// The set's own form decides the shape. An ordinary set signs the block identity; a
/// Simplex set signs a vote for a candidate, and which vote is what the spike is
/// establishing, so both are offered.
pub fn candidate_messages(link: &Forward) -> Vec<(&'static str, Vec<u8>)> {
    match &link.set {
        SignatureSet::Ordinary { .. } => vec![
            (
                "ton.blockId",
                sig::signed_message(sig::TON_BLOCK_ID, &link.to.root_hash, &link.to.file_hash),
            ),
            (
                "ton.blockIdApprove",
                sig::signed_message(
                    sig::TON_BLOCK_ID_APPROVE,
                    &link.to.root_hash,
                    &link.to.file_hash,
                ),
            ),
        ],
        SignatureSet::Simplex {
            session_id,
            slot,
            candidate,
            ..
        } => vec![
            (
                "simplex.notarizeVote",
                sig::data_to_sign(
                    session_id,
                    &sig::simplex_vote(sig::NOTARIZE_VOTE, *slot, candidate),
                ),
            ),
            (
                "simplex.finalizeVote",
                sig::data_to_sign(
                    session_id,
                    &sig::simplex_vote(sig::FINALIZE_VOTE, *slot, candidate),
                ),
            ),
        ],
    }
}

/// Checks one signature set against one validator set, over one candidate message.
pub fn tally(link: &Forward, set: &ValidatorSet, message: &[u8]) -> Tally {
    let mut seen = std::collections::HashSet::new();
    let mut tally = Tally::default();
    for signature in link.set.signatures() {
        let Some((key, weight)) = set.weights.get(&signature.node_id_short) else {
            tally.unknown_signer += 1;
            continue;
        };
        if !seen.insert(signature.node_id_short) {
            tally.duplicate += 1;
            continue;
        }
        if sig::verify(key, message, &signature.signature) {
            tally.valid += 1;
            tally.weight += weight;
        } else {
            tally.invalid += 1;
        }
    }
    tally
}
