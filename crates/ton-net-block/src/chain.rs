// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Checking a block proof chain, one link at a time.
//!
//! A liteserver answers `getBlockProof` with a run of links connecting a block the
//! client already trusts to a later one. **The server picks the route and the client
//! believes nothing about it.** Every field of every link is a claim until something
//! here checks it, including which blocks the route passes through and which direction
//! it runs.
//!
//! What makes a link worth anything is the signatures. A block's file hash is the one
//! field of its identity no Merkle proof can establish, being a hash of the serialized
//! block file rather than of the cell tree, so a destination is believed only once more
//! than two thirds of the source key block's validator set has signed for it. The
//! header proof establishes what the block says about itself; the signatures establish
//! that it is the block the network committed.

use ton_net_tl::lite::{BlockIdExt, BlockLink, PartialBlockProof, Signature, SignatureSet};
use ton_net_tl::signed::CandidateBlock;

use crate::block::Block;
use crate::error::BlockError;
use crate::signature;
use crate::validators::ValidatorSet;

/// The masterchain workchain id.
const MASTERCHAIN: i32 = -1;
/// The masterchain shard, which is the whole address space.
const MASTERCHAIN_SHARD: u64 = 0x8000_0000_0000_0000;

/// A block a proof chain established, and the two facts a caller needs about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProvenBlock {
    /// The block's identity, signed for by the validators of the round before it.
    pub id: BlockIdExt,
    /// Whether it is a key block, and so whether a chain can continue from it.
    pub key_block: bool,
    /// When it was generated, which is what a freshness check consumes.
    pub gen_utime: u32,
}

/// Checks a whole proof chain against a block the caller already trusts.
///
/// Returns the last block the chain proves. A caller continuing a walk uses that as the
/// next anchor, which is why [`ProvenBlock::key_block`] comes back with it: a chain can
/// only be continued from a key block, because only a key block carries the validator
/// set for the step after it.
///
/// # Errors
///
/// Returns [`BlockError::ChainBroken`] if the run does not connect the blocks it claims
/// to, [`BlockError::BackwardLink`] for a step this release does not check,
/// [`BlockError::NotEnoughWeight`] if a link's signatures do not carry it,
/// [`BlockError::UnknownSignedForm`] for a signature set of a third kind, and the proof
/// and decode failures of [`Block::from_proof`] for a proof that does not check out.
pub fn verify_chain(
    anchor: &BlockIdExt,
    proof: &PartialBlockProof,
) -> Result<ProvenBlock, BlockError> {
    if proof.from != *anchor {
        return Err(BlockError::ChainBroken(
            "starts at a block other than the one it was asked about",
        ));
    }
    if proof.steps.is_empty() {
        return Err(BlockError::ChainBroken("has no steps"));
    }

    // Each step is checked against where the last one ended, so a run that skips a block
    // or doubles back cannot be stitched together into a chain that reaches the target.
    // Nothing enforces that the blocks between the ends are key blocks: that falls out
    // of reading each step's source configuration, which only a key block has.
    let mut proven: Option<ProvenBlock> = None;
    for step in &proof.steps {
        let from = proven.as_ref().map_or(anchor, |block| &block.id);
        proven = Some(verify_link(step, from)?);
    }

    // The empty case is refused above, so the loop ran at least once. Saying so by
    // repeating that refusal rather than by asserting it keeps a later edit to the guard
    // from turning this into a panic inside a verifier.
    let last = proven.ok_or(BlockError::ChainBroken("has no steps"))?;
    if last.id != proof.to {
        return Err(BlockError::ChainBroken("ends somewhere other than it says"));
    }
    Ok(last)
}

/// Checks one link against the block it must start from.
fn verify_link(link: &BlockLink, from: &BlockIdExt) -> Result<ProvenBlock, BlockError> {
    // A backward link exists so a client whose known block is not a key block can reach
    // the last key block before it. A client whose anchor is always a key block never
    // needs one, so rather than being read and half-checked it is named and refused.
    let BlockLink::Forward {
        to_key_block,
        from: source,
        to,
        dest_proof,
        config_proof,
        signatures,
    } = link
    else {
        return Err(BlockError::BackwardLink);
    };

    if source != from {
        return Err(BlockError::ChainBroken(
            "has a link that does not start where the last one ended",
        ));
    }
    if !is_masterchain(source) || !is_masterchain(to) {
        return Err(BlockError::ChainBroken(
            "has a link outside the masterchain",
        ));
    }
    // The direction the link declares has to agree with which end is higher, or a run of
    // links could arrive back where it started while every step looked forward.
    if to.seqno <= source.seqno {
        return Err(BlockError::ChainBroken(
            "has a forward link that does not move forward",
        ));
    }

    let set =
        ValidatorSet::from_config(&Block::from_proof(config_proof, &source.root_hash)?.config()?)?;

    let header = Block::from_proof(dest_proof, &to.root_hash)?.header()?;
    #[allow(
        clippy::cast_sign_loss,
        reason = "the wire carries this as int32; the domain counts it unsigned"
    )]
    let to_seqno = to.seqno as u32;
    if header.seqno != to_seqno || header.workchain != to.workchain || header.shard != to.shard {
        return Err(BlockError::ChainBroken(
            "has a destination header for a different block",
        ));
    }
    // Without this a server could present an ordinary block as a key block and have the
    // chain continue from a body that carries no configuration.
    if header.key_block != *to_key_block {
        return Err(BlockError::ChainBroken(
            "has a destination that is not the kind of block the link says",
        ));
    }

    let message = signed_message(signatures, to)?;
    let carried = carried_weight(&set, signatures.signatures(), &message)?;
    if !set.carries(carried) {
        return Err(BlockError::NotEnoughWeight {
            carried,
            total: set.total_weight(),
        });
    }

    Ok(ProvenBlock {
        id: to.clone(),
        key_block: header.key_block,
        gen_utime: header.gen_utime,
    })
}

/// Rebuilds the exact bytes the validators' keys went over.
fn signed_message(set: &SignatureSet, to: &BlockIdExt) -> Result<Vec<u8>, BlockError> {
    match set {
        SignatureSet::Ordinary { .. } => {
            Ok(signature::block_id_message(&to.root_hash, &to.file_hash))
        }
        SignatureSet::Simplex {
            session_id,
            slot,
            candidate,
            ..
        } => {
            // A Simplex signature covers a vote naming a candidate by hash, which says
            // nothing on its own about which block that candidate was. Without this,
            // real signatures lifted from one block and attached to a link claiming
            // another would verify and carry it.
            //
            // Both candidate forms are accepted, and that is not an oversight. An empty
            // candidate names the block its slot extends rather than one it proposes, so
            // finalize votes over it certify that block; see `CandidateBlock::Empty`.
            let named = CandidateBlock::read_prefix(candidate).map_err(|_| {
                BlockError::ChainBroken("has a signed candidate that cannot be read")
            })?;
            if named.block() != to {
                return Err(BlockError::ChainBroken(
                    "has signatures for a block other than the one the link claims",
                ));
            }
            Ok(signature::simplex_message(session_id, *slot, candidate))
        }
        _ => Err(BlockError::UnknownSignedForm),
    }
}

/// Sums the weight of the valid signatures from distinct members of `set`.
///
/// Three details are checks rather than assumptions. A signer outside the set
/// contributes nothing rather than failing the whole set, because a hostile peer could
/// otherwise stall a client by adding one. A validator counted twice contributes once. A
/// signature is only counted after it verifies, so a bad duplicate cannot displace the
/// real one and drop a link below the threshold.
///
/// That last ordering is what makes a budget necessary. Verifying before deduplicating is
/// the sound order, but it means a repeated signer costs a curve operation every time, so
/// a set padded with copies of one member is a compute amplifier. An honest set carries
/// each member at most once, and this is the only place the set's own size is in scope to
/// say so.
fn carried_weight(
    set: &ValidatorSet,
    signatures: &[Signature],
    message: &[u8],
) -> Result<u64, BlockError> {
    let budget = set.len().saturating_mul(2);
    let mut attempts = 0usize;
    let mut counted: Vec<[u8; 32]> = Vec::new();
    let mut weight = 0u64;
    for entry in signatures {
        let Some(validator) = set.find(&entry.node_id_short) else {
            continue;
        };
        let Err(at) = counted.binary_search(&entry.node_id_short) else {
            continue;
        };
        // Spent only on an entry naming a member that is not already counted, so a set
        // also carrying signatures from other rounds is unaffected.
        if attempts >= budget {
            break;
        }
        attempts += 1;
        if !signature::verify(&validator.public_key, message, &entry.signature) {
            continue;
        }
        counted.insert(at, entry.node_id_short);
        weight = weight
            .checked_add(validator.weight)
            .ok_or(BlockError::Malformed("validator weights that overflow"))?;
        // Past the threshold nothing further can change the answer, and the rest of an
        // honest set is about a fifth of the curve work a whole sync does. The caller
        // tests the same predicate, so the weight returned here is a lower bound rather
        // than a total; only the not-enough-weight path needs the total, and that path is
        // reached only when this loop ran to the end.
        if set.carries(weight) {
            return Ok(weight);
        }
    }
    Ok(weight)
}

fn is_masterchain(id: &BlockIdExt) -> bool {
    id.workchain == MASTERCHAIN && id.shard == MASTERCHAIN_SHARD
}
