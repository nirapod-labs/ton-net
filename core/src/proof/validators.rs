// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The validator set a key block names, read from its configuration.
//!
//! This is where a light client most easily goes subtly wrong, so what the reference
//! implementation does is written down here rather than left to the code.
//!
//! Two configuration parameters can hold the round in force. Parameter 34 is the
//! standing set and parameter 35 the temporary one, and the rule is **35 when the
//! configuration carries it, 34 otherwise**, with nothing else conditioning the choice:
//! not the block's generation time, and not the window either set names. That is the
//! selection the reference implementation makes where it extracts the signing set out of
//! a key block, which is the one path a forward-link proof check reaches. Other readers
//! of the same configuration take 34 alone, so the rule is scoped to this use rather than
//! general. The reason to copy it is that a set read from the wrong parameter fails
//! quietly: what comes back is a real set that simply did not sign the block in hand, so
//! the weight threshold is missed rather than the parameter refused, and the refusal
//! arrives under a name that sends a reader looking at signatures.
//!
//! **Parameter 35 is not what a mainnet rotation installs**, which is worth saying
//! because the opposite is easy to assume from the name. No configuration read while
//! this was written carried the parameter at all: neither the mainnet nor the testnet
//! configuration on 2026-08-16, nor any of the key blocks captured under
//! `tests/fixtures/`. So the rule here is conformance to the reference's selection, not
//! the repair of anything this tree was seen refusing, and a configuration carrying the
//! parameter is a case the tests reach only by construction.
//!
//! **A pruned parameter 35 is not an absent one.** The configuration arrives inside a
//! Merkle proof, so a lookup answers found, absent, or unknown, and only the middle
//! answer licenses reading 34; the pruned case is refused as uncovered rather than
//! assumed empty.
//!
//! What makes that refusal safe to make is a property of the server rather than of the
//! captures. A node building the configuration proof for a forward link records the cells
//! that one extraction of the signing set reads, and that extraction looks 35 up before
//! it falls back, so the walk to 35 is inside what the proof carries and arrives covered
//! whether or not the parameter is there. Every configuration captured in this tree bears
//! that out, showing 35 absent rather than pruned, which is the observation and not the
//! reason.
//!
//! Both parameters carry the same shape: a count of `total` validators, a count of
//! `main`, a declared total weight, and a dictionary of descriptors keyed by index. The
//! masterchain set, the one that may sign a masterchain block, is **the first
//! `min(main, total)` entries of that list, with their weights unchanged**. The reference
//! implementation may then permute those entries with a seeded generator, but the
//! permutation is over exactly those entries: it reorders them and changes neither which
//! keys are in the set nor what each one weighs.
//!
//! Signature checking asks two questions of a set: is this signer in it, and what does
//! that signer weigh. Neither answer depends on order, so **the shuffle is not
//! implemented**, and neither is the `gen_validator_list_hash_short` cross-check, which
//! is the only check that does depend on order.
//!
//! Skipping a cross-check deserves an argument. The argument is that the check is
//! redundant against a set derived correctly, and that deriving it incorrectly fails
//! loudly rather than quietly, provided one rule holds: **the accepted signers and the
//! weight in the threshold's denominator come from the same set, never from different
//! ones.** With that rule, taking too many validators makes the threshold unreachable
//! and taking too few discards honest signatures, and either way live mainnet blocks
//! stop verifying. That is why [`total_weight`](ValidatorSet::total_weight) is summed
//! over the masterchain subset here and the declared figure in the parameter, which
//! counts every validator in every shard, is read past.
//!
//! **One check that looks obvious and must not be made.** A set names the window it is
//! valid for, and requiring a signed block's generation time to fall inside the signing
//! set's window is the natural-looking guard. It is wrong: the key block that announces
//! a rotation is stamped one second past the outgoing set's
//! [`utime_until`](ValidatorSet::utime_until) and is signed by that outgoing set, so the
//! guard refuses the first link of every rotation. The set to use is the one the source
//! key block names, and the window is not a check.

use crate::cell::{Cell, Slice};
use sha2::{Digest, Sha256};

use crate::cell::{Dict, Lookup};
use crate::tlb::BlockError;

/// The configuration parameter holding the standing validator set.
const CURRENT_VALIDATORS: i32 = 34;

/// The configuration parameter holding the temporary validator set, which takes
/// precedence over [`CURRENT_VALIDATORS`] wherever the configuration carries it.
const CURRENT_TEMP_VALIDATORS: i32 = 35;

/// `validators#11` and `validators_ext#12`
const VALIDATORS_TAG: u64 = 0x11;
const VALIDATORS_EXT_TAG: u64 = 0x12;
/// `validator#53` and `validator_addr#73`
const VALIDATOR_TAG: u64 = 0x53;
const VALIDATOR_ADDR_TAG: u64 = 0x73;
/// `ed25519_pubkey#8e81278a`
const ED25519_PUBKEY_TAG: u64 = 0x8e81_278a;

/// `pub.ed25519 key:int256 = PublicKey`, the TL form a short id is the hash of.
const PUB_ED25519: u32 = 0x4813_b4c6;

/// One validator: the key that signs, and what its signature is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Validator {
    /// The ed25519 public key that signs.
    pub public_key: [u8; 32],
    /// The weight the signature carries towards a threshold.
    pub weight: u64,
}

/// The masterchain validator set for one round.
///
/// Holds only the validators that may sign a masterchain block. See the
/// [module documentation](self) for why that subset is the head of the list, and why
/// its weight rather than the parameter's declared weight is the denominator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidatorSet {
    /// When the round begins, in seconds since the Unix epoch.
    pub utime_since: u32,
    /// When the round ends. This is not a check; see the [module documentation](self).
    pub utime_until: u32,
    /// How many validators the round has across every shard.
    pub total: u16,
    /// How many of them may sign a masterchain block.
    pub main: u16,
    /// The masterchain subset, sorted by short id so a signer can be found by binary
    /// search rather than a scan.
    members: Vec<([u8; 32], Validator)>,
    total_weight: u64,
}

impl ValidatorSet {
    /// Reads the validator set in force out of a configuration dictionary.
    ///
    /// `config` is the root of the dictionary [`crate::tlb::Block::config`] returns.
    /// Parameter 35 answers where the configuration shows it, and parameter 34 only
    /// where the configuration shows 35 absent. See the
    /// [module documentation](self) for why absent and pruned are not the same answer.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the configuration shows neither parameter
    /// present or the parameter it names is inconsistent, [`BlockError::NotCovered`] if
    /// the proof prunes the walk to parameter 35, prunes the walk to parameter 34 where
    /// 35 is absent, or prunes any descriptor in the subset, and
    /// [`BlockError::WrongConstructor`] if a tag is not what it should be.
    pub fn from_config(config: &Cell) -> Result<Self, BlockError> {
        let params = Dict::from_root(Some(config.clone()), 32)?;
        let entry = match params.get(&CURRENT_TEMP_VALIDATORS.to_be_bytes())? {
            Lookup::Found(entry) => entry,
            // A pruned branch shows nothing, so falling back here would read 34 out of a
            // configuration that may well carry 35, which is the wrong set derived in
            // silence. Only a covered absence licenses the fallback below.
            Lookup::Pruned => return Err(BlockError::NotCovered),
            Lookup::Absent => match params.get(&CURRENT_VALIDATORS.to_be_bytes())? {
                Lookup::Found(entry) => entry,
                Lookup::Absent => {
                    return Err(BlockError::Malformed(
                        "a configuration without the validator set",
                    ))
                }
                Lookup::Pruned => return Err(BlockError::NotCovered),
            },
        };
        // Every configuration parameter is stored behind a reference, so the entry's
        // own slice holds the pointer rather than the value.
        Self::from_cell(entry.slice()?.load_ref()?)
    }

    /// Reads a validator set from the cell configuration parameter 34 or 35 holds.
    ///
    /// The two carry the same shape, so this reads either and nothing here distinguishes
    /// them. Which one a configuration answers with is
    /// [`from_config`](Self::from_config)'s question.
    ///
    /// # Errors
    ///
    /// As [`from_config`](Self::from_config), less the dictionary lookup.
    pub fn from_cell(param: &Cell) -> Result<Self, BlockError> {
        let mut s = param.parse();
        let extended = match s.load_uint(8)? {
            VALIDATORS_EXT_TAG => true,
            VALIDATORS_TAG => false,
            _ => {
                return Err(BlockError::WrongConstructor {
                    expected: "a validator set",
                })
            }
        };
        let utime_since = s.load_u32()?;
        let utime_until = s.load_u32()?;
        let total = s.load_u16()?;
        let main = s.load_u16()?;
        if main == 0 || main > total {
            return Err(BlockError::Malformed(
                "a validator set with no main validators, or more main than total",
            ));
        }
        if extended {
            // The declared weight is over every validator in every shard. The subset
            // that may sign a masterchain block is weighed below, from its own entries.
            s.load_uint(64)?;
        }
        let list = if extended {
            s.load_maybe_ref()?
                .ok_or(BlockError::Malformed("a validator set with no list"))?
        } else {
            s.load_ref()?
        };

        let list_dict = Dict::from_root(Some(list.clone()), 16)?;
        let mut members = Vec::with_capacity(main as usize);
        let mut total_weight = 0u64;
        for index in 0..main {
            let entry = match list_dict.get(&index.to_be_bytes())? {
                Lookup::Found(entry) => entry,
                Lookup::Absent => {
                    return Err(BlockError::Malformed(
                        "a validator set missing an entry the count promises",
                    ))
                }
                Lookup::Pruned => return Err(BlockError::NotCovered),
            };
            let validator = read_validator(&mut entry.slice()?)?;
            total_weight = total_weight
                .checked_add(validator.weight)
                .ok_or(BlockError::Malformed("validator weights that overflow"))?;
            members.push((short_id(&validator.public_key), validator));
        }

        members.sort_unstable_by_key(|(short_id, _)| *short_id);
        // A key counted twice would be paid twice towards a threshold, so a repeat is a
        // refusal rather than something to deduplicate.
        if members
            .iter()
            .zip(members.iter().skip(1))
            .any(|(left, right)| left.0 == right.0)
        {
            return Err(BlockError::Malformed(
                "a validator set that names the same key twice",
            ));
        }

        Ok(Self {
            utime_since,
            utime_until,
            total,
            main,
            members,
            total_weight,
        })
    }

    /// Finds a validator by the short id a signature names it with.
    ///
    /// Returns `None` for a signer outside the set, which is the honest answer: a
    /// signature from a validator of some other round contributes nothing, and is not a
    /// reason to refuse the whole set.
    #[must_use]
    pub fn find(&self, short_id: &[u8; 32]) -> Option<&Validator> {
        self.members
            .binary_search_by(|(id, _)| id.cmp(short_id))
            .ok()
            .and_then(|at| self.members.get(at))
            .map(|(_, validator)| validator)
    }

    /// The sum of the weights of the validators in this set, and nothing else.
    ///
    /// This is the denominator a signature threshold is measured against. See the
    /// [module documentation](self) for why it is not the figure the parameter declares.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Whether `weight` is more than two thirds of this set's weight.
    ///
    /// Strictly greater, in integer arithmetic, with no rounding and no floating point
    /// anywhere near it. That is not fastidiousness: the thinnest link on the real chain
    /// from the block the mainnet config pins to today carries 66.6712% of its set,
    /// **0.0046 percentage points** above the threshold, and a comparison done in `f64`
    /// at that margin is a coin toss.
    #[must_use]
    pub fn carries(&self, weight: u64) -> bool {
        u128::from(weight) * 3 > u128::from(self.total_weight) * 2
    }

    /// How many validators may sign a masterchain block in this round.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the set is empty, which a set read from a real block never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The validators in the set, ordered by short id rather than by round position.
    pub fn iter(&self) -> impl Iterator<Item = &Validator> {
        self.members.iter().map(|(_, validator)| validator)
    }
}

/// Reads one `ValidatorDescr`.
fn read_validator(s: &mut Slice<'_>) -> Result<Validator, BlockError> {
    let tag = s.load_uint(8)?;
    // The two forms differ only in a trailing adnl address, which signing does not use.
    if tag != VALIDATOR_TAG && tag != VALIDATOR_ADDR_TAG {
        return Err(BlockError::WrongConstructor {
            expected: "a validator descriptor",
        });
    }
    if s.load_uint(32)? != ED25519_PUBKEY_TAG {
        return Err(BlockError::WrongConstructor {
            expected: "an ed25519 public key",
        });
    }
    let public_key: [u8; 32] = s
        .load_bytes(32)?
        .try_into()
        .map_err(|_| BlockError::Malformed("an ed25519 public key that is not 32 bytes"))?;
    let weight = s.load_uint(64)?;
    Ok(Validator { public_key, weight })
}

/// A validator's short id: the SHA-256 of its key in the TL `pub.ed25519` form.
///
/// This is the value a signature names its signer by, and the same computation the ADNL
/// handshake performs on a server key. The two are written separately: this one runs once
/// per validator over a set of several hundred on every link of a chain, and the codec's
/// own serializer allocates. `the_short_id_is_the_serialized_key_hashed` holds the two
/// spellings to the same bytes, so a change to one that is not made to the other lands
/// there.
#[must_use]
pub fn short_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUB_ED25519.to_le_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-written TL form against the one the codec writes.
    ///
    /// `short_id` spells `pub.ed25519` itself rather than calling the serializer, so the
    /// constructor id and the field order are duplicated. A change to either side of that
    /// duplication that is not made to the other lands here.
    #[test]
    fn the_short_id_is_the_serialized_key_hashed() {
        let key = [7u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(crate::tl::serialize(crate::tl::adnl::PublicKey { key }));
        let through_the_codec: [u8; 32] = hasher.finalize().into();
        assert_eq!(short_id(&key), through_the_codec);
    }

    /// A set with a chosen weight and nothing else, for testing the threshold alone.
    ///
    /// The rule is arithmetic over one number, and the boundary is where an off-by-one
    /// hides. A set read from a real block fixes that number at whatever the round
    /// happened to weigh, which cannot reach the cases below.
    fn weighing(total_weight: u64) -> ValidatorSet {
        ValidatorSet {
            utime_since: 0,
            utime_until: 0,
            total: 1,
            main: 1,
            members: Vec::new(),
            total_weight,
        }
    }

    #[test]
    fn exactly_two_thirds_does_not_carry_and_one_more_does() {
        // A weight divisible by three puts the threshold on an exact integer, which is
        // the case a rule written with `>=` would pass and this one must refuse.
        let set = weighing(300);
        assert!(!set.carries(200));
        assert!(set.carries(201));

        // And where it does not divide, the smallest carrying weight is the first
        // integer above two thirds rather than the rounding of it.
        let set = weighing(100);
        assert!(!set.carries(66));
        assert!(set.carries(67));
    }

    #[test]
    fn nothing_carries_and_everything_does() {
        let set = weighing(1_000);
        assert!(!set.carries(0));
        assert!(set.carries(1_000));
        assert!(!set.carries(666));
        assert!(set.carries(667));
    }

    #[test]
    fn a_weight_near_the_top_of_its_type_does_not_wrap() {
        // Three times a weight overflows a u64 well before the weight itself does. In
        //64-bit arithmetic the multiplication would wrap and a set of nothing would
        // carry everything.
        let set = weighing(u64::MAX);
        assert!(!set.carries(u64::MAX / 2));
        assert!(set.carries(u64::MAX));
        assert!(!set.carries(0));

        // Two thirds of the largest weight there is, exactly at the boundary.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "dividing 2 * u128::from(u64::MAX) by 3 yields at most 2/3 of u64::MAX, \
                      which is under u64::MAX, so the truncation to u64 cannot lose any bits"
        )]
        let boundary = ((2 * u128::from(u64::MAX)) / 3) as u64;
        assert!(!set.carries(boundary));
        assert!(set.carries(boundary + 1));
    }
}
