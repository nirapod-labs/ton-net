//! Walking the anchor forward, and the bounds that keep a server from deciding how far.
//!
//! The loop is short, because the protocol puts the routing on the server: ask for a
//! proof from the block the client trusts to the head the server reports, check every
//! link of whatever route comes back, and ask again from where it ended until the server
//! says the chain is complete.
//!
//! # What the client keeps
//!
//! **The anchor is always a key block, never the head.** That single rule is what removes
//! backward links from the picture. A backward link exists so a client whose known block
//! is not a key block can reach the last key block before it; a client whose anchor is
//! always a key block never needs one, which is why `ton-net-block` refuses one by name
//! rather than checking it. The head a sync proves is handed back for the read that
//! wanted it and then dropped, because keeping it would mean starting the next sync from
//! a block no chain can continue from.
//!
//! # Bounds
//!
//! This is the first place in the library where a server decides how much work the client
//! does, so the bounds are part of the design rather than a later hardening pass. Each one
//! ends the sync with a named error, and none of them relaxes a check to let a sync
//! succeed.

use ton_net_lite::{BlockIdExt, PartialBlockProof};

use crate::Error;

/// The most links one reply may carry. Mainnet sends sixteen.
const MAX_LINKS_PER_REPLY: usize = 64;

/// The most links one sync may check.
///
/// A cold sync from the block the mainnet config pins was 1242 links in July 2026, and
/// that figure grows by about 800 a year for as long as the config keeps pinning the same
/// block. This leaves room for several years of that and still ends a runaway chain.
const MAX_LINKS_PER_SYNC: usize = 4096;

/// The most replies one sync may take. A cold sync took 78.
const MAX_ROUNDS: usize = 512;

/// The most bytes one Merkle proof inside a link may be.
///
/// A configuration proof runs about 36 kB, and it is the larger of the two a link
/// carries, so this is a wide margin over anything real. It sits on top of the cell
/// engine's own cell and depth bounds rather than replacing them.
const MAX_PROOF_BYTES: usize = 1 << 20;

/// The most signatures one set may carry.
///
/// Checked before any verification runs, so a set cannot be a compute amplifier: without
/// it a server could attach a hundred thousand signatures to one link and make the client
/// spend a minute refusing them. Mainnet runs about a hundred masterchain validators.
const MAX_SIGNATURES: usize = 1024;

/// Refuses a reply that is larger than anything the protocol produces, before any of it
/// is checked.
///
/// The order matters. Everything here is a count or a length read straight off the wire,
/// so it costs nothing, and it runs before the cell engine parses a proof or the curve
/// arithmetic touches a signature.
pub(crate) fn within_bounds(reply: &PartialBlockProof) -> Result<(), Error> {
    use ton_net_lite::BlockLink;

    if reply.steps.len() > MAX_LINKS_PER_REPLY {
        return Err(Error::Sync(format!(
            "a reply with {} links, past the {MAX_LINKS_PER_REPLY} a reply may carry",
            reply.steps.len()
        )));
    }
    for step in &reply.steps {
        let (dest_proof, other, signatures) = match step {
            BlockLink::Forward {
                dest_proof,
                config_proof,
                signatures,
                ..
            } => (dest_proof, config_proof, Some(signatures)),
            BlockLink::Back {
                dest_proof,
                state_proof,
                ..
            } => (dest_proof, state_proof, None),
            // An unknown link is refused when it is checked, which is where the error
            // naming it belongs. Nothing here can measure one.
            _ => continue,
        };
        for proof in [dest_proof, other] {
            if proof.len() > MAX_PROOF_BYTES {
                return Err(Error::Sync(format!(
                    "a {} byte proof, past the {MAX_PROOF_BYTES} byte bound",
                    proof.len()
                )));
            }
        }
        if let Some(set) = signatures {
            let count = set.signatures().len();
            if count > MAX_SIGNATURES {
                return Err(Error::Sync(format!(
                    "a set of {count} signatures, past the {MAX_SIGNATURES} bound"
                )));
            }
        }
    }
    Ok(())
}

/// Counts a round and its links, refusing a walk that will not end.
///
/// Strict progress is the third bound and the one that catches a server which answers
/// forever without getting anywhere: an unfinished reply that leaves the anchor where it
/// was ends the sync rather than going round again.
pub(crate) struct Walk {
    rounds: usize,
    links: usize,
}

impl Walk {
    pub(crate) fn new() -> Walk {
        Walk {
            rounds: 0,
            links: 0,
        }
    }

    /// Records one reply, or refuses to let the walk continue.
    pub(crate) fn round(&mut self, links: usize) -> Result<(), Error> {
        self.rounds += 1;
        if self.rounds > MAX_ROUNDS {
            return Err(Error::Sync(format!(
                "more than {MAX_ROUNDS} replies without reaching the head"
            )));
        }
        self.links += links;
        if self.links > MAX_LINKS_PER_SYNC {
            return Err(Error::Sync(format!(
                "more than {MAX_LINKS_PER_SYNC} links without reaching the head"
            )));
        }
        Ok(())
    }

    /// How many links the walk checked and how many replies it took.
    pub(crate) fn cost(&self) -> (usize, usize) {
        (self.links, self.rounds)
    }
}

/// What one sync reached and what it cost.
///
/// The counts are here because a first sync is slow enough that a caller has a right to
/// know what it did rather than only how long it took. They are observations, not a
/// promise: the numbers move as the network does.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncReport {
    /// The head the walk proved. It is proved for the read that wanted it and is not
    /// kept: the client keeps the last key block on the way, which
    /// [`Client::anchor`](crate::Client::anchor) hands back.
    pub head: BlockIdExt,
    /// How many links were checked, each one a validator signature set.
    pub links: usize,
    /// How many replies the server took to finish the chain.
    pub rounds: usize,
}

/// Refuses a step that does not raise the anchor.
pub(crate) fn advanced(before: &BlockIdExt, after: &BlockIdExt) -> Result<(), Error> {
    if after.seqno <= before.seqno {
        return Err(Error::Sync(format!(
            "a reply left the anchor at {}, so the walk cannot end",
            before.seqno
        )));
    }
    Ok(())
}

/// Refuses a proven head older than the bound, measured against the local clock.
///
/// The local clock is the only thing there is to measure against. A proof establishes
/// that a block is real and was committed by the validators, and says nothing at all
/// about when it was handed over, so a server replaying a genuine block from last year
/// passes every other check in this library and fails only here.
pub(crate) fn fresh_enough(gen_utime: u32, limit_seconds: u32) -> Result<(), Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // A local clock behind the block reads as an age of zero rather than as a wrap. A
    // clock that wrong is a caller problem, and refusing a fresh block over it would be
    // the wrong failure.
    let age = now.saturating_sub(u64::from(gen_utime));
    if age > u64::from(limit_seconds) {
        return Err(Error::Stale {
            age_seconds: age,
            limit_seconds: u64::from(limit_seconds),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_walk_that_does_not_end_is_stopped() {
        let mut walk = Walk::new();
        for _ in 0..MAX_ROUNDS {
            walk.round(1).expect("a round within the bound");
        }
        assert!(matches!(walk.round(1), Err(Error::Sync(_))));
    }

    #[test]
    fn a_walk_with_too_many_links_is_stopped_before_the_round_bound() {
        let mut walk = Walk::new();
        // At the most links a reply may carry, the link bound bites before the round one.
        while walk.round(MAX_LINKS_PER_REPLY).is_ok() {
            assert!(walk.cost().1 <= MAX_ROUNDS, "the link bound never bit");
        }
        assert!(walk.cost().0 > MAX_LINKS_PER_SYNC);
    }

    #[test]
    fn an_anchor_that_does_not_move_ends_the_walk() {
        let at = |seqno: u32| BlockIdExt::new(-1, 0x8000_0000_0000_0000, seqno, [0; 32], [0; 32]);
        assert!(advanced(&at(10), &at(11)).is_ok());
        assert!(matches!(advanced(&at(10), &at(10)), Err(Error::Sync(_))));
        assert!(matches!(advanced(&at(10), &at(9)), Err(Error::Sync(_))));
    }

    #[test]
    fn a_head_older_than_the_bound_is_stale() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs() as u32;

        assert!(fresh_enough(now, 600).is_ok());
        assert!(fresh_enough(now - 599, 600).is_ok());
        assert!(fresh_enough(now - 601, 600).is_err());

        // A block stamped in the future is not stale, whatever else it is. Refusing it
        // here would report the wrong failure for a clock that is merely behind.
        assert!(fresh_enough(now + 10_000, 600).is_ok());

        match fresh_enough(now - 4_000, 600) {
            Err(Error::Stale {
                age_seconds,
                limit_seconds,
            }) => {
                assert!((3_999..=4_001).contains(&age_seconds));
                assert_eq!(limit_seconds, 600);
            }
            other => panic!("expected a stale head, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_bound_refuses_every_head() {
        // Documented behaviour rather than an accident: a caller who says no staleness at
        // all gets what they asked for, including on a block a second old.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs() as u32;
        assert!(fresh_enough(now - 1, 0).is_err());
    }
}
