// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The domain response types and the unverified-read wrapper.
//!
//! These are the cleaned-up forms of the liteserver wire types: a reader sees a block
//! sequence number as an unsigned height, an account read as a block and a state, and
//! the proof bytes set aside in [`ServerReported`] rather than mixed into the value.
//! Each is `#[non_exhaustive]` so fields can be added before 1.0 without a breaking
//! change.
//!
//! One type here is not a read at all. [`Accepted`] is what a server says back when it
//! is offered a message, and it is kept apart from the read wrapper rather than folded
//! into it, because an acknowledgement and a value read out of the chain are different
//! kinds of thing and a wrapper that carried both would say something slightly false
//! about one of them.

/// A value a liteserver returned without a checked proof.
///
/// A `LiteClient` checks nothing, so everything it returns is the server's word and wears
/// this wrapper to say so. A caller reaches the inner value through
/// [`value`](Self::value) or [`into_value`](Self::into_value) and cannot mistake it for
/// verified state.
///
/// The raw proof bytes the server sent are kept by [`proof`](Self::proof), so the layer
/// above can check them without another round trip. That is what [`crate::proof`] does,
/// and it is why the `ton-net` facade can hand back a proved value while the calls here
/// still hand back this one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerReported<T> {
    value: T,
    proof: Vec<u8>,
}

impl<T> ServerReported<T> {
    /// Wraps a value with the unchecked proof bytes the server sent for it.
    pub(crate) fn new(value: T, proof: Vec<u8>) -> Self {
        Self { value, proof }
    }

    /// Returns a reference to the server-reported value, which is not proof-verified.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the wrapper and returns the server-reported value, not proof-verified.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Returns the raw proof bytes the server sent, still unchecked. Empty when the
    /// response carried no proof.
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Replaces the value with something read out of it, keeping the proof bytes.
    ///
    /// Decoding a reported value leaves it just as unproven as it was, so the wrapper
    /// travels with it rather than being unwrapped and forgotten. The proof bytes stay
    /// attached for whatever checks them later.
    ///
    /// # Errors
    ///
    /// Returns whatever `read` returns, unchanged.
    pub fn try_map<U, E>(
        self,
        read: impl FnOnce(&T) -> Result<U, E>,
    ) -> Result<ServerReported<U>, E> {
        let value = read(&self.value)?;
        Ok(ServerReported {
            value,
            proof: self.proof,
        })
    }
}

/// One liteserver's acknowledgement that it took an external message.
///
/// This is a third result shape beside [`ServerReported`] and
/// [`Verified`](crate::Verified), and it is a separate type because a send is neither
/// kind of read. There is no chain value inside it to reach, so it offers no `value` and
/// no `try_map` of its own, and nothing turns one into a [`Verified`](crate::Verified):
/// that wrapper's constructor is crate-private and it carries no map, so the type an
/// acknowledgement cannot reach is the proven one.
///
/// **The unverified wrapper is not sealed the same way**, and the difference is worth
/// naming rather than glossed. [`ServerReported::try_map`] bounds neither what it maps
/// to nor what it maps from, so a caller holding any reported value can put an `Accepted`
/// inside one and hold a `ServerReported<Accepted>` whose proof bytes belong to the read
/// it was mapped from. Nothing in this library produces that value and nothing consumes
/// it, so what the shape offers a caller is a mislabel of their own making rather than a
/// route from an acknowledgement to a read.
///
/// **What an acknowledgement establishes.** This is an external fact about how a
/// liteserver behaves, not a property this tree checks, and it is written here because
/// it is the whole meaning of the value. The server that answered parsed the message,
/// resolved the account it addresses, ran it against that account in a state the server
/// itself holds, and the contract accepted it. A refusal at any of those stages comes
/// back as an error rather than as this value.
///
/// **What it does not establish is everything after that point.** Acceptance is not
/// inclusion. The server undertakes to propagate the message and answers before it has
/// done so, so whether the message reached a collator, whether a collator selected it,
/// and whether the block that took it was finalized are three further questions on
/// which this value is silent. It is also one server's word, checked against nothing.
///
/// What settles a send is reading its consequence back out of the chain, which is a
/// proven account read and not this.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Accepted {
    status: i32,
}

impl Accepted {
    /// Records that a server acknowledged a message with `status`.
    pub(crate) fn new(status: i32) -> Self {
        Self { status }
    }

    /// The integer the server sent with its acknowledgement.
    ///
    /// The protocol fixes no meaning for any particular value, and the reference node
    /// writes `1` at the single site where it builds this response, so on that
    /// implementation the number repeats what the value's existence already says. It is
    /// carried because a server is free to answer with a different one, and discarding
    /// it here would leave a caller no way to see that it had.
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }
}

/// A full block identifier: the id and its shard coordinates plus hashes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BlockIdExt {
    /// The workchain id, `-1` for the masterchain.
    pub workchain: i32,
    /// The shard prefix, `0x8000000000000000` for the masterchain.
    pub shard: u64,
    /// The block sequence number, a height.
    pub seqno: u32,
    /// The block root hash.
    pub root_hash: [u8; 32],
    /// The block file hash.
    pub file_hash: [u8; 32],
}

impl From<crate::tl::lite::BlockIdExt> for BlockIdExt {
    /// The sequence number is a height, so it becomes unsigned crossing into the domain.
    fn from(wire: crate::tl::lite::BlockIdExt) -> Self {
        Self {
            workchain: wire.workchain,
            shard: wire.shard,
            #[allow(
                clippy::cast_sign_loss,
                reason = "the liteserver wire carries seqno as TL's i32; this reinterprets those bits as the domain's u32, with no range check performed here"
            )]
            seqno: wire.seqno as u32,
            root_hash: wire.root_hash,
            file_hash: wire.file_hash,
        }
    }
}

impl From<&BlockIdExt> for crate::tl::lite::BlockIdExt {
    fn from(block: &BlockIdExt) -> Self {
        Self {
            workchain: block.workchain,
            shard: block.shard,
            #[allow(
                clippy::cast_possible_wrap,
                reason = "reinterprets the domain's u32 seqno back into the wire's i32 field for the TL encoding, with no range check performed here"
            )]
            seqno: block.seqno as i32,
            root_hash: block.root_hash,
            file_hash: block.file_hash,
        }
    }
}

impl BlockIdExt {
    /// Names a block by its five identifying parts.
    ///
    /// Reads hand these back, so a caller rarely builds one. The case that needs this is
    /// the one a verified read is for: an anchor block the caller learned somewhere other
    /// than from the server about to be checked. Without a way to name that block there
    /// is no way to check anything against it, and asking the server for its own anchor
    /// proves only that the server agrees with itself.
    ///
    /// For a masterchain block, `workchain` is `-1` and `shard` is `0x8000_0000_0000_0000`.
    #[must_use]
    pub fn new(
        workchain: i32,
        shard: u64,
        seqno: u32,
        root_hash: [u8; 32],
        file_hash: [u8; 32],
    ) -> Self {
        Self {
            workchain,
            shard,
            seqno,
            root_hash,
            file_hash,
        }
    }
}

/// A masterchain head as a liteserver reports it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MasterchainInfo {
    /// The last masterchain block the server knows.
    pub last: BlockIdExt,
    /// The masterchain state root hash.
    pub state_root_hash: [u8; 32],
}

/// An account's state as a liteserver reports it.
///
/// The state is raw bag-of-cells bytes. This crate neither reads the cell tree as a
/// balance, code, and data nor checks the proofs that came with it; both happen a layer
/// up, and the bytes are carried here so they can.
///
/// Two proofs come back for one read, and they chain. The account-state proof, kept on
/// the [`ServerReported`] wrapper, roots at [`shard_block`](Self::shard_block). The shard
/// proof kept here roots at [`block`](Self::block) and is what ties that shard block to
/// the masterchain, so a reader with a trusted masterchain hash can follow one to the
/// other. A masterchain account is already in the masterchain block, so its shard proof
/// is empty and its shard block is the block it was read at.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccountState {
    /// The masterchain block the state was read at.
    pub block: BlockIdExt,
    /// The shard block holding the account, equal to [`block`](Self::block) for a
    /// masterchain account.
    pub shard_block: BlockIdExt,
    /// The proof tying the shard block to the masterchain block, as raw bag-of-cells
    /// bytes. Empty for a masterchain account.
    pub shard_proof: Vec<u8>,
    /// The account state, as raw bag-of-cells bytes. Empty for an account that does not
    /// exist at the block.
    pub state: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::Accepted;

    // The reference node writes 1 at its one construction site, so 1 is the value that
    // tells a carried integer apart from nothing at all: an accessor answering a
    // constant reads the same as an accessor answering the field. The values away from
    // 1 are what the claim on `status` rests on.
    #[test]
    fn an_acknowledgement_carries_the_integer_the_server_sent() {
        assert_eq!(Accepted::new(1).status(), 1);
        assert_eq!(Accepted::new(0).status(), 0);
        assert_eq!(Accepted::new(-7).status(), -7);
    }
}
