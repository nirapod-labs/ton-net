//! The domain response types and the unverified-read wrapper.
//!
//! These are the cleaned-up forms of the liteserver wire types: a reader sees a block
//! sequence number as an unsigned height, an account read as a block and a state, and
//! the proof bytes set aside in [`ServerReported`] rather than mixed into the value.
//! Each is `#[non_exhaustive]` so fields can be added before 1.0 without a breaking
//! change.

/// A value a liteserver returned without a checked proof.
///
/// In this release the client does not verify the Merkle proofs a liteserver sends, so
/// every read is the server's unproven word. This wrapper keeps that fact in the type: a
/// caller reaches the inner value through [`value`](Self::value) or
/// [`into_value`](Self::into_value) and cannot mistake it for verified state.
///
/// The raw proof bytes the server sent are kept by [`proof`](Self::proof) so a later
/// release can check them without another round trip.
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
/// The state is raw bag-of-cells bytes. This client does not parse the cell tree into a
/// balance, code, and data, nor check the proofs the server sent alongside it.
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
