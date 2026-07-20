//! Liteserver query and response TL types.
//!
//! These are the `liteServer.*` requests and responses the first release reads,
//! plus the shared block and account identifiers they carry. A request is wrapped
//! in a [`Query`], whose bytes then travel inside an [`crate::adnl::Message::Query`].
//!
//! Every response here is the server's word. This crate decodes it; it does not
//! verify the Merkle proofs a liteserver returns. Proof verification is a later
//! layer.

use tl_proto::{TlRead, TlWrite};

/// A full block identifier: the block's workchain and shard, its sequence number,
/// and its root and file hashes.
///
/// This is TON's `tonNode.blockIdExt`. It is a bare type: as a field of another
/// type it carries no constructor id.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockIdExt {
    /// The workchain id. The masterchain is `-1`.
    pub workchain: i32,
    /// The shard prefix as a 64-bit mask. The masterchain shard is
    /// `0x8000000000000000`.
    pub shard: u64,
    /// The block sequence number.
    pub seqno: i32,
    /// The block root hash.
    pub root_hash: [u8; 32],
    /// The block file hash.
    pub file_hash: [u8; 32],
}

/// A zero-state identifier: the genesis state of a workchain.
///
/// This is TON's `tonNode.zeroStateIdExt`, a bare type.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZeroStateIdExt {
    /// The workchain id.
    pub workchain: i32,
    /// The zero-state root hash.
    pub root_hash: [u8; 32],
    /// The zero-state file hash.
    pub file_hash: [u8; 32],
}

/// An account identifier: a workchain and a 256-bit account id.
///
/// This is TON's `liteServer.accountId`, a bare type.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId {
    /// The workchain id.
    pub workchain: i32,
    /// The 32-byte account id.
    pub id: [u8; 32],
}

/// The `liteServer.query` wrapper: a serialized liteserver request as bytes.
///
/// A liteserver method is serialized on its own, then placed in [`Query::data`] and
/// serialized again; those bytes are the payload of an
/// [`crate::adnl::Message::Query`].
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x798c06df)]
pub struct Query {
    /// The serialized liteserver request.
    pub data: Vec<u8>,
}

/// The `liteServer.getMasterchainInfo` request: ask for the current masterchain
/// head. It answers with a [`MasterchainInfo`].
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x89b5e62e)]
pub struct GetMasterchainInfo;

/// The `liteServer.getTime` request: ask for the server's current time. It answers
/// with a [`CurrentTime`].
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x16ad5a34)]
pub struct GetTime;

/// The `liteServer.getVersion` request: ask for the server's version and
/// capabilities. It answers with a [`Version`].
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x232b940b)]
pub struct GetVersion;

/// The `liteServer.getAccountState` request: ask for an account's state at a block.
/// It answers with an [`AccountState`].
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x6b890e25)]
pub struct GetAccountState {
    /// The masterchain block to read the account at.
    pub id: BlockIdExt,
    /// The account to read.
    pub account: AccountId,
}

/// The `liteServer.masterchainInfo` response: the server's current masterchain head.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x85832881)]
pub struct MasterchainInfo {
    /// The last masterchain block the server knows.
    pub last: BlockIdExt,
    /// The masterchain state root hash.
    pub state_root_hash: [u8; 32],
    /// The masterchain zero state.
    pub init: ZeroStateIdExt,
}

/// The `liteServer.currentTime` response: the server's current Unix time.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0xe953000d)]
pub struct CurrentTime {
    /// The server's current time, in seconds since the Unix epoch.
    pub now: i32,
}

/// The `liteServer.version` response: the server's protocol version and
/// capabilities.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x5a0491e5)]
pub struct Version {
    /// A mode flag word, reserved by the protocol.
    pub mode: u32,
    /// The liteserver version.
    pub version: i32,
    /// The capability bitmask.
    pub capabilities: i64,
    /// The server's current time, in seconds since the Unix epoch.
    pub now: i32,
}

/// The `liteServer.accountState` response: an account's state and its proofs.
///
/// The state and both proofs are raw bags-of-cells bytes. This crate does not parse
/// the cell tree or check the proofs.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x7079c751)]
pub struct AccountState {
    /// The masterchain block the state was read at.
    pub id: BlockIdExt,
    /// The shard block that holds the account.
    pub shardblk: BlockIdExt,
    /// The proof linking the masterchain block to the shard block, as raw BoC bytes.
    pub shard_proof: Vec<u8>,
    /// The proof of the account state within the shard block, as raw BoC bytes.
    pub proof: Vec<u8>,
    /// The account state, as raw BoC bytes.
    pub state: Vec<u8>,
}

/// The `liteServer.error` response: an error a liteserver returns in place of a
/// result.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0xbba9e148)]
pub struct Error {
    /// The liteserver error code.
    pub code: i32,
    /// The human-readable error message, as UTF-8 bytes.
    pub message: Vec<u8>,
}
