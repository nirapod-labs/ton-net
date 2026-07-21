//! Liteserver query and response TL types.
//!
//! These are the `liteServer.*` requests and responses the client reads, plus the
//! shared block and account identifiers they carry. A request is wrapped in a
//! [`Query`], whose bytes then travel inside an [`crate::adnl::Message::Query`].
//!
//! Every response here is the server's word. This crate decodes it and checks nothing,
//! neither the Merkle proofs nor the validator signatures a liteserver returns.
//! Verification belongs to `ton-net-block`, over the types decoded here.

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

/// The `liteServer.getBlockProof` request: ask a server to connect a block the client
/// already trusts to a later one. It answers with a [`PartialBlockProof`].
///
/// The `mode` word on the wire is a flag set, and its only flag says whether a target
/// block follows. It is derived from [`target_block`](Self::target_block) rather than
/// carried, so the two cannot disagree. With no target the server picks one, which is
/// not what a client walking towards a known head wants.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x8aea9c44)]
pub struct GetBlockProof {
    /// The wire flag word, written from the fields below and discarded on read.
    #[tl(flags)]
    pub mode: (),
    /// The block the client already trusts, which the proof starts from.
    pub known_block: BlockIdExt,
    /// The block to prove, or `None` to let the server choose one.
    #[tl(flags_bit = 0)]
    pub target_block: Option<BlockIdExt>,
}

/// One validator's signature, in the `liteServer.signature` bare form.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The signer's short id: SHA-256 of its key in the `pub.ed25519` TL form, the
    /// same computation the ADNL handshake performs on a server key.
    pub node_id_short: [u8; 32],
    /// The 64-byte ed25519 signature.
    pub signature: Vec<u8>,
}

/// A `liteServer.SignatureSet`: what a set of validator signatures covers.
///
/// Mainnet has used two forms. [`Ordinary`](Self::Ordinary) signs a block identity
/// directly. [`Simplex`](Self::Simplex) comes from TON's Simplex consensus and signs a
/// vote naming a candidate, so the block is reached through the candidate rather than
/// signed outright. Mainnet changed form at masterchain block 59379986, and a chain
/// spanning that point carries both.
///
/// The two arms are not interchangeable: their first two integer fields are in the
/// opposite order, so reading one as the other silently swaps them. The constructor id
/// is what tells them apart, and a third form no version of this client knows is
/// refused by [`TlError::UnknownConstructor`](crate::TlError::UnknownConstructor)
/// rather than read as either.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed)]
#[non_exhaustive]
pub enum SignatureSet {
    /// The original form. The signatures cover a [`crate::signed::BlockId`].
    ///
    /// Its scheme line carries an explicit constructor id, which is exactly the id the
    /// older unnamed `liteServer.signatureSet` line computes to. The union was added
    /// without moving the wire form a client already spoke.
    #[tl(id = 0xf644a6e6)]
    Ordinary {
        /// A short hash of the validator set that signed.
        validator_set_hash: i32,
        /// The catchain sequence number the set belongs to.
        catchain_seqno: i32,
        /// The signatures.
        signatures: Vec<Signature>,
    },
    /// The Simplex form. The signatures cover a [`crate::signed::DataToSign`] wrapping
    /// a finalize vote, built from `session_id`, `slot`, and the hash of `candidate`.
    #[tl(id = 0xac249800)]
    Simplex {
        /// The catchain sequence number the set belongs to.
        cc_seqno: i32,
        /// A short hash of the validator set that signed.
        validator_set_hash: i32,
        /// The signatures.
        signatures: Vec<Signature>,
        /// The consensus session the vote belongs to. It is signed alongside the vote,
        /// so a signature raised in one session cannot be replayed into another.
        session_id: [u8; 32],
        /// The slot the candidate was proposed for.
        slot: i32,
        /// The serialized `consensus.CandidateHashData` the vote names, kept as bytes
        /// because the vote covers its hash and never needs it decoded.
        candidate: Vec<u8>,
    },
}

impl SignatureSet {
    /// The signatures the set carries, whichever form it takes.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        match self {
            SignatureSet::Ordinary { signatures, .. }
            | SignatureSet::Simplex { signatures, .. } => signatures,
        }
    }
}

/// A `liteServer.BlockLink`: one step of a block proof chain.
///
/// A [`Forward`](Self::Forward) step goes from a key block to a later block and is
/// carried by the signatures of the validator set that key block named. A
/// [`Back`](Self::Back) step goes the other way and cannot use signatures, because a
/// block is not signed by validators who came later; it shows instead that the
/// destination is recorded in the source block's state.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed)]
#[non_exhaustive]
pub enum BlockLink {
    /// A step backwards, proved from the source block's state.
    #[tl(id = 0xef7e1bef)]
    Back {
        /// Whether the destination is a key block.
        to_key_block: bool,
        /// The block the step starts from.
        from: BlockIdExt,
        /// The block the step ends at.
        to: BlockIdExt,
        /// A proof of the destination block's header, as raw bag-of-cells bytes.
        dest_proof: Vec<u8>,
        /// A proof of the source block, as raw bag-of-cells bytes.
        proof: Vec<u8>,
        /// A proof of the source block's state, holding its list of previous
        /// masterchain blocks, as raw bag-of-cells bytes.
        state_proof: Vec<u8>,
    },
    /// A step forwards, carried by validator signatures.
    #[tl(id = 0x520fce1c)]
    Forward {
        /// Whether the destination is a key block.
        to_key_block: bool,
        /// The key block the step starts from.
        from: BlockIdExt,
        /// The block the step ends at.
        to: BlockIdExt,
        /// A proof of the destination block's header, as raw bag-of-cells bytes.
        dest_proof: Vec<u8>,
        /// A proof of the source key block's configuration, which is where the
        /// validator set that signed comes from, as raw bag-of-cells bytes.
        config_proof: Vec<u8>,
        /// The signatures over the destination.
        signatures: SignatureSet,
    },
}

/// The `liteServer.partialBlockProof` response: as much of a proof chain as the server
/// chose to send at once.
///
/// The server picks the route. A client validates every step of it and believes
/// nothing about the route itself, including whether it runs forwards.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x8ed0d2c1)]
pub struct PartialBlockProof {
    /// Whether the chain reaches the requested target. When it does not, the caller
    /// asks again from [`to`](Self::to).
    pub complete: bool,
    /// The block the chain starts from.
    pub from: BlockIdExt,
    /// The block the chain reaches.
    pub to: BlockIdExt,
    /// The steps, in order.
    pub steps: Vec<BlockLink>,
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
