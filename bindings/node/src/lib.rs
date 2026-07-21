//! Node.js binding for the ton-net TON client.
//!
//! This crate wraps the `ton-net` facade with napi-rs. Reads cross the FFI boundary as
//! JavaScript-native shapes: a u64 shard becomes a lowercase hex string, block heights are
//! numbers, hashes and cells are Buffers, and an amount or a logical time is a decimal
//! string because either can run past what a JavaScript number holds exactly.
//!
//! Whether a read was proved stays visible in the shape. A `{ value, proof }` object is
//! the server's word with the proof it sent, unchecked. A `{ value, anchor }` object was
//! proved against the block in `anchor`. The two are never the same shape, so a caller
//! cannot mistake one for the other.
//!
//! The one connection is held behind an async mutex, so overlapping calls from
//! JavaScript run one after another over the single channel rather than corrupting it.
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::sync::Arc;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use tokio::sync::Mutex;

/// The length of every hash that crosses the boundary.
const HASH_LEN: usize = 32;

/// The workchain id of the masterchain.
const MASTERCHAIN: i32 = -1;

/// Maps a facade error to a JavaScript exception.
fn to_js<E: std::fmt::Display>(error: E) -> napi::Error {
    napi::Error::from_reason(error.to_string())
}

/// The public network parameters a client needs to reach TON.
#[napi]
pub struct Config {
    inner: ton_net::Config,
}

#[napi]
impl Config {
    /// Returns a config for TON mainnet from a bundled snapshot.
    #[napi(factory)]
    pub fn mainnet() -> Config {
        Config {
            inner: ton_net::Config::mainnet(),
        }
    }

    /// Parses a config from the TON `global.config.json` format.
    #[napi(factory)]
    pub fn from_json(json: String) -> napi::Result<Config> {
        Ok(Config {
            inner: ton_net::Config::from_json(&json).map_err(to_js)?,
        })
    }
}

/// The full identity of a block.
///
/// This crosses in both directions: it comes back from a read, and it goes in as the
/// block a verified read is proved against.
#[napi(object)]
pub struct BlockId {
    /// The workchain id, `-1` for the masterchain.
    pub workchain: i32,
    /// The shard prefix as a 16-digit lowercase hex string; a u64 does not fit a JS number.
    ///
    /// Read back in this form. Accepted on the way in with or without a `0x` prefix.
    pub shard: String,
    /// The block sequence number.
    pub seqno: u32,
    /// The block root hash, 32 bytes.
    pub root_hash: Buffer,
    /// The block file hash, 32 bytes.
    pub file_hash: Buffer,
}

/// An account, decoded.
#[napi(object)]
pub struct Account {
    /// The balance in nanotons, as a decimal string.
    ///
    /// A string rather than a number: mainnet balances run past what a JavaScript number
    /// holds exactly, so a number would round some of them silently.
    pub balance: String,
    /// The account status: `nonexistent`, `uninit`, `frozen`, or `active`.
    pub status: String,
    /// The logical time just after the account's last transaction, as a decimal string.
    ///
    /// One past the logical time of that transaction itself, so it will not equal the
    /// last transaction's own logical time as an explorer reports it.
    pub last_trans_lt: String,
    /// The contract code as a bag of cells, present only for an active account.
    pub code: Option<Buffer>,
    /// The contract data as a bag of cells, present only for an active account.
    pub data: Option<Buffer>,
    /// The hash of the state the account had when it froze, present only when frozen.
    pub state_hash: Option<Buffer>,
}

/// The raw bytes of an account read, as the server sent them.
#[napi(object)]
pub struct AccountState {
    /// The masterchain block the state was read at.
    pub block: BlockId,
    /// The shard block the server says holds the account.
    ///
    /// The server's word, and not what a check relies on: verification derives the shard
    /// block from the masterchain state instead of believing this.
    pub shard_block: BlockId,
    /// The proof tying the shard block to the masterchain block. Empty in the masterchain.
    pub shard_proof: Buffer,
    /// The account state as a bag of cells. Empty for an account that does not exist.
    pub state: Buffer,
}

/// A masterchain head with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedMasterchainInfo {
    /// The head block's id, not proof-verified.
    pub value: BlockId,
    /// The raw proof bytes, still unchecked; empty for this response.
    pub proof: Buffer,
}

/// An account with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedAccount {
    /// The reported value, not proof-verified.
    pub value: Account,
    /// The raw proof bytes the server sent, still unchecked.
    pub proof: Buffer,
}

/// An account's raw state with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedAccountState {
    /// The reported bytes, not proof-verified.
    pub value: AccountState,
    /// The raw proof bytes the server sent, still unchecked.
    pub proof: Buffer,
}

/// An account proved to sit in the state of a block the caller trusts.
///
/// There is no way to build one of these from a reported read: the shape exists only on
/// the way out of a check that passed.
#[napi(object)]
pub struct VerifiedAccount {
    /// The proved account.
    pub value: Account,
    /// The block the account was proved against.
    pub anchor: BlockId,
}

/// One account read as a server answered it, ready to be checked.
#[napi(object)]
pub struct AccountRead {
    /// The account's address, raw `workchain:hex` or user-friendly base64.
    pub address: String,
    /// The root hash of the masterchain block the caller trusts, 32 bytes.
    pub trusted_root_hash: Buffer,
    /// The proof tying the account's shard block to the trusted block.
    ///
    /// Required outside the masterchain, where it is the step that ties the shard to a
    /// block the caller trusts. Ignored for a masterchain account, which is in that
    /// block's own state.
    pub shard_proof: Option<Buffer>,
    /// The account-state proof the server sent.
    pub proof: Buffer,
    /// The account state as a bag of cells.
    pub state: Buffer,
}

/// A connection to a single TON liteserver.
///
/// Reads run one at a time over the single channel: the connection is behind an async
/// mutex, so overlapping calls from JavaScript serialize rather than corrupt the stream.
#[napi]
pub struct TonClient {
    inner: Arc<Mutex<ton_net::Client>>,
}

#[napi]
impl TonClient {
    /// Connects to a liteserver from the config and completes the ADNL handshake.
    #[napi]
    pub async fn connect(config: &Config) -> napi::Result<TonClient> {
        let network = config.inner.clone();
        let client = ton_net::Client::connect(&network).await.map_err(to_js)?;
        Ok(TonClient {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// Reads the liteserver's current masterchain head.
    #[napi]
    pub async fn masterchain_info(&self) -> napi::Result<ReportedMasterchainInfo> {
        let mut client = self.inner.lock().await;
        let reported = client.masterchain_info().await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        Ok(ReportedMasterchainInfo {
            value: block_id(&reported.into_value().last),
            proof,
        })
    }

    /// Reads and decodes an account at the current masterchain head.
    ///
    /// `address` is a raw `workchain:hex` or user-friendly base64 address. The result is
    /// the server's word: the proof it sent comes back alongside, unchecked. To have that
    /// proof checked, use `accountVerified`.
    #[napi]
    pub async fn account(&self, address: String) -> napi::Result<ReportedAccount> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let mut client = self.inner.lock().await;
        let reported = client.account_reported(&parsed).await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        Ok(ReportedAccount {
            value: account(reported.into_value()),
            proof,
        })
    }

    /// Reads an account at a block the caller trusts, and proves it belongs to that block.
    ///
    /// The proofs are checked against `trusted`'s root hash, and for an account outside
    /// the masterchain the shard block holding it is derived from the masterchain state
    /// rather than taken from what the server named. A proof that does not check out
    /// rejects; there is no unproved fallback. An account the block's state does not hold
    /// comes back as `nonexistent`, which is a proved answer rather than a failure.
    ///
    /// `trusted` is the one input taken on faith, and taking it from `masterchainInfo` on
    /// this same client proves nothing: that only shows the server agrees with itself. It
    /// has to come from somewhere the caller trusts independently.
    #[napi]
    pub async fn account_verified(
        &self,
        address: String,
        trusted: BlockId,
    ) -> napi::Result<VerifiedAccount> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let anchor = block_id_ext(&trusted)?;
        let mut client = self.inner.lock().await;
        let verified = client.account_at(&parsed, &anchor).await.map_err(to_js)?;
        Ok(VerifiedAccount {
            anchor: block_id(verified.anchor()),
            value: account(verified.into_value()),
        })
    }

    /// Reads an account's raw state and proofs at a given block.
    ///
    /// The bytes come back as the server sent them, unchecked and undecoded. This is the
    /// way out for a caller who wants to keep the proofs, check them elsewhere, or check
    /// them against an anchor obtained later, with `verifyAccount`.
    #[napi]
    pub async fn account_state(
        &self,
        address: String,
        block: BlockId,
    ) -> napi::Result<ReportedAccountState> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let at = block_id_ext(&block)?;
        let mut client = self.inner.lock().await;
        let reported = client.account_state(&parsed, &at).await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        let state = reported.into_value();
        Ok(ReportedAccountState {
            value: AccountState {
                block: block_id(&state.block),
                shard_block: block_id(&state.shard_block),
                shard_proof: Buffer::from(state.shard_proof),
                state: Buffer::from(state.state),
            },
            proof,
        })
    }
}

/// Proves an account read against the block hash the read was checked to.
///
/// `accountVerified` reads and proves in one call, and is what most callers want. This is
/// the same check on its own, for the case where the bytes and the anchor arrive
/// separately: bytes fetched now with `accountState` and an anchor that turns up later, or
/// bytes handed over by something that is not this client at all.
///
/// The check reaches no network and depends on nothing but its argument, so the same
/// bytes always give the same answer. It throws if the proof does not root at the trusted
/// hash, or if the account does not bind to it.
#[napi]
pub fn verify_account(read: AccountRead) -> napi::Result<Account> {
    let parsed = ton_net::Address::parse(&read.address).map_err(to_js)?;
    let anchor = hash(&read.trusted_root_hash, "trustedRootHash")?;
    let shard_proof = read.shard_proof.unwrap_or_default();

    let checked = if parsed.workchain() == MASTERCHAIN {
        ton_net::AccountRead::masterchain(&anchor, parsed.account_id(), &read.proof, &read.state)
    } else if shard_proof.is_empty() {
        // Without it there is no step tying the shard to the trusted block. Saying so
        // beats letting empty bytes fail later as bytes that are not cells, which points
        // at the wrong thing.
        return Err(napi::Error::from_reason(
            "shardProof is required outside the masterchain",
        ));
    } else {
        ton_net::AccountRead::in_shard(
            &anchor,
            parsed.workchain(),
            parsed.account_id(),
            &shard_proof,
            &read.proof,
            &read.state,
        )
    };
    Ok(account(ton_net::verify_account(&checked).map_err(to_js)?))
}

/// Maps a decoded account across the boundary.
fn account(account: ton_net::Account) -> Account {
    use ton_net::AccountStatus;

    let status = match &account.status {
        AccountStatus::Nonexistent => "nonexistent",
        AccountStatus::Uninit => "uninit",
        AccountStatus::Frozen { .. } => "frozen",
        AccountStatus::Active { .. } => "active",
        // A status added to the core after this binding was built. Naming it rather than
        // guessing keeps a caller from reading a new state as one of the old ones.
        _ => "unknown",
    };
    let state_hash = match &account.status {
        // All that is left of a frozen account, so dropping it would leave a caller
        // nothing to identify the state it froze in.
        AccountStatus::Frozen { state_hash } => Some(Buffer::from(state_hash.to_vec())),
        _ => None,
    };
    let boc =
        |cell: Option<&ton_net::Cell>| cell.and_then(|cell| cell.to_boc().ok()).map(Buffer::from);

    Account {
        balance: account.balance.to_string(),
        status: status.to_string(),
        last_trans_lt: account.last_trans_lt.to_string(),
        code: boc(account.code()),
        data: boc(account.data()),
        state_hash,
    }
}

/// Maps a block id out to JavaScript.
fn block_id(id: &ton_net::BlockIdExt) -> BlockId {
    BlockId {
        workchain: id.workchain,
        shard: format!("{:016x}", id.shard),
        seqno: id.seqno,
        root_hash: Buffer::from(id.root_hash.to_vec()),
        file_hash: Buffer::from(id.file_hash.to_vec()),
    }
}

/// Reads a block id back in from JavaScript.
///
/// Every field is checked here rather than deeper in, because a short hash silently
/// padded or a shard misread as zero would send a read at a block the caller did not mean
/// and prove the answer against it.
fn block_id_ext(id: &BlockId) -> napi::Result<ton_net::BlockIdExt> {
    let shard = id.shard.strip_prefix("0x").unwrap_or(&id.shard);
    let shard = u64::from_str_radix(shard, 16)
        .map_err(|_| napi::Error::from_reason(format!("shard is not a hex u64: {:?}", id.shard)))?;
    Ok(ton_net::BlockIdExt::new(
        id.workchain,
        shard,
        id.seqno,
        hash(&id.root_hash, "rootHash")?,
        hash(&id.file_hash, "fileHash")?,
    ))
}

/// Reads a 32-byte hash out of a Buffer, naming the field when the length is wrong.
fn hash(bytes: &[u8], field: &str) -> napi::Result<[u8; HASH_LEN]> {
    <[u8; HASH_LEN]>::try_from(bytes).map_err(|_| {
        napi::Error::from_reason(format!(
            "{field} must be {HASH_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}
