// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

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
//! What the block in `anchor` is worth depends on where it came from, and that is what
//! `sync()` settles. It walks from the key block the config names to the network's
//! current head, checking a validator signature set at every step, so `account()` proves
//! against a block this client derived rather than one a server offered. The block it
//! ends on comes back from `anchor()`; saving it and handing it to `connectFrom` is what
//! makes a later run cheap. Nothing is stored here: a block identity is two buffers, and
//! where it lives is the caller's decision, because whatever can write to it can choose
//! what a later client believes.
//!
//! The one connection is held behind an async mutex, so overlapping calls from
//! JavaScript run one after another over the single channel rather than corrupting it.
#![deny(unsafe_code)]
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

/// What every call returns: a value, or an exception whose message opens with a code.
type Result<T> = napi::Result<T>;

/// Maps a facade error to a JavaScript exception, keeping which kind it was.
///
/// # Telling one failure from another
///
/// The message of every exception this crate throws opens with a stable code, an upper
/// case token followed by `": "`. That prefix is a contract and will not change with the
/// wording after it:
///
/// ```js
/// const code = (error) => String(error.message).split(":", 1)[0];
/// try {
///   await client.account(address);
/// } catch (error) {
///   if (code(error) === "PROOF") throw error;   // this server is lying; do not retry it
///   if (code(error) === "TRANSPORT") retry();   // the socket dropped; the server may be fine
/// }
/// ```
///
/// A caller needs this, because trying another server is the right answer to some of
/// these and the wrong answer to others, and a client that retries a server which failed
/// to prove its answer is doing the opposite of what this library is for.
///
/// The prefix carries it rather than `error.code`, which would be the natural place,
/// because napi fixes the status of anything returned from an async function to its own
/// enum, and every call here is async. When that changes, the code moves to `error.code`
/// and this prefix stays where it is.
fn to_js(error: ton_net::Error) -> napi::Error {
    // The names come from the core rather than from a table kept here. This was a match
    // per variant ending in a wildcard, and the wildcard was the defect: a variant added
    // to the facade would have gone on compiling and arrived in JavaScript as UNKNOWN.
    // The core's own match has no wildcard, so that case is a build failure there now,
    // and every later binding reads the same list instead of writing its own.
    let code = error.code().as_str();
    // Several of the facade's messages already open with a lowercase kind, which the code
    // now says better. Printing both would stutter: "PROOF: proof: no merkle proof".
    let text = error.to_string();
    let text = text
        .strip_prefix(&format!("{}: ", code.to_lowercase()))
        .unwrap_or(&text);
    napi::Error::new(napi::Status::GenericFailure, format!("{code}: {text}"))
}

/// An exception for an argument this crate refused before any call was made.
///
/// Carries napi's own `InvalidArg` status as well as the message prefix, since this one
/// failure is the caller's rather than the network's and `error.code` can say so.
fn invalid(reason: String) -> napi::Error {
    // Spelled by the core even though no core error carries it, so that this binding and
    // the ones after it name the caller's own mistake the same way.
    let code = ton_net::ErrorCode::InvalidArgument.as_str();
    napi::Error::new(napi::Status::InvalidArg, format!("{code}: {reason}"))
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
    pub fn from_json(json: String) -> Result<Config> {
        Ok(Config {
            inner: ton_net::Config::from_json(&json).map_err(to_js)?,
        })
    }

    /// Returns the same config with a different bound on how old a proven head may be.
    ///
    /// The default is generous, because a first sync takes a couple of minutes and the
    /// head it lands on was read before the walk began. A caller who knows their server
    /// is current, and who is reading a balance before acting on it, wants it tighter:
    /// this is the only thing standing between a client and a server that proves a real
    /// block from last week, since nothing inside a proof says when it was served.
    ///
    /// Zero refuses every head, which is a way to say the client should not proceed on a
    /// proven read at all.
    #[napi]
    #[must_use]
    pub fn with_max_head_age(&self, seconds: u32) -> Config {
        Config {
            inner: self.inner.clone().with_max_head_age(seconds),
        }
    }

    /// How old a proven head may be before a sync refuses it, in seconds.
    #[napi(getter)]
    #[must_use]
    pub fn max_head_age(&self) -> u32 {
        self.inner.max_head_age()
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

/// What one sync reached and what it cost.
#[napi(object)]
pub struct SyncReport {
    /// The head the walk proved. It is proved for the caller that asked and not kept:
    /// what the client keeps is the last key block on the way, from `anchor()`.
    pub head: BlockId,
    /// How many links were checked, each one a validator signature set.
    pub links: u32,
    /// How many replies the server took to finish the chain.
    pub rounds: u32,
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
/// Nothing this crate returns in this shape skipped the check. The shape itself is not a
/// guarantee, though, and the difference matters to anyone building on top: the Rust
/// `Verified<T>` has a private constructor and cannot be forged, while this crosses as a
/// plain object, so JavaScript being what it is, any `{ value, anchor }` a caller
/// assembles is indistinguishable from one that came from here. Treat it as a label on
/// this crate's output, not as a check on an object of unknown origin.
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
    pub async fn connect(config: &Config) -> Result<TonClient> {
        let network = config.inner.clone();
        let client = ton_net::Client::connect(&network).await.map_err(to_js)?;
        Ok(TonClient {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// Connects and starts the walk from a key block proven on an earlier run.
    ///
    /// `anchor` is this client's root of trust: everything it goes on to believe is
    /// derived from that block, so it is worth exactly what the storage it came from is
    /// worth. Anything that can write to where a caller keeps one can choose what this
    /// client believes. The binding stores nothing and picks no location; a `BlockId` is
    /// an object with two buffers, and where it lives is the caller's decision.
    #[napi]
    pub async fn connect_from(config: &Config, anchor: BlockId) -> Result<TonClient> {
        let network = config.inner.clone();
        let start = block_id_ext(&anchor)?;
        let client = ton_net::Client::connect_from(&network, &start)
            .await
            .map_err(to_js)?;
        Ok(TonClient {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// The key block this client's trust rests on, or null before it has synced.
    ///
    /// Save it and hand it to `connectFrom` on a later run to make that run's sync short.
    #[napi]
    pub async fn anchor(&self) -> Option<BlockId> {
        let client = self.inner.lock().await;
        client.anchor().map(block_id)
    }

    /// Walks the anchor forward to the network's current head.
    ///
    /// Without an anchor the walk starts at the config's init block, which is a first
    /// sync and runs over every key block published since: minutes and tens of megabytes
    /// against mainnet. With one it is a link or two.
    #[napi]
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut client = self.inner.lock().await;
        let report = client.sync().await.map_err(to_js)?;
        Ok(SyncReport {
            head: block_id(&report.head),
            links: report.links as u32,
            rounds: report.rounds as u32,
        })
    }

    /// Reads the liteserver's current masterchain head.
    #[napi]
    pub async fn masterchain_info(&self) -> Result<ReportedMasterchainInfo> {
        let mut client = self.inner.lock().await;
        let reported = client.masterchain_info().await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        Ok(ReportedMasterchainInfo {
            value: block_id(&reported.into_value().last),
            proof,
        })
    }

    /// Reads an account and proves it against a block this client established itself.
    ///
    /// `address` is a raw `workchain:hex` or user-friendly base64 address. Walks the
    /// chain to a current head, reads the account there, and checks the proofs against
    /// it, so nothing in the result rests on a block the caller supplied. The first call
    /// pays for the walk; save `anchor()` and pass it to `connectFrom` next time.
    ///
    /// Every call walks. A caller reading several accounts should `sync()` once and pass
    /// that head to `accountAt` rather than pay for a walk per account.
    #[napi]
    pub async fn account(&self, address: String) -> Result<VerifiedAccount> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let mut client = self.inner.lock().await;
        let verified = client.account(&parsed).await.map_err(to_js)?;
        Ok(VerifiedAccount {
            anchor: block_id(verified.anchor()),
            value: account(verified.into_value()),
        })
    }

    /// Reads an account at the current masterchain head without checking anything.
    ///
    /// The result is the server's word: the proof it sent comes back alongside,
    /// unchecked. It is named for what it is, because the proven read is the one a caller
    /// lands on without choosing and this is the exception.
    #[napi]
    pub async fn account_reported(&self, address: String) -> Result<ReportedAccount> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let mut client = self.inner.lock().await;
        let reported = client.account_reported(&parsed).await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        Ok(ReportedAccount {
            value: account(reported.into_value()),
            proof,
        })
    }

    /// Reads an account at a block the caller names, and proves it belongs to that block.
    ///
    /// The proofs are checked against `trusted`'s root hash, and for an account outside
    /// the masterchain the shard block holding it is derived from the masterchain state
    /// rather than taken from what the server named. A proof that does not check out
    /// rejects; there is no unproved fallback. An account the block's state does not hold
    /// comes back as `nonexistent`, which is a proved answer rather than a failure.
    ///
    /// `trusted` is taken on faith, so where it came from is the whole question. Taking it
    /// from `masterchainInfo` on this same client proves nothing: that only shows the
    /// server agrees with itself. The two sources that mean something are a block this
    /// client proved, from `sync()` or `anchor()`, and a block the caller trusts
    /// independently.
    #[napi]
    pub async fn account_at(&self, address: String, trusted: BlockId) -> Result<VerifiedAccount> {
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
    ) -> Result<ReportedAccountState> {
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
/// `account` reads and proves in one call, and is what most callers want. This is
/// the same check on its own, for the case where the bytes and the anchor arrive
/// separately: bytes fetched now with `accountState` and an anchor that turns up later, or
/// bytes handed over by something that is not this client at all.
///
/// The check reaches no network and depends on nothing but its argument, so the same
/// bytes always give the same answer. It throws if the proof does not root at the trusted
/// hash, or if the account does not bind to it.
#[napi]
pub fn verify_account(read: AccountRead) -> Result<Account> {
    let parsed = ton_net::Address::parse(&read.address).map_err(to_js)?;
    let anchor = hash(&read.trusted_root_hash, "trustedRootHash")?;
    let shard_proof = read.shard_proof.unwrap_or_default();

    let checked = if parsed.workchain() == MASTERCHAIN {
        ton_net::AccountRead::masterchain(&anchor, parsed.account_id(), &read.proof, &read.state)
    } else if shard_proof.is_empty() {
        // Without it there is no step tying the shard to the trusted block. Saying so
        // beats letting empty bytes fail later as bytes that are not cells, which points
        // at the wrong thing.
        return Err(invalid(
            "shardProof is required outside the masterchain".to_string(),
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
/// The shard and the two hashes are checked here rather than deeper in, because a short
/// hash silently padded or a shard read in the wrong base would send a read at a block the
/// caller did not mean.
///
/// The shard is required to be sixteen hex digits, which is what this crate writes on the
/// way out. Shorter is a shard that would once have parsed, and a decimal shard from
/// another library is the case that matters: sixteen decimal digits are also valid hex,
/// so without the check they would be read as a different shard without complaint.
///
/// `workchain` and `seqno` are not checked and cannot be, because JavaScript numbers
/// reach a `u32` and an `i32` through the language's own coercion: -1 arrives as
/// 4294967295 and a fraction arrives truncated, with nothing left for this code to see.
/// They are safe to leave because neither reaches a proof. Verification anchors on
/// `rootHash` alone, so a mangled height asks about the wrong block and gets an error,
/// never a wrong answer that verifies.
fn block_id_ext(id: &BlockId) -> Result<ton_net::BlockIdExt> {
    let shard = id.shard.strip_prefix("0x").unwrap_or(&id.shard);
    if shard.len() != 16 || !shard.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "shard must be 16 hex digits, got {:?}",
            id.shard
        )));
    }
    let shard = u64::from_str_radix(shard, 16)
        .map_err(|_| invalid(format!("shard is not a hex u64: {:?}", id.shard)))?;
    Ok(ton_net::BlockIdExt::new(
        id.workchain,
        shard,
        id.seqno,
        hash(&id.root_hash, "rootHash")?,
        hash(&id.file_hash, "fileHash")?,
    ))
}

/// Reads a 32-byte hash out of a Buffer, naming the field when the length is wrong.
fn hash(bytes: &[u8], field: &str) -> Result<[u8; HASH_LEN]> {
    <[u8; HASH_LEN]>::try_from(bytes).map_err(|_| {
        invalid(format!(
            "{field} must be {HASH_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}
