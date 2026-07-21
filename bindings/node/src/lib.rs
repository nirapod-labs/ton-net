//! Node.js binding for the ton-net TON client.
//!
//! This crate wraps the `ton-net` facade with napi-rs. Reads cross the FFI boundary as
//! JavaScript-native shapes: a u64 shard becomes a lowercase hex string, block heights are
//! numbers, hashes and cells are Buffers, and an amount or a logical time is a decimal
//! string because either can run past what a JavaScript number holds exactly. Every read
//! is a `{ value, proof }` object, so the unverified nature of a liteserver read stays
//! visible on the JS side.
//!
//! The one connection is held behind an async mutex, so overlapping calls from
//! JavaScript run one after another over the single channel rather than corrupting it.
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::sync::Arc;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use tokio::sync::Mutex;

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

/// A masterchain head as a liteserver reports it.
#[napi(object)]
pub struct MasterchainInfo {
    /// The workchain id, `-1` for the masterchain.
    pub workchain: i32,
    /// The shard prefix as a 16-digit lowercase hex string; a u64 does not fit a JS number.
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
    pub last_trans_lt: String,
    /// The contract code as a bag of cells, present only for an active account.
    pub code: Option<Buffer>,
    /// The contract data as a bag of cells, present only for an active account.
    pub data: Option<Buffer>,
}

/// A masterchain head with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedMasterchainInfo {
    /// The reported value, not proof-verified.
    pub value: MasterchainInfo,
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
        Ok(reported_masterchain_info(reported))
    }

    /// Reads and decodes an account at the current masterchain head.
    ///
    /// `address` is a raw `workchain:hex` or user-friendly base64 address. The result is
    /// the server's word: the proof it sent comes back alongside, unchecked.
    #[napi]
    pub async fn account(&self, address: String) -> napi::Result<ReportedAccount> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let mut client = self.inner.lock().await;
        let reported = client.account(&parsed).await.map_err(to_js)?;
        let proof = Buffer::from(reported.proof().to_vec());
        Ok(ReportedAccount {
            value: account(reported.into_value()),
            proof,
        })
    }
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
    let boc =
        |cell: Option<&ton_net::Cell>| cell.and_then(|cell| cell.to_boc().ok()).map(Buffer::from);

    Account {
        balance: account.balance.to_string(),
        status: status.to_string(),
        last_trans_lt: account.last_trans_lt.to_string(),
        code: boc(account.code()),
        data: boc(account.data()),
    }
}

fn reported_masterchain_info(
    reported: ton_net::ServerReported<ton_net::MasterchainInfo>,
) -> ReportedMasterchainInfo {
    let proof = Buffer::from(reported.proof().to_vec());
    let info = reported.into_value();
    let last = info.last;
    ReportedMasterchainInfo {
        value: MasterchainInfo {
            workchain: last.workchain,
            shard: format!("{:016x}", last.shard),
            seqno: last.seqno,
            root_hash: Buffer::from(last.root_hash.to_vec()),
            file_hash: Buffer::from(last.file_hash.to_vec()),
        },
        proof,
    }
}
