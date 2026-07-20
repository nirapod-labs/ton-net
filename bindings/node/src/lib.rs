//! Node.js binding for the ton-net TON client.
//!
//! This crate wraps the `ton-net` facade with napi-rs. Reads cross the FFI boundary as
//! JavaScript-native shapes: a u64 shard becomes a lowercase hex string, block heights
//! are numbers, and hashes and raw state are Buffers. Every read is a `{ value, proof }`
//! object, so the unverified nature of a liteserver read stays visible on the JS side.
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

/// An account's state as a liteserver reports it.
#[napi(object)]
pub struct AccountState {
    /// The workchain of the block the state was read at.
    pub workchain: i32,
    /// The shard of that block, as a 16-digit lowercase hex string.
    pub shard: String,
    /// The sequence number of that block.
    pub seqno: u32,
    /// The account state as raw bag-of-cells bytes, not decoded in this release.
    pub state: Buffer,
}

/// A masterchain head with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedMasterchainInfo {
    /// The reported value, not proof-verified.
    pub value: MasterchainInfo,
    /// The raw proof bytes, still unchecked; empty for this response.
    pub proof: Buffer,
}

/// An account state with the unchecked proof the server sent.
#[napi(object)]
pub struct ReportedAccountState {
    /// The reported value, not proof-verified.
    pub value: AccountState,
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

    /// Reads an account's raw state at the current masterchain head.
    ///
    /// `address` is a raw `workchain:hex` or user-friendly base64 address.
    #[napi]
    pub async fn account(&self, address: String) -> napi::Result<ReportedAccountState> {
        let parsed = ton_net::Address::parse(&address).map_err(to_js)?;
        let mut client = self.inner.lock().await;
        let reported = client.account(&parsed).await.map_err(to_js)?;
        Ok(reported_account_state(reported))
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

fn reported_account_state(
    reported: ton_net::ServerReported<ton_net::AccountState>,
) -> ReportedAccountState {
    let proof = Buffer::from(reported.proof().to_vec());
    let state = reported.into_value();
    let block = state.block;
    ReportedAccountState {
        value: AccountState {
            workchain: block.workchain,
            shard: format!("{:016x}", block.shard),
            seqno: block.seqno,
            state: Buffer::from(state.state),
        },
        proof,
    }
}
