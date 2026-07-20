//! ton-net: a direct client for the TON network.
//!
//! This crate connects to a TON liteserver over ADNL and reads chain state without an
//! HTTP indexer in the path. It speaks the wire protocols directly: the TL codec, the
//! ADNL transport, and the liteserver query layer.
//!
//! # Verification status
//!
//! In this release reads are **not** proof-verified. A liteserver's answer is returned
//! as a [`ServerReported`] value, the server's unproven word. Proof verification and
//! block sync arrive in later releases; until then a [`ServerReported`] must not be
//! treated as verified chain state.
//!
//! # Example
//!
//! ```no_run
//! use ton_net::{Client, Config};
//!
//! # async fn run() -> Result<(), ton_net::Error> {
//! let config = Config::mainnet();
//! let mut client = Client::connect(&config).await?;
//!
//! let info = client.masterchain_info().await?;
//! println!("masterchain seqno: {}", info.value().last.seqno);
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod address;
mod client;
mod codec;
mod config;
mod error;

pub use address::Address;
pub use client::Client;
pub use config::Config;
pub use error::Error;

/// The read response types, defined in ton-net-lite and surfaced here.
pub use ton_net_lite::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};
