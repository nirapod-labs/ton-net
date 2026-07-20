//! Liteserver read client for ton-net.
//!
//! [`LiteClient`] speaks the liteserver query protocol over an ADNL connection and
//! decodes the read responses into the domain types this crate defines. Every read is
//! returned as a [`ServerReported`] value: the server's word, not proof-verified in this
//! release.
//!
//! [`LiteClient::masterchain_info`] reads the current masterchain head and
//! [`LiteClient::account_state`] reads an account's raw state at a given block. The
//! facade above this crate wraps a `LiteClient` over a TCP transport and adds address
//! parsing and a bundled config.
//!
//! This crate maps the wire types from ton-net-tl into cleaner domain types: block
//! sequence numbers become unsigned, the response keeps only what a reader needs, and
//! the proof bytes move into [`ServerReported`] for a later verification layer. It is an
//! internal crate of the ton-net client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod client;
mod types;

pub use client::{LiteClient, LiteError};
pub use types::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};

/// An account identifier: a workchain and a 256-bit account id.
///
/// This is the account [`LiteClient::account_state`] reads, re-exported from ton-net-tl.
/// The facade builds one from a parsed address.
pub use ton_net_tl::lite::AccountId;
