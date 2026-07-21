// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Liteserver read client for ton-net.
//!
//! [`LiteClient`] speaks the liteserver query protocol over an ADNL connection and
//! decodes the read responses into the domain types this crate defines. Nothing here
//! checks anything: a read comes back as a [`ServerReported`] value, and the proof
//! bytes travel with it for the layer above to verify.
//!
//! [`LiteClient::masterchain_info`] reads the current masterchain head,
//! [`LiteClient::account_state`] reads an account's raw state at a given block, and
//! [`LiteClient::block_proof`] asks for the links between two blocks. The facade above
//! this crate wraps a `LiteClient` over a TCP transport and adds address parsing and a
//! bundled config.
//!
//! This crate maps the wire types from ton-net-tl into cleaner domain types: block
//! sequence numbers become unsigned, and a response keeps only what a reader needs. The
//! block-proof types are the exception and are re-exported as they come off the wire,
//! because their reader is a verifier rather than a person. It is an internal crate of
//! the ton-net client.
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

/// The block-proof types [`LiteClient::block_proof`] answers with, re-exported from
/// ton-net-tl so a caller need not name that crate to read a chain.
pub use ton_net_tl::lite::{BlockLink, PartialBlockProof, Signature, SignatureSet};
