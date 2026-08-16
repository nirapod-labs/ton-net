// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// A library that decodes bytes from a peer it does not trust must fail by returning, not
// by unwinding: a panic in a decoder is a denial of service in whatever process embedded
// it. The lints sit on the library because a test is the opposite case, where an unwrap
// is the assertion. Arithmetic is deliberately not in the set: every count these formats
// carry is bounded before it is used, and each subtraction sits within a few lines of the
// guard that makes it safe, so denying it would bury the real bounds under checked_sub.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::indexing_slicing
)]

//! TON block and account structures, decoded from cells, for ton-net.
//!
//! This crate turns the cells a liteserver returns into values a reader can use. It
//! reads the account structure into an [`Account`], walks the fragments of a block and a
//! shard state that an account read and its proof depend on, and reads a block's
//! [`BlockHeader`] and the [`ValidatorSet`] a key block names.
//!
//! It decodes only what a read or a proof needs. A shard state carries message queues
//! and libraries, and a block carries its whole transaction set; none of that is read
//! here.
//!
//! # Trust
//!
//! Decoding and checking are separate here, and the types say which is which. An
//! [`Account`] from [`Account::decode`] is bytes a server sent, believed because the
//! server said so. The same type from [`proof::verify_account`] was checked against a
//! block hash the caller trusts. Nothing about the value records the difference, so the
//! caller keeps track of which call produced it; the facade above this crate is where
//! that distinction is carried in the type.
//!
//! This is an internal crate of the ton-net client.
//!
//! # Examples
//!
//! ```
//! use ton_net_block::{Account, AccountStatus};
//!
//! // A liteserver reports an address nothing has been stored under as empty bytes.
//! let account = Account::decode(&[])?;
//! assert_eq!(account.status, AccountStatus::Nonexistent);
//! assert_eq!(account.balance.nanotons(), 0);
//! # Ok::<(), ton_net_block::BlockError>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod account;
mod block;
pub mod chain;
mod coins;
mod error;
pub mod proof;
mod shard;
pub mod signature;
pub mod validators;

pub use account::{Account, AccountStatus};
pub use block::{Block, BlockHeader};
pub use chain::{verify_chain, ProvenBlock};
pub use coins::Coins;
pub use error::BlockError;
pub use proof::{verify_account, AccountRead};
pub use shard::{McStateExtra, ShardAccountEntry, ShardDescr, ShardState};
pub use validators::{Validator, ValidatorSet};

/// How a dictionary lookup ended, re-exported from ton-net-cell because this crate's
/// own reads answer with it.
pub use ton_net_cell::Lookup;

/// The block identity and proof-chain types [`verify_chain`] reads, re-exported from
/// ton-net-tl so a caller need not name that crate to check a chain.
pub use ton_net_tl::lite::{BlockIdExt, BlockLink, PartialBlockProof};

// The README ships to crates.io and cannot be replaced once a version is published,
// so its examples are compiled here rather than trusted. Doc-only: this does not
// appear in the rendered documentation.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;
