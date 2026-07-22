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

//! ton-net: a direct client for the TON network.
//!
//! This crate connects to a TON liteserver over ADNL and reads chain state without an
//! HTTP indexer in the path. It speaks the wire protocols directly: the TL codec, the
//! ADNL transport, and the liteserver query layer.
//!
//! # Verification status
//!
//! Every read says in its type whether it was proved.
//!
//! A [`ServerReported`] value is the liteserver's word, returned without checking the
//! proofs that came with it. A [`Verified`] value was checked: its Merkle proofs were
//! recomputed against a block hash the caller supplied, and the account was bound to that
//! block's state. There is no way to turn the first into the second.
//!
//! What [`Verified`] does not settle on its own is where the block hash came from.
//! Passing [`Client::account_at`] a head read from the same liteserver shows only that the
//! server agrees with itself, which a server making things up can also manage.
//!
//! [`Client::sync`] is what closes that. It walks from the key block the config pins to
//! the network's current head, checking a validator signature set at every step, and
//! leaves the client holding a block it proved rather than one a server named. The block
//! it starts from is the one thing still taken on trust from the chain's side, and it
//! comes from the file that already decides which network a client is on.
//!
//! The other trusted input is the local clock. A proof establishes that a block is real
//! and was committed; it says nothing about when it was handed over, so a server
//! replaying a genuine chain from last year passes every other check here. The clock is
//! what catches that, which means a client whose clock is wrong has a weaker freshness
//! guarantee than one whose clock is right. A clock far enough behind is reported rather
//! than obeyed, so the check never silently stops running.
//!
//! [`Client::account`] reads against that block, so it is the read to reach for.
//! [`Client::account_at`] proves against a block the caller names, and
//! [`Client::account_reported`] checks nothing at all. The safe one is the one with the
//! plain name.
//!
//! # Example
//!
//! ```no_run
//! use ton_net::{Address, Client, Config};
//!
//! # async fn run() -> Result<(), ton_net::Error> {
//! let config = Config::mainnet();
//! let mut client = Client::connect(&config).await?;
//! let elector = Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;
//!
//! // Proved against a block the client walked to itself. The first call pays for the
//! // walk; save `client.anchor()` and hand it to `connect_from` next time.
//! let account = client.account(&elector).await?;
//! println!("proved balance: {}", account.value().balance);
//!
//! // The server's word, for a caller who asks for it by name.
//! let reported = client.account_reported(&elector).await?;
//! println!("reported balance: {}", reported.value().balance);
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
mod proof;
mod sync;
mod verified;

/// Which set of things this build will accept as proven.
///
/// A version number answers "is this API compatible". It cannot answer the question a
/// caller of a verifier actually has, which is whether an upgrade changed what the
/// library believes. Those are different questions: the accept and reject boundary can
/// move while every signature stays byte-identical, and it can stay fixed across a
/// breaking API change.
///
/// So this is a separate number. It rises when a new kind of proof is accepted, when an
/// acceptance condition tightens or loosens, when the rule for validator signature weight
/// changes, or when a freshness default changes. It does not move for wording, for
/// performance, or for anything a caller cannot observe in an accept or reject.
///
/// A caller that recorded a result can compare the epoch it was verified under against
/// this one and decide whether to check again. Nothing else in the API answers that.
///
/// ```
/// # let cached_epoch = ton_net::VERIFY_EPOCH;
/// if cached_epoch < ton_net::VERIFY_EPOCH {
///     // this build accepts a different set of things; verify again rather than trust
///     // a result an older set of rules produced
/// }
/// ```
///
/// The number is meaningless across libraries and is not a version. It only ever
/// increases, and each increase is recorded in the changelog as the delta in what is
/// accepted and what is refused.
pub const VERIFY_EPOCH: u32 = 1;

pub use address::Address;
pub use client::Client;
pub use config::Config;
pub use error::{Error, ErrorCode};
pub use proof::verify_account;
pub use sync::SyncReport;
pub use verified::Verified;

/// The read response types, defined in ton-net-lite and surfaced here.
pub use ton_net_lite::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};

/// The decoded chain structures, defined in ton-net-block and surfaced here.
pub use ton_net_block::{Account, AccountRead, AccountStatus, Coins};

/// The cell types a decoded account carries, defined in ton-net-cell and surfaced here.
pub use ton_net_cell::{Cell, CellType};
