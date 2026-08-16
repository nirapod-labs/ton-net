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
#![cfg_attr(
    feature = "net",
    doc = r#"# Example

```no_run
use ton_net::{Address, Client, Config};

# async fn run() -> Result<(), ton_net::Error> {
let config = Config::mainnet();
let mut client = Client::connect(&config).await?;
let elector = Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;

// Proved against a block the client walked to itself. The first call pays for the
// walk; save `client.anchor()` and hand it to `connect_from` next time.
let account = client.account(&elector).await?;
println!("proved balance: {}", account.value().balance);

// The server's word, for a caller who asks for it by name.
let reported = client.account_reported(&elector).await?;
println!("reported balance: {}", reported.value().balance);
# Ok(())
# }
```
"#
)]
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
//! # What is at the root
//!
//! [`Client`] is the way in and [`Config`] is what it takes. [`Address`] parses what a
//! person writes, [`Verified`] and [`ServerReported`] say which kind of answer came back,
//! and [`verify_account`] is the same check as a standalone function for bytes that
//! arrived some other way.
//!
//! The cell types beside them are the closure of one rule: a type a method on a
//! re-exported cell type answers with is named here too, so a caller never has to reach
//! past the root to use what the root handed them. An [`Account`] carries its code and data
//! as [`Cell`]s, and from a [`Cell`] that reaches a [`Slice`] from [`Cell::parse`], an
//! [`Identity`] from [`Cell::identity`], a [`Builder`] from [`Cell::to_builder`], a
//! [`CellType`] from [`Cell::cell_type`], and a [`CellError`] from every read that can
//! fail. A [`Slice`] adds the [`Dict`] that [`Slice::load_dict`] answers with, the
//! [`Lookup`], [`DictEntry`] and [`DictIter`] a dictionary is read through, and the
//! [`MsgAddress`] that [`Slice::load_address`] reads. [`MsgAddress`] is the wire form an
//! address takes inside a message, which is not [`Address`]: that one is the form a person
//! writes.
//!
//! [`parse_boc`] and [`serialize_boc`] are here because [`AccountState`] hands a proof and
//! a state back as raw bag bytes, so a root with [`Cell::to_boc`] and no [`parse_boc`]
//! could write a bag out and not read one in. [`MAX_CELLS`] and [`MAX_DEPTH`] are the
//! bounds a parse refuses past; [`MAX_BITS`] and [`MAX_REFS`] are the bounds one cell holds
//! within.
//!
//! **The rule curates, it does not gate.** What it leaves out is a level down and public:
//! the augmented and prefix dictionaries, the proof builders and the streaming readers are
//! reachable from no method on a type this list returns, so they are not at the root, and a
//! consumer whose need is the cell engine names [`cell`] and has all of it. The one thing
//! genuinely not at the root is [`BlockError`](tlb::BlockError): [`Account::decode`]
//! answers with it, and a root-level caller reads that failure through the `From`
//! conversion into [`Error`] rather than by naming it.
//!
//! [`Client::account`] reads against that block, so it is the read to reach for.
//! [`Client::account_at`] proves against a block the caller names, and
//! [`Client::account_reported`] checks nothing at all. The safe one is the one with the
//! plain name.
//!
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Documentation is published with every feature on, which `[package.metadata.docs.rs]`
// fixes, so every link in this crate resolves in the build a reader is served. rustdoc has
// no way to write a link that resolves only under a feature, and a `net`-off documentation
// build is one nobody publishes, so the deny sits where it can find a real broken link and
// the warning covers the build where it can only find a gated one.
#![cfg_attr(feature = "net", deny(rustdoc::broken_intra_doc_links))]
#![cfg_attr(not(feature = "net"), warn(rustdoc::broken_intra_doc_links))]
// Six crate-private items serve only the networked half: the two wrappers' constructors,
// the config's liteserver list and its fields, and the decode-error mapping. A build
// without `net` keeps them rather than giving `Config` and `Verified` a second shape, so
// it sees them unused. The allowance is conditioned on that build and cannot hide dead
// code in the one that ships.
#![cfg_attr(not(feature = "net"), allow(dead_code))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod adnl;
pub mod cell;
pub mod client;
pub mod lite;
pub mod proof;
pub mod tl;
pub mod tlb;

mod address;
mod codec;
mod config;
mod error;
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
pub const VERIFY_EPOCH: u32 = 2;

pub use address::Address;
pub use config::Config;
pub use error::{Error, ErrorCode};
pub use verified::Verified;

// The three entry points are inlined so the root page describes them where a reader lands.
// A plain `pub use` renders as a bare line in the re-exports table with no description,
// which is where the way into the library was sitting, weighted like a bound constant.
#[doc(inline)]
pub use client::verify_account;
#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
#[doc(inline)]
pub use client::Client;
#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
#[doc(inline)]
pub use client::SyncReport;

pub use crate::lite::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};
pub use crate::proof::AccountRead;
pub use crate::tlb::{Account, AccountStatus, Coins};

pub use crate::cell::{parse_boc, serialize_boc, MAX_BITS, MAX_CELLS, MAX_DEPTH, MAX_REFS};
pub use crate::cell::{
    Builder, Cell, CellError, CellType, Dict, DictEntry, DictIter, Identity, Lookup, MsgAddress,
    Slice,
};

// The README ships to crates.io and cannot be replaced once a version is published,
// so its examples are compiled here rather than trusted. Doc-only: this does not
// appear in the rendered documentation.
#[cfg(all(doctest, feature = "net"))]
#[doc = include_str!("../README.md")]
struct Readme;
