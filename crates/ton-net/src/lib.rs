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
//! it starts from is the single input still taken on trust, and it comes from the file
//! that already decides which network a client is on.
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

pub use address::Address;
pub use client::Client;
pub use config::Config;
pub use error::Error;
pub use proof::verify_account;
pub use sync::SyncReport;
pub use verified::Verified;

/// The read response types, defined in ton-net-lite and surfaced here.
pub use ton_net_lite::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};

/// The decoded chain structures, defined in ton-net-block and surfaced here.
pub use ton_net_block::{Account, AccountRead, AccountStatus, Coins};

/// The cell types a decoded account carries, defined in ton-net-cell and surfaced here.
pub use ton_net_cell::{Cell, CellType};
