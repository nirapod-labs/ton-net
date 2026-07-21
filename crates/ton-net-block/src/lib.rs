//! TON block and account structures, decoded from cells, for ton-net.
//!
//! This crate turns the cells a liteserver returns into values a reader can use. It
//! reads the account structure into an [`Account`], and walks the fragments of a block
//! and a shard state that an account read and its proof depend on.
//!
//! It decodes only what a read needs. A shard state carries message queues, libraries
//! and the network configuration, and a block carries its whole transaction set; none of
//! that is read here.
//!
//! # Trust
//!
//! Nothing in this crate checks a proof. An [`Account`] decoded from bytes a liteserver
//! sent is the server's word until something verifies it, and the type does not claim
//! otherwise. The proof engine that turns a trusted block hash into a checked account
//! read builds on [`Block::new_state_hash`], [`ShardState::account`], and the cell
//! hashing beneath them.
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
mod coins;
pub mod dict;
mod error;
mod shard;

pub use account::{Account, AccountStatus};
pub use block::Block;
pub use coins::Coins;
pub use error::BlockError;
pub use shard::{ShardAccountEntry, ShardState};
