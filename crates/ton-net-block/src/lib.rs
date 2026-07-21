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
mod coins;
pub mod dict;
mod error;
pub mod proof;
mod shard;
pub mod validators;

pub use account::{Account, AccountStatus};
pub use block::{Block, BlockHeader};
pub use coins::Coins;
pub use dict::Lookup;
pub use error::BlockError;
pub use proof::{verify_account, AccountRead};
pub use shard::{McStateExtra, ShardAccountEntry, ShardDescr, ShardState};
pub use validators::{Validator, ValidatorSet};
