// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! TON block and account structures, decoded from cells.
//!
//! This module turns the cells a liteserver returns into values a reader can use. It
//! reads the account structure into an [`Account`], walks the fragments of a block and a
//! shard state that an account read and its proof depend on, and reads a block's
//! [`BlockHeader`] and the [`ValidatorSet`](crate::proof::ValidatorSet) a key block
//! names.
//!
//! It decodes only what a read or a proof needs. A shard state carries message queues
//! and libraries, and a block carries its whole transaction set; none of that is read
//! here.
//!
//! Nothing here checks anything. An [`Account`] from [`Account::decode`] is bytes a server
//! sent, believed because the server said so; [`crate::proof`] is what turns one into an
//! answer, and [`Verified`](crate::Verified) is what records that it did.
//!
//! # Examples
//!
//! ```
//! use ton_net::tlb::{Account, AccountStatus};
//!
//! // A liteserver reports an address nothing has been stored under as empty bytes.
//! let account = Account::decode(&[])?;
//! assert_eq!(account.status, AccountStatus::Nonexistent);
//! assert_eq!(account.balance.nanotons(), 0);
//! # Ok::<(), ton_net::tlb::BlockError>(())
//! ```

mod account;
mod block;
mod coins;
mod error;
mod shard;

pub use account::{Account, AccountStatus};
pub use block::{Block, BlockHeader};
pub use coins::Coins;
pub use error::BlockError;
pub use shard::{McStateExtra, ShardAccountEntry, ShardDescr, ShardState};

/// How a dictionary lookup ended, re-exported from [`crate::cell`] because this module's
/// own reads answer with it.
pub use crate::cell::Lookup;
