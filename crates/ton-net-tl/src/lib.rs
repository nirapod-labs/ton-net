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

//! TL codec for ton-net: TON's Type Language wire format.
//!
//! This crate defines the TON TL types the client reads and writes, derived over
//! [`tl_proto`], and re-exports the serialize and deserialize entry points. It
//! covers the ADNL message envelope ([`adnl`]), the liteserver query and response
//! types ([`lite`]), and the messages a validator signature covers ([`signed`]).
//! It performs no I/O, and it checks nothing: a decoded response is the server's
//! word until `ton-net-block` verifies it.
//!
//! A boxed type carries a four-byte constructor id: the CRC32-IEEE of its TL scheme
//! line, written little-endian on the wire. A bare type, used only as a field of
//! another type, carries none. Both are handled by the [`tl_proto`] derives, so a
//! caller serializes and deserializes typed values and never touches the tags.
//!
//! # Example
//!
//! ```
//! use ton_net_tl::lite::GetMasterchainInfo;
//!
//! // A nullary boxed request serializes to exactly its constructor id.
//! let bytes = ton_net_tl::serialize(GetMasterchainInfo);
//! assert_eq!(bytes, [0x2e, 0xe6, 0xb5, 0x89]);
//! ```
//!
//! It is an internal crate of the ton-net client. Most consumers use the `ton-net`
//! facade rather than this crate directly.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod adnl;
pub mod lite;
pub mod signed;

#[doc(no_inline)]
pub use tl_proto::{deserialize, serialize, TlError, TlRead, TlResult, TlWrite};
