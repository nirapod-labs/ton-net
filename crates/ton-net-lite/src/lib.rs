//! Liteserver read client for ton-net.
//!
//! This crate wraps the liteserver query protocol over an ADNL connection and
//! decodes the read responses. Reads are returned as the server reported them and
//! are not proof-verified in the current release.
//!
//! It is an internal crate of the ton-net client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The liteserver client, method set, and response types land in the next step of
// the plan.
