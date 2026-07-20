//! ADNL transport for ton-net: the encrypted link to a liteserver.
//!
//! This crate builds the ADNL-over-TCP handshake and stream framing as sans-I/O
//! logic, defines the transport seam that moves the bytes, and provides the native
//! TCP transport. The browser transport is added in a later release.
//!
//! It is an internal crate of the ton-net client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The handshake, framing, transport seam, and connection driver land in the next
// steps of the plan.
