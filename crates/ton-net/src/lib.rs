//! ton-net: a direct client for the TON network.
//!
//! This crate connects to a TON liteserver over ADNL and reads chain state without
//! an HTTP indexer in the path. It speaks the wire protocols directly: the TL codec,
//! the ADNL transport, and the liteserver query layer.
//!
//! # Verification status
//!
//! Reads are not proof-verified in the current release; a liteserver's answer is the
//! server's unproven word. Proof verification and block sync arrive in later
//! releases. The client API arrives across the steps of the v0.1.0 plan.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
