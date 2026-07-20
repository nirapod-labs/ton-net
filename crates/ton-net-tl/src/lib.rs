//! TL codec for ton-net: TON's Type Language wire format.
//!
//! This crate encodes and decodes TON's TL types: constructor tags, boxed and bare
//! types, and the schema types the client reads. It performs no I/O.
//!
//! It is an internal crate of the ton-net client. Most consumers use the `ton-net`
//! facade rather than this crate directly.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The codec and the v0.1.0 schema types land in the next step of the plan.
