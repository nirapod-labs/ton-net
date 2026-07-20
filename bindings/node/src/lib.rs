//! Node.js binding for the ton-net TON client.
//!
//! This crate wraps the `ton-net` facade for Node.js with napi-rs. The binding
//! classes and their TypeScript types are added in a later step of the v0.1.0 plan,
//! where the FFI edge is the one place `unsafe` is allowed and documented.
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
