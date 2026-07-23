// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The cell crate's public boundary, exercised as one test binary.
//!
//! Each topic below was its own `tests/*.rs`, and so its own compiled and linked binary.
//! They are modules of one binary here instead. Cargo builds every file directly under
//! `tests/` as a separate crate and links the library into each; the directory form is what
//! collapses that to one target (NET-ADR-011).

mod augmented;
mod hashing;
mod hostile;
mod mainnet_boc;
mod merkle;
mod whole_block;
