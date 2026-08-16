// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What a build with no socket still carries, named one item at a time.
//!
//! `core/Cargo.toml` says the `net` feature carries the socket and the randomness it
//! draws, and that everything the library decides rather than fetches builds without it.
//! That is a claim about a feature resolution, and a claim about a feature resolution is
//! worth what a build of that resolution says. Nothing else in the gate compiles this one:
//! `test` runs the default build and the all-features build, and both have `net` on.
//!
//! So each capability the manifest names gets a line here that binds it to an explicitly
//! written type or calls it. Gate one of them behind `net` and this file stops compiling
//! under `--no-default-features`, which `just sans-io` reports as a failure.
//!
//! Nothing here is `#[cfg]`-guarded, so the same file also compiles in the default build
//! and `cargo test` runs it. A guard would let the file pass the configuration it exists
//! to check by not being read in it.
//!
//! # The scope, exactly
//!
//! This covers the capabilities `core/Cargo.toml` names and nothing wider. It does not
//! assert that the socket is absent; `scripts/check-layers.mjs` reads the source text for
//! that, and the two answer different questions. It also does not run on a target without
//! threads or a clock: it establishes that the code compiles and its pure paths answer,
//! not that a browser would be happy.

use ton_net::cell::{parse_boc, serialize_boc, Builder, Cell, CellError, Slice, UsageTree};
use ton_net::proof::{signature, verify_account, verify_chain, AccountRead, ValidatorSet};
use ton_net::tlb::{Account, AccountStatus, Block, BlockError, Coins, ShardState};
use ton_net::{Address, Config, Error, ErrorCode, Verified, VERIFY_EPOCH};

/// The elector, a masterchain address that is always deployed.
const ELECTOR: &str = "-1:3333333333333333333333333333333333333333333333333333333333333333";

/// The cell engine: a bag is read in and written back out.
#[test]
fn the_cell_engine_is_here() {
    let mut builder = Builder::new();
    builder.store_uint(0xab, 8).unwrap();
    let cell: Cell = builder.build().unwrap();
    let bag: Vec<u8> = serialize_boc(&[cell.clone()]).unwrap();
    let roots: Vec<Cell> = parse_boc(&bag).unwrap();
    assert_eq!(roots[0].hash(), cell.hash());

    let mut slice: Slice<'_> = roots[0].parse();
    assert_eq!(slice.load_uint(8).unwrap(), 0xab);

    // The proof machinery is a cell concern and travels with the engine.
    let tree = UsageTree::new(cell.clone());
    let _ = tree.prove();

    // And the error a read fails with is nameable without a socket.
    let refused: Result<Vec<Cell>, CellError> = parse_boc(&[]);
    assert!(refused.is_err());
}

/// The typed structures: an absent account decodes to a value, not to a failure.
#[test]
fn the_typed_structures_are_here() {
    let account: Account = Account::decode(&[]).unwrap();
    assert_eq!(account.status, AccountStatus::Nonexistent);

    let balance: Coins = account.balance;
    assert_eq!(balance.nanotons(), 0);

    // Named rather than exercised: these need bytes a fixture would supply, and this file
    // reads no fixture. Naming them is what proves they are reachable.
    let _: Option<fn(&[u8]) -> Result<Block, BlockError>> = None;
    let _: Option<fn(&[u8]) -> Result<ShardState, BlockError>> = None;
}

/// The verification engine, including the standalone check the root re-exports.
#[test]
fn the_proof_engine_is_here() {
    // A signature over nothing verifies as false rather than failing to link.
    assert!(!signature::verify(&[0; 32], b"", &[0; 64]));

    let _: Option<fn(&AccountRead<'_>) -> Result<Account, BlockError>> = Some(verify_account);
    let _: Option<fn(&Cell) -> Result<ValidatorSet, BlockError>> = Some(ValidatorSet::from_config);
    // `verify_chain` takes wire types; naming it is what this line is for.
    let _ = verify_chain;

    // The root's own check, at the root's error type, is not behind the feature either.
    let _: Option<fn(&AccountRead<'_>) -> Result<Account, Error>> = Some(ton_net::verify_account);
}

/// Address parsing and the configuration reader.
#[test]
fn the_reader_and_the_parser_are_here() {
    let address: Address = Address::parse(ELECTOR).unwrap();
    assert_eq!(address.workchain(), -1);

    let config: Config = Config::mainnet();
    assert!(config.init_block().is_some());

    let refused: Result<Address, Error> = Address::parse("not an address");
    assert_eq!(refused.unwrap_err().code(), ErrorCode::Address);
}

/// The trust wrapper and the epoch, which a caller records alongside a stored result.
#[test]
fn the_trust_vocabulary_is_here() {
    // `Verified` has no public constructor by design, so what is asserted is that the name
    // resolves and carries its parameter, not that one can be built here.
    let _: Option<fn(Verified<Account>) -> Account> = Some(Verified::into_value);
    assert_eq!(VERIFY_EPOCH, 2);
}
