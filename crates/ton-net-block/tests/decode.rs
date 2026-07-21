//! Decoding accounts and walking a proof, against bytes TON produced.
//!
//! The fixtures are account states and a proof a mainnet liteserver returned, captured
//! by `spikes/proof-feasibility`. The values asserted here were confirmed against a
//! public API independent of that liteserver, so a decode that drifts is caught rather
//! than agreeing with itself.
//!
//! The storage layout is the reason this matters. Between the address and the balance
//! sits `StorageExtraInfo`, whose `none` case is three zero bits, exactly what an older
//! layout's public-cells counter looks like when it holds zero. Most accounts therefore
//! decode the same either way, so one sample cannot tell the two apart. An account that
//! does carry storage extra can, and reading it as a counter there loses 256 bits of
//! alignment: the balance becomes noise and the status reads as frozen. Both an account
//! with storage extra and one without are pinned here so the ambiguity stays closed.

use ton_net_block::{proof, Account, AccountStatus, Block, BlockError, Coins, Lookup, ShardState};
use ton_net_cell::parse_boc;

/// A basechain account with a balance and no code: the zero address.
const UNINIT_ACCOUNT: &str = include_str!("fixtures/uninit-account.hex");

/// A basechain account that is deployed and spent down to nothing.
const ACTIVE_ACCOUNT: &str = include_str!("fixtures/active-account.hex");

/// An account carrying storage extra, which the older storage layout misreads.
const STORAGE_EXTRA_ACCOUNT: &str = include_str!("fixtures/storage-extra-account.hex");

/// The proof a liteserver returned for the config contract.
const ACCOUNT_PROOF: &str = include_str!("fixtures/account-proof.hex");

/// The root hash of the masterchain block that proof was read at.
///
/// `ton-net-cell` pins the same hash, where recomputing it from the pruned tree is what
/// shows the level rules are right. Here it is the anchor the proof has to root at before
/// anything below it is read.
const PROOF_BLOCK_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

/// The balance an independent public API reported for the zero address.
const UNINIT_BALANCE: u128 = 6_910_657_721_334;

/// The balance that same API reported for the storage-extra account.
const STORAGE_EXTRA_BALANCE: u128 = 1_067_259_229_327;

/// The logical time just after that account's last transaction.
///
/// An explorer reports the transaction's own logical time, which is one lower.
const UNINIT_LAST_TRANS_LT: u64 = 91_525_464_000_006;

/// The code an independent public API served for the active account.
const ACTIVE_CODE_BOC: &str = "b5ee9c7241010101004700008aff0020dd2082014c97ba9730ed44d0d70b1fe0a4f260d31f01ed44d0d31fd166baf2a1f8000120d74a8e11d307d459821804a817c80073fb0201fb00ded1a4c8cb1fc9ed542212ea86";

/// The data that same API served for it.
const ACTIVE_DATA_BOC: &str = "b5ee9c7241010101000600000800000111f8dc38fe";

/// The account id of the config contract, the key its proof covers.
const CONFIG_ACCOUNT_ID: [u8; 32] = [0x55; 32];

/// The hash of the config contract's state at the block the proof was read at.
const CONFIG_ACCOUNT_HASH: &str =
    "264d8098b38f47d053b8eaf20e611ee7755c67874527ab4d5c555f6a678b0b28";

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn an_uninitialized_account_decodes_to_its_reported_balance() {
    let account = Account::decode(&unhex(UNINIT_ACCOUNT)).expect("the account decodes");

    assert_eq!(account.status, AccountStatus::Uninit);
    assert_eq!(account.balance.nanotons(), UNINIT_BALANCE);
    assert_eq!(account.last_trans_lt, UNINIT_LAST_TRANS_LT);
    assert!(
        account.exists(),
        "an address can hold TON before deployment"
    );
    assert!(!account.is_active());
    assert!(account.code().is_none());
    assert!(account.data().is_none());
}

#[test]
fn a_balance_renders_as_exact_decimal_digits() {
    let account = Account::decode(&unhex(UNINIT_ACCOUNT)).expect("the account decodes");
    assert_eq!(account.balance.to_string(), "6910657721334");

    // Mainnet balances do run past what a JavaScript number holds exactly. The elector
    // held this much when these fixtures were taken, which is well beyond 2^53, so a
    // binding carries an amount as digits rather than as a number.
    let elector = Coins::from_nanotons(1_309_278_166_029_167_874);
    assert!(elector.nanotons() > (1u128 << 53));
    assert_eq!(elector.to_string(), "1309278166029167874");
}

#[test]
fn an_account_carrying_storage_extra_decodes_to_its_reported_balance() {
    // The discriminating case for the storage layout. Read with a third counter in place
    // of the storage-extra tag, this account's balance comes out as 14772718 and its
    // status as frozen; the independent source says otherwise.
    let account = Account::decode(&unhex(STORAGE_EXTRA_ACCOUNT)).expect("the account decodes");

    assert_eq!(account.balance.nanotons(), STORAGE_EXTRA_BALANCE);
    assert!(account.is_active());
    assert_ne!(account.balance.nanotons(), 14_772_718);
}

#[test]
fn an_active_account_decodes_to_the_code_and_data_served_for_it() {
    let account = Account::decode(&unhex(ACTIVE_ACCOUNT)).expect("the account decodes");

    assert!(account.is_active());
    assert_eq!(account.balance.nanotons(), 0, "spent down to nothing");

    // The independent API serves the code and data as their own bags of cells. Parsing
    // those and matching hashes checks the decode against a separate source, not against
    // this crate.
    let code = account.code().expect("an active account has code");
    let data = account.data().expect("an active account has data");
    let expected_code = parse_boc(&unhex(ACTIVE_CODE_BOC)).expect("the served code parses");
    let expected_data = parse_boc(&unhex(ACTIVE_DATA_BOC)).expect("the served data parses");

    assert_eq!(code.hash(), expected_code[0].hash(), "code hash");
    assert_eq!(data.hash(), expected_data[0].hash(), "data hash");
}

/// The shard state the proof covers, reached through the checked chain.
///
/// Picking whichever root happens to decode would read a proof without ever requiring it
/// to root anywhere, which is the mistake the engine exists to prevent. The state below is
/// reached the same way a verified read reaches it: from the pinned block hash, through
/// the block's state update, to the proof that covers that state.
fn proved_state() -> ShardState {
    let anchor: [u8; 32] = unhex(PROOF_BLOCK_HASH).try_into().expect("32 bytes");
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");
    let state_hash =
        proof::verify_block_state(&roots, &anchor).expect("a root covers the pinned block");
    proof::verify_shard_state(&roots, &state_hash).expect("a root covers the state it leaves")
}

#[test]
fn the_proof_walks_from_the_block_to_the_state_it_leaves() {
    let anchor: [u8; 32] = unhex(PROOF_BLOCK_HASH).try_into().expect("32 bytes");
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");

    // The block's state update names a state, and a second root in the same bag covers
    // exactly that state. Both links are checked by recomputing hashes, so a bag whose
    // halves belong to different blocks does not get this far.
    let state_hash =
        proof::verify_block_state(&roots, &anchor).expect("a root covers the pinned block");
    let state =
        proof::verify_shard_state(&roots, &state_hash).expect("a root covers the named state");
    assert_eq!(*state.cell().hash(), state_hash);

    // An anchor the bag says nothing about gets no further than the first step.
    let mut elsewhere = anchor;
    elsewhere[0] ^= 1;
    assert_eq!(
        proof::verify_block_state(&roots, &elsewhere),
        Err(BlockError::ProofNotAnchored)
    );
}

#[test]
fn the_accounts_dictionary_finds_the_account_the_proof_covers() {
    let state = proved_state();

    let entry = state
        .account(&CONFIG_ACCOUNT_ID)
        .expect("the dictionary reads")
        .found()
        .expect("the proof covers this account");

    // Inside a proof the account itself is pruned away, and the placeholder carries the
    // hash. That hash is what binds a separately delivered account state to this block.
    assert_eq!(
        entry.account_hash()[..],
        unhex(CONFIG_ACCOUNT_HASH)[..],
        "the dictionary must land on the account the proof was built for"
    );
    assert!(
        entry.last_trans_lt() > 0,
        "an active contract has transacted"
    );
    assert_ne!(entry.last_trans_hash(), &[0u8; 32]);
}

#[test]
fn an_account_the_proof_does_not_cover_reads_as_pruned_not_absent() {
    let state = proved_state();

    // A proof prunes every branch but the one it covers, so a walk toward any other
    // account runs into a placeholder and stops there, having learned nothing. Reporting
    // that as absence would let a server deny an account by refusing to prove anything.
    assert_eq!(
        state.account(&[0xAA; 32]).expect("the dictionary reads"),
        Lookup::Pruned
    );
}

#[test]
fn a_cell_that_is_not_a_shard_state_is_refused() {
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");
    // The Merkle roots themselves are not shard states.
    assert!(matches!(
        ShardState::from_cell(&roots[0]),
        Err(BlockError::WrongConstructor { .. }) | Err(BlockError::Cell(_))
    ));
    assert!(matches!(
        Block::from_cell(&roots[0]),
        Err(BlockError::WrongConstructor { .. }) | Err(BlockError::Cell(_))
    ));
}
