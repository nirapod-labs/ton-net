//! Verifying account reads against a trusted block hash, and refusing tampered ones.
//!
//! The fixtures are whole `getAccountState` answers a mainnet liteserver returned,
//! captured together by `spikes/proof-feasibility` so the proofs chain. Each is a
//! masterchain block hash, a shard proof, an account-state proof, and the state.
//!
//! # Where the trust comes from
//!
//! A test that took the anchor from the same liteserver that sent the proofs would prove
//! nothing: a server that made up a block can make up a proof that roots at it. Every
//! anchor below was confirmed against a public API independent of that liteserver before
//! being pinned, and so was every shard block hash the engine is required to derive. What
//! is being checked is that recomputing SHA-256 over the server's bytes lands on a hash a
//! second party already published.
//!
//! # What the tamper cases are for
//!
//! Verifying a good proof only shows the engine accepts. The cases below are the attacks
//! a lying server would actually run: answer with another account's state, answer from
//! another block, answer with a proof that covers nothing, answer with a placeholder that
//! carries the right hash and no contents, or edit the bytes. None of them may produce an
//! account.

use ton_net_block::{
    proof, verify_account, AccountRead, AccountStatus, BlockError, Coins, ShardState,
};
use ton_net_cell::parse_boc;

/// A masterchain account: the zero address, which is deployed and holds a balance.
const MASTERCHAIN: &str = include_str!("fixtures/read-masterchain.txt");

/// A basechain account: a deployed contract whose code is a library reference.
const BASECHAIN: &str = include_str!("fixtures/read-basechain.txt");

/// A basechain address nothing has ever been stored under.
const ABSENT: &str = include_str!("fixtures/read-absent.txt");

/// The balance an independent public API reported for the masterchain account.
const MASTERCHAIN_BALANCE: u128 = 222_859_282_039_087;

/// The balance that same API reported for the basechain account.
const BASECHAIN_BALANCE: u128 = 1_067_259_229_327;

/// One captured answer to `liteServer.getAccountState`.
struct Read {
    workchain: i32,
    account_id: [u8; 32],
    block_root_hash: [u8; 32],
    shard_block_root_hash: [u8; 32],
    shard_proof: Vec<u8>,
    proof: Vec<u8>,
    state: Vec<u8>,
}

impl Read {
    fn parse(text: &str) -> Read {
        let field = |name: &str| -> &str {
            text.lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                .unwrap_or_else(|| panic!("fixture has no {name}"))
                .trim()
        };
        Read {
            workchain: field("workchain").parse().expect("workchain"),
            account_id: hash(field("account_id")),
            block_root_hash: hash(field("block_root_hash")),
            shard_block_root_hash: hash(field("shard_block_root_hash")),
            shard_proof: unhex(field("shard_proof")),
            proof: unhex(field("proof")),
            state: unhex(field("state")),
        }
    }

    /// The read as the engine takes it, with every byte as captured.
    fn as_read(&self) -> AccountRead<'_> {
        self.with_state(&self.state)
    }

    /// The same read with the account state replaced, for the substitution cases.
    fn with_state<'a>(&'a self, state: &'a [u8]) -> AccountRead<'a> {
        if self.workchain == -1 {
            AccountRead::masterchain(&self.block_root_hash, &self.account_id, &self.proof, state)
        } else {
            AccountRead::in_shard(
                &self.block_root_hash,
                self.workchain,
                &self.account_id,
                &self.shard_proof,
                &self.proof,
                state,
            )
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hash(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

#[test]
fn a_masterchain_account_verifies_against_the_hash_a_second_source_published() {
    let read = Read::parse(MASTERCHAIN);
    let account = verify_account(&read.as_read()).expect("the read verifies");

    assert_eq!(account.balance.nanotons(), MASTERCHAIN_BALANCE);
    assert!(account.is_active());
    assert!(account.code().is_some());
    assert!(account.data().is_some());
}

#[test]
fn a_basechain_account_verifies_through_its_shard() {
    let read = Read::parse(BASECHAIN);
    let account = verify_account(&read.as_read()).expect("the read verifies");

    assert_eq!(account.balance.nanotons(), BASECHAIN_BALANCE);
    assert!(account.is_active());
}

#[test]
fn the_shard_block_is_derived_from_the_masterchain_rather_than_believed() {
    let read = Read::parse(BASECHAIN);
    let derived = proof::verify_shard_block(
        &read.shard_proof,
        &read.block_root_hash,
        read.workchain,
        &read.account_id,
    )
    .expect("the shard proof checks out");

    // The server also names this block in its answer, and that word is never used. The
    // hash below was confirmed against an independent public API, so the derivation is
    // checked against a second party rather than against the server that sent the proof.
    assert_eq!(derived, read.shard_block_root_hash);
}

#[test]
fn an_address_nothing_was_stored_under_is_proved_absent() {
    let read = Read::parse(ABSENT);
    assert!(read.state.is_empty(), "the server reports no state");

    let account = verify_account(&read.as_read()).expect("absence is a result, not an error");
    assert_eq!(account.status, AccountStatus::Nonexistent);
    assert_eq!(account.balance, Coins::ZERO);
}

#[test]
fn an_anchor_that_is_not_the_block_the_proof_covers_is_refused() {
    let read = Read::parse(MASTERCHAIN);
    let mut wrong = read.block_root_hash;
    wrong[0] ^= 1;

    let attempt = AccountRead::masterchain(&wrong, &read.account_id, &read.proof, &read.state);
    assert_eq!(verify_account(&attempt), Err(BlockError::ProofNotAnchored));
}

#[test]
fn a_proof_from_another_block_is_refused() {
    // Two real answers, each valid on its own. Crossing them is what a server replaying an
    // old proof against a current block would produce.
    let current = Read::parse(BASECHAIN);
    let other = Read::parse(ABSENT);

    let crossed = AccountRead::in_shard(
        &current.block_root_hash,
        current.workchain,
        &current.account_id,
        &other.shard_proof,
        &other.proof,
        &current.state,
    );
    assert_eq!(verify_account(&crossed), Err(BlockError::ProofNotAnchored));
}

#[test]
fn another_accounts_state_does_not_bind_to_this_proof() {
    let read = Read::parse(BASECHAIN);
    let other = Read::parse(MASTERCHAIN);

    // A real account state, correctly formed, for the wrong account. Only the binding
    // step catches this: every proof in the answer still verifies.
    assert_eq!(
        verify_account(&read.with_state(&other.state)),
        Err(BlockError::NotBound)
    );
}

#[test]
fn claiming_absence_against_a_proof_that_shows_the_account_is_refused() {
    let read = Read::parse(BASECHAIN);
    assert_eq!(
        verify_account(&read.with_state(&[])),
        Err(BlockError::NotBound)
    );
}

#[test]
fn claiming_a_state_against_a_proof_of_absence_is_refused() {
    let absent = Read::parse(ABSENT);
    let other = Read::parse(BASECHAIN);
    assert_eq!(
        verify_account(&absent.with_state(&other.state)),
        Err(BlockError::NotBound)
    );
}

/// The same read redirected at a different account id.
fn asking_for<'a>(read: &'a Read, account_id: &'a [u8; 32], state: &'a [u8]) -> AccountRead<'a> {
    AccountRead::in_shard(
        &read.block_root_hash,
        read.workchain,
        account_id,
        &read.shard_proof,
        &read.proof,
        state,
    )
}

#[test]
fn an_account_the_proof_prunes_away_is_not_answered() {
    let read = Read::parse(BASECHAIN);
    // Near the root the accounts dictionary really does fork, and a proof replaces the
    // half it does not need with a placeholder. A key that turns off into one learns
    // nothing: not that the account is there, and not that it is not.
    let mut elsewhere = read.account_id;
    elsewhere[0] ^= 0x80;

    assert_eq!(
        verify_account(&asking_for(&read, &elsewhere, &read.state)),
        Err(BlockError::NotCovered)
    );
    // Answering the same read with no state does not turn a shrug into proved absence.
    assert_eq!(
        verify_account(&asking_for(&read, &elsewhere, &[])),
        Err(BlockError::NotCovered)
    );
}

#[test]
fn a_proof_for_one_account_can_prove_a_neighbour_is_absent() {
    let read = Read::parse(BASECHAIN);
    // Deeper down, the covered account's edge carries a label spanning the rest of the
    // key, and that label is inside the root hash. A key that disagrees with it has no
    // entry below, which the proof establishes without ever mentioning that key.
    let mut neighbour = read.account_id;
    neighbour[31] ^= 0xff;

    let account =
        verify_account(&asking_for(&read, &neighbour, &[])).expect("the label proves absence");
    assert_eq!(account.status, AccountStatus::Nonexistent);

    // The distinction is doing work: this is the same proof that says nothing at all
    // about the key in the test above.
    let mut elsewhere = read.account_id;
    elsewhere[0] ^= 0x80;
    assert_eq!(
        verify_account(&asking_for(&read, &elsewhere, &[])),
        Err(BlockError::NotCovered)
    );
}

#[test]
fn a_state_root_that_is_a_placeholder_is_refused() {
    // A pruned branch answers with the hash of what it replaced, so a placeholder carrying
    // the account's hash would bind if the binding compared hashes alone. It has no
    // contents, so accepting one would turn a verified read into an empty one.
    let read = Read::parse(BASECHAIN);
    let entry = {
        let roots = parse_boc(&read.proof).expect("the proof parses");
        let state_hash = proof::verify_block_state(&roots, &read.shard_block_root_hash)
            .expect("the block proof checks out");
        let state = proof::verify_shard_state(&roots, &state_hash).expect("the state is covered");
        state
            .account(&read.account_id)
            .expect("the dictionary reads")
            .found()
            .expect("the proof covers the account")
    };

    // The dictionary's own entry is that placeholder, and it carries the right hash.
    assert_eq!(entry.account_hash()[..], entry.account_cell().hash()[..]);
    let placeholder = entry
        .account_cell()
        .to_boc()
        .expect("the placeholder serializes");
    assert_eq!(
        verify_account(&read.with_state(&placeholder)),
        Err(BlockError::NotBound)
    );
}

#[test]
fn a_proof_whose_content_was_swapped_out_is_refused() {
    // The proof roots at the right hash and the bag of cells is well formed. What is wrong
    // is that the tree attached no longer hashes to the root the proof carries, which only
    // recomputing catches.
    let read = Read::parse(BASECHAIN);
    let roots = parse_boc(&read.proof).expect("the proof parses");
    let block_proof = roots
        .iter()
        .find(|root| root.data().get(1..33) == Some(&read.shard_block_root_hash[..]))
        .expect("a root covers the shard block");

    let content = block_proof.reference(0).expect("the proof has content");
    assert_eq!(
        proof::verify_merkle_proof(block_proof, &read.shard_block_root_hash),
        Ok(content)
    );

    let mut lying = read.shard_block_root_hash;
    lying[0] ^= 1;
    assert_eq!(
        proof::verify_merkle_proof(block_proof, &lying),
        Err(BlockError::ProofNotAnchored)
    );
}

#[test]
fn a_shard_record_is_read_for_the_shard_that_covers_the_account() {
    let read = Read::parse(BASECHAIN);
    let roots = parse_boc(&read.shard_proof).expect("the shard proof parses");
    let state_hash = proof::verify_block_state(&roots, &read.block_root_hash)
        .expect("the block proof checks out");
    let state: ShardState =
        proof::verify_shard_state(&roots, &state_hash).expect("the state is covered");
    let extra = state
        .masterchain_extra()
        .expect("the extra reads")
        .expect("a masterchain state has one");

    let descr = extra
        .shard_for(read.workchain, &read.account_id)
        .expect("the shard record reads")
        .found()
        .expect("the account's workchain is recorded");
    assert_eq!(descr.root_hash, read.shard_block_root_hash);

    // A workchain the masterchain has no record of.
    assert!(extra
        .shard_for(7, &read.account_id)
        .expect("the lookup reads")
        .found()
        .is_none());
}

#[test]
fn truncating_a_proof_never_produces_a_value() {
    let read = Read::parse(BASECHAIN);
    for cut in [1usize, 7, 64, 512, read.proof.len() - 1] {
        let attempt = AccountRead::in_shard(
            &read.block_root_hash,
            read.workchain,
            &read.account_id,
            &read.shard_proof,
            &read.proof[..cut],
            &read.state,
        );
        assert!(
            verify_account(&attempt).is_err(),
            "a proof cut to {cut} bytes must not verify"
        );
    }
}

/// How a corpus of single-byte edits came out.
struct Edits {
    tried: usize,
    refused: usize,
}

impl Edits {
    /// Edits every byte of `field` in turn and requires the answer never to change.
    ///
    /// The property being checked is not that every edit is refused. Some bytes a bag of
    /// cells carries take no part in the answer, and the clearest case is a pruned branch
    /// standing one level down: it holds a hash slot for every level up to its own, and a
    /// proof that only ever asks it at one level leaves the other slots unread. Editing an
    /// unread slot cannot change anything, and demanding an error there would be demanding
    /// the engine hash bytes it has no reason to hash.
    ///
    /// What must hold is that no edit produces a *different* account. Either the read
    /// fails, or it succeeds with exactly the account the untampered bytes gave.
    fn sweep(
        read: &Read,
        field: impl Fn(&Read) -> &Vec<u8>,
        rebuild: impl for<'a> Fn(&'a Read, &'a [u8]) -> AccountRead<'a>,
    ) -> Edits {
        let expected = verify_account(&read.as_read()).expect("the untampered read verifies");
        let original = field(read).clone();
        let mut edits = Edits {
            tried: 0,
            refused: 0,
        };

        for position in 0..original.len() {
            for mask in [0x01u8, 0x80] {
                let mut tampered = original.clone();
                tampered[position] ^= mask;
                edits.tried += 1;
                match verify_account(&rebuild(read, &tampered)) {
                    Err(_) => edits.refused += 1,
                    Ok(account) => assert_eq!(
                        account, expected,
                        "byte {position} edited by {mask:#04x} changed the answer"
                    ),
                }
            }
        }
        edits
    }

    /// Requires most of the bytes to be load-bearing.
    ///
    /// Not all of them are, and the share that is not depends on how many pruned branches
    /// a given proof carries and at which levels, so pinning an exact count would pin an
    /// accident of one capture. What this rules out is the failure that would matter: a
    /// change that quietly stopped most of a proof from being hashed would show up here as
    /// a collapse in the refusal rate, while the assertion inside the sweep keeps the
    /// accepted remainder from ever meaning something different.
    fn mostly_refused(&self) {
        assert!(
            self.refused * 10 >= self.tried * 9,
            "only {} of {} edits were refused",
            self.refused,
            self.tried
        );
    }
}

#[test]
fn no_edit_to_a_proof_changes_the_answer() {
    let read = Read::parse(BASECHAIN);
    // A liteserver sends these without the optional checksum, so nothing is caught
    // cheaply: every edit below is decided by recomputing hashes rather than by a
    // checksum, which is the property worth having.
    assert!(read.proof[4] & 0x40 == 0, "no checksum to hide behind");

    let edits = Edits::sweep(
        &read,
        |r| &r.proof,
        |r, bytes| {
            AccountRead::in_shard(
                &r.block_root_hash,
                r.workchain,
                &r.account_id,
                &r.shard_proof,
                bytes,
                &r.state,
            )
        },
    );
    assert!(edits.tried > 4000, "only {} edits were tried", edits.tried);
    edits.mostly_refused();
}

#[test]
fn no_edit_to_the_account_state_changes_the_answer() {
    let read = Read::parse(BASECHAIN);
    let edits = Edits::sweep(&read, |r| &r.state, |r, bytes| r.with_state(bytes));
    assert!(edits.tried > 3000, "only {} edits were tried", edits.tried);
    // Every byte of an account state is hashed into the hash the proof binds, so unlike a
    // proof there is nothing here that does not matter.
    assert_eq!(
        edits.refused, edits.tried,
        "an edit to the state left it still binding to the proof"
    );
}

#[test]
fn no_edit_to_a_shard_proof_changes_the_answer() {
    let read = Read::parse(BASECHAIN);
    // A shard proof that does not check out must never leave the engine pointed at a
    // shard block of the server's choosing.
    let edits = Edits::sweep(
        &read,
        |r| &r.shard_proof,
        |r, bytes| {
            AccountRead::in_shard(
                &r.block_root_hash,
                r.workchain,
                &r.account_id,
                bytes,
                &r.proof,
                &r.state,
            )
        },
    );
    assert!(edits.tried > 2000, "only {} edits were tried", edits.tried);
    edits.mostly_refused();
}
