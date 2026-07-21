//! Checking an account read against a block hash the caller trusts.
//!
//! A liteserver's answer is worth what its proof is worth. This module turns one trusted
//! hash into a checked account: every step recomputes a hash from bytes the server sent
//! and requires it to equal a hash the previous step already established, so nothing the
//! server says is believed except what the arithmetic forces.
//!
//! # What is trusted
//!
//! One input: the masterchain block root hash the caller supplies. Everything else is
//! derived from it. Nothing else the server sends is taken on trust, including the shard
//! block it names for the account, which is derived from the masterchain state rather
//! than believed.
//!
//! Where that hash comes from is the caller's problem in this release, and it is a real
//! one: a client that asks the same server for the anchor has proved nothing. Deriving
//! the anchor from a single pinned key block is block sync, which this crate does not do
//! yet.
//!
//! # The chain
//!
//! For an account in a shard:
//!
//! 1. The shard proof roots at the trusted block hash and exposes the block's state
//!    update, naming the masterchain state.
//! 2. A second proof in the same bag roots at that state and exposes the shard records,
//!    which give the root hash of the shard block holding the account.
//! 3. The account proof roots at that shard block hash and exposes its state update,
//!    naming the shard state.
//! 4. A second proof in the same bag roots at that state and exposes the accounts
//!    dictionary, which gives the hash of the account's own cell.
//! 5. The state bytes are hashed and required to equal it.
//!
//! For a masterchain account the first two steps are skipped: the account is in the
//! trusted block's own state.

use ton_net_cell::{parse_boc, Cell, CellType};

use crate::account::Account;
use crate::block::Block;
use crate::dict::Lookup;
use crate::error::BlockError;
use crate::shard::ShardState;

/// The workchain id of the masterchain.
const MASTERCHAIN: i32 = -1;

/// The offset of a Merkle proof's stored root hash within its cell data.
const MERKLE_HASH: usize = 1;

/// The offset of a Merkle proof's stored depth within its cell data.
const MERKLE_DEPTH: usize = 33;

/// One account read as a liteserver answered it, ready to be checked.
///
/// Build one with [`masterchain`](AccountRead::masterchain) or
/// [`in_shard`](AccountRead::in_shard). The two differ in whether a shard proof is needed,
/// and separating them keeps a shard read from silently skipping the step that ties its
/// shard to the masterchain.
#[derive(Debug, Clone, Copy)]
pub struct AccountRead<'a> {
    trusted_block_hash: &'a [u8; 32],
    workchain: i32,
    account_id: &'a [u8; 32],
    shard_proof: &'a [u8],
    proof: &'a [u8],
    state: &'a [u8],
}

impl<'a> AccountRead<'a> {
    /// A read of a masterchain account, which lives in the trusted block's own state.
    #[must_use]
    pub fn masterchain(
        trusted_block_hash: &'a [u8; 32],
        account_id: &'a [u8; 32],
        proof: &'a [u8],
        state: &'a [u8],
    ) -> AccountRead<'a> {
        AccountRead {
            trusted_block_hash,
            workchain: MASTERCHAIN,
            account_id,
            shard_proof: &[],
            proof,
            state,
        }
    }

    /// A read of an account in a shard, which `shard_proof` ties to the trusted block.
    #[must_use]
    pub fn in_shard(
        trusted_block_hash: &'a [u8; 32],
        workchain: i32,
        account_id: &'a [u8; 32],
        shard_proof: &'a [u8],
        proof: &'a [u8],
        state: &'a [u8],
    ) -> AccountRead<'a> {
        AccountRead {
            trusted_block_hash,
            workchain,
            account_id,
            shard_proof,
            proof,
            state,
        }
    }
}

/// Checks a Merkle proof cell and returns the tree it covers.
///
/// A Merkle proof carries the hash of the tree it stands for. This recomputes that hash
/// from the tree actually attached and requires the two to agree, then requires the
/// result to be `expected_root`. The recomputation is the whole point: the stored hash is
/// just a claim until the content is hashed against it.
///
/// The returned tree is the proof's content, in which the branches the proof left out are
/// pruned placeholders. Reading one yields nothing, which is what keeps a partial proof
/// from reading as a complete answer.
///
/// # Errors
///
/// Returns [`BlockError::NotAMerkleProof`] if the cell is some other kind,
/// [`BlockError::ProofNotAnchored`] if it stands for a different tree than
/// `expected_root`, or [`BlockError::ProofInconsistent`] if its content does not hash to
/// the root it carries.
pub fn verify_merkle_proof<'a>(
    cell: &'a Cell,
    expected_root: &[u8; 32],
) -> Result<&'a Cell, BlockError> {
    if cell.cell_type() != CellType::MerkleProof {
        return Err(BlockError::NotAMerkleProof);
    }
    let data = cell.data();
    let stored = data
        .get(MERKLE_HASH..MERKLE_HASH + 32)
        .ok_or(BlockError::Malformed("merkle proof without a root hash"))?;
    if stored != expected_root {
        return Err(BlockError::ProofNotAnchored);
    }

    let content = cell
        .reference(0)
        .ok_or(BlockError::Malformed("merkle proof without content"))?;
    if content.hash() != expected_root {
        return Err(BlockError::ProofInconsistent);
    }

    // The depth is hashed into the parent alongside the hash, so a proof that disagrees
    // with its own content here is malformed even though the hashes matched.
    let depth = data
        .get(MERKLE_DEPTH..MERKLE_DEPTH + 2)
        .ok_or(BlockError::Malformed("merkle proof without a depth"))?;
    if u16::from_be_bytes([depth[0], depth[1]]) != content.depth() {
        return Err(BlockError::ProofInconsistent);
    }

    Ok(content)
}

/// Finds the proof in `roots` that roots at `expected_root`, and checks it.
///
/// A bag of proofs holds several roots and does not say which is which. Selecting by the
/// hash a root claims is safe because the claim is then checked: a root that lies about
/// what it covers fails [`verify_merkle_proof`] rather than being believed.
fn rooted_at<'a>(roots: &'a [Cell], expected_root: &[u8; 32]) -> Result<&'a Cell, BlockError> {
    for root in roots {
        if root.cell_type() != CellType::MerkleProof {
            continue;
        }
        if root.data().get(MERKLE_HASH..MERKLE_HASH + 32) == Some(&expected_root[..]) {
            return verify_merkle_proof(root, expected_root);
        }
    }
    Err(BlockError::ProofNotAnchored)
}

/// Checks the proof of a block and returns the hash of the state it leaves behind.
///
/// This is the step that turns a trusted block hash into a trusted state hash. A block
/// carries a Merkle update whose new-hash names its resulting state, and that update is
/// inside the block, so it is covered by the block hash.
///
/// # Errors
///
/// Returns [`BlockError::ProofNotAnchored`] if no proof roots at `block_hash`, or
/// [`BlockError::WrongConstructor`] if what it covers is not a block.
pub fn verify_block_state(roots: &[Cell], block_hash: &[u8; 32]) -> Result<[u8; 32], BlockError> {
    Block::from_cell(rooted_at(roots, block_hash)?)?.new_state_hash()
}

/// Checks the proof of a state and returns it.
///
/// # Errors
///
/// Returns [`BlockError::ProofNotAnchored`] if no proof roots at `state_hash`, or
/// [`BlockError::WrongConstructor`] if what it covers is not a shard state.
pub fn verify_shard_state(roots: &[Cell], state_hash: &[u8; 32]) -> Result<ShardState, BlockError> {
    ShardState::from_cell(rooted_at(roots, state_hash)?)
}

/// Derives the shard block holding an account, from a proof rooted at a trusted block.
///
/// The masterchain records the latest block of every shard, so a proof of the masterchain
/// state proves which shard block an account's state has to come from. This is what stops
/// a server from answering a basechain read out of a shard block of its own choosing.
///
/// Returns the shard block's root hash.
///
/// # Errors
///
/// Returns [`BlockError::ProofNotAnchored`] if the proof does not root at
/// `trusted_block_hash`, or [`BlockError::NotCovered`] if it prunes away the shard record
/// for the account.
pub fn verify_shard_block(
    shard_proof: &[u8],
    trusted_block_hash: &[u8; 32],
    workchain: i32,
    account_id: &[u8; 32],
) -> Result<[u8; 32], BlockError> {
    let roots = parse_boc(shard_proof)?;
    let state_hash = verify_block_state(&roots, trusted_block_hash)?;
    let state = verify_shard_state(&roots, &state_hash)?;
    let extra = state.masterchain_extra()?.ok_or(BlockError::NotCovered)?;

    match extra.shard_for(workchain, account_id)? {
        Lookup::Found(descr) => Ok(descr.root_hash),
        // The masterchain has no record of this workchain at all, which is not something
        // a read of an existing account can survive.
        Lookup::Absent => Err(BlockError::Malformed("no shard record for the workchain")),
        Lookup::Pruned => Err(BlockError::NotCovered),
    }
}

/// Checks an account read against the block hash the caller trusts.
///
/// Returns the decoded account on success. An account that does not exist at the block is
/// a result, not a failure, but only when the proof shows it is not there: a proof that
/// merely declines to cover the account fails with [`BlockError::NotCovered`].
///
/// # Errors
///
/// Returns [`BlockError::ProofNotAnchored`] or [`BlockError::ProofInconsistent`] if a
/// proof does not check out, [`BlockError::NotCovered`] if the proof says nothing about
/// the account, [`BlockError::NotBound`] if the state does not match what the proof binds
/// to the block, or [`BlockError::Cell`] if any of the bytes do not parse.
pub fn verify_account(read: &AccountRead<'_>) -> Result<Account, BlockError> {
    // The block the account's state has to come from. For a shard account this is derived
    // from the masterchain state rather than taken from what the server named it.
    let block_hash = if read.workchain == MASTERCHAIN {
        *read.trusted_block_hash
    } else {
        verify_shard_block(
            read.shard_proof,
            read.trusted_block_hash,
            read.workchain,
            read.account_id,
        )?
    };

    let roots = parse_boc(read.proof)?;
    let state_hash = verify_block_state(&roots, &block_hash)?;
    let state = verify_shard_state(&roots, &state_hash)?;

    let entry = match state.account(read.account_id)? {
        Lookup::Found(entry) => entry,
        Lookup::Pruned => return Err(BlockError::NotCovered),
        Lookup::Absent => {
            // The dictionary shows the account is not in the state. A server that sent
            // state bytes anyway is contradicting its own proof.
            return if read.state.is_empty() {
                Ok(Account::nonexistent())
            } else {
                Err(BlockError::NotBound)
            };
        }
    };

    // The proof holds an account, so an empty state is the server withholding it.
    if read.state.is_empty() {
        return Err(BlockError::NotBound);
    }

    let account = parse_boc(read.state)?;
    let root = account
        .first()
        .ok_or(BlockError::Malformed("account state has no root cell"))?;
    // An account is an ordinary cell. Refusing an exotic root closes the trick of
    // answering with a placeholder that carries the right hash and no contents.
    if root.is_exotic() {
        return Err(BlockError::NotBound);
    }
    if root.hash() != entry.account_hash() {
        return Err(BlockError::NotBound);
    }

    Account::from_cell(root)
}
