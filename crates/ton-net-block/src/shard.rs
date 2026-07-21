//! The shard state, walked as far as one account.

use ton_net_cell::Cell;

use crate::coins::Coins;
use crate::dict;
use crate::error::BlockError;

/// The constructor tag a shard state begins with.
const SHARD_STATE_TAG: u32 = 0x9023_afe2;

/// The reference holding a shard state's accounts dictionary.
const ACCOUNTS_REFERENCE: usize = 1;

/// The width of an account key in the accounts dictionary.
const ACCOUNT_KEY_BITS: u16 = 256;

/// What a shard's accounts dictionary holds for one account.
///
/// Inside a Merkle proof the account itself is pruned away, so
/// [`account_cell`](ShardAccountEntry::account_cell) is a placeholder rather than the
/// account. Its [`hash`](Cell::hash) is the account's hash either way, which is what
/// binds a separately delivered account state to this block.
#[derive(Debug, Clone)]
pub struct ShardAccountEntry {
    account: Cell,
    last_trans_hash: [u8; 32],
    last_trans_lt: u64,
}

impl ShardAccountEntry {
    /// The cell the dictionary points at for this account.
    #[must_use]
    pub fn account_cell(&self) -> &Cell {
        &self.account
    }

    /// The hash of the account's state at this block.
    #[must_use]
    pub fn account_hash(&self) -> &[u8; 32] {
        self.account.hash()
    }

    /// The hash of the account's last transaction.
    #[must_use]
    pub fn last_trans_hash(&self) -> &[u8; 32] {
        &self.last_trans_hash
    }

    /// The logical time of the account's last transaction.
    #[must_use]
    pub fn last_trans_lt(&self) -> u64 {
        self.last_trans_lt
    }
}

/// A shard state, walked only as far as reading one account needs.
///
/// A shard state carries far more than this: message queues, libraries, and for the
/// masterchain the network configuration. This reads the accounts dictionary, which is
/// what an account read and its proof depend on.
#[derive(Debug, Clone)]
pub struct ShardState {
    cell: Cell,
}

impl ShardState {
    /// Reads a shard state from its root cell, checking the constructor tag.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::WrongConstructor`] if the cell is not a shard state, or
    /// [`BlockError::Cell`] if it ends early.
    pub fn from_cell(cell: &Cell) -> Result<ShardState, BlockError> {
        let tag = cell.parse().load_uint(32)? as u32;
        if tag != SHARD_STATE_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "shard_state",
            });
        }
        Ok(ShardState { cell: cell.clone() })
    }

    /// The root cell of the state.
    #[must_use]
    pub fn cell(&self) -> &Cell {
        &self.cell
    }

    /// The cell holding the accounts dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the state has no accounts reference.
    pub fn accounts(&self) -> Result<&Cell, BlockError> {
        self.cell
            .reference(ACCOUNTS_REFERENCE)
            .ok_or(BlockError::Malformed("shard state without accounts"))
    }

    /// Looks one account up in the shard's accounts dictionary.
    ///
    /// Returns `None` when the dictionary does not hold the account. Over a Merkle proof
    /// that also covers an account the proof did not include, because a proof prunes
    /// every branch but the one it covers.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] or [`BlockError::Cell`] if the state or the
    /// dictionary does not read as it should.
    pub fn account(&self, account_id: &[u8; 32]) -> Result<Option<ShardAccountEntry>, BlockError> {
        let accounts = self.accounts()?;
        let mut slice = accounts.parse();
        // An augmented dictionary: a bit, then the root, then the summary over it.
        let Some(root) = slice.load_maybe_ref()? else {
            return Ok(None);
        };
        let Some(entry) = dict::lookup(root, ACCOUNT_KEY_BITS, account_id)? else {
            return Ok(None);
        };

        let mut leaf = entry.slice()?;
        // The augmentation the accounts dictionary carries: how deep the subtree splits,
        // and the balance under it. Stepped over to reach the account itself.
        leaf.skip_bits(5)?;
        let _ = Coins::load(&mut leaf)?;
        let _ = leaf.load_maybe_ref()?;

        // The account record: the account, then how it last changed.
        let account = leaf.load_ref()?.clone();
        let hash = leaf.load_bytes(32)?;
        let mut last_trans_hash = [0u8; 32];
        last_trans_hash.copy_from_slice(&hash);
        let last_trans_lt = leaf.load_uint(64)?;

        Ok(Some(ShardAccountEntry {
            account,
            last_trans_hash,
            last_trans_lt,
        }))
    }
}
