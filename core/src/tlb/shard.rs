// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The shard state, walked as far as one account or one shard binding.

use ton_net_cell::{Cell, Dict, Lookup, Slice};

use crate::coins::Coins;
use crate::error::BlockError;

/// The constructor tag a shard state begins with.
const SHARD_STATE_TAG: u32 = 0x9023_afe2;

/// The reference holding a shard state's accounts dictionary.
const ACCOUNTS_REFERENCE: usize = 1;

/// The reference holding a masterchain state's extra, when it has one.
const CUSTOM_REFERENCE: usize = 3;

/// The width of an account key in the accounts dictionary.
const ACCOUNT_KEY_BITS: u16 = 256;

/// The constructor tag a masterchain state extra begins with.
const MC_STATE_EXTRA_TAG: u64 = 0xcc26;

/// The width of a workchain key in the shard-hashes dictionary.
const WORKCHAIN_KEY_BITS: u16 = 32;

/// The two constructor tags a shard descriptor begins with.
///
/// The two differ only past the fields read here, in whether the fee counters sit inline
/// or behind a reference.
const SHARD_DESCR_TAGS: [u64; 2] = [0xa, 0xb];

/// The deepest a workchain may split, which bounds the shard tree walk.
const MAX_SPLIT_DEPTH: usize = 60;

/// What a shard's accounts dictionary holds for one account.
///
/// Inside a Merkle proof the account itself is pruned away, so
/// [`account_cell`](ShardAccountEntry::account_cell) is a placeholder rather than the
/// account. Its [`hash`](Cell::hash) is the account's hash either way, which is what
/// binds a separately delivered account state to this block.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn from_cell(cell: &Cell) -> Result<Self, BlockError> {
        let tag = cell.parse().load_u32()?;
        if tag != SHARD_STATE_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "shard_state",
            });
        }
        Ok(Self { cell: cell.clone() })
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
    /// The three outcomes are described on [`Lookup`]. Over a Merkle proof the difference
    /// between an account the dictionary shows is not there and one the proof simply does
    /// not cover is the difference between an answer and a shrug.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] or [`BlockError::Cell`] if the state or the
    /// dictionary does not read as it should.
    pub fn account(&self, account_id: &[u8; 32]) -> Result<Lookup<ShardAccountEntry>, BlockError> {
        let accounts = self.accounts()?;
        // A proof may prune the dictionary away entirely, and a placeholder's first bit
        // is clear, which reads exactly like an empty dictionary. Without this the shrug
        // and the answer become one answer, and a server can deny that any account exists
        // by withholding rather than by lying.
        if accounts.is_exotic() {
            return Ok(Lookup::Pruned);
        }
        let mut slice = accounts.parse();
        // An augmented dictionary: a bit, then the root, then the summary over it. An
        // empty dictionary is a visible statement that it holds nothing.
        let Some(root) = slice.load_maybe_ref()? else {
            return Ok(Lookup::Absent);
        };
        let entry = match Dict::from_root(Some(root.clone()), ACCOUNT_KEY_BITS)?.get(account_id)? {
            Lookup::Found(entry) => entry,
            Lookup::Absent => return Ok(Lookup::Absent),
            Lookup::Pruned => return Ok(Lookup::Pruned),
        };

        let mut leaf = entry.slice()?;
        // The augmentation the accounts dictionary carries: how deep the subtree splits,
        // and the balance under it. Stepped over to reach the account itself. The balance
        // is a currency collection, so its extra-currency dictionary takes a reference
        // when it is not empty, and the account is not always the first reference.
        leaf.skip_bits(5)?;
        let _ = Coins::load(&mut leaf)?;
        let _ = leaf.load_maybe_ref()?;

        // The account record: the account, then how it last changed.
        let account = leaf.load_ref()?.clone();
        let hash = leaf.load_bytes(32)?;
        let mut last_trans_hash = [0u8; 32];
        last_trans_hash.copy_from_slice(&hash);
        let last_trans_lt = leaf.load_uint(64)?;

        Ok(Lookup::Found(ShardAccountEntry {
            account,
            last_trans_hash,
            last_trans_lt,
        }))
    }

    /// The masterchain extra, which only a masterchain state carries.
    ///
    /// Returns `None` for a shard state that has no extra, and for a masterchain state
    /// whose extra was pruned out of the proof being read.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the header does not read as a shard state, or
    /// [`BlockError::WrongConstructor`] if the extra is some other structure.
    pub fn masterchain_extra(&self) -> Result<Lookup<McStateExtra>, BlockError> {
        let mut slice = self.cell.parse();
        // The state says outright whether an extra follows, so a basechain state is a
        // statement rather than a silence.
        if !skip_to_custom(&mut slice)? {
            return Ok(Lookup::Absent);
        }
        let cell = self
            .cell
            .reference(CUSTOM_REFERENCE)
            .ok_or(BlockError::Malformed("shard state without its extra"))?;
        // A proof that prunes the extra away is not a state that has none, and the two
        // must not answer alike: one is a shrug and the other a fact about the chain.
        if cell.is_exotic() {
            return Ok(Lookup::Pruned);
        }
        Ok(Lookup::Found(McStateExtra::from_cell(cell)?))
    }
}

/// Reads past the fixed shard-state header, returning whether an extra follows.
///
/// The header is fixed width, so the count below is the whole of it. A shard state cell
/// holds exactly these bits and nothing more, which is what makes reading it this way
/// safe: a layout change shows up as a short read rather than as a silent shift.
fn skip_to_custom(slice: &mut Slice<'_>) -> Result<bool, BlockError> {
    // The constructor tag, already checked, then the global id.
    slice.skip_bits(32 + 32)?;
    // shard_ident$00 shard_pfx_bits:(#<= 60) workchain_id:int32 shard_prefix:uint64
    if slice.load_uint(2)? != 0 {
        return Err(BlockError::Malformed("shard identifier"));
    }
    slice.skip_bits(6 + 32 + 64)?;
    // seq_no, vert_seq_no, gen_utime, gen_lt, min_ref_mc_seqno, then before_split.
    slice.skip_bits(32 + 32 + 32 + 64 + 32 + 1)?;
    Ok(slice.load_bit()?)
}

/// What a masterchain state records about one shard's latest block.
///
/// Only the fields a verified account read needs are kept: the height, and the block root
/// hash that an account-state proof for that shard has to root at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShardDescr {
    /// The shard block's sequence number.
    pub seq_no: u32,
    /// The shard block's root hash.
    pub root_hash: [u8; 32],
}

impl ShardDescr {
    /// Reads a shard descriptor from a slice positioned at its constructor tag.
    fn load(slice: &mut Slice<'_>) -> Result<Self, BlockError> {
        let tag = slice.load_uint(4)?;
        if !SHARD_DESCR_TAGS.contains(&tag) {
            return Err(BlockError::WrongConstructor {
                expected: "shard_descr",
            });
        }
        let seq_no = slice.load_u32()?;
        slice.skip_bits(32 + 64 + 64)?; // reg_mc_seqno, start_lt, end_lt
        let bytes = slice.load_bytes(32)?;
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&bytes);
        Ok(Self { seq_no, root_hash })
    }
}

/// The masterchain-only part of a masterchain state.
///
/// A masterchain state carries the network configuration, the validator set, and the
/// record of every shard's latest block. This reads the last of those, which is what ties
/// a shard block to the masterchain block a caller trusts.
#[derive(Debug, Clone)]
pub struct McStateExtra {
    cell: Cell,
}

impl McStateExtra {
    /// Reads a masterchain extra from its cell, checking the constructor tag.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::WrongConstructor`] if the cell is not a masterchain extra.
    pub fn from_cell(cell: &Cell) -> Result<Self, BlockError> {
        let tag = cell.parse().load_uint(16)?;
        if tag != MC_STATE_EXTRA_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "masterchain_state_extra",
            });
        }
        Ok(Self { cell: cell.clone() })
    }

    /// Finds the shard whose address range holds an account, and what it last recorded.
    ///
    /// The shards of a workchain form a binary tree over address prefixes, so descending
    /// it by the bits of `account_id` lands on the one shard that covers the account. The
    /// walk is the coverage check: there is no other shard the account could be in.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] or [`BlockError::Cell`] if the shard record does
    /// not read as it should.
    pub fn shard_for(
        &self,
        workchain: i32,
        account_id: &[u8; 32],
    ) -> Result<Lookup<ShardDescr>, BlockError> {
        let mut slice = self.cell.parse();
        slice.skip_bits(16)?; // the constructor tag, already checked
        let Some(root) = slice.load_maybe_ref()? else {
            return Ok(Lookup::Absent);
        };
        let entry = match Dict::from_root(Some(root.clone()), WORKCHAIN_KEY_BITS)?
            .get(&workchain.to_be_bytes())?
        {
            Lookup::Found(entry) => entry,
            Lookup::Absent => return Ok(Lookup::Absent),
            Lookup::Pruned => return Ok(Lookup::Pruned),
        };

        // The dictionary holds each workchain's shard tree behind a reference.
        let tree = entry.slice()?.load_ref()?.clone();
        find_shard(&tree, account_id)
    }
}

/// Descends a workchain's shard tree by the leading bits of an account id.
fn find_shard(root: &Cell, account_id: &[u8; 32]) -> Result<Lookup<ShardDescr>, BlockError> {
    let mut node = root.clone();
    for depth in 0..=MAX_SPLIT_DEPTH {
        if node.is_exotic() {
            return Ok(Lookup::Pruned);
        }
        let mut slice = node.parse();
        if !slice.load_bit()? {
            // bt_leaf: this shard covers the account.
            return ShardDescr::load(&mut slice).map(Lookup::Found);
        }
        // bt_fork: the address bit at this depth chooses the half. The split limit keeps
        // the walk inside the account id, and running out of address bits would mean that
        // limit had been raised past what an address can steer.
        let byte = account_id
            .get(depth / 8)
            .copied()
            .ok_or(BlockError::Malformed(
                "shard tree deeper than an account id can steer",
            ))?;
        let branch = usize::from((byte >> (7 - depth % 8)) & 1 == 1);
        node = node
            .reference(branch)
            .ok_or(BlockError::Malformed("shard tree fork without both halves"))?
            .clone();
    }
    Err(BlockError::Malformed(
        "shard tree deeper than a shard splits",
    ))
}
