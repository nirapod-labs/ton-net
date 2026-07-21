// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A block, read for its header, its configuration, and the state it leaves behind.

use ton_net_cell::{Cell, CellType, Slice};

use crate::error::BlockError;
use crate::proof::verify_merkle_proof;

/// The constructor tag a block begins with.
const BLOCK_TAG: u32 = 0x11ef_55aa;
/// `block_info#9bc7a987`
const BLOCK_INFO_TAG: u32 = 0x9bc7_a987;
/// `block_extra#4a33f6fd`
const BLOCK_EXTRA_TAG: u32 = 0x4a33_f6fd;
/// `masterchain_block_extra#cca5`
const MC_BLOCK_EXTRA_TAG: u64 = 0xcca5;

/// The reference holding a block's header.
const INFO_REFERENCE: usize = 0;
/// The reference holding a block's state update.
const STATE_UPDATE_REFERENCE: usize = 2;
/// The reference holding a block's extra.
const EXTRA_REFERENCE: usize = 3;

/// The largest shard prefix length a shard identifier may declare.
const MAX_SHARD_PREFIX_BITS: u64 = 60;

/// A masterchain block's header, read for the fields a proof chain rests on.
///
/// Every field here is covered by the block's Merkle proof, so a value read from one is
/// worth exactly what the block's root hash is worth: a header read out of an unchecked
/// proof says nothing, and one read out of a proof anchored to a signed root hash says
/// what the validators signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    /// The workchain the block belongs to. The masterchain is `-1`.
    pub workchain: i32,
    /// The shard the block covers, as the 64-bit prefix mask a block identity uses.
    /// The masterchain shard is `0x8000000000000000`.
    pub shard: u64,
    /// The block's sequence number.
    pub seqno: u32,
    /// Whether the block is a key block, and so carries the network configuration in
    /// its own body.
    pub key_block: bool,
    /// When the block was generated, in seconds since the Unix epoch.
    pub gen_utime: u32,
    /// A short hash of the validator list that signed, in the order the round put them
    /// in. Checking it requires reproducing that order, which this release does not do.
    pub gen_validator_list_hash_short: u32,
    /// The catchain sequence number the block was produced under.
    pub gen_catchain_seqno: u32,
    /// The sequence number of the key block before this one.
    pub prev_key_block_seqno: u32,
}

/// A block, walked for its header, its configuration, and the state it leaves behind.
///
/// A block carries its header, its value flow, its transactions and its state update.
/// This reads three of those: the header, because a proof chain checks a destination's
/// generation time and key-block bit against it; the configuration a key block carries,
/// because that is where the validator set for the next step comes from; and the state
/// update, because that names the shard state an account proof must root at.
#[derive(Debug, Clone)]
pub struct Block {
    cell: Cell,
}

impl Block {
    /// Reads a block from its root cell, checking the constructor tag.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::WrongConstructor`] if the cell is not a block, or
    /// [`BlockError::Cell`] if it ends early.
    pub fn from_cell(cell: &Cell) -> Result<Block, BlockError> {
        let tag = cell.parse().load_uint(32)? as u32;
        if tag != BLOCK_TAG {
            return Err(BlockError::WrongConstructor { expected: "block" });
        }
        Ok(Block { cell: cell.clone() })
    }

    /// Reads the block a Merkle proof covers, requiring the proof to root at `root_hash`.
    ///
    /// This is the only way a block should be built out of bytes a server sent. The
    /// proof is checked before anything in it is read, so a server that answers about
    /// some other block fails here rather than returning a header that looks fine.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Cell`] if the bytes are not a bag of cells,
    /// [`BlockError::Malformed`] if it holds no root, [`BlockError::NotAMerkleProof`],
    /// [`BlockError::ProofNotAnchored`] or [`BlockError::ProofInconsistent`] if the
    /// proof does not check out against `root_hash`, and
    /// [`BlockError::WrongConstructor`] if what it covers is not a block.
    pub fn from_proof(proof: &[u8], root_hash: &[u8; 32]) -> Result<Block, BlockError> {
        let roots = ton_net_cell::parse_boc(proof)?;
        let root = roots
            .first()
            .ok_or(BlockError::Malformed("a proof with no root cell"))?;
        Block::from_cell(verify_merkle_proof(root, root_hash)?)
    }

    /// Reads the block's header.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the block has no header reference or the
    /// header ends early, [`BlockError::WrongConstructor`] if what is there is not a
    /// header or its shard identifier is some other constructor, and
    /// [`BlockError::Cell`] if a field cannot be read.
    pub fn header(&self) -> Result<BlockHeader, BlockError> {
        let info = self
            .cell
            .reference(INFO_REFERENCE)
            .ok_or(BlockError::Malformed("a block without a header"))?;
        if info.is_exotic() {
            return Err(BlockError::NotCovered);
        }

        let mut s = info.parse();
        if s.load_uint(32)? as u32 != BLOCK_INFO_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "a block header",
            });
        }
        s.skip_bits(32)?; // version
                          // not_master, after_merge, before_split, after_split, want_split, want_merge
        s.skip_bits(6)?;
        let key_block = s.load_bit()?;
        s.skip_bits(1)?; // vert_seqno_incr
        s.skip_bits(8)?; // flags
        let seqno = s.load_uint(32)? as u32;
        s.skip_bits(32)?; // vert_seq_no
        let (workchain, shard) = read_shard_ident(&mut s)?;
        let gen_utime = s.load_uint(32)? as u32;
        s.skip_bits(64 + 64)?; // start_lt, end_lt
        let gen_validator_list_hash_short = s.load_uint(32)? as u32;
        let gen_catchain_seqno = s.load_uint(32)? as u32;
        s.skip_bits(32)?; // min_ref_mc_seqno
        let prev_key_block_seqno = s.load_uint(32)? as u32;

        Ok(BlockHeader {
            workchain,
            shard,
            seqno,
            key_block,
            gen_utime,
            gen_validator_list_hash_short,
            gen_catchain_seqno,
            prev_key_block_seqno,
        })
    }

    /// Reads the root of the configuration dictionary a key block carries.
    ///
    /// Only a key block holds the configuration in its body, which is what makes key
    /// blocks the waypoints of a proof chain: everything needed to check the next block
    /// is inside the one already trusted.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::NotAKeyBlock`] if the block carries no configuration,
    /// [`BlockError::NotCovered`] if the proof prunes the masterchain extra away,
    /// [`BlockError::Malformed`] if a part of the walk is missing, and
    /// [`BlockError::WrongConstructor`] if a tag along the way is not what it should be.
    pub fn config(&self) -> Result<Cell, BlockError> {
        let extra = self
            .cell
            .reference(EXTRA_REFERENCE)
            .ok_or(BlockError::Malformed("a block without an extra"))?;
        if extra.is_exotic() {
            return Err(BlockError::NotCovered);
        }

        let mut s = extra.parse();
        if s.load_uint(32)? as u32 != BLOCK_EXTRA_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "a block extra",
            });
        }
        // The three message and account descriptors come first as references. Stepping
        // over them moves the reference cursor, which is what puts the masterchain extra
        // at the reference the maybe-bit below actually names.
        s.load_ref()?; // in_msg_descr
        s.load_ref()?; // out_msg_descr
        s.load_ref()?; // account_blocks
        s.skip_bits(256 + 256)?; // rand_seed, created_by
        let custom = s.load_maybe_ref()?.ok_or(BlockError::NotAKeyBlock)?;
        if custom.is_exotic() {
            return Err(BlockError::NotCovered);
        }

        let mut s = custom.parse();
        if s.load_uint(16)? != MC_BLOCK_EXTRA_TAG {
            return Err(BlockError::WrongConstructor {
                expected: "a masterchain block extra",
            });
        }
        // The configuration is present only when this bit is set, so a chain that tries
        // to continue from an ordinary block stops here rather than reading past it.
        if !s.load_bit()? {
            return Err(BlockError::NotAKeyBlock);
        }
        s.load_maybe_ref()?; // shard_hashes
        s.load_maybe_ref()?; // shard_fees root
        skip_currency(&mut s)?; // the fees half of its augmentation
        skip_currency(&mut s)?; // the created half
        s.load_ref()?; // prev_blk_signatures and the two messages
        s.skip_bits(256)?; // config_addr
        Ok(s.load_ref()?.clone())
    }

    /// The root cell of the block.
    #[must_use]
    pub fn cell(&self) -> &Cell {
        &self.cell
    }

    /// The hash of the shard state this block leaves behind.
    ///
    /// A block stores its state as a Merkle update, an old state and a new one named by
    /// hash. The new hash is the root an account proof for this block must reproduce.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the block has no state update, or the
    /// update is not a Merkle update long enough to hold both hashes.
    pub fn new_state_hash(&self) -> Result<[u8; 32], BlockError> {
        let update = self
            .cell
            .reference(STATE_UPDATE_REFERENCE)
            .ok_or(BlockError::Malformed("block without a state update"))?;
        if update.cell_type() != CellType::MerkleUpdate {
            return Err(BlockError::Malformed(
                "block state update is not a merkle update",
            ));
        }
        // A merkle update holds a type byte, the old hash, then the new hash.
        let bytes = update
            .data()
            .get(33..65)
            .ok_or(BlockError::Malformed("merkle update is too short"))?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Ok(hash)
    }
}

/// Reads a `ShardIdent` and returns the workchain and the shard as a block identity
/// states it.
///
/// A shard identifier stores a prefix and how many of its bits are significant. A block
/// identity states the same shard as a mask, with a one marking the end of the prefix,
/// so the masterchain's empty prefix becomes `0x8000000000000000`.
fn read_shard_ident(s: &mut Slice<'_>) -> Result<(i32, u64), BlockError> {
    if s.load_uint(2)? != 0 {
        return Err(BlockError::WrongConstructor {
            expected: "a shard identifier",
        });
    }
    let prefix_bits = s.load_uint(6)?;
    if prefix_bits > MAX_SHARD_PREFIX_BITS {
        return Err(BlockError::Malformed("a shard prefix longer than 60 bits"));
    }
    let workchain = s.load_uint(32)? as u32 as i32;
    let prefix = s.load_uint(64)?;
    // Only the declared bits are the prefix; the rest of the word is cleared before the
    // terminator goes in. Every real header carries them clear already, so this changes
    // no answer today. A header that did not would otherwise give this client a shard
    // value no other implementation computes, and the shard is compared for equality.
    let significant = prefix & !(u64::MAX >> prefix_bits >> 1);
    Ok((workchain, significant | 1u64 << (63 - prefix_bits)))
}

/// Steps over a `CurrencyCollection`: a grams amount and a maybe-referenced dictionary.
fn skip_currency(s: &mut Slice<'_>) -> Result<(), BlockError> {
    s.load_var_uint(16)?;
    s.load_maybe_ref()?;
    Ok(())
}
