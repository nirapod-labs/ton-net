//! A block, read only for what an account proof depends on.

use ton_net_cell::{Cell, CellType};

use crate::error::BlockError;

/// The constructor tag a block begins with.
const BLOCK_TAG: u32 = 0x11ef_55aa;

/// The reference holding a block's state update.
const STATE_UPDATE_REFERENCE: usize = 2;

/// A block, walked only as far as the state it leaves behind.
///
/// A block carries its header, its value flow, its transactions and its state update.
/// This reads the state update, because that is what names the shard state an account
/// proof must root at, and so what ties a trusted block hash to an account read.
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
