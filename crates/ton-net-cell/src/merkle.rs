// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Merkle proofs and updates: reading the tree one stands for, and building one.
//!
//! A Merkle cell covers one or more trees by hash and reveals only the branches it chose to
//! keep. A [proof](create_proof) covers a single tree and [virtualizing](virtualize) one
//! reads it back; an [update](create_update) covers an old tree and a new one, and
//! [applying](apply_update) it rebuilds the new tree from a base that holds the old. Both
//! lean on one property of the cell model: below its own level a Merkle or pruned cell
//! answers with the level-zero hash of what it stands for, so a tree with branches replaced
//! hashes as the whole did.
//!
//! The cell model also carries the arithmetic. A Merkle cell resolves one level of what it
//! covers, so its content sits one level down and answers one level up, which [`Cell`]
//! computes when it is built. Building one is therefore storing each covered tree's level
//! zero hash and depth and letting the cell model settle the rest.
//!
//! A running virtualization offset, for reading through proofs nested inside proofs, is not
//! built here. The structures this client reads do not nest one: a block, a state, an
//! account and a shard proof each cover a single tree, and a block's state update covers a
//! pair of them at one level. The offset is added when a structure that needs it does.

mod proof;
mod update;
mod virtualize;

pub use proof::create_proof;
pub use update::{apply_update, create_update, may_apply, validate_update};
pub use virtualize::virtualize;

use crate::builder::Builder;
use crate::cell::{Cell, CellType};
use crate::error::CellError;

/// Builds an exotic cell that stands for one or more ordinary trees by hash.
///
/// A Merkle proof and a Merkle update share a shape: a tag, then each covered tree's level
/// zero hash, then each tree's depth, then the trees as references. Their mask is what the
/// children imply, the covered masks combined and shifted down one, which the cell model
/// requires and this gives. Every covered tree has to be ordinary, since a Merkle cell
/// stands for the ordinary trees a proof or an update transforms.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `kind` is not an exotic covering kind, if a covered
/// tree is exotic, or if the cell does not form.
fn covering_cell(kind: CellType, covered: &[&Cell]) -> Result<Cell, CellError> {
    let tag = kind
        .tag()
        .ok_or(CellError::Malformed("an ordinary cell cannot cover a tree"))?;

    let mut mask = 0u8;
    for &cell in covered {
        if cell.is_exotic() {
            return Err(CellError::Malformed(
                "a merkle cell stands for an ordinary tree",
            ));
        }
        mask |= cell.level_mask();
    }

    let mut builder = Builder::new();
    builder.store_uint(u64::from(tag), 8)?;
    for &cell in covered {
        builder.store_bytes(cell.hash())?;
    }
    for &cell in covered {
        builder.store_uint(u64::from(cell.depth()), 16)?;
    }
    for &cell in covered {
        builder.store_ref(cell.clone())?;
    }
    // A Merkle cell stands one level up from what it covers, so its mask is the covered
    // masks shifted down one. The cell model implies exactly this and refuses any other.
    builder.finish(kind, mask >> 1)
}
