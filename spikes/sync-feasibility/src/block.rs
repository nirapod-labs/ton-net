//! The block header and the validator set, decoded from the cells a link carries.
//!
//! Two walks. The destination proof gives the header, which says whether the block is
//! a key block and when it was generated. The source key block's config proof gives
//! the validator set that has to have signed the destination.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use ton_net_block::{dict, proof::verify_merkle_proof, Lookup};
use ton_net_cell::{parse_boc, Cell, Slice};

/// `block#11ef55aa`
const BLOCK_TAG: u32 = 0x11ef_55aa;
/// `block_info#9bc7a987`
const BLOCK_INFO_TAG: u32 = 0x9bc7_a987;
/// `block_extra#4a33f6fd`
const BLOCK_EXTRA_TAG: u32 = 0x4a33_f6fd;
/// `masterchain_block_extra#cca5`
const MC_BLOCK_EXTRA_TAG: u64 = 0xcca5;
/// `validators#11` and `validators_ext#12`
const VALIDATORS_TAG: u64 = 0x11;
const VALIDATORS_EXT_TAG: u64 = 0x12;
/// `validator#53` and `validator_addr#73`
const VALIDATOR_TAG: u64 = 0x53;
const VALIDATOR_ADDR_TAG: u64 = 0x73;
/// `ed25519_pubkey#8e81278a`
const ED25519_PUBKEY_TAG: u64 = 0x8e81_278a;

/// The configuration parameter holding the current validator set.
const CURRENT_VALIDATORS: i32 = 34;

/// `pub.ed25519 key:int256 = PublicKey`, whose sha256 is a validator's short id.
const PUB_ED25519: u32 = 0x4813_b4c6;

pub type Error = String;

/// A masterchain block header, read for what a link check needs.
#[derive(Debug, Clone, Copy)]
pub struct BlockHeader {
    pub key_block: bool,
    pub seq_no: u32,
    pub gen_utime: u32,
    pub gen_validator_list_hash_short: u32,
    pub gen_catchain_seqno: u32,
    pub prev_key_block_seqno: u32,
}

/// The masterchain validator set for one round, as signature checking needs it.
///
/// `weights` holds only the validators that may sign a masterchain block, and
/// `total_weight` is the sum over exactly those. Deriving both from the same set is
/// the rule that makes a wrong derivation fail on live data rather than pass quietly.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub utime_since: u32,
    pub utime_until: u32,
    pub total: u16,
    pub main: u16,
    /// Short id to public key and weight, for the masterchain subset only.
    pub weights: HashMap<[u8; 32], ([u8; 32], u64)>,
    pub total_weight: u64,
}

fn cell_err(e: impl std::fmt::Display) -> Error {
    format!("cell: {e}")
}

/// Virtualizes a Merkle proof and returns the block cell it covers.
fn block_of(proof: &[u8], root_hash: &[u8; 32]) -> Result<Cell, Error> {
    let roots = parse_boc(proof).map_err(cell_err)?;
    let root = roots
        .first()
        .ok_or_else(|| "proof has no root cell".to_string())?;
    let covered = verify_merkle_proof(root, root_hash).map_err(|e| format!("merkle: {e}"))?;
    let tag = covered.parse().load_uint(32).map_err(cell_err)? as u32;
    if tag != BLOCK_TAG {
        return Err(format!("{tag:#010x} is not a block"));
    }
    Ok(covered.clone())
}

/// Reads the header of the block a `dest_proof` covers.
pub fn header(dest_proof: &[u8], root_hash: &[u8; 32]) -> Result<BlockHeader, Error> {
    let block = block_of(dest_proof, root_hash)?;
    let info = block
        .reference(0)
        .ok_or_else(|| "block without an info reference".to_string())?;

    let mut s = info.parse();
    let tag = s.load_uint(32).map_err(cell_err)? as u32;
    if tag != BLOCK_INFO_TAG {
        return Err(format!("{tag:#010x} is not a block info"));
    }
    s.skip_bits(32).map_err(cell_err)?; // version
                                        // not_master, after_merge, before_split, after_split, want_split, want_merge
    s.skip_bits(6).map_err(cell_err)?;
    let key_block = s.load_bit().map_err(cell_err)?;
    s.skip_bits(1).map_err(cell_err)?; // vert_seqno_incr
    s.skip_bits(8).map_err(cell_err)?; // flags
    let seq_no = s.load_uint(32).map_err(cell_err)? as u32;
    s.skip_bits(32).map_err(cell_err)?; // vert_seq_no
                                        // shard_ident$00 shard_pfx_bits:(#<= 60) workchain_id:int32 shard_prefix:uint64
    s.skip_bits(2 + 6 + 32 + 64).map_err(cell_err)?;
    let gen_utime = s.load_uint(32).map_err(cell_err)? as u32;
    s.skip_bits(64 + 64).map_err(cell_err)?; // start_lt, end_lt
    let gen_validator_list_hash_short = s.load_uint(32).map_err(cell_err)? as u32;
    let gen_catchain_seqno = s.load_uint(32).map_err(cell_err)? as u32;
    s.skip_bits(32).map_err(cell_err)?; // min_ref_mc_seqno
    let prev_key_block_seqno = s.load_uint(32).map_err(cell_err)? as u32;

    Ok(BlockHeader {
        key_block,
        seq_no,
        gen_utime,
        gen_validator_list_hash_short,
        gen_catchain_seqno,
        prev_key_block_seqno,
    })
}

/// Steps over a `CurrencyCollection`: a grams amount and a maybe-referenced dictionary.
fn skip_currency(s: &mut Slice<'_>) -> Result<(), Error> {
    s.load_var_uint(16).map_err(cell_err)?;
    s.load_maybe_ref().map_err(cell_err)?;
    Ok(())
}

/// Reads the validator set a key block names, from a proof of that key block.
///
/// A key block carries the whole network configuration in its own body, which is why
/// key blocks are the waypoints of a sync: everything needed to check the next block
/// is inside the one already trusted.
pub fn validator_set(config_proof: &[u8], root_hash: &[u8; 32]) -> Result<ValidatorSet, Error> {
    let block = block_of(config_proof, root_hash)?;
    let extra = block
        .reference(3)
        .ok_or_else(|| "block without an extra reference".to_string())?;

    let mut s = extra.parse();
    let tag = s.load_uint(32).map_err(cell_err)? as u32;
    if tag != BLOCK_EXTRA_TAG {
        return Err(format!("{tag:#010x} is not a block extra"));
    }
    // The three message and account descriptors come first as references. Stepping over
    // them moves the reference cursor, which is what puts the masterchain extra at the
    // reference the maybe-bit below actually names.
    s.load_ref().map_err(cell_err)?; // in_msg_descr
    s.load_ref().map_err(cell_err)?; // out_msg_descr
    s.load_ref().map_err(cell_err)?; // account_blocks
    s.skip_bits(256 + 256).map_err(cell_err)?; // rand_seed, created_by
    let custom = s
        .load_maybe_ref()
        .map_err(cell_err)?
        .ok_or_else(|| "block extra without a masterchain extra".to_string())?;
    if custom.is_exotic() {
        return Err("the masterchain extra is pruned out of the proof".to_string());
    }

    let mut s = custom.parse();
    let tag = s.load_uint(16).map_err(cell_err)?;
    if tag != MC_BLOCK_EXTRA_TAG {
        return Err(format!("{tag:#06x} is not a masterchain block extra"));
    }
    let key_block = s.load_bit().map_err(cell_err)?;
    if !key_block {
        return Err("a forward link starts at a block that carries no config".to_string());
    }
    s.load_maybe_ref().map_err(cell_err)?; // shard_hashes
    s.load_maybe_ref().map_err(cell_err)?; // shard_fees root
    skip_currency(&mut s)?; // the fees half of its augmentation
    skip_currency(&mut s)?; // the created half
    s.load_ref().map_err(cell_err)?; // prev_blk_signatures and the two messages
    s.skip_bits(256).map_err(cell_err)?; // config_addr
    let config_root = s.load_ref().map_err(cell_err)?;

    let entry = match dict::lookup(config_root, 32, &CURRENT_VALIDATORS.to_be_bytes())
        .map_err(|e| format!("config dictionary: {e}"))?
    {
        Lookup::Found(entry) => entry,
        Lookup::Absent => return Err("the config has no parameter 34".to_string()),
        Lookup::Pruned => return Err("parameter 34 is pruned out of the proof".to_string()),
    };
    let param = entry
        .slice()
        .map_err(cell_err)?
        .load_ref()
        .map_err(cell_err)?
        .clone();

    read_validator_set(&param)
}

fn read_validator_set(param: &Cell) -> Result<ValidatorSet, Error> {
    let mut s = param.parse();
    let tag = s.load_uint(8).map_err(cell_err)?;
    let ext = match tag {
        VALIDATORS_EXT_TAG => true,
        VALIDATORS_TAG => false,
        other => return Err(format!("{other:#04x} is not a validator set")),
    };
    let utime_since = s.load_uint(32).map_err(cell_err)? as u32;
    let utime_until = s.load_uint(32).map_err(cell_err)? as u32;
    let total = s.load_uint(16).map_err(cell_err)? as u16;
    let main = s.load_uint(16).map_err(cell_err)? as u16;
    if main == 0 || main > total {
        return Err(format!("a set of {total} with {main} main is not valid"));
    }
    // The declared total weight is over every validator; the masterchain subset's
    // weight is summed below from the entries that may actually sign.
    let _declared_total_weight = if ext {
        s.load_uint(64).map_err(cell_err)?
    } else {
        0
    };
    let list = if ext {
        s.load_maybe_ref()
            .map_err(cell_err)?
            .ok_or_else(|| "an empty validator set".to_string())?
    } else {
        s.load_ref().map_err(cell_err)?
    };

    // The masterchain set is the head of the list. The reference implementation may
    // permute those entries with a seeded generator, but the permutation is over
    // exactly these, so membership and weight are the same either way.
    let mut weights = HashMap::with_capacity(main as usize);
    let mut total_weight = 0u64;
    for index in 0..main {
        let entry = match dict::lookup(list, 16, &index.to_be_bytes())
            .map_err(|e| format!("validator {index}: {e}"))?
        {
            Lookup::Found(entry) => entry,
            Lookup::Absent => return Err(format!("validator {index} is missing from the list")),
            Lookup::Pruned => return Err(format!("validator {index} is pruned out of the proof")),
        };
        let (key, weight) = read_validator(&mut entry.slice().map_err(cell_err)?)?;
        total_weight = total_weight
            .checked_add(weight)
            .ok_or_else(|| "the validator weights overflow".to_string())?;
        weights.insert(short_id(&key), (key, weight));
    }
    if weights.len() != main as usize {
        return Err(format!(
            "{} distinct validators for {main} entries, so the list repeats a key",
            weights.len()
        ));
    }

    Ok(ValidatorSet {
        utime_since,
        utime_until,
        total,
        main,
        weights,
        total_weight,
    })
}

fn read_validator(s: &mut Slice<'_>) -> Result<([u8; 32], u64), Error> {
    let tag = s.load_uint(8).map_err(cell_err)?;
    if tag != VALIDATOR_TAG && tag != VALIDATOR_ADDR_TAG {
        return Err(format!("{tag:#04x} is not a validator descriptor"));
    }
    let key_tag = s.load_uint(32).map_err(cell_err)?;
    if key_tag != ED25519_PUBKEY_TAG {
        return Err(format!("{key_tag:#010x} is not an ed25519 public key"));
    }
    let key: [u8; 32] = s
        .load_bytes(32)
        .map_err(cell_err)?
        .try_into()
        .expect("32 bytes");
    let weight = s.load_uint(64).map_err(cell_err)?;
    Ok((key, weight))
}

/// A validator's short id: sha256 of the key in its TL `pub.ed25519` form.
///
/// The same computation the ADNL handshake already performs for a server key.
pub fn short_id(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUB_ED25519.to_le_bytes());
    hasher.update(key);
    hasher.finalize().into()
}
