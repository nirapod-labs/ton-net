// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Proof-engine feasibility spike for ton-net v0.2.0.
//!
//! The riskiest piece of v0.2.0 is cell hashing: a Merkle proof is believed only
//! because recomputing cell hashes reproduces a known root, and the level rule is
//! subtle. This spike proves the hashing against a live mainnet liteserver, in stages,
//! each checked against a hash the TON node itself computed, so a wrong hasher cannot
//! pass by agreeing with data this program also produced.
//!
//! It reuses the v0.1.0 facade to fetch a real account and its proof, then hand-rolls
//! the bag-of-cells parse and the representation hashing that `ton-net-cell` will hold.
//!
//! - Stage 1: the account state's root hash, computed here, is the hash the node
//!   embedded in the proof as a pruned branch.
//! - Stage 2: every Merkle-proof cell self-certifies, its stored hash equals the
//!   recomputed level-0 hash of the tree it covers.
//! - Stage 3: the whole account read verifies, the block proof roots at the trusted
//!   block hash, the block's state update names the state root, and the state proof
//!   roots there and carries the account.
//!
//! The hashing rules follow the specification: `d1 = r + 8s + 32l`,
//! `d2 = floor(b/8) + ceil(b/8)`, and the standard representation is
//! `d1 || d2 || data || ref depths || ref hashes`. A pruned branch's level-0 hash is
//! the stored hash of the subtree it replaced, at `data[2 + 32i .. 2 + 32(i+1)]`, which
//! is what makes a pruned tree hash to the same root as the full one. A Merkle cell
//! reads its children one level up.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use ton_net::{Address, Client, Config};

/// A cell as read from a bag of cells, before hashing.
struct RawCell {
    /// The refs-and-type descriptor byte, as stored.
    d1: u8,
    /// The bit-length descriptor byte, as stored.
    d2: u8,
    /// The cell data, in the stored (byte-augmented) form used for hashing.
    data: Vec<u8>,
    /// Indices of this cell's references in the parsed cell list.
    refs: Vec<usize>,
    /// Whether the exotic flag is set.
    exotic: bool,
}

/// The cell kinds this spike distinguishes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Ordinary,
    Pruned,
    Library,
    MerkleProof,
    MerkleUpdate,
}

/// Classifies a cell by its exotic flag and leading type byte.
fn kind(c: &RawCell) -> Kind {
    if !c.exotic {
        return Kind::Ordinary;
    }
    match c.data.first() {
        Some(0x01) => Kind::Pruned,
        Some(0x02) => Kind::Library,
        Some(0x03) => Kind::MerkleProof,
        Some(0x04) => Kind::MerkleUpdate,
        _ => Kind::Ordinary,
    }
}

/// Renders bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads an `n`-byte big-endian unsigned integer at `p`.
fn be(bytes: &[u8], p: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for k in 0..n {
        v = (v << 8) | u64::from(bytes[p + k]);
    }
    v
}

/// Copies a 32-byte hash out of a slice.
fn hash32(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&s[..32]);
    out
}

/// Parses a standard bag of cells into its cells and the indices of its roots.
fn parse_boc(b: &[u8]) -> Result<(Vec<RawCell>, Vec<usize>), String> {
    if b.len() < 6 || b[0..4] != [0xb5, 0xee, 0x9c, 0x72] {
        return Err("bad magic".into());
    }
    let flags = b[4];
    let has_idx = flags & 0x80 != 0;
    let size = (flags & 0x07) as usize;
    let off = b[5] as usize;
    if size == 0 || size > 4 || off == 0 || off > 8 {
        return Err(format!("bad size/off: size={size} off={off}"));
    }
    let mut p = 6usize;
    let cells = be(b, p, size) as usize;
    p += size;
    let roots = be(b, p, size) as usize;
    p += size;
    let _absent = be(b, p, size) as usize;
    p += size;
    let _tot = be(b, p, off) as usize;
    p += off;

    let mut root_list = Vec::with_capacity(roots);
    for _ in 0..roots {
        root_list.push(be(b, p, size) as usize);
        p += size;
    }
    if has_idx {
        p += cells * off;
    }

    let mut out = Vec::with_capacity(cells);
    for i in 0..cells {
        if p + 2 > b.len() {
            return Err(format!("truncated at cell {i} header"));
        }
        let d1 = b[p];
        let d2 = b[p + 1];
        p += 2;
        let refs_count = (d1 & 7) as usize;
        let exotic = d1 & 8 != 0;
        if d1 & 16 != 0 {
            return Err("inline hashes not handled in this spike".into());
        }
        let data_len = ((d2 >> 1) + (d2 & 1)) as usize;
        if p + data_len > b.len() {
            return Err(format!("truncated at cell {i} data"));
        }
        let data = b[p..p + data_len].to_vec();
        p += data_len;
        let mut refs = Vec::with_capacity(refs_count);
        for _ in 0..refs_count {
            let r = be(b, p, size) as usize;
            p += size;
            if r >= cells {
                return Err(format!("cell {i} ref {r} out of range"));
            }
            refs.push(r);
        }
        out.push(RawCell {
            d1,
            d2,
            data,
            refs,
            exotic,
        });
    }
    Ok((out, root_list))
}

/// The number of higher hashes a pruned branch stores, one per set level-mask bit.
fn pruned_levels(c: &RawCell) -> usize {
    c.data.get(1).map_or(0, |m| m.count_ones() as usize)
}

/// The hash and depth of a cell at a given level.
///
/// A pruned branch below its own level answers with the stored hash and depth of the
/// subtree it replaced, which is what makes a pruned tree hash to the root of the full
/// tree. A Merkle cell reads its children one level up. Every other cell hashes its
/// standard representation with the level mask applied for this level.
fn hash_at(
    cells: &[RawCell],
    idx: usize,
    level: usize,
    memo: &mut HashMap<(usize, usize), ([u8; 32], u16)>,
) -> ([u8; 32], u16) {
    if let Some(v) = memo.get(&(idx, level)) {
        return *v;
    }
    let c = &cells[idx];
    let k = kind(c);

    let result = if k == Kind::Pruned && level < pruned_levels(c) {
        // Below its own level a pruned branch stands in for the subtree it replaced.
        let n = pruned_levels(c);
        let h = hash32(&c.data[2 + 32 * level..]);
        let d = be(&c.data, 2 + 32 * n + 2 * level, 2) as u16;
        (h, d)
    } else {
        // A Merkle cell's content sits one level down, so its children answer one up.
        let child_level = if matches!(k, Kind::MerkleProof | Kind::MerkleUpdate) {
            level + 1
        } else {
            level
        };
        let mask = c.d1 >> 5;
        let applied = mask & ((1u8 << level).wrapping_sub(1));
        let d1 = (c.d1 & 0x1F) | (applied << 5);

        let mut children = Vec::with_capacity(c.refs.len());
        let mut depth = 0u16;
        for &r in &c.refs {
            let (h, d) = hash_at(cells, r, child_level, memo);
            children.push((h, d));
            depth = depth.max(d + 1);
        }

        let mut repr = Vec::with_capacity(2 + c.data.len() + c.refs.len() * 34);
        repr.push(d1);
        repr.push(c.d2);
        repr.extend_from_slice(&c.data);
        for (_, d) in &children {
            repr.extend_from_slice(&d.to_be_bytes());
        }
        for (h, _) in &children {
            repr.extend_from_slice(h);
        }
        (Sha256::digest(&repr).into(), depth)
    };

    memo.insert((idx, level), result);
    result
}

#[tokio::main]
async fn main() {
    const CONFIG_CONTRACT: &str =
        "-1:5555555555555555555555555555555555555555555555555555555555555555";

    let config = Config::mainnet();
    let mut client = match Client::connect(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no mainnet liteserver reachable: {e}");
            std::process::exit(1);
        }
    };

    let address = Address::parse(CONFIG_CONTRACT).expect("valid address");
    let block = client
        .masterchain_info()
        .await
        .expect("masterchain head")
        .into_value()
        .last;
    // The raw bytes, so this spike hashes what the server sent rather than a decode of it.
    let reported = client
        .account_state(&address, &block)
        .await
        .expect("account read");
    let state = reported.value().state.clone();
    let proof = reported.proof().to_vec();

    println!("== capture ==");
    println!(
        "block seqno {}  root_hash {}",
        block.seqno,
        hex(&block.root_hash)
    );
    println!("state {} bytes, proof {} bytes", state.len(), proof.len());

    // The account state: an ordinary tree, so its level-0 hash is the account hash.
    let (scells, sroots) = parse_boc(&state).expect("parse state boc");
    let mut smemo = HashMap::new();
    let (account_hash, account_depth) = hash_at(&scells, sroots[0], 0, &mut smemo);
    println!("== state ==");
    println!(
        "cells {} (exotic {})",
        scells.len(),
        scells.iter().filter(|c| c.exotic).count()
    );
    println!(
        "account root hash {}  depth {}",
        hex(&account_hash),
        account_depth
    );

    let (pcells, proots) = parse_boc(&proof).expect("parse proof boc");
    let mut counts: HashMap<String, usize> = HashMap::new();
    for c in &pcells {
        *counts.entry(format!("{:?}", kind(c))).or_default() += 1;
    }
    println!("== proof ==");
    println!("cells {}, roots {}", pcells.len(), proots.len());
    let mut kinds: Vec<_> = counts.iter().collect();
    kinds.sort();
    println!("kinds: {kinds:?}");

    // ---- Stage 1: the account hash is in the proof as a pruned branch. ----
    let mut stage1 = false;
    for c in &pcells {
        if kind(c) == Kind::Pruned {
            for k in 0..pruned_levels(c) {
                if hash32(&c.data[2 + 32 * k..]) == account_hash {
                    stage1 = true;
                }
            }
        }
    }
    println!("== stage 1 ==");
    println!("account hash present in the proof: {stage1}");

    // ---- Stage 2: every Merkle-proof cell self-certifies. ----
    println!("== stage 2 ==");
    let mut pmemo = HashMap::new();
    let mut stage2 = true;
    let mut merkle_roots: Vec<(usize, [u8; 32])> = Vec::new();
    for (i, c) in pcells.iter().enumerate() {
        if kind(c) == Kind::MerkleProof {
            let stored = hash32(&c.data[1..]);
            let (computed, _) = hash_at(&pcells, c.refs[0], 0, &mut pmemo);
            let ok = computed == stored;
            stage2 &= ok;
            println!(
                "  merkle cell {i}: stored {}  recomputed {}  {}",
                hex(&stored[..8]),
                hex(&computed[..8]),
                if ok { "MATCH" } else { "MISMATCH" }
            );
            merkle_roots.push((i, stored));
        }
    }

    // ---- Stage 3: the chain from the trusted block hash down to the account. ----
    println!("== stage 3 ==");
    let block_proof = merkle_roots.iter().find(|(_, h)| *h == block.root_hash);
    match block_proof {
        Some((i, _)) => println!("  block proof (cell {i}) roots at the trusted block hash: MATCH"),
        None => println!("  no merkle root matches the trusted block hash: MISMATCH"),
    }

    // The block's state update names the state root the state proof must cover.
    let state_root = pcells
        .iter()
        .find(|c| kind(c) == Kind::MerkleUpdate)
        .map(|c| hash32(&c.data[33..]));
    let mut stage3 = block_proof.is_some();
    match state_root {
        Some(new_hash) => {
            println!("  state update new state root {}", hex(&new_hash[..8]));
            let linked = merkle_roots.iter().any(|(_, h)| *h == new_hash);
            println!(
                "  a merkle root covers that state root: {}",
                if linked { "MATCH" } else { "MISMATCH" }
            );
            stage3 &= linked;
        }
        None => {
            println!("  no merkle update cell found");
            stage3 = false;
        }
    }

    println!("== result ==");
    println!("stage 1 (ordinary hashing vs the node): {stage1}");
    println!("stage 2 (merkle cells self-certify):    {stage2}");
    println!("stage 3 (chain to the trusted block):   {stage3}");
    if stage1 && stage2 && stage3 {
        println!("PASS: the account read verifies against the trusted block hash.");
    } else {
        println!("INCOMPLETE: see the mismatches above.");
        std::process::exit(2);
    }

    println!("== pin ==");
    println!("BLOCK_SEQNO={}", block.seqno);
    println!("BLOCK_ROOT_HASH={}", hex(&block.root_hash));
    println!("ACCOUNT_HASH={}", hex(&account_hash));
    println!("PROOF_HEX={}", hex(&proof));
}
