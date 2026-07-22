// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The dictionary engine, checked against the dictionaries mainnet actually holds.
//!
//! A dictionary has one correct serialization and several readable ones. Every edge label
//! can be written three ways, all three parse back to the same label, and only the
//! shortest is the form TON's own nodes write. A client that picked another would build a
//! tree that reads back correctly, hashes differently, and so fails every proof it is put
//! to, without anything reporting a fault.
//!
//! No round trip can catch that: a round trip re-reads whatever it wrote. The oracle has
//! to come from outside, so these tests take six dictionaries out of captured mainnet
//! proofs, at key widths of 16, 32 and 256 bits, and require the library to write each
//! label exactly as the network wrote it. The labels are read here by a second reader
//! written from `block.tlb` rather than by the library's own.
//!
//! The tests live beside the block fixtures because that is where a real dictionary can
//! be reached; what they exercise is `ton_net_cell::Dict`.

use ton_net_block::{proof, Block, ShardState};
use ton_net_cell::{Builder, Cell, CellError, Dict, Lookup, Slice};

/// One forward proof link, holding a key block's configuration.
const CHAIN: &str = include_str!("fixtures/chain.hex");

/// A captured basechain account read: a shard binding and an account proof.
const BASECHAIN: &str = include_str!("fixtures/read-basechain.txt");

/// A masterchain read, and a read of an address nothing was ever stored under. Each
/// carries an accounts dictionary of its own, and a deep account leaf is the one place
/// mainnet writes a label too long for the unary form.
const MASTERCHAIN: &str = include_str!("fixtures/read-masterchain.txt");
const ABSENT: &str = include_str!("fixtures/read-absent.txt");

// ---------------------------------------------------------------------------
// Reaching the dictionaries
// ---------------------------------------------------------------------------

/// A dictionary as mainnet wrote it.
struct Sample {
    what: &'static str,
    root: Cell,
    key_bits: u16,
}

fn samples() -> Vec<Sample> {
    let config = config_dictionary();
    let list = validator_list(&config);
    let basechain = Read::parse(BASECHAIN);
    let mut samples = vec![
        Sample {
            what: "the validator list",
            root: list,
            key_bits: 16,
        },
        Sample {
            what: "the network configuration",
            root: config,
            key_bits: 32,
        },
        Sample {
            what: "the masterchain shard hashes",
            root: shard_hashes(&basechain),
            key_bits: 32,
        },
    ];
    for (what, text) in [
        ("the basechain accounts", BASECHAIN),
        ("the masterchain accounts", MASTERCHAIN),
        ("the accounts of an absent read", ABSENT),
    ] {
        samples.push(Sample {
            what,
            root: shard_accounts(&Read::parse(text)),
            key_bits: 256,
        });
    }
    samples
}

/// The configuration dictionary a key block's own proof carries.
fn config_dictionary() -> Cell {
    let link = Link::parse(CHAIN);
    Block::from_proof(&link.config_proof, &link.from_root_hash)
        .expect("the config proof roots at the key block")
        .config()
        .expect("a key block carries a configuration")
}

/// The validator list configuration parameter 34 holds behind its header.
fn validator_list(config: &Cell) -> Cell {
    let entry = Dict::from_root(Some(config.clone()), 32)
        .expect("a 32-bit dictionary")
        .get(&34i32.to_be_bytes())
        .expect("the lookup runs")
        .found()
        .expect("the proof covers the parameter it was sent for");
    let param = entry
        .slice()
        .expect("the entry reads")
        .load_ref()
        .expect("a parameter sits behind a reference")
        .clone();

    // validators_ext#12 utime_since:uint32 utime_until:uint32 total:uint16 main:uint16
    // total_weight:uint64 list:(HashmapE 16 ValidatorDescr)
    let mut slice = param.parse();
    assert_eq!(slice.load_uint(8).expect("a tag"), 0x12, "an extended set");
    slice.skip_bits(32 + 32 + 16 + 16 + 64).expect("the header");
    slice
        .load_maybe_ref()
        .expect("the list reads")
        .expect("the set names a list")
        .clone()
}

/// The masterchain's shard hashes, out of the proof that binds a basechain read.
fn shard_hashes(read: &Read) -> Cell {
    let state = read.state_of(&read.shard_proof, &read.block_root_hash);
    // The masterchain extra: a tag, then the shard hashes.
    let extra = state
        .cell()
        .reference(3)
        .expect("a masterchain state carries its extra");
    let mut slice = extra.parse();
    slice.skip_bits(16).expect("the tag");
    slice
        .load_maybe_ref()
        .expect("the shard hashes read")
        .expect("mainnet has shards")
        .clone()
}

/// The shard's accounts dictionary, out of the account proof.
fn shard_accounts(read: &Read) -> Cell {
    let state = read.state_of(&read.proof, &read.shard_block_root_hash);
    let accounts = state.accounts().expect("a state carries its accounts");
    accounts
        .parse()
        .load_maybe_ref()
        .expect("the accounts read")
        .expect("a shard holds accounts")
        .clone()
}

// ---------------------------------------------------------------------------
// A second reader, from block.tlb
// ---------------------------------------------------------------------------

/// One node of a dictionary as it was written.
struct Node {
    cell: Cell,
    label: Vec<bool>,
    /// The key bits still to spend at this node, which sets the width of a length field.
    max: u16,
    /// How many bits the label's encoding took.
    encoded: usize,
    form: &'static str,
}

/// Reads one edge label, following `block.tlb` rather than the library.
///
/// ```text
/// hml_short$0 {m:#} {n:#} len:(Unary ~n) s:(n * Bit)  = HmLabel ~n m;
/// hml_long$10 {m:#} n:(#<= m) s:(n * Bit)             = HmLabel ~n m;
/// hml_same$11 {m:#} v:Bit n:(#<= m)                   = HmLabel ~n m;
/// ```
fn read_label(slice: &mut Slice<'_>, max: u16) -> (Vec<bool>, usize, &'static str) {
    let width = u16::BITS - max.leading_zeros();
    if !slice.load_bit().unwrap() {
        let mut len = 0usize;
        while slice.load_bit().unwrap() {
            len += 1;
        }
        let bits = (0..len).map(|_| slice.load_bit().unwrap()).collect();
        return (bits, 2 + 2 * len, "short");
    }
    if !slice.load_bit().unwrap() {
        let len = slice.load_uint(width).unwrap() as usize;
        let bits = (0..len).map(|_| slice.load_bit().unwrap()).collect();
        return (bits, 2 + width as usize + len, "long");
    }
    let value = slice.load_bit().unwrap();
    let len = slice.load_uint(width).unwrap() as usize;
    (vec![value; len], 3 + width as usize, "same")
}

/// Every node a dictionary shows. A proof prunes what it does not cover, and a pruned
/// branch holds a hash rather than a node, so the walk stops there.
fn walk(node: &Cell, max: u16, out: &mut Vec<Node>) {
    if node.is_exotic() {
        return;
    }
    let mut slice = node.parse();
    let (label, encoded, form) = read_label(&mut slice, max);
    let len = label.len();
    out.push(Node {
        cell: node.clone(),
        label,
        max,
        encoded,
        form,
    });
    if len == usize::from(max) {
        return;
    }
    let below = max - len as u16 - 1;
    for branch in 0..2 {
        walk(
            node.reference(branch).expect("a fork has two branches"),
            below,
            out,
        );
    }
}

fn nodes(sample: &Sample) -> Vec<Node> {
    let mut out = Vec::new();
    walk(&sample.root, sample.key_bits, &mut out);
    out
}

/// The first `count` data bits of a cell.
fn leading(cell: &Cell, count: usize) -> Vec<bool> {
    let mut slice = cell.parse();
    (0..count).map(|_| slice.load_bit().unwrap()).collect()
}

/// Packs key bits into bytes, most significant bit first.
fn pack(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            out[index / 8] |= 1 << (7 - (index % 8));
        }
    }
    out
}

/// The cell the library writes when it has to label an edge with `label` under `max`.
///
/// This goes through the public dictionary rather than reaching for the label writer, so
/// it checks the path a caller actually takes. A label as long as the key is what a
/// dictionary of one entry writes. A shorter one is what two keys write when they agree
/// over the label and part on the bit after it: the fork they force carries exactly that
/// label, under exactly that maximum.
fn written(label: &[bool], max: u16) -> Cell {
    let mut dict = Dict::new(max).expect("a dictionary that wide");
    let mut value = Builder::new();
    value.store_bit(true).expect("one bit fits");

    if label.len() == usize::from(max) {
        dict.set(&pack(label), &value).expect("the only key");
    } else {
        for parting in [false, true] {
            let mut key = label.to_vec();
            key.push(parting);
            key.resize(usize::from(max), false);
            dict.set(&pack(&key), &value).expect("one of two keys");
        }
    }
    dict.root().expect("a root").clone()
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn every_label_mainnet_wrote_is_the_label_this_writes() {
    let mut checked = 0usize;
    for sample in samples() {
        for node in nodes(&sample) {
            let rebuilt = written(&node.label, node.max);
            let (mine, encoded, form) = read_label(&mut rebuilt.parse(), node.max);
            assert_eq!(
                (leading(&rebuilt, encoded), form),
                (leading(&node.cell, node.encoded), node.form),
                "{}: a {}-bit label under {} came out as {form}, mainnet wrote {}",
                sample.what,
                node.label.len(),
                node.max,
                node.form,
            );
            assert_eq!(mine, node.label);
            checked += 1;
        }
    }
    // A walk that reached nothing would pass every assertion above.
    assert!(checked > 800, "only {checked} labels were checked");
}

#[test]
fn the_corpus_exercises_all_three_label_encodings() {
    // The canonical choice is only tested where the three forms compete. A dense
    // dictionary uses the short form throughout and would pass whatever the other two
    // rules said, so the corpus has to be shown to reach them rather than assumed to.
    //
    // As captured the corpus runs to 886 labels: the unary form on 879, the repeated form
    // on 6 runs of equal bits, and the explicit form on exactly one, the basechain
    // account leaf, where two hundred-odd bits of key settle at once and a unary count
    // for them would run longer than the label itself. The masterchain account is address
    // zero, so its own leaf is a run of equal bits and takes the repeated form instead.
    let mut seen = std::collections::BTreeMap::new();
    for sample in samples() {
        for node in nodes(&sample) {
            *seen.entry(node.form).or_insert(0usize) += 1;
        }
    }
    for form in ["short", "long", "same"] {
        assert!(
            seen.get(form).copied().unwrap_or(0) > 0,
            "no mainnet label used the {form} form: {seen:?}"
        );
    }
}

#[test]
fn a_dictionary_rebuilt_from_its_own_entries_keeps_its_root_hash() {
    // The hash is the oracle. It was computed by the network over bytes this crate did
    // not write, so reproducing it means every label, every fork and every ordering
    // decision came out the way TON makes them.
    let mut rebuilt = 0usize;
    for sample in samples() {
        let dict = Dict::from_root(Some(sample.root.clone()), sample.key_bits).expect("a root");
        let Ok(entries) = dict
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "pruned")
        else {
            // A proof carries one path and prunes the rest, so most of these cannot be
            // enumerated. The label check above is what covers them.
            continue;
        };

        // Both orders, because a radix tree has one shape per key set and a wrong split
        // or a wrong merge is what would make the order matter.
        for order in [false, true] {
            let mut fresh = Dict::new(sample.key_bits).expect("a dictionary that wide");
            let ordered: Vec<_> = if order {
                entries.iter().rev().collect()
            } else {
                entries.iter().collect()
            };
            for (key, entry) in ordered {
                let value = entry.slice().expect("the leaf reads").to_builder().unwrap();
                fresh.set(key, &value).expect("the key fits");
            }
            assert_eq!(
                fresh.root().map(Cell::repr_hash),
                Some(sample.root.repr_hash()),
                "{} did not rebuild to its own root hash",
                sample.what
            );
        }
        rebuilt += 1;
    }
    assert!(rebuilt > 0, "no dictionary was complete enough to rebuild");
}

#[test]
fn a_key_put_into_a_mainnet_dictionary_and_taken_out_again_leaves_it_as_it_was() {
    // Adding a key splits an edge in two and relabels both halves; taking it out has to
    // put that edge back exactly as it stood, label and all. A merge that came out even
    // one bit different would read back the same entries and hash differently, so the
    // root hash the network computed is the only thing that can tell the two apart.
    let mut checked = 0usize;
    for sample in samples() {
        let dict = Dict::from_root(Some(sample.root.clone()), sample.key_bits).expect("a root");
        if dict.iter().collect::<Result<Vec<_>, _>>().is_err() {
            continue;
        }
        let mut value = Builder::new();
        value
            .store_uint(0xdead_beef, 32)
            .expect("a value that fits");

        for seed in 0..8u8 {
            let mut key = vec![seed; usize::from(sample.key_bits).div_ceil(8)];
            key[0] = 0x5a ^ seed;
            let mut edited = dict.clone();
            if matches!(edited.get(&key).expect("the lookup runs"), Lookup::Found(_)) {
                continue;
            }

            edited.set(&key, &value).expect("the key fits");
            assert_ne!(
                edited.root().map(Cell::repr_hash),
                Some(sample.root.repr_hash()),
                "{}: storing a key it did not hold changed nothing",
                sample.what
            );
            assert!(edited.remove(&key).expect("the removal runs"));
            assert_eq!(
                edited.root().map(Cell::repr_hash),
                Some(sample.root.repr_hash()),
                "{}: a key put in and taken out again did not leave the dictionary alone",
                sample.what
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no dictionary was complete enough to edit");
}

#[test]
fn an_augmented_dictionary_is_read_but_not_rewritten() {
    // The accounts dictionary summarises each subtree in the fork above it. Rewriting one
    // means recomputing those summaries, and copying them forward would describe the
    // subtree that used to be there. Refusing is the honest answer until that arrives.
    let read = Read::parse(BASECHAIN);
    let mut accounts = Dict::from_root(Some(shard_accounts(&read)), 256).expect("a root");

    let mut value = Builder::new();
    value.store_bit(true).expect("one bit fits");
    assert!(matches!(
        accounts.set(&read.account_id, &value),
        Err(CellError::Malformed(_))
    ));

    // Reading the same dictionary is fine, and is what the proof engine already does.
    let found = accounts.get(&read.account_id).expect("the lookup runs");
    assert!(found.found().is_some());
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn unhex(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hash32(text: &str) -> [u8; 32] {
    unhex(text).try_into().expect("32 bytes")
}

/// One forward link, reduced to what these tests read out of it.
struct Link {
    from_root_hash: [u8; 32],
    config_proof: Vec<u8>,
}

impl Link {
    fn parse(text: &str) -> Link {
        let proof: ton_net_tl::lite::PartialBlockProof =
            ton_net_tl::deserialize(&unhex(text)).expect("the fixture decodes");
        match proof.steps.into_iter().next().expect("one step") {
            ton_net_tl::lite::BlockLink::Forward {
                from, config_proof, ..
            } => Link {
                from_root_hash: from.root_hash,
                config_proof,
            },
            _ => panic!("expected a forward link"),
        }
    }
}

/// One captured answer to `liteServer.getAccountState`.
struct Read {
    account_id: [u8; 32],
    block_root_hash: [u8; 32],
    shard_block_root_hash: [u8; 32],
    shard_proof: Vec<u8>,
    proof: Vec<u8>,
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
            account_id: hash32(field("account_id")),
            block_root_hash: hash32(field("block_root_hash")),
            shard_block_root_hash: hash32(field("shard_block_root_hash")),
            shard_proof: unhex(field("shard_proof")),
            proof: unhex(field("proof")),
        }
    }

    /// The shard state a proof carries, checked against the block it claims to be of.
    fn state_of(&self, bytes: &[u8], block_root_hash: &[u8; 32]) -> ShardState {
        let roots = ton_net_cell::parse_boc(bytes).expect("the proof parses");
        let state_hash =
            proof::verify_block_state(&roots, block_root_hash).expect("the proof roots");
        proof::verify_shard_state(&roots, &state_hash).expect("the state is covered")
    }
}
