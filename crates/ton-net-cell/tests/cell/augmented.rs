// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Augmented dictionaries, gated on the account blocks of a whole mainnet block.
//!
//! The fixture is basechain block `86062610`, whose `BlockExtra` carries an
//! `account_blocks` of eleven entries over ten forks, every one of them with both children
//! visible. That is what makes it usable where `ShardAccounts` is not: a Merkle proof is a
//! chain, so none of its forks has both children, and a fork that cannot see both children
//! is no evidence about a rule for summarising two subtrees.
//!
//! The augmentation is a `CurrencyCollection`, and its rule is that the summaries add up.
//! The eleven leaves' grams sum to 3,942,413, which is exactly what the validators wrote
//! in the top-level summary, so the rule is read off mainnet rather than assumed.
//!
//! Two key widths are covered. The 256-bit dictionary sits at a cell boundary, so it can
//! be rebuilt from its own entries and held to the root hash the validators computed. Each
//! `AccountBlock` then carries a `HashmapAug 64` of its own transactions, but inline rather
//! than behind a reference, so the edge shares a cell with the account address before it
//! and the state update reference after it. Ten of the eleven hold one entry, and for those
//! the whole remainder of the cell is the edge, so they rebuild and compare exactly. The
//! eleventh has a real fork, whose root shares its cell with a reference the dictionary
//! does not own; that one is held to the summary rule directly instead.

use ton_net_cell::{
    parse_boc, AugDict, Augmentation, Builder, Cell, CellError, CellType, Lookup, Slice, MAX_BITS,
};

const BASECHAIN: &str = include_str!("../fixtures/block-basechain.hex");

/// The root hash the validators computed for `account_blocks`, as it stands in the block.
const ACCOUNT_BLOCKS_ROOT: &str =
    "5cb7df251ec0478e20648626b19944b00719e5cf93d799c7de506d72edaf02d5";

/// What the block's top-level summary says the eleven entries add up to.
const TOTAL_GRAMS: u128 = 3_942_413;

const ACCOUNT_KEY_BITS: u16 = 256;
const TRANSACTION_KEY_BITS: u16 = 64;

/// `block_extra ... account_blocks:^ShardAccountBlocks ...`, the fourth reference of a block.
const BLOCK_EXTRA_REF: usize = 3;
const ACCOUNT_BLOCKS_REF: usize = 2;

/// `acc_trans#5 account_addr:bits256 transactions:(HashmapAug 64 ^Transaction ...)`
const ACC_TRANS_TAG: u64 = 5;

fn unhex(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A `CurrencyCollection`: an amount of grams, and a dictionary of every other currency.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Currencies {
    grams: u128,
    other: Option<Cell>,
}

/// The augmentation an account-blocks dictionary carries.
///
/// Every collection in the fixture is grams only, so combining two that are not is refused
/// rather than guessed at. Adding two currency dictionaries is the caller's business, and
/// a wrong guess here would show up as a root hash that happened to match nothing.
#[derive(Debug, Clone)]
struct SumCurrencies;

impl Augmentation for SumCurrencies {
    type Extra = Currencies;

    fn read(&self, slice: &mut Slice<'_>) -> Result<Currencies, CellError> {
        Ok(Currencies {
            grams: slice.load_coins()?,
            other: slice.load_maybe_ref()?.cloned(),
        })
    }

    fn combine(&self, left: &Currencies, right: &Currencies) -> Result<Currencies, CellError> {
        if left.other.is_some() || right.other.is_some() {
            return Err(CellError::Malformed("extra currencies are not summed here"));
        }
        Ok(Currencies {
            grams: left.grams + right.grams,
            other: None,
        })
    }

    fn write(&self, extra: &Currencies, into: &mut Builder) -> Result<(), CellError> {
        into.store_coins(extra.grams)?;
        into.store_maybe_ref(extra.other.clone())?;
        Ok(())
    }
}

/// An augmentation whose combining depends on which child is which.
///
/// A sum cannot tell a fork's two children apart, so a defect that swapped them would leave
/// every root hash in this file intact. This one is here so the order is pinned by
/// something.
#[derive(Debug)]
struct Ordered;

impl Augmentation for Ordered {
    type Extra = u64;

    fn read(&self, slice: &mut Slice<'_>) -> Result<u64, CellError> {
        slice.load_uint(32)
    }

    fn combine(&self, left: &u64, right: &u64) -> Result<u64, CellError> {
        Ok((left.wrapping_mul(3).wrapping_add(*right)) & 0xffff_ffff)
    }

    fn write(&self, extra: &u64, into: &mut Builder) -> Result<(), CellError> {
        into.store_uint(*extra, 32)?;
        Ok(())
    }
}

// An independent reader for the parts of a node this file inspects directly, so the checks
// below are not the write path grading its own work.

fn bounded_width(max: u16) -> u32 {
    u16::BITS - max.leading_zeros()
}

fn read_label(slice: &mut Slice<'_>, max: u16) -> Result<Vec<bool>, CellError> {
    if !slice.load_bit()? {
        let mut len = 0u16;
        while slice.load_bit()? {
            len += 1;
        }
        return (0..len).map(|_| slice.load_bit()).collect();
    }
    if !slice.load_bit()? {
        let len = slice.load_uint(bounded_width(max))?;
        return (0..len).map(|_| slice.load_bit()).collect();
    }
    let value = slice.load_bit()?;
    let len = slice.load_uint(bounded_width(max))?;
    Ok(vec![
        value;
        usize::try_from(len)
            .expect("a label is at most 1023 bits")
    ])
}

/// The summary a node carries, which in either kind of node follows the label.
fn extra_at(node: &Cell, max: u16) -> Currencies {
    let mut slice = node.parse();
    read_label(&mut slice, max).expect("a label");
    SumCurrencies.read(&mut slice).expect("a summary")
}

/// Every fork under `node`, as its own summary beside its two children's.
fn forks(node: &Cell, max: u16, out: &mut Vec<(Currencies, Currencies, Currencies)>) {
    let mut slice = node.parse();
    let label = read_label(&mut slice, max).expect("a label");
    if label.len() == usize::from(max) {
        return;
    }

    let stored = SumCurrencies.read(&mut slice).expect("a summary");
    let below = max - u16::try_from(label.len()).expect("a label fits its width") - 1;
    let left = node.reference(0).expect("a left branch");
    let right = node.reference(1).expect("a right branch");
    out.push((stored, extra_at(left, below), extra_at(right, below)));

    forks(left, below, out);
    forks(right, below, out);
}

/// A pruned branch from the block's state update.
///
/// Found by walking rather than by a fixed path, so it does not have to be kept in step
/// with where the block happens to put its Merkle update.
fn a_pruned_branch() -> Cell {
    let block = parse_boc(&unhex(BASECHAIN)).expect("the fixture parses");
    let mut stack = vec![block[0].clone()];
    while let Some(cell) = stack.pop() {
        if cell.cell_type() == CellType::PrunedBranch {
            return cell;
        }
        for index in 0..4 {
            if let Some(child) = cell.reference(index) {
                stack.push(child.clone());
            }
        }
    }
    panic!("a block carries a merkle update, so the fixture has pruned branches")
}

/// The block's `account_blocks`, as the cell the `HashmapAugE` points at.
fn account_blocks() -> Cell {
    let roots = parse_boc(&unhex(BASECHAIN)).expect("the fixture parses");
    let extra = roots[0]
        .reference(BLOCK_EXTRA_REF)
        .expect("a block carries its extra")
        .reference(ACCOUNT_BLOCKS_REF)
        .expect("a block extra carries its account blocks");

    let mut slice = extra.parse();
    let root = slice
        .load_maybe_ref()
        .expect("a maybe reference")
        .expect("the fixture's dictionary is not empty")
        .clone();

    // The wrapper's own summary, which belongs to the caller rather than to the edge.
    let total = SumCurrencies.read(&mut slice).expect("a summary");
    assert_eq!(total.grams, TOTAL_GRAMS);
    assert_eq!(slice.remaining_bits(), 0, "nothing follows the summary");
    root
}

/// Every entry of a dictionary, as the key, the summary and the value it stores.
fn entries<A: Augmentation>(dict: &AugDict<A>) -> Vec<(Vec<u8>, A::Extra, Builder)> {
    dict.iter()
        .map(|found| {
            let (key, found) = found.expect("an entry");
            let value = found
                .entry
                .slice()
                .expect("a value")
                .to_builder()
                .expect("a builder");
            (key, found.extra, value)
        })
        .collect()
}

#[test]
fn the_accounts_dictionary_rebuilds_to_the_hash_the_validators_computed() {
    let root = account_blocks();
    assert_eq!(hex(root.repr_hash()), ACCOUNT_BLOCKS_ROOT);

    let real = AugDict::from_root(SumCurrencies, Some(root), ACCOUNT_KEY_BITS).unwrap();
    let entries = entries(&real);
    assert_eq!(entries.len(), 11);

    // The summary over the whole edge is the one the block states for it.
    assert_eq!(real.root_extra().unwrap().unwrap().grams, TOTAL_GRAMS);

    // Rebuilding is what tests canonical form. A label and a summary each have encodings
    // that read back the same and hash differently, so a rebuilt dictionary that reaches
    // the validators' own hash chose every one of them the way TON does.
    //
    // Both orders, because a dictionary's shape must follow from its entries and not from
    // the order they arrived in.
    for order in [false, true] {
        let mut rebuilt = AugDict::new(SumCurrencies, ACCOUNT_KEY_BITS).unwrap();
        let mut entries = entries.clone();
        if order {
            entries.reverse();
        }
        for (key, extra, value) in &entries {
            rebuilt.set(key, extra, value).unwrap();
        }
        assert_eq!(
            hex(rebuilt.root().unwrap().repr_hash()),
            ACCOUNT_BLOCKS_ROOT,
            "rebuilt in {} order",
            if order { "descending" } else { "ascending" }
        );
    }
}

#[test]
fn every_fork_summarises_the_two_subtrees_below_it() {
    let mut found = Vec::new();
    forks(&account_blocks(), ACCOUNT_KEY_BITS, &mut found);
    assert_eq!(found.len(), 10, "the fixture's forks");

    for (stored, left, right) in found {
        assert_eq!(
            stored,
            SumCurrencies.combine(&left, &right).unwrap(),
            "a fork's summary is its children's combined"
        );
    }
}

#[test]
fn validate_accepts_the_real_accounts_dictionary() {
    // The same check as the walk above, run through the dictionary's own validate: every
    // fork of a real block sums the two subtrees below it.
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    real.validate()
        .expect("every mainnet fork sums its children");
}

#[test]
fn fork_extras_lists_every_fork_the_block_carries() {
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    let listed = real.fork_extras().unwrap();
    assert_eq!(listed.len(), 10, "ten forks over eleven leaves");
    assert_eq!(
        listed[0].1,
        real.root_extra().unwrap().unwrap(),
        "the first fork in pre-order is the root, over the whole dictionary"
    );
}

#[test]
fn the_leaves_add_up_to_what_the_block_says_they_do() {
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    let total: u128 = entries(&real).iter().map(|(_, extra, _)| extra.grams).sum();
    assert_eq!(total, TOTAL_GRAMS);
}

#[test]
fn from_items_rebuilds_the_accounts_dictionary_to_the_validators_hash() {
    // The bulk path has to land on the same canonical tree the one-at-a-time rebuild does,
    // so it answers to the same hash the validators computed, in either order.
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    let entries = entries(&real);
    for order in [false, true] {
        let mut items = entries.clone();
        if order {
            items.reverse();
        }
        let bulk = AugDict::from_items(SumCurrencies, ACCOUNT_KEY_BITS, items).unwrap();
        assert_eq!(
            hex(bulk.root().unwrap().repr_hash()),
            ACCOUNT_BLOCKS_ROOT,
            "from_items in {} order",
            if order { "descending" } else { "ascending" }
        );
    }
}

#[test]
fn a_carved_accounts_sub_dictionary_stays_consistent_and_canonical() {
    // Carving keeps every subtree it holds, so the summary rule still holds over the sub,
    // and a fresh build over its entries reaches the same tree.
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    let all = entries(&real);
    let lead = all[0].0[0];
    let narrower = ACCOUNT_KEY_BITS - 8;

    let sub = real.subdict(&[lead], 8).unwrap();
    assert_eq!(sub.key_bits(), narrower);
    sub.validate()
        .expect("a carved augmented dictionary is still consistent");

    let expected: Vec<(Vec<u8>, u128)> = all
        .iter()
        .filter(|(key, _, _)| key[0] == lead)
        .map(|(key, extra, _)| (key[1..].to_vec(), extra.grams))
        .collect();
    let carved: Vec<(Vec<u8>, u128)> = entries(&sub)
        .into_iter()
        .map(|(key, extra, _)| (key, extra.grams))
        .collect();
    assert!(
        !carved.is_empty(),
        "the first entry's byte carves at least it"
    );
    assert_eq!(carved, expected);

    let rebuilt = AugDict::from_items(SumCurrencies, narrower, entries(&sub)).unwrap();
    assert_eq!(
        rebuilt.root().map(Cell::repr_hash),
        sub.root().map(Cell::repr_hash),
    );
}

#[test]
fn combining_two_halves_of_the_accounts_dictionary_rebuilds_the_validators_hash() {
    // Split the eleven entries into two dictionaries and combine them back. The union has to
    // land on the same canonical tree the validators wrote, summaries and all, which is the
    // hash the block was served under.
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    let all = entries(&real);
    let mid = all.len() / 2;

    let mut left =
        AugDict::from_items(SumCurrencies, ACCOUNT_KEY_BITS, all[..mid].iter().cloned()).unwrap();
    let right =
        AugDict::from_items(SumCurrencies, ACCOUNT_KEY_BITS, all[mid..].iter().cloned()).unwrap();
    left.combine_with(&right).unwrap();

    assert_eq!(hex(left.root().unwrap().repr_hash()), ACCOUNT_BLOCKS_ROOT);
    assert_eq!(left.root_extra().unwrap().unwrap().grams, TOTAL_GRAMS);
}

/// Each `AccountBlock`, as the transactions edge it carries and the summary above it.
fn transaction_edges() -> Vec<(Cell, Currencies)> {
    let real = AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    real.iter()
        .map(|found| {
            let (_, found) = found.expect("an entry");
            let mut value = found.entry.slice().expect("an account block");
            assert_eq!(value.load_uint(4).unwrap(), ACC_TRANS_TAG);
            let _address = value.load_bytes(32).unwrap();
            (value.to_cell().expect("the rest of the cell"), found.extra)
        })
        .collect()
}

#[test]
fn the_transaction_dictionaries_hold_to_the_same_rule_at_a_narrower_key() {
    let edges = transaction_edges();
    assert_eq!(edges.len(), 11);

    let mut single = 0usize;
    let mut forked = 0usize;

    for (edge, above) in edges {
        let dict =
            AugDict::from_root(SumCurrencies, Some(edge.clone()), TRANSACTION_KEY_BITS).unwrap();
        let entries = entries(&dict);

        // What the account block states for its transactions is what they add up to.
        let total: u128 = entries.iter().map(|(_, extra, _)| extra.grams).sum();
        assert_eq!(total, above.grams);
        assert_eq!(dict.root_extra().unwrap().unwrap().grams, above.grams);

        let mut fork_summaries = Vec::new();
        forks(&edge, TRANSACTION_KEY_BITS, &mut fork_summaries);
        for (stored, left, right) in &fork_summaries {
            assert_eq!(*stored, SumCurrencies.combine(left, right).unwrap());
        }

        if fork_summaries.is_empty() {
            // One entry, so the edge is the whole rest of the cell and rebuilding it
            // compares exactly. This is what pins the label and the summary encodings at
            // a 64-bit key, where a label runs to a different form than at 256.
            single += 1;
            let mut rebuilt = AugDict::new(SumCurrencies, TRANSACTION_KEY_BITS).unwrap();
            for (key, extra, value) in &entries {
                rebuilt.set(key, extra, value).unwrap();
            }
            assert_eq!(rebuilt.root().unwrap().repr_hash(), edge.repr_hash());
        } else {
            forked += 1;
        }
    }

    assert_eq!(
        (single, forked),
        (10, 1),
        "the fixture's transaction dictionaries"
    );
}

#[test]
fn a_key_added_and_taken_away_again_leaves_the_dictionary_where_it_was() {
    let mut dict =
        AugDict::from_root(SumCurrencies, Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();

    let key = [0x5au8; 32];
    let extra = Currencies {
        grams: 1_000,
        other: None,
    };
    let mut value = Builder::new();
    value.store_uint(0xdead_beef, 32).unwrap();

    dict.set(&key, &extra, &value).unwrap();
    assert_ne!(hex(dict.root().unwrap().repr_hash()), ACCOUNT_BLOCKS_ROOT);

    // The summaries above it moved by exactly what was added.
    assert_eq!(
        dict.root_extra().unwrap().unwrap().grams,
        TOTAL_GRAMS + extra.grams
    );
    let Lookup::Found(found) = dict.get(&key).unwrap() else {
        unreachable!("the key was just stored")
    };
    assert_eq!(found.extra, extra);
    assert_eq!(
        found.entry.slice().unwrap().load_uint(32).unwrap(),
        0xdead_beef
    );

    assert!(dict.remove(&key).unwrap());
    assert_eq!(
        hex(dict.root().unwrap().repr_hash()),
        ACCOUNT_BLOCKS_ROOT,
        "removing what was added restores the mainnet tree, summaries included"
    );
    assert_eq!(dict.root_extra().unwrap().unwrap().grams, TOTAL_GRAMS);
}

#[test]
fn which_child_is_which_decides_a_fork_that_can_tell_them_apart() {
    // Two keys parting at the first bit, so the root is a fork over them.
    let mut dict = AugDict::new(Ordered, 32).unwrap();
    let value = Builder::new();
    dict.set(&0x0000_0001u32.to_be_bytes(), &2, &value).unwrap();
    dict.set(&0x8000_0000u32.to_be_bytes(), &5, &value).unwrap();

    // combine(left, right) with the low key on the left: 2 * 3 + 5.
    assert_eq!(dict.root_extra().unwrap(), Some(11));
    assert_ne!(
        dict.root_extra().unwrap(),
        Some(Ordered.combine(&5, &2).unwrap()),
        "the two orders differ, so this dictionary would notice a swap"
    );
}

#[test]
fn a_summary_cannot_be_invented_for_a_subtree_a_proof_hid() {
    // A plain dictionary can be written next to a pruned branch, because a fork holds
    // nothing that depends on what is under its sibling. An augmented one cannot: the
    // fork's summary covers the sibling too, and a placeholder holds a hash rather than
    // anything to summarise.
    let pruned = a_pruned_branch();

    let mut fork = Builder::new();
    // A fork over a 32-bit key: an empty label, a summary, then the two branches.
    fork.store_bit(false).unwrap();
    fork.store_bit(false).unwrap();
    Ordered.write(&7, &mut fork).unwrap();
    let mut leaf = Builder::new();
    // The other branch is an ordinary leaf over the 31 bits still to spend, labelled in
    // the explicit-length form: a length field for a 31-bit key is five bits wide.
    leaf.store_uint(0b10, 2).unwrap();
    leaf.store_uint(31, 5).unwrap();
    leaf.store_uint(0, 31).unwrap();
    Ordered.write(&7, &mut leaf).unwrap();
    fork.store_ref(leaf.build().unwrap()).unwrap();
    fork.store_ref(pruned).unwrap();

    let mut dict = AugDict::from_root(Ordered, Some(fork.build().unwrap()), 32).unwrap();
    assert_eq!(
        dict.set(&0u32.to_be_bytes(), &1, &Builder::new()),
        Err(CellError::Pruned),
        "rebuilding the fork above a pruned sibling would have to invent its summary"
    );
}

#[test]
fn each_dictionary_refuses_the_other_shape_on_the_way_in() {
    use ton_net_cell::Dict;

    // A plain writer refuses an augmented fork, because it would drop the summary it has
    // no reading for and rebuild a tree that hashes as a well-formed dictionary.
    let mut plain = Dict::from_root(Some(account_blocks()), ACCOUNT_KEY_BITS).unwrap();
    assert_eq!(
        plain.set(&[0x11u8; 32], &Builder::new()),
        Err(CellError::Malformed(
            "a dictionary fork carrying data past its label"
        ))
    );

    // Reading is left permissive on purpose: the accounts dictionary of a shard is
    // augmented, and the proof engine walks it with a plain lookup and steps over the
    // summary itself.
    assert!(matches!(plain.get(&[0x11u8; 32]), Ok(Lookup::Absent)));

    // An augmented writer refuses a plain fork, which ends where a summary should start.
    let mut ordinary = Dict::new(32).unwrap();
    ordinary.set(&1u32.to_be_bytes(), &Builder::new()).unwrap();
    ordinary.set(&2u32.to_be_bytes(), &Builder::new()).unwrap();
    let mut augmented = AugDict::from_root(Ordered, ordinary.root().cloned(), 32).unwrap();
    assert!(augmented
        .set(&3u32.to_be_bytes(), &1, &Builder::new())
        .is_err());
}

#[test]
fn a_key_wider_than_a_cell_is_refused() {
    assert_eq!(
        AugDict::new(Ordered, MAX_BITS + 1).unwrap_err(),
        CellError::Malformed("dictionary key wider than a cell")
    );
}
