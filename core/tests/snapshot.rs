// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Whether the bundled mainnet snapshot still describes the network.
//!
//! [`Config::mainnet`] returns a copy of the public mainnet configuration taken on a
//! date, and both halves of it decay. Liteservers rotate, so an address in the snapshot
//! stops answering; the block the validator section pins recedes, so a first sync walks
//! further every day. A crate cannot be replaced once published, only superseded, so a
//! snapshot that had already decayed at release is a patch release rather than a fix.
//!
//! What makes this checkable rather than a note in a document is that decay is gradual.
//! Nothing breaks on the day a liteserver goes: [`Client::connect`] tries the next one
//! and every other test still passes, right up until the last one goes too. So the check
//! is not whether the config works, which stays true far too long, but how much of it is
//! left.
//!
//! `#[ignore]` so the hermetic suite never reaches the network. The network CI job runs
//! these with `--ignored`, daily, which is the cadence the question deserves.

use std::time::Duration;

use ton_net::{Client, Config};

/// The snapshot as it ships, read here so the check is over the bytes a caller gets.
const BUNDLED: &str = include_str!("../src/mainnet.config.json");

/// How many of the bundled liteservers must still answer.
///
/// Set from a measurement, and the measurement is the reason this file exists: on
/// 2026-07-21, eleven of the eighteen answered. Four refused the connection outright and
/// three never completed one. Nothing showed it, because the first entry in the list is
/// among the eleven and every other test connects through it.
///
/// The floor is half. It leaves room for the few that are down on any given day and
/// still fails while there is time to refresh the snapshot, rather than when the last one
/// goes and every caller is already stranded.
const MIN_REACHABLE: usize = 9;

/// How far the pinned block may fall behind the head before the snapshot is too old.
///
/// A first sync walks every key block published since the pinned one, so this is the
/// gap a new caller pays for once. On 2026-07-21 the pinned block was 34.3 million
/// masterchain blocks back, which the cold-sync test measured as 1244 links and 95.8
/// seconds. The bound is roughly double that gap: a first sync of a minute and a half is
/// a slow start, one of several minutes is a broken one.
///
/// The pinned block is where the published mainnet config puts it rather than where this
/// library chose, so crossing this bound is a decision to carry an anchor of this
/// project's own, not a line to edit.
const MAX_BLOCKS_BEHIND: u32 = 70_000_000;

/// A copy of the bundled config carrying one liteserver, so each can be dialled alone.
///
/// `Client::connect` walks the list until one answers, which is the behaviour a caller
/// wants and the opposite of what this file needs to see.
fn only_server(index: usize) -> String {
    let mut config: serde_json::Value =
        serde_json::from_str(BUNDLED).expect("the bundled snapshot is json");
    let servers = config["liteservers"]
        .as_array()
        .expect("the snapshot lists liteservers")
        .clone();
    config["liteservers"] = serde_json::Value::Array(vec![servers[index].clone()]);
    config.to_string()
}

fn server_count() -> usize {
    serde_json::from_str::<serde_json::Value>(BUNDLED).expect("the bundled snapshot is json")
        ["liteservers"]
        .as_array()
        .expect("the snapshot lists liteservers")
        .len()
}

#[tokio::test]
#[ignore = "dials every bundled liteserver; run with --ignored in the network job"]
async fn most_of_the_bundled_liteservers_still_answer() {
    let total = server_count();
    let mut reachable = Vec::new();
    let mut silent = Vec::new();

    for index in 0..total {
        let config = Config::from_json(&only_server(index)).expect("a one-server config parses");
        // A dead address costs the full connect timeout, and there are eighteen of them,
        // so each attempt is held to something shorter than the suite's patience.
        let attempt = tokio::time::timeout(Duration::from_secs(20), async {
            let mut client = Client::connect(&config).await?;
            client.masterchain_info().await
        })
        .await;

        match attempt {
            Ok(Ok(_)) => reachable.push(index),
            Ok(Err(e)) => silent.push(format!("{index}: {e}")),
            Err(_) => silent.push(format!("{index}: no answer within ten seconds")),
        }
    }

    eprintln!(
        "bundled liteservers answering: {} of {total}",
        reachable.len()
    );
    for entry in &silent {
        eprintln!("  silent {entry}");
    }

    assert!(
        reachable.len() >= MIN_REACHABLE,
        "only {} of {total} bundled liteservers answered, below the floor of {MIN_REACHABLE}. \
         The snapshot in crates/ton-net/src/mainnet.config.json needs refreshing from the \
         published mainnet config before the next release.",
        reachable.len()
    );
}

#[tokio::test]
#[ignore = "reads the live masterchain head; run with --ignored in the network job"]
async fn the_pinned_block_has_not_receded_out_of_reach() {
    let config = Config::mainnet();
    let Ok(mut client) = Client::connect(&config).await else {
        eprintln!("skipping: no mainnet liteserver reachable");
        return;
    };

    let pinned = config
        .init_block()
        .expect("the bundled snapshot pins an init block")
        .seqno;
    let head = client
        .masterchain_info()
        .await
        .expect("masterchain_info")
        .value()
        .last
        .seqno;

    let behind = head.saturating_sub(pinned);
    eprintln!("pinned block {pinned}, head {head}, behind by {behind}");

    assert!(
        behind <= MAX_BLOCKS_BEHIND,
        "the pinned init block is {behind} masterchain blocks behind the head, past the \
         bound of {MAX_BLOCKS_BEHIND}. Every first sync walks that gap, so the snapshot \
         in crates/ton-net/src/mainnet.config.json needs refreshing."
    );
}
