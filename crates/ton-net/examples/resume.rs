// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Saves the block a walk ended on, so the next run does not walk again.
//!
//! ```text
//! cargo run --example resume        # first run walks
//! cargo run --example resume        # second run does not
//! ```
//!
//! A first sync checks every key block published since the pinned one, which is over a
//! thousand links. A client that keeps the block it finished on hands that back and
//! pays one. The saved block is written out field by field rather than through a
//! serializer, because what is being persisted is worth seeing: five numbers that
//! become the next run's root of trust.

use std::fs;
use std::path::Path;
use ton_net::{Address, BlockIdExt, Client, Config, Error};

const SAVED: &str = "anchor.txt";

fn main() -> Result<(), Error> {
    let body = async {
        let config = Config::mainnet();

        let mut client = if let Some(anchor) = load(Path::new(SAVED)) {
            println!("resuming from block {}", anchor.seqno);
            Client::connect_from(&config, &anchor).await?
        } else {
            println!("no saved anchor, walking from the block the config pins");
            Client::connect(&config).await?
        };

        let report = client.sync().await?;
        println!(
            "{} links this time, head {}",
            report.links, report.head.seqno
        );

        let elector =
            Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;
        println!(
            "balance {}",
            client.account(&elector).await?.value().balance
        );

        // The client keeps a key block behind the head rather than the head itself, so
        // the next walk has something a chain can continue from.
        if let Some(anchor) = client.anchor() {
            save(Path::new(SAVED), anchor);
            println!("saved block {} for next time", anchor.seqno);
        }

        Ok::<(), Error>(())
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Config(e.to_string()))?
        .block_on(body)
}

/// Writes the anchor as workchain, shard, seqno and the two hashes, one per line.
fn save(path: &Path, anchor: &BlockIdExt) {
    let text = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        anchor.workchain,
        anchor.shard,
        anchor.seqno,
        hex(&anchor.root_hash),
        hex(&anchor.file_hash),
    );
    let _ = fs::write(path, text);
}

/// Reads back what `save` wrote, or nothing if this is a first run.
fn load(path: &Path) -> Option<BlockIdExt> {
    let text = fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    Some(BlockIdExt::new(
        lines.next()?.parse().ok()?,
        lines.next()?.parse().ok()?,
        lines.next()?.parse().ok()?,
        unhex(lines.next()?)?,
        unhex(lines.next()?)?,
    ))
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}
