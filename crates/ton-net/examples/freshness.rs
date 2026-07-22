// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Handles the two errors that mean the answer was old rather than wrong.
//!
//! ```text
//! cargo run --example freshness
//! ```
//!
//! A proof establishes that a block is real and that the validators committed it. It says
//! nothing about when it was handed over, so a server replaying a genuine chain from last
//! year passes every cryptographic check the library makes. The local clock is what
//! catches that, which makes these two errors different in kind from the rest: they are
//! not a failure of verification, they are verification working and the freshness bound
//! being the thing that refused.

use ton_net::{Client, Config, Error};

#[tokio::main]
async fn main() {
    // A deliberately impatient bound, so the path below is easy to exercise. The default
    // is chosen for a client that wants a current head without being brittle about it.
    let config = Config::mainnet().with_max_head_age(30);
    println!("refusing a head older than {}s", config.max_head_age());

    match run(&config).await {
        Ok(seqno) => println!("head {seqno} is within the bound"),

        // The chain is ahead of this machine's clock. Validators do not sign blocks from
        // the future, so the fault is on this side and another server will not fix it.
        Err(Error::ClockBehind {
            by_seconds,
            tolerated_seconds,
        }) => {
            eprintln!(
                "the local clock is {by_seconds}s behind the chain, past {tolerated_seconds}s"
            );
            eprintln!("fix the clock; retrying against a different server changes nothing");
        }

        // The head proved fine and is simply too old. That is a server that has stopped
        // keeping up, or one replaying an old chain, and either way it is worth leaving.
        Err(Error::Stale {
            age_seconds,
            limit_seconds,
        }) => {
            eprintln!("the proven head is {age_seconds}s old, past the {limit_seconds}s bound");
            eprintln!("the proof was good; the block was not current");
        }

        Err(other) => eprintln!("something else failed: {other}"),
    }
}

async fn run(config: &Config) -> Result<u32, Error> {
    let mut client = Client::connect(config).await?;
    Ok(client.sync().await?.head.seqno)
}
