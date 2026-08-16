// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reads one account's balance, proved rather than taken on a server's word.
//!
//! ```text
//! cargo run --example balance
//! ```
//!
//! The walk this does once is the expensive part, and [`resume`] shows how not to
//! pay for it twice.
//!
//! [`resume`]: https://github.com/nirapod-labs/ton-net/blob/main/crates/ton-net/examples/resume.rs

use ton_net::{Address, Client, Config};

#[tokio::main]
async fn main() -> Result<(), ton_net::Error> {
    let mut client = Client::connect(&Config::mainnet()).await?;

    // Walks from the key block the configuration pins to the current head, checking a
    // validator signature set at every link. Nothing below is believed without it.
    let report = client.sync().await?;
    println!(
        "proved {} links over {} replies, reaching block {}",
        report.links, report.rounds, report.head.seqno
    );

    // The elector, which every TON network has and which is always active.
    let elector =
        Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;
    let account = client.account(&elector).await?;

    // `Verified<Account>` has no public constructor, so holding one is itself the
    // evidence that a proof checked out. The balance below was proved, not reported.
    println!("balance {}", account.value().balance);
    println!("status  {:?}", account.value().status);
    println!("proved against block {}", account.anchor().seqno);

    Ok(())
}
