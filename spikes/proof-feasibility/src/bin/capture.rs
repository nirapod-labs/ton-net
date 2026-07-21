//! Captures everything one account read returns, to pin as a test fixture.
//!
//! The cell and block crates are tested against bytes TON produced rather than bytes
//! they wrote themselves. A verified read needs the whole matched set, not just the
//! state: the masterchain block it was read at, the shard block holding the account, the
//! proof tying the two together, the account-state proof, and the state itself. Captured
//! separately they would not chain, so they are captured in one call.
//!
//! ```text
//! cargo run --bin capture -- -1:5555555555555555555555555555555555555555555555555555555555555555
//! ```
//!
//! The block root hash it prints is the liteserver's own word. Confirm it against a
//! source independent of that server before pinning it as a trusted anchor.

use ton_net::{Address, Client, Config};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() {
    let Some(address) = std::env::args().nth(1) else {
        eprintln!("usage: capture <address>");
        std::process::exit(2);
    };

    let config = Config::mainnet();
    let mut client = match Client::connect(&config).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("no mainnet liteserver reachable: {e}");
            std::process::exit(1);
        }
    };

    let parsed = Address::parse(&address).expect("valid address");
    let head = client
        .masterchain_info()
        .await
        .expect("masterchain head")
        .into_value()
        .last;
    // The raw read: a fixture needs the bytes as the server sent them, not a decode of
    // them, so the proofs it carries can be checked later.
    let reported = client
        .account_state(&parsed, &head)
        .await
        .expect("account read");
    let read = reported.value();

    println!("# {address}");
    println!("workchain={}", parsed.workchain());
    println!("account_id={}", hex(parsed.account_id()));
    println!("block_seqno={}", read.block.seqno);
    println!("block_root_hash={}", hex(&read.block.root_hash));
    println!("shard_block_seqno={}", read.shard_block.seqno);
    println!("shard_block_shard={:016x}", read.shard_block.shard);
    println!("shard_block_root_hash={}", hex(&read.shard_block.root_hash));
    println!("shard_proof={}", hex(&read.shard_proof));
    println!("proof={}", hex(reported.proof()));
    println!("state={}", hex(&read.state));
}
