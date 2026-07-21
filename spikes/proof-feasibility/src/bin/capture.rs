//! Captures an account's state and proof as hex, to pin as a test fixture.
//!
//! The cell and block crates are tested against bytes TON produced rather than bytes
//! they wrote themselves. This dumps those bytes for one account.
//!
//! ```text
//! cargo run --bin capture -- 0:fcb91a3a...
//! ```

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
    let reported = client.account(&parsed).await.expect("account read");
    let block = &reported.value().block;

    println!("ADDRESS={address}");
    println!("BLOCK_SEQNO={}", block.seqno);
    println!("BLOCK_ROOT_HASH={}", hex(&block.root_hash));
    println!("STATE_LEN={}", reported.value().state.len());
    println!("STATE_HEX={}", hex(&reported.value().state));
    println!("PROOF_HEX={}", hex(reported.proof()));
}
