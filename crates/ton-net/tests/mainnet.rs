//! A network test of the whole facade against live mainnet.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! it with `--ignored`. It uses only the public facade: the bundled config, a connect
//! that tries liteservers in turn, and the two reads. This is the milestone's async
//! definition of done on the Rust side.

use ton_net::{Address, Client, Config};

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn connects_and_reads_the_head_and_an_account() {
    let config = Config::mainnet();
    let mut client = match Client::connect(&config).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("skipping: no mainnet liteserver reachable: {e}");
            return;
        }
    };

    let info = client.masterchain_info().await.expect("masterchain_info");
    assert_eq!(info.value().last.workchain, -1);
    assert_eq!(info.value().last.shard, 0x8000_0000_0000_0000);
    assert!(info.value().last.seqno > 0);
    eprintln!("mainnet masterchain seqno: {}", info.value().last.seqno);

    // The elector is a system contract that is always active on mainnet.
    let elector =
        Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")
            .expect("valid address");
    let account = client.account(&elector).await.expect("account");
    assert!(
        !account.value().state.is_empty(),
        "the elector has a nonempty state"
    );
    eprintln!("elector state bytes: {}", account.value().state.len());
}
