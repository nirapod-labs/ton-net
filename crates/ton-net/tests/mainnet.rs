//! Network tests of the whole facade against live mainnet.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! them with `--ignored`. They use only the public facade and each skips if no
//! liteserver is reachable, so liteserver rotation does not fail the build.

use ton_net::{Address, Client, Config};

// Address of a system contract that is always active on mainnet.
const ELECTOR: &str = "-1:3333333333333333333333333333333333333333333333333333333333333333";
const CONFIG_CONTRACT: &str = "-1:5555555555555555555555555555555555555555555555555555555555555555";
// A basechain (workchain 0) account, to exercise the non-masterchain read path.
const BASECHAIN: &str = "0:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260";

async fn connect() -> Option<Client> {
    match Client::connect(&Config::mainnet()).await {
        Ok(client) => Some(client),
        Err(e) => {
            eprintln!("skipping: no mainnet liteserver reachable: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn reads_the_masterchain_head_with_every_invariant() {
    let Some(mut client) = connect().await else {
        return;
    };

    let head = client.masterchain_info().await.expect("masterchain_info");
    let last = &head.value().last;
    assert_eq!(last.workchain, -1, "masterchain workchain");
    assert_eq!(last.shard, 0x8000_0000_0000_0000, "masterchain shard");
    assert!(last.seqno > 0, "seqno is live");
    assert_ne!(last.root_hash, [0u8; 32], "root hash is set");
    assert_ne!(last.file_hash, [0u8; 32], "file hash is set");
    assert_ne!(
        head.value().state_root_hash,
        [0u8; 32],
        "state root hash is set"
    );
    // masterchainInfo carries no proof.
    assert!(head.proof().is_empty(), "masterchain head has no proof");

    // A second read never goes backwards: the head is monotonic.
    let again = client
        .masterchain_info()
        .await
        .expect("second masterchain_info");
    assert!(
        again.value().last.seqno >= last.seqno,
        "the head does not go backwards"
    );
    eprintln!("mainnet masterchain seqno: {}", again.value().last.seqno);
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn reads_accounts_in_both_workchains() {
    let Some(mut client) = connect().await else {
        return;
    };

    // The elector and the config contract are always-active masterchain contracts.
    for (name, address) in [("elector", ELECTOR), ("config", CONFIG_CONTRACT)] {
        let parsed = Address::parse(address).expect("valid address");
        let account = client.account(&parsed).await.expect("account read");
        assert_eq!(
            account.value().block.workchain,
            -1,
            "read at a masterchain block"
        );
        assert!(
            !account.value().state.is_empty(),
            "{name} has a nonempty state"
        );
        eprintln!("{name} state bytes: {}", account.value().state.len());
    }

    // A basechain account: the read must complete and decode even if the account is empty.
    let basechain = Address::parse(BASECHAIN).expect("valid address");
    let account = client
        .account(&basechain)
        .await
        .expect("basechain account read");
    eprintln!(
        "basechain account state bytes: {}",
        account.value().state.len()
    );
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn connect_rotates_past_a_dead_liteserver() {
    // A config whose first liteserver is a closed local port and whose second is real.
    // connect must skip the dead one and complete a handshake with the live one. The key
    // is shared; the dead entry never gets far enough to use it.
    let json = r#"{"liteservers":[
        {"ip":2130706433,"port":1,"id":{"@type":"pub.ed25519","key":"n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="}},
        {"ip":84478511,"port":19949,"id":{"@type":"pub.ed25519","key":"n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk="}}
    ]}"#;
    let config = Config::from_json(json).expect("config parses");

    let mut client = match Client::connect(&config).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("skipping: live liteserver unreachable: {e}");
            return;
        }
    };
    let head = client
        .masterchain_info()
        .await
        .expect("head after rotation");
    assert_eq!(head.value().last.workchain, -1);
    eprintln!(
        "rotated past a dead server; seqno {}",
        head.value().last.seqno
    );
}
