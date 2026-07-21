//! Network tests of the whole facade against live mainnet.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! them with `--ignored`. They use only the public facade and each skips if no
//! liteserver is reachable, so liteserver rotation does not fail the build.

use ton_net::{Address, Client, Config, Error};

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
        assert!(account.value().is_active(), "{name} is deployed");
        assert!(
            account.value().balance.nanotons() > 0,
            "{name} holds a balance"
        );
        assert!(account.value().code().is_some(), "{name} has code");
        eprintln!("{name} balance: {}", account.value().balance);
    }

    // A basechain account: the read must complete and decode even if the account is empty.
    let basechain = Address::parse(BASECHAIN).expect("valid address");
    let account = client
        .account(&basechain)
        .await
        .expect("basechain account read");
    eprintln!("basechain account balance: {}", account.value().balance);
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn verifies_live_accounts_in_both_workchains() {
    let Some(mut client) = connect().await else {
        return;
    };

    // The anchor here is the server's own head, so this test says nothing about whether
    // the server is honest: it exercises the machinery against live data. The check that
    // the machinery lands on hashes a second party published is hermetic, over captured
    // bytes, in ton-net-block.
    let trusted = client
        .masterchain_info()
        .await
        .expect("masterchain_info")
        .into_value()
        .last;

    for (name, address) in [
        ("elector", ELECTOR),
        ("config", CONFIG_CONTRACT),
        ("basechain", BASECHAIN),
    ] {
        let parsed = Address::parse(address).expect("valid address");
        let verified = client
            .account_verified(&parsed, &trusted)
            .await
            .unwrap_or_else(|e| panic!("{name} did not verify: {e}"));

        assert_eq!(verified.anchor().seqno, trusted.seqno);
        eprintln!(
            "{name} verified at seqno {}: balance {}",
            trusted.seqno,
            verified.value().balance
        );
    }
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn a_block_the_server_does_not_know_is_refused_before_any_proof() {
    let Some(mut client) = connect().await else {
        return;
    };

    let mut unknown = client
        .masterchain_info()
        .await
        .expect("masterchain_info")
        .into_value()
        .last;
    unknown.root_hash[0] ^= 1;

    // A verified read is made at the block it is checked against, so the two cannot drift
    // apart by accident. A caller who invents a block never reaches the proof engine: the
    // server has no such block to read at.
    let parsed = Address::parse(ELECTOR).expect("valid address");
    match client.account_verified(&parsed, &unknown).await {
        Err(Error::LiteServer { .. }) => {}
        Err(other) => panic!("expected the server to refuse the block, got {other}"),
        Ok(_) => panic!("a read succeeded at a block that does not exist"),
    }
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn live_proof_bytes_are_refused_against_the_wrong_block() {
    use ton_net_block::{proof, AccountRead};

    let Some(mut client) = connect().await else {
        return;
    };

    let head = client
        .masterchain_info()
        .await
        .expect("masterchain_info")
        .into_value()
        .last;
    let parsed = Address::parse(ELECTOR).expect("valid address");
    let reported = client
        .account_state(&parsed, &head)
        .await
        .expect("account state");
    let state = reported.value();

    // Genuine bytes, read at a real block. Against that block's hash they check out.
    let good = AccountRead::masterchain(
        &head.root_hash,
        parsed.account_id(),
        reported.proof(),
        &state.state,
    );
    proof::verify_account(&good).expect("a live read verifies against the block it was read at");

    // The same bytes against any other hash prove nothing. Driving the engine directly is
    // the only way to reach this case, because the client reads at the block it checks
    // against; today's mainnet bytes have to fail it just as the pinned ones do.
    let mut wrong = head.root_hash;
    wrong[0] ^= 1;
    let bad = AccountRead::masterchain(&wrong, parsed.account_id(), reported.proof(), &state.state);
    assert!(
        proof::verify_account(&bad).is_err(),
        "live proof bytes verified against a block they say nothing about"
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
