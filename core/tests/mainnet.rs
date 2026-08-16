// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Network tests of the whole facade against live mainnet.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! them with `--ignored`. They use only the public facade and each skips if no
//! liteserver is reachable, so liteserver rotation does not fail the build.

use std::time::{Duration, Instant};

use ton_net::{AccountRead, Address, Client, Config, Error};

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
        let account = client
            .account_reported(&parsed)
            .await
            .expect("account read");
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
        .account_reported(&basechain)
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
            .account_at(&parsed, &trusted)
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
    match client.account_at(&parsed, &unknown).await {
        Err(Error::LiteServer { .. }) => {}
        Err(other) => panic!("expected the server to refuse the block, got {other}"),
        Ok(_) => panic!("a read succeeded at a block that does not exist"),
    }
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn live_proof_bytes_are_refused_against_the_wrong_block() {
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
    ton_net::verify_account(&good).expect("a live read verifies against the block it was read at");

    // The same bytes against any other hash prove nothing. Checking the bytes separately
    // is the only way to reach this case, because a verified read is made at the block it
    // is checked against; today's mainnet bytes have to fail it just as the pinned ones do.
    let mut wrong = head.root_hash;
    wrong[0] ^= 1;
    let bad = AccountRead::masterchain(&wrong, parsed.account_id(), reported.proof(), &state.state);
    match ton_net::verify_account(&bad) {
        Err(Error::Proof(_)) => {}
        Err(other) => panic!("expected a proof failure, got {other}"),
        Ok(_) => panic!("live proof bytes verified against a block they say nothing about"),
    }
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

// The milestone's gate, and the one test here that cannot be made fast. It walks every
// key block the network has published since the block the config pins, which was 1242 of
// them and 52 MB in July 2026, so it runs on a schedule rather than on every commit. Its
// name carries `cold_sync` so the per-commit run can skip it by that.
#[tokio::test]
#[ignore = "walks every key block since the config's init block; minutes and tens of megabytes"]
async fn a_cold_sync_from_the_config_reaches_a_head_a_warm_one_then_reaches_cheaply() {
    let config = Config::mainnet();
    let init = config
        .init_block()
        .expect("the bundled config names an init block");
    let Some(mut client) = connect().await else {
        return;
    };
    assert!(
        client.anchor().is_none(),
        "a client trusts nothing before it has synced"
    );

    let started = Instant::now();
    let cold = match client.sync().await {
        Ok(report) => report,
        // A server that drops a connection part way through a two minute walk is ordinary
        // and must not turn the build red. A chain that does not check out is the thing
        // this test exists to catch, so it fails rather than skipping.
        Err(e @ (Error::Transport(_) | Error::Timeout)) => {
            eprintln!("skipping: the liteserver went away mid-walk: {e}");
            return;
        }
        Err(e) => panic!("the cold sync did not check out: {e}"),
    };
    let cold_elapsed = started.elapsed();

    // Reaching a head at all is the point: the client now trusts a block it derived from
    // the config's, with a validator signature set checked at every step in between.
    assert!(cold.head.seqno > init.seqno);
    assert_eq!(cold.head.workchain, -1);
    assert!(cold.links > 0 && cold.rounds > 0);
    eprintln!(
        "cold sync: {} links over {} rounds in {:.1?}, {} -> {}",
        cold.links, cold.rounds, cold_elapsed, init.seqno, cold.head.seqno
    );

    // What the client kept is a key block behind the head, never the head itself, so the
    // next walk has something a chain can continue from.
    let anchor = client
        .anchor()
        .expect("a synced client has an anchor")
        .clone();
    assert!(anchor.seqno > init.seqno);
    assert!(anchor.seqno <= cold.head.seqno);

    // The saved anchor is the whole reason it is handed back: the second run pays a few
    // links instead of the whole history.
    let started = Instant::now();
    let mut warm = match Client::connect_from(&config, &anchor).await {
        Ok(client) => client,
        Err(e) => panic!("a warm sync from the anchor the cold one produced failed: {e}"),
    };
    let warm_elapsed = started.elapsed();
    let warm_report = warm.sync().await.expect("a second warm sync");
    eprintln!(
        "warm sync: connect_from in {warm_elapsed:.1?}, then {} links over {} rounds",
        warm_report.links, warm_report.rounds
    );
    assert!(
        warm_report.links * 20 < cold.links,
        "a warm sync cost {} links against the cold sync's {}",
        warm_report.links,
        cold.links
    );

    // The freshness bound is the one thing standing between a client and a server that
    // proves a real block from last year, and nothing inside a proof can establish it. A
    // bound of zero refuses every head there is, which is the only way to reach the check
    // against a live network where an honest head is seconds old. Run from the anchor, so
    // it costs a warm sync rather than another walk.
    let strict = Config::mainnet().with_max_head_age(0);
    match Client::connect_from(&strict, &anchor).await {
        Err(Error::Stale {
            age_seconds,
            limit_seconds,
        }) => {
            assert_eq!(limit_seconds, 0);
            eprintln!("refused a head {age_seconds}s old against a zero bound");
        }
        Err(e) => panic!("expected a stale head, got {e}"),
        Ok(_) => panic!("a bound of zero accepted a head"),
    }
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn a_sync_from_a_block_that_is_not_on_the_chain_is_refused() {
    let config = Config::mainnet();
    let Some(mut client) = connect().await else {
        return;
    };
    let head = client
        .masterchain_info()
        .await
        .expect("masterchain_info")
        .into_value()
        .last;

    // A real, current masterchain block with one bit of its root hash flipped. It names
    // nothing the network ever committed, so no server can prove a chain from it.
    let mut invented = head.clone();
    invented.root_hash[0] ^= 0x01;
    match Client::connect_from(&config, &invented).await {
        Err(Error::Sync(_) | Error::LiteServer { .. }) => {}
        Err(other) => panic!("expected a sync failure, got {other}"),
        Ok(_) => panic!("a block the chain does not contain was accepted as an anchor"),
    }
}

// The milestone's point, end to end: a proved account balance with nothing handed to the
// client but the config. Every hash it rests on was derived by walking from the key block
// that config pins, so it costs a first sync and runs on the same schedule as one.
//
// The root hashes are printed because a live balance cannot be matched against a second
// source without racing the chain, and a block can. Run on 2026-07-21 this reached head
// 81097241 with root 05f66b3ec144e7e43c177f4c95585110b3623379c38a228d38ea7f486449f1d6 and
// kept anchor 81095391 with root 870c400aa1d2616d04576e08e266a94ef340084e2b233fa7e3c9bd11788b4d3d.
// tonapi.io reports both root hashes exactly, and gives the head's prev_key_block_seqno as
// 81095391, so the block the client kept is the last key block before the head it proved.
// The independent balance match is the hermetic one in ton-net-block, at a pinned block
// where a second public API can be asked the same question and the answer holds still.
#[tokio::test]
#[ignore = "walks every key block since the config's init block; minutes and tens of megabytes"]
async fn a_cold_sync_then_proves_an_account_against_a_block_it_derived() {
    let config = Config::mainnet();
    let init = config.init_block().expect("an init block").clone();
    let Some(mut client) = connect().await else {
        return;
    };

    let elector = Address::parse(ELECTOR).expect("valid address");
    let started = Instant::now();
    let account = match client.account(&elector).await {
        Ok(account) => account,
        Err(e @ (Error::Transport(_) | Error::Timeout)) => {
            eprintln!("skipping: the liteserver went away mid-walk: {e}");
            return;
        }
        Err(e) => panic!("a proved read from the config alone failed: {e}"),
    };

    // The block it was proved against is one the client walked to, not one it was given.
    let anchor = client.anchor().expect("a synced client has an anchor");
    assert!(anchor.seqno > init.seqno);
    assert!(account.anchor().seqno > init.seqno);
    assert_eq!(account.anchor().workchain, -1);
    assert!(account.value().balance.nanotons() > 0);
    let hex = |bytes: &[u8]| -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
    };
    eprintln!(
        "proved the elector at {} in {:.1?}: balance {}",
        account.anchor().seqno,
        started.elapsed(),
        account.value().balance
    );
    eprintln!(
        "  head   {} root {}",
        account.anchor().seqno,
        hex(&account.anchor().root_hash)
    );
    eprintln!("  anchor {} root {}", anchor.seqno, hex(&anchor.root_hash));

    // The proved path and the unchecked one read the same chain, so they agree. This is a
    // cross-check between two code paths on one server, not an independent source.
    let reported = client
        .account_reported(&elector)
        .await
        .expect("an unchecked read");
    // The code cell, not the whole state: the elector's data moves between two reads
    // seconds apart, and a test that compares it is asserting the chain stood still.
    assert_eq!(
        reported.value().code().map(ton_net::Cell::hash),
        account.value().code().map(ton_net::Cell::hash),
        "the proved and unchecked reads decoded different contract code"
    );

    // A second proved read is cheap, because the anchor now stands near the head.
    let started = Instant::now();
    client
        .account(&elector)
        .await
        .expect("a second proved read");
    let second = started.elapsed();
    eprintln!("a second proved read took {second:.1?}");
    assert!(second < Duration::from_secs(30));
}
