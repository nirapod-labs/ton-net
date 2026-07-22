// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What this build accepts as proven, written down.
//!
//! [`ton_net::VERIFY_EPOCH`] is a promise that the accept and reject boundary has not
//! moved since the last time the number did. A constant alone cannot keep that promise:
//! nothing stops an edit from changing what verifies while the number stays where it is,
//! and a number nobody is forced to reconsider is decoration.
//!
//! So the boundary is pinned here as a transcript. Each case below is run through the
//! public API and its verdict recorded, and the whole transcript is compared against the
//! text this file carries. Change what the engine accepts and this test fails, which is
//! the moment to decide whether the epoch moves.
//!
//! # Reading a failure
//!
//! The assertion prints both transcripts, so the diff names the case that moved and what
//! it moved to. Two outcomes are possible and they are not the same:
//!
//! - The change was intended. Raise `VERIFY_EPOCH`, paste the new transcript in, and
//!   record in the changelog what is now accepted or refused that was not before.
//! - The change was not intended. The transcript just caught a verifier accepting
//!   something it used to refuse, which is the failure this file exists to catch.
//!
//! # Why a transcript rather than a digest
//!
//! A digest answers "something changed" and a transcript answers "this case changed, to
//! this". The second is what a reader needs at the moment the test fails, and the cost is
//! a few hundred bytes of test source.
//!
//! # What is covered
//!
//! One captured masterchain read and ten edits of it, chosen to sit on the decision
//! boundary rather than to be numerous: the anchor, the proof bytes, the state bytes, the
//! account asked about, and a whole valid state belonging to somebody else.
//!
//! Every refusal reads `PROOF`, and that is the facade's design rather than a loss here:
//! bytes handed over as a proof that do not parse are a server failing to prove its
//! answer, so they are not sorted into a separate kind. The transcript is therefore
//! coarse among refusals and exact about the two transitions that matter, which are a
//! refusal becoming a proof and a proved value changing. Verdicts use error codes rather
//! than messages, so rewording is free and reclassifying is not.

use ton_net::{verify_account, AccountRead, ErrorCode};

/// A real masterchain read: anchor, proof and state as one liteserver answered them.
const READ: &str = include_str!("fixtures/read-masterchain.txt");

/// A second real read, of a different account. Only its state bytes are used, as the
/// substitution a lying server would actually attempt: bytes that parse perfectly well
/// and describe an account other than the one asked about. An edit that merely corrupts
/// the state dies in the parser and never reaches the check that binds state to proof,
/// so without this case the most important refusal here is never exercised.
const OTHER_READ: &str = include_str!("fixtures/read-basechain.txt");

/// The boundary this build stands behind.
///
/// Regenerate by running with `--nocapture` and reading the printed transcript, but only
/// after deciding the change was meant.
const TRANSCRIPT: &str = "\
epoch 1
account-substituted     -> refused PROOF
anchor-flipped          -> refused PROOF
captured                -> proved 222859282039087 active
proof-empty             -> refused PROOF
proof-flipped           -> refused PROOF
proof-is-not-a-bag      -> refused PROOF
proof-truncated         -> refused PROOF
state-empty             -> refused PROOF
state-flipped           -> refused PROOF
state-substituted       -> refused PROOF
state-truncated         -> refused PROOF";

/// One captured answer to `liteServer.getAccountState`.
struct Read {
    account_id: [u8; 32],
    block_root_hash: [u8; 32],
    proof: Vec<u8>,
    state: Vec<u8>,
}

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("fixture has no {name}"))
        .trim()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hash(s: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(unhex(s).as_slice()).expect("32 bytes")
}

impl Read {
    fn parse() -> Read {
        Read {
            account_id: hash(field(READ, "account_id")),
            block_root_hash: hash(field(READ, "block_root_hash")),
            proof: unhex(field(READ, "proof")),
            state: unhex(field(READ, "state")),
        }
    }
}

/// Runs one case and renders its verdict as a single stable line.
///
/// A proved read records the balance and the status rather than only "proved", so a
/// change in what is decoded fails here too, not merely a change in whether it verifies.
fn verdict(anchor: &[u8; 32], account: &[u8; 32], proof: &[u8], state: &[u8]) -> String {
    let read = AccountRead::masterchain(anchor, account, proof, state);
    match verify_account(&read) {
        Ok(account) => {
            let status = match account.status {
                ton_net::AccountStatus::Nonexistent => "nonexistent",
                ton_net::AccountStatus::Uninit => "uninit",
                ton_net::AccountStatus::Frozen { .. } => "frozen",
                ton_net::AccountStatus::Active { .. } => "active",
                _ => "unknown",
            };
            format!("proved {} {status}", account.balance)
        }
        Err(e) => format!("refused {}", ErrorCode::as_str(e.code())),
    }
}

/// Flips one bit a good way into the buffer, past any header.
fn flip(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let at = out.len() / 2;
    out[at] ^= 0x01;
    out
}

#[test]
fn the_accepted_set_is_what_the_epoch_claims() {
    let read = Read::parse();
    let anchor = read.block_root_hash;
    let account = read.account_id;

    let mut other_account = account;
    other_account[0] ^= 0xff;
    let mut other_anchor = anchor;
    other_anchor[0] ^= 0xff;

    let cases: Vec<(&str, String)> = vec![
        (
            "captured",
            verdict(&anchor, &account, &read.proof, &read.state),
        ),
        (
            "anchor-flipped",
            verdict(&other_anchor, &account, &read.proof, &read.state),
        ),
        (
            "account-substituted",
            verdict(&anchor, &other_account, &read.proof, &read.state),
        ),
        (
            "proof-flipped",
            verdict(&anchor, &account, &flip(&read.proof), &read.state),
        ),
        (
            "proof-truncated",
            verdict(
                &anchor,
                &account,
                &read.proof[..read.proof.len() / 2],
                &read.state,
            ),
        ),
        ("proof-empty", verdict(&anchor, &account, &[], &read.state)),
        (
            "proof-is-not-a-bag",
            verdict(&anchor, &account, b"not a bag of cells", &read.state),
        ),
        (
            "state-flipped",
            verdict(&anchor, &account, &read.proof, &flip(&read.state)),
        ),
        (
            "state-truncated",
            verdict(
                &anchor,
                &account,
                &read.proof,
                &read.state[..read.state.len() / 2],
            ),
        ),
        ("state-empty", verdict(&anchor, &account, &read.proof, &[])),
        (
            "state-substituted",
            verdict(
                &anchor,
                &account,
                &read.proof,
                &unhex(field(OTHER_READ, "state")),
            ),
        ),
    ];

    // Sorted, so adding a case does not reshuffle the transcript and hide a real move.
    let mut lines: Vec<String> = cases
        .iter()
        .map(|(name, v)| format!("{name:<23} -> {v}"))
        .collect();
    lines.sort();

    // The epoch is the first line rather than a separate assertion, so the number and
    // the boundary it describes are one pinned pair. Either moving without the other
    // fails here, which is the whole promise the constant makes.
    let transcript = format!("epoch {}\n{}", ton_net::VERIFY_EPOCH, lines.join("\n"));

    println!("{transcript}");
    assert_eq!(
        transcript, TRANSCRIPT,
        "\nthe epoch and what this build accepts have come apart. If the boundary moved \
         on purpose, raise VERIFY_EPOCH, paste the transcript above in, and record the \
         delta in the changelog. If it did not, a verifier changed its mind on its own.\n"
    );
}
