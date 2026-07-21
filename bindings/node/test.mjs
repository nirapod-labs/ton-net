// Gate test: exercise the whole binding from Node against live mainnet.
//
// It proves the async design across the FFI boundary: the class factory returns a real
// Promise, the reads resolve to the documented shapes, a verified read proves what it
// returns, a proof checked against the wrong block is refused, and a bad input rejects.
// It also carries an anchor out to JavaScript and back in, which is how a caller pays for
// a chain walk once rather than once per process.
// It reaches the network, so it runs in the network CI job, not the hermetic one.
//
// The walk from the block the config pins runs over every key block published since, so
// it is behind TON_NET_COLD_SYNC and CI sets that on a schedule rather than per commit.

import assert from "node:assert/strict";
import binding from "./index.js";

const { Config, TonClient, verifyAccount } = binding;

// The elector is a system contract that is always active on mainnet.
const ELECTOR =
  "-1:3333333333333333333333333333333333333333333333333333333333333333";
// Another always-active masterchain contract, for the wrong-account case.
const CONFIG =
  "-1:5555555555555555555555555555555555555555555555555555555555555555";
// A basechain account, to exercise the shard path where the proof has a step more.
const BASECHAIN =
  "0:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260";

// The accounts checked against a second party, chosen for what each one can settle.
const SECOND_PARTY = [
  {
    // Quiet enough that its state is almost always the same in both reads, so the
    // comparison actually runs. It is in a shard, the longer proof chain, and its storage
    // layout is the one that tells the two readings of StorageInfo apart, so a decode
    // regression surfaces here rather than staying hidden behind an account that reads
    // the same either way.
    name: "usdt master",
    address: "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe",
  },
  {
    // A balance past 2^53, in the masterchain. It transacts constantly, so its state
    // often moves between the two reads and the comparison then has nothing to say.
    name: "elector",
    address: ELECTOR,
  },
];

// A public indexer, used here as a second party. It runs its own nodes, so a block id or
// a balance it publishes did not come from the liteserver this test is checking.
const TONCENTER = "https://toncenter.com/api/v3/";

const sleep = (ms) => new Promise((resume) => setTimeout(resume, ms));

// Unauthenticated toncenter allows about one request a second, so the calls are spaced
// and a refusal is waited out once. Every one of them is one request more than the
// hermetic suite makes, which is why this whole section is allowed to skip.
let lastRequest = 0;
async function toncenter(path, retries = 1) {
  const wait = 1200 - (Date.now() - lastRequest);
  if (wait > 0) {
    await sleep(wait);
  }
  lastRequest = Date.now();
  const response = await fetch(`${TONCENTER}${path}`, {
    signal: AbortSignal.timeout(20_000),
  });
  if (response.status === 429 && retries > 0) {
    await sleep(3_000);
    return toncenter(path, retries - 1);
  }
  if (!response.ok) {
    throw new Error(`toncenter ${path}: HTTP ${response.status}`);
  }
  return response.json();
}

function assertBlockId(id, what) {
  assert.equal(typeof id.workchain, "number", `${what} workchain is a number`);
  assert.match(id.shard, /^[0-9a-f]{16}$/, `${what} shard is 16 hex digits`);
  assert.ok(id.seqno > 0, `${what} seqno is live`);
  for (const field of ["rootHash", "fileHash"]) {
    assert.ok(
      Buffer.isBuffer(id[field]) && id[field].length === 32,
      `${what} ${field} is a 32-byte Buffer`,
    );
  }
}

// A decimal string is the whole reason a balance is not a number: past 2^53 a number
// rounds, and the rounding is silent. Digit-for-digit survival is the property.
function assertDecimal(value, what) {
  assert.equal(typeof value, "string", `${what} is a string`);
  assert.match(value, /^\d+$/, `${what} is decimal digits`);
  assert.equal(BigInt(value).toString(), value, `${what} keeps every digit`);
}

async function main() {
  const config = Config.mainnet();
  assert.ok(config instanceof Config, "mainnet() returns a Config");

  const connecting = TonClient.connect(config);
  assert.ok(connecting instanceof Promise, "connect() returns a Promise");
  let client;
  try {
    client = await connecting;
  } catch (error) {
    console.log(`gate: skip (no mainnet liteserver reachable): ${error.message}`);
    return;
  }
  assert.ok(client instanceof TonClient, "connect() resolves to a TonClient");

  const querying = client.masterchainInfo();
  assert.ok(querying instanceof Promise, "masterchainInfo() returns a Promise");
  const info = await querying;

  assertBlockId(info.value, "head");
  assert.equal(info.value.workchain, -1, "masterchain workchain");
  assert.equal(info.value.shard, "8000000000000000", "masterchain shard as u64 hex");
  assert.ok(Buffer.isBuffer(info.proof), "proof is a Buffer");
  const head = info.value;
  console.log(`masterchain seqno ${head.seqno}, shard ${head.shard}`);

  // A reported read: the server's word, with its proof unchecked alongside.
  const reported = await client.accountReported(ELECTOR);
  assert.equal(reported.value.status, "active", "the elector is deployed");
  assert.ok(
    Buffer.isBuffer(reported.value.code) && reported.value.code.length > 0,
    "an active account has code",
  );
  assert.ok(Buffer.isBuffer(reported.proof), "the unchecked proof comes back");
  assertDecimal(reported.value.balance, "reported balance");
  assertDecimal(reported.value.lastTransLt, "reported lastTransLt");

  // A verified read: the same account, proved to sit in the head block's state. The
  // anchor here is the server's own head, so this says nothing about whether the server
  // is honest; it exercises the whole chain across the boundary on live data. That the
  // chain lands on hashes a second party published is checked hermetically in Rust.
  let proved;
  for (const [name, address] of [
    ["elector", ELECTOR],
    ["basechain", BASECHAIN],
  ]) {
    const verified = await client.accountAt(address, head);
    assert.equal(verified.anchor.seqno, head.seqno, `${name} anchor seqno`);
    assert.ok(
      verified.anchor.rootHash.equals(head.rootHash),
      `${name} was proved against the block it was asked for`,
    );
    assert.equal(verified.proof, undefined, "a verified read carries no loose proof");
    assertDecimal(verified.value.balance, `${name} verified balance`);
    console.log(
      `${name} verified at seqno ${head.seqno}: ${verified.value.balance} nanotons`,
    );
    if (address === ELECTOR) {
      proved = verified;
    }
  }

  // The elector's balance runs past 2^53, so a JS number would round it and say nothing
  // about having done so. Asserting the rounding is real keeps the decimal string from
  // resting on a case that no longer occurs.
  const big = proved.value.balance;
  assert.notEqual(
    Number(big).toString(),
    big,
    `the elector balance ${big} now fits a JS number exactly`,
  );

  // The two paths read the same block, so they have to agree to the nanoton. A proved
  // balance that differed from the reported one would mean the decode and the proof walk
  // disagree about which bytes are the account.
  const at = await client.accountState(ELECTOR, head);
  assertBlockId(at.value.block, "read block");
  assertBlockId(at.value.shardBlock, "shard block");
  assert.ok(at.value.state.length > 0, "the elector has state bytes");
  const checked = verifyAccount({
    address: ELECTOR,
    trustedRootHash: head.rootHash,
    proof: at.proof,
    state: at.value.state,
  });
  assert.equal(
    checked.balance,
    proved.value.balance,
    "checking the bytes separately gives the same balance as the verified read",
  );

  // Real proof bytes against a block they say nothing about. Checking the bytes
  // separately is the only way to reach this: a verified read is made at the block it is
  // checked against, so the client never has a proof and a mismatched anchor at once.
  const wrong = Buffer.from(head.rootHash);
  wrong[0] ^= 1;
  assert.throws(
    () =>
      verifyAccount({
        address: ELECTOR,
        trustedRootHash: wrong,
        proof: at.proof,
        state: at.value.state,
      }),
    // Every failure names its kind before its message, so a caller can tell a server
    // that did not prove its answer from a socket that dropped without matching on
    // prose. The two are not the same situation: one is a reason to stop asking this
    // server, the other is a reason to try again.
    (error) => error.message.startsWith("PROOF: "),
    "live proof bytes verified against a block they say nothing about",
  );

  // The account is bound by its own id, so the same proof must not answer for another
  // account in the same block. The proof exposes the path to the elector and prunes the
  // rest of the accounts, so the config contract is not in it to be found.
  assert.throws(
    () =>
      verifyAccount({
        address: CONFIG,
        trustedRootHash: head.rootHash,
        proof: at.proof,
        state: at.value.state,
      }),
    /proof/,
    "one account's proof answered for another",
  );

  // Outside the masterchain the shard proof is the step tying the shard to the trusted
  // block. Skipping it must be refused, not quietly treated as a masterchain read.
  assert.throws(
    () =>
      verifyAccount({
        address: BASECHAIN,
        trustedRootHash: head.rootHash,
        proof: at.proof,
        state: at.value.state,
      }),
    /shardProof is required outside the masterchain/,
    "a shard read without a shard proof was checked anyway",
  );

  // A block id read back in is checked field by field: a short hash silently padded
  // would send a read at a block the caller did not mean.
  await assert.rejects(
    client.accountAt(ELECTOR, { ...head, rootHash: head.rootHash.subarray(0, 31) }),
    /rootHash must be 32 bytes, got 31/,
    "a short root hash rejects",
  );
  await assert.rejects(
    client.accountAt(ELECTOR, { ...head, shard: "not-hex" }),
    /shard must be 16 hex digits/,
    "a shard that is not hex rejects",
  );
  // Sixteen decimal digits are sixteen hex digits too, so a shard written in decimal by
  // another library would be read as a different shard with nothing said about it.
  await assert.rejects(
    client.accountAt(ELECTOR, { ...head, shard: "9223372036854775808" }),
    /shard must be 16 hex digits/,
    "a decimal shard rejects rather than being read as hex",
  );

  // A block outside the masterchain cannot anchor a read: a shard block would leave the
  // masterchain path checking a server's proof against a server's hash.
  await assert.rejects(
    client.accountAt(ELECTOR, { ...head, workchain: 0, shard: "2000000000000000" }),
    (error) => error.message.startsWith("PROOF: the trusted block is in workchain"),
    "a block outside the masterchain is refused as an anchor",
  );

  // The freshness bound reaches JavaScript, and it is the only thing standing between a
  // caller and a genuine block from last week proved against its own signatures.
  assert.strictEqual(Config.mainnet().maxHeadAge, 600, "the default bound is readable");
  assert.strictEqual(
    Config.mainnet().withMaxHeadAge(30).maxHeadAge,
    30,
    "the bound can be tightened",
  );

  // A malformed address rejects rather than throwing synchronously or hanging.
  await assert.rejects(
    client.accountReported("not-a-real-address"),
    /address/,
    "a bad address rejects",
  );

  // A busy account can move mid-run and leave nothing to compare. One more pass settles
  // that. `null` is a skip that said why; a zero twice over is a check that has quietly
  // stopped checking anything, which must not pass for one that ran.
  let compared = await againstASecondParty(client);
  if (compared === 0) {
    compared = await againstASecondParty(client);
  }
  assert.ok(
    compared === null || compared > 0,
    "no balance was compared against a second party in two passes",
  );

  // The anchor out and back in, which is what makes a chain walk a once-per-caller cost
  // rather than a once-per-process one.
  try {
    await anchorRoundTrip(config);
  } catch (error) {
    if (error instanceof TypeError || /toncenter|HTTP/.test(error.message)) {
      console.log(`gate: skip anchor round trip (second party unreachable): ${error.message}`);
    } else {
      throw error;
    }
  }

  if (process.env.TON_NET_COLD_SYNC === "1") {
    await coldSync(config);
  } else {
    console.log("gate: skip cold sync (set TON_NET_COLD_SYNC=1 to run it)");
  }

  console.log("gate: pass");
}

// The only check here that says anything about whether the liteserver is honest.
//
// Everywhere above, the anchor came from the same server that then proved the answer,
// which shows only that the server agrees with itself. Here the anchor comes from an
// indexer running its own nodes, so a proof that roots at it was checked against a block
// a second party published. That is the shape the trust model describes: an anchor
// obtained out of band, and a read proved against it.
//
// The indexer answers about its own head while the proof covers the anchor block, so a
// balance is only comparable when the account sat still across the whole run. Reading the
// indexer before and after says whether it did. The two sides do not report the same
// logical time and cannot be compared directly: a decoded account carries the lt just
// after its last transaction, the indexer publishes the lt of the transaction itself.
//
// Returns the number of balances compared, or null if the check could not run.
async function againstASecondParty(client) {
  const state = (address) =>
    toncenter(`accountStates?address=${encodeURIComponent(address)}`).then(
      (body) => body.accounts[0],
    );

  let published;
  let before;
  try {
    // A few blocks back, so the liteserver has certainly seen it.
    published = (await toncenter("blocks?workchain=-1&limit=1&offset=5&sort=desc"))
      .blocks[0];
    before = [];
    for (const { address } of SECOND_PARTY) {
      before.push(await state(address));
    }
  } catch (error) {
    console.log(`gate: skip second-party check (${error.message})`);
    return null;
  }

  const anchor = {
    workchain: published.workchain,
    shard: published.shard,
    seqno: published.seqno,
    rootHash: Buffer.from(published.root_hash, "base64"),
    fileHash: Buffer.from(published.file_hash, "base64"),
  };

  const proved = [];
  for (const { name, address } of SECOND_PARTY) {
    try {
      proved.push(await client.accountAt(address, anchor));
    } catch (error) {
      // A server that has not caught up cannot answer at this block at all. A proof that
      // fails to check out is a different thing entirely, and fails the gate.
      if (/liteserver error/.test(error.message)) {
        console.log(`gate: skip second-party check (${error.message})`);
        return null;
      }
      throw error;
    }
    console.log(
      `${name} proved against a block toncenter published, seqno ${published.seqno}`,
    );
  }

  let compared = 0;
  for (const [i, { name, address }] of SECOND_PARTY.entries()) {
    let after;
    try {
      after = await state(address);
    } catch (error) {
      console.log(`gate: skip second-party check (${error.message})`);
      return null;
    }
    if (after.last_transaction_lt !== before[i].last_transaction_lt) {
      console.log(
        `${name} balance not compared: it transacted during the run ` +
          `(lt ${before[i].last_transaction_lt} then ${after.last_transaction_lt})`,
      );
      continue;
    }
    assert.equal(
      proved[i].value.balance,
      after.balance,
      `${name}: a proved balance disagreed with the one a second party published`,
    );
    compared += 1;
    console.log(`${name} balance matches the second party: ${after.balance} nanotons`);
  }
  return compared;
}

// Carries the anchor across the boundary in both directions.
//
// The starting block comes from the second party rather than from the liteserver being
// questioned, which is the case `connectFrom` exists for: a caller who trusts something
// else. Reaching for the latest key block also keeps this cheap, because the walk from it
// is a link or two instead of a year of them.
async function anchorRoundTrip(config) {
  const latest = await toncenter("blocks?workchain=-1&limit=1&sort=desc");
  const keyBlockSeqno = latest.blocks[0].prev_key_block_seqno;
  const found = await toncenter(`blocks?workchain=-1&seqno=${keyBlockSeqno}`);
  const block = found.blocks[0];
  const anchor = {
    workchain: -1,
    shard: "8000000000000000",
    seqno: block.seqno,
    rootHash: Buffer.from(block.root_hash, "base64"),
    fileHash: Buffer.from(block.file_hash, "base64"),
  };
  assertBlockId(anchor, "second-party key block");
  console.log(`second party names key block ${anchor.seqno}`);

  const client = await TonClient.connectFrom(config, anchor);
  assert.ok(client instanceof TonClient, "connectFrom() resolves to a TonClient");

  // Syncing again from where that left off is the short case, and the report is what
  // says so rather than a stopwatch.
  const report = await client.sync();
  assertBlockId(report.head, "synced head");
  assert.ok(report.links > 0, "a sync checks at least one link");
  assert.ok(report.links < 32, `a warm sync checked ${report.links} links`);
  console.log(`warm sync: ${report.links} links over ${report.rounds} rounds`);

  // The anchor comes back out, is a key block at or above the one handed in, and is not
  // the head: what the client keeps is a block a later chain can continue from.
  const kept = await client.anchor();
  assertBlockId(kept, "anchor");
  assert.ok(kept.seqno >= anchor.seqno, "the anchor did not go backwards");
  assert.ok(kept.seqno <= report.head.seqno, "the anchor is at or behind the head");

  // A proved read with nothing supplied: the block it rests on was derived, not given.
  const account = await client.account(ELECTOR);
  assert.equal(account.proof, undefined, "a proved read carries no loose proof");
  assertDecimal(account.value.balance, "proved balance");
  assert.ok(
    account.anchor.seqno >= kept.seqno,
    "the account was proved against a block at or past the anchor",
  );
  console.log(
    `proved the elector at ${account.anchor.seqno}: ${account.value.balance} nanotons`,
  );

  // And the round trip: the anchor JavaScript just read goes back in, and the sync that
  // follows is short because of it.
  const resumed = await TonClient.connectFrom(config, kept);
  const second = await resumed.sync();
  assert.ok(
    second.links <= report.links + 2,
    `a resumed sync checked ${second.links} links against the first walk's ${report.links}`,
  );
  console.log(`resumed from the saved anchor: ${second.links} links`);
}

// The walk the config's own block implies, which is the expensive one.
async function coldSync(config) {
  const client = await TonClient.connect(config);
  assert.equal(await client.anchor(), null, "a client trusts nothing before it syncs");
  const started = Date.now();
  const report = await client.sync();
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  assert.ok(report.links > 100, `a first sync checked only ${report.links} links`);
  assertBlockId(report.head, "cold head");
  const kept = await client.anchor();
  assertBlockId(kept, "cold anchor");
  console.log(
    `cold sync: ${report.links} links over ${report.rounds} rounds in ${elapsed}s`,
  );
}

main().catch((error) => {
  console.error("gate: fail");
  console.error(error);
  process.exit(1);
});
