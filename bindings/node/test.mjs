// Gate test: exercise the whole binding from Node against live mainnet.
//
// It proves the async design across the FFI boundary: the class factory returns a real
// Promise, the reads resolve to the documented shapes, a verified read proves what it
// returns, a proof checked against the wrong block is refused, and a bad input rejects.
// It reaches the network, so it runs in the network CI job, not the hermetic one.

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
  const reported = await client.account(ELECTOR);
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
    const verified = await client.accountVerified(address, head);
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
    /proof/,
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
    client.accountVerified(ELECTOR, { ...head, rootHash: head.rootHash.subarray(0, 31) }),
    /rootHash must be 32 bytes, got 31/,
    "a short root hash rejects",
  );
  await assert.rejects(
    client.accountVerified(ELECTOR, { ...head, shard: "not-hex" }),
    /shard is not a hex u64/,
    "a shard that is not hex rejects",
  );

  // A malformed address rejects rather than throwing synchronously or hanging.
  await assert.rejects(
    client.account("not-a-real-address"),
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
      proved.push(await client.accountVerified(address, anchor));
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

main().catch((error) => {
  console.error("gate: fail");
  console.error(error);
  process.exit(1);
});
