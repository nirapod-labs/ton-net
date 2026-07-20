// Gate test: exercise the whole binding from Node against live mainnet.
//
// It proves the async design across the FFI boundary: the class factory returns a real
// Promise, the reads resolve to the documented shapes, and a bad address rejects. It
// reaches the network, so it runs in the network CI job, not the hermetic one.

import assert from "node:assert/strict";
import binding from "./index.js";

const { Config, TonClient } = binding;

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

  assert.equal(info.value.workchain, -1, "masterchain workchain");
  assert.equal(info.value.shard, "8000000000000000", "masterchain shard as u64 hex");
  assert.equal(typeof info.value.seqno, "number", "seqno is a number");
  assert.ok(info.value.seqno > 0, "seqno is live");
  assert.ok(
    Buffer.isBuffer(info.value.rootHash) && info.value.rootHash.length === 32,
    "rootHash is a 32-byte Buffer",
  );
  assert.ok(
    Buffer.isBuffer(info.value.fileHash) && info.value.fileHash.length === 32,
    "fileHash is a 32-byte Buffer",
  );
  assert.ok(Buffer.isBuffer(info.proof), "proof is a Buffer");
  console.log(`masterchain seqno ${info.value.seqno}, shard ${info.value.shard}`);

  // The elector is a system contract that is always active on mainnet.
  const elector =
    "-1:3333333333333333333333333333333333333333333333333333333333333333";
  const account = await client.account(elector);
  assert.equal(account.value.workchain, -1, "account block workchain");
  assert.equal(typeof account.value.shard, "string", "shard is a string");
  assert.ok(
    Buffer.isBuffer(account.value.state) && account.value.state.length > 0,
    "the elector has a nonempty state Buffer",
  );
  console.log(`elector state bytes ${account.value.state.length}`);

  // A malformed address rejects rather than throwing synchronously or hanging.
  await assert.rejects(
    client.account("not-a-real-address"),
    /address/,
    "a bad address rejects",
  );

  console.log("gate: pass");
}

main().catch((error) => {
  console.error("gate: fail");
  console.error(error);
  process.exit(1);
});
