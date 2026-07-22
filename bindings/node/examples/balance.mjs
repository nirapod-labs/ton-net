// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Reads one account's balance, proved rather than taken on a server's word.
//
//   node examples/balance.mjs
//
// The walk this does once is the expensive part; resume.mjs shows how not to pay for
// it twice.

import { Config, TonClient } from "ton-net";

const client = await TonClient.connect(Config.mainnet());

// Walks from the key block the configuration pins to the current head, checking a
// validator signature set at every link. Nothing below is believed without it.
const report = await client.sync();
console.log(
  `proved ${report.links} links over ${report.rounds} replies, reaching block ${report.head.seqno}`,
);

// The elector, which every TON network has and which is always active.
const elector =
  "-1:3333333333333333333333333333333333333333333333333333333333333333";
const account = await client.account(elector);

// `account()` returns only what the walk proved. A read that fails verification throws
// rather than handing back something unchecked, so there is no unverified branch here
// to forget to handle.
console.log("balance", account.value.balance);
console.log("status ", account.value.status);
console.log("proved against block", account.anchor.seqno);
