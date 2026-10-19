// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { unlinkSync } from "node:fs";
import { ReceiverQuarantine } from "../src/wallet/quarantine.js";
import { PolicyGate } from "../src/governance/gate.js";
import { AT, gateFixture, incomingFixture } from "./helpers.js";
test("flagged and error incoming transfers are persisted in receiver-local asset quarantine", async () => {
  for (const kind of ["flagged", "error"]) {
    const f = incomingFixture({ flagged: kind === "flagged" });
    const input =
      kind === "error" ? { ...f.input, previousTransactions: {} } : f.input;
    await f.service.verifyIncoming(input);
    assert.throws(
      () =>
        f.service.quarantine.assertSpendable(
          input.network,
          input.receiverWalletId,
          input.assetId,
        ),
      /QUARANTINED/,
    );
    const restarted = new ReceiverQuarantine(
      f.service.quarantine.file,
      f.key,
      f.log,
    );
    assert.throws(
      () =>
        restarted.assertSpendable(
          input.network,
          input.receiverWalletId,
          input.assetId,
        ),
      /QUARANTINED/,
    );
  }
});
test("clear receive cannot automatically unfreeze previously quarantined asset", async () => {
  const f = incomingFixture({ sanctioned: true });
  await f.service.verifyIncoming(f.input);
  f.service.quarantine.record(
    f.input.network,
    f.input.receiverWalletId,
    f.input.assetId,
    {
      attestationHash: "clear-later",
      witnessTxid: f.input.witnessTxid,
      overall: "clear",
      at: AT,
    },
  );
  assert.throws(
    () =>
      f.service.quarantine.assertSpendable(
        f.input.network,
        f.input.receiverWalletId,
        f.input.assetId,
      ),
    /QUARANTINED/,
  );
});
test("clear receives remain spendable and quarantine is scoped to network/wallet/asset", async () => {
  const f = incomingFixture();
  await f.service.verifyIncoming(f.input);
  f.service.quarantine.assertSpendable(
    f.input.network,
    f.input.receiverWalletId,
    f.input.assetId,
  );
  f.service.quarantine.record(
    f.input.network,
    f.input.receiverWalletId,
    "different-asset",
    {
      attestationHash: "flagged-other",
      witnessTxid: f.input.witnessTxid,
      overall: "flagged",
      at: AT,
    },
  );
  f.service.quarantine.assertSpendable(
    f.input.network,
    f.input.receiverWalletId,
    f.input.assetId,
  );
});
test("enrolled receiver gate blocks new authorization and pre-issued token after incoming quarantine", () => {
  const f = gateFixture();
  const quarantine = new ReceiverQuarantine(
    join(f.dir, "receiver-quarantine.json"),
    f.gateKey,
    f.log,
  );
  const gate = new PolicyGate({ ...f.gateOptions, quarantine });
  gate.install(f.policy);
  const request = f.request();
  const decision = gate.authorize(request);
  assert(decision.token);
  quarantine.record("utexo-testnet", "A-unit-only", f.policy.assetId, {
    attestationHash: "flagged-receive",
    witnessTxid: "ab".repeat(32),
    overall: "flagged",
    at: AT,
  });
  assert(
    gate
      .authorize(f.request())
      .why.includes("RECEIVER_ASSET_QUARANTINED_FLAGGED"),
  );
  assert.throws(
    () => gate.consume(decision.token!, request.plan, request.preview),
    /QUARANTINED/,
  );
});
test("quarantine deletion alongside signed receive history fails closed", async () => {
  const f = incomingFixture({ flagged: true });
  await f.service.verifyIncoming(f.input);
  unlinkSync(f.service.quarantine.file);
  assert.throws(
    () =>
      f.service.quarantine.assertSpendable(
        f.input.network,
        f.input.receiverWalletId,
        f.input.assetId,
      ),
    /state missing/,
  );
});
