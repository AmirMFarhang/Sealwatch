// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Transaction } from "bitcoinjs-lib";
import { decodeWitness } from "../src/verify/witness.js";
import { incomingFixture } from "./helpers.js";

// Public script/address from the first real RGB witness's input prevout.
// The transactions below are synthetic; no wallet or chain state is needed.
const taprootScript = Buffer.from(
  "51206673db9064fe0283371c0e255098c4076c65d4a70727c0ec678b9676e2c179a8",
  "hex",
);
const taprootAddress = "tb1pveeahyrylcpgxdcupcj4pxxyqakxt498qunupmr83wt8dckp0x5qvnh8pd";
function evidence(script = taprootScript) {
  const parent = new Transaction();
  parent.addInput(Buffer.alloc(32), 0xffffffff);
  parent.addOutput(script, 10000n);
  const tx = new Transaction();
  tx.addInput(Buffer.from(parent.getId(), "hex").reverse(), 0);
  tx.addOutput(taprootScript, 9000n);
  tx.addOutput(Buffer.from("6a", "hex"), 0n);
  return {
    witnessTxid: tx.getId(),
    witnessRawHex: tx.toHex(),
    previousTransactions: { [parent.getId()]: parent.toHex() },
  };
}

for (const network of ["utexo-testnet", "mutinynet"] as const) {
  test(`Taproot prevout and output decode without global ECC initialization: ${network}`, () => {
    const decoded = decodeWitness(evidence(), network);
    assert.deepEqual(decoded.senderAddresses, [taprootAddress]);
    assert.deepEqual(decoded.outputAddresses, [taprootAddress]);
    assert.equal(decoded.inputOutpoints.length, 1);
  });
}

test("actual Taproot script shape passes incoming verification", async () => {
  const fixture = incomingFixture();
  const attestation = await fixture.service.verifyIncoming({ ...fixture.input, ...evidence() });
  assert.equal(attestation.overall, "clear");
  assert.equal(attestation.checks.sanctions.status, "clear");
  assert.equal(attestation.checks.flaggedL1.status, "clear");
});

test("malformed Taproot sender scripts still refuse incomplete screening", () => {
  for (const script of [taprootScript.subarray(0, 33), Buffer.concat([taprootScript, Buffer.from([0])]), Buffer.from("5121" + "00".repeat(32), "hex")]) {
    assert.throws(() => decodeWitness(evidence(script), "utexo-testnet"), /sender script/);
  }
});
