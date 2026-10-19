// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { copyFileSync, mkdirSync } from "node:fs";
import { hashObject, signObject, sha256Hex } from "../src/core/crypto.js";
import {
  SanctionsScreen,
  BUNDLED_SANCTIONS_MANIFEST_SHA256,
} from "../src/compliance/sanctions.js";
import {
  LocalFileFlaggedListProvider,
  UtexoApiFlaggedListProvider,
} from "../src/compliance/flagged.js";
import { attestationProblems } from "../src/verify/incoming.js";
import { AT, incomingFixture, key, flaggedFixture, temp } from "./helpers.js";
const trust = (f: ReturnType<typeof incomingFixture>) => ({
  checkerPk: f.key.pubkey,
  flaggedIssuerKeys: [f.flags.issuer.pubkey],
  now: AT,
});
test("clear attestation checks decoded witness prevouts, carries signed list, and verifies offline with pinned trust", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming({ ...f.input, senderAddresses: [] });
  assert.equal(a.overall, "clear");
  assert.equal(a.checks.rgbAncestry.status, "designed");
  assert.deepEqual(attestationProblems(a, trust(f)), []);
  assert.deepEqual(f.log.verify(), []);
  assert.equal(
    f.log.entries().filter((e) => e.kind === "incoming-verification").length,
    1,
  );
});
test("sanctions hit derives sender address even when caller supplies empty sender list", async () => {
  const f = incomingFixture({ sanctioned: true });
  const a = await f.service.verifyIncoming({ ...f.input, senderAddresses: [] });
  assert.equal(a.overall, "flagged");
  assert.equal(a.checks.sanctions.code, "SANCTIONS_HIT");
});
test("spoofed sender address causes error instead of clearing incoming transfer", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming({
    ...f.input,
    senderAddresses: ["tb1spoofed"],
  });
  assert.equal(a.overall, "error");
});
test("flagged L1 matches an independently decoded witness input", async () => {
  const f = incomingFixture({ flagged: true });
  const a = await f.service.verifyIncoming(f.input);
  assert.equal(a.overall, "flagged");
  assert.equal(a.checks.flaggedL1.code, "FLAGGED_WITNESS_INPUT");
});
test("receiver-local counterparties are screened as additional scope", async () => {
  const f = incomingFixture();
  const first = "1AJbsFZ64EpEfS5UAjAfcUG8pH8Jn3rn1F";
  const list = readFileSync(
    resolve("fixtures/sanctions/ofac-sdn-xbt-20261001.txt"),
    "utf8",
  )
    .trim()
    .split("\n")[0];
  const a = await f.service.verifyIncoming({
    ...f.input,
    counterpartyAddresses: [list],
  });
  assert.equal(a.overall, "flagged");
});
test("wrong witness txid errors, and cannot be used with a fabricated clear input list", async () => {
  const f = incomingFixture({ flagged: true });
  const a = await f.service.verifyIncoming({
    ...f.input,
    witnessTxid: "ab".repeat(32),
  });
  assert.equal(a.overall, "error");
});
test("missing prevout and wrong prevout bytes refuse incomplete sender screening", async () => {
  for (const previousTransactions of [{}, { ["ff".repeat(32)]: "00" }]) {
    const f = incomingFixture();
    const a = await f.service.verifyIncoming({
      ...f.input,
      previousTransactions,
    });
    assert.equal(a.overall, "error");
  }
});
test("attestation never contains raw history, matched addresses or witness input outpoints", async () => {
  const f = incomingFixture({ sanctioned: true, flagged: true });
  const a = await f.service.verifyIncoming(f.input);
  const wire = JSON.stringify(a);
  assert(!wire.includes(f.vector.senderAddress));
  assert(!wire.includes(f.input.witnessRawHex));
  assert(!wire.includes(f.vector.outpoint));
  const file = join(f.dir, "history", readdirSync(join(f.dir, "history"))[0]);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert(readFileSync(file, "utf8").includes(f.input.witnessRawHex));
});
test("tampered attestation fails signature and semantic checks", async () => {
  const f = incomingFixture({ flagged: true });
  const a = await f.service.verifyIncoming(f.input);
  a.overall = "clear";
  assert(attestationProblems(a, trust(f)).length > 0);
});
test("valid signature from an unknown checker is not trusted", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  const attacker = key();
  const forged = signObject(
    { ...a, checkerPk: attacker.pubkey },
    attacker.secretKey,
  );
  assert(
    attestationProblems(forged, trust(f)).some((p) => p.includes("checker")),
  );
});
test("flagged-list issuer trust is independent from checker signature", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  assert(
    attestationProblems(a, {
      ...trust(f),
      flaggedIssuerKeys: [key().pubkey],
    }).some((p) => p.includes("issuer")),
  );
});
test("attestation wrong network, future time and stale age refuse", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  assert(attestationProblems(a, { ...trust(f), network: "mutinynet" }).length);
  assert(attestationProblems(a, { ...trust(f), now: AT - 1 }).length);
  assert(
    attestationProblems(a, { ...trust(f), now: AT + 60, maxAgeSeconds: 30 })
      .length,
  );
});
test("tampered flagged-list bytes refused even with valid unchanged manifest", async () => {
  const f = incomingFixture();
  writeFileSync(join(f.dir, "flags/flagged-outpoints.json"), "{}");
  await assert.rejects(f.service.verifyIncoming(f.input), /SHA-256/);
});
test("tampered signed manifest refused after attacker recomputes list hash", async () => {
  const f = incomingFixture();
  const manifest = { ...f.flags.manifest, sha256: sha256Hex("{}") };
  writeFileSync(join(f.dir, "flags/flagged-outpoints.json"), "{}");
  writeFileSync(join(f.dir, "flags/manifest.json"), JSON.stringify(manifest));
  await assert.rejects(f.service.verifyIncoming(f.input), /signature/);
});
test("self-signed foreign flagged issuer is refused", async () => {
  const f = flaggedFixture(temp());
  const provider = new LocalFileFlaggedListProvider(f.provider.dir, [
    key().pubkey,
  ]);
  await assert.rejects(provider.load("utexo-testnet", AT), /untrusted/);
});
test("signed flagged lists refuse wrong network and expired or future validity", async () => {
  const f = flaggedFixture(temp());
  await assert.rejects(f.provider.load("mutinynet", AT), /network/);
  await assert.rejects(f.provider.load("utexo-testnet", AT + 3600), /valid/);
  await assert.rejects(f.provider.load("utexo-testnet", AT - 101), /valid/);
});
test("malformed and duplicate outpoints refused after legitimate issuer signs", async () => {
  for (const outpoints of [
    ["not-an-outpoint"],
    ["ab".repeat(32) + ":0", "ab".repeat(32) + ":0"],
  ]) {
    const f = flaggedFixture(temp(), key(), outpoints);
    await assert.rejects(f.provider.load("utexo-testnet", AT), /outpoints/);
  }
});
test("Utexo API provider is explicit fail-closed stub", async () => {
  await assert.rejects(
    new UtexoApiFlaggedListProvider().load("utexo-testnet", AT),
    /STUB/,
  );
});
test("sanctions manifests and data files have independent trusted hash pins", () => {
  const f = temp();
  const orig = resolve("fixtures/sanctions");
  for (const name of readdirSync(orig))
    copyFileSync(join(orig, name), join(f, name));
  writeFileSync(join(f, "ofac-sdn-xbt-20261001.txt"), "tampered");
  assert.throws(() => new SanctionsScreen(f), /hash/);
  const manifest = JSON.parse(readFileSync(join(f, "manifest.json"), "utf8"));
  manifest.lists[0].sha256 = sha256Hex("tampered");
  writeFileSync(join(f, "manifest.json"), JSON.stringify(manifest));
  assert.throws(() => new SanctionsScreen(f), /trusted SHA/);
});
test("incoming wrong configured network and future received time refuse", async () => {
  const f = incomingFixture();
  await assert.rejects(
    f.service.verifyIncoming({ ...f.input, network: "mutinynet" }),
    /network/,
  );
  await assert.rejects(
    f.service.verifyIncoming({ ...f.input, receivedAt: AT + 1 }),
    /future/,
  );
});
