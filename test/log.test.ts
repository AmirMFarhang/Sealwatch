// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { hashObject, signObject } from "../src/core/crypto.js";
import { verifyLog } from "../src/governance/log.js";
import { gateFixture, key } from "./helpers.js";
function logged() {
  const f = gateFixture();
  f.gate.install(f.policy);
  f.gate.authorize(f.request());
  return f;
}
test("log hash chain and node signatures verify against explicitly trusted key", () => {
  const f = logged();
  assert.deepEqual(f.log.verify(), []);
  assert(verifyLog(f.log.entries(), key().pubkey).length);
});
test("altered log content breaks hash chain and signatures, append refuses corruption", () => {
  const f = logged();
  const es = f.log.entries();
  es[0].result = "tampered";
  writeFileSync(f.log.file, es.map((e) => JSON.stringify(e)).join("\n") + "\n");
  assert(f.log.verify().length);
  assert.throws(() => f.log.append("test", "should-refuse", {}), /broken log/);
});
test("deleting and reordering log entries is detected", () => {
  for (const mutate of [
    (es: any[]) => es.reverse(),
    (es: any[]) => es.slice(1),
  ]) {
    const f = logged();
    const es = mutate(f.log.entries());
    writeFileSync(
      f.log.file,
      es.map((e: any) => JSON.stringify(e)).join("\n") + "\n",
    );
    assert(f.log.verify().length);
  }
});
test("suffix truncation detected against durable signed checkpoint", () => {
  const f = logged();
  const es = f.log.entries().slice(0, 1);
  writeFileSync(f.log.file, es.map((e) => JSON.stringify(e)).join("\n") + "\n");
  assert(f.log.verify().some((p) => p.includes("checkpoint")));
});
test("missing log and deleted checkpoint each fail closed when counterpart remains", () => {
  const f = logged();
  unlinkSync(f.log.file);
  assert(f.log.verify().length);
  const g = logged();
  unlinkSync(g.log.checkpointFile);
  assert(g.log.verify().length);
});
test("attacker recomputing full chain with their own key remains untrusted", () => {
  const f = logged();
  const attacker = key();
  let previous: string | null = null;
  const es = f.log.entries().map((e) => {
    const { hash, sig, ...body } = e;
    const b = { ...body, nodePk: attacker.pubkey, prevHash: previous };
    const result = signObject(
      { ...b, hash: hashObject(b) },
      attacker.secretKey,
    );
    previous = result.hash;
    return result;
  });
  writeFileSync(f.log.file, es.map((e) => JSON.stringify(e)).join("\n") + "\n");
  assert(f.log.verify().some((p) => p.includes("signature")));
});
