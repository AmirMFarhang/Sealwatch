import test from "node:test";
import assert from "node:assert/strict";
import { createAuditPack, verifyAuditPack } from "../src/audit/pack.js";
import { encodeZip, decodeZip } from "../src/audit/zip.js";
import { RECEIVER_POLICY } from "../src/verify/policy.js";
import { canonicalJson, sha256Hex, signObject } from "../src/core/crypto.js";
import { AT, incomingFixture, key } from "./helpers.js";
async function packFixture() {
  const f = incomingFixture(); const a = await f.service.verifyIncoming(f.input);
  const trust = { checkerPk: f.key.pubkey, flaggedIssuerKeys: [f.flags.issuer.pubkey], logPk: f.key.pubkey, providerPins: [], now: AT };
  const pack = createAuditPack({ attestation: a, entries: f.log.entries(), checkpoint: f.log.checkpoint()!, policy: RECEIVER_POLICY }, f.key, trust);
  return { ...f, a, trust, pack };
}
test("audit pack verifies signed manifest, attestation, checkpoint, decision link and exact policy", async () => {
  const f = await packFixture();
  assert.deepEqual(verifyAuditPack(f.pack, f.trust), []);
  assert.equal(decodeZip(f.pack).size, 5);
  assert.match(Buffer.from(f.pack).subarray(0, 4).toString("hex"), /^504b0304$/);
  assert.equal(f.a.verificationPolicy?.version, 1);
});
test("audit rejects foreign trust and corrupted ZIP body/directory", async () => {
  const f = await packFixture();
  assert(verifyAuditPack(f.pack, { ...f.trust, checkerPk: key().pubkey }).length);
  for (const index of [45, f.pack.length - 6]) {
    const altered = Buffer.from(f.pack); altered[index] ^= 1;
    assert(verifyAuditPack(altered, f.trust).length);
  }
});
test("rewritten file with valid ZIP checksum still fails manifest hash", async () => {
  const f = await packFixture(), files = decodeZip(f.pack);
  files.set("policy.json", Buffer.from(canonicalJson({ ...RECEIVER_POLICY, version: 9 })));
  assert.match(verifyAuditPack(encodeZip(files), f.trust).join(), /hash/);
});
test("even checker-resigned manifest cannot change decision-bound policy version", async () => {
  const f = await packFixture(), files = decodeZip(f.pack);
  files.set("policy.json", Buffer.from(canonicalJson({ ...RECEIVER_POLICY, version: 9 })));
  const m = JSON.parse(files.get("manifest.json")!.toString());
  m.files = m.files.map((v: any) => v.name === "policy.json" ? { ...v, sha256: sha256Hex(files.get(v.name)!), bytes: files.get(v.name)!.length } : v);
  files.set("manifest.json", Buffer.from(canonicalJson(signObject(m, f.key.secretKey))));
  assert.match(verifyAuditPack(encodeZip(files), f.trust).join(), /policy version/);
});
test("pack creation refuses a mismatched checkpoint, missing decision, or wrong policy", async () => {
  const f = await packFixture();
  const base = { attestation: f.a, entries: f.log.entries(), checkpoint: f.log.checkpoint()!, policy: RECEIVER_POLICY };
  assert.throws(() => createAuditPack({ ...base, entries: [] }, f.key, f.trust), /decision absent|inconsistent/);
  assert.throws(() => createAuditPack({ ...base, policy: { ...RECEIVER_POLICY, version: 2 } }, f.key, f.trust), /policy/);
  assert.throws(() => createAuditPack({ ...base, checkpoint: { ...base.checkpoint, count: 0 } }, f.key, f.trust), /inconsistent/);
});
test("ZIP codec rejects unsafe paths, oversized files and unsupported archive forms", () => {
  assert.throws(() => encodeZip(new Map([["../secret.json", Buffer.from("x")]])), /filename/);
  assert.throws(() => encodeZip(new Map([["huge.json", Buffer.alloc(4 * 1024 * 1024 + 1)]])), /large/);
  const bytes = encodeZip(new Map([["test.json", Buffer.from("{}")]]));
  bytes.writeUInt16LE(8, 8); assert.throws(() => decodeZip(bytes), /stored/);
});
