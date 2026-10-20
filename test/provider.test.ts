import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, hashObject, randomHex } from "../src/core/crypto.js";
import { PAYLOAD_TYPE, strictestOutcome, type ProviderRecord, type ProviderResponse } from "../src/provider/protocol.js";
import { pae, verifyProviderResponse } from "../src/provider/dsse.js";
import { transferRequest } from "../src/provider/transfer.js";
import { RemoteCheckProvider } from "../src/provider/remote.js";
import { VerifyService, attestationProblems } from "../src/verify/incoming.js";
import { SanctionsScreen } from "../src/compliance/sanctions.js";
import { AT, incomingFixture, temp } from "./helpers.js";
function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pins = [{ provider_id: "local-checks", keyid: "active", public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString() }];
  const input = incomingFixture().input;
  const evidence = [{ id: "witness", kind: "bitcoin-transaction", data: { txid: input.witnessTxid }, sha256: hashObject({ txid: input.witnessTxid }) }];
  const request = transferRequest(input, evidence, AT * 1000);
  const record: ProviderRecord = { version: 1, provider_id: "local-checks", request_id: request.request_id, request_sha256: hashObject(request), issued_at: request.issued_at, expires_at: request.expires_at, workload: { id: "flow-risk", version: "v1", sha256: "11".repeat(32) }, model: { id: "test-fixed", mode: "fixed-rules" }, policy: { id: "v1", sha256: "22".repeat(32) }, input_scope: { evidence_ids: ["witness"], fields: ["evidence.witness"] }, result: { kind: "transfer-flow-risk", risk_band: "low", findings: [] }, execution: "software" };
  const response = (r = record): ProviderResponse => {
    const payload = Buffer.from(canonicalJson(r));
    return { result: r, evidence_envelope: { payloadType: PAYLOAD_TYPE, payload: payload.toString("base64"), signatures: [{ keyid: "active", sig: sign(null, pae(PAYLOAD_TYPE, payload), privateKey).toString("base64") }] } };
  };
  return { pins, request, record, response, evidence };
}
test("DSSE uses standard byte-length PAE and accepts standard or URL-safe base64", () => {
  assert.equal(pae("http://example.com/HelloWorld", Buffer.from("hello world")).toString(), "DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  assert.equal(pae("é", Buffer.from("é")).toString(), "DSSEv1 2 é 2 é");
  const f = fixture(); const r = f.response();
  assert.equal(verifyProviderResponse(r, f.request, f.pins, AT * 1000).record.execution, "software");
  r.evidence_envelope.payload = Buffer.from(r.evidence_envelope.payload, "base64").toString("base64url");
  r.evidence_envelope.signatures[0].sig = Buffer.from(r.evidence_envelope.signatures[0].sig, "base64").toString("base64url");
  assert.equal(verifyProviderResponse(r, f.request, f.pins, AT * 1000).record.provider_id, "local-checks");
});
test("provider rejects foreign keys, altered unsigned result, payload type and request replay", () => {
  const f = fixture();
  assert.throws(() => verifyProviderResponse(f.response(), f.request, fixture().pins, AT * 1000), /trusted provider key/);
  const altered = f.response(); altered.result = { ...altered.result, provider_id: "attacker" };
  assert.throws(() => verifyProviderResponse(altered, f.request, f.pins, AT * 1000), /unsigned result/);
  const type = f.response(); type.evidence_envelope.payloadType = "application/json";
  assert.throws(() => verifyProviderResponse(type, f.request, f.pins, AT * 1000), /payload type/);
  assert.throws(() => verifyProviderResponse(f.response(), { ...f.request, request_id: randomHex(32) }, f.pins, AT * 1000), /another request/);
});
test("even signed hardware labels, ungrounded findings, excessive scope and expired records refuse", () => {
  const f = fixture();
  for (const change of [
    { execution: "tee:aws-nitro" },
    { provider_id: "other-signer" },
    { input_scope: { evidence_ids: ["secret"], fields: [] } },
    { result: { kind: "transfer-flow-risk", risk_band: "high", findings: [{ code: "SUSPECT", evidence_ids: ["invented"] }] } },
    { expires_at: new Date(AT * 1000).toISOString() },
    { input_scope: { evidence_ids: ["witness"], fields: ["wallet.seed"] } },
    { result: { ...f.record.result, debug_private: "synthetic-private-address" } },
    { result: { kind: "transfer-flow-risk", risk_band: "review", findings: [{ code: "REVIEW", evidence_ids: ["witness"], private_detail: "synthetic-private-match" }] } },
  ]) assert.throws(() => verifyProviderResponse(f.response({ ...f.record, ...change } as ProviderRecord), f.request, f.pins, AT * 1000));
});
test("folding never relaxes a local refusal", () => {
  assert.equal(strictestOutcome("flagged", "clear"), "flagged");
  assert.equal(strictestOutcome("error", "clear"), "error");
  assert.equal(strictestOutcome("clear", "flagged"), "flagged");
});
test("remote client authenticates, stores private envelope, and refuses replay after restart", async () => {
  const f = fixture(); const dir = temp(); const token = randomHex(32);
  const server = createServer((req, res) => { assert.equal(req.headers.authorization, `Bearer ${token}`); res.setHeader("content-type", "application/json"); res.end(canonicalJson(f.response())); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const options = { url: `http://127.0.0.1:${port}/checks`, token, pins: f.pins, evidenceDir: dir, now: () => AT * 1000 };
  try {
    const result = await new RemoteCheckProvider(options).check(f.request);
    assert.equal(statSync(result.evidence_file).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(result.evidence_file, "utf8")).request.request_id, f.request.request_id);
    await assert.rejects(new RemoteCheckProvider(options).check(f.request), /EEXIST/);
    assert.throws(() => new RemoteCheckProvider({ ...options, url: "http://example.test/check" }), /HTTPS/);
    assert.throws(() => new RemoteCheckProvider({ ...options, url: `http://127.0.0.1:${port}/?token=secret` }), /query/);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
test("Verify keeps local flagged results, binds provider digest, and fails closed on provider outage", async () => {
  for (const broken of [false, true]) {
    const f = incomingFixture({ flagged: true });
    const service = new VerifyService({ key: f.key, network: "utexo-testnet", sanctions: new SanctionsScreen("fixtures/sanctions"), flagged: f.flags.provider, log: f.log, historyDir: join(f.dir, "provider-history"), now: () => AT, providerEvidence: async () => [], provider: { check: async request => {
      if (broken) throw new Error("private endpoint and token must never be disclosed");
      const wire = fixture();
      return { record: { ...wire.record, request_id: request.request_id, request_sha256: hashObject(request) }, evidence_sha256: "55".repeat(32), evidence_file: "/private/local" };
    } } });
    const a = await service.verifyIncoming(f.input);
    assert.equal(a.overall, broken ? "error" : "flagged");
    assert.deepEqual(attestationProblems(a, { checkerPk: f.key.pubkey, flaggedIssuerKeys: [f.flags.issuer.pubkey], now: AT }), []);
    assert(!canonicalJson(a).includes("/private/local"));
    assert(!canonicalJson(a).includes("private endpoint"));
    if (!broken) assert.equal(a.provider?.evidence_sha256, "55".repeat(32));
  }
});
