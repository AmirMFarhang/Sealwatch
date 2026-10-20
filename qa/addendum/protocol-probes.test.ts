// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
// Independent addendum probes. All authorities and evidence are synthetic and local.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson, hashObject, randomHex, randomKeyPair, signObject } from '../../src/core/crypto.js';
import { PAYLOAD_TYPE } from '../../src/provider/protocol.js';
import { pae, verifyProviderResponse } from '../../src/provider/dsse.js';
import { strictestOutcome } from '../../src/provider/protocol.js';
import { signFlaggedManifest } from '../../src/compliance/flagged.js';
import { createAuditPack, verifyAuditPack } from '../../src/audit/pack.js';
import { RECEIVER_POLICY, RECEIVER_POLICY_REF } from '../../src/verify/policy.js';
import { encodeZip, decodeZip } from '../../src/audit/zip.js';

const NOW = Date.parse('2026-10-20T12:00:00Z');
function wire(at = NOW) {
 const keys = generateKeyPairSync('ed25519');
 const witness = '00'.repeat(32), asset = 'rgb:independent-qa';
 const evidence = { id: 'witness', kind: 'bitcoin-transaction', data: { txid: witness } };
 const request: any = { version: 1, request_id: randomHex(32), issued_at: new Date(at - 1000).toISOString(), expires_at: new Date(at + 60_000).toISOString(), check: 'transfer-flow-risk', network: 'utexo-testnet', subject: { witness_txid: witness, asset_id: asset }, evidence: [{ ...evidence, sha256: hashObject(evidence.data) }], context: { scope: 'bounded' } };
 const record: any = { version: 1, provider_id: 'independent-qa', request_id: request.request_id, request_sha256: hashObject(request), issued_at: new Date(at).toISOString(), expires_at: request.expires_at, workload: { id: 'flow-risk', version: 'v1', sha256: '11'.repeat(32) }, model: { id: 'unit-fixed', mode: 'fixed-rules' }, policy: { id: 'unit-v1', sha256: '22'.repeat(32) }, input_scope: { evidence_ids: ['witness'], fields: ['evidence.witness', 'subject.witness_txid', 'context.scope'] }, result: { kind: 'transfer-flow-risk', risk_band: 'low', findings: [] }, execution: 'software' };
 const pins = [{ provider_id: record.provider_id, keyid: 'qa', public_key_pem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
 const signed = (r: any = record, bytes = Buffer.from(canonicalJson(r))) => ({ result: r, evidence_envelope: { payloadType: PAYLOAD_TYPE, payload: bytes.toString('base64'), signatures: [{ keyid: 'qa', sig: sign(null, pae(PAYLOAD_TYPE, bytes), keys.privateKey).toString('base64') }] } });
 return { keys, request, record, pins, signed, verify: (r: any) => verifyProviderResponse(signed(r), request, pins, at) };
}
test('independent DSSE: all caller context and nonce are covered by the exact request hash', () => {
 const f = wire(); assert.equal(f.verify(f.record).record.provider_id, f.record.provider_id);
 for (const mutate of [(r: any) => { r.request_id = randomHex(32); }, (r: any) => { r.subject.asset_id += '-changed'; }, (r: any) => { r.context.scope = 'different'; }, (r: any) => { r.network = 'mutinynet'; }]) {
  const r = structuredClone(f.request); mutate(r);
  assert.throws(() => verifyProviderResponse(f.signed(), r, f.pins, NOW), /another request/);
 }
});
test('independent DSSE: valid signature cannot establish an unpinned provider identity or unsigned result', () => {
 const f = wire(); const other = wire();
 assert.throws(() => verifyProviderResponse(f.signed(), f.request, other.pins, NOW), /trusted provider key/);
 assert.throws(() => f.verify({ ...f.record, provider_id: 'other-provider' }), /identity/);
 const response = f.signed(); response.result = { ...f.record, execution: 'tee:aws-nitro' };
 assert.throws(() => verifyProviderResponse(response, f.request, f.pins, NOW), /unsigned result/);
});
test('independent privacy regression: signed extra result and finding fields are refused', () => {
 const f = wire();
 for (const mutate of [(r: any) => { r.result.debug_private = { raw_match: 'synthetic-private-match' }; }, (r: any) => { r.result.findings = [{ code: 'REVIEW', evidence_ids: ['witness'], raw_match: 'synthetic-private-match' }]; }]) {
  const record = structuredClone(f.record); mutate(record);
  assert.throws(() => f.verify(record), /unsupported fields/);
 }
});
test('independent scope regression: signed scope fields and finding IDs must have been supplied', () => {
 const f = wire();
 for (const fields of [['wallet.seed'], ['env.UNSUPPLIED'], ['evidence.not-supplied'], ['subject.not-supplied'], ['context.not-supplied']]) assert.throws(() => f.verify({ ...f.record, input_scope: { evidence_ids: ['witness'], fields } }), /scope/);
 assert.throws(() => f.verify({ ...f.record, result: { kind: 'transfer-flow-risk', risk_band: 'review', findings: [{ code: 'REVIEW', evidence_ids: ['invented'] }] } }), /ungrounded/);
});
test('independent canonical-byte regression: signed invalid UTF-8 and noncanonical JSON cannot alias canonical payload', () => {
 const f = wire(), record = { ...f.record, model: { ...f.record.model, description: 'é' } };
 const payload = Buffer.from(canonicalJson(record)); payload[payload.indexOf(Buffer.from('é'))] = 255;
 const lossy = JSON.parse(payload.toString('utf8'));
 assert(!payload.equals(Buffer.from(canonicalJson(lossy))));
 assert.throws(() => verifyProviderResponse(f.signed(lossy, payload), f.request, f.pins, NOW), /encoded data|UTF|encoding/i);
 assert.throws(() => verifyProviderResponse(f.signed(f.record, Buffer.from(JSON.stringify(f.record, null, 2))), f.request, f.pins, NOW), /canonical/);
});
test('independent validity: expired/future records and all hardware labels refuse even with trusted signatures', () => {
 const f = wire();
 for (const patch of [{ issued_at: new Date(NOW + 1000).toISOString() }, { expires_at: new Date(NOW).toISOString() }, ...['tee:aws-nitro', 'tee:intel-tdx', 'tee:amd-sev-snp', 'device:apple-app-attest', 'device:android-key-attestation'].map(execution => ({ execution }))]) assert.throws(() => f.verify({ ...f.record, ...patch }));
});
test('independent strictest fold covers every local/provider pair', () => {
 const ranks: any = { clear: 0, flagged: 1, error: 2 };
 for (const local of ['clear', 'flagged', 'error'] as const) for (const provider of ['clear', 'flagged', 'error'] as const) assert.equal(ranks[strictestOutcome(local, provider)], Math.max(ranks[local], ranks[provider]));
});

function packFixture(options: { expired?: boolean; wrongTransfer?: boolean } = {}) {
 const f = wire(options.expired ? NOW - 120_000 : NOW), checker = randomKeyPair(), issuer = randomKeyPair();
 const at = Math.floor(NOW / 1000);
 const snapshot: any = { v: 1, domain: 'trust-flagged-outpoints-v1', id: 'qa-empty', version: '1', network: 'utexo-testnet', testOnly: true, outpoints: [] };
 const manifest = signFlaggedManifest(snapshot, 'list.json', Buffer.from(canonicalJson(snapshot)), issuer, at - 600, at + 600);
 const provider = { request: f.request, ...f.signed() };
 const attestation: any = signObject({ v: 2, domain: 'trust-incoming-attestation-v2', execution: 'software', verificationPolicy: RECEIVER_POLICY_REF, provider: { provider_id: f.record.provider_id, evidence_sha256: hashObject(provider.evidence_envelope), provider_result: f.record.result, execution: 'software' }, network: 'utexo-testnet', assetId: f.request.subject.asset_id, witnessTxid: options.wrongTransfer ? 'ff'.repeat(32) : f.request.subject.witness_txid, checks: { sanctions: { status: 'clear', scope: 'qa', code: 'CLEAR' }, flaggedL1: { status: 'clear', scope: 'qa', code: 'CLEAR' }, provider: { status: 'clear', scope: 'qa', code: 'LOW' }, rgbAncestry: { status: 'designed', scope: 'qa', code: 'DESIGNED' } }, lists: [{ id: manifest.listId, version: manifest.version, sha256: manifest.sha256, testOnly: manifest.testOnly }], flaggedManifest: manifest, overall: 'clear', time: at, checkerPk: checker.pubkey }, checker.secretKey);
 const body: any = { v: 1, domain: 'trust-decision-log-v1', seq: 0, prevHash: null, at, kind: 'incoming-verification', actionId: null, result: 'clear', detail: { attestationHash: hashObject(attestation) }, nodePk: checker.pubkey };
 const entry = signObject({ ...body, hash: hashObject(body) }, checker.secretKey);
 const checkpoint: any = signObject({ domain: 'trust-log-checkpoint-v1', count: 1, head: entry.hash, nodePk: checker.pubkey }, checker.secretKey);
 const trust = { checkerPk: checker.pubkey, flaggedIssuerKeys: [issuer.pubkey], network: 'utexo-testnet' as const, logPk: checker.pubkey, providerPins: f.pins, now: at };
 const input = { attestation, entries: [entry], checkpoint, policy: RECEIVER_POLICY, provider };
 return { input, checker, trust, create: () => createAuditPack(input, checker, trust) };
}
test('independent audit: valid complete provider pack verifies canonical ZIP, exact policy and signed run', () => {
 const f = packFixture(), pack = f.create();
 assert.equal(decodeZip(pack).size, 6);
 assert.deepEqual(verifyAuditPack(pack, f.trust), []);
 assert(verifyAuditPack(pack, { ...f.trust, providerPins: wire().pins }).length);
});
test('independent audit chronology regression: provider expired before signed decision cannot form a valid archive', () => {
 assert.throws(() => packFixture({ expired: true }).create(), /outside validity/);
});
test('independent audit: a provider result for a different witness remains refused despite checker signatures', () => {
 assert.throws(() => packFixture({ wrongTransfer: true }).create(), /transfer binding/);
});
test('independent audit: valid ZIP rewrite cannot hide altered policy, missing evidence or a truncated log', () => {
 const f = packFixture(), original = decodeZip(f.create());
 for (const mutate of [(m: Map<string, Buffer>) => { m.set('policy.json', Buffer.from('{}')); }, (m: Map<string, Buffer>) => { m.delete('provider-evidence.json'); }, (m: Map<string, Buffer>) => { m.set('log.json', Buffer.from('[]')); }]) {
  const files = new Map(original); mutate(files);
  assert(verifyAuditPack(encodeZip(files), f.trust).length);
 }
});
