// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
// Independent gate concurrency and public-interface probes. All keys/providers are unit fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashObject, canonicalJson, signObject, randomHex, bytesToHex } from '../../src/core/crypto.js';
import { PolicyGate } from '../../src/governance/gate.js';
import { createTrustServer } from '../../src/http.js';
import { PAYLOAD_TYPE } from '../../src/provider/protocol.js';
import { pae } from '../../src/provider/dsse.js';
import { gateFixture } from '../../test/helpers.js';

function approval(request: any) {
 const record: any = { version: 1, provider_id: 'qa-review', request_id: request.request_id, request_sha256: hashObject(request), issued_at: request.issued_at, expires_at: request.expires_at, workload: { id: 'qa-unit-review', version: 'v1', sha256: '11'.repeat(32) }, model: { id: 'unit-fixed', mode: 'fixed-rules' }, policy: { id: 'qa-unit', sha256: '22'.repeat(32) }, input_scope: { evidence_ids: request.evidence.map((e: any) => e.id), fields: request.evidence.map((e: any) => `evidence.${e.id}`) }, result: { kind: 'agent-action-review', recommendation: 'approve', findings: [{ code: 'UNIT_APPROVE', evidence_ids: ['send-plan'] }] }, execution: 'software' };
 return { record, evidence_sha256: hashObject(record), evidence_file: '/unit/not-exported' };
}
function fixture(check: (r: any) => Promise<any>) {
 const f = gateFixture();
 const policy = signObject({ ...f.policy, maxPerSend: '80', maxPerDay: '100', review: { softLimit: '40', humanThreshold: '80', providerId: 'qa-review', maxReviewSeconds: 90 } }, f.owner.secretKey);
 const gate = new PolicyGate({ ...f.gateOptions, reviewProvider: { check } }); gate.install(policy);
 return { ...f, gate, policy };
}
test('independent review race: simultaneous replayed send requests cannot produce two tokens', async () => {
 let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; }); let calls = 0;
 const f = fixture(async request => { calls++; await pending; return approval(request); });
 const request = f.request(); const one = f.gate.authorizeReviewed(request), two = f.gate.authorizeReviewed(request);
 assert.equal(calls, 2); release();
 const results = await Promise.all([one, two]);
 assert.equal(results.filter(d => d.allowed).length, 1);
 assert(results.find(d => !d.allowed)!.why.includes('REQUEST_REPLAY_OR_ID_INVALID'));
 assert.equal(Object.values(f.gate.store.read().tokens).length, 1);
 assert.equal(Object.values(f.gate.store.read().spentByDay)[0], '50');
});
test('independent review race: concurrent approvals recheck the cumulative cap before reserving', async () => {
 let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; }); let calls = 0;
 const f = fixture(async request => { calls++; await pending; return approval(request); });
 const decisions = Array.from({ length: 3 }, () => f.gate.authorizeReviewed(f.request()));
 assert.equal(calls, 3); release();
 const results = await Promise.all(decisions);
 assert.equal(results.filter(d => d.allowed).length, 2);
 assert(results.find(d => !d.allowed)!.why.includes('DAILY_LIMIT_EXCEEDED'));
 assert.equal(Object.values(f.gate.store.read().spentByDay)[0], '100');
});
test('independent HTTP wiring: authorize waits for reviewed gate path and never invokes synchronous bypass', async () => {
 let calls = 0;
 const gate = { authorize() { throw new Error('synchronous bypass must not execute'); }, async authorizeReviewed(body: any) { calls++; await new Promise<void>(resolve => setImmediate(resolve)); return { allowed: false, token: null, why: ['UNIT_REVIEW_ESCALATED'], actionId: body.actionId }; } };
 const token = randomHex(32), server = createTrustServer({ gate } as any, token);
 await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
 try {
  const port = (server.address() as any).port;
  const r = await fetch(`http://127.0.0.1:${port}/v1/authorize`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ actionId: 'qa-http-unit' }) });
  assert.equal(r.status, 200); assert.deepEqual(await r.json(), { actionId: 'qa-http-unit', allowed: false, token: null, why: ['UNIT_REVIEW_ESCALATED'] }); assert.equal(calls, 1);
 } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
test('independent CLI wiring: configured DSSE reviewer produces a bound reviewed token through actual command', async () => {
 const f = gateFixture(), now = Math.floor(Date.now() / 1000), ed = generateKeyPairSync('ed25519');
 const policy = signObject({ ...f.policy, notBefore: now - 1, expiresAt: now + 600, review: { softLimit: '40', humanThreshold: '80', providerId: 'qa-review', maxReviewSeconds: 90 } }, f.owner.secretKey);
 f.setTime(now);
 new PolicyGate({ ...f.gateOptions, stateFile: join(f.dir, 'gate-state.json') }).install(policy);
 const request = signObject({ ...f.request(), issuedAt: now, expiresAt: now + 120 }, f.agent.secretKey);
 const token = randomHex(32); let calls = 0;
 const provider = createServer(async (req, res) => {
  assert.equal(req.headers.authorization, `Bearer ${token}`); calls++;
  let body = ''; for await (const chunk of req) body += chunk;
  const check = JSON.parse(body), record = approval(check).record;
  record.issued_at = new Date().toISOString();
  const payload = Buffer.from(canonicalJson(record));
  res.setHeader('content-type', 'application/json'); res.end(canonicalJson({ result: record, evidence_envelope: { payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'), signatures: [{ keyid: 'qa', sig: sign(null, pae(PAYLOAD_TYPE, payload), ed.privateKey).toString('base64') }] } }));
 });
 await new Promise<void>(resolve => provider.listen(0, '127.0.0.1', resolve));
 const config = join(f.dir, 'config.json'), input = join(f.dir, 'request.json'), pins = join(f.dir, 'provider-public-pins.json');
 writeFileSync(config, JSON.stringify({ v: 1, network: 'utexo-testnet', walletId: f.gateOptions.walletId, stateDir: '.', checkerSecretEnv: 'TRUST_QA_GATE_SECRET', ownerPk: f.owner.pubkey, sanctionsDir: join(process.cwd(), 'fixtures/sanctions'), flagged: { provider: 'local-file', dir: '.', trustedIssuerKeys: [f.owner.pubkey] } }), { mode: 0o600 });
 writeFileSync(input, canonicalJson(request), { mode: 0o600 });
 writeFileSync(pins, JSON.stringify({ providers: [{ provider_id: 'qa-review', keyid: 'qa', public_key_pem: ed.publicKey.export({type:'spki',format:'pem'}).toString() }] }), { mode: 0o600 });
 try {
  const out = await promisify(execFile)(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'authorize', input, '--config', config], { env: { ...process.env, TRUST_QA_GATE_SECRET: bytesToHex(f.gateKey.secretKey), TRUST_PROVIDER_URL: `http://127.0.0.1:${(provider.address() as any).port}/checks`, TRUST_PROVIDER_KEYS_FILE: pins, TRUST_PROVIDER_TOKEN: token }, timeout: 10000 });
  const decision = JSON.parse(out.stdout); assert.equal(calls, 1); assert.equal(decision.allowed, true); assert.equal(decision.token.review.recommendation, 'approve'); assert.equal(decision.token.review.execution, 'software'); assert.equal(decision.token.review.policyHash, hashObject(policy));
  assert(!out.stdout.includes('/unit/not-exported'));
 } finally { provider.closeAllConnections(); await new Promise<void>(resolve => provider.close(() => resolve())); }
});
