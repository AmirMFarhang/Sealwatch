// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Independent receipt/public-chain verification. Never opens an SDK wallet, seed, key or database.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { Transaction } from 'bitcoinjs-lib';
import { canonicalJson, sha256Hex, verifyObject } from '../src/core/crypto.js';
import { SanctionsScreen } from '../src/compliance/sanctions.js';
import { attestationProblems, type Attestation } from '../src/verify/incoming.js';

const receiptFile = process.argv[2];
assert(receiptFile, 'usage: node --import tsx qa/verify-live-receipt.ts RECEIPT [OUTPUT]');
const outputFile = process.argv[3] ?? 'qa/live-receipt-verification.json';
const pins = JSON.parse(readFileSync('qa/live-run-authorities.json', 'utf8'));
const receipt = JSON.parse(readFileSync(receiptFile, 'utf8'));
const sanctions = new SanctionsScreen('fixtures/sanctions');
const problems: string[] = [];
const pending: string[] = [];
const checks: unknown[] = [];
const hosts = ['https://mempool.space', 'https://blockstream.info'];
if (receipt.network !== pins.network || receipt.fallback !== false) problems.push('network/fallback mismatch');
if (receipt.asset?.assetId !== pins.assetId || receipt.asset?.label !== 'test USD, not USDT') problems.push('asset identity/label mismatch');
for (const name of ['clear', 'flagged']) {
  const txid = receipt.transactions?.[name];
  const a = receipt.attestations?.[name] as Attestation | undefined;
  if (!txid) { pending.push(`${name}: transaction not recorded`); continue; }
  const publicChecks = await Promise.all(hosts.map(async host => {
    try {
      const [jsonRes, hexRes] = await Promise.all([
        fetch(`${host}/testnet/api/tx/${txid}`, { signal: AbortSignal.timeout(20_000) }),
        fetch(`${host}/testnet/api/tx/${txid}/hex`, { signal: AbortSignal.timeout(20_000) }),
      ]);
      assert(jsonRes.ok && hexRes.ok, 'public transaction/hex endpoint failed');
      const tx = await jsonRes.json() as { txid: string; status: { confirmed: boolean; block_height?: number; block_hash?: string }; fee: number };
      const decoded = Transaction.fromHex((await hexRes.text()).trim());
      assert(tx.txid === txid && decoded.getId() === txid, 'public raw transaction ID mismatch');
      return { host, txid, decoded, status: tx.status, feeSats: tx.fee };
    } catch (error) { return { host, txid, error: String(error) }; }
  }));
  for (const c of publicChecks) {
    if ('error' in c) pending.push(`${name}: ${c.host} unavailable: ${c.error}`);
    else if (!c.status.confirmed) pending.push(`${name}: ${c.host} unconfirmed`);
  }
  const decoded = publicChecks.find(c => 'decoded' in c && c.decoded)?.decoded;
  if (!a) { pending.push(`${name}: attestation not recorded`); }
  let attestationValid = false;
  let exactTestListHashMatches = false;
  if (a) {
    const found = attestationProblems(a, {
      checkerPk: pins.checkerPk, flaggedIssuerKeys: [pins.flaggedIssuerPk],
      network: pins.network, sanctionsListPins: sanctions.lists.filter(l => !l.testOnly).map(l => l.sha256),
      maxAgeSeconds: 86400,
    });
    if (a.assetId !== pins.assetId || a.witnessTxid !== txid) found.push('attestation asset/witness mismatch');
    for (const list of sanctions.lists) {
      if (!a.lists.some(l => l.id === list.id && l.version === list.version && l.sha256 === list.sha256 && !l.testOnly)) found.push(`required pinned sanctions snapshot missing: ${list.id}`);
    }
    if (a.overall !== name || a.checks.flaggedL1.status !== (name === 'clear' ? 'clear' : 'flagged')) found.push('wrong clear/flagged result');
    if (!a.flaggedManifest.testOnly) found.push('demonstration list must be labelled test-only');
    if (decoded) {
      // Recreate exactly the runner's synthetic list, using public-chain input data only.
      // Raw outpoints remain in memory and are never exported in this QA report.
      const first = decoded.ins[0];
      const outpoints = name === 'clear' ? [] : [`${Buffer.from(first.hash).reverse().toString('hex')}:${first.index}`];
      const m = a.flaggedManifest;
      const snapshot = { v: 1, domain: 'trust-flagged-outpoints-v1', id: m.listId, version: m.version, network: m.network, testOnly: m.testOnly, outpoints };
      exactTestListHashMatches = sha256Hex(canonicalJson(snapshot) + '\n') === m.sha256;
      if (!exactTestListHashMatches) found.push('signed test-list hash differs from independently reconstructed actual witness-input list');
    } else pending.push(`${name}: public raw transaction unavailable for list reconstruction`);
    attestationValid = found.length === 0;
    problems.push(...found.map(p => `${name}: ${p}`));
  }
  checks.push({ name, txid, attestationValid, exactTestListHashMatches, publicExplorers: publicChecks.map(c => 'error' in c ? { host: c.host, error: c.error } : { host: c.host, explorerUrl: `${c.host}/testnet/tx/${txid}`, status: c.status, feeSats: c.feeSats, decodedTxidMatches: true }) });
}
const auth = receipt.authorization ?? {};
const allowed = auth.clear;
if (!allowed) pending.push('clear governed authorization missing');
else if (!allowed.allowed || !allowed.token || allowed.token.gatePk !== pins.gatePk || !verifyObject(allowed.token, pins.gatePk)) problems.push('clear governed token signature/gate invalid');
for (const [name, reason] of [['overLimit', 'PER_SEND_LIMIT_EXCEEDED'], ['stopped', 'KILL_SWITCH_STOPPED']]) {
  if (!auth[name]) pending.push(`${name}: refusal not recorded`);
  else if (auth[name].allowed || !auth[name].why?.includes(reason) || auth[name].token !== null) problems.push(`${name}: wrong refusal semantics`);
}
if (!receipt.quarantine?.enforced) pending.push('native quarantine enforcement not recorded');
if (receipt.status !== 'complete') pending.push(`receipt status is ${receipt.status}`);
const result = { version: 1, independentQa: true, checkedAt: new Date().toISOString(), receiptStatus: receipt.status, receiptUpdatedAt: receipt.updatedAt, receiptSha256: sha256Hex(readFileSync(receiptFile)), network: pins.network, fallback: false, verdict: problems.length ? 'FAIL' : pending.length ? 'PENDING' : 'PASS_PUBLIC_TRANSACTIONS_AND_ATTESTATIONS', problems, pending, checks, limitations: ['Receiver SDK provides RGB receive/asset membership; this independently decodes public Bitcoin witnesses and verifies signed attestations, not RGB consignments.', 'Authorization refusal records are checked structurally; independent signed decision-log verification is recorded separately.'] };
writeFileSync(outputFile, JSON.stringify(result, null, 2) + '\n');
process.stdout.write(JSON.stringify({ verdict: result.verdict, problems, pending, outputFile }) + '\n');
if (problems.length) process.exitCode = 1;
