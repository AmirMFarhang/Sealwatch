// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Reads only named signed decision logs/checkpoints. Never opens a seed, key, wallet database or raw receiver history.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyLog, type LogEntry } from '../src/governance/log.js';
import { hashObject, sha256Hex } from '../src/core/crypto.js';

const root = process.argv[2];
assert(root, 'usage: node --import tsx qa/verify-live-logs.ts DEMO_LOG_DIRECTORY [RECEIPT]');
const pins = JSON.parse(readFileSync('qa/live-run-authorities.json', 'utf8'));
const receipt = process.argv[3] ? JSON.parse(readFileSync(process.argv[3], 'utf8')) : null;
const results = [];
for (const [name, file, key] of [['authorization', 'decisions.jsonl', pins.gatePk], ['receiver', 'receiver-decisions.jsonl', pins.checkerPk]]) {
  const logFile = join(root, file), checkpointFile = logFile + '.checkpoint.json';
  if (!existsSync(logFile) || !existsSync(checkpointFile)) { results.push({ name, status: 'pending_no_log_yet' }); continue; }
  const before = readFileSync(checkpointFile, 'utf8'), bytes = readFileSync(logFile), after = readFileSync(checkpointFile, 'utf8');
  if (before !== after) { results.push({ name, status: 'pending_concurrent_append' }); continue; }
  const entries = bytes.toString().split('\n').filter(Boolean).map(l => JSON.parse(l)) as LogEntry[];
  const problems = verifyLog(entries, key, JSON.parse(after));
  const kinds: Record<string, number> = {};
  for (const e of entries) kinds[e.kind] = (kinds[e.kind] ?? 0) + 1;
  const bindings = [];
  if (receipt && name === 'authorization') for (const [label, d] of Object.entries(receipt.authorization ?? {}) as [string, any][]) {
    const e = entries.find(e => e.kind === 'authorization' && e.actionId === d.actionId);
    const detail = e?.detail as any;
    const decisionMatches = !!e && e.result === (d.allowed ? 'allowed' : 'refused') && hashObject(detail?.why) === hashObject(d.why);
    if (!decisionMatches) problems.push(`${label}: receipt decision differs from signed authorization log`);
    let tokenConsumptionMatches: boolean | null = null;
    if (d.allowed) {
      const burn = entries.find(e => e.kind === 'signing-token' && e.actionId === d.actionId && e.result === 'consumed');
      const burnDetail = burn?.detail as any;
      tokenConsumptionMatches = !!burn && burnDetail.tokenId === d.token?.id && burnDetail.planHash === d.token?.planHash && detail?.planHash === d.token?.planHash && detail?.policyHash === d.token?.policyHash;
      if (!tokenConsumptionMatches) problems.push(`${label}: signed plan/policy/token consumption binding missing`);
    }
    bindings.push({ label, decisionMatches, tokenConsumptionMatches });
  }
  if (receipt && name === 'receiver') for (const [label, a] of Object.entries(receipt.attestations ?? {}) as [string, any][]) {
    const e = entries.find(e => e.kind === 'incoming-verification' && (e.detail as any)?.attestationHash === hashObject(a));
    const detail = e?.detail as any;
    const attestationLogMatches = !!e && e.result === a.overall && detail?.witnessTxid === a.witnessTxid && detail?.assetId === a.assetId;
    if (!attestationLogMatches) problems.push(`${label}: attestation absent from signed receiver log`);
    bindings.push({ label, attestationLogMatches });
  }
  results.push({ name, status: problems.length ? 'fail' : 'pass', nodePk: key, entryCount: entries.length, logSha256: sha256Hex(bytes), checkpointSha256: sha256Hex(after), kinds, bindings, problems });
}
const report = { version: 1, independentQa: true, checkedAt: new Date().toISOString(), scope: 'Read only named signed decision logs/checkpoints; no wallet database, seed, key or receiver raw history opened; no log contents exported.', results };
writeFileSync('qa/live-decision-log-verification.json', JSON.stringify(report, null, 2) + '\n');
process.stdout.write(JSON.stringify(report) + '\n');
if (results.some(r => r.status === 'fail')) process.exitCode = 1;
