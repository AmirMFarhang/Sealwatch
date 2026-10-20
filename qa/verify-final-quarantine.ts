// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Independent read-only live-state verification. Only signed state/log files are read;
// runtime classes operate on QA copies, with a dummy SDK and no private key.
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashObject, sha256Hex, verifyObject } from '../src/core/crypto.js';
import { FileDecisionLog, verifyLog } from '../src/governance/log.js';
import { ReceiverQuarantine } from '../src/wallet/quarantine.js';
import { TestnetWallet } from '../src/testnet/wallet.js';
import { networkConfig } from '../src/network/config.js';
import { attestationProblems } from '../src/verify/incoming.js';

const root = process.argv[2], receiptFile = process.argv[3];
assert(root && receiptFile, 'usage: verify-final-quarantine.ts NETWORK_STATE RECEIPT');
const pins = JSON.parse(readFileSync('qa/live-run-authorities.json', 'utf8'));
// Independently derived by parent from the known B authority file, public value only.
const nativePk = '38e1b635c8ce7dcd30a7931b5a7d631c15da509ac1858f9c51c303a8ff4f09d1';
const receipt = JSON.parse(readFileSync(receiptFile, 'utf8'));
const original = JSON.parse(readFileSync('qa/preserved-live-receiver-error.json', 'utf8'));
const errorAttestation = original.attestation ?? original;
assert.equal(errorAttestation.overall, 'error');
assert.deepEqual(attestationProblems(errorAttestation, { checkerPk: pins.checkerPk, flaggedIssuerKeys: [pins.flaggedIssuerPk], network: pins.network, now: errorAttestation.time }), []);
const errorHash = hashObject(errorAttestation), flaggedHash = hashObject(receipt.attestations.flagged);
assert(receipt.priorAttestations.some((x: any) => hashObject(x.attestation) === errorHash));
assert.equal(receipt.transactions.clear, errorAttestation.witnessTxid);
const reports = [];
const originals = new Map<string, string>();
let nativeStore: ReceiverQuarantine | undefined;
for (const spec of [
  { name: 'receiver', directory: join(root, 'demo'), state: 'receiver-history/quarantine-state.json', log: 'receiver-decisions.jsonl', pk: pins.checkerPk },
  { name: 'native-wallet-B', directory: join(root, 'B'), state: 'quarantine-state.json', log: 'wallet-decisions.jsonl', pk: nativePk },
]) {
  const copy = join('.state/qa/final-quarantine-copy', spec.name);
  mkdirSync(copy, { recursive: true });
  for (const [source, target] of [[spec.state, 'quarantine.json'], [spec.log, 'decisions.jsonl'], [spec.log + '.checkpoint.json', 'decisions.jsonl.checkpoint.json']]) {
    const file = join(spec.directory, source);
    originals.set(file, sha256Hex(readFileSync(file)));
    copyFileSync(file, join(copy, target));
  }
  const snapshot = JSON.parse(readFileSync(join(copy, 'quarantine.json'), 'utf8'));
  const entries = readFileSync(join(copy, 'decisions.jsonl'), 'utf8').split('\n').filter(Boolean).map(x => JSON.parse(x));
  const checkpoint = JSON.parse(readFileSync(join(copy, 'decisions.jsonl.checkpoint.json'), 'utf8'));
  assert.deepEqual(verifyLog(entries, spec.pk, checkpoint), []);
  assert.equal(snapshot.pubkey, spec.pk);
  assert(verifyObject(snapshot, spec.pk));
  const commit = entries.filter((e: any) => e.kind === 'state-commit' && e.detail.namespace === 'receiver-quarantine').at(-1);
  assert(commit && commit.detail.stateHash === hashObject(snapshot) && commit.detail.revision === snapshot.revision);
  const rows: any[] = Object.values(snapshot.state.receives).flat();
  assert(rows.some(r => r.attestationHash === errorHash && r.overall === 'error'));
  assert(rows.some(r => r.attestationHash === flaggedHash && r.overall === 'flagged'));
  // This dummy secret is never used: all journal and snapshot checks are public verification.
  const publicOnlyKey = { pubkey: spec.pk, secretKey: new Uint8Array(32) };
  const log = new FileDecisionLog(join(copy, 'decisions.jsonl'), publicOnlyKey);
  const store = new ReceiverQuarantine(join(copy, 'quarantine.json'), publicOnlyKey, log);
  const reasons = store.problems(pins.network, 'utexo-testnet:B', pins.assetId);
  assert(reasons.includes('RECEIVER_ASSET_QUARANTINED_ERROR') && reasons.includes('RECEIVER_ASSET_QUARANTINED_FLAGGED'));
  assert.throws(() => store.assertSpendable(pins.network, 'utexo-testnet:B', pins.assetId), /ASSET_QUARANTINED/);
  if (spec.name === 'native-wallet-B') nativeStore = store;
  if (spec.name === 'receiver') assert(entries.some((e: any) => e.kind === 'incoming-verification' && e.detail.attestationHash === errorHash));
  reports.push({ name: spec.name, publicKey: spec.pk, logEntries: entries.length, snapshotRevision: snapshot.revision, signedSnapshotAndRetainedJournalMatch: true, originalErrorAndFlaggedRecordsRetained: true, exactAssetRefusalReasons: reasons, snapshotSha256: originals.get(join(spec.directory, spec.state)) });
}
let sdkCalls = 0;
const account = { getRgbWallet() { sdkCalls++; throw new Error('SDK must never be called'); } };
const Constructor = TestnetWallet as unknown as new (...args: any[]) => any;
const wallet = new Constructor('B', 'utexo-testnet:B', networkConfig(), '.state/qa/final-quarantine-copy', 'unused', account, {});
wallet.quarantineStore = nativeStore;
assert.throws(() => wallet.prepareSend('not-decoded', pins.assetId, 1), /RECEIVER_ASSET_QUARANTINED_ERROR.*RECEIVER_ASSET_QUARANTINED_FLAGGED/);
assert.equal(sdkCalls, 0);
for (const [file, hash] of originals) assert.equal(sha256Hex(readFileSync(file)), hash, 'operational evidence changed during verification');
const result = { version: 1, independentQa: true, checkedAt: new Date().toISOString(), verdict: 'PASS_PERSISTENT_QUARANTINE_AND_NATIVE_REFUSAL', network: pins.network, assetId: pins.assetId, originalErrorHash: errorHash, originalErrorRetainedInReceiptAndSignedLog: true, originalClearWitnessUnchanged: true, reports, nativePrepareSendOnCopiedActualState: 'refused exact actual asset before SDK call', sdkCalls, operationalFilesUnchanged: true, noOperationalWalletOrPrivateKeyOpened: true, limitation: 'Native refusal replay uses actual signed state and production guard with dummy SDK; the original live refusal is separately recorded by the frozen runner.' };
writeFileSync('qa/final-quarantine-verification.json', JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ verdict: result.verdict, originalErrorHash: errorHash, sdkCalls }));
