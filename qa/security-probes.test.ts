// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Independent adversarial QA. These probes do not alter application runtime code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { PolicyGate } from '../src/governance/gate.js';
import { ReceiverQuarantine } from '../src/wallet/quarantine.js';
import { bytesToHex } from '../src/core/crypto.js';
import { AT, gateFixture, incomingFixture } from '../test/helpers.js';

test('QA: retained current log prevents restoring consumed approval state', () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const request = f.request();
  const decision = f.gate.authorize(request);
  assert(decision.token);
  const beforeConsume = readFileSync(f.gateOptions.stateFile);
  f.gate.consume(decision.token, request.plan, request.preview);
  const retainedCheckpoint = readFileSync(f.log.checkpointFile);
  writeFileSync(f.gateOptions.stateFile, beforeConsume);
  assert.deepEqual(readFileSync(f.log.checkpointFile), retainedCheckpoint);
  assert.throws(() => new PolicyGate(f.gateOptions).consume(decision.token!, request.plan, request.preview), /rollback|REUSED|history|checkpoint|state/i);
});

test('QA: retained current log prevents rollback of the stop switch', () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const beforeStop = readFileSync(f.gateOptions.stateFile);
  f.gate.stop(f.stop());
  writeFileSync(f.gateOptions.stateFile, beforeStop);
  const gate = new PolicyGate(f.gateOptions);
  let blocked = false;
  try { blocked = !gate.authorize(f.request()).allowed; } catch { blocked = true; }
  assert(blocked, 'restoring older signed gate state must not undo a logged owner stop');
});

test('QA: retained current log prevents rollback of daily reservations', () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const beforeReservations = readFileSync(f.gateOptions.stateFile);
  assert(f.gate.authorize(f.request(f.plan('100'))).allowed);
  writeFileSync(f.gateOptions.stateFile, beforeReservations);
  let blocked = false;
  try { blocked = !new PolicyGate(f.gateOptions).authorize(f.request(f.plan('100'))).allowed; } catch { blocked = true; }
  assert(blocked, 'restoring older signed state must not bypass the cumulative daily cap');
});

test('QA: retained receiver log prevents rollback from flagged quarantine to clear', async () => {
  const f = incomingFixture();
  await f.service.verifyIncoming(f.input);
  const beforeFlagged = readFileSync(f.service.quarantine.file);
  f.service.quarantine.record(f.input.network, f.input.receiverWalletId, f.input.assetId, {
    attestationHash: 'qa-flagged-after-clear', witnessTxid: f.input.witnessTxid, overall: 'flagged', at: AT,
  });
  f.log.append('incoming-verification', 'flagged', { assetId: f.input.assetId });
  writeFileSync(f.service.quarantine.file, beforeFlagged);
  const restarted = new ReceiverQuarantine(f.service.quarantine.file, f.key, f.log);
  assert.throws(() => restarted.assertSpendable(f.input.network, f.input.receiverWalletId, f.input.assetId), /rollback|QUARANTINED|history|checkpoint|state/i);
});

test('QA: consumed token replay is refused across two independent Node processes', () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const request = f.request();
  const decision = f.gate.authorize(request);
  assert(decision.token);
  const payloadFile = join(f.dir, 'qa-process-payload.json');
  writeFileSync(payloadFile, JSON.stringify({
    gateSecret: bytesToHex(f.gateKey.secretKey), ownerPk: f.owner.pubkey,
    stateFile: f.gateOptions.stateFile, logFile: f.log.file,
    token: decision.token, request,
  }), { mode: 0o600 });
  const code = `import {readFileSync} from 'node:fs';
    import {keyPairFromSecret} from './src/core/crypto.ts';
    import {PolicyGate} from './src/governance/gate.ts';
    import {FileDecisionLog} from './src/governance/log.ts';
    const p=JSON.parse(readFileSync(process.argv[1],'utf8'));
    const key=keyPairFromSecret(p.gateSecret);
    const gate=new PolicyGate({key,ownerPk:p.ownerPk,network:'utexo-testnet',walletId:'A-unit-only',stateFile:p.stateFile,log:new FileDecisionLog(p.logFile,key,()=>${AT}),now:()=>${AT}});
    try {gate.consume(p.token,p.request.plan,p.request.preview);process.stdout.write('consumed');}
    catch(e) {process.stdout.write(String(e.message));process.exitCode=3;}`;
  const args = ['--import', 'tsx', '--input-type=module', '-e', code, payloadFile];
  const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
  const second = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stdout, 'consumed');
  assert.equal(second.status, 3, second.stderr);
  assert.match(second.stdout, /REUSED/);
});
