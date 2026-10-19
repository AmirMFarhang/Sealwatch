// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Independent adapter-level probes with injected SDK/account fakes; no native wallet or chain actions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { TestnetWallet, type PreparedSend } from '../src/testnet/wallet.js';
import { networkConfig } from '../src/network/config.js';
import { ReceiverQuarantine } from '../src/wallet/quarantine.js';
import { SignedStore } from '../src/core/store.js';
import { FileDecisionLog } from '../src/governance/log.js';
import { PolicyGate, signPolicy, signRequest } from '../src/governance/gate.js';
import { AT, gateFixture } from '../test/helpers.js';

function fixture() {
  const f = gateFixture();
  const recipientId = 'qa:wvout:receiver';
  const policy = signPolicy({ ...f.policy, allowedRecipients: [recipientId] }, f.owner);
  f.gate.install(policy);
  const events: string[] = [];
  let enrollHook: undefined | (() => void);
  let registered: any;
  const unsignedPsbt = f.plan().unsignedPsbt;
  const client = {
    getOnline: () => ({}),
    decodeRGBInvoice: () => ({ recipientId, network: 'testnet', assignment: { Fungible: 50 }, transportEndpoints: ['rpcs://qa.example.test/json-rpc'] }),
    wallet: { sendBegin: (_online: unknown, map: any, donation: boolean) => {
      assert.equal(donation, true); assert.equal(map[policy.assetId][0].assignment.Fungible, 50); return unsignedPsbt;
    } },
  };
  const account = {
    getRgbWallet: () => ({ client }),
    toReadOnlyAccount: () => ({}),
    sendEnd: () => { events.push('broadcast'); return { txid: 'qa-fake-never-broadcast', batchTransferIdx: 1 }; },
  };
  const governed = { signPsbt: async (psbt: string) => {
    assert.equal(psbt, unsignedPsbt);
    assert.equal(registered.rules[0].conditions[0]({ args: [psbt] }), false, 'temporary exact PSBT permit must be present');
    const records = f.gate.store.read().tokens;
    assert(Object.values(records).some(r => r.used), 'durable token must be burned before signing');
    events.push('sign'); return psbt;
  } };
  const wdk = { registerPolicy: (p: any) => { registered = p; }, getAccount: async () => { enrollHook?.(); return governed; } };
  const Constructor = TestnetWallet as unknown as new (...args: any[]) => TestnetWallet;
  const wallet = new Constructor('A', f.gateOptions.walletId, networkConfig(), f.dir, 'unused-public-address', account, wdk) as any;
  wallet.adapterKey = f.adapter;
  const log = new FileDecisionLog(join(f.dir, 'wallet-journal.jsonl'), f.adapter, () => AT);
  const quarantine = new ReceiverQuarantine(join(f.dir, 'native-quarantine.json'), f.adapter, log);
  wallet.quarantineStore = quarantine;
  wallet.gateBindingStore = new SignedStore(join(f.dir, 'native-gate-binding.json'), f.adapter, () => ({ binding: null }), { log, namespace: 'qa-native-gate' });
  const prepare = async () => {
    await wallet.bindGate(f.gate);
    const plan = wallet.prepareSend('qa-native-decoded-invoice', policy.assetId, 50) as PreparedSend;
    const preview = await wallet.certifyPreview(plan);
    const request = signRequest({ ...f.request(plan), preview }, f.agent);
    const decision = f.gate.authorize(request);
    assert(decision.token, decision.why.join(', '));
    return { plan, preview, token: decision.token };
  };
  const flag = () => quarantine.record('utexo-testnet', f.gateOptions.walletId, policy.assetId, { attestationHash: 'qa-local-flag', witnessTxid: 'ab'.repeat(32), overall: 'flagged', at: AT });
  return { ...f, wallet, quarantine, log, policy, prepare, flag, events, duringEnrollment: (hook: () => void) => { enrollHook = hook; } };
}

test('QA native: SDK-produced exact plan is certified and token consumed before exact PSBT signing', async () => {
  const f = fixture(); const p = await f.prepare();
  await f.wallet.sendPrepared(p.plan, p.token, p.preview);
  assert.deepEqual(f.events, ['sign', 'broadcast']);
  await assert.rejects(() => f.wallet.sendPrepared(p.plan, p.token, p.preview));
});

test('QA native: amount, recipient map, invoice and PSBT changes cannot be certified or signed', async () => {
  const f = fixture(); const p = await f.prepare();
  for (const mutate of [
    (plan: any) => { plan.amount = '51'; },
    (plan: any) => { plan.recipientMap[plan.assetId][0].assignment.Fungible = 51; },
    (plan: any) => { plan.invoice += '-changed'; },
    (plan: any) => { plan.unsignedPsbt += 'changed'; },
  ]) {
    const changed = structuredClone(p.plan); mutate(changed);
    await assert.rejects(() => f.wallet.certifyPreview(changed));
    await assert.rejects(() => f.wallet.sendPrepared(changed, p.token, p.preview));
  }
  assert.deepEqual(f.events, []);
});

test('QA native: stop after approval prevents signer invocation', async () => {
  const f = fixture(); const p = await f.prepare(); f.gate.stop(f.stop());
  await assert.rejects(() => f.wallet.sendPrepared(p.plan, p.token, p.preview), /STOPPED/);
  assert.deepEqual(f.events, []);
});

test('QA native: retained journal catches quarantine deletion and signed snapshot rollback', async () => {
  const f = fixture(); await f.prepare();
  f.quarantine.record('utexo-testnet', f.gateOptions.walletId, f.policy.assetId, { attestationHash: 'qa-clear', witnessTxid: 'cd'.repeat(32), overall: 'clear', at: AT });
  const clear = readFileSync(f.quarantine.file); f.flag();
  writeFileSync(f.quarantine.file, clear);
  assert.throws(() => f.wallet.prepareSend('qa', f.policy.assetId, 50), /rollback/);
  unlinkSync(f.quarantine.file);
  assert.throws(() => f.wallet.prepareSend('qa', f.policy.assetId, 50), /missing/);
});

test('QA native: owner gate binding cannot be replaced or deleted beside retained journal', async () => {
  const f = fixture(); await f.prepare();
  const alternate = new PolicyGate({ ...f.gateOptions, stateFile: join(f.dir, 'other-gate.json') });
  await assert.rejects(() => f.wallet.bindGate(alternate), /binding changed/);
  unlinkSync(join(f.dir, 'native-gate-binding.json'));
  await assert.rejects(() => f.wallet.bindGate(f.gate), /missing/);
});

test('QA native: quarantine arriving during asynchronous enrollment prevents a preapproved send', async () => {
  const f = fixture(); const p = await f.prepare(); f.duringEnrollment(f.flag);
  await assert.rejects(() => f.wallet.sendPrepared(p.plan, p.token, p.preview), /QUARANTINED/);
  assert.deepEqual(f.events, []);
});
