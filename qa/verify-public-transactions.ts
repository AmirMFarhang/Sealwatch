// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Public raw-transaction verification for every setup and demonstration txid.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { Transaction } from 'bitcoinjs-lib';
const transactions = [
  ['faucet-B', '655090b2862de7bf6bd92ec0566c0643a017513dbc4bdb151569396055306b0c'],
  ['setup-B-to-A', 'c92c1d073eb8aaba75f3c72e45d3f5618556890e60fde8b79d07911d38105ffa'],
  ['create-utxos-A', '0a531d17c0240b1fee7b4e3db59014a2c5ef5f0e15f976082b6537d278e03476'],
  ['create-utxos-B', '5e5d07f25608b5429a8c67f53a23fc0416839cc74b28c27154ed0ca933d7a9c0'],
  ['clear', 'e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06'],
  ['flagged', '8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b'],
];
const checks = await Promise.all(transactions.flatMap(([name, txid]) => ['https://mempool.space', 'https://blockstream.info'].map(async host => {
  const [summary, raw] = await Promise.all([fetch(`${host}/testnet/api/tx/${txid}`, { signal: AbortSignal.timeout(25000) }), fetch(`${host}/testnet/api/tx/${txid}/hex`, { signal: AbortSignal.timeout(25000) })]);
  assert(summary.ok && raw.ok, `${name}: public endpoints failed`);
  const s: any = await summary.json(), tx = Transaction.fromHex((await raw.text()).trim());
  assert.equal(tx.getId(), txid); assert.equal(s.txid, txid); assert.equal(s.status.confirmed, true);
  assert.equal(tx.ins.length, s.vin.length); assert.equal(tx.outs.length, s.vout.length);
  for (let i = 0; i < tx.outs.length; i++) { assert.equal(tx.outs[i].value, BigInt(s.vout[i].value)); assert.equal(Buffer.from(tx.outs[i].script).toString('hex'), s.vout[i].scriptpubkey); }
  assert.equal(BigInt(s.vin.reduce((sum: number, v: any) => sum + v.prevout.value, 0)) - tx.outs.reduce((sum, o) => sum + o.value, 0n), BigInt(s.fee));
  return { name, txid, explorerUrl: `${host}/testnet/tx/${txid}`, checkedAt: new Date().toISOString(), status: s.status, feeSats: s.fee, rawTxidMatches: true, publicOutputValuesAndScriptsMatchRaw: true };
})));
for (const [name] of transactions) { const rows = checks.filter(c => c.name === name); assert.equal(rows[0].status.block_hash, rows[1].status.block_hash); }
const report = { version: 1, independentQa: true, checkedAt: new Date().toISOString(), verdict: 'PASS_ALL_SIX_CONFIRMED_ON_BOTH_EXPLORERS', transactionCount: transactions.length, explorerChecks: checks.length, checks, note: 'RGB asset identity comes from receiver SDK membership and signed attestation; this verifies all recorded setup and witness transactions, not RGB consignments. Asset issuance has no separate recorded broadcast txid.' };
writeFileSync('qa/public-explorer-checks.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ verdict: report.verdict, transactionCount: transactions.length, checks: checks.length }));
