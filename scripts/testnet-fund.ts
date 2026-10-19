// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { networkConfig, transactionUrl } from '../src/network/config.js'
import { TestnetWallet } from '../src/testnet/wallet.js'

async function main() {
  const config = networkConfig()
  const stateRoot = process.env.TRUST_STATE_DIR ?? '.state'
  const file = resolve(stateRoot, config.name, 'funding-split.json')
  try { console.log(await readFile(file, 'utf8')); return }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
  const opened: TestnetWallet[] = []
  try {
    const a = await TestnetWallet.open('A', config, stateRoot); opened.push(a)
    const b = await TestnetWallet.open('B', config, stateRoot); opened.push(b)
    a.refresh(); b.refresh()
    const aBalance = a.publicState().btcBalance as { vanilla: { settled: number; future: number } }
    if (aBalance.vanilla.future >= 45_000) { console.log('A already has sufficient faucet funding; no split needed'); return }
    const bBalance = b.publicState().btcBalance as { vanilla: { settled: number; spendable: number } }
    if (bBalance.vanilla.settled < 115_000 || bBalance.vanilla.spendable < 115_000) throw new Error('Wait for at least 115,000 fresh B faucet sats to confirm before splitting')
    const split = { network: config.name, fallback: config.fallback, sentAt: new Date().toISOString(), ...(await b.fundNewPeer(a)), status: 'broadcast_waiting_confirmation' }
    await writeFile(file, `${JSON.stringify(split, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
    console.log(JSON.stringify({ ...split, explorerUrl: transactionUrl(config, split.txid) }, null, 2))
  } finally { for (const wallet of opened) wallet.close() }
}
void main().catch(error => { console.error(String(error)); process.exitCode = 1 })
