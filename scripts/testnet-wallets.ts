// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { TestnetWallet } from '../src/testnet/wallet.js'
import { networkConfig } from '../src/network/config.js'

async function main() {
  const config = networkConfig()
  const stateRoot = process.env.TRUST_STATE_DIR ?? '.state'
  const command = process.argv[2] ?? 'status'
  if (!['status', 'create-utxos', 'issue'].includes(command)) throw new Error('Usage: testnet-wallets.ts [status|create-utxos|issue]')
  const opened: TestnetWallet[] = []
  try {
    for (const name of ['A', 'B'] as const) opened.push(await TestnetWallet.open(name, config, stateRoot))
    for (const wallet of opened) wallet.refresh()
    if (command === 'create-utxos') {
      for (const wallet of opened) {
        const balance = wallet.publicState().btcBalance as { vanilla: { spendable: number; settled: number }; colored: { spendable: number; settled: number } }
        if (balance.colored.spendable >= 40_000) continue
        if (balance.vanilla.spendable < 45_000 || balance.vanilla.settled < 45_000) throw new Error(`${wallet.name} needs at least 45,000 confirmed faucet sats for eight 5,000-sat colorable outputs and fees`)
        console.log(JSON.stringify({ wallet: wallet.name, createdColorableOutputs: await wallet.createUtxos() }))
      }
    }
    if (command === 'issue') {
      const file = resolve(stateRoot, config.name, 'test-asset.json')
      try { console.log(await readFile(file, 'utf8')) }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        const assetId = opened[0].issueTestAsset()
        const asset = { network: config.name, fallback: config.fallback, label: 'test USD, not USDT', ticker: 'TUSD', precision: 2, amount: 1_000_000, assetId, issuedAt: new Date().toISOString() }
        await mkdir(resolve(stateRoot, config.name), { recursive: true, mode: 0o700 })
        await writeFile(file, `${JSON.stringify(asset, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
        console.log(JSON.stringify(asset))
      }
    }
    console.log(JSON.stringify({ network: config.name, fallback: config.fallback, wallets: opened.map(w => w.publicState()) }, null, 2))
  } finally { for (const wallet of opened) wallet.close() }
}
void main().catch(error => { console.error(String(error)); process.exitCode = 1 })
