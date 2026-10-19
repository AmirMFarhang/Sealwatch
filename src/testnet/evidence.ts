// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { Transaction } from 'bitcoinjs-lib'
import type { NetworkConfig } from '../network/config.js'
import { rawTransaction } from '../network/probe.js'
import type { IncomingTransfer } from '../verify/incoming.js'
import type { TestnetWallet } from './wallet.js'

export async function incomingEvidence(config: NetworkConfig, receiver: TestnetWallet, assetId: string, witnessTxid: string): Promise<IncomingTransfer> {
  // RGB asset/receive membership comes from the receiver's own SDK database, not agent input.
  const transfer = receiver.transfers(assetId).find(t => t.txid === witnessTxid && t.kind === 'ReceiveWitness' && t.status === 'Settled')
  if (!transfer) throw new Error('The receiver SDK has no settled witness receive for this asset/transaction')
  const witnessRawHex = await rawTransaction(config, witnessTxid)
  const tx = Transaction.fromHex(witnessRawHex)
  if (tx.getId() !== witnessTxid) throw new Error('Indexer returned a different witness transaction')
  const previousTransactions: Record<string, string> = {}
  for (const input of tx.ins) {
    const previousTxid = Buffer.from(input.hash).reverse().toString('hex')
    if (!(previousTxid in previousTransactions)) previousTransactions[previousTxid] = await rawTransaction(config, previousTxid)
  }
  return { network: config.name, assetId, receiverWalletId: receiver.walletId, receivedAt: Math.floor(Date.now() / 1000), witnessTxid, witnessRawHex, previousTransactions }
}

export async function publicExplorerEvidence(config: NetworkConfig, txid: string) {
  const response = await fetch(`${config.esploraUrl}/tx/${txid}`, { signal: AbortSignal.timeout(20_000) })
  if (!response.ok) throw new Error(`Public explorer could not verify ${txid}: HTTP ${response.status}`)
  const tx = await response.json() as { txid: string; status: { confirmed: boolean; block_height?: number; block_hash?: string } }
  if (tx.txid !== txid || !tx.status.confirmed) throw new Error('Public explorer does not confirm the exact transaction')
  return { checkedAt: new Date().toISOString(), explorerUrl: `${config.explorerUrl}/${txid}`, apiUrl: `${config.esploraUrl}/tx/${txid}`, txid: tx.txid, confirmed: true, blockHeight: tx.status.block_height, blockHash: tx.status.block_hash }
}
