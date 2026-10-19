// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { createHash } from 'node:crypto'
import { connect } from 'node:tls'
import { networkConfig, proxyHttpUrl, type NetworkConfig } from './config.js'

export async function electrumCall(config: NetworkConfig, method: string, params: unknown[] = [], timeoutMs = 15_000): Promise<unknown> {
  const endpoint = new URL(config.indexerUrl)
  if (endpoint.protocol !== 'ssl:') throw new Error('This Electrum client requires TLS; use Esplora for fallback')
  return new Promise((resolve, reject) => {
    const socket = connect({ host: endpoint.hostname, port: Number(endpoint.port), servername: endpoint.hostname })
    let data = ''
    const finish = (error?: Error, result?: unknown) => { socket.destroy(); error ? reject(error) : resolve(result) }
    socket.setTimeout(timeoutMs, () => finish(new Error('Electrum request timed out')))
    socket.once('error', (error) => finish(error))
    socket.once('secureConnect', () => socket.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })}\n`))
    socket.on('data', (chunk) => {
      data += chunk.toString()
      if (data.length > 8_000_000) return finish(new Error('Electrum response too large'))
      for (const line of data.split('\n').slice(0, -1)) {
        try {
          const reply = JSON.parse(line) as { id?: number; error?: unknown; result?: unknown }
          if (reply.id === 1) return reply.error ? finish(new Error(JSON.stringify(reply.error))) : finish(undefined, reply.result)
        } catch (error) { return finish(error as Error) }
      }
    })
    socket.once('end', () => finish(new Error('Electrum closed without a response')))
  })
}

async function jsonFetch(url: string, init: RequestInit = {}): Promise<unknown> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) })
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${url}`)
  return response.json()
}

export function headerHash(hex: string): string {
  if (!/^[0-9a-f]{160}$/i.test(hex)) throw new Error('Invalid block header')
  return createHash('sha256').update(createHash('sha256').update(Buffer.from(hex, 'hex')).digest()).digest().reverse().toString('hex')
}

export async function probeNetwork(config = networkConfig()) {
  const startedAt = new Date().toISOString()
  const probes = await Promise.allSettled([
    config.sdkNetwork === 'testnet'
      ? Promise.all([electrumCall(config, 'server.features'), electrumCall(config, 'blockchain.block.header', [0]), electrumCall(config, 'blockchain.headers.subscribe')]).then(([features, rawHeader, tip]) => {
          const advertised = (features as { genesis_hash: string }).genesis_hash
          const actual = headerHash(String(rawHeader))
          if (advertised !== config.genesisHash || actual !== config.genesisHash) throw new Error(`Chain mismatch: advertised ${advertised}, decoded ${actual}`)
          return { verified: true, advertisedGenesis: advertised, decodedGenesis: actual, features, tip }
        })
      : fetch(`${config.esploraUrl}/block-height/0`, { signal: AbortSignal.timeout(20_000) }).then(async response => {
          if (!response.ok) throw new Error(`Esplora HTTP ${response.status}`)
          const genesis = (await response.text()).trim()
          if (genesis !== config.genesisHash) throw new Error(`Chain mismatch: ${genesis}`)
          // A signet genesis alone does not identify Mutinynet; its pinned endpoint and live tip must be recorded too.
          const tip = await jsonFetch(`${config.esploraUrl}/blocks`)
          return { verified: true, decodedGenesis: genesis, tip, identityScope: 'signet genesis plus configured Mutinynet endpoint; custom signet challenge not independently checked' }
        }),
    jsonFetch(proxyHttpUrl(config), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server.info', params: {} }) }).then(reply => {
      const data = reply as { error?: unknown; result?: { protocol_version?: string } }
      if (data.error || data.result?.protocol_version !== '0.2') throw new Error(`RGB proxy did not confirm protocol 0.2: ${JSON.stringify(reply)}`)
      return reply
    }),
  ])
  const [chain, proxy] = probes.map(result => result.status === 'fulfilled' ? { ok: true, evidence: result.value } : { ok: false, error: String(result.reason) })
  return { version: 1, startedAt, completedAt: new Date().toISOString(), network: config.name, label: config.label, fallback: config.fallback, config, chain, proxy, ready: Boolean(chain?.ok && proxy?.ok) }
}

export async function rawTransaction(config: NetworkConfig, txid: string): Promise<string> {
  if (!/^[a-f0-9]{64}$/.test(txid)) throw new Error('Invalid transaction id')
  if (config.sdkNetwork === 'testnet') return String(await electrumCall(config, 'blockchain.transaction.get', [txid, false]))
  const response = await fetch(`${config.esploraUrl}/tx/${txid}/hex`, { signal: AbortSignal.timeout(20_000) })
  if (!response.ok) throw new Error(`Transaction HTTP ${response.status}`)
  return (await response.text()).trim()
}
