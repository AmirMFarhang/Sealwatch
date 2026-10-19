// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
export type NetworkName = 'utexo-testnet' | 'mutinynet'
export interface NetworkConfig {
  name: NetworkName
  label: string
  fallback: boolean
  sdkNetwork: 'testnet' | 'signet'
  indexerUrl: string
  transportEndpoint: string
  genesisHash: string
  esploraUrl: string
  explorerUrl: string
  faucets: string[]
}

export const NETWORKS: Readonly<Record<NetworkName, Readonly<NetworkConfig>>> = Object.freeze({
  'utexo-testnet': Object.freeze({
    name: 'utexo-testnet', label: 'Utexo SDK documented Bitcoin testnet3', fallback: false,
    sdkNetwork: 'testnet', indexerUrl: 'ssl://electrum.iriswallet.com:50013',
    transportEndpoint: 'rpcs://proxy.iriswallet.com/0.2/json-rpc',
    genesisHash: '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
    esploraUrl: 'https://mempool.space/testnet/api', explorerUrl: 'https://mempool.space/testnet/tx',
    faucets: ['https://coinfaucet.eu/en/btc-testnet/', 'https://bitcoinfaucet.uo1.net/'],
  }),
  mutinynet: Object.freeze({
    name: 'mutinynet', label: 'Mutinynet fallback (custom Bitcoin signet)', fallback: true,
    sdkNetwork: 'signet', indexerUrl: 'https://esplora.signet.kaleidoswap.com',
    transportEndpoint: 'rpcs://proxy.kaleidoswap.com/json-rpc',
    genesisHash: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
    esploraUrl: 'https://esplora.signet.kaleidoswap.com', explorerUrl: 'https://mutinynet.com/tx',
    faucets: ['https://faucet.mutinynet.com'],
  }),
})

/** This single switch controls SDK network, endpoints, explorer and faucet together. */
export function networkConfig(value = process.env.TRUST_NETWORK ?? 'utexo-testnet'): Readonly<NetworkConfig> {
  if (value !== 'utexo-testnet' && value !== 'mutinynet') throw new Error('TRUST_NETWORK must be utexo-testnet or mutinynet; real-money networks are forbidden')
  return NETWORKS[value]
}

export function proxyHttpUrl(config: NetworkConfig): string {
  return config.transportEndpoint.replace(/^rpcs:/, 'https:').replace(/^rpc:/, 'http:')
}

export function transactionUrl(config: NetworkConfig, txid: string): string {
  if (!/^[a-f0-9]{64}$/.test(txid)) throw new Error('Invalid transaction id')
  return `${config.explorerUrl}/${txid}`
}
