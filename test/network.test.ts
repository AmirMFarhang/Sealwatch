// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import test from 'node:test'
import assert from 'node:assert/strict'
import { networkConfig, proxyHttpUrl, transactionUrl } from '../src/network/config.js'
import { headerHash } from '../src/network/probe.js'

const genesis = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'
test('raw Bitcoin testnet3 genesis header independently matches pinned identity', () => {
  assert.equal(headerHash(genesis), networkConfig('utexo-testnet').genesisHash)
  assert.notEqual(headerHash(`${genesis.slice(0, -2)}00`), networkConfig('utexo-testnet').genesisHash)
  assert.throws(() => headerHash('00'), /Invalid block header/)
})
test('real-money and unrecognized network selections fail closed', () => {
  for (const name of ['mainnet', 'bitcoin', 'testnet4', 'regtest', '']) assert.throws(() => networkConfig(name), /TRUST_NETWORK/)
})
test('fallback selector changes SDK chain, transport and explorer as a single profile', () => {
  const config = networkConfig('mutinynet')
  assert.equal(config.fallback, true)
  assert.equal(config.sdkNetwork, 'signet')
  assert.equal(proxyHttpUrl(config), 'https://proxy.kaleidoswap.com/json-rpc')
  assert.equal(transactionUrl(config, 'a'.repeat(64)), `https://mutinynet.com/tx/${'a'.repeat(64)}`)
  assert.throws(() => transactionUrl(config, '../secret'))
})
