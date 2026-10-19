// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { Transaction } from 'bitcoinjs-lib'
import { bytesToHex, keyPairFromSecret, randomKeyPair, randomHex, canonicalJson, type KeyPair } from '../core/crypto.js'
import { PolicyGate, signPolicy, signRequest, signStop, type Decision } from '../governance/gate.js'
import { FileDecisionLog } from '../governance/log.js'
import { LocalFileFlaggedListProvider, signFlaggedManifest, type FlaggedSnapshot } from '../compliance/flagged.js'
import { SanctionsScreen } from '../compliance/sanctions.js'
import { VerifyService, type Attestation } from '../verify/incoming.js'
import { networkConfig } from '../network/config.js'
import { probeNetwork } from '../network/probe.js'
import { TestnetWallet } from './wallet.js'
import { incomingEvidence, publicExplorerEvidence } from './evidence.js'

const STARTED_AT = '2026-10-19T15:07:03Z'
const PRIMARY_DEADLINE = '2026-10-19T19:07:03Z'
interface Progress {
  invoices: Record<string, { invoice: string; recipientId: string }>
  txids: Record<string, string>
  decisions: Record<string, Decision>
  attestations: Record<string, Attestation>
  explorerChecks: Record<string, unknown>
  quarantine?: { enforced: boolean; reason: string }
}

async function loadKey(file: string): Promise<KeyPair> {
  try { return keyPairFromSecret((await readFile(file, 'utf8')).trim()) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    const key = randomKeyPair()
    await writeFile(file, `${bytesToHex(key.secretKey)}\n`, { mode: 0o600, flag: 'wx' })
    return key
  }
}

/** Repeatable journal: recorded broadcasts are resumed rather than sent a second time. */
export async function runTestnetDemo() {
  process.umask(0o077)
  const config = networkConfig()
  if (config.fallback && Date.now() < Date.parse(PRIMARY_DEADLINE)) throw new Error(`Primary network time box is still active until ${PRIMARY_DEADLINE}`)
  const probe = await probeNetwork(config)
  if (!probe.ready) throw new Error('Network/proxy identity probe failed; refusing wallet actions')
  const stateRoot = process.env.TRUST_STATE_DIR ?? '.state'
  const dir = resolve(stateRoot, config.name, 'demo')
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const asset = JSON.parse(await readFile(resolve(stateRoot, config.name, 'test-asset.json'), 'utf8')) as { assetId: string; label: string }
  if (asset.label !== 'test USD, not USDT') throw new Error('Wrong test-asset label')
  let progress: Progress
  try { progress = JSON.parse(await readFile(`${dir}/progress.json`, 'utf8')) as Progress }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; progress = { invoices: {}, txids: {}, decisions: {}, attestations: {}, explorerChecks: {} } }
  const keys = { owner: await loadKey(`${dir}/owner.key`), gate: await loadKey(`${dir}/gate.key`), agent: await loadKey(`${dir}/agent.key`), checker: await loadKey(`${dir}/checker.key`), issuer: await loadKey(`${dir}/issuer.key`) }
  const wallets: TestnetWallet[] = []
  const save = async (status: string, error?: string) => {
    await writeFile(`${dir}/progress.json`, `${JSON.stringify(progress, null, 2)}\n`, { mode: 0o600 })
    await mkdir('release', { recursive: true })
    const receipt = { version: 1, status, updatedAt: new Date().toISOString(), network: config.name, label: config.label, fallback: config.fallback, networkTimeBox: { startedAt: STARTED_AT, primaryDeadline: PRIMARY_DEADLINE }, asset, wallets: wallets.map(w => w.publicState()), transactions: progress.txids, explorerChecks: progress.explorerChecks, attestations: progress.attestations, authorization: progress.decisions, quarantine: progress.quarantine ?? { enforced: false, reason: 'not_run' }, privacy: 'Raw witness/prevout transactions, SDK state, test flagged list and all private keys remain only in ignored receiver-local .state.', ...(error ? { error } : {}) }
    await writeFile('release/testnet-receipt.json', `${JSON.stringify(receipt, null, 2)}\n`)
  }
  try {
    const sender = await TestnetWallet.open('A', config, stateRoot); wallets.push(sender)
    const receiver = await TestnetWallet.open('B', config, stateRoot); wallets.push(receiver)
    for (const [name, amount] of Object.entries({ clear: 1000, flagged: 500, overLimit: 1001, stopped: 100 })) if (!progress.invoices[name]) progress.invoices[name] = receiver.invoice(amount)
    await save('running')
    const log = new FileDecisionLog(`${dir}/decisions.jsonl`, keys.gate)
    const gate = new PolicyGate({ key: keys.gate, ownerPk: keys.owner.pubkey, network: config.name, walletId: sender.walletId, stateFile: `${dir}/gate-state.json`, log })
    const now = () => Math.floor(Date.now() / 1000)
    if (!gate.store.read().policy) gate.install(signPolicy({ v: 1, domain: 'trust-spending-policy-v1', version: 1, prevHash: null, network: config.name, walletId: sender.walletId, gatePk: keys.gate.pubkey, ownerPk: keys.owner.pubkey, walletAdapterPk: await sender.adapterPublicKey(), agentKeys: [keys.agent.pubkey], assetId: asset.assetId, maxPerSend: '1000', maxPerDay: '3000', maxBitcoinFeeSats: '3000', allowedRecipients: Object.values(progress.invoices).map(i => i.recipientId), notBefore: now() - 1, expiresAt: now() + 86_400, tokenTtlSeconds: 120 }, keys.owner))
    const authorize = async (name: string, amount: number) => {
      const plan = sender.prepareSend(progress.invoices[name].invoice, asset.assetId, amount)
      const preview = await sender.certifyPreview(plan)
      const decision = gate.authorize(signRequest({ v: 1, domain: 'trust-authorize-request-v1', requestId: randomHex(16), agentPk: keys.agent.pubkey, issuedAt: now(), expiresAt: now() + 120, plan, preview }, keys.agent))
      progress.decisions[name] = decision
      await save('running')
      return { plan, preview, decision }
    }
    const awaitSettled = async (txid: string) => {
      for (let attempt = 0; attempt < 120; attempt++) {
        receiver.refresh(); sender.refresh()
        const received = receiver.transfers().find(t => t.txid === txid && t.kind === 'ReceiveWitness')
        const sent = sender.transfers().find(t => t.txid === txid && t.kind === 'Send')
        if (received?.status === 'Failed' || sent?.status === 'Failed') throw new Error(`SDK failed transfer ${txid}`)
        if (received?.status === 'Settled' && sent?.status === 'Settled') return
        console.log(JSON.stringify({ txid, receiverStatus: received?.status, senderStatus: sent?.status, attempt }))
        await delay(15_000)
      }
      throw new Error(`Public chain did not settle transfer within the polling window: ${txid}`)
    }
    const send = async (name: string, amount: number) => {
      if (!progress.txids[name]) {
        const { plan, preview, decision } = await authorize(name, amount)
        if (!decision.allowed || !decision.token) throw new Error(`Expected in-limit send refused: ${decision.why.join(', ')}`)
        const sent = await sender.sendPrepared(plan, p => gate.consume(decision.token!, p, preview))
        progress.txids[name] = sent.txid
        await save('running')
      }
      await awaitSettled(progress.txids[name])
      progress.explorerChecks[name] = await publicExplorerEvidence(config, progress.txids[name])
      await save('running')
      return progress.txids[name]
    }
    const lists = `${dir}/flagged-list`
    await mkdir(lists, { recursive: true, mode: 0o700 })
    const writeList = async (version: string, outpoints: string[]) => {
      const list: FlaggedSnapshot = { v: 1, domain: 'trust-flagged-outpoints-v1', id: 'test-demo-flagged-outpoints', version, network: config.name, testOnly: true, outpoints }
      const bytes = Buffer.from(`${canonicalJson(list)}\n`)
      await writeFile(`${lists}/flagged-outpoints.json`, bytes, { mode: 0o600 })
      await writeFile(`${lists}/manifest.json`, `${JSON.stringify(signFlaggedManifest(list, 'flagged-outpoints.json', bytes, keys.issuer, now() - 1, now() + 86_400), null, 2)}\n`, { mode: 0o600 })
    }
    const verifier = new VerifyService({ key: keys.checker, network: config.name, sanctions: new SanctionsScreen(resolve('fixtures/sanctions'), undefined, { id: 'test-demo-sanctions', version: '1', addresses: [] }), flagged: new LocalFileFlaggedListProvider(lists, [keys.issuer.pubkey]), log: new FileDecisionLog(`${dir}/receiver-decisions.jsonl`, keys.checker), historyDir: `${dir}/receiver-history` })
    const clearTxid = await send('clear', 1000)
    if (!progress.attestations.clear) {
      await writeList('1', [])
      progress.attestations.clear = await verifier.verifyIncoming(await incomingEvidence(config, receiver, asset.assetId, clearTxid))
      if (progress.attestations.clear.overall !== 'clear') throw new Error('Actual incoming clear transfer did not receive a clear attestation')
      await save('running')
    }
    const flaggedTxid = await send('flagged', 500)
    if (!progress.attestations.flagged) {
      const evidence = await incomingEvidence(config, receiver, asset.assetId, flaggedTxid)
      const input = Transaction.fromHex(evidence.witnessRawHex).ins[0]
      await writeList('2', [`${Buffer.from(input.hash).reverse().toString('hex')}:${input.index}`])
      progress.attestations.flagged = await verifier.verifyIncoming(evidence)
      if (progress.attestations.flagged.overall !== 'flagged' || progress.attestations.flagged.checks.flaggedL1.status !== 'flagged') throw new Error('Actual matching witness input did not produce a flagged L1 attestation')
      await save('running')
    }
    await receiver.quarantine(asset.assetId)
    try { receiver.prepareSend(progress.invoices.clear.invoice, asset.assetId, 1); throw new Error('Receiver allowed a quarantined asset send') }
    catch (error) {
      if (!String(error).includes('ASSET_QUARANTINED')) throw error
      progress.quarantine = { enforced: true, reason: String(error) }
    }
    if (!progress.decisions.overLimit) {
      const result = await authorize('overLimit', 1001)
      if (result.decision.allowed || !result.decision.why.includes('PER_SEND_LIMIT_EXCEEDED')) throw new Error('Expected signed-policy over-limit refusal was not demonstrated')
    }
    if (!progress.decisions.stopped) {
      // A real prepared plan exists before stop; it still cannot obtain a new signing token afterward.
      const plan = sender.prepareSend(progress.invoices.stopped.invoice, asset.assetId, 100)
      const preview = await sender.certifyPreview(plan)
      gate.stop(signStop({ v: 1, domain: 'trust-stop-v1', id: randomHex(16), network: config.name, walletId: sender.walletId, gatePk: keys.gate.pubkey, ownerPk: keys.owner.pubkey, issuedAt: now(), expiresAt: now() + 120, reason: 'Meeting demo: owner stopped the agent wallet' }, keys.owner))
      progress.decisions.stopped = gate.authorize(signRequest({ v: 1, domain: 'trust-authorize-request-v1', requestId: randomHex(16), agentPk: keys.agent.pubkey, issuedAt: now(), expiresAt: now() + 120, plan, preview }, keys.agent))
      if (progress.decisions.stopped.allowed || !progress.decisions.stopped.why.includes('KILL_SWITCH_STOPPED')) throw new Error('Expected kill-switch refusal was not demonstrated')
    }
    if (log.verify().length) throw new Error('Authorization decision log verification failed')
    await save('complete')
    console.log(JSON.stringify({ status: 'complete', network: config.name, fallback: config.fallback, transactions: progress.txids, receipt: 'release/testnet-receipt.json' }, null, 2))
  } catch (error) { await save('incomplete', String(error)); throw error }
  finally { for (const wallet of wallets) wallet.close() }
}
