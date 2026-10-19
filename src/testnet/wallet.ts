// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Adapts Satstride src/rgb/wallet.ts SDK quirks and WDK signing guard (Apache-2.0); see NOTICE.
import './native-runtime.js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import WDK from '@tetherto/wdk'
import WalletManagerRgb from '@utexo/wdk-wallet-rgb'
import { Psbt } from 'bitcoinjs-lib'
import { networkConfig, type NetworkConfig } from '../network/config.js'
import type { GateToken, PolicyGate } from '../governance/gate.js'
import type { WalletPreview } from '../wallet/plan.js'
import { ReceiverQuarantine } from '../wallet/quarantine.js'
import { FileDecisionLog } from '../governance/log.js'
import { hashObject } from '../core/crypto.js'
import { SignedStore } from '../core/store.js'
import type { Attestation } from '../verify/incoming.js'

interface DecodedInvoice {
  recipientId: string; assetId?: string; network: string
  assignment: { Fungible?: number }; transportEndpoints: string[]; expirationTimestamp?: number
}
interface NativeClient {
  getOnline(): unknown
  decodeRGBInvoice(params: { invoice: string }): DecodedInvoice
  wallet: {
    sendBegin(online: unknown, recipientMap: unknown, donation: boolean, feeRate: string, minConfirmations: string): string
    listTransfers(asset: string | null): Record<string, unknown>[]
  }
}
interface Account {
  getAddress(): string
  getRgbWallet(): { client: NativeClient; getBtcBalance(): unknown; getAssetBalance(asset: string): unknown; sendBtcBegin(params: { address: string; amount: number; feeRate: number }): string; sendBtcEnd(params: { signedPsbt: string }): string }
  createUtxos(params: { upTo: boolean; num: number; size: number; feeRate: number }): Promise<number>
  issueAssetNia(params: { ticker: string; name: string; precision: number; amounts: number[] }): { assetId?: string }
  receiveAsset(params: { witness: boolean; amount: number; minConfirmations: number; durationSeconds: number }): { invoice: string; recipientId: string }
  refreshWallet(): void
  signPsbt(psbt: string): Promise<string>
  sendEnd(params: { signedPsbt: string }): { txid: string; batchTransferIdx: number }
  toReadOnlyAccount(): { _wallet?: { dispose(): void } }
  dispose(): void
}
interface GateBinding { domain: string; network: string; walletId: string; gatePk: string; ownerPk: string; stateFile: string }

export interface PreparedSend {
  kind: 'rgb-send'
  network: NetworkConfig['name']
  walletId: string
  assetId: string
  amount: string
  recipientId: string
  invoice: string
  decodedInvoice: { recipientId: string; assetId: string | null; network: string; amount: string | null; transportEndpoints: string[] }
  recipientMap: Record<string, { recipientId: string; witnessData: { amountSat: string; blinding: null }; assignment: { Fungible: number }; transportEndpoints: string[] }[]>
  unsignedPsbt: string
}

/** Private local wallet adapter. Seeds and SDK wallet databases never leave stateRoot. */
export class TestnetWallet {
  private readonly prepared = new Map<string, string>()
  private readonly allowedPsbts = new Set<string>()
  private readonly signingAssets = new Map<string, string>()
  private readonly policyViews: { _wallet?: { dispose(): void } }[] = []
  private quarantineStore?: ReceiverQuarantine
  private gateBindingStore?: SignedStore<{ binding: GateBinding | null }>
  private adapterKey?: import('../core/crypto.js').KeyPair
  private gate?: PolicyGate
  private governed?: Account
  private constructor(readonly name: string, readonly walletId: string, readonly config: NetworkConfig, readonly dataDir: string, private readonly depositAddress: string, private readonly account: Account, private readonly wdk: WDK) {}

  static async open(name: 'A' | 'B', config = networkConfig(), stateRoot = '.state'): Promise<TestnetWallet> {
    process.umask(0o077)
    const expected = networkConfig(config.name)
    if (config.sdkNetwork !== expected.sdkNetwork || config.indexerUrl !== expected.indexerUrl || config.transportEndpoint !== expected.transportEndpoint || config.genesisHash !== expected.genesisHash) throw new Error('Wallet configuration differs from the selected fixed test-network profile')
    const dataDir = resolve(stateRoot, config.name, name)
    await mkdir(dataDir, { recursive: true, mode: 0o700 })
    let seed: string
    try { seed = (await readFile(`${dataDir}/wallet.seed`, 'utf8')).trim() }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      seed = WDK.getRandomSeedPhrase(12)
      await writeFile(`${dataDir}/wallet.seed`, `${seed}\n`, { mode: 0o600, flag: 'wx' })
    }
    const wdk = new WDK(seed).registerWallet('rgb', WalletManagerRgb as never, { network: config.sdkNetwork, indexerUrl: config.indexerUrl, transportEndpoint: config.transportEndpoint, dataDir: `${dataDir}/rgb` } as never)
    const account = await wdk.getAccount('rgb', 0) as unknown as Account
    let depositAddress: string | undefined
    try { depositAddress = (JSON.parse(await readFile(`${dataDir}/public.json`, 'utf8')) as { address?: string }).address }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    const wallet = new TestnetWallet(name, `${config.name}:${name}`, config, dataDir, depositAddress ?? account.getAddress(), account, wdk)
    try { await readFile(`${dataDir}/quarantine.json`); throw new Error('Legacy unsigned quarantine state requires reviewed migration; refusing wallet reset') }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    const adapterKey = await wallet.localAdapterKey()
    const walletLog = new FileDecisionLog(`${dataDir}/wallet-decisions.jsonl`, adapterKey)
    wallet.quarantineStore = new ReceiverQuarantine(`${dataDir}/quarantine-state.json`, adapterKey, walletLog)
    wallet.gateBindingStore = new SignedStore(`${dataDir}/wallet-gate-state.json`, adapterKey, () => ({ binding: null }), { log: walletLog, namespace: `wallet-gate:${wallet.walletId}` })
    try { await readFile(`${dataDir}/gate-binding.json`); throw new Error('Legacy unjournaled gate binding requires reviewed migration') }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    wallet.gateBindingStore.read()
    await writeFile(`${dataDir}/public.json`, `${JSON.stringify(wallet.publicState(), null, 2)}\n`, { mode: 0o600 })
    return wallet
  }

  private get client(): NativeClient { return this.account.getRgbWallet().client }
  publicState() { return { name: this.name, walletId: this.walletId, network: this.config.name, fallback: this.config.fallback, address: this.depositAddress, btcBalance: this.account.getRgbWallet().getBtcBalance() } }
  balance(assetId: string) { return this.account.getRgbWallet().getAssetBalance(assetId) }
  refresh() { this.account.refreshWallet() }
  transfers(assetId?: string) { return this.client.wallet.listTransfers(assetId ?? null) }
  createUtxos(num = 8, size = 5000) { return this.account.createUtxos({ upTo: true, num, size, feeRate: 1 }) }
  issueTestAsset(amount = 1_000_000): string {
    const asset = this.account.issueAssetNia({ ticker: 'TUSD', name: 'test USD, not USDT', precision: 2, amounts: [amount] })
    if (!asset.assetId) throw new Error('SDK issuance did not return an asset id')
    return asset.assetId
  }
  invoice(amount: number) {
    // Leave asset unspecified for a receiver that has not yet learned the contract.
    return this.account.receiveAsset({ witness: true, amount, minConfirmations: 1, durationSeconds: 14_400 })
  }

  /** Setup only: split public-faucet BTC between these two brand-new wallets before RGB use. */
  async fundNewPeer(peer: TestnetWallet, amount = 65_000) {
    if (this.governed || this.config.name !== peer.config.name || this.name !== 'B' || peer.name !== 'A') throw new Error('Faucet split is limited to fresh B -> A setup on the same test network')
    if (this.transfers().some(t => t.txid)) throw new Error('Faucet split must precede any RGB transaction')
    const sdk = this.account.getRgbWallet()
    const unsignedPsbt = sdk.sendBtcBegin({ address: peer.depositAddress, amount, feeRate: 1 })
    const psbt = /^[a-f0-9]+$/i.test(unsignedPsbt) ? Psbt.fromHex(unsignedPsbt) : Psbt.fromBase64(unsignedPsbt)
    let inputs = 0n
    for (const input of psbt.data.inputs) {
      if (!input.witnessUtxo) throw new Error('Faucet split PSBT lacks input value')
      inputs += input.witnessUtxo.value
    }
    const outputs = psbt.txOutputs.reduce((sum, output) => sum + output.value, 0n)
    const fee = inputs - outputs
    if (fee <= 0n || fee > 3000n) throw new Error('Faucet split fee exceeds setup budget')
    const signedPsbt = await this.account.signPsbt(unsignedPsbt)
    const txid = sdk.sendBtcEnd({ signedPsbt })
    return { txid, amountSats: amount, feeSats: String(fee), senderWalletId: this.walletId, receiverWalletId: peer.walletId, receiverAddress: peer.depositAddress, source: 'Public testnet faucet funded newly created B; setup split to newly created A only' }
  }

  /** Prepare exact native PSBT; donation=true is required by the pinned SDK stack. */
  prepareSend(invoice: string, assetId: string, amount: number): PreparedSend {
    this.quarantineStore!.assertSpendable(this.config.name, this.walletId, assetId)
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('Amount must be a positive safe integer in the asset smallest unit')
    const decoded = this.client.decodeRGBInvoice({ invoice })
    if (decoded.assetId && decoded.assetId !== assetId) throw new Error('Invoice asset mismatch')
    if (decoded.network.toLowerCase() !== this.config.sdkNetwork) throw new Error('Invoice network mismatch')
    if (decoded.assignment?.Fungible && decoded.assignment.Fungible !== amount) throw new Error('Invoice amount mismatch')
    if (!decoded.recipientId.includes(':wvout:')) throw new Error('Demo requires witness receive mode')
    if (decoded.expirationTimestamp && decoded.expirationTimestamp * 1000 <= Date.now()) throw new Error('Invoice expired')
    const recipientMap = { [assetId]: [{ recipientId: decoded.recipientId, witnessData: { amountSat: '1000', blinding: null }, assignment: { Fungible: amount }, transportEndpoints: [...decoded.transportEndpoints] }] }
    const unsignedPsbt = this.client.wallet.sendBegin(this.client.getOnline(), recipientMap, true, '1', '1')
    const decodedInvoice = { recipientId: decoded.recipientId, assetId: decoded.assetId ?? null, network: decoded.network.toLowerCase(), amount: decoded.assignment?.Fungible === undefined ? null : String(decoded.assignment.Fungible), transportEndpoints: [...decoded.transportEndpoints] }
    const plan: PreparedSend = { kind: 'rgb-send', network: this.config.name, walletId: this.walletId, assetId, amount: String(amount), recipientId: decoded.recipientId, invoice, decodedInvoice, recipientMap, unsignedPsbt }
    this.prepared.set(this.psbtHash(unsignedPsbt), JSON.stringify(plan))
    return structuredClone(plan)
  }

  private psbtHash(psbt: string) { return createHash('sha256').update(psbt).digest('hex') }

  private async localAdapterKey() {
    const { keyPairFromSecret, randomKeyPair, bytesToHex } = await import('../core/crypto.js')
    if (this.adapterKey) return this.adapterKey
    try { this.adapterKey = keyPairFromSecret((await readFile(`${this.dataDir}/adapter.key`, 'utf8')).trim()) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      this.adapterKey = randomKeyPair()
      await writeFile(`${this.dataDir}/adapter.key`, `${bytesToHex(this.adapterKey.secretKey)}\n`, { mode: 0o600, flag: 'wx' })
    }
    return this.adapterKey
  }
  async adapterPublicKey(): Promise<string> { return (await this.localAdapterKey()).pubkey }
  async certifyPreview(plan: PreparedSend) {
    if (this.prepared.get(this.psbtHash(plan.unsignedPsbt)) !== JSON.stringify(plan)) throw new Error('Cannot certify a plan not generated by this wallet')
    const { certifyPreview } = await import('../wallet/plan.js')
    return certifyPreview(plan, await this.localAdapterKey())
  }

  /** Owner setup pins the actual gate; agents cannot inject a callback or replace its authority. */
  async bindGate(gate: PolicyGate): Promise<void> {
    if (gate.options.network !== this.config.name || gate.options.walletId !== this.walletId) throw new Error('Gate wallet/network mismatch')
    const binding = { domain: 'trust-wallet-gate-binding-v1', network: this.config.name, walletId: this.walletId, gatePk: gate.options.key.pubkey, ownerPk: gate.options.ownerPk, stateFile: resolve(gate.options.stateFile) }
    const stored = this.gateBindingStore!.read().binding
    if (stored && hashObject(stored) !== hashObject(binding)) throw new Error('Wallet gate binding changed or was tampered with')
    if (!stored) this.gateBindingStore!.transact(state => { state.binding = binding })
    this.gate = gate
  }

  /** Coarse local receiver policy: any flagged receive freezes this asset in this wallet. */
  async quarantine(assetId: string, attestation: Attestation): Promise<void> {
    if (attestation.assetId !== assetId || attestation.network !== this.config.name || attestation.overall === 'clear') throw new Error('Quarantine requires a matching flagged/error attestation')
    this.quarantineStore!.record(this.config.name, this.walletId, assetId, { attestationHash: hashObject(attestation), witnessTxid: attestation.witnessTxid, overall: attestation.overall, at: attestation.time })
  }

  private async enrollPolicy(): Promise<void> {
    if (this.governed) return
    this.wdk.registerPolicy({ id: 'trust-layer-send', name: 'Trust layer: one consumed approval per PSBT', scope: 'project', wallet: 'rgb', rules: [
      { name: 'requires-consumed-approval', reason: 'No consumed trust-layer approval or asset quarantined for this exact PSBT', operation: 'signPsbt', action: 'DENY', conditions: [(context: { args: readonly unknown[] }) => {
        const psbt = String(context.args[0]); const assetId = this.signingAssets.get(psbt)
        if (!this.allowedPsbts.has(psbt) || !assetId) return true
        try { this.quarantineStore!.assertSpendable(this.config.name, this.walletId, assetId); return false }
        catch { return true }
      }] },
      { name: 'other-calls', operation: '*', action: 'ALLOW', conditions: [] },
    ] } as never)
    const original = this.account.toReadOnlyAccount
    this.account.toReadOnlyAccount = () => { const view = original.call(this.account); this.policyViews.push(view); return view }
    try { this.governed = await this.wdk.getAccount('rgb', 0) as unknown as Account }
    finally { this.account.toReadOnlyAccount = original }
  }

  /** The pinned gate burns a one-use signed approval immediately before this exact PSBT is signed. */
  async sendPrepared(plan: PreparedSend, token: GateToken, preview: WalletPreview) {
    plan = structuredClone(plan)
    if (!this.gate) throw new Error('Wallet has no pinned policy gate')
    this.quarantineStore!.assertSpendable(this.config.name, this.walletId, plan.assetId)
    const hash = this.psbtHash(plan.unsignedPsbt)
    if (this.prepared.get(hash) !== JSON.stringify(plan)) throw new Error('Prepared send changed or was not generated by this wallet')
    await this.enrollPolicy()
    // Enrollment awaits WDK; an incoming verification may quarantine the asset meanwhile.
    this.quarantineStore!.assertSpendable(this.config.name, this.walletId, plan.assetId)
    this.gate.consume(token, structuredClone(plan), structuredClone(preview))
    this.prepared.delete(hash)
    this.allowedPsbts.add(plan.unsignedPsbt)
    this.signingAssets.set(plan.unsignedPsbt, plan.assetId)
    let signedPsbt: string
    try { signedPsbt = await this.governed!.signPsbt(plan.unsignedPsbt) }
    finally { this.allowedPsbts.delete(plan.unsignedPsbt); this.signingAssets.delete(plan.unsignedPsbt) }
    return this.account.sendEnd({ signedPsbt })
  }

  close() { for (const view of this.policyViews.splice(0)) view._wallet?.dispose(); this.account.dispose() }
}
