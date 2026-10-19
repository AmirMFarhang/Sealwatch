// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import './native-runtime.js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import WDK from '@tetherto/wdk'
import WalletManagerRgb from '@utexo/wdk-wallet-rgb'
import { networkConfig, type NetworkConfig } from '../network/config.js'

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
  getRgbWallet(): { client: NativeClient; getBtcBalance(): unknown; getAssetBalance(asset: string): unknown }
  createUtxos(params: { upTo: boolean; num: number; size: number; feeRate: number }): Promise<number>
  issueAssetNia(params: { ticker: string; name: string; precision: number; amounts: number[] }): { assetId?: string }
  receiveAsset(params: { witness: boolean; amount: number; minConfirmations: number; durationSeconds: number }): { invoice: string; recipientId: string }
  refreshWallet(): void
  signPsbt(psbt: string): Promise<string>
  sendEnd(params: { signedPsbt: string }): { txid: string; batchTransferIdx: number }
  toReadOnlyAccount(): { _wallet?: { dispose(): void } }
  dispose(): void
}

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
  private readonly policyViews: { _wallet?: { dispose(): void } }[] = []
  private readonly quarantinedAssets = new Set<string>()
  private adapterKey?: import('../core/crypto.js').KeyPair
  private governed?: Account
  private constructor(readonly name: string, readonly walletId: string, readonly config: NetworkConfig, readonly dataDir: string, private readonly depositAddress: string, private readonly account: Account, private readonly wdk: WDK) {}

  static async open(name: 'A' | 'B', config = networkConfig(), stateRoot = '.state'): Promise<TestnetWallet> {
    process.umask(0o077)
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
    try { for (const assetId of JSON.parse(await readFile(`${dataDir}/quarantine.json`, 'utf8')) as string[]) wallet.quarantinedAssets.add(assetId) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
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

  /** Prepare exact native PSBT; donation=true is required by the pinned SDK stack. */
  prepareSend(invoice: string, assetId: string, amount: number): PreparedSend {
    if (this.quarantinedAssets.has(assetId)) throw new Error('ASSET_QUARANTINED: receiver trust check flagged an incoming transfer')
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

  /** Coarse local receiver policy: any flagged receive freezes this asset in this wallet. */
  async quarantine(assetId: string): Promise<void> {
    this.quarantinedAssets.add(assetId)
    await writeFile(`${this.dataDir}/quarantine.json`, `${JSON.stringify([...this.quarantinedAssets])}\n`, { mode: 0o600 })
  }

  private async enrollPolicy(): Promise<void> {
    if (this.governed) return
    this.wdk.registerPolicy({ id: 'trust-layer-send', name: 'Trust layer: one consumed approval per PSBT', scope: 'project', wallet: 'rgb', rules: [
      { name: 'requires-consumed-approval', reason: 'No consumed trust-layer approval for this exact PSBT', operation: 'signPsbt', action: 'DENY', conditions: [(context: { args: readonly unknown[] }) => !this.allowedPsbts.has(String(context.args[0]))] },
      { name: 'other-calls', operation: '*', action: 'ALLOW', conditions: [] },
    ] } as never)
    const original = this.account.toReadOnlyAccount
    this.account.toReadOnlyAccount = () => { const view = original.call(this.account); this.policyViews.push(view); return view }
    try { this.governed = await this.wdk.getAccount('rgb', 0) as unknown as Account }
    finally { this.account.toReadOnlyAccount = original }
  }

  /** consume must verify a one-use signed gate token immediately before signing. */
  async sendPrepared(plan: PreparedSend, consume: (plan: PreparedSend) => unknown | Promise<unknown>) {
    plan = structuredClone(plan)
    if (this.quarantinedAssets.has(plan.assetId)) throw new Error('ASSET_QUARANTINED')
    const hash = this.psbtHash(plan.unsignedPsbt)
    if (this.prepared.get(hash) !== JSON.stringify(plan)) throw new Error('Prepared send changed or was not generated by this wallet')
    await this.enrollPolicy()
    await consume(structuredClone(plan))
    this.prepared.delete(hash)
    this.allowedPsbts.add(plan.unsignedPsbt)
    let signedPsbt: string
    try { signedPsbt = await this.governed!.signPsbt(plan.unsignedPsbt) }
    finally { this.allowedPsbts.delete(plan.unsignedPsbt) }
    return this.account.sendEnd({ signedPsbt })
  }

  close() { for (const view of this.policyViews.splice(0)) view._wallet?.dispose(); this.account.dispose() }
}
