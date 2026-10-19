// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Synthetic transaction vectors for isolated unit tests; never claimed as chain transactions.
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Transaction, payments, networks, Psbt } from "bitcoinjs-lib";
import {
  hashObject,
  randomHex,
  randomKeyPair,
  signObject,
} from "../src/core/crypto.js";
import { atomicWrite } from "../src/core/store.js";
import { FileDecisionLog } from "../src/governance/log.js";
import {
  PolicyGate,
  signPolicy,
  signRequest,
  signStop,
  type SpendingPolicy,
} from "../src/governance/gate.js";
import {
  LocalFileFlaggedListProvider,
  signFlaggedManifest,
  type FlaggedSnapshot,
} from "../src/compliance/flagged.js";
import { SanctionsScreen } from "../src/compliance/sanctions.js";
import {
  VerifyService,
  type IncomingTransfer,
} from "../src/verify/incoming.js";
import { certifyPreview, type WalletSendPlan } from "../src/wallet/plan.js";
export const AT = 1792418400;
export const key = () => randomKeyPair();
export const temp = () => mkdtempSync(join(tmpdir(), "trust-core-"));
export function transactionVector() {
  const sender = key();
  const script = payments.p2wpkh({
    pubkey: Buffer.from(`02${sender.pubkey}`, "hex"),
    network: networks.testnet,
  }).output!;
  const parent = new Transaction();
  parent.addInput(Buffer.alloc(32), 0xffffffff);
  parent.addOutput(script, 10000n);
  const tx = new Transaction();
  tx.addInput(Buffer.from(parent.getId(), "hex").reverse(), 0);
  tx.addOutput(script, 9000n);
  const psbt = new Psbt({ network: networks.testnet })
    .addInput({
      hash: parent.getId(),
      index: 0,
      witnessUtxo: { script, value: 10000n },
    })
    .addOutput({ script, value: 9000n });
  return {
    parent,
    tx,
    script,
    psbt,
    senderAddress: payments.p2wpkh({
      pubkey: Buffer.from(`02${sender.pubkey}`, "hex"),
      network: networks.testnet,
    }).address!,
    outpoint: `${parent.getId()}:0`,
  };
}
export function flaggedFixture(
  dir: string,
  issuer = key(),
  outpoints: string[] = [],
  extra: Partial<FlaggedSnapshot> = {},
) {
  const list: FlaggedSnapshot = {
    v: 1,
    domain: "trust-flagged-outpoints-v1",
    id: "test-flagged-outpoints",
    version: "unit-v1",
    network: "utexo-testnet",
    testOnly: true,
    outpoints,
    ...extra,
  };
  const bytes = Buffer.from(JSON.stringify(list));
  atomicWrite(join(dir, "flagged-outpoints.json"), bytes.toString());
  const manifest = signFlaggedManifest(
    list,
    "flagged-outpoints.json",
    bytes,
    issuer,
    AT - 100,
    AT + 3600,
  );
  atomicWrite(join(dir, "manifest.json"), JSON.stringify(manifest));
  return {
    issuer,
    list,
    manifest,
    provider: new LocalFileFlaggedListProvider(dir, [issuer.pubkey]),
  };
}
export function incomingFixture(
  options: { sanctioned?: boolean; flagged?: boolean } = {},
) {
  const dir = temp();
  const k = key();
  const v = transactionVector();
  const f = flaggedFixture(
    join(dir, "flags"),
    key(),
    options.flagged ? [v.outpoint] : [],
  );
  const screen = new SanctionsScreen(
    resolve("fixtures/sanctions"),
    undefined,
    options.sanctioned
      ? {
          id: "test-sanctions",
          version: "unit-v1",
          addresses: [v.senderAddress],
        }
      : undefined,
  );
  const log = new FileDecisionLog(join(dir, "decision-log.jsonl"), k, () => AT);
  const service = new VerifyService({
    key: k,
    network: "utexo-testnet",
    sanctions: screen,
    flagged: f.provider,
    log,
    historyDir: join(dir, "history"),
    now: () => AT,
  });
  const input: IncomingTransfer = {
    network: "utexo-testnet",
    assetId: "rgb:test-usd-not-usdt",
    receiverWalletId: "B-unit-only",
    receivedAt: AT,
    witnessTxid: v.tx.getId(),
    witnessRawHex: v.tx.toHex(),
    previousTransactions: { [v.parent.getId()]: v.parent.toHex() },
  };
  return { dir, key: k, log, service, input, vector: v, flags: f };
}
export function gateFixture() {
  const dir = temp();
  const owner = key(),
    gateKey = key(),
    agent = key(),
    adapter = key();
  let at = AT;
  const log = new FileDecisionLog(
    join(dir, "decision-log.jsonl"),
    gateKey,
    () => at,
  );
  const gateOptions = {
    key: gateKey,
    ownerPk: owner.pubkey,
    network: "utexo-testnet" as const,
    walletId: "A-unit-only",
    stateFile: join(dir, "gate.json"),
    log,
    now: () => at,
  };
  const gate = new PolicyGate(gateOptions);
  const policy = signPolicy(
    {
      v: 1,
      domain: "trust-spending-policy-v1",
      version: 1,
      prevHash: null,
      network: "utexo-testnet",
      walletId: "A-unit-only",
      gatePk: gateKey.pubkey,
      ownerPk: owner.pubkey,
      walletAdapterPk: adapter.pubkey,
      agentKeys: [agent.pubkey],
      assetId: "rgb:test-usd-not-usdt",
      maxPerSend: "100",
      maxPerDay: "150",
      maxBitcoinFeeSats: "2000",
      allowedRecipients: ["receiver-B"],
      notBefore: AT - 10,
      expiresAt: AT + 3600,
      tokenTtlSeconds: 60,
    },
    owner,
  );
  const plan = (amount = "50"): WalletSendPlan => ({
    kind: "rgb-send",
    network: "utexo-testnet",
    walletId: "A-unit-only",
    assetId: policy.assetId,
    amount,
    recipientId: "receiver-B",
    invoice: "rgb:unit-fixture-invoice",
    decodedInvoice: {
      recipientId: "receiver-B",
      assetId: null,
      network: "testnet",
      amount: null,
      transportEndpoints: ["rpcs://proxy.example.test/json-rpc"],
    },
    recipientMap: {
      [policy.assetId]: [
        {
          recipientId: "receiver-B",
          witnessData: { amountSat: "1000", blinding: null },
          assignment: { Fungible: Number(amount) },
          transportEndpoints: ["rpcs://proxy.example.test/json-rpc"],
        },
      ],
    },
    unsignedPsbt: transactionVector().psbt.toBase64(),
  });
  const request = (p = plan()) =>
    signRequest(
      {
        v: 1,
        domain: "trust-authorize-request-v1",
        requestId: randomHex(16),
        agentPk: agent.pubkey,
        issuedAt: at,
        expiresAt: at + 120,
        plan: p,
        preview: certifyPreview(p, adapter),
      },
      agent,
    );
  const stop = () =>
    signStop(
      {
        v: 1,
        domain: "trust-stop-v1",
        id: randomHex(16),
        network: "utexo-testnet",
        walletId: "A-unit-only",
        gatePk: gateKey.pubkey,
        ownerPk: owner.pubkey,
        issuedAt: at,
        expiresAt: at + 120,
        reason: "unit test stop",
      },
      owner,
    );
  return {
    dir,
    owner,
    gateKey,
    agent,
    adapter,
    log,
    gate,
    gateOptions,
    policy,
    plan,
    request,
    stop,
    setTime: (value: number) => {
      at = value;
    },
    getTime: () => at,
  };
}
