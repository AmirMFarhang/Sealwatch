// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { Psbt, Transaction } from "bitcoinjs-lib";
import {
  hashObject,
  signObject,
  verifyObject,
  type KeyPair,
} from "../core/crypto.js";
import {
  assert,
  network,
  text,
  units,
  type Network,
} from "../core/validation.js";
export interface Recipient {
  recipientId: string;
  witnessData: { amountSat: string; blinding: null };
  assignment: { Fungible: number | string };
  transportEndpoints: string[];
}
export interface WalletSendPlan {
  kind: "rgb-send";
  network: Network;
  walletId: string;
  assetId: string;
  amount: string;
  recipientId: string;
  invoice: string;
  decodedInvoice: {
    recipientId: string;
    assetId: string | null;
    network: string;
    amount: string | null;
    transportEndpoints: string[];
  };
  recipientMap: Record<string, Recipient[]>;
  unsignedPsbt: string;
}
export interface DecodedSend {
  network: Network;
  walletId: string;
  assetId: string;
  amount: string;
  recipientId: string;
  unsignedTxid: string;
  inputs: string[];
  outputs: { scriptHex: string; valueSats: string }[];
  bitcoinFeeSats: string;
  psbtHash: string;
  recipientMapHash: string;
  invoiceHash: string;
}
export interface WalletPreview {
  v: 1;
  domain: "trust-wallet-preview-v1";
  planHash: string;
  adapterPk: string;
  sig: string;
}
export function decodeSendPlan(plan: WalletSendPlan): DecodedSend {
  assert(plan.kind === "rgb-send", "only RGB sends are supported");
  network(plan.network);
  text(plan.walletId, "walletId");
  text(plan.assetId, "assetId");
  text(plan.recipientId, "recipientId");
  text(plan.invoice, "invoice");
  assert(units(plan.amount) > 0n, "send amount must be positive");
  const assets = Object.keys(plan.recipientMap);
  assert(
    assets.length === 1 && assets[0] === plan.assetId,
    "recipient map must contain exactly the requested asset",
  );
  const recipients = plan.recipientMap[plan.assetId];
  assert(
    Array.isArray(recipients) && recipients.length === 1,
    "one recipient per authorized send is required",
  );
  const r = recipients[0];
  assert(
    r.recipientId === plan.recipientId,
    "recipient map destination mismatch",
  );
  const amount = r.assignment.Fungible;
  assert(
    (typeof amount === "number" &&
      Number.isSafeInteger(amount) &&
      amount > 0) ||
      typeof amount === "string",
    "native RGB amount must be a safe integer or canonical integer string",
  );
  assert(
    units(String(amount)) === units(plan.amount),
    "recipient map amount mismatch",
  );
  assert(Object.keys(r.assignment).length === 1, "unexpected RGB assignment");
  assert(
    units(r.witnessData.amountSat) > 0n && r.witnessData.blinding === null,
    "invalid witness funding",
  );
  assert(
    Array.isArray(r.transportEndpoints) &&
      r.transportEndpoints.length > 0 &&
      r.transportEndpoints.every(
        (x) => typeof x === "string" && /^rpcs?:\/\//.test(x),
      ),
    "missing RGB transport endpoint",
  );
  const invoice = plan.decodedInvoice;
  assert(
    invoice.recipientId === r.recipientId &&
      (!invoice.assetId || invoice.assetId === plan.assetId) &&
      (!invoice.amount || units(invoice.amount) === units(plan.amount)),
    "decoded invoice recipient/asset/amount mismatch",
  );
  const expectedNetwork =
    plan.network === "utexo-testnet" ? "testnet" : "signet";
  assert(
    invoice.network === expectedNetwork,
    "decoded invoice network mismatch",
  );
  assert(
    hashObject([...invoice.transportEndpoints].sort()) ===
      hashObject([...r.transportEndpoints].sort()),
    "decoded invoice transport mismatch",
  );
  const psbt = /^[0-9a-f]+$/i.test(plan.unsignedPsbt)
    ? Psbt.fromHex(plan.unsignedPsbt)
    : Psbt.fromBase64(plan.unsignedPsbt);
  assert(
    psbt.inputCount > 0 && psbt.txOutputs.length > 0,
    "empty PSBT cannot be authorized",
  );
  for (const i of psbt.data.inputs)
    assert(
      !i.partialSig &&
        !i.tapKeySig &&
        !i.tapScriptSig &&
        !i.finalScriptSig &&
        !i.finalScriptWitness,
      "preview PSBT is already signed",
    );
  const unsigned = Transaction.fromBuffer(
    psbt.data.globalMap.unsignedTx.toBuffer(),
  );
  const inputs = unsigned.ins.map(
    (i) => `${Buffer.from(i.hash).reverse().toString("hex")}:${i.index}`,
  );
  assert(new Set(inputs).size === inputs.length, "PSBT has duplicate inputs");
  let valueIn = 0n;
  psbt.data.inputs.forEach((i, index) => {
    if (i.witnessUtxo) valueIn += i.witnessUtxo.value;
    else if (i.nonWitnessUtxo) {
      const previous = Transaction.fromBuffer(i.nonWitnessUtxo);
      assert(
        previous.getId() === inputs[index].split(":")[0],
        "PSBT prevout transaction mismatch",
      );
      const out = previous.outs[unsigned.ins[index].index];
      assert(out, "PSBT missing previous output");
      valueIn += out.value;
    } else
      throw new Error("PSBT lacks previous output values; cannot bound fee");
  });
  const valueOut = unsigned.outs.reduce((v, o) => v + o.value, 0n);
  assert(valueIn >= valueOut, "PSBT outputs exceed inputs");
  return {
    network: plan.network,
    walletId: plan.walletId,
    assetId: plan.assetId,
    amount: plan.amount,
    recipientId: plan.recipientId,
    unsignedTxid: unsigned.getId(),
    inputs,
    outputs: unsigned.outs.map((o) => ({
      scriptHex: Buffer.from(o.script).toString("hex"),
      valueSats: String(o.value),
    })),
    bitcoinFeeSats: String(valueIn - valueOut),
    psbtHash: hashObject({ psbt: plan.unsignedPsbt }),
    recipientMapHash: hashObject(plan.recipientMap),
    invoiceHash: hashObject({
      invoice: plan.invoice,
      decodedInvoice: plan.decodedInvoice,
    }),
  };
}
export const sendPlanHash = (plan: WalletSendPlan): string =>
  hashObject({
    domain: "trust-decoded-send-v1",
    decoded: decodeSendPlan(plan),
  });
/** Called only inside the receiver-owned wallet adapter, after native invoice decode/sendBegin. Never expose its signing key to an agent. */
export function certifyPreview(
  plan: WalletSendPlan,
  key: KeyPair,
): WalletPreview {
  return signObject(
    {
      v: 1 as const,
      domain: "trust-wallet-preview-v1" as const,
      planHash: sendPlanHash(plan),
      adapterPk: key.pubkey,
    },
    key.secretKey,
  );
}
export function previewValid(
  plan: WalletSendPlan,
  preview: WalletPreview,
  expectedAdapterPk: string,
): boolean {
  return (
    preview.v === 1 &&
    preview.domain === "trust-wallet-preview-v1" &&
    preview.adapterPk === expectedAdapterPk &&
    verifyObject(preview, expectedAdapterPk) &&
    preview.planHash === sendPlanHash(plan)
  );
}
