// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
import { Transaction } from "bitcoinjs-lib";
import { randomHex, hashObject } from "../core/crypto.js";
import { assert } from "../core/validation.js";
import { networkConfig } from "../network/config.js";
import { decodeWitness } from "../verify/witness.js";
import type { IncomingTransfer } from "../verify/incoming.js";
import type { CheckRequest } from "./protocol.js";
export type TransferEvidenceSource = (input: IncomingTransfer) => Promise<CheckRequest["evidence"]>;
export function transferRequest(input: IncomingTransfer, evidence: CheckRequest["evidence"], now = Date.now()): CheckRequest {
  return { version: 1, request_id: randomHex(32), issued_at: new Date(now).toISOString(), expires_at: new Date(now + 300_000).toISOString(), check: "transfer-flow-risk", network: input.network, subject: { witness_txid: input.witnessTxid, asset_id: input.assetId }, evidence, context: { scope: "receiver-held-context-and-bounded-public-chain", complete_rgb_history: false } };
}
/** Bounded public neighborhood, deliberately never described as full graph coverage. */
export const collectPublicTransferEvidence: TransferEvidenceSource = async (input) => {
  const decoded = decodeWitness(input, input.network);
  const config = networkConfig(input.network);
  const json = async (path: string): Promise<any> => {
    const response = await fetch(`${config.esploraUrl}${path}`, { signal: AbortSignal.timeout(20_000), redirect: "error" });
    assert(response.ok, "public chain evidence unavailable");
    const body = await response.text(); assert(Buffer.byteLength(body) <= 512 * 1024, "public chain evidence too large");
    return JSON.parse(body);
  };
  const witness = await json(`/tx/${input.witnessTxid}`);
  assert(witness.txid === input.witnessTxid && witness.status?.confirmed, "provider proof requires a confirmed witness");
  // Check the explorer's anchor/input/output facts against receiver-held raw bytes.
  const tx = Transaction.fromHex(input.witnessRawHex);
  assert(witness.vin.length === tx.ins.length && witness.vout.length === tx.outs.length, "public witness structure differs from raw transaction");
  tx.ins.forEach((v, i) => {
    const id = Buffer.from(v.hash).reverse().toString("hex"); const prev = Transaction.fromHex(input.previousTransactions[id]);
    assert(witness.vin[i].txid === id && witness.vin[i].vout === v.index && witness.vin[i].prevout.value === Number(prev.outs[v.index].value) && witness.vin[i].prevout.scriptpubkey === Buffer.from(prev.outs[v.index].script).toString("hex"), "public witness prevout differs from receiver bytes");
  });
  tx.outs.forEach((v, i) => assert(witness.vout[i].value === Number(v.value) && witness.vout[i].scriptpubkey === Buffer.from(v.script).toString("hex"), "public witness output differs from receiver bytes"));
  const transactions = new Map<string, any>();
  const addresses = [...new Set([...decoded.senderAddresses, ...decoded.outputAddresses])].slice(0, 16);
  for (const address of addresses) {
    const rows = await json(`/address/${encodeURIComponent(address)}/txs`);
    assert(Array.isArray(rows), "public address history malformed");
    for (const row of rows.slice(0, 6)) {
      if (transactions.size >= 64) break;
      if (row?.status?.confirmed && typeof row.txid === "string") transactions.set(row.txid, row);
    }
  }
  const receiverContext: Record<string, unknown> = { witness_txid: input.witnessTxid, asset_id: input.assetId, received_at: input.receivedAt };
  if (input.consignmentSha256) { assert(/^[0-9a-f]{64}$/.test(input.consignmentSha256), "consignment digest malformed"); receiverContext.consignment_sha256 = input.consignmentSha256; }
  const values = [
    { id: "witness", kind: "bitcoin-transaction", data: witness },
    { id: "public-neighborhood", kind: "bitcoin-neighborhood", data: { transactions: [...transactions.values()], complete: false, scope: "bounded-public-chain" } },
    { id: "receiver-context", kind: "receiver-context", data: receiverContext },
  ];
  return values.map(e => ({ ...e, sha256: hashObject(e.data) }));
};
