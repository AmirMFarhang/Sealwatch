// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { Transaction, address, networks } from "bitcoinjs-lib";
import { isHex } from "../core/crypto.js";
import { assert, network, type Network } from "../core/validation.js";
export interface WitnessEvidence {
  witnessTxid: string;
  witnessRawHex: string;
  previousTransactions: Record<string, string>;
}
export interface DecodedWitness {
  txid: string;
  inputOutpoints: string[];
  senderAddresses: string[];
  outputAddresses: string[];
}
function outputAddress(script: Uint8Array): string {
  // Address encoding needs the witness program, not an ECC signing context.
  // bitcoinjs-lib's P2TR payment matcher requires ECC initialization even when
  // only decoding an address. Both supported chains use the testnet HRP.
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return address.toBech32(script.slice(2), 1, networks.testnet.bech32);
  }
  return address.fromOutputScript(script, networks.testnet);
}
export function decodeWitness(e: WitnessEvidence, n: Network): DecodedWitness {
  network(n);
  assert(
    isHex(e.witnessTxid, 32) &&
      isHex(e.witnessRawHex) &&
      e.witnessRawHex.length > 0,
    "witness transaction id/raw hex malformed",
  );
  const tx = Transaction.fromHex(e.witnessRawHex);
  assert(
    tx.getId() === e.witnessTxid,
    "raw witness transaction id does not match the received transfer",
  );
  assert(
    tx.ins.length > 0 && tx.outs.length > 0,
    "witness transaction must have inputs and outputs",
  );
  const inputOutpoints: string[] = [];
  const senderAddresses: string[] = [];
  for (const input of tx.ins) {
    const previousTxid = Buffer.from(input.hash).reverse().toString("hex");
    assert(
      previousTxid !== "0".repeat(64),
      "coinbase cannot be an incoming RGB witness",
    );
    inputOutpoints.push(`${previousTxid}:${input.index}`);
    const previous = e.previousTransactions?.[previousTxid];
    assert(
      typeof previous === "string",
      `missing previous transaction ${previousTxid}; cannot screen sending address`,
    );
    const parent = Transaction.fromHex(previous);
    assert(parent.getId() === previousTxid, "previous transaction id mismatch");
    const output = parent.outs[input.index];
    assert(output, "witness input prevout does not exist");
    try {
      senderAddresses.push(outputAddress(output.script));
    } catch {
      throw new Error(
        "sender script has no supported Bitcoin address; sanctions screening incomplete",
      );
    }
  }
  assert(
    new Set(inputOutpoints).size === inputOutpoints.length,
    "duplicate witness inputs",
  );
  const outputAddresses: string[] = [];
  for (const out of tx.outs) {
    try {
      outputAddresses.push(outputAddress(out.script));
    } catch {
      /* OP_RETURN commitments have no address */
    }
  }
  return {
    txid: tx.getId(),
    inputOutpoints,
    senderAddresses: [...new Set(senderAddresses)],
    outputAddresses,
  };
}
