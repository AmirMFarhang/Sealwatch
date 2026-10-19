// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { hashObject, type KeyPair } from "../core/crypto.js";
import { SignedStore } from "../core/store.js";
import { assert, type Network } from "../core/validation.js";
import type { FileDecisionLog } from "../governance/log.js";
interface ReceiveRecord {
  attestationHash: string;
  witnessTxid: string;
  overall: "clear" | "flagged" | "error";
  at: number;
}
interface QuarantineState {
  receives: Record<string, ReceiveRecord[]>;
}
const id = (network: Network, walletId: string, assetId: string) =>
  hashObject({ network, walletId, assetId });
/** Conservative receiver-local policy: a flagged/error receive quarantines that asset in this wallet. No automatic unfreeze. */
export class ReceiverQuarantine {
  private store: SignedStore<QuarantineState>;
  constructor(
    readonly file: string,
    key: KeyPair,
    log: FileDecisionLog,
  ) {
    this.store = new SignedStore(
      file,
      key,
      () => {
        assert(
          !log.entries().some((e) => e.kind === "incoming-verification"),
          "receiver quarantine state missing beside prior verification history; refusing reset",
        );
        return { receives: {} };
      },
      { log, namespace: "receiver-quarantine" },
    );
  }
  record(
    network: Network,
    walletId: string,
    assetId: string,
    receive: ReceiveRecord,
  ): void {
    this.store.transact((s) => {
      const records = (s.receives[id(network, walletId, assetId)] ??= []);
      if (!records.some((r) => r.attestationHash === receive.attestationHash))
        records.push(receive);
    });
  }
  problems(network: Network, walletId: string, assetId: string): string[] {
    const rows =
      this.store.read().receives[id(network, walletId, assetId)] ?? [];
    return rows
      .filter((r) => r.overall !== "clear")
      .map((r) => `RECEIVER_ASSET_QUARANTINED_${r.overall.toUpperCase()}`);
  }
  assertSpendable(network: Network, walletId: string, assetId: string): void {
    const problems = this.problems(network, walletId, assetId);
    assert(!problems.length, problems.join("; "));
  }
}
