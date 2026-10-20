// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { join } from "node:path";
import {
  canonicalJson,
  hashObject,
  signObject,
  verifyObject,
  type KeyPair,
} from "../core/crypto.js";
import { atomicWrite, withFileLock } from "../core/store.js";
import {
  assert,
  integer,
  network,
  text,
  type Network,
} from "../core/validation.js";
import {
  type FlaggedListProvider,
  type FlaggedManifest,
} from "../compliance/flagged.js";
import { SanctionsScreen, type ListInfo } from "../compliance/sanctions.js";
import { FileDecisionLog } from "../governance/log.js";
import { decodeWitness, type WitnessEvidence } from "./witness.js";
import { ReceiverQuarantine } from "../wallet/quarantine.js";
import { CURRENT_EXECUTION } from "../execution/types.js";
export interface IncomingTransfer extends WitnessEvidence {
  network: Network;
  assetId: string;
  receiverWalletId: string;
  receivedAt: number;
  counterpartyAddresses?: string[];
  senderAddresses?: string[];
}
export interface Check {
  status: "clear" | "flagged" | "error" | "designed";
  scope: string;
  code: string;
}
interface AttestationFields {
  network: Network;
  assetId: string;
  witnessTxid: string;
  checks: { sanctions: Check; flaggedL1: Check; rgbAncestry: Check };
  lists: ListInfo[];
  flaggedManifest: FlaggedManifest;
  overall: "clear" | "flagged" | "error";
  time: number;
  checkerPk: string;
  sig: string;
}
/** Historical records retain their original signed shape; no execution is inferred into it. */
export interface LegacyAttestation extends AttestationFields {
  v: 1;
  domain: "trust-incoming-attestation-v1";
  execution?: never;
}
/** Newly issued records explicitly describe today's software execution. */
export interface SoftwareAttestation extends AttestationFields {
  v: 2;
  domain: "trust-incoming-attestation-v2";
  execution: typeof CURRENT_EXECUTION;
}
export type Attestation = LegacyAttestation | SoftwareAttestation;
export interface AttestationTrust {
  checkerPk: string;
  flaggedIssuerKeys: readonly string[];
  network?: Network;
  sanctionsListPins?: readonly string[];
  now?: number;
  maxAgeSeconds?: number;
}
export function attestationProblems(
  a: Attestation,
  trust: AttestationTrust,
): string[] {
  const errors: string[] = [];
  try {
    if (
      !(
        (a.v === 1 &&
          a.domain === "trust-incoming-attestation-v1" &&
          !Object.hasOwn(a, "execution")) ||
        (a.v === 2 &&
          a.domain === "trust-incoming-attestation-v2" &&
          a.execution === CURRENT_EXECUTION)
      ) ||
      a.checkerPk !== trust.checkerPk ||
      !verifyObject(a, trust.checkerPk)
    )
      errors.push("attestation signature/checker trust invalid");
    network(a.network);
    integer(a.time, "attestation time");
    text(a.assetId, "assetId");
    if (trust.network && a.network !== trust.network)
      errors.push("attestation network mismatch");
    const now = trust.now ?? Math.floor(Date.now() / 1000);
    if (
      a.time > now ||
      (trust.maxAgeSeconds !== undefined && now - a.time > trust.maxAgeSeconds)
    )
      errors.push("attestation time outside trusted window");
    const m = a.flaggedManifest;
    if (
      m.v !== 1 ||
      m.domain !== "trust-flagged-manifest-v1" ||
      !trust.flaggedIssuerKeys.includes(m.issuerPk) ||
      !verifyObject(m, m.issuerPk)
    )
      errors.push(
        "flagged-list issuer untrusted or manifest signature invalid",
      );
    if (m.network !== a.network || a.time < m.issuedAt || a.time >= m.expiresAt)
      errors.push(
        "flagged-list manifest not valid at attestation time/network",
      );
    if (
      !a.lists.some(
        (l) =>
          l.id === m.listId &&
          l.version === m.version &&
          l.sha256 === m.sha256 &&
          l.testOnly === m.testOnly,
      )
    )
      errors.push("flagged-list identity/hash missing from attestation");
    if (
      trust.sanctionsListPins &&
      a.lists.some(
        (l) =>
          l.id !== m.listId &&
          !l.testOnly &&
          !trust.sanctionsListPins!.includes(l.sha256),
      )
    )
      errors.push("sanctions snapshot hash untrusted");
    const required = [a.checks.sanctions, a.checks.flaggedL1];
    const overall = required.some((c) => c.status === "error")
      ? "error"
      : required.some((c) => c.status === "flagged")
        ? "flagged"
        : "clear";
    if (
      required.some((c) => !["clear", "flagged", "error"].includes(c.status)) ||
      a.overall !== overall ||
      a.checks.rgbAncestry.status !== "designed"
    )
      errors.push("attestation check/result semantics invalid");
  } catch {
    errors.push("attestation malformed");
  }
  return errors;
}
export class VerifyService {
  readonly quarantine: ReceiverQuarantine;
  constructor(
    private options: {
      key: KeyPair;
      network: Network;
      receiverWalletId?: string;
      sanctions: SanctionsScreen;
      flagged: FlaggedListProvider;
      log: FileDecisionLog;
      historyDir: string;
      now?: () => number;
    },
  ) {
    this.quarantine = new ReceiverQuarantine(
      join(options.historyDir, "quarantine-state.json"),
      options.key,
      options.log,
    );
  }
  async verifyIncoming(input: IncomingTransfer): Promise<SoftwareAttestation> {
    const o = this.options;
    const at = o.now?.() ?? Math.floor(Date.now() / 1000);
    network(input.network);
    assert(
      input.network === o.network,
      "incoming network differs from configured receiver",
    );
    if (o.receiverWalletId)
      assert(
        input.receiverWalletId === o.receiverWalletId,
        "incoming receiver wallet differs from configured wallet",
      );
    text(input.assetId, "assetId");
    text(input.receiverWalletId, "receiverWalletId");
    integer(input.receivedAt, "receivedAt");
    assert(input.receivedAt <= at, "incoming receive time is in the future");
    const flagged = await o.flagged.load(input.network, at); // An untrusted/tampered list is refused, never converted to clear.
    let sanctions: Check = {
      status: "error",
      scope:
        "decoded witness sending addresses and receiver-local counterparties",
      code: "WITNESS_EVIDENCE_INVALID",
    };
    let flaggedL1: Check = {
      status: "error",
      scope: "decoded witness transaction input outpoints",
      code: "WITNESS_EVIDENCE_INVALID",
    };
    let privateDetail: unknown = null;
    try {
      const decoded = decodeWitness(input, input.network);
      if (input.senderAddresses)
        assert(
          input.senderAddresses.every((a) =>
            decoded.senderAddresses.includes(a),
          ),
          "claimed sending address is not in the decoded prevouts",
        );
      assert(
        !input.counterpartyAddresses ||
          input.counterpartyAddresses.every(
            (a) => typeof a === "string" && a.length > 0,
          ),
        "counterparty addresses malformed",
      );
      const screen = o.sanctions.screen([
        ...decoded.senderAddresses,
        ...(input.counterpartyAddresses ?? []),
      ]);
      const hits = decoded.inputOutpoints.filter((p) =>
        flagged.outpoints.has(p),
      );
      sanctions = {
        status: screen.status,
        scope: sanctions.scope,
        code:
          screen.status === "clear" ? "NOT_ON_PINNED_LISTS" : "SANCTIONS_HIT",
      };
      flaggedL1 = {
        status: hits.length ? "flagged" : "clear",
        scope: flaggedL1.scope,
        code: hits.length
          ? "FLAGGED_WITNESS_INPUT"
          : "NO_FLAGGED_WITNESS_INPUT",
      };
      privateDetail = {
        decoded,
        sanctionsHits: screen.hits,
        flaggedInputs: hits,
      };
    } catch (e) {
      privateDetail = { error: (e as Error).message };
    }
    const overall: Attestation["overall"] = [sanctions, flaggedL1].some(
      (c) => c.status === "error",
    )
      ? "error"
      : [sanctions, flaggedL1].some((c) => c.status === "flagged")
        ? "flagged"
        : "clear";
    const attestation = signObject(
      {
        v: 2 as const,
        domain: "trust-incoming-attestation-v2" as const,
        execution: CURRENT_EXECUTION,
        network: input.network,
        assetId: input.assetId,
        witnessTxid: input.witnessTxid,
        checks: {
          sanctions,
          flaggedL1,
          rgbAncestry: {
            status: "designed" as const,
            scope: "RGB consignment ancestry",
            code: "SDK_RELIABLE_ANCESTRY_API_REQUIRED",
          },
        },
        lists: [...o.sanctions.lists, flagged.info],
        flaggedManifest: flagged.manifest,
        overall,
        time: at,
        checkerPk: o.key.pubkey,
      },
      o.key.secretKey,
    );
    const id = hashObject(attestation);
    // Full evidence is written only to a private receiver-local file, never to the portable attestation.
    withFileLock(join(o.historyDir, "receiver-history"), () => {
      atomicWrite(
        join(o.historyDir, `${id}.json`),
        canonicalJson({ input, privateDetail, attestation }) + "\n",
      );
      this.quarantine.record(
        input.network,
        input.receiverWalletId,
        input.assetId,
        { attestationHash: id, witnessTxid: input.witnessTxid, overall, at },
      );
      o.log.append("incoming-verification", overall, {
        attestationHash: id,
        witnessTxid: input.witnessTxid,
        assetId: input.assetId,
        listVersions: attestation.lists.map((l) => ({
          id: l.id,
          version: l.version,
          sha256: l.sha256,
        })),
        historyFile: `${id}.json`,
      });
    });
    return attestation;
  }
}
