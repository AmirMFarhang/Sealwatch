// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Adapted from PassBook src/checknode/tee.ts (Apache-2.0); original attribution and terms in NOTICE.
// The root -> leaf -> document, key, measurement, fresh report and result-signature
// checks follow that verifier pattern. Replay persistence adds a signed local journal.
import {
  hashObject,
  isHex,
  sha256Hex,
  verifyHash,
  type KeyPair,
} from "../core/crypto.js";
import { SignedStore } from "../core/store.js";
import { assert, integer, publicKey } from "../core/validation.js";
import { FileDecisionLog } from "../governance/log.js";
import { CURRENT_EXECUTION, type Execution } from "./types.js";

export type QuoteVendor =
  | "aws-nitro"
  | "intel-tdx"
  | "amd-sev-snp"
  | "apple-app-attest"
  | "android-key-attestation"
  | "test-vendor";
export interface QuoteEvidence {
  vendor: QuoteVendor;
  document: string;
  /** The actual result commitment signed by the key bound into the quote. */
  commitmentHash: string;
  resultSignature: string;
}
export interface QuoteContext {
  /** Receiver-selected release and challenge, not values accepted from the quote. */
  releaseId: string;
  requestNonce: string;
  commitmentHash: string;
  resultKey: string;
}
export interface QuoteCheck {
  id: string;
  ok: boolean;
  detail: string;
}
export interface QuoteVerification {
  verified: boolean;
  execution: Execution;
  /** A successful test fixture must never be presented as real hardware evidence. */
  testOnly: boolean;
  vendor: QuoteVendor;
  quoteSha256: string | null;
  checks: QuoteCheck[];
}
export interface QuoteVerifier {
  verify(evidence: QuoteEvidence, context: QuoteContext): QuoteVerification;
}
/**
 * No real vendor parser/root-chain verifier is built. Configuration or a claimed
 * label cannot turn software into hardware evidence. This remains the default.
 */
export class SoftwareOnlyQuoteVerifier implements QuoteVerifier {
  verify(evidence: QuoteEvidence, _context: QuoteContext): QuoteVerification {
    return {
      verified: false,
      execution: CURRENT_EXECUTION,
      testOnly: evidence.vendor === "test-vendor",
      vendor: evidence.vendor,
      quoteSha256:
        typeof evidence.document === "string"
          ? sha256Hex(evidence.document)
          : null,
      checks: [
        {
          id: "vendor-verifier",
          ok: false,
          detail:
            "No real hardware or device quote verifier is built; pinned vendor-root validation and an approved measurement are required.",
        },
      ],
    };
  }
}
export interface TestVendorDocument {
  vendor: "test-vendor";
  measurement: string;
  publicKey: string;
  reportData: string;
  timestamp: number;
  leafPk: string;
  leafSignature: string;
  sig: string;
}
export function testVendorLeafHash(leafPk: string): string {
  return hashObject({ domain: "trust-test-vendor-leaf-v1", leafPk });
}
export function testVendorDocumentHash(
  document: Omit<TestVendorDocument, "sig">,
): string {
  return hashObject({ domain: "trust-test-vendor-quote-v1", ...document });
}
export function quoteReportData(context: QuoteContext): string {
  return hashObject({
    domain: "trust-quote-report-v1",
    releaseId: context.releaseId,
    requestNonce: context.requestNonce,
    commitmentHash: context.commitmentHash,
    resultKey: context.resultKey,
  });
}
interface ReplayState {
  nonces: Record<
    string,
    { quoteSha256: string; commitmentHash: string; at: number }
  >;
}
export interface TestVendorQuoteOptions {
  /** Test-only pinned root, supplied by the caller's trusted local configuration. */
  rootPk: string;
  /** Approved release -> measurement mapping. No measurement is trusted from the request. */
  approvedMeasurements: Readonly<Record<string, string>>;
  maxAgeSeconds?: number;
  now?: () => number;
  replay: { file: string; key: KeyPair; log: FileDecisionLog };
}
/**
 * Positive fixture verifier for the five PassBook checks. A successful fixture
 * returns verified:true but execution:'software', testOnly:true. It cannot grant
 * any tee:* or device:* label, and no test root is shipped in runtime config.
 */
export class TestVendorQuoteVerifier implements QuoteVerifier {
  private readonly replay: SignedStore<ReplayState>;
  private readonly rootPk: string;
  private readonly now: () => number;
  private readonly measurements: ReadonlyMap<string, string>;
  private readonly maxAgeSeconds: number;
  constructor(private readonly options: TestVendorQuoteOptions) {
    publicKey(options.rootPk, "test vendor root");
    this.rootPk = options.rootPk;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.measurements = new Map(Object.entries(options.approvedMeasurements));
    assert(
      this.measurements.size > 0 &&
        [...this.measurements.values()].every(
          (v) => typeof v === "string" && v.length > 0,
        ),
      "approved test vendor release measurements are required",
    );
    this.maxAgeSeconds = options.maxAgeSeconds ?? 600;
    integer(this.maxAgeSeconds, "max quote age");
    assert(
      this.maxAgeSeconds > 0 && this.maxAgeSeconds <= 3600,
      "max quote age must be 1..3600 seconds",
    );
    this.replay = new SignedStore<ReplayState>(
      options.replay.file,
      options.replay.key,
      () => ({ nonces: {} }),
      {
        log: options.replay.log,
        namespace: `quote-replay:test-vendor:${options.rootPk}`,
      },
    );
  }
  verify(evidence: QuoteEvidence, context: QuoteContext): QuoteVerification {
    const checks: QuoteCheck[] = [];
    const tick = (id: string, ok: boolean, detail: string) =>
      checks.push({ id, ok, detail });
    const response = (
      verified = false,
      quoteSha256: string | null = null,
    ): QuoteVerification => ({
      verified,
      execution: CURRENT_EXECUTION,
      testOnly: true,
      vendor: evidence.vendor,
      quoteSha256,
      checks,
    });
    if (evidence.vendor !== "test-vendor") {
      tick(
        "vendor",
        false,
        "The fixture verifier never verifies real hardware or device documents.",
      );
      return response();
    }
    let doc: TestVendorDocument;
    let quoteHash: string;
    let at: number;
    try {
      assert(
        typeof evidence.document === "string" &&
          evidence.document.length > 0 &&
          evidence.document.length <= 64 * 1024,
        "test quote document must be bounded JSON",
      );
      doc = JSON.parse(evidence.document);
      assert(
        doc?.vendor === "test-vendor" &&
          typeof doc.measurement === "string" &&
          doc.measurement.length > 0,
        "not a test-vendor quote",
      );
      publicKey(doc.publicKey, "quote result key");
      publicKey(doc.leafPk, "quote leaf key");
      integer(doc.timestamp, "quote timestamp");
      assert(
        isHex(doc.reportData, 32) &&
          isHex(doc.leafSignature, 64) &&
          isHex(doc.sig, 64),
        "quote document signature/report shape invalid",
      );
      publicKey(context.resultKey, "expected result key");
      assert(
        typeof context.releaseId === "string" &&
          context.releaseId.length > 0 &&
          context.releaseId.length <= 512 &&
          isHex(context.requestNonce, 32) &&
          isHex(context.commitmentHash, 32) &&
          isHex(evidence.commitmentHash, 32) &&
          isHex(evidence.resultSignature, 64),
        "quote context or result signature malformed",
      );
      at = this.now();
      integer(at, "quote verification time");
      quoteHash = sha256Hex(evidence.document);
    } catch (error) {
      tick("document", false, (error as Error).message);
      return response();
    }
    const { sig, ...unsigned } = doc;
    const rootOk = verifyHash(
      doc.leafSignature,
      testVendorLeafHash(doc.leafPk),
      this.rootPk,
    );
    const documentOk = verifyHash(
      sig,
      testVendorDocumentHash(unsigned),
      doc.leafPk,
    );
    tick(
      "vendor-chain",
      rootOk && documentOk,
      "The pinned test root signs the leaf; the leaf signs this exact document.",
    );
    tick(
      "enclave-key",
      doc.publicKey === context.resultKey,
      "The test document binds the expected result signing key.",
    );
    const measurement = this.measurements.get(context.releaseId);
    tick(
      "measurement",
      !!measurement && measurement === doc.measurement,
      "The measured test release must equal a locally approved measurement.",
    );
    tick(
      "fresh-report",
      doc.reportData === quoteReportData(context) &&
        doc.timestamp <= at &&
        at - doc.timestamp <= this.maxAgeSeconds,
      "The report binds this receiver challenge, release and result; future or stale reports are refused.",
    );
    tick(
      "result-signature",
      evidence.commitmentHash === context.commitmentHash &&
        verifyHash(
          evidence.resultSignature,
          context.commitmentHash,
          context.resultKey,
        ),
      "The quote-bound key must sign the receiver-expected result commitment.",
    );
    if (checks.some((c) => !c.ok)) return response(false, quoteHash);
    try {
      this.replay.transact((state) => {
        const nonceId = hashObject({
          rootPk: this.rootPk,
          nonce: context.requestNonce,
        });
        assert(
          !Object.hasOwn(state.nonces, nonceId),
          "QUOTE_REPLAY: this test-vendor challenge was already consumed",
        );
        state.nonces[nonceId] = {
          quoteSha256: quoteHash,
          commitmentHash: context.commitmentHash,
          at,
        };
      });
      tick(
        "replay",
        true,
        "Receiver challenge consumed in the persistent signed replay journal.",
      );
    } catch (error) {
      tick("replay", false, (error as Error).message);
      return response(false, quoteHash);
    }
    return response(true, quoteHash);
  }
}
