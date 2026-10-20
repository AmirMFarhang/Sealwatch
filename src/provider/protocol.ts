// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
import type { Network } from "../core/validation.js";
export const PAYLOAD_TYPE = "application/vnd.attested-check.v1+json";
export interface CheckRequest {
  version: 1;
  request_id: string;
  issued_at: string;
  expires_at: string;
  check: "transfer-flow-risk" | "agent-action-review";
  network: Network;
  subject: Record<string, unknown>;
  evidence: { id: string; kind: string; sha256: string; data: unknown }[];
  context: Record<string, unknown>;
}
export interface Finding { code: string; evidence_ids: string[] }
export type CheckResult =
  | { kind: "transfer-flow-risk"; risk_band: "low" | "review" | "high"; findings: Finding[] }
  | { kind: "agent-action-review"; recommendation: "approve" | "escalate"; findings: Finding[] };
export interface ProviderRecord {
  version: 1;
  provider_id: string;
  request_id: string;
  request_sha256: string;
  issued_at: string;
  expires_at: string;
  workload: { id: string; version: string; sha256: string };
  model: { id: string; mode: string };
  policy: { id: string; sha256: string };
  input_scope: { evidence_ids: string[]; fields: string[] };
  result: CheckResult;
  execution: "software";
}
export interface EvidenceEnvelope {
  payloadType: string;
  payload: string;
  signatures: { keyid?: string; sig: string }[];
}
export interface ProviderResponse { result: ProviderRecord; evidence_envelope: EvidenceEnvelope }
export interface ProviderPin { provider_id: string; keyid: string; public_key_pem: string }
export interface VerifiedCheck {
  record: ProviderRecord;
  evidence_sha256: string;
  /** Absolute private path, never included in portable attestations. */
  evidence_file: string;
}
export interface AttestedCheckProvider { check(request: CheckRequest): Promise<VerifiedCheck> }
export type Outcome = "clear" | "flagged" | "error";
export function providerOutcome(result: CheckResult): Outcome {
  return result.kind === "transfer-flow-risk"
    ? result.risk_band === "low" ? "clear" : "flagged"
    : result.recommendation === "approve" ? "clear" : "flagged";
}
export function strictestOutcome(a: Outcome, b: Outcome): Outcome {
  return a === "error" || b === "error" ? "error" : a === "flagged" || b === "flagged" ? "flagged" : "clear";
}
