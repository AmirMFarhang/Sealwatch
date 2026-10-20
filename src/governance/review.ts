// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
import { hashObject, isHex, randomHex } from "../core/crypto.js";
import { assert, integer, units } from "../core/validation.js";
import { validateRequest } from "../provider/dsse.js";
import type { CheckRequest, VerifiedCheck } from "../provider/protocol.js";
import { decodeSendPlan, sendPlanHash } from "../wallet/plan.js";
import type { GateToken, SendRequest, SpendingPolicy } from "./gate.js";

export interface AgentReviewPolicy {
  /** Sends strictly above this amount need a provider review. */
  softLimit: string;
  /** Sends strictly above this amount are refused until an actual human flow exists. */
  humanThreshold: string;
  providerId: string;
  maxReviewSeconds: number;
}
export interface AgentReviewSummary {
  providerId: string;
  evidenceSha256: string;
  resultRecordHash: string;
  requestHash: string;
  planHash: string;
  policyHash: string;
  recommendation: "approve" | "escalate";
  reasonCodes: string[];
  execution: "software";
  expiresAt: number;
}
export function validateReviewPolicy(policy: SpendingPolicy): void {
  const review = policy.review;
  if (review === undefined) return;
  assert(
    review && typeof review === "object" && !Array.isArray(review),
    "invalid review policy",
  );
  assert(
    units(review.softLimit) < units(review.humanThreshold) &&
      units(review.humanThreshold) <= units(policy.maxPerSend),
    "review thresholds must satisfy softLimit < humanThreshold <= maxPerSend",
  );
  assert(
    typeof review.providerId === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(review.providerId),
    "invalid review provider identifier",
  );
  integer(review.maxReviewSeconds, "maximum review time");
  assert(
    review.maxReviewSeconds > 0 && review.maxReviewSeconds <= 300,
    "maximum review time must be 1..300 seconds",
  );
}
export function needsAgentReview(
  policy: SpendingPolicy,
  amount: string,
): boolean {
  return !!policy.review && units(amount) > units(policy.review.softLimit);
}
/** No secrets, raw PSBT or signed private envelope are sent; the exact plan/policy hashes bind scope. */
export function agentReviewRequest(
  request: SendRequest,
  policy: SpendingPolicy,
  at: number,
): CheckRequest {
  assert(policy.review, "review policy required");
  const decoded = decodeSendPlan(request.plan);
  const planHash = sendPlanHash(request.plan),
    policyHash = hashObject(policy);
  const limits = {
    policy_version: policy.version,
    max_per_send: policy.maxPerSend,
    max_per_day: policy.maxPerDay,
    max_bitcoin_fee_sats: policy.maxBitcoinFeeSats,
    soft_limit: policy.review.softLimit,
    human_threshold: policy.review.humanThreshold,
  };
  const evidence = [
    {
      id: "send-plan",
      kind: "decoded-send-plan",
      data: decoded,
      sha256: hashObject(decoded),
    },
    {
      id: "spending-policy",
      kind: "spending-limits",
      data: limits,
      sha256: hashObject(limits),
    },
  ];
  const result: CheckRequest = {
    version: 1,
    request_id: randomHex(32),
    issued_at: new Date(at * 1000).toISOString(),
    expires_at: new Date(
      Math.min(
        at + policy.review.maxReviewSeconds,
        request.expiresAt,
        policy.expiresAt,
      ) * 1000,
    ).toISOString(),
    check: "agent-action-review",
    network: decoded.network,
    subject: {
      wallet_id: decoded.walletId,
      asset_id: decoded.assetId,
      amount: decoded.amount,
      recipient_id: decoded.recipientId,
    },
    evidence,
    context: {
      scope: "decoded-send-and-signed-local-policy",
      plan_sha256: planHash,
      policy_sha256: policyHash,
      send_request_sha256: hashObject(request),
      agent_public_key: request.agentPk,
      human_approval_available: false,
    },
  };
  validateRequest(result, at * 1000);
  return result;
}
/** The configured provider verifies DSSE; the gate rechecks exact binding, scope and validity after await. */
export function summarizeAgentReview(
  checked: VerifiedCheck,
  expected: CheckRequest,
  policy: SpendingPolicy,
  at: number,
): AgentReviewSummary {
  validateRequest(expected, at * 1000);
  const record = checked.record;
  assert(
    policy.review &&
      record.version === 1 &&
      record.provider_id === policy.review.providerId,
    "review provider identity mismatch",
  );
  assert(
    record.request_id === expected.request_id &&
      record.request_sha256 === hashObject(expected),
    "review request binding mismatch",
  );
  assert(
    record.execution === "software",
    "review hardware execution is unavailable",
  );
  const issued = Date.parse(record.issued_at),
    expires = Date.parse(record.expires_at);
  assert(
    Number.isFinite(issued) &&
      Number.isFinite(expires) &&
      issued >= Date.parse(expected.issued_at) &&
      issued <= at * 1000 &&
      at * 1000 < expires &&
      expires <= Date.parse(expected.expires_at),
    "review response expired or outside request validity",
  );
  assert(
    isHex(checked.evidence_sha256, 32),
    "review evidence digest malformed",
  );
  const result = record.result;
  assert(
    result.kind === "agent-action-review" &&
      ["approve", "escalate"].includes(result.recommendation),
    "review result kind or recommendation invalid",
  );
  assert(
    Array.isArray(result.findings) && result.findings.length <= 128,
    "review findings malformed",
  );
  const allowed = new Set(expected.evidence.map((e) => e.id));
  assert(
    Array.isArray(record.input_scope.evidence_ids) &&
      record.input_scope.evidence_ids.every((id) => allowed.has(id)),
    "review evidence scope exceeds supplied evidence",
  );
  for (const finding of result.findings)
    assert(
      typeof finding.code === "string" &&
        /^[A-Z][A-Z0-9_]{0,63}$/.test(finding.code) &&
        Array.isArray(finding.evidence_ids) &&
        finding.evidence_ids.length > 0 &&
        finding.evidence_ids.every((id) =>
          record.input_scope.evidence_ids.includes(id),
        ),
      "review reasons must be grounded codes",
    );
  assert(
    result.recommendation !== "escalate" || result.findings.length > 0,
    "review escalation requires reasons",
  );
  return {
    providerId: record.provider_id,
    evidenceSha256: checked.evidence_sha256,
    resultRecordHash: hashObject(record),
    requestHash: hashObject(expected),
    planHash: String(expected.context.plan_sha256),
    policyHash: hashObject(policy),
    recommendation: result.recommendation,
    reasonCodes: [...new Set(result.findings.map((f) => f.code))],
    execution: "software",
    expiresAt: Math.floor(expires / 1000),
  };
}
/** Signed token proof must remain valid at consumption and the actual wallet signing barrier. */
export function assertTokenReview(
  policy: SpendingPolicy,
  plan: SendRequest["plan"],
  token: GateToken,
  at: number,
): void {
  if (!needsAgentReview(policy, plan.amount)) return;
  const review = token.review;
  assert(
    policy.review && units(plan.amount) <= units(policy.review.humanThreshold),
    "HUMAN_APPROVAL_REQUIRED",
  );
  assert(
    review &&
      review.recommendation === "approve" &&
      review.providerId === policy.review.providerId &&
      review.execution === "software" &&
      review.policyHash === hashObject(policy) &&
      review.planHash === token.planHash &&
      isHex(review.evidenceSha256, 32) &&
      isHex(review.resultRecordHash, 32) &&
      isHex(review.requestHash, 32),
    "TOKEN_PROVIDER_REVIEW_INVALID",
  );
  assert(
    at < review.expiresAt && token.expiresAt <= review.expiresAt,
    "TOKEN_PROVIDER_REVIEW_EXPIRED",
  );
}
