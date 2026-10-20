// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
// All providers in this file are isolated test fixtures, never live runtime evidence.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  canonicalJson,
  hashObject,
  randomHex,
  signObject,
} from "../src/core/crypto.js";
import { PolicyGate } from "../src/governance/gate.js";
import {
  agentReviewRequest,
  assertTokenReview,
  type AgentReviewPolicy,
} from "../src/governance/review.js";
import type {
  AttestedCheckProvider,
  CheckRequest,
  ProviderRecord,
  VerifiedCheck,
} from "../src/provider/protocol.js";
import { AT, gateFixture } from "./helpers.js";
type ProviderBehavior = (request: CheckRequest) => Promise<VerifiedCheck>;
function reviewedFixture(
  behavior?: (
    request: CheckRequest,
    f: ReturnType<typeof gateFixture>,
  ) => Promise<VerifiedCheck>,
  review: Partial<AgentReviewPolicy> = {},
) {
  const f = gateFixture();
  const calls: CheckRequest[] = [];
  const provider: AttestedCheckProvider = {
    check: async (request) => {
      calls.push(structuredClone(request));
      return behavior ? behavior(request, f) : record(request);
    },
  };
  const policy = signObject(
    {
      ...f.policy,
      review: {
        softLimit: "40",
        humanThreshold: "80",
        providerId: "test-review-fixture",
        maxReviewSeconds: 90,
        ...review,
      },
    },
    f.owner.secretKey,
  );
  const gate = new PolicyGate({ ...f.gateOptions, reviewProvider: provider });
  gate.install(policy);
  return { ...f, gate, policy, provider, calls };
}
function record(
  request: CheckRequest,
  changes: Partial<ProviderRecord> = {},
): VerifiedCheck {
  const value: ProviderRecord = {
    version: 1,
    provider_id: "test-review-fixture",
    request_id: request.request_id,
    request_sha256: hashObject(request),
    issued_at: request.issued_at,
    expires_at: request.expires_at,
    workload: {
      id: "test-agent-review",
      version: "v1",
      sha256: "ab".repeat(32),
    },
    model: { id: "test-fixed", mode: "fixed-rules" },
    policy: { id: "test-review", sha256: "cd".repeat(32) },
    input_scope: {
      evidence_ids: ["send-plan", "spending-policy"],
      fields: ["evidence.send-plan", "evidence.spending-policy"],
    },
    result: {
      kind: "agent-action-review",
      recommendation: "approve",
      findings: [
        { code: "WITHIN_REVIEW_CONTEXT", evidence_ids: ["send-plan"] },
      ],
    },
    execution: "software",
    ...changes,
  };
  return {
    record: value,
    evidence_sha256: hashObject({ fixtureRecord: value }),
    evidence_file: "/private/test-fixture/envelope.json",
  };
}
test("signed soft threshold requires review; synchronous path cannot bypass it", () => {
  const f = reviewedFixture();
  const decision = f.gate.authorize(f.request());
  assert(!decision.allowed);
  assert(decision.why.includes("PROVIDER_REVIEW_REQUIRED"));
  assert.equal(f.calls.length, 0);
  assert.deepEqual(f.gate.store.read().spentByDay, {});
});
test("old policies and requests at or below soft limit retain synchronous behavior without provider", async () => {
  const f = reviewedFixture();
  assert(f.gate.authorize(f.request(f.plan("40"))).allowed);
  assert((await f.gate.authorizeReviewed(f.request(f.plan("1")))).allowed);
  assert.equal(f.calls.length, 0);
  const old = gateFixture();
  old.gate.install(old.policy);
  assert((await old.gate.authorizeReviewed(old.request())).allowed);
});
test("provider approval yields exact signed-plan token with logged digest, grounded reasons and software execution", async () => {
  const f = reviewedFixture();
  const request = f.request();
  const decision = await f.gate.authorizeReviewed(request);
  assert(decision.allowed && decision.token);
  assert.equal(f.calls.length, 1);
  const check = f.calls[0];
  assert.equal(check.check, "agent-action-review");
  assert.equal(check.context.plan_sha256, decision.token.planHash);
  assert.equal(check.context.policy_sha256, hashObject(f.policy));
  assert.equal(check.context.send_request_sha256, hashObject(request));
  assert.equal(decision.token.review?.recommendation, "approve");
  assert.equal(decision.token.review?.execution, "software");
  assert.equal(decision.token.expiresAt, AT + 60);
  assert.deepEqual(decision.token.review?.reasonCodes, [
    "WITHIN_REVIEW_CONTEXT",
  ]);
  f.gate.consume(decision.token, request.plan, request.preview);
  f.gate.assertSigningAllowed(decision.token, request.plan, request.preview);
  const detail = JSON.stringify(
    f.log.entries().filter((e) => e.kind === "authorization"),
  );
  assert(detail.includes(decision.token.review!.evidenceSha256));
  assert(!detail.includes("/private/test-fixture"));
  assert(!detail.includes(request.plan.unsignedPsbt));
  assert.deepEqual(f.log.verify(), []);
});
test("hard human threshold is always a local refusal and provider is never called", async () => {
  const f = reviewedFixture();
  const decision = await f.gate.authorizeReviewed(f.request(f.plan("81")));
  assert(!decision.allowed);
  assert(decision.why.includes("HUMAN_APPROVAL_REQUIRED"));
  assert.equal(f.calls.length, 0);
  assert.deepEqual(f.gate.store.read().spentByDay, {});
});
test("a verified provider timestamp within the gate clock's current second is accepted", async () => {
  const f = reviewedFixture(async request => record(request, { issued_at: new Date(AT * 1000 + 500).toISOString() }));
  assert((await f.gate.authorizeReviewed(f.request())).allowed);
});
test("amount exactly at hard human threshold can be reviewed but cannot exceed local per-send cap", async () => {
  const f = reviewedFixture();
  assert((await f.gate.authorizeReviewed(f.request(f.plan("80")))).allowed);
  const over = await f.gate.authorizeReviewed(f.request(f.plan("101")));
  assert(!over.allowed);
  assert(over.why.includes("PER_SEND_LIMIT_EXCEEDED"));
  assert.equal(f.calls.length, 1);
});
test("review policy validates signed ordering, provider identity and bounded response lifetime", () => {
  for (const review of [
    { softLimit: "80", humanThreshold: "80" },
    { softLimit: "0", humanThreshold: "101" },
    { softLimit: "-1" },
    { providerId: "invalid id" },
    { maxReviewSeconds: 0 },
    { maxReviewSeconds: 301 },
  ])
    assert.throws(() => reviewedFixture(undefined, review));
});
test("provider escalation is stricter than local approval and reserves no funds", async () => {
  const f = reviewedFixture(async (request) =>
    record(request, {
      result: {
        kind: "agent-action-review",
        recommendation: "escalate",
        findings: [
          { code: "CONTEXT_NEEDS_HUMAN", evidence_ids: ["send-plan"] },
        ],
      },
    }),
  );
  const d = await f.gate.authorizeReviewed(f.request());
  assert(!d.allowed);
  assert(d.why.includes("PROVIDER_REVIEW_ESCALATED"));
  assert.deepEqual(f.gate.store.read().spentByDay, {});
  assert(JSON.stringify(f.log.entries()).includes("CONTEXT_NEEDS_HUMAN"));
});
test("missing or failed provider never relaxes required review or leaks its private exception", async () => {
  const f = reviewedFixture(async () => {
    throw new Error("private endpoint token should never leave provider");
  });
  const failed = await f.gate.authorizeReviewed(f.request());
  assert(!failed.allowed);
  assert(failed.why.includes("PROVIDER_REVIEW_FAILED"));
  assert(!JSON.stringify(f.log.entries()).includes("private endpoint"));
  const without = new PolicyGate(f.gateOptions);
  const missing = await without.authorizeReviewed(f.request());
  assert(!missing.allowed);
  assert(missing.why.includes("PROVIDER_REVIEW_UNAVAILABLE"));
});
test("all fixed local rules run before any provider review request", async () => {
  const f = reviewedFixture();
  const invalid = f.request();
  invalid.sig = "00".repeat(64);
  assert(!(await f.gate.authorizeReviewed(invalid)).allowed);
  f.gate.stop(f.stop());
  assert(!(await f.gate.authorizeReviewed(f.request())).allowed);
  assert.equal(f.calls.length, 0);
});
test("daily reservations are checked again after concurrent provider checks finish", async () => {
  let release!: () => void;
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  const f = reviewedFixture(async (request) => {
    await wait;
    return record(request);
  });
  const requests = [f.request(f.plan("80")), f.request(f.plan("80"))];
  const promises = requests.map((r) => f.gate.authorizeReviewed(r));
  await Promise.resolve();
  assert.equal(f.calls.length, 2);
  release();
  const results = await Promise.all(promises);
  assert.equal(results.filter((d) => d.allowed).length, 1);
  assert(results.some((d) => d.why.includes("DAILY_LIMIT_EXCEEDED")));
});
test("stop applied during provider await refuses final approval", async () => {
  const f = reviewedFixture(async (request, inner) => {
    new PolicyGate(inner.gateOptions).stop(inner.stop());
    return record(request);
  });
  const d = await f.gate.authorizeReviewed(f.request());
  assert(!d.allowed);
  assert(d.why.includes("KILL_SWITCH_STOPPED"));
});
test("policy replacement during await refuses old approval even when new policy disables review", async () => {
  let f!: ReturnType<typeof reviewedFixture>;
  f = reviewedFixture(async (request) => {
    f.gate.install(
      signObject(
        {
          ...f.policy,
          version: 2,
          prevHash: hashObject(f.policy),
          review: { ...f.policy.review, softLimit: "70" },
        },
        f.owner.secretKey,
      ),
    );
    return record(request);
  });
  const d = await f.gate.authorizeReviewed(f.request());
  assert(!d.allowed);
  assert(d.why.includes("POLICY_CHANGED_DURING_REVIEW"));
});
test("send request and provider approval expiration are rechecked after provider await", async () => {
  for (const kind of ["request", "provider"]) {
    const f = reviewedFixture(async (request, inner) => {
      inner.setTime(AT + (kind === "request" ? 120 : 91));
      return record(request);
    });
    const d = await f.gate.authorizeReviewed(f.request());
    assert(!d.allowed);
    if (kind === "request") assert(d.why.includes("REQUEST_TIME_INVALID"));
    assert(d.why.includes("PROVIDER_REVIEW_FAILED"));
  }
});
test("exact amount/preview and immutable provider request binding cannot change across await", async () => {
  let original: any;
  const f = reviewedFixture(async (request) => {
    original.plan.amount = "1";
    request.context.plan_sha256 = "00".repeat(32);
    return record(request);
  });
  original = f.request();
  const d = await f.gate.authorizeReviewed(original);
  assert(!d.allowed);
  assert(d.why.includes("PROVIDER_REVIEW_FAILED"));
  assert.deepEqual(f.gate.store.read().spentByDay, {});
});
test("provider cannot approve another policy, plan, nonce, provider id, kind, execution or ungrounded reason", async () => {
  for (const mutate of [
    (r: ProviderRecord) => {
      r.request_id = randomHex(32);
    },
    (r: ProviderRecord) => {
      r.request_sha256 = "00".repeat(32);
    },
    (r: ProviderRecord) => {
      r.provider_id = "other-provider";
    },
    (r: ProviderRecord) => {
      r.result = { kind: "transfer-flow-risk", risk_band: "low", findings: [] };
    },
    (r: any) => {
      r.execution = "tee:aws-nitro";
    },
    (r: ProviderRecord) => {
      r.result = {
        kind: "agent-action-review",
        recommendation: "escalate",
        findings: [{ code: "REVIEW", evidence_ids: ["unsupplied"] }],
      };
    },
  ]) {
    const f = reviewedFixture(async (request) => {
      const reply = record(request);
      mutate(reply.record);
      return reply;
    });
    const d = await f.gate.authorizeReviewed(f.request());
    assert(!d.allowed);
    assert(d.why.includes("PROVIDER_REVIEW_FAILED"));
  }
});
test("short provider validity limits approval token and signing-barrier lifetime", async () => {
  const f = reviewedFixture(async (request) =>
    record(request, { expires_at: new Date((AT + 5) * 1000).toISOString() }),
  );
  const r = f.request();
  const d = await f.gate.authorizeReviewed(r);
  assert(d.token);
  assert.equal(d.token.expiresAt, AT + 5);
  f.gate.consume(d.token, r.plan, r.preview);
  f.setTime(AT + 5);
  assert.throws(
    () => f.gate.assertSigningAllowed(d.token!, r.plan, r.preview),
    /TOKEN_TIME_INVALID/,
  );
});
test("signed review proof is required for consumption and actual signing barrier", async () => {
  const f = reviewedFixture();
  const r = f.request();
  const d = await f.gate.authorizeReviewed(r);
  assert(d.token);
  const { review, ...bare } = d.token;
  const forged = signObject(bare, f.gateKey.secretKey);
  assert.throws(
    () => assertTokenReview(f.policy, r.plan, forged, AT),
    /TOKEN_PROVIDER_REVIEW_INVALID/,
  );
  assert.throws(
    () => f.gate.consume(forged, r.plan, r.preview),
    /TOKEN_PROVIDER_REVIEW_INVALID/,
  );
  f.gate.consume(d.token, r.plan, r.preview);
  assert.throws(
    () => f.gate.assertSigningAllowed(forged, r.plan, r.preview),
    /TOKEN_PROVIDER_REVIEW_INVALID/,
  );
});
test("review request sends only decoded scope and strict policy hashes, no wallet secrets or raw PSBT", () => {
  const f = reviewedFixture();
  const r = f.request();
  const check = agentReviewRequest(r, f.policy, AT);
  assert(!canonicalJson(check).includes(r.plan.unsignedPsbt));
  assert.equal(
    Date.parse(check.expires_at),
    Math.min(r.expiresAt, AT + 90) * 1000,
  );
  assert.equal(check.context.human_approval_available, false);
  assert(check.evidence.every((e) => hashObject(e.data) === e.sha256));
});

test("caller cannot change an approved request across provider await; token still binds frozen original plan", async () => {
  let original: any;
  let saved: any;
  const f = reviewedFixture(async (request) => {
    original.plan.amount = "1";
    return record(request);
  });
  original = f.request();
  saved = structuredClone(original);
  const d = await f.gate.authorizeReviewed(original);
  assert(d.token);
  assert.equal(d.token.review!.planHash, saved.preview.planHash);
  assert.throws(() =>
    f.gate.consume(d.token!, original.plan, original.preview),
  );
  f.gate.consume(d.token, saved.plan, saved.preview);
});
test("new receiver quarantine while review awaits refuses final token without local reservation", async () => {
  const f = gateFixture();
  let quarantined = false;
  const policy = signObject(
    {
      ...f.policy,
      review: {
        softLimit: "40",
        humanThreshold: "80",
        providerId: "test-review-fixture",
        maxReviewSeconds: 90,
      },
    },
    f.owner.secretKey,
  );
  const gate = new PolicyGate({
    ...f.gateOptions,
    quarantine: {
      problems: () =>
        quarantined ? ["RECEIVER_ASSET_QUARANTINED_FLAGGED"] : [],
    },
    reviewProvider: {
      check: async (request) => {
        quarantined = true;
        return record(request);
      },
    },
  });
  gate.install(policy);
  const d = await gate.authorizeReviewed(f.request());
  assert(!d.allowed);
  assert(d.why.includes("RECEIVER_ASSET_QUARANTINED_FLAGGED"));
  assert.deepEqual(gate.store.read().spentByDay, {});
});
test("reusing a request after reviewed authorization cannot call provider again or issue a second token", async () => {
  const f = reviewedFixture();
  const request = f.request();
  assert((await f.gate.authorizeReviewed(request)).allowed);
  const replay = await f.gate.authorizeReviewed(request);
  assert(!replay.allowed);
  assert(replay.why.includes("REQUEST_REPLAY_OR_ID_INVALID"));
  assert.equal(f.calls.length, 1);
});
