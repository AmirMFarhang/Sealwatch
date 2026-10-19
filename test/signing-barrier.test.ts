// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { hashObject, signObject } from "../src/core/crypto.js";
import { PolicyGate } from "../src/governance/gate.js";
import { certifyPreview } from "../src/wallet/plan.js";
import { AT, gateFixture } from "./helpers.js";
function consumed() {
  const f = gateFixture();
  f.gate.install(f.policy);
  const request = f.request();
  const decision = f.gate.authorize(request);
  assert(decision.token);
  f.gate.consume(decision.token, request.plan, request.preview);
  return { ...f, request, token: decision.token };
}
test("signing barrier accepts consumed approval without changing state, log or spending reservation", () => {
  const f = consumed();
  const beforeState = readFileSync(f.gateOptions.stateFile),
    beforeLog = readFileSync(f.log.file);
  new PolicyGate(f.gateOptions).assertSigningAllowed(
    f.token,
    f.request.plan,
    f.request.preview,
  );
  assert.deepEqual(readFileSync(f.gateOptions.stateFile), beforeState);
  assert.deepEqual(readFileSync(f.log.file), beforeLog);
  assert.equal(
    f.gate.store.read().spentByDay[
      new Date(AT * 1000).toISOString().slice(0, 10)
    ],
    "50",
  );
});
test("owner stop after consumption is refused at actual signing barrier", () => {
  const f = consumed();
  new PolicyGate(f.gateOptions).stop(f.stop());
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(f.token, f.request.plan, f.request.preview),
    /KILL_SWITCH_STOPPED/,
  );
});
test("policy replacement after consumption invalidates old approval at signing barrier", () => {
  const f = consumed();
  f.gate.install(
    signObject(
      { ...f.policy, version: 2, prevHash: hashObject(f.policy) },
      f.owner.secretKey,
    ),
  );
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(f.token, f.request.plan, f.request.preview),
    /TOKEN_POLICY_OR_AGENT_CHANGED/,
  );
});
test("token and policy validity are rechecked at signing time after asynchronous delay", () => {
  const f = consumed();
  f.setTime(f.token.expiresAt);
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(f.token, f.request.plan, f.request.preview),
    /TOKEN_TIME_INVALID/,
  );
  f.setTime(f.policy.expiresAt);
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(f.token, f.request.plan, f.request.preview),
    /POLICY_EXPIRED_OR_NOT_ACTIVE/,
  );
});
test("unconsumed, forged and unknown approvals cannot pass signing barrier", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const request = f.request();
  const decision = f.gate.authorize(request);
  assert(decision.token);
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(
        decision.token!,
        request.plan,
        request.preview,
      ),
    /TOKEN_NOT_CONSUMED_OR_UNKNOWN/,
  );
  f.gate.consume(decision.token, request.plan, request.preview);
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(
        { ...decision.token!, sig: "00".repeat(64) },
        request.plan,
        request.preview,
      ),
    /TOKEN_SIGNATURE_INVALID/,
  );
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(
        signObject(
          { ...decision.token!, id: "ab".repeat(32) },
          f.gateKey.secretKey,
        ),
        request.plan,
        request.preview,
      ),
    /TOKEN_NOT_CONSUMED_OR_UNKNOWN/,
  );
});
test("signing barrier revalidates exact transaction and independently trusted wallet preview", () => {
  const f = consumed();
  const changed = f.plan("49");
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(
        f.token,
        changed,
        certifyPreview(changed, f.adapter),
      ),
    /DECODED_TRANSACTION_MISMATCH/,
  );
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(
        f.token,
        f.request.plan,
        certifyPreview(f.request.plan, f.agent),
      ),
    /WALLET_PREVIEW_SIGNATURE_INVALID/,
  );
});
test("retained current journal prevents rollback to consumed state before a signing-barrier stop", () => {
  const f = consumed();
  const consumedState = readFileSync(f.gateOptions.stateFile);
  f.gate.stop(f.stop());
  writeFileSync(f.gateOptions.stateFile, consumedState);
  assert.throws(
    () =>
      f.gate.assertSigningAllowed(f.token, f.request.plan, f.request.preview),
    /rollback/,
  );
});
test("new incoming quarantine after consume is rechecked before signing", () => {
  const f = gateFixture();
  let flagged = false;
  const gate = new PolicyGate({
    ...f.gateOptions,
    quarantine: {
      problems: () => (flagged ? ["RECEIVER_ASSET_QUARANTINED_FLAGGED"] : []),
    },
  });
  gate.install(f.policy);
  const request = f.request();
  const decision = gate.authorize(request);
  assert(decision.token);
  gate.consume(decision.token, request.plan, request.preview);
  flagged = true;
  assert.throws(
    () =>
      gate.assertSigningAllowed(decision.token!, request.plan, request.preview),
    /QUARANTINED/,
  );
});
