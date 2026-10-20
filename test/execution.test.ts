// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalJson, signObject, verifyObject } from "../src/core/crypto.js";
import {
  CURRENT_EXECUTION,
  EXECUTIONS,
  isExecution,
} from "../src/execution/types.js";
import {
  attestationProblems,
  type Attestation,
} from "../src/verify/incoming.js";
import { AT, incomingFixture } from "./helpers.js";

test("new local attestations explicitly sign v2 software execution for clear, flagged and error results", async () => {
  for (const kind of ["clear", "flagged", "error"]) {
    const f = incomingFixture({ flagged: kind === "flagged" });
    const a = await f.service.verifyIncoming(
      kind === "error" ? { ...f.input, previousTransactions: {} } : f.input,
    );
    assert.equal(a.v, 2);
    assert.equal(a.domain, "trust-incoming-attestation-v2");
    assert.equal(a.execution, "software");
    assert.equal(a.overall, kind);
    assert.deepEqual(
      attestationProblems(a, {
        checkerPk: f.key.pubkey,
        flaggedIssuerKeys: [f.flags.issuer.pubkey],
        now: AT,
      }),
      [],
    );
    assert(verifyObject(a, f.key.pubkey));
  }
});
test("historical committed v1 live records verify without adding or resigning any original field", () => {
  const receipt = JSON.parse(
    readFileSync("release/testnet-receipt.json", "utf8"),
  );
  const records = Object.values(receipt.attestations) as Attestation[];
  assert(records.length > 0);
  for (const a of records) {
    const before = canonicalJson(a);
    assert.equal(a.v, 1);
    assert(!Object.hasOwn(a, "execution"));
    assert.deepEqual(
      attestationProblems(a, {
        checkerPk: a.checkerPk,
        flaggedIssuerKeys: [a.flaggedManifest.issuerPk],
        now: a.time,
      }),
      [],
    );
    assert.equal(canonicalJson(a), before);
  }
});
test("changing execution label or dropping it from signed v2 record fails verification", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  const trust = {
    checkerPk: f.key.pubkey,
    flaggedIssuerKeys: [f.flags.issuer.pubkey],
    now: AT,
  };
  for (const execution of EXECUTIONS.filter((x) => x !== "software"))
    assert(
      attestationProblems({ ...a, execution } as unknown as Attestation, trust)
        .length,
    );
  const { execution, ...missing } = a;
  assert(attestationProblems(missing as Attestation, trust).length);
});
test("even checker-signed local hardware claims are refused until real vendor verification exists", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  for (const execution of EXECUTIONS.filter((x) => x !== "software")) {
    const forged = signObject({ ...a, execution }, f.key.secretKey);
    assert(
      attestationProblems(forged as unknown as Attestation, {
        checkerPk: f.key.pubkey,
        flaggedIssuerKeys: [f.flags.issuer.pubkey],
        now: AT,
      }).length,
    );
  }
});
test("legacy domain cannot smuggle a new execution claim, even with a valid checker signature", async () => {
  const f = incomingFixture();
  const a = await f.service.verifyIncoming(f.input);
  const claim = signObject(
    { ...a, v: 1, domain: "trust-incoming-attestation-v1" },
    f.key.secretKey,
  );
  assert(
    attestationProblems(claim as unknown as Attestation, {
      checkerPk: f.key.pubkey,
      flaggedIssuerKeys: [f.flags.issuer.pubkey],
      now: AT,
    }).length,
  );
});
test("execution vocabulary includes future hardware and device labels without enabling them", () => {
  assert.equal(CURRENT_EXECUTION, "software");
  for (const label of EXECUTIONS) assert(isExecution(label));
  assert(!isExecution("tee:test-vendor"));
  assert(!isExecution("hardware"));
});
