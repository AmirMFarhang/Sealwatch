// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import {
  bytesToHex,
  hashObject,
  randomHex,
  signHash,
} from "../src/core/crypto.js";
import { FileDecisionLog } from "../src/governance/log.js";
import {
  SoftwareOnlyQuoteVerifier,
  TestVendorQuoteVerifier,
  testVendorLeafHash,
  testVendorDocumentHash,
  quoteReportData,
  type QuoteContext,
  type QuoteEvidence,
  type QuoteVendor,
  type TestVendorDocument,
} from "../src/execution/quote.js";
import { AT, key, temp } from "./helpers.js";
function fixture() {
  const dir = temp(),
    root = key(),
    leaf = key(),
    result = key(),
    receiver = key();
  let at = AT;
  const context: QuoteContext = {
    releaseId: "test-release-v1",
    requestNonce: randomHex(32),
    commitmentHash: hashObject({ result: "test-only-software" }),
    resultKey: result.pubkey,
  };
  const doc = (
    changes: Partial<Omit<TestVendorDocument, "sig">> = {},
  ): TestVendorDocument => {
    const unsigned = {
      vendor: "test-vendor" as const,
      measurement: "test-measurement-v1",
      publicKey: result.pubkey,
      reportData: quoteReportData(context),
      timestamp: AT,
      leafPk: leaf.pubkey,
      leafSignature: signHash(testVendorLeafHash(leaf.pubkey), root.secretKey),
      ...changes,
    };
    return {
      ...unsigned,
      sig: signHash(testVendorDocumentHash(unsigned), leaf.secretKey),
    };
  };
  const evidence = (
    changes: Partial<Omit<TestVendorDocument, "sig">> = {},
  ): QuoteEvidence => ({
    vendor: "test-vendor",
    document: JSON.stringify(doc(changes)),
    commitmentHash: context.commitmentHash,
    resultSignature: signHash(context.commitmentHash, result.secretKey),
  });
  const log = new FileDecisionLog(
    join(dir, "quote-log.jsonl"),
    receiver,
    () => at,
  );
  const options = {
    rootPk: root.pubkey,
    approvedMeasurements: { [context.releaseId]: "test-measurement-v1" },
    maxAgeSeconds: 600,
    now: () => at,
    replay: { file: join(dir, "replay.json"), key: receiver, log },
  };
  return {
    dir,
    root,
    leaf,
    result,
    receiver,
    context,
    doc,
    evidence,
    log,
    options,
    verifier: new TestVendorQuoteVerifier(options),
    setTime: (value: number) => {
      at = value;
    },
  };
}
test("valid test-vendor quote checks root, key, measurement, fresh challenge and result signature but grants only software", () => {
  const f = fixture();
  const verified = f.verifier.verify(f.evidence(), f.context);
  assert(verified.verified);
  assert.equal(verified.execution, "software");
  assert.equal(verified.testOnly, true);
  assert(verified.checks.every((c) => c.ok));
  assert.deepEqual(f.log.verify(), []);
});
test("wrong approved measurement and unapproved release are refused", () => {
  for (const change of ["measurement", "release"]) {
    const f = fixture();
    const v = f.verifier.verify(
      change === "measurement"
        ? f.evidence({ measurement: "unapproved" })
        : f.evidence(),
      change === "release"
        ? { ...f.context, releaseId: "other-release" }
        : f.context,
    );
    assert(!v.verified);
    assert(v.checks.some((c) => c.id === "measurement" && !c.ok));
  }
});
test("wrong pinned root refuses a correctly leaf-signed document", () => {
  const f = fixture();
  const verifier = new TestVendorQuoteVerifier({
    ...f.options,
    rootPk: key().pubkey,
  });
  const v = verifier.verify(f.evidence(), f.context);
  assert(!v.verified);
  assert(v.checks.some((c) => c.id === "vendor-chain" && !c.ok));
});
test("tampering quote fields or leaf certificate breaks vendor-chain signatures", () => {
  for (const field of ["timestamp", "leafSignature"]) {
    const f = fixture();
    const e = f.evidence();
    const d = JSON.parse(e.document);
    d[field] = field === "timestamp" ? AT - 1 : "00".repeat(64);
    const v = f.verifier.verify(
      { ...e, document: JSON.stringify(d) },
      f.context,
    );
    assert(!v.verified);
    assert(v.checks.some((c) => c.id === "vendor-chain" && !c.ok));
  }
});
test("wrong result key, wrong commitment and wrong signature are refused independently", () => {
  for (const kind of ["key", "commitment", "signature"]) {
    const f = fixture();
    const e = f.evidence();
    const changed =
      kind === "commitment"
        ? { ...e, commitmentHash: randomHex(32) }
        : kind === "signature"
          ? { ...e, resultSignature: "00".repeat(64) }
          : e;
    const v = f.verifier.verify(
      changed,
      kind === "key" ? { ...f.context, resultKey: key().pubkey } : f.context,
    );
    assert(!v.verified);
    assert(
      v.checks.some(
        (c) =>
          (kind === "key"
            ? c.id === "enclave-key"
            : c.id === "result-signature") && !c.ok,
      ),
    );
  }
});
test("new nonce, stale report and future report refuse freshness", () => {
  for (const kind of ["nonce", "stale", "future"]) {
    const f = fixture();
    if (kind === "stale") f.setTime(AT + 601);
    if (kind === "future") f.setTime(AT - 1);
    const v = f.verifier.verify(
      f.evidence(),
      kind === "nonce"
        ? { ...f.context, requestNonce: randomHex(32) }
        : f.context,
    );
    assert(!v.verified);
    assert(v.checks.some((c) => c.id === "fresh-report" && !c.ok));
  }
});
test("a valid test quote cannot be replayed in the same verifier or after restart", () => {
  const f = fixture();
  const e = f.evidence();
  assert(f.verifier.verify(e, f.context).verified);
  for (const verifier of [f.verifier, new TestVendorQuoteVerifier(f.options)]) {
    const replay = verifier.verify(e, f.context);
    assert(!replay.verified);
    assert(
      replay.checks.some(
        (c) => c.id === "replay" && c.detail.includes("QUOTE_REPLAY"),
      ),
    );
  }
});
test("invalid quotes do not consume a valid receiver challenge", () => {
  const f = fixture();
  assert(
    !f.verifier.verify(f.evidence({ measurement: "bad" }), f.context).verified,
  );
  assert(f.verifier.verify(f.evidence(), f.context).verified);
});
test("restoring an older valid signed replay ledger is refused against the retained current journal", () => {
  const f = fixture();
  assert(f.verifier.verify(f.evidence(), f.context).verified);
  const old = readFileSync(f.options.replay.file);
  const next = { ...f.context, requestNonce: randomHex(32) };
  const e = f.evidence({ reportData: quoteReportData(next) });
  assert(f.verifier.verify(e, next).verified);
  writeFileSync(f.options.replay.file, old);
  const v = new TestVendorQuoteVerifier(f.options).verify(e, next);
  assert(!v.verified);
  assert(
    v.checks.some((c) => c.id === "replay" && c.detail.includes("rollback")),
  );
});
test("deleting the replay ledger cannot clear consumed challenges while journal remains", () => {
  const f = fixture();
  const e = f.evidence();
  assert(f.verifier.verify(e, f.context).verified);
  unlinkSync(f.options.replay.file);
  const v = new TestVendorQuoteVerifier(f.options).verify(e, f.context);
  assert(!v.verified);
  assert(
    v.checks.some((c) => c.id === "replay" && c.detail.includes("missing")),
  );
});
test("replay refusal persists across an independent Node process", () => {
  const f = fixture();
  const evidence = f.evidence();
  assert(f.verifier.verify(evidence, f.context).verified);
  const file = join(f.dir, "replay-process.json");
  writeFileSync(
    file,
    JSON.stringify({
      rootPk: f.root.pubkey,
      approvedMeasurements: f.options.approvedMeasurements,
      evidence,
      context: f.context,
      stateFile: f.options.replay.file,
      logFile: f.log.file,
      at: AT,
    }),
    { mode: 0o600 },
  );
  const code = `import{readFileSync}from'node:fs';import{keyPairFromSecret}from'./src/core/crypto.ts';import{FileDecisionLog}from'./src/governance/log.ts';import{TestVendorQuoteVerifier}from'./src/execution/quote.ts';const p=JSON.parse(readFileSync(process.env.TRUST_QUOTE_TEST_INPUT,'utf8'));const key=keyPairFromSecret(process.env.TRUST_QUOTE_TEST_SECRET);const verifier=new TestVendorQuoteVerifier({rootPk:p.rootPk,approvedMeasurements:p.approvedMeasurements,now:()=>p.at,replay:{file:p.stateFile,key,log:new FileDecisionLog(p.logFile,key,()=>p.at)}});process.stdout.write(JSON.stringify(verifier.verify(p.evidence,p.context)));`;
  const child = spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", code],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        TRUST_QUOTE_TEST_INPUT: file,
        TRUST_QUOTE_TEST_SECRET: bytesToHex(f.receiver.secretKey),
      },
    },
  );
  assert.equal(child.status, 0, child.stderr);
  const v = JSON.parse(child.stdout);
  assert(!v.verified);
  assert(
    v.checks.some(
      (c: any) => c.id === "replay" && c.detail.includes("QUOTE_REPLAY"),
    ),
  );
});
test("default verifier refuses all real hardware and device claims and never elevates execution", () => {
  for (const vendor of [
    "aws-nitro",
    "intel-tdx",
    "amd-sev-snp",
    "apple-app-attest",
    "android-key-attestation",
    "test-vendor",
  ] as QuoteVendor[]) {
    const f = fixture();
    const v = new SoftwareOnlyQuoteVerifier().verify(
      { ...f.evidence(), vendor },
      f.context,
    );
    assert(!v.verified);
    assert.equal(v.execution, "software");
  }
});
test("test-vendor verifier cannot accept any real vendor label even for its valid fixture document", () => {
  for (const vendor of [
    "aws-nitro",
    "intel-tdx",
    "amd-sev-snp",
    "apple-app-attest",
    "android-key-attestation",
  ] as QuoteVendor[]) {
    const f = fixture();
    const v = f.verifier.verify({ ...f.evidence(), vendor }, f.context);
    assert(!v.verified);
    assert.equal(v.execution, "software");
    assert.equal(v.testOnly, true);
  }
});
test("trusted root and approved measurements are snapshotted rather than mutable caller options", () => {
  const f = fixture();
  f.options.rootPk = key().pubkey;
  f.options.approvedMeasurements[f.context.releaseId] = "tampered";
  assert(f.verifier.verify(f.evidence(), f.context).verified);
});
test("malformed or oversized documents fail closed before touching replay journal", () => {
  for (const document of ["{", "{}", "x".repeat(65537)]) {
    const f = fixture();
    const v = f.verifier.verify({ ...f.evidence(), document }, f.context);
    assert(!v.verified);
    assert.equal(f.log.entries().length, 0);
  }
});
