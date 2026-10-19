// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { hashObject, randomHex, signObject } from "../src/core/crypto.js";
import {
  PolicyGate,
  signPolicy,
  signRequest,
  signStop,
} from "../src/governance/gate.js";
import { certifyPreview, decodeSendPlan } from "../src/wallet/plan.js";
import { AT, gateFixture, key } from "./helpers.js";
test("signed owner policy authorizes within-limit native preview and durable one-use token", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.allowed && d.token);
  assert.equal(d.token.planHash, r.preview.planHash);
  f.gate.consume(d.token, r.plan, r.preview);
  assert.throws(() => f.gate.consume(d.token!, r.plan, r.preview), /REUSED/);
  assert.deepEqual(f.log.verify(), []);
});
test("token replay stays refused after gate process object restarts", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  new PolicyGate(f.gateOptions).consume(d.token, r.plan, r.preview);
  assert.throws(
    () => new PolicyGate(f.gateOptions).consume(d.token!, r.plan, r.preview),
    /REUSED/,
  );
});
test("over-limit send refuses with why and no token, decision persisted", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const d = f.gate.authorize(f.request(f.plan("101")));
  assert.equal(d.allowed, false);
  assert.equal(d.token, null);
  assert(d.why.includes("PER_SEND_LIMIT_EXCEEDED"));
  const why = f.gate.why(d.actionId);
  assert(
    why.entries.some((e) =>
      JSON.stringify(e.detail).includes("PER_SEND_LIMIT_EXCEEDED"),
    ),
  );
  assert.deepEqual(why.chainProblems, []);
});
test("cumulative reservations prevent multiple pending sends from exceeding daily cap", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  assert(f.gate.authorize(f.request(f.plan("100"))).allowed);
  const second = new PolicyGate(f.gateOptions).authorize(
    f.request(f.plan("51")),
  );
  assert(!second.allowed);
  assert(second.why.includes("DAILY_LIMIT_EXCEEDED"));
});
test("request replay cannot reserve or issue a second token", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  assert(f.gate.authorize(r).allowed);
  assert(f.gate.authorize(r).why.includes("REQUEST_REPLAY_OR_ID_INVALID"));
});
test("policy requires configured owner, node, wallet and network bindings", () => {
  for (const field of ["ownerPk", "gatePk", "walletId", "network"] as const) {
    const f = gateFixture();
    const p = {
      ...f.policy,
      [field]:
        field === "network"
          ? "mutinynet"
          : field === "walletId"
            ? "foreign-wallet"
            : key().pubkey,
    };
    const signed = signObject(p, f.owner.secretKey);
    assert.throws(() => f.gate.install(signed), /policy/);
  }
});
test("unsigned/tampered policy and self-authorized agent are refused", () => {
  const f = gateFixture();
  assert.throws(
    () => f.gate.install({ ...f.policy, maxPerSend: "999" }),
    /signed/,
  );
  assert.throws(
    () =>
      f.gate.install(
        signObject(
          { ...f.policy, agentKeys: [f.owner.pubkey] },
          f.owner.secretKey,
        ),
      ),
    /distinct/,
  );
});
test("policy requires explicit recipients and valid bounded token duration", () => {
  for (const changes of [
    { allowedRecipients: [] },
    { tokenTtlSeconds: 0 },
    { tokenTtlSeconds: 601 },
    { maxPerSend: "0" },
    { maxPerDay: "99" },
    { notBefore: AT + 1 },
    { expiresAt: AT },
  ]) {
    const f = gateFixture();
    assert.throws(() =>
      f.gate.install(
        signObject({ ...f.policy, ...changes }, f.owner.secretKey),
      ),
    );
  }
});
test("policy version updates require previous signed policy hash and revoke old tokens", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  const bad = signObject(
    { ...f.policy, version: 2, prevHash: "ab".repeat(32) },
    f.owner.secretKey,
  );
  assert.throws(() => f.gate.install(bad), /chain/);
  f.gate.install(
    signObject(
      {
        ...f.policy,
        version: 2,
        prevHash: hashObject(f.policy),
        maxPerSend: "90",
      },
      f.owner.secretKey,
    ),
  );
  assert.throws(() => f.gate.consume(d.token!, r.plan, r.preview), /POLICY/);
});
test("request signer must be a permitted distinct agent", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  assert(!f.gate.authorize({ ...r, sig: "00".repeat(64) }).allowed);
  const attacker = key();
  assert(
    !f.gate.authorize(
      signObject({ ...r, agentPk: attacker.pubkey }, attacker.secretKey),
    ).allowed,
  );
});
test("expired future and overly long requests are refused", () => {
  for (const times of [
    { issuedAt: AT + 1, expiresAt: AT + 120 },
    { issuedAt: AT - 120, expiresAt: AT },
    { issuedAt: AT, expiresAt: AT + 601 },
  ]) {
    const f = gateFixture();
    f.gate.install(f.policy);
    const r = signObject({ ...f.request(), ...times }, f.agent.secretKey);
    assert(f.gate.authorize(r).why.includes("REQUEST_TIME_INVALID"));
  }
});
test("expired policy refuses authorization and pending token consumption", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  f.setTime(AT + 3600);
  assert(
    f.gate.authorize(f.request()).why.includes("POLICY_EXPIRED_OR_NOT_ACTIVE"),
  );
  assert.throws(() => f.gate.consume(d.token!, r.plan, r.preview), /POLICY/);
});
test("token expires at exact expiry and future-issued token is refused", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  f.setTime(d.token.expiresAt);
  assert.throws(() => f.gate.consume(d.token!, r.plan, r.preview), /TIME/);
  f.setTime(AT - 1);
  assert.throws(() => f.gate.consume(d.token!, r.plan, r.preview), /TIME/);
});
test("wallet adapter preview signature is independently pinned, agent cannot certify its own plan", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const fake = certifyPreview(r.plan, f.agent);
  assert(
    f.gate
      .authorize(signObject({ ...r, preview: fake }, f.agent.secretKey))
      .why.includes("WALLET_PREVIEW_SIGNATURE_INVALID"),
  );
});
test("changed decoded outputs and preview after approval cannot consume token", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  const changed = f.plan("49");
  const preview = certifyPreview(changed, f.adapter);
  assert.throws(() => f.gate.consume(d.token!, changed, preview), /DECODED/);
  f.gate.consume(d.token, r.plan, r.preview);
});
test("tampered token, foreign gate/network/wallet token, and unknown token are refused", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  for (const changes of [
    { sig: "00".repeat(64) },
    { network: "mutinynet" },
    { walletId: "other" },
    { gatePk: key().pubkey },
    { id: randomHex(32) },
  ]) {
    const forged = signObject({ ...d.token, ...changes }, f.gateKey.secretKey);
    assert.throws(() =>
      f.gate.consume(forged as typeof d.token, r.plan, r.preview),
    );
  }
});
test("stop freezes new approvals and all previously unconsumed tokens across restarts", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  f.gate.stop(f.stop());
  const restarted = new PolicyGate(f.gateOptions);
  assert(restarted.authorize(f.request()).why.includes("KILL_SWITCH_STOPPED"));
  assert.throws(
    () => restarted.consume(d.token!, r.plan, r.preview),
    /STOPPED/,
  );
});
test("stop refuses foreign signer/network/wallet, future or replayed commands", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  for (const changes of [
    { ownerPk: key().pubkey },
    { network: "mutinynet" },
    { walletId: "other" },
    { issuedAt: AT + 1 },
    { expiresAt: AT },
  ])
    assert.throws(() =>
      f.gate.stop(
        signObject(
          { ...f.stop(), ...changes },
          f.owner.secretKey,
        ) as ReturnType<typeof f.stop>,
      ),
    );
  const command = f.stop();
  f.gate.stop(command);
  assert.throws(() => f.gate.stop(command), /REPLAY/);
});
test("tampered durable replay state is rejected before signing", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const r = f.request();
  const d = f.gate.authorize(r);
  assert(d.token);
  const state = JSON.parse(readFileSync(f.gateOptions.stateFile, "utf8"));
  state.state.tokens[d.token.id].used = false;
  state.state.spentByDay = {};
  writeFileSync(f.gateOptions.stateFile, JSON.stringify(state));
  assert.throws(
    () => f.gate.consume(d.token!, r.plan, r.preview),
    /state signature/,
  );
});
test("decoded map, invoice and PSBT amounts, fee, network and recipients are checked", () => {
  for (const mutate of [
    (p: any) => {
      p.amount = "1";
    },
    (p: any) => {
      p.decodedInvoice.amount = "49";
    },
    (p: any) => {
      p.decodedInvoice.network = "signet";
    },
    (p: any) => {
      p.recipientMap[p.assetId][0].recipientId = "other";
    },
    (p: any) => {
      p.recipientMap[p.assetId][0].assignment.Fungible =
        Number.MAX_SAFE_INTEGER + 1;
    },
  ]) {
    const f = gateFixture();
    const p = f.plan();
    mutate(p);
    assert.throws(() => decodeSendPlan(p));
  }
});
test("foreign asset, recipient, wallet, network or excessive fee fail policy", () => {
  for (const mutate of [
    (p: any) => {
      p.assetId = "other";
      p.recipientMap = { other: Object.values(p.recipientMap)[0] };
    },
    (p: any) => {
      p.recipientId = "other";
      p.decodedInvoice.recipientId = "other";
      p.recipientMap[p.assetId][0].recipientId = "other";
    },
    (p: any) => {
      p.walletId = "other";
    },
    (p: any) => {
      p.network = "mutinynet";
      p.decodedInvoice.network = "signet";
    },
  ]) {
    const f = gateFixture();
    f.gate.install(f.policy);
    const p = f.plan();
    mutate(p);
    assert(!f.gate.authorize(f.request(p)).allowed);
  }
  const f = gateFixture();
  f.gate.install(
    signObject({ ...f.policy, maxBitcoinFeeSats: "999" }, f.owner.secretKey),
  );
  assert(
    f.gate.authorize(f.request()).why.includes("BITCOIN_FEE_LIMIT_EXCEEDED"),
  );
});
test("no installed policy is fail-closed and has a decision log", () => {
  const f = gateFixture();
  const d = f.gate.authorize(f.request());
  assert(!d.allowed);
  assert(d.why.includes("NO_POLICY"));
  assert.equal(f.log.entries().length, 1);
});
