// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import {
  readFileSync,
  writeFileSync,
  statSync,
  existsSync,
  unlinkSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import type { AddressInfo } from "node:net";
import { createTrustServer } from "../src/http.js";
import { PolicyGate } from "../src/governance/gate.js";
import { bytesToHex, randomHex } from "../src/core/crypto.js";
import { SanctionsScreen } from "../src/compliance/sanctions.js";
import type { TrustConfig } from "../src/config.js";
import { AT, incomingFixture, gateFixture, key } from "./helpers.js";
async function apiFixture(t: any) {
  const f = incomingFixture();
  const owner = key();
  const token = randomHex(32);
  const config: TrustConfig = {
    v: 1,
    network: "utexo-testnet",
    walletId: "B-unit",
    stateDir: f.dir,
    checkerSecretEnv: "UNUSED",
    ownerPk: owner.pubkey,
    sanctionsDir: resolve("fixtures/sanctions"),
    flagged: {
      provider: "local-file",
      dir: join(f.dir, "flags"),
      trustedIssuerKeys: [f.flags.issuer.pubkey],
    },
  };
  const gate = new PolicyGate({
    key: f.key,
    ownerPk: owner.pubkey,
    network: "utexo-testnet",
    walletId: config.walletId,
    stateFile: join(f.dir, "gate.json"),
    log: f.log,
    now: () => AT,
  });
  const services = {
    config,
    key: f.key,
    verify: f.service,
    gate,
    log: f.log,
    sanctions: new SanctionsScreen(config.sanctionsDir),
  };
  const server = createTrustServer(services, token);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  t.after(
    () =>
      new Promise<void>((r, e) => server.close((err) => (err ? e(err) : r()))),
  );
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (
    route: string,
    body: unknown,
    headers: Record<string, string> = {},
  ) =>
    fetch(url + route, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        ...headers,
      },
      body: JSON.stringify(body),
    });
  return { ...f, server, url, token, post };
}
test("localhost API authenticates, verifies incoming and independently checks attestation/log", async (t) => {
  const f = await apiFixture(t);
  const res = await f.post("/v1/verify-incoming", f.input);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const a = await res.json();
  assert.equal(a.overall, "clear");
  const verified = await f.post("/v1/attestations/verify", a);
  assert((await verified.json()).valid);
  const log = await f.post("/v1/log/verify", {});
  assert((await log.json()).valid);
});
test("localhost API refuses unauthenticated, cross-origin and non-JSON requests", async (t) => {
  const f = await apiFixture(t);
  assert.equal(
    (
      await f.post("/v1/verify-incoming", f.input, {
        authorization: "Bearer incorrect",
      })
    ).status,
    401,
  );
  assert.equal(
    (
      await f.post("/v1/verify-incoming", f.input, {
        origin: "https://attacker.example",
      })
    ).status,
    403,
  );
  assert.equal(
    (await f.post("/v1/log/verify", {}, { "content-type": "text/plain" }))
      .status,
    415,
  );
  assert.equal((await f.post("/does-not-exist", {})).status, 404);
});
test("localhost API rejects oversized JSON and wrong method", async (t) => {
  const f = await apiFixture(t);
  assert.equal(
    (await f.post("/v1/log/verify", "x".repeat(2 * 1024 * 1024))).status,
    413,
  );
  const response = await fetch(f.url + "/v1/log/verify", {
    headers: { authorization: `Bearer ${f.token}` },
  });
  assert.equal(response.status, 405);
});
test("local demo CLI creates private keys/config and executable verification commands without live claims", () => {
  const relative = `.state/test-cli-${randomHex(8)}`;
  const run = (args: string[], env: NodeJS.ProcessEnv = process.env) =>
    spawnSync(process.execPath, ["bin/trust", ...args], {
      encoding: "utf8",
      env,
    });
  const result = run(["demo-local", "--state-dir", relative]);
  assert.equal(result.status, 0, result.stderr);
  const demo = JSON.parse(result.stdout);
  assert.equal(demo.liveTransfers, false);
  assert.equal(demo.mode, "synthetic-local-structural-demo");
  assert.equal(demo.clear, "clear");
  assert.equal(demo.flagged, "flagged");
  assert(demo.withinAllowed && !demo.overAllowed && !demo.stoppedAllowed);
  const secrets = readFileSync(join(relative, "secrets.env"), "utf8");
  assert.equal(statSync(join(relative, "secrets.env")).mode & 0o777, 0o600);
  assert(!result.stdout.includes(secrets.split("\n")[0].split("=")[1]));
  const env = { ...process.env };
  for (const line of secrets.trim().split("\n")) {
    const [name, value] = line.replace(/^export /, "").split("=");
    env[name] = value;
  }
  const config = ["--config", demo.configFile];
  const verify = run(
    [
      "verify-incoming",
      ...config,
      "--input",
      join(relative, "incoming-clear.json"),
    ],
    env,
  );
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).overall, "clear");
  const att = run([
    "attestation",
    "verify",
    join(relative, "attestation-flagged.json"),
    "--checker-pk",
    demo.checkerPk,
    "--issuer-pk",
    demo.flaggedIssuerPk,
  ]);
  assert.equal(att.status, 0, att.stderr);
  assert(JSON.parse(att.stdout).valid);
  const log = run(["log", "verify", ...config], env);
  assert.equal(log.status, 0, log.stderr);
  assert(JSON.parse(log.stdout).valid);
  const why = run(["why", demo.overActionId, ...config], env);
  assert.equal(why.status, 0, why.stderr);
  assert(why.stdout.includes("PER_SEND_LIMIT_EXCEEDED"));
  const repeated = run(["demo-local", "--state-dir", relative]);
  assert.notEqual(repeated.status, 0);
  assert(repeated.stderr.includes("existing state is preserved"));
});
test("token is durably consumed before signing across two separate Node processes", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  const request = f.request();
  const decision = f.gate.authorize(request);
  assert(decision.token);
  const dataFile = join(f.dir, "child-input.json");
  writeFileSync(
    dataFile,
    JSON.stringify({
      request,
      token: decision.token,
      ownerPk: f.owner.pubkey,
      at: AT,
      stateFile: f.gateOptions.stateFile,
      logFile: f.log.file,
    }),
    { mode: 0o600 },
  );
  const code = `import {readFileSync} from 'node:fs';import {keyPairFromSecret} from './src/core/crypto.ts';import {PolicyGate} from './src/governance/gate.ts';import {FileDecisionLog} from './src/governance/log.ts';const d=JSON.parse(readFileSync(process.env.TRUST_TEST_DATA,'utf8'));const key=keyPairFromSecret(process.env.TRUST_TEST_SECRET);const log=new FileDecisionLog(d.logFile,key,()=>d.at);const gate=new PolicyGate({key,ownerPk:d.ownerPk,network:'utexo-testnet',walletId:'A-unit-only',stateFile:d.stateFile,log,now:()=>d.at});try{gate.consume(d.token,d.request.plan,d.request.preview);process.stdout.write('consumed')}catch(e){process.stderr.write(e.message);process.exitCode=1}`;
  const env = {
    ...process.env,
    TRUST_TEST_DATA: dataFile,
    TRUST_TEST_SECRET: bytesToHex(f.gateKey.secretKey),
  };
  const run = () =>
    spawnSync(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", code],
      { encoding: "utf8", env },
    );
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stdout, "consumed");
  const second = run();
  assert.equal(second.status, 1);
  assert(second.stderr.includes("REUSED"));
});
test("deleted replay state cannot silently initialize beside signed governance history", () => {
  const f = gateFixture();
  f.gate.install(f.policy);
  unlinkSync(f.gateOptions.stateFile);
  assert.throws(
    () => new PolicyGate(f.gateOptions).install(f.policy),
    /prior signed governance history/,
  );
});
