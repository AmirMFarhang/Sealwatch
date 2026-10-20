// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "./core/crypto.js";
import { assert } from "./core/validation.js";
import { loadConfig } from "./config.js";
import { createTrustServer } from "./http.js";
import { demoLocal } from "./demo-local.js";
import { attestationProblems } from "./verify/incoming.js";
import { createAuditPack, saveAuditPack, verifyAuditPackFile, type PackTrust } from "./audit/pack.js";
import { RECEIVER_POLICY } from "./verify/policy.js";
const help = `Private trust layer: Verify, Authorize, Settle, Remember.
Node 22/24 only. Utexo testnet primary; Mutinynet is the fallback.
Commands (JSON output; --config defaults to trust.config.json):
  trust demo-local --state-dir .state/local-demo
  trust verify-incoming --input incoming.json
  trust attestation verify attestation.json --checker-pk HEX --issuer-pk HEX
  trust log verify
  trust audit export SPEC_JSON OUTPUT_ZIP
  trust audit verify ZIP_FILE TRUST_JSON
  trust policy install policy.json
  trust authorize request.json
  trust stop stop-command.json
  trust why ACTION_ID
  trust serve
Signing keys are supplied through the environment named in config. Policy,
request and stop-command files must already be signed by their authorized keys.
Settle is designed; RGB ancestry and Utexo flagged-list API are not built.
`;
export async function main(argv = process.argv.slice(2)): Promise<void> {
  const args = [...argv];
  const option = (name: string, otherwise?: string) => {
    const index = args.indexOf(name);
    if (index < 0) return otherwise;
    assert(index + 1 < args.length, `missing ${name} value`);
    const value = args[index + 1];
    args.splice(index, 2);
    return value;
  };
  const statePath = option("--state-dir", ".state/local-demo")!;
  const configPath = option("--config", "trust.config.json")!;
  const inputPath = option("--input");
  const checkerPk = option("--checker-pk");
  const issuerPk = option("--issuer-pk");
  const output = (value: unknown) =>
    process.stdout.write(canonicalJson(value) + "\n");
  const json = (file: string | undefined) => {
    assert(file, "a JSON input file is required");
    return JSON.parse(readFileSync(file, "utf8"));
  };
  if (!args.length || args.includes("--help") || args[0] === "help") {
    process.stdout.write(help);
    return;
  }
  if (
    args[0] === "attestation" &&
    args[1] === "verify" &&
    checkerPk &&
    issuerPk
  ) {
    const problems = attestationProblems(json(args[2] ?? inputPath), {
      checkerPk,
      flaggedIssuerKeys: [issuerPk],
    });
    output({ valid: !problems.length, problems });
    if (problems.length) process.exitCode = 1;
    return;
  }
  if (args[0] === "demo-local") {
    output(await demoLocal(statePath));
    return;
  }
  if (args[0] === "audit" && args[1] === "verify") {
    const problems = verifyAuditPackFile(args[2], json(args[3]) as PackTrust);
    output({ valid: !problems.length, problems });
    if (problems.length) process.exitCode = 1;
    return;
  }
  const services = loadConfig(configPath);
  switch (args[0]) {
    case "audit": {
      assert(args[1] === "export", "use audit export or audit verify");
      const spec = json(args[2]) as { attestation: string; providerEvidence?: string; trust: string; policy?: string };
      const bytes = createAuditPack({ attestation: json(spec.attestation), entries: services.log.entries(), checkpoint: services.log.checkpoint()!, policy: spec.policy ? json(spec.policy) : RECEIVER_POLICY, ...(spec.providerEvidence ? { provider: json(spec.providerEvidence) } : {}) }, services.key, json(spec.trust));
      assert(args[3], "audit output ZIP required");
      saveAuditPack(args[3], bytes); output({ exported: true, bytes: bytes.length });
      break;
    }
    case "verify-incoming":
      output(await services.verify.verifyIncoming(json(inputPath ?? args[1])));
      break;
    case "attestation": {
      assert(args[1] === "verify", "use attestation verify");
      const problems = attestationProblems(json(args[2] ?? inputPath), {
        checkerPk: services.key.pubkey,
        flaggedIssuerKeys: services.config.flagged.trustedIssuerKeys,
        network: services.config.network,
        sanctionsListPins: services.sanctions.lists
          .filter((l) => !l.testOnly)
          .map((l) => l.sha256),
      });
      output({ valid: !problems.length, problems });
      if (problems.length) process.exitCode = 1;
      break;
    }
    case "log": {
      assert(args[1] === "verify", "use log verify");
      const problems = services.log.verify();
      output({ valid: !problems.length, problems });
      if (problems.length) process.exitCode = 1;
      break;
    }
    case "policy":
      assert(args[1] === "install", "use policy install");
      services.gate.install(json(args[2] ?? inputPath));
      output({ installed: true });
      break;
    case "authorize":
      output(services.gate.authorize(json(args[1] ?? inputPath)));
      break;
    case "stop":
      services.gate.stop(json(args[1] ?? inputPath));
      output({ stopped: true });
      break;
    case "why":
      assert(args[1], "action id required");
      output(services.gate.why(args[1]));
      break;
    case "serve": {
      const http = services.config.http;
      assert(http, "HTTP config missing");
      const token = process.env[http.tokenEnv];
      assert(token, "HTTP token env missing");
      const server = createTrustServer(services, token);
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(http.port, "127.0.0.1", resolve);
      });
      output({
        listening: `http://127.0.0.1:${http.port}`,
        network: services.config.network,
      });
      break;
    }
    default:
      throw new Error("unknown command; run trust --help");
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((e) => {
    process.stderr.write(canonicalJson({ error: (e as Error).message }) + "\n");
    process.exitCode = 1;
  });
