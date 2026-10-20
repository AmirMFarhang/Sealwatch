// Public-chain re-screening of a receiver-held, already settled RGB transfer.
// No wallet process opens, no keys from operational wallets are read, no send occurs.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { canonicalJson, hashObject, randomKeyPair } from "../src/core/crypto.js";
import { FileDecisionLog } from "../src/governance/log.js";
import { VerifyService, attestationProblems } from "../src/verify/incoming.js";
import { SanctionsScreen } from "../src/compliance/sanctions.js";
import { LocalFileFlaggedListProvider, signFlaggedManifest, type FlaggedSnapshot } from "../src/compliance/flagged.js";
import { providerFromEnvironment } from "../src/provider/remote.js";
import { collectPublicTransferEvidence } from "../src/provider/transfer.js";

const inputFile = process.argv[2]; const dir = resolve(process.argv[3] ?? ".state/provider-live");
if (!inputFile) throw new Error("usage: provider-live INPUT_JSON NEW_PRIVATE_OUTPUT_DIR");
mkdirSync(dir, { mode: 0o700 });
const save = (name: string, value: unknown) => writeFileSync(join(dir, name), canonicalJson(value) + "\n", { flag: "wx", mode: 0o600 });
const input = JSON.parse(readFileSync(inputFile, "utf8"));
const key = randomKeyPair(), issuer = randomKeyPair();
// These are new audit/checker authorities, never existing wallet spending keys.
save("checker-secret.json", { secretHex: Buffer.from(key.secretKey).toString("hex") });
save("issuer-secret.json", { secretHex: Buffer.from(issuer.secretKey).toString("hex") });
save("public-trust.json", { checkerPk: key.pubkey, issuerPk: issuer.pubkey, network: input.network });
const at = Math.floor(Date.now() / 1000);
const list: FlaggedSnapshot = { v: 1, domain: "trust-flagged-outpoints-v1", id: "provider-testnet-local-empty", version: "1", network: input.network, testOnly: true, outpoints: [] };
const bytes = Buffer.from(canonicalJson(list));
writeFileSync(join(dir, "flagged-outpoints.json"), bytes, { mode: 0o600, flag: "wx" });
save("manifest.json", signFlaggedManifest(list, "flagged-outpoints.json", bytes, issuer, at - 10, at + 3600));
const log = new FileDecisionLog(join(dir, "decision-log.jsonl"), key);
const provider = providerFromEnvironment(join(dir, "provider-evidence"));
if (!provider) throw new Error("private provider environment required");
const evidence = await collectPublicTransferEvidence(input);
save("input-evidence.json", evidence);
const verify = new VerifyService({ key, network: input.network, receiverWalletId: input.receiverWalletId, sanctions: new SanctionsScreen(resolve("fixtures/sanctions")), flagged: new LocalFileFlaggedListProvider(dir, [issuer.pubkey]), log, historyDir: join(dir, "history"), provider, providerEvidence: async () => evidence });
const attestation = await verify.verifyIncoming(input);
save("attestation.json", attestation);
const problems = attestationProblems(attestation, { checkerPk: key.pubkey, flaggedIssuerKeys: [issuer.pubkey], network: input.network });
save("receipt.json", { network: input.network, networkLabel: "Utexo SDK Bitcoin testnet3", operation: "fresh-provider-rescreen-of-existing-confirmed-receive", newTransactionBroadcast: false, witnessTxid: input.witnessTxid, priorReceiverInputHash: hashObject(input), attestation, problems, logProblems: log.verify() });
console.log(canonicalJson({ network: input.network, witnessTxid: input.witnessTxid, execution: attestation.execution, overall: attestation.overall, providerEvidenceHash: attestation.provider?.evidence_sha256 ?? null, problems, logProblems: log.verify() }));
if (!attestation.provider || problems.length || log.verify().length) process.exitCode = 1;
