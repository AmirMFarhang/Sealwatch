import { readFileSync, writeFileSync } from "node:fs";
import { canonicalJson, hashObject, sha256Hex, signObject, verifyObject, type KeyPair } from "../core/crypto.js";
import { assert } from "../core/validation.js";
import { attestationProblems, type Attestation, type AttestationTrust } from "../verify/incoming.js";
import { verifyLog, type LogEntry, type LogCheckpoint } from "../governance/log.js";
import { verifyProviderResponse } from "../provider/dsse.js";
import type { CheckRequest, ProviderPin, ProviderResponse } from "../provider/protocol.js";
import { encodeZip, decodeZip } from "./zip.js";
type ProviderEvidence = ProviderResponse & { request: CheckRequest };
interface Manifest {
  version: 1; domain: "trust-audit-pack-v1"; checkerPk: string;
  files: { name: string; sha256: string; bytes: number }[]; sig: string;
}
export interface PackTrust extends AttestationTrust { logPk: string; providerPins: readonly ProviderPin[] }
export function createAuditPack(input: { attestation: Attestation; entries: LogEntry[]; checkpoint: LogCheckpoint; policy: unknown; provider?: ProviderEvidence }, key: KeyPair, trust: PackTrust): Buffer {
  assert(key.pubkey === input.attestation.checkerPk && key.pubkey === trust.checkerPk, "audit pack signer must be trusted checker");
  const values: Record<string, unknown> = { "attestation.json": input.attestation, "log.json": input.entries, "checkpoint.json": input.checkpoint, "policy.json": input.policy };
  if (input.provider) values["provider-evidence.json"] = input.provider;
  const files = new Map(Object.entries(values).map(([name, value]) => [name, Buffer.from(canonicalJson(value) + "\n")]));
  const manifest = signObject({ version: 1 as const, domain: "trust-audit-pack-v1" as const, checkerPk: key.pubkey, files: [...files].map(([name, bytes]) => ({ name, sha256: sha256Hex(bytes), bytes: bytes.length })) }, key.secretKey);
  files.set("manifest.json", Buffer.from(canonicalJson(manifest) + "\n"));
  const pack = encodeZip(files);
  const problems = verifyAuditPack(pack, trust); assert(!problems.length, `audit pack is inconsistent: ${problems.join("; ")}`);
  return pack;
}
export function verifyAuditPack(bytes: Buffer, trust: PackTrust): string[] {
  try {
    const files = decodeZip(bytes);
    const json = (name: string) => { const file = files.get(name); assert(file, `audit pack missing ${name}`); return JSON.parse(file.toString("utf8")); };
    const m = json("manifest.json") as Manifest;
    assert(m.version === 1 && m.domain === "trust-audit-pack-v1" && m.checkerPk === trust.checkerPk && verifyObject(m, trust.checkerPk), "audit manifest signature/trust invalid");
    assert(Array.isArray(m.files) && new Set(m.files.map(f => f.name)).size === m.files.length && m.files.length === files.size - 1, "audit manifest inventory mismatch");
    const allowed = new Set(["attestation.json", "log.json", "checkpoint.json", "policy.json", "provider-evidence.json"]);
    for (const item of m.files) { const file = files.get(item.name); assert(allowed.has(item.name) && file && file.length === item.bytes && sha256Hex(file) === item.sha256, "audit file hash/inventory mismatch"); }
    const a = json("attestation.json") as Attestation;
    const problems = attestationProblems(a, trust);
    const entries = json("log.json") as LogEntry[];
    const checkpoint = json("checkpoint.json") as LogCheckpoint;
    assert(checkpoint, "signed audit log checkpoint required");
    problems.push(...verifyLog(entries, trust.logPk, checkpoint));
    assert(entries.some(e => e.kind === "incoming-verification" && (e.detail as any)?.attestationHash === hashObject(a) && e.result === a.overall), "audit decision absent from signed log");
    const policy = json("policy.json");
    assert(a.v === 2 && a.verificationPolicy && policy.id === a.verificationPolicy.id && policy.version === a.verificationPolicy.version && hashObject(policy) === a.verificationPolicy.sha256, "audit policy version/hash binding invalid");
    if (a.provider) {
      const p = json("provider-evidence.json") as ProviderEvidence;
      // Archive verification checks validity at signed issuance, rather than treating an old receipt as a fresh approval.
      const issued = Date.parse(p.result.issued_at);
      const decisionTime = Math.max(issued, a.time * 1000);
      const checked = verifyProviderResponse(p, p.request, trust.providerPins, decisionTime);
      assert(issued < (a.time + 1) * 1000 && issued >= Date.parse(p.request.issued_at), "provider evidence chronology invalid");
      assert(checked.evidence_sha256 === a.provider.evidence_sha256 && checked.record.provider_id === a.provider.provider_id && canonicalJson(checked.record.result) === canonicalJson(a.provider.provider_result), "audit provider summary/hash binding invalid");
      assert(p.request.subject.witness_txid === a.witnessTxid && p.request.subject.asset_id === a.assetId && p.request.network === a.network, "audit provider transfer binding invalid");
    } else assert(!files.has("provider-evidence.json"), "unexpected provider evidence");
    return problems;
  } catch (error) { return [(error as Error).message]; }
}
export function saveAuditPack(file: string, bytes: Buffer): void { writeFileSync(file, bytes, { flag: "wx", mode: 0o600 }); }
export function verifyAuditPackFile(file: string, trust: PackTrust): string[] { return verifyAuditPack(readFileSync(file), trust); }
