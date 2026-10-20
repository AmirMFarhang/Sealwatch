// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
import { createPublicKey, verify } from "node:crypto";
import { canonicalJson, hashObject } from "../core/crypto.js";
import { assert, network } from "../core/validation.js";
import { PAYLOAD_TYPE, type CheckRequest, type EvidenceEnvelope, type ProviderPin, type ProviderRecord, type ProviderResponse } from "./protocol.js";

/** Standard DSSE pre-authentication encoding; lengths count UTF-8 bytes. */
export function pae(type: string, payload: Uint8Array): Buffer {
  const t = Buffer.from(type, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}
function base64(value: unknown): Buffer {
  assert(typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/_-]*={0,2}$/.test(value), "invalid DSSE base64");
  const bytes = Buffer.from(value, "base64");
  assert(bytes.toString("base64url") === value.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"), "noncanonical DSSE base64");
  return bytes;
}
function ident(value: unknown): asserts value is string {
  assert(typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value), "invalid provider identifier");
}
function digest(value: unknown): void { assert(typeof value === "string" && /^[a-f0-9]{64}$/.test(value), "invalid SHA-256 digest"); }
function exactKeys(value: object, keys: string[]): void {
  assert(value && Object.getPrototypeOf(value) === Object.prototype && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort()), "provider output contains unsupported fields");
}
function time(value: unknown): number {
  assert(typeof value === "string" && /^\d{4}-\d\d-\d\dT/.test(value), "invalid provider timestamp");
  const n = Date.parse(value); assert(Number.isFinite(n), "invalid provider timestamp"); return n;
}
export function validateRequest(request: CheckRequest, now = Date.now()): void {
  assert(Buffer.byteLength(canonicalJson(request)) <= 512 * 1024, "provider request too large");
  assert(request.version === 1, "unsupported provider request version");
  digest(request.request_id); network(request.network);
  assert(["transfer-flow-risk", "agent-action-review"].includes(request.check), "unsupported provider check");
  assert(time(request.issued_at) <= now && now < time(request.expires_at) && time(request.expires_at) - time(request.issued_at) <= 300_000, "provider request outside validity window");
  assert(request.subject && typeof request.subject === "object" && !Array.isArray(request.subject), "provider subject malformed");
  assert(request.context && typeof request.context === "object" && !Array.isArray(request.context), "provider context malformed");
  assert(Array.isArray(request.evidence) && request.evidence.length <= 128, "invalid provider evidence");
  const ids = new Set<string>();
  for (const item of request.evidence) {
    ident(item.id); ident(item.kind); digest(item.sha256);
    assert(!ids.has(item.id), "duplicate evidence identifier"); ids.add(item.id);
    assert(hashObject(item.data) === item.sha256, "provider input evidence hash mismatch");
  }
}
/** Verify the exact payload bytes, then parse those bytes once. Keys are external pins. */
export function verifyProviderResponse(response: ProviderResponse, request: CheckRequest, pins: readonly ProviderPin[], now = Date.now()): { record: ProviderRecord; envelope: EvidenceEnvelope; evidence_sha256: string } {
  validateRequest(request, now);
  assert(Buffer.byteLength(canonicalJson(response)) <= 1024 * 1024, "provider response too large");
  const e = response.evidence_envelope;
  assert(e?.payloadType === PAYLOAD_TYPE, "unsupported DSSE payload type");
  const payload = base64(e.payload);
  assert(Array.isArray(e.signatures) && e.signatures.length > 0 && e.signatures.length <= 16, "invalid DSSE signatures");
  const accepted = new Set<string>();
  for (const signature of e.signatures) {
    const sig = base64(signature.sig);
    for (const pin of pins) {
      if (signature.keyid !== undefined && signature.keyid !== pin.keyid) continue;
      const pk = createPublicKey(pin.public_key_pem);
      assert(pk.asymmetricKeyType === "ed25519", "provider key must be Ed25519");
      if (verify(null, pae(e.payloadType, payload), pk, sig)) accepted.add(pin.provider_id);
    }
  }
  assert(accepted.size > 0, "DSSE signature has no trusted provider key");
  const decodedText = new TextDecoder("utf-8", { fatal: true }).decode(payload);
  const record = JSON.parse(decodedText) as ProviderRecord;
  assert(Buffer.from(canonicalJson(record), "utf8").equals(payload), "provider payload must use canonical JSON bytes");
  assert(canonicalJson(record) === canonicalJson(response.result), "unsigned result differs from signed payload");
  assert(record.version === 1 && accepted.has(record.provider_id), "provider identity not bound to trusted key");
  ident(record.provider_id);
  assert(record.request_id === request.request_id && record.request_sha256 === hashObject(request), "provider evidence belongs to another request");
  assert(time(record.issued_at) >= time(request.issued_at) && time(record.issued_at) <= now && now < time(record.expires_at) && time(record.expires_at) <= time(request.expires_at), "provider record outside validity window");
  assert(record.execution === "software", "hardware/device execution requires a real vendor quote verifier");
  ident(record.workload.id); ident(record.workload.version); digest(record.workload.sha256);
  ident(record.model.id); ident(record.model.mode); ident(record.policy.id); digest(record.policy.sha256);
  const allowed = new Set(request.evidence.map(e => e.id));
  assert(Array.isArray(record.input_scope.evidence_ids) && record.input_scope.evidence_ids.every(id => allowed.has(id)) && new Set(record.input_scope.evidence_ids).size === record.input_scope.evidence_ids.length, "provider input scope exceeds supplied evidence");
  const allowedFields = new Set([...request.evidence.map(e => `evidence.${e.id}`), ...Object.keys(request.subject).map(k => `subject.${k}`), ...Object.keys(request.context).map(k => `context.${k}`)]);
  exactKeys(record.input_scope, ["evidence_ids", "fields"]);
  assert(Array.isArray(record.input_scope.fields) && record.input_scope.fields.length <= 128 && record.input_scope.fields.every(f => typeof f === "string" && allowedFields.has(f)), "provider input fields exceed supplied scope");
  const r = record.result;
  assert(r.kind === request.check, "provider result check mismatch");
  exactKeys(r, r.kind === "transfer-flow-risk" ? ["kind", "risk_band", "findings"] : ["kind", "recommendation", "findings"]);
  if (r.kind === "transfer-flow-risk") assert(["low", "review", "high"].includes(r.risk_band), "invalid provider risk band");
  else assert(["approve", "escalate"].includes(r.recommendation), "invalid provider recommendation");
  assert(Array.isArray(r.findings) && r.findings.length <= 128, "invalid findings");
  for (const f of r.findings) {
    exactKeys(f, ["code", "evidence_ids"]);
    assert(typeof f.code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(f.code), "invalid finding code");
    assert(Array.isArray(f.evidence_ids) && f.evidence_ids.length > 0 && f.evidence_ids.every(id => record.input_scope.evidence_ids.includes(id)), "ungrounded finding evidence");
  }
  if ((r.kind === "transfer-flow-risk" && r.risk_band !== "low") || (r.kind === "agent-action-review" && r.recommendation === "escalate")) assert(r.findings.length > 0, "stricter result requires grounded reasons");
  return { record, envelope: e, evidence_sha256: hashObject(e) };
}
