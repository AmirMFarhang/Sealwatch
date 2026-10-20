// Copyright 2026 Amir Mohammad Farhang; all rights reserved; private.
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { canonicalJson } from "../core/crypto.js";
import { assert } from "../core/validation.js";
import { validateRequest, verifyProviderResponse } from "./dsse.js";
import type { AttestedCheckProvider, CheckRequest, ProviderPin, ProviderResponse, VerifiedCheck } from "./protocol.js";
export class RemoteCheckProvider implements AttestedCheckProvider {
  private readonly url: URL;
  constructor(private options: { url: string; token: string; pins: readonly ProviderPin[]; evidenceDir: string; timeoutMs?: number; now?: () => number }) {
    this.options = { ...options, pins: JSON.parse(canonicalJson(options.pins)) };
    this.url = new URL(options.url);
    assert(!this.url.username && !this.url.password && !this.url.search && !this.url.hash, "provider URL must not contain credentials/query/fragment");
    assert(this.url.protocol === "https:" || (this.url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(this.url.hostname)), "provider transport requires HTTPS or literal loopback HTTP");
    assert(options.token.length >= 32 && !/[\r\n]/.test(options.token), "provider authentication token missing/invalid");
    assert(options.pins.length > 0 && isAbsolute(options.evidenceDir), "provider pins and absolute private evidence directory required");
  }
  async check(request: CheckRequest): Promise<VerifiedCheck> {
    const body = canonicalJson(request); // Freeze caller input before awaiting transport.
    const frozen = JSON.parse(body) as CheckRequest;
    validateRequest(frozen, this.options.now?.() ?? Date.now());
    const response = await fetch(this.url, {
      method: "POST", redirect: "error", headers: { "content-type": "application/json", authorization: `Bearer ${this.options.token}` }, body,
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 30_000),
    });
    assert(response.ok, `provider request refused (HTTP ${response.status})`);
    assert(response.headers.get("content-type")?.split(";")[0].trim() === "application/json", "provider response must be JSON");
    assert(response.body, "provider response body missing");
    const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length; assert(size <= 1024 * 1024, "provider response too large"); chunks.push(part.value); }
    } catch (error) { await reader.cancel(); throw error; }
    const decoded = JSON.parse(Buffer.concat(chunks).toString("utf8")) as ProviderResponse;
    const checked = verifyProviderResponse(decoded, frozen, this.options.pins, this.options.now?.() ?? Date.now());
    mkdirSync(this.options.evidenceDir, { recursive: true, mode: 0o700 });
    const file = join(this.options.evidenceDir, `${checked.evidence_sha256}.json`);
    // Exclusive request marker prevents accepting the same request after restart.
    writeFileSync(join(this.options.evidenceDir, `request-${frozen.request_id}.used`), checked.evidence_sha256, { flag: "wx", mode: 0o600 });
    writeFileSync(file, canonicalJson({ request: frozen, ...decoded }) + "\n", { flag: "wx", mode: 0o600 });
    return { record: checked.record, evidence_sha256: checked.evidence_sha256, evidence_file: file };
  }
}
/** Endpoint and pins are never repository configuration values. */
export function providerFromEnvironment(evidenceDir: string): RemoteCheckProvider | undefined {
  const url = process.env.TRUST_PROVIDER_URL;
  const keysFile = process.env.TRUST_PROVIDER_KEYS_FILE;
  const token = process.env.TRUST_PROVIDER_TOKEN;
  if (!url && !keysFile && !token) return undefined;
  assert(url && keysFile && token, "provider URL, pinned keys file and token must all be supplied");
  const pins = JSON.parse(readFileSync(keysFile, "utf8")) as { providers: ProviderPin[] };
  assert(Array.isArray(pins.providers), "provider key file malformed");
  const timeoutMs = Number(process.env.TRUST_PROVIDER_TIMEOUT_MS ?? 270_000);
  assert(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 270_000, "provider timeout must be 1..270000 milliseconds");
  return new RemoteCheckProvider({ url, token, pins: pins.providers, evidenceDir, timeoutMs });
}
