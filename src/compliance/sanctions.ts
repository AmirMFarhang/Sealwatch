// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Adapted from Satstride src/compliance/sanctions.ts (Apache-2.0); see NOTICE.
import { readFileSync } from "node:fs";
import { resolve, relative } from "node:path";
import { sha256Hex } from "../core/crypto.js";
import { assert } from "../core/validation.js";
export const BUNDLED_SANCTIONS_MANIFEST_SHA256 =
  "37b8ac7a74045a7fd60c063c2680b36ce9caf9bcda81a2b13de50a5f42e65f51";
export interface ListInfo {
  id: string;
  version: string;
  sha256: string;
  testOnly: boolean;
}
export const normalizeAddress = (address: string) =>
  /^(bc|tb|bcrt)1/i.test(address) ? address.toLowerCase() : address;
export function localFile(dir: string, file: string): string {
  const path = resolve(dir, file);
  assert(
    relative(resolve(dir), path) !== "" &&
      !relative(resolve(dir), path).startsWith("..") &&
      !file.startsWith("/"),
    "list path escapes its configured directory",
  );
  return path;
}
export class SanctionsScreen {
  readonly lists: ListInfo[] = [];
  private entries = new Set<string>();
  constructor(
    dir: string,
    manifestHash = BUNDLED_SANCTIONS_MANIFEST_SHA256,
    extra?: { id: string; version: string; addresses: string[] },
  ) {
    const bytes = readFileSync(resolve(dir, "manifest.json"));
    assert(
      sha256Hex(bytes) === manifestHash,
      "sanctions manifest does not match trusted SHA-256 pin",
    );
    const manifest = JSON.parse(bytes.toString());
    assert(
      manifest.v === 1 &&
        Array.isArray(manifest.lists) &&
        manifest.lists.length > 0,
      "sanctions manifest missing lists",
    );
    for (const m of manifest.lists) {
      const data = readFileSync(localFile(dir, m.file));
      assert(
        sha256Hex(data) === m.sha256,
        `sanctions file hash mismatch: ${m.file}`,
      );
      const lines = data
        .toString()
        .split("\n")
        .filter((l) => l.trim());
      assert(lines.length === m.entries, "sanctions entry count mismatch");
      assert(
        m.format === "lines" || m.format.startsWith("tsv"),
        "unknown sanctions format",
      );
      for (const line of lines)
        this.entries.add(
          normalizeAddress(m.format === "lines" ? line : line.split("\t")[0]),
        );
      this.lists.push({
        id: m.list_id,
        version: m.as_of,
        sha256: m.sha256,
        testOnly: false,
      });
    }
    if (extra) {
      assert(
        extra.id.startsWith("test-"),
        "test list must be explicitly labelled test-*",
      );
      for (const address of extra.addresses)
        this.entries.add(normalizeAddress(address));
      this.lists.push({
        id: extra.id,
        version: extra.version,
        sha256: sha256Hex(JSON.stringify(extra)),
        testOnly: true,
      });
    }
  }
  screen(addresses: string[]): {
    status: "clear" | "flagged";
    screened: number;
    hits: string[];
  } {
    const unique = [...new Set(addresses.map(normalizeAddress))];
    const hits = unique.filter((a) => this.entries.has(a));
    return {
      status: hits.length ? "flagged" : "clear",
      screened: unique.length,
      hits,
    };
  }
}
