// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Derived from Satstride src/governance/log.ts (Apache-2.0); see NOTICE.
import {
  appendFileSync,
  existsSync,
  readFileSync,
  openSync,
  closeSync,
  fsyncSync,
} from "node:fs";
import {
  hashObject,
  signObject,
  verifyObject,
  type KeyPair,
} from "../core/crypto.js";
import { atomicWrite, withFileLock } from "../core/store.js";
import { assert } from "../core/validation.js";
export interface LogEntry {
  v: 1;
  domain: "trust-decision-log-v1";
  seq: number;
  prevHash: string | null;
  at: number;
  kind: string;
  actionId: string | null;
  result: string;
  detail: unknown;
  nodePk: string;
  hash: string;
  sig: string;
}
export interface LogCheckpoint {
  domain: "trust-log-checkpoint-v1";
  count: number;
  head: string | null;
  nodePk: string;
  sig: string;
}
const body = (e: LogEntry) => {
  const { hash, sig, ...rest } = e;
  return rest;
};
export function verifyLog(
  entries: LogEntry[],
  expectedKey: string,
  checkpoint?: LogCheckpoint,
): string[] {
  const errors: string[] = [];
  entries.forEach((e, i) => {
    if (e.v !== 1 || e.domain !== "trust-decision-log-v1" || e.seq !== i)
      errors.push(`entry ${i}: sequence/domain invalid`);
    if (e.prevHash !== (i === 0 ? null : entries[i - 1].hash))
      errors.push(`entry ${i}: broken hash chain`);
    if (e.hash !== hashObject(body(e)))
      errors.push(`entry ${i}: content hash mismatch`);
    if (e.nodePk !== expectedKey || !verifyObject(e, expectedKey))
      errors.push(`entry ${i}: node signature invalid`);
  });
  if (
    checkpoint &&
    (checkpoint.domain !== "trust-log-checkpoint-v1" ||
      checkpoint.nodePk !== expectedKey ||
      !verifyObject(checkpoint, expectedKey) ||
      checkpoint.count !== entries.length ||
      checkpoint.head !== (entries.at(-1)?.hash ?? null))
  )
    errors.push("checkpoint: truncated, replaced or uncommitted log");
  return errors;
}
export class FileDecisionLog {
  readonly checkpointFile: string;
  constructor(
    readonly file: string,
    private key: KeyPair,
    private now = () => Math.floor(Date.now() / 1000),
  ) {
    this.checkpointFile = `${file}.checkpoint.json`;
  }
  entries(): LogEntry[] {
    if (!existsSync(this.file)) return [];
    return readFileSync(this.file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }
  checkpoint(): LogCheckpoint | undefined {
    return existsSync(this.checkpointFile)
      ? JSON.parse(readFileSync(this.checkpointFile, "utf8"))
      : undefined;
  }
  verify(): string[] {
    try {
      const es = this.entries();
      const cp = this.checkpoint();
      return [
        ...verifyLog(es, this.key.pubkey, cp),
        ...(es.length && !cp ? ["checkpoint missing"] : []),
      ];
    } catch (e) {
      return [`log parse failed: ${(e as Error).message}`];
    }
  }
  append(
    kind: string,
    result: string,
    detail: unknown,
    actionId: string | null = null,
  ): LogEntry {
    return withFileLock(this.file, () => {
      const errors = this.verify();
      assert(!errors.length, `refusing broken log: ${errors.join("; ")}`);
      const es = this.entries();
      const b = {
        v: 1 as const,
        domain: "trust-decision-log-v1" as const,
        seq: es.length,
        prevHash: es.at(-1)?.hash ?? null,
        at: this.now(),
        kind,
        actionId,
        result,
        detail,
        nodePk: this.key.pubkey,
      };
      const entry = signObject(
        { ...b, hash: hashObject(b) },
        this.key.secretKey,
      );
      appendFileSync(this.file, JSON.stringify(entry) + "\n", { mode: 0o600 });
      const fd = openSync(this.file, "r");
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      atomicWrite(
        this.checkpointFile,
        JSON.stringify(
          signObject(
            {
              domain: "trust-log-checkpoint-v1",
              count: es.length + 1,
              head: entry.hash,
              nodePk: this.key.pubkey,
            },
            this.key.secretKey,
          ),
        ) + "\n",
      );
      return entry;
    });
  }
  why(actionId: string): {
    actionId: string;
    entries: LogEntry[];
    chainProblems: string[];
  } {
    return {
      actionId,
      entries: this.entries().filter((e) => e.actionId === actionId),
      chainProblems: this.verify(),
    };
  }
}
