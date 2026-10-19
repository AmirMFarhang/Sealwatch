// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
// Derived from Satstride src/governance/store.ts (Apache-2.0); see NOTICE.
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  hashObject,
  isHex,
  randomHex,
  signObject,
  verifyObject,
  type KeyPair,
} from "./crypto.js";
import type { FileDecisionLog, LogEntry } from "../governance/log.js";
import { assert } from "./validation.js";
/** Fail closed on an existing lock. Never evict a live writer using a time heuristic. */
export function withFileLock<T>(file: string, fn: () => T): T {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  let fd: number;
  try {
    fd = openSync(`${file}.lock`, "wx", 0o600);
  } catch (e) {
    throw new Error(
      `state locked; retry after the writer exits: ${file}.lock`,
      { cause: e },
    );
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    unlinkSync(`${file}.lock`);
  }
}
export function atomicWrite(file: string, contents: string): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  const fd = openSync(temp, "w", 0o600);
  try {
    writeFileSync(fd, contents);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temp, file);
  const dir = openSync(dirname(file), "r");
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}
interface StateEnvelope<T> {
  domain: "trust-state-v2";
  namespace: string;
  revision: number;
  previousHash: string | null;
  pubkey: string;
  state: T;
  sig: string;
}
interface StateTransition {
  namespace: string;
  revision: number;
  previousHash: string | null;
  transactionId: string;
  stateHash?: string;
}
interface JournalHead {
  revision: number;
  stateHash: string | null;
  pending: StateTransition | null;
}
/** Interpret only this store's journal; unrelated log events cannot establish freshness. */
function stateHead(entries: LogEntry[], namespace: string): JournalHead {
  const head: JournalHead = { revision: 0, stateHash: null, pending: null };
  for (const entry of entries) {
    if (!["state-prepare", "state-commit", "state-abort"].includes(entry.kind))
      continue;
    const detail = entry.detail as StateTransition | null;
    if (!detail || detail.namespace !== namespace) continue;
    assert(
      Number.isSafeInteger(detail.revision) &&
        detail.revision > 0 &&
        isHex(detail.transactionId, 16),
      "state journal transition malformed",
    );
    if (entry.kind === "state-prepare") {
      assert(
        !head.pending &&
          detail.revision === head.revision + 1 &&
          detail.previousHash === head.stateHash,
        "state journal history fork or incomplete transaction",
      );
      head.pending = detail;
    } else {
      assert(
        head.pending &&
          detail.transactionId === head.pending.transactionId &&
          detail.revision === head.pending.revision &&
          detail.previousHash === head.pending.previousHash,
        "state journal commit/abort lacks matching prepare",
      );
      if (entry.kind === "state-commit") {
        assert(
          isHex(detail.stateHash, 32),
          "state journal commit hash malformed",
        );
        head.revision = detail.revision;
        head.stateHash = detail.stateHash;
      }
      head.pending = null;
    }
  }
  return head;
}
export class SignedStore<T> {
  constructor(
    readonly file: string,
    private key: KeyPair,
    private initial: () => T,
    private journal: { log: FileDecisionLog; namespace: string },
  ) {
    assert(
      journal.namespace.length > 0,
      "signed state requires a journal namespace",
    );
  }

  private snapshot(): { state: T; revision: number; stateHash: string | null } {
    const entries = this.journal.log.verifiedEntries();
    const head = stateHead(entries, this.journal.namespace);
    assert(
      !head.pending,
      "state journal has an incomplete transaction; refusing ambiguous crash state",
    );
    if (!existsSync(this.file)) {
      assert(
        head.revision === 0,
        "state file missing beside committed journal history; refusing replay-state reset",
      );
      return { state: this.initial(), revision: 0, stateHash: null };
    }
    const value = JSON.parse(
      readFileSync(this.file, "utf8"),
    ) as StateEnvelope<T>;
    assert(
      value.domain === "trust-state-v2" &&
        value.namespace === this.journal.namespace &&
        value.pubkey === this.key.pubkey &&
        verifyObject(value, this.key.pubkey),
      "state signature/domain invalid; legacy, altered or foreign state requires explicit offline recovery",
    );
    const stateHash = hashObject(value);
    assert(
      value.revision === head.revision && stateHash === head.stateHash,
      "state rollback or uncommitted snapshot: revision/hash differs from retained signed journal history",
    );
    return {
      state: structuredClone(value.state),
      revision: value.revision,
      stateHash,
    };
  }
  read(): T {
    return this.snapshot().state;
  }

  transact<R>(fn: (state: T) => R): R {
    return withFileLock(this.file, () => {
      const prior = this.snapshot();
      const transition: StateTransition = {
        namespace: this.journal.namespace,
        revision: prior.revision + 1,
        previousHash: prior.stateHash,
        transactionId: randomHex(16),
      };
      const expectPrior = (entries: LogEntry[]) => {
        const head = stateHead(entries, this.journal.namespace);
        assert(
          !head.pending &&
            head.revision === prior.revision &&
            head.stateHash === prior.stateHash,
          "state journal changed before prepare; retry with current state",
        );
      };
      const expectPending = (entries: LogEntry[]) => {
        const head = stateHead(entries, this.journal.namespace);
        assert(
          head.pending?.transactionId === transition.transactionId,
          "state journal pending transaction changed",
        );
      };
      this.journal.log.append(
        "state-prepare",
        "prepared",
        transition,
        null,
        expectPrior,
      );
      let result: R;
      try {
        result = fn(prior.state);
      } catch (error) {
        // A deliberate refusal may close its preparation. If the log is damaged,
        // abort also fails and the incomplete journal continues to fail closed.
        this.journal.log.append(
          "state-abort",
          "aborted",
          transition,
          null,
          expectPending,
        );
        throw error;
      }
      const value = signObject(
        {
          domain: "trust-state-v2" as const,
          namespace: this.journal.namespace,
          revision: transition.revision,
          previousHash: transition.previousHash,
          pubkey: this.key.pubkey,
          state: prior.state,
        },
        this.key.secretKey,
      );
      // Journal commitment precedes replacement. A crash at either boundary leaves
      // a pending preparation or a snapshot/hash mismatch, never usable old state.
      this.journal.log.append(
        "state-commit",
        "committed",
        { ...transition, stateHash: hashObject(value) },
        null,
        expectPending,
      );
      atomicWrite(this.file, JSON.stringify(value) + "\n");
      return result;
    });
  }
}
