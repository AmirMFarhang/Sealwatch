// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  unlinkSync,
  renameSync,
  mkdirSync,
  rmdirSync,
} from "node:fs";
import { join } from "node:path";
import { hashObject, randomHex, signObject } from "../src/core/crypto.js";
import { SignedStore } from "../src/core/store.js";
import { FileDecisionLog } from "../src/governance/log.js";
import { AT, key, temp } from "./helpers.js";
function fixture() {
  const dir = temp(),
    k = key();
  const log = new FileDecisionLog(join(dir, "journal.jsonl"), k, () => AT);
  const file = join(dir, "state.json");
  const store = new SignedStore(file, k, () => ({ count: 0 }), {
    log,
    namespace: "test-counter",
  });
  return { dir, key: k, log, file, store };
}
test("retained signed journal rejects an older legitimate signed mutable snapshot", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const old = readFileSync(f.file);
  f.store.transact((s) => {
    s.count = 2;
  });
  writeFileSync(f.file, old);
  assert.throws(() => f.store.read(), /rollback/);
});
test("unrelated signed log entries do not invalidate a current state snapshot", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  f.log.append("unrelated", "informational", { any: "event" });
  assert.equal(f.store.read().count, 1);
  f.store.transact((s) => {
    s.count = 2;
  });
  assert.equal(f.store.read().count, 2);
});
test("separate namespaces share one signed log without inheriting each others revisions", () => {
  const f = fixture();
  const other = new SignedStore(
    join(f.dir, "other.json"),
    f.key,
    () => ({ count: 0 }),
    { log: f.log, namespace: "other-counter" },
  );
  f.store.transact((s) => {
    s.count = 1;
  });
  other.transact((s) => {
    s.count = 9;
  });
  f.store.transact((s) => {
    s.count = 2;
  });
  assert.equal(other.read().count, 9);
  assert.equal(f.store.read().count, 2);
});
test("interrupted preparation refuses old state despite no committed snapshot replacement", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const prior = JSON.parse(readFileSync(f.file, "utf8"));
  f.log.append("state-prepare", "prepared", {
    namespace: "test-counter",
    revision: prior.revision + 1,
    previousHash: hashObject(prior),
    transactionId: randomHex(16),
  });
  assert.throws(() => f.store.read(), /incomplete transaction/);
  assert.throws(
    () =>
      f.store.transact((s) => {
        s.count = 0;
      }),
    /incomplete transaction/,
  );
});
test("snapshot from newer state refuses an older retained log/checkpoint pair", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const oldLog = readFileSync(f.log.file),
    oldCheckpoint = readFileSync(f.log.checkpointFile);
  f.store.transact((s) => {
    s.count = 2;
  });
  writeFileSync(f.log.file, oldLog);
  writeFileSync(f.log.checkpointFile, oldCheckpoint);
  assert.throws(() => f.store.read(), /uncommitted snapshot/);
});
test("a valid signed snapshot not committed to the journal remains unusable", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const prior = JSON.parse(readFileSync(f.file, "utf8"));
  const newer = signObject(
    {
      ...prior,
      revision: prior.revision + 1,
      previousHash: hashObject(prior),
      state: { count: 999 },
    },
    f.key.secretKey,
  );
  writeFileSync(f.file, JSON.stringify(newer));
  assert.throws(() => f.store.read(), /uncommitted snapshot/);
});
test("expected refusal aborts preparation without changing durable state and later writes work", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const prior = readFileSync(f.file);
  assert.throws(
    () =>
      f.store.transact((s) => {
        s.count = 99;
        f.log.append("refused-operation", "refused", {});
        throw new Error("expected refusal");
      }),
    /expected refusal/,
  );
  assert.deepEqual(readFileSync(f.file), prior);
  assert.equal(f.store.read().count, 1);
  f.store.transact((s) => {
    s.count = 2;
  });
  assert.equal(f.store.read().count, 2);
  assert.deepEqual(f.log.verify(), []);
});
test("failed journal abort leaves interrupted preparation and refuses ambiguous state", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const append = f.log.append.bind(f.log);
  f.log.append = (...args: Parameters<FileDecisionLog["append"]>) => {
    if (args[0] === "state-abort")
      throw new Error("simulated lost abort write");
    return append(...args);
  };
  assert.throws(
    () =>
      f.store.transact(() => {
        throw new Error("refusal");
      }),
    /lost abort/,
  );
  f.log.append = append;
  assert.throws(() => f.store.read(), /incomplete transaction/);
});
test("failed journal commit leaves preparation and never exposes modified state", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const prior = readFileSync(f.file);
  const append = f.log.append.bind(f.log);
  f.log.append = (...args: Parameters<FileDecisionLog["append"]>) => {
    if (args[0] === "state-commit")
      throw new Error("simulated lost commit write");
    return append(...args);
  };
  assert.throws(
    () =>
      f.store.transact((s) => {
        s.count = 99;
      }),
    /lost commit/,
  );
  f.log.append = append;
  assert.deepEqual(readFileSync(f.file), prior);
  assert.throws(() => f.store.read(), /incomplete transaction/);
});
test("committed journal with failed atomic snapshot replacement refuses restored older file", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const backup = join(f.dir, "prior.snapshot");
  assert.throws(() =>
    f.store.transact((s) => {
      s.count = 99;
      renameSync(f.file, backup);
      mkdirSync(f.file);
    }),
  );
  rmdirSync(f.file);
  renameSync(backup, f.file);
  assert.deepEqual(f.log.verify(), []);
  assert.throws(() => f.store.read(), /rollback/);
});
test("same namespace at a different missing file cannot initialize a second history", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  const competing = new SignedStore(
    join(f.dir, "duplicate.json"),
    f.key,
    () => ({ count: 0 }),
    { log: f.log, namespace: "test-counter" },
  );
  assert.throws(
    () =>
      competing.transact((s) => {
        s.count = 999;
      }),
    /missing.*history/,
  );
});
test("journal fork or orphan commit refuses state even when signed by node", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  f.log.append("state-commit", "committed", {
    namespace: "test-counter",
    revision: 9,
    previousHash: null,
    transactionId: randomHex(16),
    stateHash: "ab".repeat(32),
  });
  assert.throws(() => f.store.read(), /matching prepare/);
});
test("legacy signed v1 snapshot cannot silently establish a new state journal", () => {
  const f = fixture();
  writeFileSync(
    f.file,
    JSON.stringify(
      signObject(
        {
          domain: "trust-state-v1",
          pubkey: f.key.pubkey,
          state: { count: 999 },
        },
        f.key.secretKey,
      ),
    ),
  );
  assert.throws(() => f.store.read(), /legacy/);
});
test("deleting a signed store after first commit refuses reset even without domain-specific events", () => {
  const f = fixture();
  f.store.transact((s) => {
    s.count = 1;
  });
  unlinkSync(f.file);
  assert.throws(() => f.store.read(), /missing.*history/);
});
