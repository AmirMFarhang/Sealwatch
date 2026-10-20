# Independent QA

**PASS: local security checks and the required live Verify/Authorize testnet proof (§5.5).** The independent meeting-proof veto is lifted as of 20 October 2026. This covers the required transfers, receiver checks, quarantine and spending controls. Settle/escrow and Remember are not built. Other extraction and publication workstreams have separate acceptance.

The reviewer did not implement runtime code. QA used separate branches/worktrees, independently installed dependencies and Node 22.22.2. Operational evidence was read only; QA opened no SDK wallet, seed, private key or database and changed no operational source, wallet, chain or quarantine.

## Reproducible checks

The tested runtime `src` tree is `e92746d4cd3ffb67c58f2aee6f22227cef139fab`; standard `test` tree is `9e30e0455b4319f72d4453d0c7706df86b0e995b`. Both exactly match parent integration `538108875c5210ab53becbf6d858c2e8a2ca02e4`. QA source was frozen at `8f7fa8f`; the final QA commit changes only reports and independent verification scripts.

- Fresh `npm run check`: TypeScript clean, **88/88 standard tests** passed (85 core, 3 network), no failures or skips.
- Fresh `node --import tsx --test qa/security-probes.test.ts qa/native-guard-probes.test.ts`: **15/15** independent adversarial probes passed. Five cover retained-log rollback and process restart; ten inject SDK/account fakes into the actual native wrapper to cover exact plans, durable token consumption, quarantine, stop, policy replacement and expiry at the signing barrier. These probes perform no native wallet/chain actions.
- Prior **9/9 CLI checks** passed: synthetic demo, clear/flagged verification, valid/tampered attestation, valid/tampered log, over-limit reasons and tampered flagged list. They remain recorded in `qa/cli-results.json`.

Fresh logs are durable but ignored under `.state/qa/final-*.log`. Public summaries and reproducible verifier sources are under `qa/`; `release/verification.json` records exact counts, hashes and limits.

## Required live proof

The receipt has status `complete`, updated `2026-10-20T08:10:55.002Z`, SHA-256 `b378b52403ff485a64accc999eebc9174d11da3faf7dac3adef246939e274c35`. It uses the primary Utexo SDK Bitcoin testnet3 setup, without fallback. Two fresh wallets A and B were funded only with public faucet coins. The issued asset is **test USD, not USDT**, ticker TUSD, precision 2.

| Required result | Independent evidence |
| --- | --- |
| A sends 1000 smallest units to B; receiver produces clear | [Confirmed clear witness](https://mempool.space/testnet/tx/e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06), block 5195546; exact raw ID also verified on Blockstream; pinned signed clear attestation passes. |
| A second actual witness input matches the test list | [Confirmed 500-unit flagged witness](https://mempool.space/testnet/tx/8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b), block 5195834; exact raw ID also verified on Blockstream; signed overall/level-1 results are flagged. |
| Receiver refuses quarantined asset spending | Actual live refusal is retained. Both core and native signed quarantine snapshots match retained journals, preserve ERROR and FLAGGED, and refuse the exact asset. Replaying production native `prepareSend` on QA copies refuses before any dummy SDK call. |
| Send within limits goes through | Both actual sends confirmed; receipt approvals and consumed tokens match signed action, plan and policy hashes. |
| Send above limit is refused with why | Actual 1001-unit request refused with `PER_SEND_LIMIT_EXCEEDED`; no token; receipt decision exactly matches signed log. |
| Owner stop blocks next send | Actual prepared 100-unit request refused after signed stop with `KILL_SWITCH_STOPPED`; no token; receipt decision exactly matches signed log. |

Both Mempool and Blockstream independently confirmed **all six** recorded transactions: faucet funding, B-to-A setup split, A/B colorable-UTXO setup, clear transfer and flagged transfer. Twelve checks recomputed every raw transaction ID, compared output scripts/values and fees, and agreed on block hashes. See `qa/public-explorer-checks.json`; no standalone asset-issuance broadcast txid is recorded.

Checker, issuer and gate public keys were pinned before attestations arrived. QA verified canonical signatures, expected network/asset/witness, every required pinned sanctions snapshot and exact clear/flagged semantics. Signed demo-list hashes were independently reconstructed from actual public witness inputs; raw outpoints remain in memory. The authorization journal has **27** entries and receiver journal **9**, with valid signed checkpoints and receipt decision/attestation bindings. The native receiver journal has **6** entries. Its public pin was independently derived by the parent from the known authority file; QA never read its secret.

Reproduce with:

```sh
node --import tsx qa/verify-live-receipt.ts RECEIPT
node --import tsx qa/verify-live-logs.ts DEMO_LOG_DIRECTORY RECEIPT
node --import tsx qa/verify-final-quarantine.ts NETWORK_STATE RECEIPT
node --import tsx qa/verify-public-transactions.ts
```

The quarantine verifier reads only named signed state/log files and operates on copies in QA's ignored state. Hashes confirm operational evidence stayed unchanged. Raw receiver history and wallet databases are never opened.

## Findings history and recovery

The initial implementation accepted old correctly signed state beside a retained current log, bypassing token use, stop, daily reservations and quarantine. `f83e1be` binds exact signed snapshots and increasing revisions to namespace-specific prepare/commit records. Four original failing rollback probes now pass; all five restart/rollback probes pass. Interrupted transactions fail closed and require reviewed recovery.

QA also demonstrated quarantine arriving during asynchronous enrollment and stop/policy/expiry arriving after token consumption but before the WDK policy callback. Native `9494e42`, `11910f6`, `8efb6b9`, `96265ce` and core `6dc050e` now revalidate current signed authority and exact immutable approvals at the signing barrier. All original timing reproductions pass. Failed attempts retain consumed tokens.

The first actual receiver attempt produced an authentic signed `WITNESS_EVIDENCE_INVALID` error because bitcoinjs-lib's Taproot matcher needed an ECC context. Strict decoder fix `d966374` handles only the valid 34-byte OP_1/PUSH32 shape; malformed scripts remain refused. QA reproduced the original failure with public raw transactions and checked corrected addresses against both explorers. Original signed error hash `3fe84d0109915493794efdd2ff8e5b8b05faefc09bd95a776777422cb8d6b0fd` remains in the receipt, signed log and both quarantines. It was never represented as a successful clear result.

Polling/recovery fixes `6dfbe8a`, `18392fa` and `212bdf6` were reviewed before resume. The same confirmed clear witness was reverified without resending. Only expired unpaid invoices without signing attempts could refresh, under a signed next policy version and previous hash. Invalid prior results are preserved; exact clear and flagged result predicates are required. Neither error nor flagged quarantine was cleared. Final evidence is in `qa/final-quarantine-verification.json`, `qa/preserved-live-receiver-error.json`, `qa/taproot-live-regression.json` and `qa/live-recovery-preservation.json`.

## Boundaries and claims

This is public Bitcoin witness-input screening with signed receiver evidence. Receiver-owned SDK/indexer validation supplies RGB asset/receive membership; QA did not independently validate RGB consignments or complete provenance. The test flagged list is explicitly synthetic policy data. Utexo's production flagged-list API remains a refusal stub; ancestry screening is designed. Settle and Remember are not started.

Rollback detection requires a trusted retained current local journal/checkpoint. Restoring snapshots, journal and checkpoint together needs an external anchor, which is not built. Direct wallet keys/raw SDK signing calls are outside the governed adapter boundary. No signature can be revoked after export. Daily reservations conservatively include failed sends until UTC rollover.

Signed logs bind receipt action/token/plan/policy hashes; the compact public receipt does not disclose a complete prepared PSBT. Exact transaction handling is additionally covered by production-source review and independent adapter probes. Quarantine is a local spending restriction and cannot reverse chain settlement.

Architecture and demo claims match these limits. Parent README at `5381088` still has an old pending-live paragraph; the integration owner must update it to completed proof. Earlier explorer polling files are historical checkpoints superseded by final reports above.

