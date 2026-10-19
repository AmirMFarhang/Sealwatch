# Independent QA

The QA reviewer did not implement the runtime. Checks run in separate QA branches/worktrees with independently installed dependencies on Node 22.22.2. No operational wallet, seed, database or chain state was edited.

## Current verdict

Local acceptance **passes** after the journal and native signing-barrier fixes. The end-to-end meeting demonstration is **incomplete** until its actual RGB transfers, clear/flagged attestations, quarantine, authorized send, over-limit refusal and stop refusal are recorded and independently checked. Confirmed faucet funding alone does not satisfy that condition.

## Reproducible checks

Final tested QA source commit: `808c7a4f07d4f9aa4818c247dd00aa443e4b2c13`. Runtime `src` Git tree: `baa6f2dcbcf7fd87c5c91d806bc72d5cd21c67c8`; standard `test` tree: `952083637f67a184c738206546376049cc98d1ab`. The parent integration may have different commit IDs; matching these source/test trees establishes the tested content.

- `npm ci` and `npm run check`: TypeScript clean; 84/84 standard tests (81 core, 3 network) passed, zero failed or skipped.
- `node --import tsx --test qa/security-probes.test.ts`: the same five independent rollback/process-restart probes passed after the journal fix. Four of those probes failed on the original frozen source `d14a0c3`.
- `node --import tsx --test qa/native-guard-probes.test.ts`: injected SDK/account probes exercise the real wallet wrapper; they are synthetic and perform no native wallet or chain actions. All ten native probes pass, including quarantine, owner stop, policy replacement and token expiry arriving after token consumption but before the actual signing-policy callback. These are additional to the five independent core rollback/process-restart probes.
- Nine independent CLI checks passed: fresh synthetic demo, clear and flagged inputs, valid attestation, tampered attestation refusal, valid log, over-limit `why`, tampered flagged-list refusal and tampered-log detection. `qa/cli-results.json` records the results without secrets or raw history.

## Findings and boundaries

The original signed state accepted an old correctly signed snapshot even when the current signed decision log/checkpoint remained intact. This bypassed token use, the stop switch, daily reservations and quarantine. Commit `f83e1be` binds exact signed snapshot hashes and increasing revisions to namespace-specific prepare/commit records. The unchanged QA probes now pass. Crashes at preparation, commitment or snapshot replacement fail closed; deliberate refusal aborts preparation. Recovery from an ambiguous crash is manual. Concurrent writers use exclusive locks.

Native wallet quarantine and gate binding now use the same journal-bound state pattern. Exact SDK-generated plans are cached privately, their amount/invoice/recipient map/PSBT are certified by the wallet adapter, and the token is consumed durably before signing. Changed plans, stop before consumption, quarantine snapshot rollback/deletion and replaced/deleted gate bindings were refused in independent probes.

QA also found that a quarantine committed during asynchronous WDK enrollment could miss the initial check. Commits `11910f6` and `8efb6b9` add a check after enrollment and at the WDK policy barrier; both corresponding probes pass. Owner stop, policy replacement and token expiry after consumption but before the actual signing-policy callback also had independent failing reproductions. Core `6dc050e` adds a read-only assertion of current journal-validated authority, policy/hash/version, time, consumed token record, agent, exact plan and trusted preview. Native `96265ce` calls it synchronously inside the WDK policy condition with internally cloned approval data. All three original reproductions now pass and failed signing attempts retain consumed tokens. No post-signature revocation guarantee is assumed.

The journal guarantees rely on retaining an independently trusted current local log/checkpoint. Restoring the snapshot, complete journal and checkpoint together is undetectable without an external anchor, which is not built. Access to wallet keys or raw SDK signing methods lies outside the governed adapter's security boundary. Daily amounts are reserved conservatively, including failed sends, until UTC-day rollover.

Receiver RGB/asset membership and chain observations come from the receiver-owned SDK/indexer adapter. Core verification recomputes witness and previous transaction IDs and derives addresses/input outpoints. This is witness-input screening, not RGB consignment verification or complete provenance. A trusted checker key and independently trusted issuer/list pins are required. Utexo's flagged-list API is a refusal stub, ancestry screening is designed, and Settle/Remember are not started.

README/architecture/demo claims were audited against these boundaries. Synthetic demonstrations are marked `liveTransfers: false`; no new RGB or escrow network transaction is claimed. Raw history, private keys and matches remain local; published attestations expose the specified asset/witness identifiers and list/check results.

## Public transactions

Independent requests to both Mempool and Blockstream explorers are recorded in `qa/public-explorer-checks.json`. At 15:53 UTC on 19 October 2026, the faucet transfer `655090b2862de7bf6bd92ec0566c0643a017513dbc4bdb151569396055306b0c` was confirmed in block 5195536, with output 1 paying 129128 sats to new wallet B. The fresh B-to-A setup split `c92c1d073eb8aaba75f3c72e45d3f5618556890e60fde8b79d07911d38105ffa` paid 65000 sats to A at output 0 with a 155-sat fee and was unconfirmed on both explorers. No RGB demonstration txids have yet been supplied for independent verification.

## Compex extraction (separate project)

Independent extraction QA passed frozen `62233f0`, runtime `80ab5e8`: 51/51 tests with the full external Compex verifier (SHA-256 `bf48636dc810a34c107366c7a2335bfb2477b35fbc5bbed113600854dcfd6e91`), five extra acceptance probes, typecheck/build, 122 archive files compared byte-for-byte with original Satstride blobs, preserved import authorship/timestamps, actual tarball offline install, browser bundle and publication guard. The 51-file tarball was 43339 bytes. This is offline historical-fixture verification, not a new Compex execution. Whole-loan/mobile/check-node/chain-observer host integrations were not counted as package tests. Details are in the separate package's `qa/verification.json`, commit `d1d5064`.

Node verification authenticates the signed envelope/committed artifact; unsigned wrapper execution/contract references and the legacy `consentHash` parameter are advisory in that API. Callers must use authenticated envelope fields as authoritative references. Independent probes refused different loan amount/fee/term/grace/asset/requirements, borrower/lender/purpose, and modified signature/payload/artifact. No forged evidence or loan acceptance was demonstrated.

The final Compex private-publication workflow at `4258d04` was reviewed: manual dispatch only; exact approved commit; fixed private repository check; dedicated self-hosted runner with no hosted fallback; least permissions (`contents: read`, `packages: write`); pinned checkout without credential persistence; explicit GitHub Packages restricted publication; mode-600 temporary npm credential file and cleanup. Its complete 185-path G2 list exactly matches that frozen tree. First push still requires Amir's single G2 confirmation. QA performed no push, package publication, spending or external contact.
