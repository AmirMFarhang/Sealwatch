# Five-minute evidence walkthrough — draft for Amir, not sent

Private project by Amir Mohammad Farhang, sole current contributor. Meeting
date unconfirmed. Say **“built on Utexo's RGB SDK.”** This walkthrough reads the
recorded proof; it does not restart the operational wallets or send funds.

The runner completed on **20 October 2026 at 10:10:55 Europe/Rome** using the
SDK's documented **Bitcoin testnet3** setup (`utexo-testnet`, `fallback: false`).
The asset is **“test USD, not USDT.”** Final independent live QA **passes** the
required Verify/Authorize demonstration. Its latest verdict and scope are in
`release/verification.json`; ancestry screening and escrow are outside that pass.

## Prepare before the meeting

Use the reviewed repository with its latest `release/testnet-receipt.json`,
`release/verification.json` and `qa/live-run-authorities.json`. Use Node 22 or
24 and install dependencies with `npm ci` before the walkthrough.

The public pins below were provided to independent QA before the attestations
arrived. Compare them with `qa/live-run-authorities.json`; a key copied only
from the result being checked is not an independent trust decision.

Run from the repository root. This extracts portable signed results into a
fresh ignored directory and checks the receipt's network and witness identities:

```sh
RECEIPT=release/testnet-receipt.json
mkdir -p .state
MEETING_PROOF_DIR="$(mktemp -d .state/meeting-proof.XXXXXX)"
node --input-type=module - "$RECEIPT" "$MEETING_PROOF_DIR" <<'NODE'
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
const [receiptPath, proofDir] = process.argv.slice(2);
const r = JSON.parse(readFileSync(receiptPath, 'utf8'));
assert.equal(r.status, 'complete');
assert.equal(r.network, 'utexo-testnet');
assert.equal(r.fallback, false);
assert.equal(r.asset.label, 'test USD, not USDT');
const expected = {
  clear: 'e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06',
  flagged: '8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b',
};
for (const name of ['clear', 'flagged']) {
  const a = r.attestations[name];
  assert.equal(r.transactions[name], expected[name]);
  assert.equal(a.witnessTxid, expected[name]);
  assert.equal(a.network, r.network);
  assert.equal(a.assetId, r.asset.assetId);
  assert.equal(a.overall, name);
  writeFileSync(`${proofDir}/${name}.json`, JSON.stringify(a, null, 2) + '\n');
}
console.log(JSON.stringify({ network: r.network, fallback: r.fallback,
  asset: r.asset.label, recordedAt: r.updatedAt, proofDir }, null, 2));
NODE
CHECKER_PK=3e85071f8ffbc438b1767f777d80444861e73c346c7f6d9b4508eae4e38a5124
ISSUER_PK=53a6d15d2a7e9cca78bb13c056bf648d9768fee46dc8268e97659dfe5685daf6
```

Keep this terminal open so the variables remain available. These verification
commands need only public keys; no wallet, signing secrets or receiver config
is needed. They check signatures and result consistency. Public chain evidence,
list contents and signed decision-log bindings are covered separately by QA.

## Minute 0–1: the receiver's problem

Open the README feature table and `release/verification.json`. Read its current
`verdict` and `meetingDefinitionOfDone` exactly. Independent QA has verified
the required live Verify/Authorize proof and lifted its meeting-completion veto.

Say: “A wallet can receive test dollars and still need rules for accepting them
and for what an agent may send. We keep those checks on the receiver's machine.
This is a recorded public testnet run, and we can check its signed results now.”

## Minute 1–2: a real transfer and its signed clear result

Open the [clear transfer on the public explorer](https://mempool.space/testnet/tx/e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06).
The receipt records confirmation at block **5,195,546**. Then type:

```sh
bin/trust attestation verify "$MEETING_PROOF_DIR/clear.json" --checker-pk "$CHECKER_PK" --issuer-pk "$ISSUER_PK"
```

The audience sees `valid: true` and an empty `problems` array. Open the extracted
`clear.json`: `overall` is `clear`. The sanctions snapshots are OFAC
**2026-10-01** and OpenSanctions **2026-10-17**; demo sanctions and flagged lists
are separately labelled `testOnly: true`. “Clear” means clear under these
recorded checks, not a claim about all RGB ancestry or every possible risk.

## Minute 2–3: a flagged input and local quarantine

Open the [flagged-test transfer on the public explorer](https://mempool.space/testnet/tx/8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b).
The receipt records confirmation at block **5,195,834**. Then type:

```sh
bin/trust attestation verify "$MEETING_PROOF_DIR/flagged.json" --checker-pk "$CHECKER_PK" --issuer-pk "$ISSUER_PK"
```

Again the signature verifies. Open `flagged.json`: `overall` is `flagged`, and
`checks.flaggedL1.code` is `FLAGGED_WITNESS_INPUT`. Explain that the signed
**test** list version 2 contains an input of this actual witness transaction;
it is not Utexo's production flagged list.

Open `quarantine` in the receipt. It records an outbound refusal for the
received asset with both `RECEIVER_ASSET_QUARANTINED_ERROR` and
`RECEIVER_ASSET_QUARANTINED_FLAGGED`. The asset remains blocked locally;
quarantine does not undo the public-chain transfer.

## Minute 3–4: the allowed send, the limit and stop

Show the recorded policy decisions without issuing new commands to the wallet:

```sh
node --input-type=module - "$RECEIPT" <<'NODE'
import { readFileSync } from 'node:fs';
const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
for (const name of ['clear', 'overLimit', 'stopped']) {
  const { actionId, allowed, why, policyVersion } = r.authorization[name];
  console.log(JSON.stringify({ name, actionId, allowed, why, policyVersion }));
}
console.log(JSON.stringify({ quarantine: r.quarantine }));
NODE
```

The clear send was allowed with `WITHIN_SIGNED_POLICY_LIMITS` and produced the
first confirmed transaction. The over-limit request has `allowed: false` and
`PER_SEND_LIMIT_EXCEEDED`. After the signed stop, the next request has
`allowed: false` and `KILL_SWITCH_STOPPED`. Refused requests have no broadcast
transaction. The signed decision-log QA report binds these records to their
policies and consumed approvals; displaying receipt JSON alone is not that check.

## Minute 4–5: retain the error, state the boundary, ask

Open `priorAttestations` in the receipt. The first attempt to decode the clear
transfer's Taproot input produced a signed `WITNESS_EVIDENCE_INVALID` error and
quarantined the asset. The reviewed decoder fix allowed the same confirmed
witness to be checked again, producing the signed clear result. The original
error, receiver history and quarantine were retained; the transfer was not
rebroadcast to obtain that corrected result.

Independent QA reran **88 standard tests and 15 security probes**, all passing;
nine earlier CLI checks also passed. Final live QA independently checked both
confirmed RGB witnesses, pinned signatures and list contents, the signed logs,
actual quarantine and policy refusals. Show its **pass** and scope from
`release/verification.json`. The Utexo list API is a **stub**; RGB ancestry
screening is **designed**;
Settle and Remember are **not started**. The governed adapter controls its own
signing path; direct possession of raw wallet keys is outside that boundary.

Choose questions from [the meeting draft](MEETING-KIT-DRAFT.md). Amir presents
or sends all outside-facing material.

## Optional synthetic fallback

Use this only when the recorded proof cannot be shown, and call it a local
synthetic demonstration. It does not replace the network receipt or live QA.
The directory must be new; choose another name if it already exists:

```sh
bin/trust demo-local --state-dir .state/meeting-synthetic-20261020
```

The audience sees `liveTransfers: false`, `clear: clear`, `flagged: flagged`,
`withinAllowed: true`, `overAllowed: false` and `stoppedAllowed: false`.
