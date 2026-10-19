# Five-minute demo — draft for Amir, not sent

Use the feature table and receipts from the exact checked-out source. The
meeting date is unconfirmed. This project is private. Say “built on Utexo's RGB
SDK”; do not imply a partnership or production deployment.

## Minute 0–1: explain what the receiver needs

Say: “A wallet can receive test dollars and still need rules for accepting them
and for what an agent may send. We keep those checks on the receiver's machine.”

Open the README status table. State the selected network from
`release/testnet-receipt.json`. If `status` is incomplete, say plainly that the
network demonstration is pending. A local demonstration remains available.

## Minute 1–2: a checkable result

For a completed network run, open its recorded clear attestation and the linked
public explorer transaction. Explain that the receiver checked the sending
addresses against pinned lists and the witness inputs against a signed flagged
list. State that RGB ancestry screening is designed, not demonstrated.

If the network receipt is incomplete, run this instead in a fresh directory:

```sh
bin/trust demo-local --state-dir .state/meeting-local
```

The audience sees `liveTransfers: false`, `clear: clear` and `flagged: flagged`.
Say that these are synthetic transaction vectors testing the local controls.
Do not call them a live transfer or display an invented explorer transaction.

## Minute 2–3: verify and detect a changed result

For the local walkthrough:

```sh
source .state/meeting-local/secrets.env
bin/trust attestation verify .state/meeting-local/attestation-clear.json --config .state/meeting-local/trust.config.json
bin/trust log verify --config .state/meeting-local/trust.config.json
```

The audience sees `valid: true`. Show the checker and list issuer's public-key
identities without opening the secrets file. Explain that a verifier needs
those trusted identities in advance. Use the independent QA tamper evidence
for the changed-list/result/log cases; never alter the retained original run.

## Minute 3–4: a limit and a stop

Show the recorded allowed send, the over-limit refusal and its `why`, and the
refusal after stop. A completed network receipt must link the allowed send to
its real explorer transaction. The synthetic walkthrough instead prints
`withinAllowed: true`, `overAllowed: false`, and `stoppedAllowed: false`.
Read the recorded `overActionId` with:

```sh
bin/trust why ACTION_ID --config .state/meeting-local/trust.config.json
```

Explain that one-use approval is tied to the actual prepared transaction.
A flagged incoming asset is quarantined locally; this does not reverse the
transaction on the public chain. The controls apply to the governed adapter.

## Minute 4–5: show the boundary and ask

Open `release/verification.json` and the testnet receipt. State the independent
QA verdict exactly. The Utexo flagged-list API is a stub, ancestry screening is
designed, and Settle/Remember are not started unless newer tested evidence
changes those labels. Do not demonstrate escrow from a different application
as though this repository had completed it.

Ask Amir's selected questions from [MEETING-KIT-DRAFT.md](MEETING-KIT-DRAFT.md).
Amir sends or presents all outside-facing material.
