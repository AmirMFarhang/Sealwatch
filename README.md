# Trust layer

Private working project by Amir Mohammad Farhang. All rights reserved except
reused material identified in [NOTICE](NOTICE).

**Verify, Authorize, Settle, Remember:** receiver checks and wallet controls for
test dollars on RGB. PassBook is one application of these ideas. This project
does not lend or hold funds and contains no Compex runtime or adapter code.
It is built on Utexo's RGB SDK; no partnership is claimed.

## Current evidence

The local implementation passes **88 tests**. Independent QA also passes
**15 security probes and 9 CLI checks**; see [the QA report](docs/QA.md).
The live run uses **Utexo's documented Bitcoin testnet3**; Mutinynet fallback
has not been used. Two fresh wallets are funded with public faucet coins and
have issued **test USD, not USDT**. The first governed RGB transfer is confirmed
and has a signed **clear** receiver attestation. A second transfer is broadcast
and awaits confirmation before the flagged-input check. **The complete live
proof remains pending.** See [the receipt](release/testnet-receipt.json).

The first receiver attempt recorded a signed error because the address decoder
could not handle a Taproot prevout without an ECC context. The corrected decoder
has a regression test against that public script and was independently checked.
The receipt retains the original signed error. Its asset quarantine remains in
force; a later clear result does not silently release it.

| Building block | Status | Evidence and limits |
| --- | --- | --- |
| Verify: pinned sanctions snapshots, signed local flagged list, witness-input checks | Built; local tests | Raw witness and previous transactions are decoded; missing evidence errors. SDK receive validation is the native adapter's responsibility. |
| Signed attestations and chained log | Built; local tests | Independent checker/issuer trust is required. Gate/quarantine snapshot revisions bind to the retained signed journal; restoring old state alone refuses. Complete local rollback needs external anchoring, which is not built. |
| Receiver quarantine | Built; local tests | Flagged/error results can quarantine the whole asset. The native adapter enforces its persisted guard. It cannot undo consensus settlement. |
| Authorize: signed limits, exact transaction tokens, replay protection, stop, why | Built; local tests | Requires the governed signing adapter. Direct access to wallet keys remains outside the gate's boundary. |
| CLI and authenticated localhost API | Built; local tests | Same Verify/Authorize libraries; API binds `127.0.0.1`. |
| RGB consignment ancestry screening, level 2 | Designed | No reliable ancestry interface has been demonstrated with the pinned SDK. |
| Utexo flagged-list API | Stub | Explicit refusal until the real API and issuer trust are specified. |
| Settle: generic escrow | Not started | No trust-layer escrow testnet claim. |
| Remember: portable history | Not started | No trust-layer portable-history claim. |

## Run locally

Use **Node 22 or 24**. Versions of WDK and the RGB SDK/native binding are pinned
in `package-lock.json`.

```sh
npm ci
npm run check
node --import tsx --test qa/*.test.ts
bin/trust demo-local --state-dir .state/local-demo
```

The last command creates fresh keys, a signed demo policy and lists, and
synthetic transaction vectors in a new ignored private directory. It prints
`liveTransfers: false` alongside clear/flagged checks, an authorization within
limits, an over-limit refusal and a stop refusal. It refuses to overwrite an
existing state directory; choose a new directory for another run.

Inspect signatures and the decision log using that generated configuration:

```sh
source .state/local-demo/secrets.env
bin/trust attestation verify .state/local-demo/attestation-clear.json --config .state/local-demo/trust.config.json
bin/trust log verify --config .state/local-demo/trust.config.json
bin/trust serve --config .state/local-demo/trust.config.json
```

The HTTP API requires the generated `TRUST_HTTP_TOKEN` bearer token. Keep the
environment file private. The synthetic demo's signed stop is already active;
it is intentionally unsuitable for sending funds.

For a receiver, adapt [the example configuration](fixtures/trust.config.example.json)
to its wallet identity and independently trusted public keys. Commands include
`trust verify-incoming --input FILE`, `trust policy install FILE`,
`trust authorize FILE`, `trust stop FILE`, and `trust why ACTION_ID`.
Policies, requests, previews and stop commands must have the appropriate
signatures. Passing a claimed sender address does not override the address
derived from the witness input's actual previous output.

## Run on a public test network

Follow [NETWORK.md](docs/NETWORK.md). `TRUST_NETWORK=utexo-testnet` selects the
documented primary Bitcoin testnet3 endpoints. `mutinynet` selects the fallback;
the recorded first run enforces the brief's four-hour primary window before
switching. Every fallback output is labelled. Public faucets only; no real
funds or existing wallets. The issued asset is **“test USD, not USDT.”**

```sh
node --import tsx scripts/network-probe.ts
node --import tsx scripts/testnet-wallets.ts status
# After confirmed public faucet funding:
node --import tsx scripts/testnet-fund.ts
node --import tsx scripts/testnet-wallets.ts create-utxos
# After the setup transactions confirm:
node --import tsx scripts/testnet-wallets.ts issue
node --import tsx scripts/testnet-demo.ts
```

Preserve `.state/` when resuming. The runner records broadcasts before polling
and resumes them rather than inventing successful transactions. The wallet uses
`donation=true`, creates colorable UTXOs before the first send, and handles
transfer statuses as strings, as required by the pinned stack.

Receiver history, raw transactions, addresses and detailed matches remain local.
The portable receipt carries the required witness/asset identifiers, signed
results and list versions/hashes. OFAC/OpenSanctions snapshots are pinned; a
separate labelled test list provides testnet sanctions hits. OpenSanctions data
retains CC BY-NC terms; see NOTICE and the dataset manifest.

See [architecture](docs/ARCHITECTURE.md) and the [draft demo](docs/DEMO.md).
Meeting material is a draft for Amir; nobody else sends it externally.
