# Trust layer — one-page draft for Amir

Private working project · Amir Mohammad Farhang, sole current contributor ·
Meeting date unconfirmed · Evidence snapshot: 20 October 2026, 09:48 Europe/Rome.
Draft only; Amir presents or sends it.

**The trust layer for dollars on RGB: Verify, Authorize, Settle, Remember.**

A receiver needs to decide whether an incoming transfer meets its rules. An
agent wallet needs limits on what it may send. This project builds those checks
on the wallet owner's machine and produces signed, independently checkable
results. It never lends or holds funds. PassBook is a separate lending
application. The implementation is **built on Utexo's RGB SDK**.

| Building block | Current status | What that means today |
| --- | --- | --- |
| **Verify** | **Built; local tests pass; public RGB proof pending** | Checks sending addresses against pinned sanctions snapshots and witness inputs against a signed flagged-outpoint list. Signs the result, logs it and can quarantine the asset locally. A separate labelled test list supplies testnet hits. |
| **Authorize** | **Built; local tests pass; public RGB proof pending** | Signed spending limits, one-use approvals tied to the prepared transaction, a stop switch and a readable reason for each decision. Requires sends through the governed signing adapter. |
| RGB ancestry screening | **Designed** | A reliable history interface from the pinned SDK has not been demonstrated. Witness-input checking alone is not complete asset provenance. |
| Utexo flagged-list API | **Stub** | Refuses until the API and trusted issuer are specified. The signed local-file provider is built. |
| **Settle**: generic escrow | **Not started** | No escrow claim for this project. |
| **Remember**: portable history | **Not started** | No portable-history claim for this project. |

The CLI and authenticated localhost API are built and locally tested. Detailed
receiver history stays on the receiver's machine; the shareable result carries
asset/witness identifiers and list versions/hashes. Verifiers must already
trust the checker and list issuer's public keys. Quarantine cannot reverse
chain settlement. Signed local state and its retained journal detect partial
rollback; independent protection against rolling back all local evidence is
not built.

**Evidence now:** 88 tests, 15 independent security probes and 9 CLI checks
pass. The run uses Utexo's documented Bitcoin testnet3; Mutinynet fallback has
not been used. Both fresh wallets hold only public-faucet test coins. The issued
asset is **test USD, not USDT**. The first governed RGB transfer is confirmed
and now has a signed **clear** receiver attestation. The second transfer is
broadcast and awaits confirmation before its flagged-input check. The original
signed receiver error is preserved after fixing a Taproot address-decoding bug;
its asset quarantine remains enforced. **The full live proof is still pending.**
Use [the receipt](../release/testnet-receipt.json) and the independent verdict
in `release/verification.json` for the latest evidence.

**Proof required before calling the meeting demonstration complete:** a real
A-to-B RGB transfer with a clear receiver attestation; a transfer whose witness
input is flagged and quarantined; a governed send within its limit; an
explained over-limit refusal; and a refusal after stop. Every broadcast needs a
working public explorer link and independent QA confirmation. The
[five-minute script](DEMO.md) labels its available local walkthrough as synthetic.

**Five questions for Utexo — draft for Amir:**

1. Which network should partners test on, and is there a testnet USDT?
2. How do integrators obtain the flagged-coin list today, and do flags follow
   coins spent from a flagged output?
3. How will your bitcoin-backed loans hold collateral?
4. Which parts would you pay for, and which would you build yourselves?
5. Is open source a requirement for you?
