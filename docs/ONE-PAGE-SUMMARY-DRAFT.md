# Trust layer — one-page draft for Amir

Private project · Amir Mohammad Farhang, sole current contributor · Meeting
date unconfirmed · Evidence: 20 October 2026. Draft only; Amir presents or sends.

**The trust layer for dollars on RGB: Verify, Authorize, Settle, Remember.**

A receiver needs rules for accepting a transfer. An agent wallet needs limits
on sending one. This project checks those rules on the wallet owner's machine
and produces signed, independently checkable results. It never lends or holds
funds. PassBook is a separate lending application. The implementation is
**built on Utexo's RGB SDK**.

| Building block | Current status | What the evidence supports |
| --- | --- | --- |
| **Verify** | **Built; testnet demonstration independently verified** | Pinned sanctions snapshots and signed local flagged lists; actual clear and flagged witness-input results, signed attestations and local quarantine. Demo lists are labelled test-only. |
| **Authorize** | **Built; testnet demonstration independently verified** | Signed limits and one-use transaction-bound approvals; an allowed send, an explained over-limit refusal and a refusal after stop. Requires the governed signing adapter. |
| RGB ancestry screening | **Designed** | A reliable consignment-history interface has not been demonstrated. Witness-input checks alone are not complete asset provenance. |
| Utexo flagged-list API | **Stub** | Refuses pending its real API and issuer trust. The signed local-file provider is built. |
| **Settle**: escrow | **Not started** | No trust-layer escrow claim. |
| **Remember**: portable history | **Not started** | No trust-layer portable-history claim. |

**Recorded proof:** the runner completed on **20 October at 10:10:55 Europe/Rome**
on the SDK's documented **Bitcoin testnet3** setup (`utexo-testnet`, no Mutinynet
fallback), using **“test USD, not USDT.”** The
[clear transfer](https://mempool.space/testnet/tx/e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06)
is confirmed at block **5,195,546**; the
[flagged-test transfer](https://mempool.space/testnet/tx/8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b)
at **5,195,834**. Both have signed receiver results. The flagged result blocks
outbound use locally. The policy records an allowed send, then refusals for
`PER_SEND_LIMIT_EXCEEDED` and `KILL_SWITCH_STOPPED`.

The first clear check produced a signed Taproot-decoding error. The reviewed
fix rechecked that same witness successfully while retaining the original
error, history and quarantine. Independent QA reran **88 standard tests and
15 security probes**, all passing; nine earlier CLI checks also passed. **Final
independent live QA passes** the required Verify/Authorize demonstration,
including public witnesses, pinned signed results/lists, logs, actual quarantine
and policy refusals. Its meeting-completion veto is lifted. The
[testnet receipt](../release/testnet-receipt.json) and
[verification report](../release/verification.json) record the evidence and scope.

The [five-minute walkthrough](DEMO.md) checks portable results using public keys
pinned before the results arrived. It reads evidence without reopening wallets.
Detailed receiver history remains local. Quarantine cannot undo chain
settlement; raw wallet-key access is outside the governed adapter's boundary.
Protecting against rollback of all local evidence needs an independent anchor,
which is not built.

**Five questions for Utexo — draft for Amir:**

1. Which network should partners test on, and is there a testnet USDT?
2. How do integrators obtain the flagged-coin list today, and do flags follow
   coins spent from a flagged output?
3. How will your bitcoin-backed loans hold collateral?
4. Which parts would you pay for, and which would you build yourselves?
5. Is open source a requirement for you?
