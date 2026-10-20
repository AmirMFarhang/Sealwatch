# Draft for Amir — not sent

Private project · Amir Mohammad Farhang, sole current contributor · Meeting
date unconfirmed. Working name: trust layer. Built on Utexo's RGB SDK.

“The trust layer for dollars on RGB: **Verify, Authorize, Settle, Remember.**”

A receiver needs rules for accepting a transfer. An agent wallet needs rules
for sending one. Our Verify and Authorize modules run those checks on the
wallet owner's machine and produce signed results and reasons. The trust
layer does not lend or hold funds; PassBook is a separate lending application.

## What Amir can show now

The [testnet receipt](../release/testnet-receipt.json) records a completed runner
on the SDK's documented **Bitcoin testnet3** setup (`utexo-testnet`, no Mutinynet
fallback), completed **20 October 2026 at 10:10:55 Europe/Rome**. It uses our own
**“test USD, not USDT”** asset and new wallets funded by a public faucet.

- A real [clear transfer](https://mempool.space/testnet/tx/e8113fd72c02ea54f87520e2fdcf6cc8176a739e624930fe1f6447a9c6b00e06),
  confirmed at block 5,195,546, with a signed clear receiver result.
- A real [flagged-test transfer](https://mempool.space/testnet/tx/8543f746c5a1d0a453a2c549814470ea94fc4e766049ef0b0daf35e724d7996b),
  confirmed at block 5,195,834, whose input matches our signed test list. Its
  receiver result is flagged and the received asset is quarantined locally.
- The governed send was allowed within limits. An over-limit request was
  refused with `PER_SEND_LIMIT_EXCEEDED`; a request after stop was refused with
  `KILL_SWITCH_STOPPED`. These refusals did not broadcast transactions.
- Both portable attestations can be verified using public checker and issuer
  keys that were pinned independently before the results arrived. Follow the
  [five-minute read-only walkthrough](DEMO.md); it does not reopen the wallets.

The first receiver check produced a signed Taproot-decoding error. The reviewed
fix rechecked the same clear witness successfully; the original error, history
and quarantine remain retained. Independent QA reran **88 standard tests and 15
security probes**, all passing; nine earlier CLI checks also passed. **Final
independent live QA passes** the required Verify/Authorize proof: confirmed
public transactions, pinned signed results/lists, signed logs, actual quarantine
and policy refusals. Its meeting-completion veto is lifted. Read the verdict
and scope in `release/verification.json`.

## Feature labels and limits

**Built:** receiver sanctions and witness-input checks, signed local flagged
lists, signed attestations, local quarantine, signed spending policies,
transaction-bound one-use approvals, stop, reasons, CLI and authenticated
localhost API. The required Verify/Authorize testnet demonstration is
independently verified; its receipt and QA report establish the scope of that pass.

**Stub:** the Utexo flagged-list API, which refuses until its API and issuer are
specified. **Designed:** screening RGB consignment ancestry. **Not started:**
Settle escrow and Remember portable history. Witness-input screening does not
establish the asset's complete history. Quarantine cannot reverse chain
settlement. The receiver keeps detailed evidence locally; portable results
include the asset/witness identifiers and list versions/hashes. Complete local
evidence rollback requires an independent external anchor, which is not built.

## Five questions for Utexo

1. Which network should partners test on, and is there a testnet USDT?
2. How do integrators get the flagged-coin list today? Do flags follow the coins
   spent from a flagged output, and under what rule?
3. How will your bitcoin-backed loans hold collateral?
4. Which parts would you pay for and which would you build yourselves?
5. Is open source a requirement for you?

The project remains private. “We can open-source it if you want” is an option
Amir may discuss; it is not a publication decision. No partner logos or
partnership claim accompany this draft. Amir decides what to present or send.
