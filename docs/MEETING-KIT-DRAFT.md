# Draft for Amir — not sent

Working name: trust layer. Private project. Meeting date to be confirmed.

The intended positioning is “The trust layer for dollars on RGB: Verify,
Authorize, Settle, Remember.” PassBook is one application. The trust layer
does not lend or hold funds. Network activity must be described using the exact
network and transaction evidence in the release receipt.

## Five-minute outline

1. Explain the receiver's problem: a wallet sees an incoming transfer but still
   needs to decide whether to accept it under its own policy.
2. Show a real receiver check. State the sanctions snapshot dates, the separate
   labelled test list, and which part of the transfer is actually checked.
3. Open the signed result and its log entry. Show verification of the signature.
   The receiver keeps transaction history locally.
4. Show a flagged witness input and the resulting refusal or quarantine.
   Do not describe a local fixture as a network transfer.
5. Show the send policy: an allowed send, a refusal over its limit with a reason,
   and another refusal after the stop command.
6. Close with the feature table backed by independent QA. Present Settle and
   Remember only at the status supported by tests and the receipt.

This outline is a draft, not a completed demonstration script. `DEMO.md` must
be updated with exact tested commands and evidence before the meeting.

## Questions for Utexo

1. Which network should partners test on, and is there a testnet USDT?
2. How do integrators get the flagged-coin list today? Do flags follow the coins
   spent from a flagged output, and under what rule?
3. How will your bitcoin-backed loans hold collateral?
4. Which parts would you pay for and which would you build yourselves?
5. Is open source a requirement for you?

## Wording that needs evidence

Use “built on Utexo's RGB SDK” once that is demonstrated by the implementation.
Every feature is labelled built, stub, designed or not started. The project is
private. No partnership, commercial integration, production readiness or USDT
issuance is claimed by a test asset demonstration.
