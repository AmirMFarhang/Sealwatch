# Attested remote checks, version 1

This optional protocol adds judgment-based checks to receiver-local rules. A remote
provider cannot loosen sanctions, flagged-input, spending, quarantine or stop decisions.
An enabled provider's timeout, bad signature, invalid scope or unsupported execution
label yields an error and quarantine, never a clear result. No provider is required
for the local-only workflow. No endpoint or key is distributed with this project.

Configure an authenticated URL, an independently obtained key file and a bearer
secret through private environment values:

```sh
TRUST_PROVIDER_URL=
TRUST_PROVIDER_KEYS_FILE=
TRUST_PROVIDER_TOKEN=
```

The ignored key file is `{ "providers": [{ "provider_id": "YOUR_PROVIDER_ID",
"keyid": "YOUR_KEY_ID", "public_key_pem": "YOUR_ED25519_SPKI_PEM" }] }`.
These are placeholders, not operational keys. Use HTTPS; literal loopback HTTP is
accepted for local development. Redirects, embedded credentials and URL queries are
refused. Only share evidence the receiver is entitled and willing to disclose.

POST JSON to the configured URL with `Authorization: Bearer ...`. The request is:

```json
{
  "version": 1,
  "request_id": "RANDOM_32_BYTE_HEX_NONCE",
  "issued_at": "ISO_UTC_TIMESTAMP",
  "expires_at": "ISO_UTC_TIMESTAMP_WITHIN_FIVE_MINUTES",
  "check": "transfer-flow-risk",
  "network": "utexo-testnet",
  "subject": { "witness_txid": "PUBLIC_TRANSACTION_ID", "asset_id": "RECEIVED_ASSET_ID" },
  "evidence": [{ "id": "witness", "kind": "bitcoin-transaction", "sha256": "CANONICAL_DATA_SHA256", "data": {} }],
  "context": {}
}
```

Canonical JSON recursively sorts object keys, preserves array order, rejects
undefined/non-JSON values, permits safe integer numbers only, and uses UTF-8 with
no whitespace. `request_sha256` hashes the entire canonical request; every evidence
hash separately binds its `data`. Evidence IDs are unique. At most 128 evidence
items and 512 KiB request data are accepted. The nonce and validity window bind
the response to this invocation rather than to a reusable transfer identifier.

The response is `{ "result": RECORD, "evidence_envelope": ENVELOPE }`:

```json
{
  "version": 1,
  "provider_id": "YOUR_PROVIDER_ID",
  "request_id": "THE_REQUEST_NONCE",
  "request_sha256": "THE_ENTIRE_REQUEST_SHA256",
  "issued_at": "ISO_UTC_TIMESTAMP",
  "expires_at": "NO_LATER_THAN_REQUEST_EXPIRY",
  "workload": { "id": "transfer-flow-risk", "version": "v1", "sha256": "WORKLOAD_SHA256" },
  "model": { "id": "MODEL_ID", "mode": "local-model" },
  "policy": { "id": "POLICY_ID", "sha256": "POLICY_SHA256" },
  "input_scope": { "evidence_ids": ["witness"], "fields": ["evidence.witness"] },
  "result": { "kind": "transfer-flow-risk", "risk_band": "review", "findings": [{ "code": "BOUNDED_SCOPE", "evidence_ids": ["witness"] }] },
  "execution": "software"
}
```

The signed input scope and every finding may reference only evidence supplied
in this request. Finding codes are bounded uppercase identifiers, not free text.
The provider must use fixed code to confirm evidence-backed model proposals. Missing
neighborhood coverage must be disclosed; it cannot establish full RGB ancestry or
a complete transaction graph. The default collector cross-checks public anchor
inputs/outputs against receiver-held raw bytes and collects a bounded neighborhood
(at most 16 addresses, six transactions each, 64 transactions total). It sends
only a consignment digest when supplied, never the full consignment or wallet keys.

`agent-action-review` uses the same envelope with `result.kind` set to that check
and `recommendation: approve | escalate`, plus grounded `findings`. It can only
tighten local authorization. Integrating it into the policy gate is a separate feature.

ENVELOPE follows the [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md):
`payloadType` is `application/vnd.attested-check.v1+json`, `payload` is base64
of canonical RECORD bytes, and `signatures` contains Ed25519 signatures over
the standard byte-length DSSE PAE, with optional key-ID hints. Both standard and
URL-safe base64 are accepted. Public keys are pinned out of band; a key ID never
establishes trust. A valid signature must belong to the signed provider identity.
The unsigned `result` must exactly match the verified payload. A response is
limited to 1 MiB. Nonces accepted by the remote client are recorded privately
with exclusive creation so replay refuses across restarts; rolling back all local
evidence and replay files still requires independent external anchoring.

Today every accepted record has `execution: software`. A provider claiming any
hardware/device label is refused. Test-vendor quote verification does not authorize
a real hardware label. Real vendor root validation and approved release measurements
are prerequisites for future hardware support.

The receiver hashes canonical ENVELOPE bytes as `evidence_sha256` and includes only
`provider_id`, that hash, `provider_result` and `execution` in its own signed
attestation's `provider` object. Full request, result and envelope stay in the
ignored private state directory (files mode 600). The local checker signs the
strictest outcome: `error > flagged > clear`; `review` and `high` require quarantine.
An auditor needs the separate private envelope and independently pinned provider
keys to verify the provider's claim, rather than relying only on the checker's signature.

Designed only: Travel Rule payload checks could validate mandatory originator and
beneficiary fields, formats and consistency in a separately authorized service-to-service
exchange. This protocol does not currently transmit such personal information,
implement a Travel Rule network, or establish statutory compliance.
