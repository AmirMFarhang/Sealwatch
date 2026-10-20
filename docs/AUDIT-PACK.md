# Private audit evidence packs

The audit CLI exports one receiver decision as a ZIP and verifies it using
independently supplied public trust. It checks cryptographic consistency and
recorded policy binding. It does not certify AMLR, AI Act or other statutory
compliance, verify a complete RGB history, or establish hardware execution.

The addendum has local audit tests. Independent addendum acceptance is recorded
in `release/addendum-verification.json`; the original live demonstration's QA
report does not certify new pack code.

## Contents and checks

| File | Check |
| --- | --- |
| `manifest.json` | Checker signature, exact inventory, byte counts and SHA-256 for every included file. |
| `attestation.json` | Trusted checker and list issuer signatures, format/result semantics, network and configured trust pins. Export requires a v2 policy-bound attestation. |
| `log.json`, `checkpoint.json` | Trusted log signatures, sequence/hash chain, signed checkpoint and an incoming decision matching the exact attestation hash/result. |
| `policy.json` | Exact receiver policy id, version and SHA-256 matching `attestation.verificationPolicy`. This is the receiver verification policy, not automatically a spending-policy approval. |
| `provider-evidence.json` | Included when the attestation has a provider summary: full request, unsigned record and DSSE envelope. Checks pinned provider signature, request/transfer/result binding and exact evidence hash/summary. |

A provider-bound attestation without its corresponding private evidence is
refused. Unexpected evidence files or a manifest inventory/hash mismatch also
refuse. ZIP parsing is bounded and does not extract arbitrary paths to disk.

## Export

Use a copy of the intended receiver evidence and an appropriate receiver config.
Do not reopen or change preserved operational wallets merely to make a pack.
The command reads the configured log/checkpoint and signs the manifest with the
configured checker. Relative paths in the spec resolve from the current working
directory, not the spec file's directory.

```sh
bin/trust audit export PRIVATE_SPEC_JSON NEW_OUTPUT_ZIP --config PRIVATE_RECEIVER_CONFIG
```

The spec is private JSON containing paths:

```json
{
  "attestation": "PRIVATE_V2_ATTESTATION_JSON",
  "providerEvidence": "PRIVATE_PROVIDER_EVIDENCE_JSON",
  "trust": "INDEPENDENT_TRUST_JSON",
  "policy": "PRIVATE_RECEIVER_POLICY_JSON"
}
```

Omit `providerEvidence` for a result without a provider. Omitting `policy` selects
the built receiver policy; it still must match the attestation's signed reference.
Existing v1 signed records remain intact and verifiable separately; they cannot
be repackaged as v2 policy-bound evidence by editing their fields.

Export builds and verifies the complete pack before saving. The output uses
exclusive creation and private file permissions; choose a new filename for
another export. A successful command prints `exported: true` and the byte count.

## Independent verification

Verification does not load the receiver's config or require a signing secret:

```sh
bin/trust audit verify ZIP_FILE INDEPENDENT_TRUST_JSON
```

The trust file supplies independently obtained public identities. Placeholder
example only:

```json
{
  "checkerPk": "PINNED_CHECKER_XONLY_HEX",
  "flaggedIssuerKeys": ["PINNED_FLAGGED_LIST_ISSUER_XONLY_HEX"],
  "logPk": "PINNED_LOG_XONLY_HEX",
  "network": "utexo-testnet",
  "sanctionsListPins": ["PINNED_SANCTIONS_SNAPSHOT_SHA256"],
  "providerPins": [
    {
      "provider_id": "YOUR_PROVIDER_ID",
      "keyid": "YOUR_KEY_ID",
      "public_key_pem": "INDEPENDENTLY_PINNED_ED25519_SPKI_PEM"
    }
  ]
}
```

Use `providerPins: []` only when there is no provider evidence. Key IDs and keys
embedded in an untrusted pack do not establish identity. A valid pack prints
`valid: true` with an empty `problems` array; failures return a nonzero status.

Provider archive verification evaluates the record at its signed issuance and
decision time. It is checking retained evidence, not granting fresh approval to
reuse a request or send a transaction. Optional attestation age constraints in
the trust file may impose stricter archival acceptance.

## Privacy and boundaries

An audit ZIP contains the full provider request, record and envelope when used,
and the configured signed log, which can include more than the selected entry.
Keep the ZIP, spec, trust file and evidence in ignored private storage. Review
what the request/log discloses before sharing a pack. Public release receipts
can carry attestations and hashes without publishing these full private inputs.

A signed pack binds the supplied records; it does not independently prove the
provider's software host or model was correct. Raw-wallet-key bypass, incomplete
RGB ancestry and rollback of all retained local evidence remain separate trust
limits. Hardware labels continue to be refused in provider responses.
