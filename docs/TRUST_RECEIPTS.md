# Compact trust-admission receipts

Status: implemented

Trust receipts preserve a small, deterministic explanation of why an artifact
was accepted or refused at the Nix admission boundary.

A receipt records:

- artifact identifier, canonical fingerprint digest, and optional NAR hash;
- enforcement mode and built-in trust result;
- policy identifier, version, epoch, and canonical policy digest;
- committed minimum policy epoch;
- selected clause;
- qualifying identities, cryptographic families, authorities, and custody
  domains;
- stable policy and admission reason codes;
- the final admission decision.

## Commands

Create a receipt from a normalized Nix-integration authorization request:

```sh
cargo run --locked --bin trust-receipt -- create \
  --request authorization-request.json \
  --artifact-id /nix/store/example-system \
  --canonical-fingerprint-sha256 <64-lowercase-hex> \
  --nar-hash sha256:... \
  --output receipt.json
```

Verify receipt integrity:

```sh
cargo run --locked --bin trust-receipt -- verify --receipt receipt.json
```

Explain the decision:

```sh
cargo run --locked --bin trust-receipt -- explain --receipt receipt.json
```

## Assurance boundary

A compact receipt is an audit record, not a standalone proof of the original
signature verification. It binds the recorded decision with SHA-256 and records
the canonical policy hash, but intentionally omits the full trusted-key and
candidate inputs.

Use a policy-replay evidence bundle when an independent verifier must recompute
the authorization decision. Future Nix integrations could persist compact
receipts for routine provenance while retaining full evidence only for selected
artifacts, incidents, or transparency checkpoints.

Revocation should not automatically erase historical receipts. Operators can
separately distinguish validity at admission, current authorization status,
eligibility for new substitution, and deployment policy.

## Registry commitment

Schema v2 records the trusted-key registry ID, epoch, canonical SHA-256, minimum
committed registry epoch, and registry reason codes. A receipt therefore binds
both halves of the authorization state: the rule and the concrete trusted keys.

## Commitment format

Receipt `payload_sha256` uses the domain-separated `receipt-payload`
commitment-v1 framing documented in `docs/CANONICAL_COMMITMENTS.md`. Receipts
created before that framing are historical prototype artifacts and do not verify
under the current implementation.
