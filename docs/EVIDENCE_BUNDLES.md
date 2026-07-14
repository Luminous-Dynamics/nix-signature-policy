# Deterministic policy-decision evidence bundles

## Purpose

The policy conformance harness produces a decision from four inputs:

1. an authorization policy;
2. trusted-key assignments;
3. normalized signature candidates and verification outcomes;
4. an evaluation time.

The evidence-bundle layer makes that decision portable. The `policy-evidence` tool records the
canonical inputs, exact evaluator output, source-artifact binding, and an
optional hybrid producer attestation in a strict JSON envelope. An offline
verifier discards trust in the serialized decision and recomputes it.

## Assurance boundary

Evidence schema v1 is a **policy replay** format, not a complete cryptographic
proof of a Nix artifact.

It proves, subject to the implementation and supplied inputs, that:

- the payload matches its SHA-256 digest;
- the payload uses the canonical ordering rules;
- the recorded policy decision is exactly reproducible;
- an optional source artifact matches the recorded SHA-256 binding;
- an optional Ed25519+ML-DSA-65 producer attestation is valid;
- when a trusted `.pub` file is supplied, the attestation key matches it.

It does not prove that a producer correctly classified a raw signature as
`valid`, `invalid`, or `malformed`. The candidate verification outcomes are
inputs to schema v1. A later evidence kind may embed original `.narinfo`, key,
and signature material so an offline verifier can repeat the cryptographic
verification layer as well.

A valid attestation also does not make a dishonest observation truthful. It
answers *who emitted this bundle and whether it changed*, not whether that
producer was correct.

## Determinism

The canonical payload has no wall-clock creation time or random identifier.
Its source identifier is an explicit input, so callers seeking byte-identical
outputs should use the same stable relative identifier. Before serialization
the exporter sorts:

- algorithm definitions by algorithm identifier;
- typed group definitions by group identifier;
- policy clauses by `clause_id`;
- requirements inside each clause by group;
- relations by relation identifier and their group lists;
- trusted keys by stable key and identity fields;
- normalized candidates by key name, algorithm, signature identity, and
  verification outcome.

The decision is recomputed after canonicalization. `payload_sha256` is SHA-256
of the compact `serde_json` encoding of the payload. The outer file may use
pretty or compact JSON without changing the payload digest. Optional producer
attestation bytes are outside the payload and do not change that digest; their
byte-level determinism follows the selected signature implementation.

## Export one vector

```console
cargo run --locked --bin policy-evidence -- export-vector \
  policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --out hybrid-valid.evidence.json
```

Add a producer attestation with an existing hybrid secret key:

```console
cargo run --locked --bin policy-evidence -- export-vector \
  policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --out hybrid-valid.evidence.json \
  --signing-key evidence-1.secret
```

## Verify offline

Recompute the policy decision and check the original source-vector binding:

```console
cargo run --locked --bin policy-evidence -- verify \
  hybrid-valid.evidence.json \
  --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --require-source
```

Require an attestation from one specifically trusted key:

```console
cargo run --locked --bin policy-evidence -- verify \
  hybrid-valid.evidence.json \
  --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --require-source \
  --trusted-key evidence-1.pub \
  --require-attestation
```

Supplying `--trusted-key` already makes an attestation mandatory. The explicit
flag is useful in automation where the trust anchor may be configured
separately.

## Failure behavior

The verifier exits nonzero and emits stable failure codes for:

- unsupported schema versions;
- malformed payload structure;
- payload-digest mismatch;
- non-canonical payload ordering or decision content;
- a recorded decision that differs from the recomputed decision;
- missing or mismatched source artifacts when required;
- missing, invalid, or untrusted attestations.

Unknown JSON fields fail during parsing because all evidence structs use
`deny_unknown_fields`.

## Relationship to future evidence work

This format is not a transparency log, timestamp authority, or complete
software-supply-chain attestation. It is a deterministic decision record and an
offline policy replay boundary. Append-only publication, witness signatures,
cryptographic replay of raw Nix signatures, and provenance claims belong in
separate schema versions or evidence kinds rather than being implied by v1.
