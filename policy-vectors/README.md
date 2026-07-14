# Signature-policy conformance vectors

Status: adversarial schema version 2

These CC0 vectors test authorization semantics independently from any one Nix
signature encoding. They are intended for reuse by other Nix implementations,
cache gateways, external verifiers, and future wire adapters.

## Run

```sh
cargo run --locked --bin policy-conformance -- --vectors policy-vectors
```

Compact JSON suitable for CI ingestion:

```sh
cargo run --locked --bin policy-conformance -- \
  --vectors policy-vectors --format json > policy-report.json
```

Under Nix:

```sh
nix run .#policy-conformance
```

A nonzero exit status means at least one vector disagreed with its expected
semantic outcome or a vector could not be parsed safely.

## Model

Each vector defines:

- a versioned policy containing one or more acceptance clauses;
- a policy-owned algorithm registry and typed group predicates;
- trusted keys, logical signer identities, roles, authorities, custody domains,
  revocation state, and optional validity bounds;
- an input adapter and already-classified cryptographic verification outcomes;
- stable expected decision properties and reason codes.

Every requirement and relation inside a clause is mandatory. Satisfying any
complete clause accepts. Thresholds can count distinct identities, families,
authorities, and custody domains. Cross-group relations can require the same
identity or independently controlled identities. Duplicate signatures and
multi-key reuse do not inflate thresholds.

The harness begins after cryptographic verification. A production parser or
verifier must first turn signature bytes into `valid`, `invalid`, or `malformed`
observations. This suite tests the separate question of what authorization
policy those observations satisfy.

## Adapters

- `semantic` references trusted-key fixture IDs directly.
- `sig-pqc` models the prototype's historical Ed25519 `Sig:` plus ML-DSA
  `Sig-PQC:` representation.
- `algorithm-tagged` models an ordinary signature collection in which each
  entry identifies its algorithm, compatible with the direction demonstrated
  by Determinate's prior work and upstream key-type refactoring.

The three adapter-parity vectors must produce equivalent policy decisions. A
transport adapter is not permitted to weaken or strengthen the policy.

## Stable reason codes

Reason codes are machine-readable and intentionally separate from human error
text. Candidate diagnostics may appear in an accepted result when an invalid or
unknown extra candidate is safely ignored after another candidate satisfies the
required policy.

Policy-level refusal codes include:

- `invalid_policy`
- `policy_rollback`
- `policy_not_active`
- `policy_expired`
- `no_active_clause`
- `too_many_observations`
- `too_many_candidates`
- `conflicting_candidate`
- `missing_required_group`
- `missing_required_relation`

Candidate-level codes include duplicates, contradictory verification outcomes, unknown or mismatched keys,
invalid/malformed signatures, revocation, key validity failures, and family lifecycle states (`observe_only_family`, `deprecated_family`, and `forbidden_family`).

## Adding vectors

1. Use a globally unique `case_id`.
2. Keep `schema_version` at `2` until an incompatible schema change is needed.
3. State the adversarial property in `description` and `tags`.
4. Assert stable decision properties, not diagnostic ordering or prose.
5. Add a parity vector when introducing a new transport adapter.
6. Run the harness and the ordinary Rust suite before committing.

## Portable manifest and minimum profile

`../conformance/policy-manifest-v1.json` commits the exact SHA-256 of every
vector and defines the `core-v1` minimum interoperability profile. See
[`../docs/CONFORMANCE_PROFILE.md`](../docs/CONFORMANCE_PROFILE.md).
