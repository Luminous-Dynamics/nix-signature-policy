# `core-v1` interoperability profile

`core-v1` is the smallest frozen interoperability surface in this repository.
It is intentionally narrower than the full research framework.

A conforming implementation:

1. consumes normalized signature observations only after cryptographic
   verification;
2. derives identity, role, authority, custody, family, and assurance metadata
   from trusted policy or registry state rather than from signature input;
3. evaluates typed group thresholds and the bounded `same`/`distinct`
   cross-group relations;
4. enforces raw-observation and unique-candidate limits before unbounded work;
5. treats duplicates deterministically and prevents duplicate authority
   inflation;
6. implements family lifecycle states, policy activation, and policy epoch
   rollback refusal;
7. exposes the four integration modes with no built-in bypass in
   `authoritative` mode;
8. emits deterministic decisions, stable reason codes, and complete acceptance
   witnesses; and
9. passes every case named by the `core-v1` profile in
   `conformance/policy-manifest-v1.json`.

## Stable artifacts

- `core/core-v1.json` — machine-readable profile descriptor;
- `core/core-v1.schema.json` — closed schema for that descriptor;
- `docs/NORMATIVE_AUTHORIZATION_SPEC.md` — normative semantics;
- `conformance/policy-manifest-v1.json` — exact vector membership and hashes;
- `src/core.rs` — Rust constants published by the reference implementation;
- `model/core_v1_model.py` — independent executable semantic model.

Changing any frozen constant or removing a required vector requires a new
profile identifier. Additive experimental functionality does not change
`core-v1` unless it alters a decision observable covered by the profile.
