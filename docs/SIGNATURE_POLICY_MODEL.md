# Signature policy layer model

Status: implemented by `src/policy.rs`, `src/policy_adapters.rs`, `src/evidence.rs`, and `policy-vectors/`

The original prototype combined a transport experiment (`Sig-PQC:`) with a
specific policy rule (Ed25519 **and** ML-DSA-65). Prior-art review shows that
these concerns must be separated. Native multi-algorithm signatures can use
the ordinary Nix signature collection, while mandatory hybrid authorization
still needs explicit policy semantics.

## Six layers

### 1. Encoding

Defines how a key or signature identifies its algorithm and how it is carried
in narinfo or another store metadata representation.

Examples include ordinary algorithm-aware Nix `Sig:` entries, this prototype’s
historical `Sig:` plus `Sig-PQC:` pair, and future structured containers.
Encoding answers how bytes are represented. It must not decide which
combinations authorize an artifact.

### 2. Cryptographic verification

Determines whether one signature is mathematically valid for the canonical
store-path fingerprint, claimed algorithm, and selected public key. It returns
a typed observation such as valid, invalid, or malformed. It does not decide
whether one valid signature is sufficient for admission.

### 3. Trust

Determines whether the verified key is trusted for the relevant namespace,
cache, artifact class, role, authority, custody domain, and time interval.
Trust also covers revocation and future delegation or certificate mechanisms.

Algorithm family and assurance classification are policy-owned metadata. A key
references an algorithm from the policy registry but cannot declare that the
algorithm belongs to a stronger family or assurance class.

### 4. Authorization policy

Combines valid trusted signatures into an admission decision.

Examples include:

- any one trusted signature;
- at least two distinct trusted identities;
- one release authority and one independent security authority;
- one classical and one post-quantum signature from the same logical identity;
- two post-quantum families;
- two of three builders plus one release signer.

This is the layer where downgrade resistance exists or fails. Merely adding an
ML-DSA verifier does not change an any-valid policy into an AND policy.

The executable model uses typed group predicates and bounded cross-group
relations. Group thresholds can count distinct identities, cryptographic
families, authorities, and custody domains. Relations can require one shared
attribute value across groups or an injective set of distinct values.

### 5. Migration

Defines how policy changes over time without creating accidental outages or
silent fallback.

A useful minimum state model is:

1. `classical-only` — PQ signatures are not considered.
2. `hybrid-observe` — PQ signatures are checked and reported when present,
   but classical authorization remains sufficient.
3. `hybrid-required` — required classical and PQ groups must both pass.
4. `pq-required` — classical signatures may be retained for compatibility,
   but the post-quantum group is authoritative.

Transitions should be explicit, time- or configuration-bound, and visible in
evidence. A missing PQ signature in `hybrid-required` must not silently fall
back to `classical-only`. The policy-lifecycle layer adds machine-readable
activation, family-lifecycle, and rollback semantics rather than treating a
permanent OR clause as a migration mechanism.

### 6. Evidence

Records enough information for an independent verifier to reproduce the
decision:

- canonical artifact fingerprint;
- policy identifier and version;
- trusted-key snapshot or references;
- signatures considered;
- per-signature verification outcomes;
- distinct identity, family, authority, and custody-domain counts;
- relational witnesses;
- migration state;
- final decision and refusal reason.

The evidence-bundle layer implements a deterministic schema-v1 policy-replay
bundle and an offline verifier. It recomputes the exact decision from canonical policy inputs,
can bind the original source artifact by SHA-256, and can verify an optional
hybrid producer attestation. Candidate cryptographic verification outcomes are
still evidence inputs in v1; they are not independently re-proven from raw wire
signatures. See `EVIDENCE_BUNDLES.md`.

Evidence is not the same as a transparency log. Append-only publication,
checkpointing, witness protocols, and transport-specific cryptographic replay
are separate concerns.

## Representation-neutral conformance case

The schema uses a semantic case model rather than embedding `Sig-PQC:` strings
directly in every policy vector. A compact schema-v2 example is:

```json
{
  "schema_version": 2,
  "case_id": "hybrid-required-both-valid",
  "description": "Both typed groups are satisfied by the same signer identity.",
  "evaluation_time": 100,
  "policy": {
    "policy_id": "hybrid-required",
    "version": 1,
    "max_signature_observations": 128,
    "max_signature_candidates": 32,
    "algorithm_registry": [
      {
        "algorithm": "ed25519",
        "family": "elliptic_curve",
        "assurance_class": "classical"
      },
      {
        "algorithm": "ml-dsa-65",
        "family": "lattice",
        "assurance_class": "post_quantum"
      }
    ],
    "group_definitions": [
      {
        "group": "classical",
        "predicate": {"allowed_assurance_classes": ["classical"]}
      },
      {
        "group": "post-quantum",
        "predicate": {"allowed_assurance_classes": ["post_quantum"]}
      }
    ],
    "accept_if_any": [
      {
        "clause_id": "required",
        "required_groups": [
          {"group": "classical", "min_distinct_identities": 1},
          {"group": "post-quantum", "min_distinct_identities": 1}
        ],
        "relations": [
          {
            "relation_id": "same-signer-identity",
            "attribute": "identity",
            "mode": "same",
            "groups": ["classical", "post-quantum"]
          }
        ]
      }
    ]
  },
  "trusted_keys": [
    {
      "key_id": "cache-ed",
      "key_name": "cache",
      "signer_identity": "cache-owner",
      "algorithm": "ed25519",
      "roles": ["cache-signing"],
      "authority": "cache-owner",
      "custody_domain": "cache-ed"
    },
    {
      "key_id": "cache-pq",
      "key_name": "cache",
      "signer_identity": "cache-owner",
      "algorithm": "ml-dsa-65",
      "roles": ["cache-signing"],
      "authority": "cache-owner",
      "custody_domain": "cache-pq"
    }
  ],
  "input": {
    "adapter": "semantic",
    "signatures": [
      {"key_id": "cache-ed", "signature_id": "ed-good", "verification": "valid"},
      {"key_id": "cache-pq", "signature_id": "pq-good", "verification": "valid"}
    ]
  },
  "expected": {
    "decision": "accept",
    "satisfied_clause": "required",
    "forbidden_reason_codes": ["missing_required_group"],
    "group_counts": {"classical": 1, "post-quantum": 1}
  }
}
```

Committed adapters map equivalent cases to the semantic fixture form, the
prototype’s historical `Sig:` plus `Sig-PQC:` fields, and ordinary
algorithm-tagged signatures. The expected result must remain identical across
adapters.

## Enforced invariants

The conformance engine enforces these invariants:

1. Group membership is derived from policy-owned predicates, not key-supplied
   group labels.
2. Algorithm family and assurance class come from the policy algorithm registry.
3. Thresholds count distinct trusted attributes, not duplicate signatures.
4. A signature contributes only after verification, trust, revocation, and
   validity checks succeed.
5. Unknown algorithms never satisfy a required group.
6. Bound hybrid and independent-authority policies use explicit relations.
7. Raw observation limits are checked before deduplication.
8. Unique-candidate limits fail explicitly rather than truncating input.
9. `hybrid-required` never falls back to classical-only authorization.
10. Candidate ordering cannot alter the decision or evidence.
11. Contradictory outcomes for one signature identity fail closed.
12. Expired migration clauses cannot silently reactivate.
13. A policy below the committed epoch is refused before authorization.
14. Forbidden families cannot contribute; enabled replacement families may satisfy the same typed group.
12. Wire adapters cannot alter policy semantics.

## Non-goals for the first harness

The representation-neutral harness does not implement a complete policy
language, online certificate discovery, transparency logs, production
revocation distribution, direct Nix daemon integration, or a final upstream
configuration syntax.

Its purpose is narrower: provide machine-checkable examples that distinguish
algorithm support, trust metadata, threshold counting, relational composition,
and mandatory group authorization.

## Implementation notes

The executable schema uses a small disjunctive-normal-form policy:

- every group requirement and relation inside a clause is mandatory;
- satisfying any complete clause accepts;
- typed predicates derive membership from algorithm, family, assurance class,
  role, authority, and custody domain;
- thresholds count distinct values for explicitly selected dimensions;
- duplicate signature bytes do not increase counts;
- contradictory outcomes refuse before authorization;
- normalized candidates and diagnostics use canonical ordering;
- exceeding a configured raw or unique candidate cap refuses explicitly.

Run the committed suite with:

```sh
nix run .#policy-conformance
```

The output is a versioned JSON report containing per-case decisions, stable
reason codes, candidate diagnostics, typed group observations, and relational
witnesses.
