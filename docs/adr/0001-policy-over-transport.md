# ADR 0001: Treat signature policy as primary and transport as replaceable

- Status: Accepted
- Date: 2026-07-14
- Scope: Prototype roadmap and conformance-vector design

## Context

The initial prototype introduced a separate `Sig-PQC:` narinfo field because
the reviewed Nix baseline used a concrete Ed25519 signature representation.
Subsequent prior-art review found:

- Determinate Nix already supports ML-DSA and ECDSA algorithms through the
  ordinary signature machinery.
- NixOS/nix#15926 extracts the multi-key-type abstraction for upstream review.
- NixOS/nix#14451 proposes an external policy hook for richer trust rules.
- Ordinary any-valid verification does not express mandatory
  classical-and-post-quantum authorization.

Therefore the useful research question is not “how can narinfo carry a PQ
signature?” in isolation. It is “how should valid trusted signatures be
composed into an authoritative admission decision?”

## Decision

1. Preserve `Sig-PQC:` as a concrete historical transport experiment and an
   adapter supported by the current prototype.
2. Do not present `Sig-PQC:` as necessary for upstream Nix or as the project’s
   principal novelty.
3. Define Patch Set 3’s conformance cases in a representation-neutral semantic
   model.
4. Treat algorithm-tagged ordinary signatures as an equally valid, and likely
   preferable, adapter when the implementation supports them.
5. Center project claims on explicit required-group policy, migration states,
   downgrade resistance, and reproducible evidence.
6. Keep the policy engine independent from the question of whether enforcement
   ultimately lives in Nix, an authoritative external verifier, or a cache
   gateway.

## Consequences

Positive:

- The project incorporates prior art without discarding its working prototype.
- Conformance vectors can be reused by cppnix, Determinate Nix, tvix, cache
  gateways, and offline verifiers.
- Upstream discussion can select a transport independently from policy
  semantics.
- The project no longer claims novelty already demonstrated elsewhere.

Costs:

- Existing `Sig-PQC:` vectors remain transport-specific; Patch Set 3 adds the
  adapter layer and representation-neutral policy model required by this ADR.
- The current CLI implements only one narrow hybrid rule; documentation must
  distinguish it from the planned general model.
- A future native implementation may replace the transport while retaining the
  policy vectors.

## Rejected alternatives

### Continue treating `Sig-PQC:` as the primary RFC contribution

Rejected because native algorithm agility already demonstrates that a
parallel field is not required merely to add ML-DSA.

### Rewrite the prototype immediately around Determinate Nix

Rejected for now. The policy model should be independently specified before
binding the prototype to one downstream implementation.

### Remove the historical transport experiment

Rejected. It remains a useful backward-compatibility demonstration, concrete
implementation, and source of cryptographic and parser test vectors.

## Implementation status

Implemented in Patch Set 3 through `src/policy.rs`, `src/policy_adapters.rs`,
`src/conformance.rs`, and `policy-vectors/`. The historical transport remains
available as one adapter and no longer defines the policy semantics.
