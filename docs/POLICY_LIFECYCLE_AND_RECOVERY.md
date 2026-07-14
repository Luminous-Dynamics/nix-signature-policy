# Policy lifecycle, anti-rollback, and family recovery

Status: implemented

The typed policy core now treats cryptographic-family failure and policy
migration as normal lifecycle events rather than exceptional edits to a fixed
Ed25519-plus-ML-DSA profile.

## Family lifecycle

Every family in the policy-owned registry has one of four states:

- `enabled`: eligible for authorization;
- `observe_only`: verified and reported, but never counted toward authorization;
- `deprecated`: still eligible while producing an explicit warning;
- `forbidden`: ineligible because the family is compromised or prohibited.

Classification remains policy-owned. A key or signature cannot declare its own
family status.

A broken lattice family can therefore be marked `forbidden` while an enabled
hash-based family satisfies the same post-quantum group predicate. The policy
continues to express the security property rather than naming one permanent
algorithm.

## Activation windows

Policies have inclusive `active_from` and exclusive `expires_at` boundaries.
Individual clauses have inclusive `active_from` and exclusive `active_until`
boundaries. An expired classical migration clause no longer behaves as a
permanent permissive OR fallback.

When no clause is active, evaluation refuses with `no_active_clause`. Missing
signatures cannot reactivate an expired compatibility clause.

## Anti-rollback epochs

Each policy domain has a monotonically increasing `epoch`. Evaluation receives
a locally committed `minimum_policy_epoch` and refuses any older policy with
`policy_rollback` before considering signatures.

Policy successors can carry `previous_policy_hash`, the SHA-256 digest of the
canonical preceding policy. `validate_policy_transition` requires:

1. the same policy domain;
2. a strictly increasing epoch;
3. an exact canonical previous-policy hash.

The committed minimum epoch remains the authoritative rollback boundary. Hash
chaining makes the transition history auditable but does not replace durable
local state.

## Recovery authority boundary

This patch models safe artifact-policy transitions; it does not claim that an
artifact signing key is automatically authorized to publish policy updates.
Deployments should authenticate policy and family-registry updates using a
separate offline or threshold recovery authority whose quorum remains available
when any one cryptographic family is disabled.

## Evidence

Conformance cases and policy-replay evidence include the minimum committed epoch,
policy epoch, family lifecycle state, clause activation, and stable lifecycle
reason codes. This makes rollback and recovery decisions reproducible rather
than hidden in operator configuration.
