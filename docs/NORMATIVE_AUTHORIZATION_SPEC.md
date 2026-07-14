# Nix artifact signature authorization: normative core

Status: prototype specification, revision 1.

This document defines the transport-independent authorization semantics exercised
by this repository. It intentionally begins after signature parsing and
cryptographic verification. It does not define a new narinfo field, a signature
algorithm encoding, key storage, or a network protocol.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as normative requirements.

## 1. Inputs

An authorization decision consumes:

1. an artifact identifier and canonical fingerprint;
2. a versioned authorization policy;
3. a versioned trusted-key registry;
4. normalized signature observations;
5. an evaluation context containing the current time and committed minimum
   policy and registry epochs;
6. an enforcement mode describing the relationship with Nix's built-in
   authorization decision.

A transport adapter MAY parse ordinary algorithm-tagged Nix signatures,
historical `Sig-PQC:` observations, or another representation. Every adapter
MUST normalize equivalent verified evidence to equivalent observations.

## 2. Trust boundaries

A signature observation MUST NOT supply its own trusted identity, role,
cryptographic family, assurance class, authority, or custody domain.

The verifier MUST derive:

- key identity, role, authority, and custody domain from the trusted-key
  registry;
- algorithm family and assurance class from trusted policy metadata;
- group membership from policy-defined typed predicates.

An unknown key, unknown algorithm, algorithm mismatch, invalid signature,
malformed signature, revoked key, inactive key, forbidden family, or
observe-only family MUST NOT contribute authorization weight.

## 3. Candidate normalization

Before threshold evaluation, the verifier MUST:

1. impose a bound on raw observations;
2. normalize each observation to key name, algorithm, signature identifier,
   and cryptographic verification outcome;
3. detect exact duplicates and conflicting duplicates deterministically;
4. impose a separate bound on unique candidates;
5. resolve candidates only against locally trusted key metadata.

Duplicate evidence MUST NOT increase authority. Candidate ordering MUST NOT
change the decision.

## 4. Typed groups

A group is a policy-owned predicate over trusted attributes. Predicates MAY
constrain:

- algorithms;
- cryptographic families;
- assurance classes;
- required roles;
- administrative authorities;
- custody domains.

All populated predicate dimensions are conjunctive. An unconstrained group MUST
be explicit rather than represented by an accidentally empty predicate.

A key MUST NOT be able to place itself in a stronger group by declaring an
untrusted label.

## 5. Clauses and thresholds

A policy contains one or more clauses. Requirements within a clause are
conjunctive. Clauses are disjunctive: satisfying any active clause authorizes the
policy decision.

A group requirement MAY impose minima over distinct:

- signer identities;
- cryptographic families;
- administrative authorities;
- custody domains.

One witness MUST count at most once for each distinctness dimension. Multiple
keys representing one logical identity MUST NOT inflate an identity threshold.

## 6. Cross-group relations

A clause MAY require a relation across two or more groups.

A `same` relation is satisfied only when at least one attribute value occurs in
every named group. This supports, for example, requiring one logical cache
authority to authenticate through both a classical and a post-quantum family.

A `distinct` relation is satisfied only when the verifier can assign a different
attribute value to each named group. This supports, for example, requiring a
release authority and an independently administered security authority.

The evaluator MUST emit the relation witnesses used for an accepted decision.

## 7. Family lifecycle

Every known cryptographic family has one lifecycle state:

- `enabled`: eligible for authorization;
- `observe_only`: recorded but ineligible;
- `deprecated`: eligible while producing a warning;
- `forbidden`: ineligible.

A family-level prohibition MUST make every algorithm in that family ineligible.
A forbidden or observe-only signature MUST NOT sabotage a decision that is
otherwise satisfied by eligible evidence.

Policies SHOULD maintain at least one tested recovery route that does not depend
on every family required by the normal artifact policy.

## 8. Time and migration

Policies and clauses MAY have activation and expiry boundaries. The verifier
MUST evaluate those boundaries before authorization.

A migration fallback MUST have an explicit activation boundary, expiry
boundary, or externally committed policy transition. A classical-only fallback
MUST NOT be described as temporary if it remains active indefinitely.

Observation-only rollout and authoritative enforcement are distinct states and
MUST be represented distinctly in diagnostics or configuration.

## 9. Rollback resistance

Policies and trusted-key registries are independent append-only domains. Each
versioned object MUST carry:

- a stable domain identifier;
- a positive epoch;
- an optional hash of the previous canonical object.

A successor MUST advance the epoch and bind the canonical hash of its immediate
predecessor. A client that has committed epoch `n` MUST refuse an object with an
epoch lower than `n` for the same domain.

Canonical policy, registry, receipt-payload, and trust-state commitments MUST be
domain separated and length framed. An implementation MUST hash the validated,
canonical typed representation rather than arbitrary source JSON bytes.

Wall-clock time MUST NOT be the only rollback defense.

## 10. Enforcement modes

The integration boundary MUST distinguish at least:

- `legacy`: only the built-in Nix result is authoritative;
- `supplemental`: either built-in Nix or the external policy may authorize;
- `authoritative`: only the external policy may authorize;
- `conjunctive`: both built-in Nix and the external policy must authorize.

An implementation MUST NOT describe a policy as mandatory when a permissive
built-in path can independently authorize the artifact.

## 11. Decisions and evidence

Every decision MUST be deterministic for identical normalized inputs.

An acceptance MUST identify:

- the satisfied clause;
- qualifying identities and families;
- relation witnesses;
- the policy and trusted-key registry commitments;
- the enforcement mode.

A refusal MUST provide stable machine-readable reason codes. Human-readable text
MAY evolve without changing conformance semantics.

A trust receipt proves the evaluator's recorded decision and commitments. It
MUST NOT be represented as proving that the original cryptographic operations
were independently repeated unless the receipt verifier actually repeats them.

## 12. Required invariants

Conforming implementations MUST satisfy these invariants:

1. permutation independence;
2. duplicate non-inflation;
3. untrusted metadata non-authority;
4. unsupported algorithms cannot satisfy a requirement;
5. irrelevant ineligible evidence cannot revoke an otherwise valid acceptance;
6. every acceptance has a complete witness;
7. every refusal has at least one stable reason;
8. committed policy and registry epochs cannot roll back;
9. authoritative mode has no built-in permissive bypass;
10. family prohibition applies transitively to every registered algorithm in
    that family.

The machine-readable vectors in `policy-vectors/` are the executable
conformance companion to this document.
