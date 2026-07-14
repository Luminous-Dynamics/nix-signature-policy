---
feature: composable_signature_authorization
start-date: 2026-07-14
author: Tristan Stoltz (tstoltz)
co-authors: (open)
shepherd-team: (to be nominated)
shepherd-leader: (to be appointed)
related-issues:
  - https://github.com/NixOS/nix/issues/14451
  - https://github.com/NixOS/nix/pull/15926
  - https://github.com/Luminous-Dynamics/nix-pqc-cache-proxy
---

# Summary
[summary]: #summary

Add an explicit authorization boundary for Nix artifact signatures while
leaving signature encoding and cryptographic verification algorithm-generic.

Existing any-valid signature behavior remains the compatibility default. A
caller may instead select a bounded authorization policy that requires typed
signer groups, thresholds, family diversity, or relationships such as the same
logical authority authenticating through two independent algorithm families.

The proposal distinguishes supplemental policy from authoritative policy so a
classical built-in acceptance cannot silently bypass a mandatory composed
requirement.

# Motivation
[motivation]: #motivation

Nix has historically treated successful verification by any trusted signing key
as sufficient authorization. That model is simple and useful, but it cannot
express several increasingly relevant trust requirements:

- require both a classical and a post-quantum signature during migration;
- require two independent cryptographic families so one family-level break does
  not collapse authorization;
- require a release signer and a separately administered security signer;
- bind two algorithms to the same logical cache authority;
- observe a new algorithm without allowing it to authorize yet;
- expire a temporary compatibility fallback;
- refuse replay of an older, weaker policy after a client has committed a newer
  epoch.

Algorithm agility and authorization composition are separate concerns. Ordinary
algorithm-tagged signatures can carry Ed25519, ML-DSA, SLH-DSA, or future
algorithms. A separate transport field is not required merely to add another
algorithm. The missing abstraction is deciding which verified signatures are
jointly sufficient.

This RFC therefore proposes a small authorization layer above cryptographic
verification rather than a PQC-specific wire format.

# Detailed design
[design]: #detailed-design

## Layering

The implementation is separated into four layers:

1. transport parsing;
2. cryptographic verification;
3. trusted metadata resolution;
4. authorization policy evaluation.

Only the fourth layer is normative here. A signature cannot provide trusted
claims about its own identity, role, family, assurance class, authority, or
custody domain.

## Compatibility default

When no composed policy is configured, Nix retains its current any-valid trusted
signature behavior.

A configured integration selects one of four enforcement modes:

- `legacy`: built-in Nix authorization only;
- `supplemental`: built-in Nix or composed policy;
- `authoritative`: composed policy only;
- `conjunctive`: built-in Nix and composed policy.

Mandatory hybrid or threshold policy requires `authoritative` or `conjunctive`
mode. Supplemental mode is intentionally incapable of making a stricter policy
mandatory.

## Trusted-key registry

Trusted key metadata is supplied by local configuration or a separately
validated registry. Each entry associates a key name and algorithm with:

- a logical signer identity;
- zero or more roles;
- an administrative authority;
- a custody or failure domain;
- validity and revocation state.

Registry objects have stable identifiers, monotonic epochs, and predecessor
hashes so clients can refuse rollback.

## Algorithm and family registry

Policy-owned metadata maps each algorithm identifier to a cryptographic family
and assurance class. Family lifecycle state is one of enabled, observe-only,
deprecated, or forbidden.

Family classification is not supplied by a signature or key record. Marking a
family forbidden makes all algorithms mapped to that family ineligible.

## Typed signer groups

A policy defines named groups as predicates over trusted metadata. A predicate
may constrain algorithms, families, assurance classes, roles, authorities, and
custody domains.

A clause contains one or more group requirements. Each requirement may set
minimum counts over distinct identities, families, authorities, and custody
domains.

Clauses are disjunctive; requirements within a clause are conjunctive.

## Relational constraints

A clause may impose bounded relations across groups:

- `same identity` requires at least one logical identity to occur in every named
  group;
- `distinct authority` requires a different authority witness for each named
  group;
- equivalent relations may be applied to family and custody domain.

These primitives distinguish same-owner hybrid authentication from independent
multi-party authorization.

## Migration and family failure

Policies and clauses may have activation and expiry boundaries. A temporary
classical fallback must expire or be removed by a committed policy transition.

A family can move to forbidden without changing signature transport. A recovery
policy can then require another enabled family. Policy control should be
protected by roots that do not all depend on the same family required by normal
artifact admission.

## Rollback protection

Policies and trusted-key registries are separate append-only domains. Each
successor advances its epoch and binds the canonical hash of the immediate
predecessor.

A client stores the highest accepted epoch for each domain and refuses lower
epochs. This requirement does not depend solely on trustworthy wall-clock time.

## Bounded evaluation

The evaluator is deliberately non-Turing-complete. It imposes separate limits
on raw signature observations and normalized unique candidates. Duplicate
signatures do not increase thresholds. Evaluation and diagnostics are
order-independent.

## Explainability

An accepted decision identifies the satisfied clause and witnesses. A refusal
emits stable reason codes. Implementations may persist a compact admission
receipt containing the artifact fingerprint, policy and registry commitments,
enforcement mode, qualifying families and identities, and selected clause.

# Examples
[examples]: #examples

## Bound classical and post-quantum authentication

Require one classical and one post-quantum group, with the same logical identity
present in both. Ed25519 from cache authority A plus ML-DSA from authority A
passes. Ed25519 from A plus ML-DSA from B fails.

## Independent release and security approval

Require a release role and a security role with distinct administrative
authorities. The algorithms may differ, but one organization cannot satisfy both
roles merely by enrolling two keys.

## Family-diverse post-quantum policy

Require two distinct post-quantum families. Two lattice algorithms do not meet
the requirement. A lattice signature and a hash-based signature can.

## Emergency family prohibition

After a lattice-family break, a successor policy marks lattice forbidden and
activates a clause requiring classical plus hash-based signatures. Old policy
epochs are refused after the successor is committed.

# Drawbacks
[drawbacks]: #drawbacks

The policy introduces more configuration and more ways for operators to lock
themselves out. Typed metadata and explicit enforcement modes are more complex
than a flat list of trusted keys. Persisting rollback state also creates local
state that must be backed up and handled deliberately during disaster recovery.

The design does not make compromised builders trustworthy, prove reproducible
builds, secure signing hosts, or select safe cryptographic algorithms. It only
makes authorization composition explicit and testable.

# Alternatives
[alternatives]: #alternatives

## Keep any-valid behavior only

This preserves simplicity but cannot express mandatory composition or
independent thresholds.

## Add a PQC-specific narinfo field

A separate field can demonstrate migration, but it unnecessarily couples one
algorithm era to transport and does not generalize to family diversity,
independent authorities, or future algorithms.

## Use an unrestricted external policy language

A general policy engine is expressive but makes bounded evaluation,
implementation parity, offline operation, and security review harder. This RFC
prefers a small fixed vocabulary.

## Treat an external verifier as supplemental only

This is compatible but cannot enforce a stricter requirement because the
built-in any-valid path remains an authorization bypass.

# Unresolved questions
[unresolved]: #unresolved-questions

- Should the first upstream implementation be native C++, an authoritative
  external verifier contract, or both?
- Which trusted attributes belong in Nix configuration versus a separately
  signed registry?
- What persistence interface should store committed policy and registry epochs?
- Which subset of relational constraints is appropriate for an initial RFC?
- Should admission receipts be core Nix state, an optional audit log, or remain
  external tooling?

# Future work
[future]: #future-work

- shared conformance vectors across cppnix, tvix, and external verifiers;
- signed policy and registry distribution;
- transparency checkpoints and revocation feeds;
- re-evaluation of previously admitted paths after trust changes;
- reproducibility witnesses and builder attestations as separate typed roles.
