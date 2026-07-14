# Typed signature-policy core

Status: implemented (core-v1)

The evaluator derives signer-group membership from policy-owned predicates over
trusted metadata. Keys no longer carry arbitrary group labels.

## Trust dimensions

The model keeps the following dimensions separate:

- algorithm: the concrete signature scheme identifier;
- family: the structural cryptographic family, such as elliptic-curve, lattice,
  or hash-based;
- assurance class: a broad policy class such as classical or post-quantum;
- identity: the logical signer represented by one or more keys;
- role: an authorization capability assigned by trusted configuration;
- authority: an organizational or administrative control domain;
- custody domain: a key-storage, implementation, or operational failure domain.

Algorithm family and assurance class are defined in the policy's algorithm
registry. A key references an algorithm but cannot relabel it. This prevents an
Ed25519 key from satisfying a post-quantum group merely because a key record was
assigned a misleading label.

## Typed groups

A group is a named predicate over the dimensions above. Non-empty predicate
fields are conjunctive. A deliberately unconstrained compatibility group must
set `match_all`; an accidentally empty predicate is invalid.

Group requirements can independently count distinct identities, families,
authorities, and custody domains. Duplicate signatures and multiple keys for the
same identity do not inflate an identity threshold.

## Cross-group relations

Clauses may require a bounded relation across named groups:

- `same` requires one shared attribute value across every group;
- `distinct` requires an injective assignment of one attribute value per group.

Relations may operate on identity, family, authority, or custody domain. This
allows the policy to distinguish bound hybrid authorization from independent
dual control without embedding an arbitrary policy language.

## Resource bounds

The evaluator has separate limits for raw observations and unique candidates.
The raw limit is checked before deduplication so a duplicate flood cannot hide
its parsing, allocation, or diagnostic cost behind a small unique-candidate
count.

## Compatibility and scope

This is a reference authorization model, not a requirement that upstream Nix
adopt this exact JSON syntax. The durable artifacts are the semantics, stable
reason codes, and versioned conformance vectors. The historical `Sig-PQC:`
adapter remains only to demonstrate that transport representation cannot weaken
or strengthen authorization policy.
