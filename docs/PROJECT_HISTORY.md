# Project history

## Overview

`nix-signature-policy` began as an experiment in hybrid post-quantum signatures
for Nix binary-cache metadata. It has since evolved into a representation-neutral
framework for deciding whether verified cryptographic evidence is sufficient to
authorize admission of a Nix artifact.

This document records that evolution so that the current architecture can be
understood in the context of the problems and prior art that shaped it.

The project remains a research prototype. Its broader framework explores a
larger design space than the initial change proposed for Nix upstream.

## Phase 1: Hybrid binary-cache signature experiment

The original project was named `nix-pqc-cache-proxy`.

Its initial goal was to demonstrate a migration profile requiring both:

* an Ed25519 signature; and
* an ML-DSA signature.

The prototype introduced a separate `Sig-PQC:` narinfo field and used a proxy to
add and verify post-quantum signature material around existing Nix binary-cache
operations.

This work established several useful foundations:

* exact Nix store-path fingerprint construction;
* Ed25519 and ML-DSA signing and verification;
* duplicate-signature handling;
* deterministic test vectors;
* bounded parsing;
* proxy integration with real Nix operations;
* explicit documentation of what the prototype did and did not protect.

The proxy remains in the repository as a historical integration experiment. It
is not the normative architecture of the current framework.

## Phase 2: Prior-art review

Review of the initial RFC and existing implementations showed that post-quantum
signatures did not require a separate narinfo field.

Nix and Determinate work had already demonstrated a more general direction:
ordinary signature entries could support multiple algorithms through
polymorphic key and signature types.

This changed the central design question.

The missing capability was not:

> How should Nix transport one particular post-quantum signature?

It was:

> How should Nix determine which combination of valid signatures is sufficient
> to authorize a store path?

Supporting Ed25519 and ML-DSA simultaneously does not make both mandatory when
the admission rule remains "any valid trusted signature."

The original transport-oriented RFC was therefore closed as superseded.

## Phase 3: Pivot from transport to authorization

The project was reframed around a strict separation between verification and
authorization.

Cryptographic verification answers:

> Is this signature valid for this artifact and public key?

Authorization answers:

> Are the valid signatures and their trusted identities, roles, families, and
> authorities sufficient under the configured policy?

The project adopted ordinary algorithm-tagged signatures as the preferred
representation. The `Sig-PQC:` format was retained only for historical adapter
and compatibility tests.

This pivot led to the repository name `nix-signature-policy`.

## Phase 4: Typed authorization model

The first generalized policy model used named signer groups and thresholds.
Review revealed that arbitrary group membership could undermine the intended
security property. A classical key could be mislabeled as post-quantum, or one
identity could accidentally satisfy requirements intended to represent
independent authorities.

The model was therefore changed so that policies define typed predicates over
trusted metadata.

The framework now distinguishes:

* algorithm identifier;
* cryptographic family;
* assurance class;
* logical signer identity;
* operational role;
* authority domain;
* custody domain;
* validity and revocation state.

It also supports explicit relational requirements, including:

* the same logical identity across multiple groups;
* distinct identities across groups;
* minimum distinct cryptographic families;
* minimum independent authorities;
* minimum independent custody domains.

Signature-controlled input cannot assign these trusted properties to itself.

## Phase 5: Lifecycle, rollback, and recovery

Hybrid migration raised a further problem: what happens when an algorithm,
family, key, or policy is no longer acceptable?

The framework added:

* family lifecycle states;
* activation and expiration boundaries;
* policy epochs;
* trusted-key registry epochs;
* predecessor commitments;
* persistent minimum accepted state;
* rollback refusal;
* separately governed policy and registry transitions;
* recovery through unaffected cryptographic and organizational domains.

These mechanisms are designed to prevent replay of older states that restore:

* revoked keys;
* weaker thresholds;
* deprecated algorithms;
* expired compatibility clauses;
* removed authorities.

Policy and registry commitments use versioned, length-framed domain separation.
Different trust objects cannot accidentally share an undifferentiated
commitment.

## Phase 6: Explicit Nix admission semantics

The framework distinguishes the policy evaluator from the final Nix admission
decision.

Four admission semantics were modeled:

* **legacy**: current built-in Nix behavior;
* **supplemental**: built-in trust or external authorization may accept;
* **authoritative**: the configured authorization decision owns admission;
* **conjunctive**: both built-in trust and configured authorization must accept.

The most important distinction is between supplemental and authoritative
behavior.

Supplemental authorization is useful for migration and compatibility.
Authoritative authorization is necessary when an existing any-valid signature
must not bypass requirements such as:

* classical and post-quantum composition;
* multiple independent authorities;
* threshold approval;
* required hardware or custody properties.

The repository includes a bounded, versioned JSON helper protocol as one
integration experiment. The broader framework does not require that this exact
protocol become the upstream implementation.

## Phase 7: Frozen interoperability core

As the research framework expanded, the project separated a small stable core
from experimental extensions.

`core-v1` freezes:

* input normalization;
* duplicate handling;
* typed group membership;
* threshold counting;
* relational constraints;
* lifecycle eligibility;
* bounded deterministic evaluation;
* stable decision outcomes;
* conformance-vector expectations.

The richer lifecycle, governance, evidence, receipt, and benchmarking systems
remain outside the frozen core unless explicitly versioned into a future
profile.

## Phase 8: Independent conformance and boundedness

To reduce the risk of tests merely reproducing the Rust implementation's
assumptions, the project added an independent Python semantic model.

The independent model and Rust evaluator are compared across:

* committed core vectors;
* generated differential cases;
* candidate reordering;
* duplicates and conflicting duplicates;
* malformed observations;
* unknown keys;
* family lifecycle changes;
* policy and registry rollback;
* thresholds and group relationships;
* resource-limit boundaries.

The framework also places explicit limits on:

* signature observations;
* trusted-key registry size;
* policy groups and clauses;
* requirements and relations;
* identifier lengths;
* request and response sizes;
* diagnostic records;
* helper execution.

These limits are part of the security model rather than optional operational
tuning.

## Phase 9: Benchmark and review evidence

The benchmark suite separates costs that should not be conflated:

* cryptographic verification;
* policy evaluation;
* in-process JSON processing;
* cold helper-process startup;
* real-Nix operations;
* complete prototype demonstrations.

Reports include deterministic work estimates and machine-readable environment
metadata. Real-Nix benchmark profiles are reported separately rather than
subtracting dissimilar operations and labeling the difference as authorization
overhead.

The repository also includes:

* a maintainer review guide;
* a security review checklist;
* an upstream minimal-slice document;
* interface-alternative analysis;
* evidence and receipt schemas;
* reproducible release tooling.

## Current architecture

The current project has three conceptual layers.

### Stable semantic core

The stable `core-v1` profile defines representation-neutral authorization
semantics and conformance expectations.

### Reference implementation

The Rust implementation provides:

* policy evaluation;
* trusted registries;
* transition governance;
* rollback state;
* integration decisions;
* evidence and receipts;
* helper protocols;
* benchmark tooling.

It is one implementation of the semantic model, not necessarily the
implementation Nix upstream should adopt.

### Historical and experimental components

The repository retains:

* the original hybrid cache proxy;
* `Sig-PQC:` adapter vectors;
* advanced lifecycle and governance experiments;
* optional receipts and attestations;
* multiple integration modes;
* research benchmark infrastructure.

These components document the design history and test broader use cases. They
are not all part of the proposed minimum upstream change.

## Intended upstream contribution

The standalone framework intentionally explores more than Nix core should be
required to maintain.

The smallest upstream contribution currently recommended is:

> A disabled-by-default, bounded signature-authorization boundary at Nix
> store-path admission, with explicit supplemental and authoritative
> enforcement behavior.

Nix would continue to own:

* canonical artifact fingerprint construction;
* signature collection or verification;
* strict helper execution limits;
* the final admission decision;
* compatibility with existing trust behavior.

External authorization systems could own:

* thresholds;
* identity and role mapping;
* cryptographic-family diversity;
* policy lifecycle;
* recovery governance;
* certificates and attestations.

The exact boundary—raw signatures versus normalized verified observations,
global versus per-substituter scope, and one-shot versus persistent
communication—remains a subject for upstream discussion.

## A speculative longer-term note

The shape here — a policy decision point separated from an enforcement
point, evaluating scoped evidence rather than granting implicit, permanent
trust — composes naturally with a broader resource/subject/policy-
decision-point model in the style of NIST SP 800-207 ("zero trust
architecture"), if this pattern ever proves useful beyond Nix artifact
admission specifically. That is not proposed here, has no bearing on the
Nix integration, and is recorded only so the idea isn't lost — not as a
roadmap, a rename, or a commitment to build it.

## Security status

The project has extensive testing, conformance vectors, fuzz targets, bounded
resource profiles, independent semantic modeling, and real-Nix integration
experiments.

It has not received an independent security audit.

It should not yet be treated as production security infrastructure without:

* independent review;
* deployment-specific threat analysis;
* careful trust-root bootstrapping;
* validation of rollback and recovery operations;
* integration testing against the relevant Nix implementation;
* ongoing maintenance.
