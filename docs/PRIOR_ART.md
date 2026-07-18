# Prior art and project positioning

Status reviewed: 2026-07-14

This document records the prior art that changes how this repository should
be understood. It is intentionally narrower than a general history of Nix
signatures.

## Executive summary

This project does **not** claim to be the first implementation of
post-quantum signatures for Nix.

Determinate Systems merged native support for ECDSA P-384 and
ML-DSA-44/65/87 store-path signatures into Determinate Nix. Eelco Dolstra
then extracted the underlying multi-key-type abstraction for upstream Nix
review. That work demonstrates algorithm agility using the ordinary Nix
signature collection.

The distinct question explored here is authorization policy:

> How can a deployment require a valid classical signature **and** a valid
> post-quantum signature, rather than accepting whichever one trusted
> signature verifies first?

The current prototype answers that narrow question for one concrete pair:
it requires same-key-name Ed25519 and ML-DSA-65 signatures under its
experimental `Sig:` + `Sig-PQC:` representation. The committed
representation-neutral conformance harness expresses the policy independently
of that representation.

## Primary sources

| Work | Status at review date | What it establishes |
|---|---|---|
| [DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449) | Merged 2026-05-20 | Native key generation, parsing, signing, and verification for `ecdsa-p384` and `ml-dsa-{44,65,87}` alongside Ed25519. |
| [NixOS/nix#15926](https://github.com/NixOS/nix/pull/15926) | Open | Upstream-oriented `KeyType` and polymorphic `PublicKey`/`SecretKey` abstraction, extracted from the Determinate work. The reviewed PR currently introduces the abstraction rather than the full Determinate algorithm set. |
| [NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451) | Open proposal | A `trusted-signatures-command` hook for richer policies including rotation, certificate chains, revocation, thresholds, and attestations. Its proposed fallback is permissive OR between built-in and external verification, so a mandatory policy would need an authoritative mode. |
| [NixOS/rfcs#202](https://github.com/NixOS/rfcs/pull/202) | Closed (verified 2026-07-18; this doc's "Status reviewed" date above predates the closure) | The original `Sig-PQC:` RFC and the subsequent public reframing: reuse ordinary signatures where possible and focus on required groups, migration states, and downgrade resistance. |

The repository also pins the Nix source snapshot used for its original
verification-semantics analysis in `README.md` and the historical RFC.
Because upstream moves, those source-level claims must be rechecked before
they are treated as current.

## Capability comparison

This table distinguishes implemented behavior from proposals. “Specific
hybrid pair” means the exact Ed25519 + ML-DSA-65 rule implemented by this
prototype; it does not mean a general policy language already exists.

| Capability | Upstream Nix baseline reviewed by this project | Determinate Nix prior art | This prototype |
|---|---:|---:|---:|
| Ed25519 store-path signatures | Implemented | Implemented | Implemented |
| Multiple signature algorithms in the ordinary signature machinery | Under upstream review via #15926 | Implemented | Not its primary mechanism |
| ML-DSA store-path signing | Not in the reviewed upstream baseline | Implemented | Implemented in experimental form |
| Accept when any trusted signature verifies | Implemented admission behavior | Retained by the reviewed design | Available when PQC is not required |
| Count-based verification via `nix store verify --sigs-needed` | Implemented | Retained | Not the policy studied here |
| Require a classical **and** PQ signature | Not represented by ordinary any-valid admission | Not introduced by #449 | Implemented for one same-name pair |
| General required groups / threshold policy | Not implemented as a built-in admission policy | Not introduced by #449 | Implemented as a representation-neutral prototype evaluator |
| Rotation / revocation / certificate policy | Manual configuration; richer hook proposed in #14451 | Outside #449’s scope | Outside the current prototype |
| Representation-neutral policy vectors | No | No | 21 executable CC0 vectors across three adapters |
| Experimental `Sig-PQC:` transport vectors | No | No | Implemented |

## What Determinate solved

Determinate’s work solves an important prerequisite: signatures and keys can
identify and dispatch to multiple algorithms without inventing a parallel
narinfo field for each algorithm. That directly invalidates the earliest
motivation for treating `Sig-PQC:` as necessary merely to carry ML-DSA.

This repository should therefore treat Determinate’s work as complementary,
not as a competing or deficient design:

- Determinate advances **encoding and cryptographic verification**.
- This prototype investigates **composed authorization policy and migration**.
- A future design can combine both: ordinary algorithm-tagged signatures
  evaluated by an explicit required-group policy.

## What remains distinct

Adding ML-DSA to the accepted algorithm set does not automatically create
hybrid authorization. If admission succeeds when any trusted signature is
valid, deleting the ML-DSA signature still leaves a valid Ed25519 path.
That is algorithm agility with classical fallback, not downgrade-resistant
hybrid enforcement.

Likewise, a raw signature count is not enough to express all relevant
policies. Two Ed25519 signatures may satisfy `N = 2` while contributing no
post-quantum component. A policy model must be able to distinguish at least:

- signer identity;
- algorithm or algorithm family;
- trust group;
- minimum distinct signers per group;
- required versus optional groups;
- migration epoch or deadline;
- revocation and validity state.

The current prototype implements a deliberately narrow executable subset of
that model. Its conformance harness describes those semantics independently
from `Sig-PQC:` or any particular Nix implementation.

## Current project claim

A precise one-sentence description is:

> A reference prototype and test-vector source for mandatory
> Ed25519-and-ML-DSA binary-cache authorization, built after and alongside
> existing Nix algorithm-agility work.

It is not:

- the first PQ signature implementation for Nix;
- a production cryptographic library;
- a proof that `Sig-PQC:` is the correct upstream encoding;
- a complete production signature-policy engine;
- a post-quantum upgrade for a classically authenticated upstream cache.

## Citation and update discipline

When this document is updated:

1. Prefer primary sources: merged code, upstream pull requests, issues, and
   current Nix source.
2. Record the review date and status rather than saying “current” without a
   date.
3. Separate implemented behavior from proposals and planned work.
4. Do not describe permissive OR semantics as a defect when that behavior is
   intentional compatibility policy; describe the missing property precisely.
5. Recheck links and statuses before releases or RFC updates.
