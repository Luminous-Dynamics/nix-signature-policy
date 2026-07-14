# nix-signature-policy

[![CI](https://github.com/Luminous-Dynamics/nix-signature-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Luminous-Dynamics/nix-signature-policy/actions/workflows/ci.yml)

**A reference implementation and conformance suite for composable signature authorization in Nix.**

`nix-signature-policy` explores a narrow but important distinction:
cryptographic verification establishes that a signature is valid, while
**authorization policy** determines whether the available verified evidence is
sufficient to trust a Nix store path.

Existing any-valid-signature behavior is useful and remains the compatibility
default. It cannot, by itself, express requirements such as:

- one classical signature **and** one post-quantum signature;
- the same cache authority authenticated through two algorithm families;
- independent release and security authorities;
- thresholds over distinct signer identities;
- diversity across cryptographic families or custody domains;
- explicit migration, deprecation, recovery, and rollback rules.

This repository develops a small, deterministic, transport-independent policy
model for those cases. It includes a Rust reference evaluator, adversarial test
vectors, trusted-key registries, persistent rollback checkpoints, enforcement
modes, decision evidence, trust receipts, and a historical Nix binary-cache
proxy used as an integration harness.

> [!WARNING]
> This is exploratory, unaudited research software. It is not a production
> trust service, not an upstream Nix implementation, and not a substitute for
> cryptographic review. Do not use it to protect systems you depend on.

## The core idea

The project separates six concerns that are often conflated:

1. **Signature transport** — how candidate signatures are represented.
2. **Cryptographic verification** — whether each candidate verifies.
3. **Trusted metadata** — which identity, role, authority, family, and scope a
   key represents.
4. **Authorization policy** — which combinations of verified evidence are
   sufficient.
5. **Enforcement** — whether legacy or policy evaluation owns the final
   admission decision.
6. **Evidence and state** — how decisions, policy epochs, registry epochs, and
   rollback commitments are recorded.

The policy core does not require a PQC-specific narinfo field. Ed25519 plus
ML-DSA is a motivating profile, not a permanent architectural special case.
The same evaluator can consume semantic observations, ordinary
algorithm-tagged signatures, the repository's historical `Sig-PQC:` adapter,
or a future authoritative Nix verification interface.

## What the framework can express

### Typed signer groups

Groups are policy-defined predicates over trusted metadata, rather than labels
self-declared by keys or signatures. Predicates can constrain:

- algorithm identifiers;
- cryptographic families;
- assurance classes;
- signer roles;
- logical identities;
- administrative authorities;
- custody or failure domains.

This prevents, for example, a classical key from satisfying a post-quantum
group merely because it was assigned an unsafe label.

### Thresholds and relationships

Clauses can require minimum counts over distinct identities, families,
authorities, and custody domains. Bounded relational constraints can require:

- the **same identity** across multiple groups;
- **different identities** across groups;
- independent administrative authorities;
- distinct cryptographic families;
- distinct custody domains.

This distinguishes same-owner hybrid authentication from independent
multi-party approval.

### Algorithm and family lifecycle

Policy-owned algorithm metadata maps each algorithm to a family and assurance
class. Families can be:

- enabled;
- observe-only;
- deprecated;
- forbidden.

If a cryptographic family is broken, a successor policy can forbid that family
and activate a recovery clause using an unaffected family without changing the
signature transport.

### Migration and rollback protection

Policies and trusted-key registries are separate versioned trust domains. Each
has:

- a stable identifier;
- a monotonic epoch;
- a canonical hash;
- a predecessor hash.

Local trust-state checkpoints remember the highest accepted epochs. This lets a
client reject replay of an older policy that restores a revoked key, broken
algorithm, expired migration fallback, or weaker authorization rule.

### Explicit enforcement modes

The integration contract defines four modes:

- **legacy** — existing built-in admission behavior;
- **supplemental** — either the built-in path or policy may accept;
- **authoritative** — policy owns the final decision;
- **conjunctive** — both the built-in path and policy must accept.

The distinction is security-critical. A mandatory composed policy cannot be
enforced if a permissive legacy path remains an unconditional bypass.

### Explainable decisions

Accepted decisions identify the satisfied clause and qualifying witnesses.
Refusals use stable reason codes. Optional trust receipts can commit:

- the artifact fingerprint;
- enforcement mode;
- policy ID, hash, and epoch;
- trusted-key registry ID, hash, and epoch;
- qualifying identities, families, authorities, and custody domains;
- the selected clause and decision reason codes.

This provides a basis for answering: **Why did this machine trust this store
path?**

## Example policies

### Bound classical and post-quantum authorization

Require one classical group and one post-quantum group, with the same logical
cache identity represented in both.

- Ed25519 from cache authority A + ML-DSA from A: accepted.
- Ed25519 from A + ML-DSA from B: refused.
- Ed25519 alone: refused after enforcement begins.

### Independent release and security approval

Require one release signer and one independently administered security signer.
Two keys controlled by the same authority cannot satisfy both roles.

### Family-diverse post-quantum authorization

Require two distinct post-quantum families. Two lattice algorithms do not
satisfy the rule; a lattice signature and a hash-based signature can.

### Emergency family recovery

After a lattice-family break, advance to a successor policy that marks lattice
algorithms forbidden and requires an enabled classical-plus-hash-based profile.
Clients that committed the new epoch reject replay of the previous policy.

## Repository status

The repository currently includes:

- a representation-neutral Rust authorization evaluator;
- typed policy schema v2;
- 32 committed adversarial and adapter-parity vectors;
- a hashed cross-implementation conformance manifest;
- a mandatory `core-v1` interoperability profile;
- versioned trusted-key registries;
- policy and registry rollback checks;
- persistent local trust-state checkpoints;
- legacy, supplemental, authoritative, and conjunctive admission modes;
- deterministic decision-evidence bundles;
- compact trust-admission receipts;
- property tests and five fuzz targets;
- a locked Nix development and validation environment;
- stable and latest real-Nix integration lanes;
- a historical Ed25519 + ML-DSA binary-cache proxy demonstration.

The upstream-oriented proposal is:

- [`rfc/0001-composable-signature-authorization.md`](rfc/0001-composable-signature-authorization.md)

The original PQC transport proposal is retained only as historical context:

- [`rfc/README.md`](rfc/README.md)

## Quick start

The preferred workflow uses the locked Nix flake:

```sh
nix develop
nix flake check --print-build-logs
nix run .#policy-conformance -- --format pretty
```

Run the evidence-producing demonstration:

```sh
nix run .#demo -- --out-dir demo-output
```

Run the policy conformance harness directly with Cargo:

```sh
cargo run --locked --bin policy-conformance -- \
  --vectors policy-vectors \
  --format pretty
```

Inspect the trust-state and receipt tools:

```sh
cargo run --locked --bin trust-state -- --help
cargo run --locked --bin trust-receipt -- --help
cargo run --locked --bin policy-evidence -- --help
```

Run the real-Nix integration lanes separately from the hermetic test suite:

```sh
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
```

## Recommended review path

For a focused review, read these documents in order:

1. [`docs/NORMATIVE_AUTHORIZATION_SPEC.md`](docs/NORMATIVE_AUTHORIZATION_SPEC.md)
2. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
3. [`docs/TYPED_POLICY_CORE.md`](docs/TYPED_POLICY_CORE.md)
4. [`docs/POLICY_LIFECYCLE_AND_RECOVERY.md`](docs/POLICY_LIFECYCLE_AND_RECOVERY.md)
5. [`docs/NIX_INTEGRATION_CONTRACT.md`](docs/NIX_INTEGRATION_CONTRACT.md)
6. [`docs/TRUST_REGISTRIES.md`](docs/TRUST_REGISTRIES.md)
7. [`docs/LOCAL_TRUST_STATE.md`](docs/LOCAL_TRUST_STATE.md)
8. [`docs/CONFORMANCE_PROFILE.md`](docs/CONFORMANCE_PROFILE.md)

The shorter maintainer-oriented guide is:

- [`docs/MAINTAINER_REVIEW.md`](docs/MAINTAINER_REVIEW.md)

## Conformance suite

`policy-vectors/` contains representation-neutral semantic and transport-adapter
cases. The suite covers, among other properties:

- classical-only and PQ-only downgrade attempts;
- invalid, unknown, revoked, expired, and not-yet-valid keys;
- duplicate amplification and contradictory duplicate evidence;
- raw-observation and unique-candidate bounds;
- typed-group classification;
- same-identity and independent-authority relationships;
- cryptographic-family diversity;
- observe-only, deprecated, and forbidden family states;
- migration-clause expiry;
- policy and registry rollback;
- recovery after a family is prohibited;
- parity across semantic, algorithm-tagged, and historical `Sig-PQC:` adapters.

The conformance manifest binds every vector by SHA-256 and defines the portable
`core-v1` profile. Implementations can use the same corpus without adopting this
repository's Rust code, proxy, or configuration syntax.

```sh
nix run .#policy-conformance -- --format json > policy-report.json
```

## Architecture

Key modules include:

- `src/policy.rs` — bounded typed-group evaluator and lifecycle semantics;
- `src/policy_adapters.rs` — representation adapters;
- `src/conformance.rs` — deterministic vector execution;
- `src/registry.rs` — versioned trusted-key registries;
- `src/state.rs` — persistent rollback checkpoints;
- `src/integration.rs` — Nix admission and enforcement contract;
- `src/evidence.rs` — deterministic policy-decision evidence;
- `src/receipt.rs` — compact trust-admission receipts;
- `src/narinfo.rs` — Nix narinfo parsing and canonical fingerprinting;
- `src/proxy.rs` — historical binary-cache integration harness;
- `src/hybrid.rs` — unaudited Ed25519 + ML-DSA demonstration primitive.

Important data and specification directories:

- `policy-vectors/` — adversarial authorization cases;
- `conformance/` — portable manifest and schema;
- `trust-state/` — local checkpoint examples and schema;
- `receipts/` — receipt examples and schema;
- `evidence/` — decision-evidence examples and schema;
- `rfc/` — current and historical RFC drafts;
- `docs/` — normative model, threat model, integration contract, and review
  material.

## Historical PQC proxy

The package and legacy executable are still named `nix-pqc-cache-proxy` for
compatibility with the original research prototype. They demonstrate:

- ordinary Ed25519 cache signatures;
- an experimental parallel `Sig-PQC:` field carrying ML-DSA evidence;
- bounded reverse-proxy operation;
- local cache signing and verification;
- interaction with an unmodified Nix client.

`Sig-PQC:` is **not** proposed as the preferred upstream representation. The
policy architecture intentionally works with ordinary algorithm-tagged
signatures and future authoritative verification interfaces.

Most importantly, a translating proxy does **not** upgrade the upstream root of
trust. If the origin metadata is authenticated only by Ed25519, the proxy still
depends on that classical signature before minting new local evidence. A real
post-quantum root of trust requires the origin authority itself to sign using an
appropriate post-quantum key.

## Security boundaries and non-goals

This project does not claim to:

- make compromised builders trustworthy;
- prove that a build is reproducible;
- secure signing hosts or hardware;
- choose cryptographically safe algorithms for operators;
- make a classically authenticated origin post-quantum secure;
- provide audited production cryptography;
- define the final upstream Nix configuration syntax;
- replace transparency logs, provenance systems, or revocation services.

The reference evaluator is intentionally small and non-Turing-complete. It uses
bounded candidate sets, deterministic canonicalization, distinct-identity
counting, and stable diagnostics so independent implementations can agree on a
decision.

Read [`SECURITY.md`](SECURITY.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before evaluating deployment
ideas.

## Prior art and upstream relationship

This project does not claim first implementation of post-quantum signatures for
Nix.

Relevant work includes:

- Determinate's native ML-DSA signing work;
- upstream Nix polymorphic key-type work;
- discussion of configurable external signature verification;
- existing Nix any-valid trusted-key behavior.

The distinct question studied here is **authorization composition**: how Nix
can require particular combinations of already verified evidence without
embedding one algorithm era into the transport format.

See [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md) and
[`docs/adr/0001-policy-over-transport.md`](docs/adr/0001-policy-over-transport.md).

## Validation

The intended reproducible gate is:

```sh
nix flake check --print-build-logs
```

It covers the package build, formatting, Clippy, unit and integration tests,
JSON Schema checks, policy conformance, examples, benches, and rustdoc under the
locked toolchain.

Additional commands:

```sh
cargo test --locked
cargo check --locked --benches --examples
nix run .#fuzz-smoke
nix run .#audit
nix run .#environment > environment.json
```

The real-Nix lanes are intentionally separate because they start local services
and execute Nix store operations.

## Design principles

The project aims to remain:

- **transport-independent** — policy is not tied to `Sig-PQC:` or one wire
  format;
- **algorithm-agile** — algorithms and families are policy-owned metadata;
- **fail-closed** — unsupported required evidence and contradictory outcomes do
  not silently weaken policy;
- **bounded** — no unrestricted policy language or unbounded candidate work;
- **deterministic** — input ordering and duplicate entries do not change
  authorization;
- **explainable** — every acceptance names its rule and witnesses;
- **recoverable** — policy control need not depend on the family being removed;
- **interoperable** — shared vectors define semantics independently of this
  implementation;
- **compatible** — existing Nix behavior remains available as an explicit
  legacy mode.

## Contributing

The most useful contributions are:

- review of the normative authorization semantics;
- adversarial or ambiguous conformance cases;
- independent evaluator implementations;
- cppnix or tvix integration experiments;
- rollback and recovery analysis;
- cryptographic-family classification review;
- boundedness and denial-of-service analysis;
- documentation that narrows claims or exposes unsafe assumptions.

A negative result that rules out an unsafe design is considered a successful
contribution.

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
