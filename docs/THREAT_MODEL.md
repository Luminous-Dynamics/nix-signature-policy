# Threat model

## Scope

This document consolidates the security boundary for the reference proxy,
local signer/verifier, policy harness, offline evidence verifier, and release
tooling. The project investigates mandatory signature composition for Nix
binary-cache metadata. It does not replace Nix's local store, evaluate or build
packages, operate a transparency service, or provide a post-quantum origin for
`cache.nixos.org`.

## Assets

The system is intended to protect:

- the decision that a `.narinfo` may be admitted under a configured policy;
- the binding between a narinfo fingerprint and its classical and PQ signatures;
- local hybrid secret keys;
- the integrity of policy vectors, decision evidence, and release statements;
- proxy availability under bounded malformed or adversarial traffic;
- the operator's ability to distinguish verification failure from absence of
  verification.

NAR confidentiality is not an asset: ordinary Nix binary caches distribute
public build artifacts. Private deployments need a separate access-control and
transport-confidentiality design.

## Trust assumptions

The prototype assumes:

- the local host, Rust runtime, operating system RNG, and filesystem are not
  already fully compromised;
- the configured upstream Ed25519 public key was obtained authentically;
- locally configured hybrid public keys and release trust anchors were obtained
  independently of the artifacts they verify;
- the cryptographic libraries implement Ed25519 and ML-DSA-65 correctly;
- Nix's fingerprint and cache semantics remain compatible with the tested
  versions;
- proxy TLS termination and network exposure are supplied by the deployment
  environment when loopback-only operation is insufficient.

A re-signing proxy can authenticate what it observed from a classically signed
upstream. It cannot retroactively give that upstream a post-quantum root of
trust.

## Adversaries

The design considers:

- a network attacker modifying, truncating, redirecting, replaying, or stalling
  upstream HTTP responses;
- an upstream serving malformed metadata, oversized bodies, hostile URLs, or
  invalid signatures;
- a cache client sending malformed paths, bodies, or excessive concurrent
  requests;
- a migration or configuration error that accepts a single signature when two
  independent groups were intended;
- duplicate, contradictory, unknown, expired, revoked, or same-identity
  signatures attempting to satisfy thresholds;
- an evidence or release publisher modifying serialized decisions or artifacts
  after generation;
- accidental operator misuse, such as invoking verification without selecting
  any actual verification policy.

The prototype does not defend against an attacker with arbitrary code execution
as the signing user, a compromised compiler or dependency graph, side-channel
extraction from the host, malicious cryptographic implementations, or coerced
release-key use.

## Security boundaries

### Upstream boundary

The proxy authenticates upstream narinfo with the configured classical key,
rejects redirects, bounds metadata, validates route shapes, and requires the
re-signed `URL:` to remain inside the proxy's `nar/` namespace. NAR bytes are
streamed with bounded idle time and optional total size.

### Policy boundary

Wire representations normalize into canonical candidates. The policy evaluator
requires explicitly configured groups and distinct logical identities, ignores
exact duplicates, refuses contradictory candidate outcomes, and reports stable
failure reasons. Algorithm support alone is not treated as mandatory hybrid
authorization.

### Key boundary

Hybrid secret files are created with restrictive permissions and strict parsers.
They remain ordinary host files and are not hardware-backed, threshold-held, or
protected from a compromised user account. Release signing should use a separate
offline key rather than the online proxy key.

### Evidence boundary

Policy evidence replays normalized policy decisions and optionally authenticates
the producer. It does not yet include enough raw Nix material to repeat every
cryptographic verification observation independently.

Release attestations bind a named hybrid key to a deterministic release
statement. The statement binds the source archive and manifest, not binary
packages or a reproducible compilation result.

### Availability boundary

Concurrency, queueing, metadata sizes, response deadlines, and NAR idle time are
bounded. These controls reduce accidental and low-cost denial of service; they
do not provide distributed rate limiting, volumetric DDoS resistance, or
multi-node failover.

## Security properties deliberately not claimed

The repository does not claim:

- production readiness or an independent cryptographic audit;
- compromise resistance after both component signature schemes fail;
- that proxy re-signing makes an upstream PQ-secure;
- confidentiality of cached artifacts;
- complete provenance, SBOM, or reproducible-build proof;
- append-only transparency or globally witnessed timestamps;
- native Nix enforcement by unmodified clients;
- secure multi-tenant key custody;
- protection from a malicious local administrator.

## Residual risks

The highest remaining risks are:

- the online proxy's release/signing key is still a filesystem-held secret;
- upstream trust remains classical unless the origin signs with PQC itself;
- the prototype signature transport differs from likely upstream-native
  algorithm-tagged signatures;
- evidence schema v1 trusts reported signature-verification observations;
- TLS, authentication, configuration distribution, service packaging,
  monitoring retention, and disaster recovery remain deployment concerns;
- long-duration load, fault, and upgrade behavior has not been independently
  demonstrated;
- dependency and compiler compromise remain outside the runtime threat model.

## Review and change discipline

Changes to fingerprinting, signature parsing, trust assignment, policy
composition, release attestations, or failure behavior should include:

1. a narrow threat statement;
2. a negative regression test or conformance vector;
3. deterministic machine-readable evidence where practical;
4. documentation that states both the new property and its limit;
5. compatibility testing against real Nix before release.
