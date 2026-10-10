# nix-pqc-cache-proxy

> **Repository-name note:** this GitHub repository is currently named `nix-signature-policy`, but the checked-in Rust package is `nix-pqc-cache-proxy`. The repository name and implementation identity are inconsistent and should be reconciled in a separate decision.

> [!WARNING]
> **Exploratory prototype — not production security software.** The code is unaudited cryptographic research software. Do not use it to protect systems you depend on. The `Sig-PQC:` field is a prototype extension, not an upstream Nix feature or a ratified standard.

This repository contains a Rust prototype for hybrid Ed25519 + ML-DSA-65 signing and verification of Nix binary-cache `.narinfo` metadata, plus a local trust-translating reverse proxy. Its current checked-in implementation is the `nix-pqc-cache-proxy` CLI and library; it is **not** a general-purpose composable policy evaluator.

## What is implemented

The CLI currently exposes four workflows:

- `keygen` — generate a local hybrid signing key pair.
- `sign` — add the prototype's classical and ML-DSA signature fields to local `.narinfo` files.
- `verify` — verify classical and/or hybrid signature evidence, with an explicit `--require-pqc` option.
- `proxy` — fetch metadata from an upstream cache, verify its classical signature, and re-sign metadata with a local hybrid key.

The implementation includes Rust modules for hybrid signing, key material, narinfo parsing/fingerprinting, and the proxy; JSON test vectors; end-to-end tests; and a CI lane that attempts a real-Nix end-to-end check.

## Important trust boundary

The proxy does **not** turn an upstream Ed25519-authenticated cache into a post-quantum root of trust. It first depends on the upstream's classical signature, then adds local hybrid evidence to the metadata it re-serves. This can demonstrate a migration/testing path, but it does not upgrade the upstream authority or establish origin-side post-quantum authentication.

The prototype does not claim to make compromised builders trustworthy, prove build reproducibility, secure signing hosts, or provide audited production cryptography. A downstream client must explicitly implement and enforce the prototype's hybrid-signature policy; the existence of a `Sig-PQC:` field alone does not change the trust decision of existing clients.

## Reproduce the checked-in tests

With a compatible stable Rust toolchain:

~~~sh
cargo test --locked
cargo check --benches --examples --locked
~~~

The CI workflow also contains a separate ignored test lane that installs Nix and runs the real-Nix end-to-end test. That lane is distinct from the hermetic tests and may require additional network/build time.

The committed `test-vectors/` corpus includes fingerprint fixtures and valid/invalid `Sig-PQC:` cases. `tests/test_vectors.rs` is the Rust conformance test entry point.

## Design document and evidence

- [Hybrid binary-cache signature RFC (draft)](rfc/0000-hybrid-binary-cache-signatures.md) — proposal and threat boundary.
- [Test vectors](test-vectors/) — committed positive and negative fixtures.
- [CI workflow](.github/workflows/ci.yml) — automated test, build, and real-Nix jobs.
- [Archived README narrative](archive/README-policy-evaluator-claims-2026-10-10.md) — retained only for provenance; it contains claims and links that were out of sync with the checked-in tree and must not be treated as current evidence.

## Status and contribution boundary

This is exploratory work to test feasibility and compatibility. Before any production claim, it needs independent cryptographic review, a clearly specified upstream/downstream trust model, reproducible interoperation with independent implementations, and a maintained security-reporting path. Contributions that narrow a claim or identify an unsafe assumption are valuable.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
