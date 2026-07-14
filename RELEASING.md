# Releasing

The release process produces a deterministic, source-only archive from a clean
Git tree. Build products, `.git`, local keys, fuzz artifacts, and developer
outputs are excluded because only Git-tracked regular files enter the archive.

## Prerequisites

Run the complete validation surface first:

```console
nix flake check --print-build-logs
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
nix run .#audit
nix run .#fuzz-smoke
```

Create an annotated release tag only after those gates pass. The source archive
uses the tagged commit timestamp as `SOURCE_DATE_EPOCH`, so two builders at the
same commit should produce byte-identical source archives, manifests, and
release statements.

## Deterministic source release

From a clean checkout at the intended commit:

```console
nix run .#release-source -- --out-dir dist
```

This creates:

- `nix-pqc-cache-proxy-VERSION-source.tar.gz`;
- `nix-pqc-cache-proxy-VERSION-source.manifest.json`;
- `nix-pqc-cache-proxy-VERSION.release.json`;
- `nix-pqc-cache-proxy-VERSION.environment.json`.

The environment report is informational and intentionally not part of the
reproducible release statement. It records the builder's tools and platform;
the signed statement binds only deterministic source artifacts and locked input
manifests.

Verify the release independently:

```console
nix run .#verify-release -- \
  dist/nix-pqc-cache-proxy-VERSION.release.json
```

For a reproducibility check, build into two empty directories and compare them:

```console
nix run .#release-source -- --out-dir dist-a
nix run .#release-source -- --out-dir dist-b
diff -ru dist-a dist-b
```

## Hybrid release attestation

Generate a dedicated release key through the existing key ceremony and keep the
secret outside the repository:

```console
nix run . -- keygen luminous-release-1 --out-dir /secure/key-directory
```

Build and attest the release statement:

```console
nix run .#release-source -- \
  --out-dir dist \
  --signing-key /secure/key-directory/luminous-release-1.secret
```

The optional `release.attestation.json` carries Ed25519 and ML-DSA-65 signatures
over the canonical release statement. It does not certify code quality or make
the prototype production-ready; it binds one named release key to the exact
archive and manifest hashes.

Verify with an independently obtained public key:

```console
nix run .#verify-release -- \
  dist/nix-pqc-cache-proxy-VERSION.release.json \
  --attestation dist/nix-pqc-cache-proxy-VERSION.release.attestation.json \
  --trusted-key /trusted/luminous-release-1.pub
```

Never publish the secret release key, and never treat a public key bundled only
inside the same release as an independent trust anchor.

## Publication checklist

Before publishing:

1. Confirm the tag points to the reviewed commit.
2. Confirm the tree is clean.
3. Run all Nix, Rust, fuzz, audit, and real-Nix gates.
4. Build the release twice and compare outputs.
5. Verify the archive and manifest with `verify-release`.
6. Attest the deterministic release statement using the offline release key.
7. Publish the source archive, manifest, release statement, environment report,
   attestation, and public-key fingerprint.
8. State the known limitations from `docs/THREAT_MODEL.md`; do not call the
   prototype production-ready or claim it upgrades an untrusted upstream root.
