# Release evidence

The release tooling produces a deterministic, source-only archive and two
machine-readable records:

- a source manifest describing every archived Git-tracked file;
- a release statement binding the archive and manifest hashes to one clean Git
  commit and the locked policy/evidence/fuzz input manifests.

The environment report is intentionally separate because platform and tool
versions vary across builders. It is useful diagnostic evidence, but including
it inside the deterministic release statement would prevent two independent
builders from producing the same statement.

An optional hybrid release attestation signs the canonical release statement
with Ed25519 and ML-DSA-65. Verification requires a public key obtained through
an independent channel. The attestation proves artifact integrity and signer
identity; it does not prove production readiness, absence of vulnerabilities,
or reproducible binary compilation.

See [`../RELEASING.md`](../RELEASING.md) for the complete procedure and
[`schema-v1.json`](schema-v1.json) for the release-statement schema and
[`attestation-schema-v1.json`](attestation-schema-v1.json) for the optional
hybrid attestation envelope.
