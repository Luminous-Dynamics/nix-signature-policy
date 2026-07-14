# Policy-decision evidence format

`schema-v1.json` describes the deterministic JSON envelope emitted by the
`policy-evidence` binary.

Version 1 is deliberately limited to **policy replay**. It records normalized
signature candidates and their already-computed cryptographic verification
outcomes, then allows another implementation to reproduce the required-group
policy decision. It does not independently prove that those candidate outcomes
were correct.

An optional Ed25519+ML-DSA-65 attestation authenticates the producer of the
bundle when the verifier is given a separately trusted `.pub` file. A
self-contained attestation without an external trust anchor proves only that the
bundle has not changed since it was signed by the included key.

The original source vector can also be supplied during verification so its byte
length and SHA-256 digest are checked against the recorded source binding.

`examples/semantic-hybrid-valid.evidence.json` is a committed unsigned baseline.
CI re-exports its source vector and requires a byte-for-byte match before
running the offline verifier.
