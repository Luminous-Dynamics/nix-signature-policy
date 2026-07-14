# Maintainer review guide

This guide is for Nix, cryptography, and supply-chain reviewers who want to
evaluate the prototype without first reading the entire repository.

## Primary claim

The project does not claim first implementation of PQ signatures for Nix.
Determinate and upstream work address algorithm encoding and cryptographic
verification. This prototype isolates a different question: how a verifier can
require explicit signature groups—such as classical **and** post-quantum—rather
than accept any one valid trusted signature.

## Fifteen-minute review

Read, in order:

1. [`README.md`](../README.md), especially the trust model and proven/not-proven
   sections.
2. [`PRIOR_ART.md`](PRIOR_ART.md) for the dated relationship to Determinate and
   upstream Nix work.
3. [`NORMATIVE_AUTHORIZATION_SPEC.md`](NORMATIVE_AUTHORIZATION_SPEC.md) for
   the transport-independent requirements.
4. [`SIGNATURE_POLICY_MODEL.md`](SIGNATURE_POLICY_MODEL.md) for the six-layer
   model.
5. [`THREAT_MODEL.md`](THREAT_MODEL.md) for assumptions and non-claims.
6. `policy-vectors/semantic/002-hybrid-rejects-classical-only.json` and
   `policy-vectors/semantic/021-conflicting-duplicate-refused.json` for two
   representative downgrade cases.

Run:

```console
nix flake check --print-build-logs
nix run .#policy-conformance -- --format pretty
```

## One-hour review

In addition to the above:

1. Inspect `src/policy.rs` and `src/policy_adapters.rs`.
2. Inspect `src/narinfo.rs` for fingerprint canonicalization and parser bounds.
3. Inspect `src/proxy.rs` and `tests/proxy_e2e.rs` for upstream containment,
   streaming, overload, and failure behavior.
4. Run both real-Nix lanes:

```console
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
```

5. Run the one-command evidence-producing demonstration:

```console
nix run .#demo -- --out-dir demo-output
```

6. Build the source release twice and compare it:

```console
nix run .#release-source -- --out-dir dist-a
nix run .#release-source -- --out-dir dist-b
diff -ru dist-a dist-b
```

## Questions reviewers should challenge

- Does the canonical Nix fingerprint match real Nix for every accepted input,
  not only canonical cache output?
- Are signer identities and key groups assigned before policy evaluation in a
  way that cannot be manipulated by the transport adapter?
- Can duplicate, contradictory, revoked, expired, or unknown signatures change
  a decision improperly?
- Is every success path associated with at least one requested and successful
  verification?
- Can upstream metadata redirect clients outside the bounded proxy path?
- Do release and decision attestations prove only what their documents claim?
- Is the operational complexity justified compared with native upstream policy
  work?

## Expected outcomes

A useful review may conclude that:

- the policy distinction is real but belongs upstream in a different form;
- the `Sig-PQC:` adapter should be retired while the representation-neutral
  policy model remains useful;
- some vectors should become shared upstream conformance tests;
- the proxy is valuable only as a research harness, not as a production service;
- a negative result narrows the design space.

Those are successful outcomes. The repository is intended to make the semantic
question testable, not to pre-commit maintainers to this transport or product.

## Review packet outputs

Use [`../rfc/0001-composable-signature-authorization.md`](../rfc/0001-composable-signature-authorization.md)
as the current upstream-oriented draft. The `0000` RFC is historical.

Attach the following to a review or RFC update:

- `nix run .#environment` output;
- `nix run .#policy-conformance -- --format json` output;
- `nix run .#demo`'s `demo-report.json` and real-Nix log;
- the deterministic source release statement and manifest;
- optional hybrid release attestation and independently distributed public-key
  fingerprint.
