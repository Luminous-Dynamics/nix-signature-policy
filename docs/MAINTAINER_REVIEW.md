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
4. Inspect `src/caller.rs`, `docs/CALLER_SAFETY.md`, and
   `tests/helper_process_hostility.rs` for the external-helper invocation
   boundary — see "Caller-safety evidence" below for what this proves and
   what it deliberately doesn't attempt.
5. Run both real-Nix lanes:

```console
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
```

6. Run the one-command evidence-producing demonstration:

```console
nix run .#demo -- --out-dir demo-output
```

7. Build the source release twice and compare it:

```console
nix run .#release-source -- --out-dir dist-a
nix run .#release-source -- --out-dir dist-b
diff -ru dist-a dist-b
```

## Caller-safety evidence

The likely first question about any external-verifier proposal
(`docs/PRIOR_ART_AND_DESIGN_DELTA.md` traces this back to the original
[NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451) discussion
itself) is: what happens when the configured helper process is hung,
crashed, malicious, or just buggy? This is what's actually verified, not
asserted, for that boundary:

- 23 adversarial process-invocation tests (`tests/helper_process_hostility.rs`)
  covering missing/non-executable helpers, crashes, signal termination,
  timeouts, output that fills a pipe buffer before the process exits (both
  stdout and stderr), malformed/duplicate-keyed/multi-document/oversized
  JSON, mismatched contract versions, well-formed output paired with an
  unexpected exit code, orphaned grandchild processes, environment and
  working-directory isolation, a bounded excessive-forking simulation, and
  that repeated/concurrent invocations stay independently bounded.
- Every one of those resolves to non-admission under authoritative
  semantics — a caller failure and a helper's own refusal decision are
  distinguished for diagnostics (`InvocationOutcome::Failure` vs.
  `InvocationOutcome::Decision(.. Refuse)`), but neither can produce
  acceptance.
- Fuzz coverage for the request-decoding boundary itself
  (`fuzz/fuzz_targets/authorization_protocol.rs`), on top of the five
  targets already covering the parser, evaluator, and adapters.
- No shell, no inherited environment (`env_clear()`, opt-in allowlist
  only, no `PATH`), no inherited working directory.
- Concurrent, independently-bounded stdout/stderr draining armed before
  any wait/poll loop, so a helper that fills a pipe buffer before exiting
  cannot deadlock the caller — see `docs/CALLER_SAFETY.md` for why a
  naive `try_wait()`-then-read design can.
- Whole-process-group cleanup (not just the direct child) on timeout or
  output overflow, with the direct child always reaped afterward.
- Measured (not estimated) helper invocation overhead: 1755 cold-start
  samples of the release binary, p50 1.83ms / p99 4.66ms / max 7.15ms,
  under real background load, full methodology and reproduction command
  in `docs/CALLER_SAFETY.md`.
- `cargo test --workspace`: 171 tests total, all passing.

`docs/CALLER_SAFETY.md` maps this against the original 18-item hostile-
helper brainstorm that motivated it, including what's deliberately out of
scope for this layer (OS-level sandboxing, a literal fork bomb) and why.

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
