# Fuzzing and property hardening

Patch Set 4 established two complementary hardening layers, and Patch Set 5
extends the fuzz boundary to evidence parsing and offline replay:

1. deterministic invariant tests in `tests/properties.rs`, which run in every
   ordinary `cargo test` and `nix flake check`; and
2. five `cargo-fuzz` targets for parser, policy, codec, and evidence surfaces
   that accept adversarial input.

## Targets

| Target | Boundary | Core invariant |
|---|---|---|
| `narinfo_parse` | untrusted `.narinfo` text | parsing never panics; successful canonical serialization reparses idempotently and preserves the signing fingerprint |
| `policy_evaluator` | normalized signature observations | decision evidence is independent of candidate order, including duplicates and contradictory observations |
| `policy_adapters` | semantic, `Sig`/`Sig-PQC`, and algorithm-tagged adapters | equivalent observations normalize identically |
| `signature_codecs` | signature/key-name text codecs | malformed inputs fail cleanly; successful `Sig-PQC` decoding round-trips |
| `evidence_bundle` | strict evidence JSON plus offline replay | parsing and verification never panic; malformed, noncanonical, or contradictory bundles fail cleanly |

The parser and fuzzer entry points enforce explicit size limits. Corpus growth
must not be used to bypass those limits.

## Running

```sh
cargo test --locked --test properties
nix run .#fuzz-smoke
```

For a longer local campaign, enter the dedicated pinned-nightly shell:

```sh
nix develop .#fuzz
cargo fuzz run narinfo_parse -- -max_total_time=3600
cargo fuzz run policy_evaluator -- -max_total_time=3600
cargo fuzz run policy_adapters -- -max_total_time=3600
cargo fuzz run signature_codecs -- -max_total_time=3600
cargo fuzz run evidence_bundle -- -max_total_time=3600
```

`fuzz/artifacts/` and `fuzz/target/` are ignored. Any minimized reproducer that
causes a durable regression test should be committed to the relevant corpus or
to `test-vectors/` / `policy-vectors/`, depending on whether it expresses a
wire-format or policy-semantic property.

## Fail-closed contradiction rule

An adapter must not emit the same `(key_name, algorithm, signature_id)` with
conflicting verification outcomes. That formerly made policy results depend on
input order. The evaluator now refuses such input with
`conflicting_candidate`, and both property tests and fuzzing enforce order
independence.
