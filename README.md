# nix-signature-policy

[![CI](https://github.com/Luminous-Dynamics/nix-signature-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Luminous-Dynamics/nix-signature-policy/actions/workflows/ci.yml)

**The problem this investigates.** Nix's binary-cache trust model accepts
any *one* valid signature from a trusted key. That's sufficient for "was
this signed by someone I trust," but it can't express "require both a
classical and a post-quantum signature," "require a quorum of independent
signers," or other composed authorization rules — and today there's no
Nix-side interface for a pluggable policy to make that decision. This
repository is a reference implementation and conformance suite exploring
what such an interface could look like, in support of
[NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451).

**What was actually demonstrated.** A transport-neutral authorization core
(`core-v1`) that composes typed signer evidence into thresholds,
independent-authority and cryptographic-family requirements, rollback
protection, and deterministic decision evidence — plus a bridging adapter
that independently verifies real Ed25519 and ML-DSA-65 `Sig:` entries
produced by a real, independently-built multi-algorithm Nix
([DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449)),
so the core can be exercised against real signature bytes without depending
on [NixOS/nix#15926](https://github.com/NixOS/nix/pull/15926) landing
first. Full detail:
[`docs/RAW_EVIDENCE_ADAPTER.md`](docs/RAW_EVIDENCE_ADAPTER.md).

**Proposed vs. implemented.** The authorization core, its adapters, and the
raw-signature verifier are implemented and tested here, against real Nix
output. The corresponding Nix-side integration — an actual invocation hook
at Nix's admission boundary — is **not** implemented; see
[`docs/NIX_INTEGRATION_CONTRACT.md`](docs/NIX_INTEGRATION_CONTRACT.md) and
[`docs/NIX_INTEGRATION_ARCHAEOLOGY.md`](docs/NIX_INTEGRATION_ARCHAEOLOGY.md).

**What this does not ask of upstream Nix.** No new narinfo signature field,
no per-entry algorithm tag on the wire, no change to Nix's own verifier
internals, and no dependency on `#15926` landing first. The open question is
narrower: an explicit composition point between Nix's existing trust
decision and the result of a locally invoked, pluggable authorizer.

**Five-minute review path:**
[`docs/MAINTAINER_REVIEW.md`](docs/MAINTAINER_REVIEW.md).

**Verified evidence.** Claims about real Determinate Nix interoperability
are pinned to commit
[`a900a4f`](https://github.com/Luminous-Dynamics/nix-signature-policy/tree/a900a4f31ee270c390e99e19f202f45111c90a38)
(annotated tag `raw-evidence-adapter-verified-2026-07-16`); see
`tests/fixtures/determinate-nix-449/PROVENANCE.md` for the full build
record.

**Status:** research prototype. The policy engine and conformance suite are not
a native Nix implementation, and the bundled cryptographic/proxy components are
unaudited and must not be treated as production security infrastructure.

## Documentation

**[`docs/CANDIDATE_ARCHITECTURES.md`](docs/CANDIDATE_ARCHITECTURES.md)** —
an empirical comparison of five point-wise Nix authorization-boundary
architectures plus a closure/build-trace skeleton, each built against a
real patched Nix fork and independently verified (real diffs, real
tests, real E2E scenarios — including a demonstrated in-process-provider
crash). Grounded directly in #14451's own thread objections rather than
a single proposed design. Factual results only; no ranking or
recommendation.

Current work — composable authorization core and raw-evidence adapter:

- [`docs/RAW_EVIDENCE_ADAPTER.md`](docs/RAW_EVIDENCE_ADAPTER.md) — verifying
  real narinfo `Sig:` entries without depending on `#15926`, validated
  against a real Determinate Nix build;
- [`docs/NIX_INTEGRATION_CONTRACT.md`](docs/NIX_INTEGRATION_CONTRACT.md) —
  the proposed Nix-side composition boundary;
- [`docs/MAINTAINER_REVIEW.md`](docs/MAINTAINER_REVIEW.md) — the guided,
  five-minute review path, including the caller-safety evidence summary;
- [`docs/PRIOR_ART_AND_DESIGN_DELTA.md`](docs/PRIOR_ART_AND_DESIGN_DELTA.md) —
  the actual upstream discussion (#14451, #15926, the closed #202) and exactly
  what this project adds on top of it;
- [`docs/NIX_INTEGRATION_ARCHAEOLOGY.md`](docs/NIX_INTEGRATION_ARCHAEOLOGY.md) —
  what the real Nix source actually shows about where this would integrate;
- [`docs/CALLER_SAFETY.md`](docs/CALLER_SAFETY.md) — the hardened external-helper
  invocation contract and its adversarial test coverage;
- [`docs/CORE_V1.md`](docs/CORE_V1.md) — frozen minimal interoperability profile;
- [`docs/NORMATIVE_AUTHORIZATION_SPEC.md`](docs/NORMATIVE_AUTHORIZATION_SPEC.md),
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
  [`docs/CONFORMANCE_PROFILE.md`](docs/CONFORMANCE_PROFILE.md),
  [`docs/UPSTREAM_MINIMAL_SLICE.md`](docs/UPSTREAM_MINIMAL_SLICE.md),
  [`docs/SECURITY_REVIEW_CHECKLIST.md`](docs/SECURITY_REVIEW_CHECKLIST.md);
- [`rfc/0001-composable-signature-authorization.md`](rfc/0001-composable-signature-authorization.md)
  — the current upstream-oriented draft.

Background and superseded material:

- [`docs/PROJECT_HISTORY.md`](docs/PROJECT_HISTORY.md) — how this project got
  here, phase by phase;
- [Historical prototype and superseded wire-format exploration](#historical-prototype-and-superseded-wire-format-exploration)
  — the original `nix-pqc-cache-proxy` binary and invented `Sig-PQC:` field,
  further down this document.

## What's proven, and what isn't

**Proven, by running real code against a real `nix` binary and real Nix
source (`NixOS/nix` commit `ac94798c753e48fd0b36128a029ed8aecebe9b56`,
`master`, 2026-07-08; verified 2026-07-10 — pinned since `master` moves,
re-check against current source before relying on this), not by
assertion:**
- Our narinfo fingerprint construction is byte-identical to real Nix's for
  the covered fixtures, including `StorePathSet` reference semantics:
  whitespace tokenization, sorting, and duplicate elimination (verified
  against `src/libstore/include/nix/store/path-info.hh` and pinned by the
  fingerprint vectors below).
- The hybrid signature construction is internally sound (round-trip,
  tamper-rejection, wrong-signer-rejection — `src/hybrid.rs` tests).
- A real, unmodified `nix` binary trusts a narinfo dual-signed by this tool
  when only our key is configured as trusted, and correctly refuses it
  when no key is trusted (`tests/real_nix_e2e.rs`, run for real, not just
  compiled — see "End-to-end verification" below).
- The repository includes a hermetic unit/integration/vector suite plus a
  separately ignored real-Nix end-to-end lane, and has previously been
  verified from a completely independent copy with zero path dependencies
  on the monorepo it was developed in.

**Not proven, and not claimed:**
- That the specific `Sig-PQC:` field name or byte encoding is the one a
  real NixOS RFC would settle on — see `rfc/`'s own "Unresolved questions."
- That `src/hybrid.rs`'s construction is safe for any real use — it is
  unaudited.
- That this proxy is fit for production traffic — see "Explicitly out of
  scope" below for what was deliberately left undone.
- Storage/bandwidth cost at real `cache.nixos.org` scale — only a
  single-narinfo measurement exists here (see below).

## What's here

- `src/lib.rs` — library crate (`hybrid`/`narinfo`/`keys`/`proxy` plus the
  representation-neutral `policy`/`policy_adapters`/`conformance` modules) so
  integration tests, the policy harness, and the criterion bench can exercise
  the logic directly; `src/main.rs` is a thin CLI wrapper over it.
- `src/hybrid.rs` — the hybrid Ed25519+ML-DSA-65 primitive: keygen, sign,
  verify, persistence. Vendored (not path-dependency'd) from this
  monorepo's `mycelix-crypto::hybrid_sig` — same author, same
  AGPL-3.0-or-later license — specifically so this crate has **zero
  private-monorepo path dependencies** and builds from a fresh clone.
  `mycelix-crypto` belongs to a separate, larger PQC roadmap with its own
  audit/publish timeline; vendoring keeps that roadmap independent of this
  prototype's needs and puts the entire construction this RFC relies on in
  one directly-auditable ~250-line file.
- `src/narinfo.rs` — hand-rolled `.narinfo` parser/serializer + the Nix v1
  signing fingerprint (`1;<path>;<narhash>;<narsize>;<refs>`). Verified
  bit-compatible with real Nix: a frozen fixture (a real narinfo fetched from
  `cache.nixos.org` for `bash-5.2p37`) round-trips through parse → fingerprint
  → **Ed25519 verify against the real `cache.nixos.org-1` public key**, and
  that verification actually passes. References are tokenized on
  whitespace, sorted, and deduplicated before fingerprinting, matching real
  Nix's `StorePathSet` (`std::set`) semantics — see "Reference-set
  canonicalization" below.
- `src/keys.rs` — hybrid key generation/storage, and the `Sig-PQC:` wire
  encoding: `name:base64(alg_tag(1B) || ml_dsa_sig)` — deliberately **not**
  a copy of the Ed25519 signature, which already lives in the same-keyname
  `Sig:` line. `decode_sig_pqc()` enforces the exact expected ML-DSA-65
  signature length (3309 bytes) at this codec boundary. `verify_hybrid()`
  requires **both** an Ed25519 `Sig:` candidate and an ML-DSA `Sig-PQC:`
  candidate for the given keyname to independently verify against the
  fixed keys/message — checked in O(n+m), not by trying every classical×PQC
  pairing (an earlier O(n×m) version did this; pairing turned out to have
  no effect on the result, since neither half's verification depends on
  which candidate it's nominally paired with) — with a per-half candidate
  cap plus dedup so a narinfo with many repeated same-keyname lines can't
  force unbounded work. Matches Nix's own any-of-N-signatures trust model,
  and treats a malformed/unrecognized-algorithm/duplicate candidate as
  dropped during collection, never a hard abort that could block a
  different, valid candidate. Exceeding the distinct-candidate cap is an
  explicit policy error rather than an order-dependent rejection after only
  the first entries were checked. `keygen`-time names are validated
  (`validate_key_name`: ASCII alnum + `.`/`_`/`-` only, ≤128 chars) since
  they're embedded verbatim into `Sig:`/`Sig-PQC:` lines and output
  filenames — an unvalidated name could inject a colon or newline into the
  wire format. Secret/public key files are created through a synced sibling
  temporary file and an atomic no-replace hard-link commit, so concurrent
  key generation cannot overwrite an existing key; overwrite operations use
  temp-file + rename. The secret file is mode 0600 on Unix and the parent
  directory is synced after commit.
- `src/policy.rs`, `src/policy_adapters.rs`, and `src/conformance.rs` — a
  representation-neutral typed-group evaluator with identity/family/authority
  relations, plus adapters for semantic,
  historical `Sig:` + `Sig-PQC:`, and ordinary algorithm-tagged observations,
  plus a deterministic machine-readable vector runner. Thresholds count
  distinct logical signer identities rather than signature entries or keys.
  Candidate evidence is canonicalized so input order cannot select a result;
  contradictory outcomes for one signature identity fail closed. The committed
  adversarial suite covers downgrade attempts, invalid halves,
  revocation/validity windows, duplicate amplification, candidate limits, and
  transport parity.
- `policy-vectors/` — 32 CC0 schema-v2 policy vectors and a JSON Schema. Run
  them with `nix run .#policy-conformance` or the equivalent Cargo binary.
- `src/artifact_attestation.rs`, `src/bin/artifact-attestation.rs`, and
  `release/` — deterministic hybrid attestations over release statements plus
  a strict source-release schema. The release statement binds a clean Git
  commit to the source archive, file manifest, and locked research-input
  manifests; the optional Ed25519+ML-DSA-65 attestation authenticates that
  statement without pretending to certify production readiness. See
  [`RELEASING.md`](RELEASING.md).
- `src/evidence.rs`, `src/bin/policy-evidence.rs`, and `evidence/` — strict,
  deterministic policy-decision evidence payloads and optional producer attestations. The offline verifier checks
  the payload digest, canonical ordering, exact decision replay, optional source
  binding, and optional Ed25519+ML-DSA-65 producer attestation. Schema v1 is
  deliberately limited to policy replay: candidate cryptographic outcomes are
  inputs, not independently re-proven facts. See `docs/EVIDENCE_BUNDLES.md`.
- `src/proxy.rs` — an axum reverse proxy speaking the Nix HTTP binary-cache
  protocol: fetches `nix-cache-info` / `.narinfo` / `nar/*` from a configured
  upstream, verifies the upstream's `Sig:` against a configured public key
  (name-enforced when `--upstream-pubkey` carries a `name:` prefix, exactly
  like `nix.conf`'s `trusted-public-keys`; name-blind with a startup warning
  otherwise), and re-serves the narinfo with an added ordinary `Sig:` plus
  `Sig-PQC:`. The operational boundary is now explicit: bounded in-flight
  work and queueing, strict route-segment and metadata validation, redirect
  refusal, configurable connect/header/idle deadlines, optional total NAR
  limits, graceful Ctrl-C/SIGTERM draining, JSON event logs, and low-cardinality
  `/healthz`, `/readyz`, and `/metrics` endpoints. NAR bodies remain streamed
  rather than buffered, and their concurrency permit is held until the body
  reaches EOF or fails. Re-signing is idempotent for the proxy's own key. See
  [`docs/OPERATIONAL_HARDENING.md`](docs/OPERATIONAL_HARDENING.md) and the
  trust-model warning above.
- Main CLI: `keygen`, `sign <cache_dir>`, `verify <narinfo> [--pubkey
  name:base64] [--pqc-pubkey path] [--require-pqc]`, `proxy`. The separate
  `policy-conformance`, `policy-evidence`, and `artifact-attestation` binaries
  run adversarial vectors, portable decision evidence, and release-statement
  attestation respectively. At least one
  verification key is required. Supplying `--pqc-pubkey` is itself an
  explicit hybrid-verification request: a missing or invalid `Sig-PQC:` now
  fails even without the redundant `--require-pqc` marker, and
  `--require-pqc` without a PQC public key is rejected.

## Bounded proxy operation

The proxy defaults to loopback and conservative operational limits:

```console
cargo run --locked --bin nix-pqc-cache-proxy -- proxy \
  --upstream https://cache.example \
  --upstream-pubkey cache.example-1:BASE64 \
  --key proxy-1.secret \
  --listen 127.0.0.1:8443
```

The limits can be changed with `--max-in-flight`, `--queue-timeout-ms`,
`--connect-timeout-secs`, `--metadata-timeout-secs`,
`--nar-header-timeout-secs`, `--nar-idle-timeout-secs`, and the optional
`--max-nar-bytes`. Requests that exceed bounded queue capacity receive a
stable `503` refusal rather than waiting indefinitely.

Operational endpoints:

- `/healthz` — local process/router liveness;
- `/readyz` — validated upstream `nix-cache-info` reachability;
- `/metrics` — Prometheus text counters without path, key, or client labels.

Every NAR stream retains an in-flight permit until EOF, failure, timeout, or
client cancellation. Re-signed narinfo metadata is constrained to a relative
`nar/<validated-filename>` URL so clients cannot be redirected around the
bounded streaming path.

The CLI drains admitted requests on Ctrl-C and SIGTERM. Full semantics and
remaining limitations are in
[`docs/OPERATIONAL_HARDENING.md`](docs/OPERATIONAL_HARDENING.md).

## Offline policy-decision evidence

One conformance vector can be normalized, evaluated, and exported as a
self-contained deterministic bundle:

```console
cargo run --locked --bin policy-evidence -- export-vector \
  policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --out hybrid-valid.evidence.json
```

The verifier recomputes the policy decision rather than trusting the serialized
result. Supplying the original vector checks the recorded byte length and
SHA-256 source binding:

```console
cargo run --locked --bin policy-evidence -- verify \
  hybrid-valid.evidence.json \
  --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --require-source
```

`--signing-key` adds a hybrid producer attestation; `--trusted-key` requires the
attestation to match a separately trusted public key. A self-contained key is
not a trust anchor, and even a trusted producer signature cannot prove that the
producer's candidate-verification observations were correct. The exact
assurance boundary and stable refusal codes are documented in
`docs/EVIDENCE_BUNDLES.md`.

## Real, previously-undetected bug: reference-set canonicalization

Real Nix stores narinfo `references` in a `StorePathSet`
(`std::set<StorePath>`, ordered by `StorePath`'s default lexicographic
comparison on the basename — verified directly against
`src/libstore/include/nix/store/path-info.hh`, whose doc comment on
`fingerprint()` literally says "the sorted references"). It never trusts
the narinfo text's original order. This prototype's first several passes
stored references as a plain `Vec` and joined them in whatever order the
text had — silently correct in every test so far only because every real
narinfo used as a fixture happened to already be canonically sorted (since
real Nix always emits them that way). `fingerprint()` now applies the
complete set semantics before joining: whitespace tokenization, sorting,
and duplicate elimination. The unit tests plus
`fingerprint-003-shuffled-references.json` and
`fingerprint-004-duplicate-references.json` pin those properties down so
they cannot silently regress.

## Reproducible Nix workflow

The repository is itself a locked Nix flake. `flake.lock` pins nixpkgs,
`rust-overlay`, and `flake-utils`; `rust-toolchain.toml` remains the single
source of truth for the Rust 1.86 compiler floor, and the flake consumes that
exact version rather than drifting with nixpkgs.

```console
nix develop
nix flake check
nix run .#check
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
nix run .#audit
nix run .#policy-conformance -- --format json > policy-report.json
nix run .#policy-evidence -- --help
nix run .#environment > environment.json
```

`nix flake check` is the hermetic local/CI gate. It builds the package and
runs format, Clippy, unit/integration/vector tests, JSON Schema validation,
the executable policy conformance harness, examples/bench compilation, and
rustdoc against the locked Cargo dependency graph. The ignored real-Nix
proof remains separate because it starts local HTTP services and exercises
Nix's store commands. Its two flake apps run the same proof with nixpkgs'
`nixVersions.stable` and `nixVersions.latest` packages. Both supply an
already-built `hello` store path from the locked nixpkgs input, so the proof
does not depend on the caller's flake registry or resolve `nixpkgs#hello` at
runtime.

`nix run .#environment` emits a JSON record of the exact Rust/Cargo/Nix
binaries, direct locked Cargo dependencies, flake input revisions and hashes,
platform, configured TLS backend, and SHA-256 manifests of the committed
policy-vector, evidence-schema/example, and fuzzing surfaces. Attach it to benchmark or interoperability
results instead of relying on a hand-written environment description. Reqwest is
configured with `rustls-tls` and default features disabled, so OpenSSL is not a
direct build/runtime requirement of this crate.

CI intentionally has one additional `cargo +stable` lane. The flake proves the
documented Rust 1.86 floor; the forward-compatibility lane detects breakage on
the current stable compiler without changing the reproducible baseline.

To update the pinned environment, review and commit the lock change
deliberately:

```console
nix flake update
nix flake check
nix run .#real-nix-e2e-stable
nix run .#real-nix-e2e-latest
```

## Testing

- `nix flake check` — the authoritative reproducible gate: package build,
  formatting, Clippy, hermetic tests, examples/benches, and documentation under
  the Rust version pinned in `rust-toolchain.toml`.
- `nix run .#check` — the same fast validation commands in the current checkout,
  useful while iterating before asking Nix to build each check derivation.
- `cargo test --locked` — the underlying hermetic unit, proxy integration, and
  committed JSON-vector suite. It requires neither network access nor a local
  `nix` installation.
- `tests/real_nix_e2e.rs` — the full real-`nix` proof, `#[ignore]`d in the
  hermetic lane because it needs `nix` and `python3`. Run it through
  `nix run .#real-nix-e2e-stable` or `nix run .#real-nix-e2e-latest`; those apps
  supply a pinned, prebuilt store path. A manual Cargo invocation still falls
  back to resolving `nixpkgs#hello` when `NIX_PQC_E2E_STORE_PATH` is absent.
- `cargo check --locked --benches --examples` — compiles the Criterion bench
  and vector generator, which ordinary `cargo test` does not guarantee.
- `cargo bench --locked` — timings for keygen/sign/verify/encoding and narinfo
  parse/serialization.
- `policy-vectors/*.json` — representation-neutral adversarial authorization
  vectors. `cargo run --locked --bin policy-conformance -- --format json`
  emits a stable report and exits nonzero on any semantic mismatch. The locked
  Nix gate also validates every fixture against `schema-v2.json`.
- `tests/properties.rs` — deterministic generated invariants for reference-set
  canonicalization, serialization idempotence, signature replacement,
  adapter parity, candidate bounds, and policy permutation independence.
- `nix run .#fuzz-smoke` — five bounded nightly libFuzzer campaigns over the
  narinfo parser, signature codecs, transport adapters, policy evaluator, and
  evidence parser/offline verifier.
  See [`docs/FUZZING.md`](docs/FUZZING.md) for longer campaigns and corpus
  handling.
- `test-vectors/*.json` — four fingerprint vectors (canonical references,
  zero references, shuffled order, and duplicate references) plus eight
  signature vectors. `tests/test_vectors.rs` consumes every committed vector
  so generator/implementation drift fails CI.
- `rust-toolchain.toml` pins the documented MSRV toolchain locally; CI also
  checks stable Rust and the Rust 1.86 floor. External GitHub Actions are
  pinned by commit rather than floating tags.

## Real measurements from this pass

- **Signature overhead**: measured directly on a real narinfo
  (`bash-5.2p37`) — the `Sig-PQC:` line alone is **~4.4KB** (ML-DSA-65's
  3309-byte signature, base64-inflated ~4/3×, plus a 1-byte tag and the
  field/keyname prefix). An earlier draft duplicated the Ed25519 signature
  inside `Sig-PQC:` too (~4.6KB); removed once no one could justify the
  extra ~88 base64 characters per entry — see the RFC's "Wire format"
  section. This is a single-narinfo measurement; a real projection at
  `cache.nixos.org`'s actual scale would need access this prototype
  doesn't have (flagged as an open question in the RFC).
- **Sign/verify speed** — historical numbers from Criterion's optimized
  bench profile (`cargo bench`, `benches/pqc_bench.rs`) on the original
  author's machine. They are useful as order-of-magnitude evidence, not a
  reproducible cross-machine benchmark until the CPU/compiler/profile
  metadata is captured alongside a fresh run:

  | Operation | Time |
  |---|---|
  | `hybrid_keygen` | ~649 µs |
  | `hybrid_sign_fingerprint` | ~1.04 ms |
  | `hybrid_verify` | ~523 µs |
  | `sig_pqc_encode` (base64 + tag) | ~5.76 µs |
  | `narinfo_parse` | ~971 ns |
  | `narinfo_to_text` | ~3.31 µs |

  ML-DSA-65 sign/verify dominate, as expected — both are still
  sub-millisecond, so at CLI/HTTP granularity this is negligible next to
  network I/O.

## End-to-end verification actually performed

Originally done by hand and then codified as `tests/real_nix_e2e.rs`. A
previous recorded run completed successfully in 136.26 seconds. The CI lane
is the authoritative check for any later commit:

1. `cargo test --locked` — the hermetic suite, including a real (not fabricated)
   narinfo fixture verifying against the real `cache.nixos.org-1` Ed25519
   key, deliberate corruption tests for both the classical and ML-DSA
   halves, and the full test-vector suite.
2. Selected a real `hello` store path and `nix copy`'d its closure to a
   local `file://` binary cache. The historical manual run built
   `nixpkgs#hello`; current flake lanes inject `${pkgs.hello}` from the locked
   nixpkgs input instead.
3. `keygen` a hybrid key; `sign` the local cache — all 5 narinfo files
   gained a `Sig:` (our key) and `Sig-PQC:` line; `verify --require-pqc`
   passed; a deliberately-corrupted `Sig-PQC` byte was correctly rejected.
4. Served that cache over plain HTTP; ran `proxy` in front of it. Fetching
   `/<hash>.narinfo` through the proxy returned the upstream's original
   `Sig:` **plus** our added `Sig:`/`Sig-PQC:` — after the proxy verified the
   upstream's signature first (a deliberately-wrong `--upstream-pubkey`
   causes every narinfo fetch to fail closed).
5. A real, unmodified `nix copy --from http://127.0.0.1:8998 ...` pulled the
   full closure through the proxy successfully.

## An honest correction found during testing

Step 5 above is **not**, by itself, proof that `nix` verified any signature —
this was an actual, non-obvious discovery while building the demo: `nix copy`
between two arbitrary stores (a real substituter → a local `file://`
directory you own) does **not** enforce `.narinfo` signature checks in
practice, regardless of `--option trusted-public-keys`. That check matters
for the *destination* protecting itself from an untrusted writer; an ad hoc
`file://` directory you already have write access to isn't a protected
destination, so there's nothing to enforce.

The rigorous test is **`nix store verify`**, which directly exercises Nix's
own trust logic against an existing store:

```console
$ nix store verify --store file:///tmp/pqc-demo-dest3 \
    --option trusted-public-keys 'demo-1:1K2jCetCe2XrIXvUX9xo+W/t2FhZscU2HEKUZgErh1Q=' \
    /nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3
checking '/nix/store/...-hello-2.12.3'...
$ echo $?
0

$ nix store verify --store file:///tmp/pqc-demo-dest3 \
    --option trusted-public-keys '' \
    /nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3
checking '/nix/store/...-hello-2.12.3'...
path '/nix/store/...-hello-2.12.3' is untrusted
```

Trusting **only** our proxy's hybrid-signing key is sufficient for real,
unmodified `nix` to consider the path trusted; trusting no key at all is
correctly refused. This is the actual proof that the classical half of our
hybrid format is fully backward compatible: real `nix` accepts the added
classical `Sig:` line we produce and simply never looks at `Sig-PQC:` at
all — it does not "accept the hybrid signature" in any sense beyond that.

## Maintainer review, demonstration, and releases

The shortest evidence-oriented review path is documented in
[`docs/MAINTAINER_REVIEW.md`](docs/MAINTAINER_REVIEW.md). The consolidated
security assumptions and non-claims are in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

A single command runs the policy harness, exports and replays decision evidence,
and executes the real-Nix interoperability proof while preserving machine-
readable outputs:

```console
nix run .#demo -- --out-dir demo-output
```

Deterministic source-only releases are built from clean Git-tracked files:

```console
nix run .#release-source -- --out-dir dist
nix run .#verify-release -- dist/nix-signature-policy-VERSION.release.json
```

The release statement may be hybrid-attested with a separate Ed25519+ML-DSA-65
release key. This binds the source archive and manifest to the named key; it does
not certify production readiness, audit status, or reproducible binaries. See
[`RELEASING.md`](RELEASING.md) and [`SECURITY.md`](SECURITY.md).

## Explicitly out of scope

- No changes to the real Nix daemon/client source, no liboqs FFI, no attempt
  to make `cache.nixos.org` itself PQC-signed.
- Production service operation. The operational-hardening profile adds
  bounded admission, differentiated failures, safe cache headers,
  health/readiness/metrics, structured logs, redirect refusal, fault
  injection, and graceful draining, but it does not provide TLS termination,
  client authentication, distributed rate limiting, supervisor packaging,
  long-duration soak evidence, or an independent security audit.
- Production key management, rotation, or multi-algorithm PQC support in
  the proxy itself (the wire format's tag byte anticipates it; the proxy
  doesn't implement it).

## Historical prototype and superseded wire-format exploration

This section documents the project's original phase: the `nix-pqc-cache-proxy`
binary and an invented `Sig-PQC:` narinfo field. That phase is superseded by
the composable-authorization-core work described at the top of this document
— it's kept here for the proxy's own users and for historical/audit
completeness. See [`docs/PROJECT_HISTORY.md`](docs/PROJECT_HISTORY.md) for
the full evolution.

### The proxy's trust model

**The proxy upgrades the signature *format*. It does not upgrade the
upstream *root of trust*.** Its flow is: receive upstream metadata signed
with Ed25519 → verify that Ed25519 signature → mint a new hybrid signature
(our own Ed25519 + ML-DSA) over the same content. If an attacker can forge
Ed25519 signatures (the exact threat a cryptographically-relevant quantum
computer poses), they can hand the proxy forged upstream metadata; the
proxy will happily verify that forged classical signature and then mint a
perfectly valid ML-DSA signature over it. **The proxy is only as
trustworthy as the classical upstream it's translating from** — it is a
wire-format and deployment-mechanics demonstration, not a way to make a
classically-signed cache post-quantum secure. A real post-quantum root of
trust requires the origin cache itself to sign
with a PQC key. DeterminateSystems/nix-src#449 demonstrates native
ML-DSA algorithm agility, while upstream Nix PR #15926 proposes the
corresponding key-type abstraction. Those are direct prior art and solve a
different prerequisite. The remaining question studied here is policy:
ordinary any-valid signature admission does not by itself require a
classical **and** PQ authorization group. Useful things this prototype
demonstrates are one concrete AND-composed rule, a backward-compatible
experimental adapter, deployment mechanics, and a migration bridge for
caches whose origin is independently authenticated by another means.

### Original scope

Nix's supply chain has two halves for quantum readiness: store-path hashing
(truncated SHA-256, still fine under Grover's algorithm) and binary-cache
trust (Ed25519 `.narinfo` signatures, broken outright by Shor's algorithm on
a cryptographically-relevant quantum computer). This tool addresses the
second half — but **it does not and cannot make `cache.nixos.org` itself
PQC-signed**: upstream doesn't sign with ML-DSA and we don't hold their key.
What it demonstrates is one mandatory hybrid rule and a local
trust-translating proxy, using a format (`Sig-PQC:`) that is our own
invention for this prototype, not a Nix or IETF specification. The bundled
RFC is retained as a historical transport-format draft. The committed
`policy-vectors/` suite and `src/policy*.rs` harness model policy independently
from transport so the same cases can be evaluated through ordinary
algorithm-tagged signatures, this prototype’s parallel field, or a future
authoritative external verifier.

## RFC and current upstream context

The current upstream-oriented draft is
[`rfc/0001-composable-signature-authorization.md`](rfc/0001-composable-signature-authorization.md).
It replaces the historical transport proposal with a bounded,
transport-independent authorization layer. The original `Sig-PQC:` RFC remains
in the repository only as an auditable record of the experiment that exposed
the policy distinction.


The repository’s current position is documented in
[`docs/PRIOR_ART.md`](docs/PRIOR_ART.md). In summary, as reviewed on
2026-07-14:

- [DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449)
  is merged and implements `ecdsa-p384` plus `ml-dsa-{44,65,87}` through
  the ordinary key/signature machinery.
- [NixOS/nix PR #15926](https://github.com/NixOS/nix/pull/15926) is open and
  extracts the multi-key-type abstraction for upstream review.
- [NixOS/nix issue #14451](https://github.com/NixOS/nix/issues/14451) is an
  open proposal for externally configurable verification policy, including
  rotation, revocation, thresholds, and attestations.
- [NixOS/rfcs PR #202](https://github.com/NixOS/rfcs/pull/202) contains the
  original `Sig-PQC:` proposal and the public reframing toward ordinary
  signatures plus explicit policy and migration semantics.

Those developments show that a separate `Sig-PQC:` field is not required
merely to achieve algorithm agility. This project does not claim first PQ
signature support for Nix. Its continuing contribution is narrower:
machine-checkable exploration of the difference between any-valid
verification and mandatory signature-group composition.

[`docs/PRIOR_ART_AND_DESIGN_DELTA.md`](docs/PRIOR_ART_AND_DESIGN_DELTA.md)
records that upstream discussion in more detail than the summary above —
including where #14451's own author already flagged the exit-code
ambiguity this project resolves, and a NixOS/nix maintainer's real,
acknowledged-not-dismissed concern about point-wise vs. closure-wide trust.
[`docs/NIX_INTEGRATION_ARCHAEOLOGY.md`](docs/NIX_INTEGRATION_ARCHAEOLOGY.md)
is a read-only research pass against the real Nix source tracing the
actual signature-admission call flow, with file:line citations, rather
than assumption. [`docs/CALLER_SAFETY.md`](docs/CALLER_SAFETY.md) documents
`src/caller.rs`, a hardened reference implementation of safely invoking an
external authorization helper, adversarially tested in
`tests/helper_process_hostility.rs` against hangs, crashes, malformed
output, and orphaned processes.

The six-layer model in
[`docs/SIGNATURE_POLICY_MODEL.md`](docs/SIGNATURE_POLICY_MODEL.md) separates:
encoding, cryptographic verification, trust, authorization policy,
migration, and evidence. The representation-neutral conformance harness in
`policy-vectors/` and `src/policy*.rs` now exercises that model without
treating `Sig-PQC:` as the policy itself.

`rfc/0000-hybrid-binary-cache-signatures.md` remains unchanged in identity
as the historical transport draft that produced the prototype. Its status
and reading order are explicit in [`rfc/README.md`](rfc/README.md).

## License

The crate (`src/`, `tests/`, `benches/`, `examples/`) is
AGPL-3.0-or-later, per `Cargo.toml` and `LICENSE` — deliberate, since this
is network-facing server software (the `proxy` subcommand) and
modifications served over a network should stay open per the AGPL's intent.
This has no bearing on Nix itself (LGPL-2.1-or-later): every design here
assumes an out-of-process interface (an external command Nix invokes and
reads a response from, per
[NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451)'s own proposed
shape), so nothing in this repository would need to be copied, linked, or
incorporated into Nix for the interface itself to be usable.

`test-vectors/*.json` is CC0-1.0 (`test-vectors/LICENSE`) instead: those
exist specifically so an independent implementation (`tvix`, Cachix,
Attic, ...) can copy them wholesale into its own test suite without
inheriting a copyleft obligation on its own code. Copyleft-licensing pure
interop test data would work against the one thing that directory is for.

See `docs/POLICY_LIFECYCLE_AND_RECOVERY.md` for family failure and anti-rollback semantics.
