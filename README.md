# nix-pqc-cache-proxy: self-contained reference-format prototype

Not a production proxy, not a native Nix implementation, not audited
crypto. What it is: a working, independently-buildable, test-vectored
prototype of a hybrid Ed25519 + ML-DSA-65 signature scheme for Nix's
`.narinfo` binary-cache format — a CLI to generate keys / dual-sign /
verify a local binary cache, and a reverse proxy that verifies an
upstream's classical signature and re-serves the narinfo augmented with
the hybrid field. Real, unmodified `nix` accepts the *classical* signature
this tool adds and ignores the added `Sig-PQC:` field entirely (see "An
honest correction" below for exactly how that was proven, not just
asserted).

**This is exploratory, unaudited, prototype code.** It vendors a hybrid
Ed25519+ML-DSA-65 construction (see `src/hybrid.rs`) that is itself
EXPERIMENTAL and has not had a crypto audit. Do not point this at anything
you actually depend on for security.

## Scope

Nix's supply chain has two halves for quantum readiness: store-path hashing
(truncated SHA-256, still fine under Grover's algorithm) and binary-cache
trust (Ed25519 `.narinfo` signatures, broken outright by Shor's algorithm on
a cryptographically-relevant quantum computer). This tool addresses the
second half — but **it does not and cannot make `cache.nixos.org` itself
PQC-signed**: upstream doesn't sign with ML-DSA and we don't hold their key.
What it demonstrates is the hybrid-signature mechanics and a local
trust-translating proxy, using a format (`Sig-PQC:`) that is our own
invention for this prototype, not a Nix or IETF spec — see `rfc/` for the
actual proposal.

## What's proven, and what isn't

**Proven, by running real code against a real `nix` binary and real Nix
source, not by assertion:**
- Our narinfo fingerprint construction is byte-identical to real Nix's,
  including reference-order canonicalization (verified against
  `src/libstore/include/nix/store/path-info.hh`'s `StorePathSet` — see
  "Real, previously-undetected bug" below).
- The hybrid signature construction is internally sound (round-trip,
  tamper-rejection, wrong-signer-rejection — `src/hybrid.rs` tests).
- A real, unmodified `nix` binary trusts a narinfo dual-signed by this tool
  when only our key is configured as trusted, and correctly refuses it
  when no key is trusted (`tests/real_nix_e2e.rs`, run for real, not just
  compiled — see "End-to-end verification" below).
- This crate builds and passes all 44 tests from a **completely
  independent copy with zero path dependencies** on the monorepo it was
  developed in (verified by literally copying it to `/tmp` and running
  `cargo test` there).

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

- `src/lib.rs` — library crate (`hybrid`/`narinfo`/`keys`/`proxy` modules)
  so integration tests and the criterion bench can exercise the logic
  directly; `src/main.rs` is a thin CLI wrapper over it.
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
  that verification actually passes. References are sorted before
  fingerprinting, matching real Nix's `StorePathSet` (`std::set`) semantics
  — see "Real, previously-undetected bug" below.
- `src/keys.rs` — hybrid key generation/storage, and the `Sig-PQC:` wire
  encoding: `name:base64(alg_tag(1B) || ml_dsa_sig)` — deliberately **not**
  a copy of the Ed25519 signature, which already lives in the same-keyname
  `Sig:` line. `decode_sig_pqc()` enforces the exact expected ML-DSA-65
  signature length (3309 bytes) at this codec boundary. `verify_hybrid()`
  tries **every** same-keyname `Sig:` candidate against **every**
  same-keyname `Sig-PQC:` candidate and succeeds if any pairing verifies —
  matching Nix's own any-of-N-signatures trust model — and treats a
  malformed or unrecognized-algorithm candidate as a failed candidate to
  skip, never a hard abort that could block a different, valid pairing.
  The leading tag byte (`SigPqcAlgorithm`, currently one variant,
  `MlDsa65 = 1`) makes the format self-describing — a future ML-DSA-87 or
  Falcon variant is a new enum arm, not a format rewrite.
- `src/proxy.rs` — an axum reverse proxy speaking the Nix HTTP binary-cache
  protocol: fetches `nix-cache-info` / `.narinfo` / `nar/*` from a configured
  upstream, verifies the upstream's `Sig:` against a configured public key,
  and re-serves the narinfo with an added `Sig:` (same key material, so
  ordinary `nix` needs zero awareness of the hybrid format) plus `Sig-PQC:`.
  `.narinfo` text is buffered (it has to be — we parse and mutate it), but
  NAR bytes are streamed straight through (`axum::body::Body::from_stream`)
  rather than buffered, since a real store path can be gigabytes. The HTTP
  client has a 30s request timeout so a hung upstream can't wedge the proxy
  indefinitely.
- CLI: `keygen`, `sign <cache_dir>`, `verify <narinfo> [--require-pqc]`,
  `proxy`.

## Real, previously-undetected bug: reference-order canonicalization

Real Nix stores narinfo `references` in a `StorePathSet`
(`std::set<StorePath>`, ordered by `StorePath`'s default lexicographic
comparison on the basename — verified directly against
`src/libstore/include/nix/store/path-info.hh`, whose doc comment on
`fingerprint()` literally says "the sorted references"). It never trusts
the narinfo text's original order. This prototype's first several passes
stored references as a plain `Vec` and joined them in whatever order the
text had — silently correct in every test so far only because every real
narinfo used as a fixture happened to already be canonically sorted (since
real Nix always emits them that way). `fingerprint()` now sorts references
before joining; `narinfo::tests::fingerprint_is_invariant_to_reference_order_in_text`
and `test-vectors/fingerprint-003-shuffled-references.json` pin this down
so it can't silently regress.

## Testing

- `cargo test` — 44 tests: unit tests (`src/`, including `hybrid.rs`'s own
  primitive-level suite), `tests/proxy_e2e.rs` (4 **hermetic** integration
  tests: an in-process fake upstream binary cache with its own throwaway
  Ed25519 key, real HTTP on an OS-assigned port, no network or `nix`
  binary required — narinfo augmentation, fail-closed on an unverifiable
  upstream signature, byte-exact 5MB NAR streaming, `nix-cache-info`
  passthrough), and `tests/test_vectors.rs` (13 tests consuming
  `test-vectors/*.json`). Fast (a couple seconds) and safe to run
  anywhere, including CI, including a machine with no access to this
  monorepo at all.
- `tests/real_nix_e2e.rs` — the full real-`nix` proof (see next section),
  `#[ignore]`d since it needs `nix`, network, and `python3`. Run explicitly:
  `cargo test --test real_nix_e2e -- --ignored --nocapture`.
- `cargo bench` — `benches/pqc_bench.rs`, timing keygen/sign/verify/encode
  and narinfo parse/serialize against a real captured narinfo fixture.
- `test-vectors/*.json` (generated by `cargo run --example
  generate_test_vectors`) — 3 fingerprint vectors (including a
  shuffled-reference-order case) and 8 signature vectors (valid; corrupted
  ML-DSA; unknown algorithm tag; missing classical pairing; duplicate
  invalid-first/valid-second Sig: and Sig-PQC: entries; malformed base64;
  wrong-length ML-DSA signature; unknown-tag-then-valid-tag candidates),
  each with a pinned expected result — so an independent implementation of
  the wire format can check itself without reading this crate's source.
  `tests/test_vectors.rs` runs them against this crate's own
  implementation as a regression check.
- **Fresh-clone reproducibility**, verified directly: `cp -r
  nix-pqc-cache-proxy /tmp/elsewhere && cd /tmp/elsewhere && cargo test`
  passes all 44 tests with zero reference back to this monorepo — no path
  dependencies, no sibling-crate assumptions.

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
- **Sign/verify speed** — real numbers from `cargo bench`
  (`benches/pqc_bench.rs`, this machine, debug build):

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

Originally done by hand; now codified as `tests/real_nix_e2e.rs` and
actually run (not just compiled) against the current code, including every
fix described above — **136.26s, PASSED**:

1. `cargo test` — all 44 tests pass, including a real (not fabricated)
   narinfo fixture verifying against the real `cache.nixos.org-1` Ed25519
   key, deliberate corruption tests for both the classical and ML-DSA
   halves, and the full test-vector suite.
2. Built `nixpkgs#hello` for real, `nix copy`'d its closure (5 store paths)
   to a local `file://` binary cache.
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

## Explicitly out of scope

- No changes to the real Nix daemon/client source, no liboqs FFI, no attempt
  to make `cache.nixos.org` itself PQC-signed.
- HTTP hygiene beyond a request timeout: upstream status codes other than
  success are currently all mapped to a generic 404, and there's no
  header/cache-control passthrough. Deferred as proxy polish that doesn't
  bear on the RFC's trust argument — see the RFC discussion for why request
  timeouts were prioritized and the rest wasn't.
- Production key management, rotation, or multi-algorithm PQC support in
  the proxy itself (the wire format's tag byte anticipates it; the proxy
  doesn't implement it).

## RFC

`rfc/0000-hybrid-binary-cache-signatures.md` — a draft NixOS RFC proposing
this hybrid `Sig-PQC:` scheme upstream, following the real `NixOS/rfcs`
template. Points at this prototype as supporting evidence and cites exact
file/function names in real `NixOS/nix` source (verified against the
GitHub repo, not reconstructed from memory) for where a real implementation
would land: `ValidPathInfo::fingerprint()`/`checkSignatures()`
(`src/libstore/path-info.cc`), the `Signer` interface
(`src/libutil/signature/signer.hh`), and `LocalStore::pathInfoIsUntrusted()`
(`src/libstore/local-store.cc`).
