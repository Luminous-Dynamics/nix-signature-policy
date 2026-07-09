# nix-pqc-cache-proxy (prototype)

A local prototype for post-quantum-ready Nix binary-cache signing: a hybrid
Ed25519 + ML-DSA-65 signature scheme for `.narinfo` metadata, a CLI to
generate keys / dual-sign / verify a local binary cache, and a reverse proxy
that verifies an upstream's classical signature and re-serves the narinfo
augmented with a hybrid signature that an unmodified `nix` client accepts.

**This is exploratory, unaudited, prototype code.** It reuses
`mycelix-crypto::hybrid_sig`, which is itself explicitly EXPERIMENTAL and
pending a crypto review (see `mycelix-workspace/PQC_ROADMAP_2026-07-07.md`).
Do not point this at anything you actually depend on for security.

## Scope

Nix's supply chain has two halves for quantum readiness: store-path hashing
(truncated SHA-256, still fine under Grover's algorithm) and binary-cache
trust (Ed25519 `.narinfo` signatures, broken outright by Shor's algorithm on
a cryptographically-relevant quantum computer). This tool addresses the
second half — but **it does not and cannot make `cache.nixos.org` itself
PQC-signed**: upstream doesn't sign with ML-DSA and we don't hold their key.
What it demonstrates is the hybrid-signature mechanics and a local
trust-translating proxy, using a format (`Sig-PQC:`) that is our own
invention for this prototype, not a Nix or IETF spec.

## What's here

- `src/narinfo.rs` — hand-rolled `.narinfo` parser/serializer + the Nix v1
  signing fingerprint (`1;<path>;<narhash>;<narsize>;<refs>`). Verified
  bit-compatible with real Nix: a frozen fixture (a real narinfo fetched from
  `cache.nixos.org` for `bash-5.2p37`) round-trips through parse → fingerprint
  → **Ed25519 verify against the real `cache.nixos.org-1` public key**, and
  that verification actually passes.
- `src/keys.rs` — hybrid key generation/storage on top of
  `mycelix_crypto::hybrid_sig::HybridSigner`, and the `Sig-PQC:` wire encoding
  (`name:base64(ed25519(64B) || ml_dsa)`).
- `src/proxy.rs` — an axum reverse proxy speaking the Nix HTTP binary-cache
  protocol: fetches `nix-cache-info` / `.narinfo` / `nar/*` from a configured
  upstream, verifies the upstream's `Sig:` against a configured public key,
  and re-serves the narinfo with an added `Sig:` (same key material, so
  ordinary `nix` needs zero awareness of the hybrid format) plus `Sig-PQC:`.
- CLI: `keygen`, `sign <cache_dir>`, `verify <narinfo> [--require-pqc]`,
  `proxy`.

## Real measurements from this pass

- **Signature overhead**: an unsigned narinfo for `hello-2.12.3`'s runtime
  dependencies was ~510-660 bytes. After dual-signing: ~5.1-5.3KB — roughly
  **+4.6KB per narinfo** (Ed25519 64B + ML-DSA-65 ~3.3KB, base64-inflated
  ~4/3×, plus the `Sig-PQC:` line prefix). For a cache with millions of
  narinfo entries this is a meaningful bandwidth/storage cost to weigh in any
  real spec.
- **Sign/verify speed**: not machine-measured precisely in this pass (a
  criterion bench like `mycelix-crypto/benches/pqc_bench.rs` would give real
  numbers) — CLI keygen/sign/verify all completed sub-second per invocation
  in manual testing, which is unsurprising for ML-DSA-65 but wasn't isolated
  from process startup cost here.

## End-to-end verification actually performed

1. `cargo test` — 10/10 pass, including a real (not fabricated) narinfo
   fixture verifying against the real `cache.nixos.org-1` Ed25519 key, and
   deliberate corruption tests for both the classical and ML-DSA halves.
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
hybrid format is fully backward compatible — real `nix` never needs to know
`Sig-PQC:` exists.

## Explicitly out of scope

- No changes to the real Nix daemon/client source, no liboqs FFI, no attempt
  to make `cache.nixos.org` itself PQC-signed.
- No RFC text yet — this prototype is what a future RFC would cite.
- `mycelix-crypto` itself is untouched — consumed only via a path dependency.
