# Determinate Nix #449 interoperability fixtures — provenance

Real, reproducible evidence that this crate's fingerprint construction and
signature verification interoperate with a real, independently-built Nix
implementing multi-algorithm (Ed25519 + ML-DSA-65) signing:
[DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449).

This is not a synthetic fixture. Every file in this directory (and its
`same-name-collision/` subdirectory) was produced by actually building and
running that Nix, signing a real store path, and exporting the real
on-wire `.narinfo` and JSON output. Nothing here was hand-constructed.

## Build

- **Source**: `github:DeterminateSystems/nix-src`
- **Commit pinned**: `6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6` (merge commit of PR
  #449 on `main`, head branch `eelcodolstra/nix-373` — confirmed via
  `gh pr view 449 --repo DeterminateSystems/nix-src --json mergeCommit,baseRefName,headRefName`)
- **Build command**: `nix build "github:DeterminateSystems/nix-src/6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6#nix" --no-link --print-out-paths`
- **Resulting package**: `determinate-nix-3.20.0`
- **Resulting binary reported version**: see `nix-version.txt` — `nix (Determinate Nix 3.20.0) 2.34.6`
- **Build platform**: see `build-platform.txt`

### Build history (environmental, not a code defect)

The first full build attempt failed: 27 derivations queued, 206/216
functional tests passed, 9 skipped, and exactly one —
`nix-functional-tests:main / binary-cache` — crashed with SIGSEGV (signal
11), and that test-suite derivation is wired as a hard build dependency of
the final `determinate-nix` package output, so the whole build failed.
This happened under `load average ~48` and effectively 0 free RAM (heavy
swap use) on a machine running 12+ concurrent build sessions — conditions
strongly consistent with resource-starvation flakiness in a test that
spins up subprocess servers, not a logic bug in the pinned commit.

A retry rebuilt only the 2 previously-failed derivations (everything else
was cache-hit) and completed cleanly with no failures. **The successful
retry is what every fixture and interoperability claim below rests on** —
the earlier failure is recorded here only as build history, per explicit
instruction not to let a transient environmental failure stand in for the
real result.

## Keys generated

Two experimental-feature-gated key types, generated with the built binary
(`nix key generate-secret --extra-experimental-features cnsa --key-type
ml-dsa-65 ...` — matching @grahamc's own demonstrated command from the
#202 GitHub discussion thread):

| Key name | Algorithm | Command |
|---|---|---|
| `interop-cache-ed25519` | Ed25519 | `nix key generate-secret --key-name interop-cache-ed25519 --key-type ed25519` |
| `interop-cache-mldsa65` | ML-DSA-65 | `nix key generate-secret --extra-experimental-features cnsa --key-name interop-cache-mldsa65 --key-type ml-dsa-65` |

Public keys extracted with `nix key convert-secret-to-public` are committed
as `verification-key-ed25519.pub` and
`verification-key-ml-dsa-65-spki-der.pub` (both real `key-name:base64`
lines, unmodified).

**Distinct key names per algorithm, deliberately** — see "Same-name
collision" below for why.

## Signed store path

Built a trivial fixed-output-free derivation locally
(`interop-fixture-2`), signed it with both keys, then exported it to a
local `file://` binary cache with `nix copy --to file://...` to obtain the
**real on-wire `.narinfo` text** (not the `path-info --json` form, whose
`narHash` field uses SRI encoding rather than the `sha256:<base32>` form
that actually feeds the signing fingerprint). That real narinfo is
committed verbatim as `interop-fixture-2.narinfo`.

Key facts, read directly from that file:

- `StorePath`: `/nix/store/31ahsdff5bd9pk77n2avvys6zdxbrknh-interop-fixture-2`
- `NarHash`: `sha256:17w50rmznwp0qfq5k8x0987j3i6sw5ryjp52qcrr0jpf7gsf35qb`
- `NarSize`: `128`
- `References`: (empty)
- **Two ordinary `Sig:` lines** — `interop-cache-ed25519:...` and
  `interop-cache-mldsa65:...`. Real Nix does **not** emit a separate
  PQC-specific field; it just adds another `Sig:` line per key. See
  "Sig-PQC correction" below.

### Exact fingerprint (Nix v1 signing fingerprint)

Constructed per `NarInfo::fingerprint()`
(`1;<store_path>;<nar_hash>;<nar_size>;<comma-joined refs>`):

```
1;/nix/store/31ahsdff5bd9pk77n2avvys6zdxbrknh-interop-fixture-2;sha256:17w50rmznwp0qfq5k8x0987j3i6sw5ryjp52qcrr0jpf7gsf35qb;128;
```

(128 bytes, empty references, so the format's trailing `;` has nothing
after it.)

## Cross-implementation verification result (the decisive check)

This crate's own `narinfo::NarInfo::fingerprint()` (fed the fields above)
plus `hybrid::verify_ed25519_only` / `hybrid::verify_ml_dsa_only`
(Rust `ed25519-dalek` / RustCrypto `ml-dsa`) were run directly against the
real `Sig:` bytes from `interop-fixture-2.narinfo` and the real public keys
in this directory:

```
ED25519:   VERIFIED against real Determinate Nix signature
ML-DSA-65: VERIFIED against real Determinate Nix signature
```

This demonstrates, with real (not self-generated-only) evidence:

- our fingerprint construction is byte-exact with real Nix's;
- our narinfo `Sig:` parsing is compatible with real narinfo output;
- Rust `ed25519-dalek`/`ml-dsa` interoperate with Determinate's
  OpenSSL-backed signing for both algorithms;
- the raw-evidence adapter's premise (independently verify ordinary
  `Sig:` entries without depending on Nix itself producing a
  `VerificationOutcome`) is not merely architecturally plausible, it
  actually works against a real implementation.

## ML-DSA-65 public key encoding: X.509 SubjectPublicKeyInfo DER

`verification-key-ml-dsa-65-spki-der.pub` decodes (after the
`key-name:` prefix) to **1974 bytes**, not the raw FIPS-204 1952-byte
public key. Confirmed via `openssl asn1parse` / `openssl pkey -pubin
-inform DER`:

```
SEQUENCE (1970 bytes)
  SEQUENCE (11 bytes)
    OBJECT: ML-DSA-65            (OID 2.16.840.1.101.3.4.3.18)
  BIT STRING (1953 bytes: 1 unused-bits byte + 1952 raw key bytes)
```

A fixed 22-byte DER/SPKI header precedes the raw key for this exact
algorithm identifier (SEQUENCE + AlgorithmIdentifier SEQUENCE + OID +
BIT STRING header + unused-bits byte). The **signature** has no such
wrapper — `ml-dsa-65` `Sig:` entries decode to exactly 3309 bytes, the
raw FIPS-204 signature length, with no ASN.1 wrapping at all. This
asymmetry (wrapped public key, unwrapped signature) is non-obvious and
worth knowing before writing a verifier against real Determinate keys.

The **Ed25519** public key was also checked, not assumed: it decodes to
exactly 32 raw bytes, no wrapper.

The adapter parses this via `ml_dsa::pkcs8::SubjectPublicKeyInfoRef` +
`ml_dsa::VerifyingKey::<MlDsa65>::try_from(..)` — real SPKI/DER parsing
from the same RustCrypto `pkcs8`/`der`/`spki` crates already pulled in
transitively by `ml-dsa` itself (zero new dependencies), which validates
the ASN.1 structure, asserts the algorithm OID, and extracts the raw key
— not a hand-rolled fixed-offset byte slice.

## Same-name collision: a real, reproducible Nix limitation

See `same-name-collision/`. Signing the *same* store path with an
Ed25519 key and an ML-DSA-65 key that share the **identical**
`--key-name` (`interop-cache-1`) produces a narinfo with two valid
`Sig:` entries under that one name (captured in
`same-name-collision/pathinfo.json`). But `nix store verify
--trusted-public-keys "<ed25519 pub> <ml-dsa pub>" --sigs-needed 2`
**fails** ("path ... is untrusted", exit 2) — deterministically,
regardless of the order the two `--trusted-public-keys` are given.

At `--sigs-needed 1`, verification against *either* key alone, or both
together, succeeds — meaning only one of the two same-named keys is ever
actually live in Nix's internal trust map at a time; the other is
silently shadowed. This is a real, reproducible limitation of current
(Determinate) Nix: **a single key name cannot carry simultaneous trust
across two algorithms.** Assigning each algorithm a distinct key name
(as this fixture set does throughout) sidesteps it completely — confirmed
working at `--sigs-needed 2` with `interop-cache-ed25519` /
`interop-cache-mldsa65`.

This is a genuine, citable data point for the composed-authorization
proposal: even Nix's own newest multi-algorithm signing implementation
cannot yet make one operator identity simultaneously trusted under both
algorithms through the built-in key-name mechanism alone.

## Sig-PQC correction

An earlier prototype in this crate speculatively invented a `Sig-PQC:`
narinfo field for a second (PQC) signature. Real Nix does not do this —
it emits ordinary repeated `Sig:` lines, one per key, regardless of
algorithm (see `interop-fixture-2.narinfo` above: two `Sig:` lines, no
`Sig-PQC:`). `Sig-PQC:` should be treated as this project's own
historical/prototype-specific field, not a claim about real narinfo wire
format. (Tracked as a separate, out-of-scope-for-this-series cleanup.)

## CI verification status

Standalone repository (`Luminous-Dynamics/nix-signature-policy`),
branch `sync-composable-policy-framework`, commit
`c3af364c340268081ea794538d9823226dd2924c` — the code/fixture/test
state CI actually verified. (This documentation section was added in
a later, docs-only commit on top of that verified commit; it changes
no code, fixture, or test file, so the CI result below still
describes the current state faithfully. See the repository's
immutable evidence tag, if one has been cut, for the exact final
commit this record was frozen at.)

CI run: [29455601462](https://github.com/Luminous-Dynamics/nix-signature-policy/actions/runs/29455601462)
(triggered manually via `workflow_dispatch`, since this workflow only
auto-triggers on `main`/pull requests).

| Lane | Result |
|---|---|
| Maintainer real-Nix demonstration | ✅ pass |
| Real Nix proof (stable) | ✅ pass |
| Real Nix proof (latest) | ✅ pass |
| Nix flake check (ubuntu-latest) | ✅ pass |
| Deterministic source release | ✅ pass |
| Locked dependency audit | ✅ pass |
| Current stable Rust forward compatibility | ✅ pass |
| Bounded fuzz smoke (all 8 targets, incl. the 2 new raw-evidence targets) | ✅ pass |
| Nix flake check (macos-latest) | ❌ fail |

All relevant Linux, interoperability, release, audit and fuzz lanes
pass. The existing macOS flake-check failure remains a separately
tracked LLVM bitcode-version incompatibility
(`LLVM error: Unknown attribute kind (102) (Producer: 'LLVM21.1.8'
Reader: 'LLVM 19.1.7-rust-1.86.0-stable')`, in the `alloca` crate's
build) and **predates the raw-evidence adapter** — confirmed
byte-identical across three separate CI runs on three different
commits during this work, none of which touched anything on the
macOS build path. It is tracked as a separate, deferred repository-
hygiene item, not folded into this evidence.
