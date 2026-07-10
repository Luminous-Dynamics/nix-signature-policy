---
feature: hybrid_narinfo_signatures
start-date: 2026-07-10
author: Tristan Stoltz (tstoltz)
co-authors: (find a buddy later to help out with the RFC)
shepherd-team: (names, to be nominated and accepted by RFC steering committee)
shepherd-leader: (name to be appointed by RFC steering committee)
related-issues: (prototype implementation currently private; see "Supporting prototype" below)
---

# Summary
[summary]: #summary

Add an optional, additive, fully backward-compatible hybrid post-quantum
signature to the `.narinfo` binary-cache format: a second signature field
(`Sig-PQC:`, proposed name) carrying an ML-DSA-65 (FIPS 204) signature
alongside Nix's existing Ed25519 `Sig:` line, both computed over the same
signing fingerprint Nix already generates. A path is PQC-trusted only when
**both** halves verify, so this can never be weaker than today's trust
model and becomes quantum-resistant the moment ML-DSA is added — while
every existing `nix` client keeps working unmodified, because unrecognized
narinfo fields are already silently ignored.

## Supporting prototype

This RFC is backed by a working, tested prototype (`nix-pqc-cache-proxy`,
currently in a private monorepo, path available on request) that:
implements the exact narinfo fingerprint algorithm Nix uses (verified
byte-for-byte against a real `cache.nixos.org`-signed narinfo and its real
published Ed25519 key); dual-signs a local binary cache with a hybrid
Ed25519+ML-DSA-65 signer; runs a reverse proxy that verifies an upstream's
classical signature and re-serves narinfo augmented with the hybrid field;
and proves, via `nix store verify` against a real unmodified `nix` binary,
that a client trusting only the new hybrid key correctly trusts a
dual-signed path and correctly refuses an untrusted one. All claims below
about current Nix source (file paths, function names, trust logic) were
verified directly against the `NixOS/nix` GitHub repository while writing
this RFC, not reconstructed from memory.

# Motivation
[motivation]: #motivation

Nix's supply-chain integrity splits into two independent cryptographic
layers, and they age very differently under quantum attack:

- **Store-path/NAR content hashing** uses SHA-256. Grover's algorithm gives
  only a quadratic speedup against a hash function's preimage resistance,
  so even the worst case (a fully truncated 160-bit store-path hash) still
  retains a large security margin. This layer does not need urgent
  attention.
- **Binary-cache trust** is 100% classical: every `.narinfo`'s `Sig:` line
  is an Ed25519 signature, and Ed25519's security rests entirely on the
  hardness of the elliptic-curve discrete-log problem — which Shor's
  algorithm solves outright given a cryptographically-relevant quantum
  computer (CRQC). Unlike encrypted data, there is no "harvest now, decrypt
  later" window to worry about; the exposure is worse in a different way:
  the moment a CRQC exists, an attacker can derive *any* trusted signing
  key's private component from its long-published public key and forge
  a `Sig:` line for arbitrary content, retroactively and going forward,
  for every binary cache whose trust still rests on that key.

Nix has **no migration path today**. `SecretKey`/`PublicKey`/`Signature`
(`src/libutil/signature/local-keys.cc`) are concrete structs that call
libsodium's `crypto_sign_*` functions directly — there is no algorithm
field, no dispatch, nothing to extend. The one genuinely positive sign is
that `Signer` (`src/libutil/signature/signer.hh`, `signer.cc`) is already
an abstract interface — `LocalSigner` is its only concrete implementation
today, but the shape for a second implementation already exists on the
*signing* side. There is no equivalent on the *verification* side
(`PublicKey::verifyDetachedAnon`, the free function `verifyDetached()`):
both are hardcoded to `crypto_sign_verify_detached`.

The case for acting now, well before any CRQC exists, is migration lead
time: cache signing keys and client `trusted-public-keys` configuration are
long-lived and slow to rotate across an ecosystem this size. A narinfo
signed today with Ed25519 only will still be the thing a client fetches in
five or ten years. If caches can start *dual-signing* years ahead of need,
the signatures already exist in the wild by the time enforcement actually
matters — the alternative (starting only once a CRQC is imminent) means
racing a migration under real pressure instead of a calm, staged rollout.

# Detailed design
[design]: #detailed-design

## Wire format

Add one new, optional, repeatable narinfo field, `Sig-PQC:`, alongside the
existing `Sig:` field. Its value has the same `<keyname>:<base64-data>`
shape Nix already uses for `Sig:` (see `Signature::parse`/`to_string` in
`local-keys.cc`), but the base64 payload is:

```
alg_tag (1 byte) || ed25519_signature (64 bytes) || ml_dsa_65_signature (~3309 bytes)
```

The leading algorithm tag makes the field self-describing: a future
ML-DSA-87 or Falcon variant is a new tag value, not a format break, and an
entry tagged with an algorithm a given `nix` build doesn't understand
should be rejected (or ignored, for verification purposes) rather than
misparsed. This is not a novel invention for this RFC — it is exactly what
the supporting prototype implements and tests (`SigPqcAlgorithm`,
`encode_sig_pqc`/`decode_sig_pqc`).

Both signatures are computed over the **same fingerprint** Nix already
computes today, unchanged:

```cpp
// src/libstore/path-info.cc, ValidPathInfo::fingerprint()
"1;" + store.printStorePath(path) + ";" + narHash.to_string(HashFormat::Nix32, true)
    + ";" + std::to_string(narSize) + ";" + concatStringsSep(",", store.printStorePathSet(references))
```

The prototype reimplements this construction independently (Rust, not
linked against Nix) and verifies it produces byte-identical fingerprints
to real Nix, cross-checked by successfully verifying a real
`cache.nixos.org`-issued Ed25519 signature with it.

## Why an additional field, not a change to `Signature`

`Signature { keyName, sig }` (`local-keys.cc`) is a flat opaque byte blob
with no algorithm field, stored in a `std::set<Signature>` on
`ValidPathInfo`/`UnkeyedNarInfo`. The trust decision itself is a simple
any-of-N-keys OR, not a threshold or composite scheme:

```cpp
// src/libstore/path-info.cc
size_t ValidPathInfo::checkSignatures(const StoreDirConfig & store, const PublicKeys & publicKeys) const {
    if (isContentAddressed(store)) return maxSigs;
    size_t good = 0;
    for (auto & sig : sigs) if (checkSignature(store, publicKeys, sig)) good++;
    return good;
}

// src/libstore/local-store.cc
bool LocalStore::pathInfoIsUntrusted(const ValidPathInfo & info) {
    return config->requireSigs && !info.checkSignatures(*this, getPublicKeys());
}
```

There is no concept anywhere in this path of "these two signatures must
both hold as one unit." Retrofitting AND-composition into the *existing*
`Sig:`/`Signature` machinery would touch: the SQLite schema and queries
backing `LocalStore`'s path-info table, `toJSON`/`fromJSON` for three JSON
format versions, `checkSignatures`/`checkSignature`, `verifyDetached`, and
every external consumer of `PublicKeys`/`Signature`. That is a large,
high-blast-radius change for what should be an opt-in extension.

A parallel field avoids essentially all of it. The `.narinfo` text-format
parser (`NarInfo::NarInfo(...)` in `src/libstore/nar-info.cc`, which
constructs into a `ValidPathInfo`-derived object) is a plain
`if (name == "...") ... else if (...)` chain with **no catch-all error
branch** — an unrecognized field name is silently skipped today, verified
directly from source. This is precisely what makes `Sig-PQC:` free:
existing `nix` versions require zero code changes to remain fully
functional and fully compatible with a dual-signed narinfo.

## Signing-side integration

`ValidPathInfo` already supports signing with multiple independent signers
in one pass:

```cpp
void ValidPathInfo::sign(const Store & store, const std::vector<std::unique_ptr<Signer>> & signers) {
    auto fingerprint = this->fingerprint(store);
    for (auto & signer : signers) sigs.insert(signer->signDetached(fingerprint));
}
```

A `HybridSigner : Signer` is architecturally plausible here, but
`Signer::signDetached()` returns a single `Signature` destined for the
`sigs` set — it cannot itself produce a `Sig-PQC:` line without either a
new `Signer` subtype specifically for the hybrid field, or a second,
parallel signing pass outside the existing `sign()` loop that writes
directly into a new `sigsPqc`-equivalent field. The latter is simpler and
lower-risk for an initial implementation.

## Verification-side integration

Needs a new check parallel to, not replacing, `pathInfoIsUntrusted`:

```cpp
// existing
bool LocalStore::pathInfoIsUntrusted(const ValidPathInfo & info) {
    return config->requireSigs && !info.checkSignatures(*this, getPublicKeys());
}
// proposed (new nix.conf setting `require-pqc-sigs`, default false)
bool LocalStore::pathInfoIsPqcUntrusted(const ValidPathInfo & info) {
    return config->requirePqcSigs && !info.checkPqcSignatures(*this, getPqcPublicKeys());
}
```

`nix store verify --sigs-needed N` already generalizes "how many
signatures are enough" for the classical case; whether a hybrid PQC
signature should count toward that same counter or be tracked
independently is an open question (see Unresolved questions).

## Rollout

Caches SHOULD start dual-signing as soon as tooling exists — it is
additive and costs only extra bytes (measured, see Drawbacks). Clients
should NOT set `require-pqc-sigs = true` until enough of the caches they
actually depend on have dual-signed; this is a config knob a site enables
for itself once ready, not something that needs ecosystem-wide
synchronization. This RFC deliberately does not propose changing
`nix-store --generate-binary-cache-key`'s default output format, the
on-disk SQLite schema, or JSON `PathInfoJsonFormat` versions — those follow
once the narinfo wire-format extension has proven out in practice.

# Examples and Interactions
[examples-and-interactions]: #examples-and-interactions

A real narinfo (fetched from `cache.nixos.org` for `bash-5.2p37`), before:

```
StorePath: /nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37
URL: nar/08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93.nar.xz
Compression: xz
FileHash: sha256:08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93
FileSize: 448312
NarHash: sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48
NarSize: 1654112
References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66
Deriver: c8dsr967ap3j1l01l565w926bahlxpmc-bash-5.2p37.drv
Sig: cache.nixos.org-1:DCeO+o0Q4DlnCPr8TeBZE77GhRlm11H9x609XtU7rUS69am2qkhX4zTsK4URTHG/vEMX4avP8HVcIHwXHq3+CQ==
```

... and after a cache adopts this proposal. The `Sig-PQC:` value below is
**genuinely generated by the prototype** for this exact narinfo (not typed
by hand) — truncated here for readability, since a real ML-DSA-65 signature
is ~3.3KB before base64:

```
StorePath: /nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37
URL: nar/08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93.nar.xz
Compression: xz
FileHash: sha256:08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93
FileSize: 448312
NarHash: sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48
NarSize: 1654112
References: 00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37 q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66
Deriver: c8dsr967ap3j1l01l565w926bahlxpmc-bash-5.2p37.drv
Sig: cache.nixos.org-1:DCeO+o0Q4DlnCPr8TeBZE77GhRlm11H9x609XtU7rUS69am2qkhX4zTsK4URTHG/vEMX4avP8HVcIHwXHq3+CQ==
Sig-PQC: cache.nixos.org-1:AWvNSk+S+4MLbwklVC34XQmxv/HH+RlQa2v50j92xvr3IJs32Wpoo1ORypEPQVyEpwfeqKGo2jEXHX3RbE141Q64MtQA7/P3rWJSyuwnHMDYO9Lv9pcfM1LmtM/V9XjyIoA8T/UT5uK9jvPY775M6lm3mJIBBoN8UsgVQZO3ekkWEJg/CWU40RhEIVi+08KWszXgj0vPYBrVsWquGSfh09zi...
```

(Note: the prototype's default `sign` subcommand also appends a second,
independent classical `Sig:` line under the same key name, which is a
byproduct of it being built for a cache initializing hybrid signing from
scratch — omitted from this figure since it would confusingly suggest two
different keys sharing a name. A real cache dual-signing with its
already-published Ed25519 key would just add the one new `Sig-PQC:` line,
exactly as shown.)

An **unmodified, older `nix` client** fetching this narinfo behaves
identically to before: it parses `StorePath` through `Sig:`, hits
`Sig-PQC:`, doesn't recognize the field name, and (per the current
`nar-info.cc` parser, which has no catch-all-error branch) simply moves on
to the next line. No crash, no warning, no behavior change.

A **PQC-aware client** with `require-pqc-sigs = true` and the cache's
hybrid public key configured performs the existing Ed25519 check exactly
as today, plus decodes and verifies the `Sig-PQC:` entry, requiring both
halves to succeed before considering the path trusted.

# Drawbacks
[drawbacks]: #drawbacks

- **Real measured storage/bandwidth overhead**: dual-signing a narinfo adds
  roughly **+4.6KB** (Ed25519's 64 bytes plus ML-DSA-65's ~3.3KB signature,
  inflated ~4/3× by base64, plus the field prefix) — measured directly on
  real narinfo files in the prototype. `cache.nixos.org` serves narinfo for
  a very large number of distinct historical store paths; dual-signing
  all of them at this per-entry cost is a genuine, non-trivial storage and
  bandwidth line item that scales linearly with cache size. This RFC does
  not have access to `cache.nixos.org`'s actual path count to turn that
  into a precise total — that projection should come from whoever operates
  it before this proceeds.
- **ML-DSA is comparatively new** (standardized as FIPS 204 in 2024) versus
  Ed25519's decade-plus track record. The RustCrypto-backed hybrid
  construction the prototype uses for both algorithms is explicitly
  unaudited experimental code, not production-grade.
- **No existing PQC dependency** in Nix's C++ implementation — `local-keys.cc`
  depends on libsodium directly for Ed25519, and there is no `liboqs` or
  equivalent already vendored. A real (non-prototype) C++ implementation
  needs a new native dependency; `tvix` (the Rust reimplementation) can
  likely reach pure-Rust ML-DSA crates without that cost — see Unresolved
  questions.
- **Roughly doubles narinfo signature-check cost** — measured from the
  prototype's benchmark: ML-DSA-65 sign ~1.04ms, verify ~523µs (versus
  Ed25519's typical sub-100µs). Negligible per individual fetch against
  network I/O, but non-trivial at cache-population or CI scale doing
  millions of verifications.

# Alternatives
[alternatives]: #alternatives

- **Pure PQC-only signatures, dropping Ed25519.** Rejected: current NIST
  and broader cryptographic guidance favors hybrid schemes until PQC
  algorithms accumulate more real-world scrutiny, and this would break
  backward compatibility completely rather than being additive.
- **Falcon instead of ML-DSA.** ML-DSA was chosen for this proposal mainly
  for current library maturity (including pure-Rust, wasm-capable
  implementations already exercised elsewhere) and because it is NIST's
  primary standardized signature recommendation; the algorithm-tag design
  in the wire format exists specifically so Falcon or another scheme could
  be added later without another format change.
- **Do nothing until a CRQC is imminent.** Rejected on migration-lead-time
  grounds argued in Motivation: signing keys and trust configuration are
  long-lived, so waiting for urgency means a rushed migration instead of a
  calm, staged one.
- **A trust-translating local proxy, no changes to Nix itself.** This is
  exactly what this RFC's supporting prototype does, and it works today,
  verified against a real unmodified `nix` client. It is a legitimate
  stop-gap anyone can deploy right now without waiting on this RFC — but it
  doesn't scale as a long-term answer, since it requires trusting a proxy
  operator's re-signing step rather than the original cache's own key, and
  provides no benefit for narinfo never routed through such a proxy. This
  RFC proposes making the capability native so caches can dual-sign
  themselves, which the proxy approach cannot offer.

# Prior art
[prior-art]: #prior-art

- TLS 1.3's hybrid key-exchange deployments (e.g. X25519+ML-KEM composite
  key agreement, already shipping in some stacks) follow the same
  "require both, break neither" philosophy this proposal borrows for
  signatures rather than key exchange.
- The RustCrypto-backed hybrid Ed25519+ML-DSA-65 construction this
  proposal's prototype uses originates from unrelated work in the same
  monorepo (a decentralized-trust protocol's own binary/credential
  signing) that independently arrived at the identical hybrid pattern —
  suggestive that this is a convergent design choice, not an idiosyncratic
  one, though it is not independent published prior art in the
  traditional sense.
- This RFC's author has not exhaustively searched existing `NixOS/nix`
  issues or Discourse threads for prior PQC-specific discussion; whoever
  carries this RFC forward should do that search and summarize findings
  here before requesting shepherds.

# Unresolved questions
[unresolved]: #unresolved-questions

- Exact field name and byte-level wire format — `Sig-PQC:` and the tagged
  encoding above are this proposal's concrete starting point (implemented
  and tested in the prototype), not a settled spec.
- **C++ (`cppnix`) vs Rust (`tvix`) as the first implementation target.**
  `tvix` likely has a much lower-friction path to a working implementation
  via pure-Rust ML-DSA crates, avoiding a new C library dependency
  entirely; `cppnix` needs `liboqs` or equivalent. Prototyping against
  `tvix` first, then porting the wire-format learnings back to `cppnix`,
  may be the pragmatic order.
- Independent key rotation for the PQC half versus always-paired-with-Ed25519.
- Whether `nix-store --generate-binary-cache-key` should grow a flag to
  produce hybrid keypairs by default going forward, or remain opt-in.
- How a hybrid `Sig-PQC:` entry should interact with `nix store verify
  --sigs-needed N`'s existing threshold counter — does one hybrid
  signature count as one toward that threshold, or does hybrid trust need
  its own independent counter?
- A real storage/bandwidth projection at `cache.nixos.org`'s actual scale,
  which requires access this RFC's author doesn't have.

# Future work
[future]: #future-work

- The identical `Signature`/`PublicKey` machinery and OR-across-keys trust
  model also backs `Realisation::checkSignatures` (build-result signing),
  found alongside `ValidPathInfo::checkSignatures` during research for this
  RFC — extending the same hybrid pattern there is a natural follow-up,
  out of scope here.
- Adding a `liboqs` (or, for `tvix`, a chosen pure-Rust crate set) build
  dependency is a prerequisite for turning this from a design into a real
  implementation.
- Eventually deprecating classical-only trust once ML-DSA has more
  real-world track record is explicitly **not** proposed here — this RFC
  is additive only.
- Standardizing this wire-format extension across the broader
  narinfo-speaking ecosystem (`attic`, `Cachix`, and other third-party
  binary caches) so PQC-signed caches interoperate beyond just
  `cppnix`/`tvix`.
