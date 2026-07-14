# Portable conformance profile

The policy vectors are intended to outlive this Rust implementation. The
committed file `conformance/policy-manifest-v1.json` provides deterministic
SHA-256 commitments for every vector and names a minimum interoperability
profile.

## `core-v1`

`core-v1` contains the smallest current set that exercises the security
properties an implementation must not weaken:

- ordinary acceptance and missing-group refusal;
- invalid, revoked, duplicate, conflicting, and unknown evidence;
- typed group classification;
- same-identity binding;
- family diversity and family prohibition;
- independent raw and normalized input bounds;
- expiring migration fallback;
- policy rollback refusal;
- recovery from lattice to hash-based post-quantum authorization;
- observation-only algorithms remaining non-authoritative.

Passing only `core-v1` is not equivalent to passing every vector. It is the
minimum profile suitable for an early cppnix, tvix, cache, or external-verifier
implementation. Full conformance requires every vector committed by the
manifest.

## Integrity and updates

The manifest hashes the exact JSON bytes of each vector. Any semantic or
editorial vector change requires rebuilding the manifest. A new incompatible
vector shape requires a new vector schema version. A materially changed minimum
profile should receive a new profile name rather than silently changing the
meaning of an already published profile.

Run:

```console
python3 scripts/build-policy-manifest.py --check
python3 scripts/check-semantic-consistency.py
```
