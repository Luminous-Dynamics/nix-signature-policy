# Canonical commitments

Policy and trusted-key registry hashes are security boundaries: they link
successor epochs, anchor local rollback state, and appear in trust receipts.
`core-v1` therefore uses an explicit domain-separated commitment framing.

For canonical payload bytes `P`, object domain `D`, and commitment format
version `V`, the digest is:

`SHA-256("nix-signature-policy\\0" || D || 0x00 || u32be(V) || u64be(len(P)) || P)`

Defined domains are:

- `policy`;
- `registry`;
- `receipt-payload`;
- `trust-state-payload`;
- `transition`.

Canonical policy and registry payloads are closed typed objects serialized as
compact JSON after semantically unordered collections are sorted. Arbitrary
input JSON bytes are never hashed directly.

Known-answer vectors live in `core/commitment-v1-vectors.json`. Any change to
the framing requires a new commitment format version and must not silently
reinterpret an existing stored digest.

## Prototype migration note

Earlier prototype revisions used undifferentiated SHA-256 over compact JSON for
some commitments. Those digests are not `commitment-v1` values and must not be
reinterpreted as such. Existing local trust-state files and receipts from those
revisions should be archived as historical evidence and regenerated from a
trusted current policy/registry checkpoint before enforcement.

Receipt schema v2 and trust-state schema v1 map to commitment format v1 in this
prototype revision. A future commitment framing change must either bump the
containing schema or add an explicit commitment-format field before accepting
both formats concurrently.
