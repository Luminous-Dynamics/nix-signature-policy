# Cache-invalidation: preserved questions, not a design

**Status: a question list, deliberately not a specification.** Written
so the idea raised alongside the performance campaign isn't lost, while
explicitly not designing or implementing any caching mechanism. Caching
here would create a new security-sensitive state machine whose
correctness becomes part of admission — that deserves its own
research project, triggered only if `docs/PERFORMANCE_PROTOCOL.md`'s
stop/go criteria actually point at it (see that document's "Begin
cache-correctness research" condition).

## The questions a future study must answer

- **Which stage would be cached**: `R→O` (observation caching, verifying
  the same evidence produces the same observations), `O→P` (policy
  caching, the same observations under the same policy produce the same
  result), or neither?
- **What immutable inputs define the cache key?** Candidates raised but
  not adopted: subject identity, raw-evidence digest, verification-
  registry digest, verifier/evaluator implementation identity
  (including — for O-provider specifically — that a library path alone
  is not enough, since the running process may have an older version
  already `dlopen`'d and cached for its lifetime), protocol version,
  policy digest, trust-state digest or epoch, composition mode.
- **What trust-state changes must invalidate a cached result?**
  Candidates raised but not adopted: key revocation, key rotation,
  policy/threshold changes, trust-epoch advance or rollback,
  verifier/evaluator code changes, authority/group membership changes.
- **Can a cache hit ever bypass mandatory integrity or native `B`?**
  The working assumption throughout the architecture comparison is no
  — every model composes with Nix's own trust check, never replaces it.
  Any future caching design must preserve that, not merely intend to.
- **Is the expected reuse rate high enough to matter at all?** Nix
  admission decisions are per-artifact and per-signature-set; unlike,
  e.g., a network-request cache, it isn't yet established that the same
  (evidence, policy) pair recurs often enough for caching to pay for
  its own complexity. This is precisely what the performance campaign's
  results should establish before any of the above is worth answering
  in detail.

## What this document is not

Not a cache-key schema, not a commitment format, not an invalidation
matrix, not an implementation plan. Those were sketched in discussion
but are deliberately not transcribed here — writing them down in detail
would itself start pre-committing to a design before the performance
data justifies building anything at all.
